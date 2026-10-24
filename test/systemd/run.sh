#!/usr/bin/env bash
# gosftpd under the packaged systemd unit (ADR 0011): installs the files as
# docs/install.md does, with a binary built with -tags landlockprobe, and
# drives the service through systemd: Landlock, uploads, reloads and their
# status line, a disk mounted on the mount's directory, host key rotation,
# exec hooks and KillMode=mixed, port 22's
# capability, seccomp filters without the Landlock calls, the drop-in for
# systemd before 253, and the upgrade from the interim unit of v0.3's
# hardening guide.
#
# It changes the machine (/usr/bin, /etc, a system user) and needs systemd
# as PID 1 and sudo: it runs in the CI job "systemd" on a throwaway
# ubuntu-24.04 runner, and refuses to run unless CI=true or
# GOSFTPD_SYSTEMD_TEST=1. Usage: test/systemd/run.sh (from anywhere).
# Needs Go, openssh-client, jq and findmnt. In a container, make / shared
# first (mount --make-rshared /), as systemd does at boot on a machine:
# the phase with a disk mounted while gosftpd runs fails with a setup
# error otherwise.

# Functions called through check are not unreachable.
# shellcheck disable=SC2317
set -euo pipefail

if [ "${CI:-}" != true ] && [ -z "${GOSFTPD_SYSTEMD_TEST:-}" ]; then
	echo "test/systemd/run.sh installs gosftpd into this system; run it on a throwaway machine with GOSFTPD_SYSTEMD_TEST=1" >&2
	exit 2
fi
if [ ! -d /run/systemd/system ]; then
	echo "FAIL: systemd is not PID 1 here" >&2
	exit 1
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PKG="$ROOT/packaging"
WORK="$(mktemp -d)"
FAILED=0
CONFIG=/etc/gosftpd/config.toml
AUDIT=/var/log/gosftpd/audit.jsonl
DROPINS=/etc/systemd/system/gosftpd.service.d
HOOKS=/usr/local/libexec/gosftpd-ci
INBOX=/srv/sftp/inbox
# The tmpfs mounted on $INBOX while there is one, for on_exit.
REMOUNTED=

fail() { echo "FAIL: $*" >&2; FAILED=1; }
pass() { echo "ok:   $*"; }
die() { fail "$*"; exit 1; }
phase() { printf '\n=== %s\n' "$*"; }
on_exit() {
	local status=$?
	if [ "$FAILED" != 0 ] || [ "$status" != 0 ]; then
		echo "--- journal of gosftpd.service" >&2
		sudo journalctl -u gosftpd -n 150 --no-pager >&2 || true
	fi
	if [ -n "$REMOUNTED" ]; then
		sudo systemctl stop gosftpd || true
		sudo umount "$REMOUNTED" || sudo umount -l "$REMOUNTED" || true
	fi
	rm -rf "$WORK"
}
trap on_exit EXIT

# check WHAT COMMAND...: pass or fail by the command's exit status.
check() {
	local what=$1
	shift
	if "$@"; then pass "$what"; else fail "$what"; fi
}
# refused COMMAND...: the command fails.
refused() { ! "$@"; }

# The journal of gosftpd.service only grows during the test: a mark is its
# number of lines, and since MARK prints what came after.
journal_mark() { sudo journalctl -q -u gosftpd -o cat --no-pager | wc -l; }
journal_since() { sudo journalctl -q -u gosftpd -o cat --no-pager | tail -n "+$(($1 + 1))"; }
# journal_has MARK REGEX: the journal has a matching line after MARK; it may
# take journald a moment. (Output is captured before grep -q: with pipefail,
# a writer cut off by grep -q would turn a match into a failure.)
journal_has() {
	local out
	for _ in $(seq 50); do
		out=$(journal_since "$1")
		if grep -Eq -- "$2" <<<"$out"; then return 0; fi
		sleep 0.2
	done
	return 1
}
main_pid() { systemctl show -p MainPID --value gosftpd; }
status_text() { systemctl show -p StatusText --value gosftpd; }
# status_is TEXT: the status line becomes TEXT (with the legacy drop-in it
# may come a moment after systemctl reload returns).
status_is() {
	for _ in $(seq 50); do
		if [ "$(status_text)" = "$1" ]; then return 0; fi
		sleep 0.2
	done
	echo "status: $(status_text)" >&2
	return 1
}
# status_shown TEXT: systemctl status shows the status line TEXT.
status_shown() { grep -qF "Status: \"$1\"" <<<"$(systemctl status gosftpd --no-pager || true)"; }
# last_reload_is FILTER: the last server.reload audit event matches the jq
# FILTER.
last_reload_is() { sudo grep '"event":"server.reload"' "$AUDIT" | tail -n 1 | jq -e "$1" >/dev/null; }
reload_ok='.result == "ok" and (has("restart_required") | not)'
last_event_is() { grep -qF "\"event\":\"$1\"" <<<"$(sudo tail -n 1 "$AUDIT")"; }
# unit_file_is PATH: systemd uses the unit file PATH for gosftpd.service.
unit_file_is() { [ "$(systemctl cat gosftpd | sed -n 1p)" = "# $1" ]; }
gone() { ! sudo kill -0 "$1" 2>/dev/null; }
exposure_at_most_1_2() { systemd-analyze security --threshold=12 gosftpd.service >/dev/null; }
# start: start the service and wait until it is up (Type=notify-reload
# waits for READY=1).
start() {
	sudo systemctl start gosftpd || die "systemctl start gosftpd"
	[ "$(systemctl is-active gosftpd)" = active ] || die "gosftpd is not active after start"
}
# stop_within_timeout: stop, and fail if it took TimeoutStopSec (45 s) or
# more; prints the seconds taken.
stop_within_timeout() {
	local t0 t1
	t0=$(date +%s)
	sudo systemctl stop gosftpd
	t1=$(date +%s)
	if [ $((t1 - t0)) -lt 45 ]; then pass "stopped in $((t1 - t0)) s"; else fail "stop took $((t1 - t0)) s"; fi
}
# config_with TEXT: the packaged configuration with TEXT appended, written
# in place (as an editor that keeps the file would).
config_with() {
	{ cat "$PKG/config.toml"; printf '%s\n' "$1"; } | sudo tee "$CONFIG" >/dev/null
}
# sftp_as USER PORT BATCH: run an sftp batch.
sftp_as() {
	sftp -q -b "$3" -P "$2" -i "$WORK/$1" -o IdentitiesOnly=yes -o BatchMode=yes \
		-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$1@127.0.0.1"
}
# as_gosftpd COMMAND...: run a command as the service user, from /.
as_gosftpd() { (cd / && sudo runuser -u gosftpd -- "$@"); }
proc_status() { sudo grep "^$2:" "/proc/$1/status" | cut -f 2; }

# The binary logs the result of os.Open("/etc/passwd") after Landlock is
# applied ("landlock probe"); the release path is CGO_ENABLED=0.
(cd "$ROOT" && CGO_ENABLED=0 go build -tags landlockprobe -trimpath -o "$WORK/gosftpd" ./cmd/gosftpd)
for u in alice bob; do ssh-keygen -q -t ed25519 -N '' -f "$WORK/$u"; done
head -c 1048576 /dev/urandom >"$WORK/payload"
systemctl --version | sed -n 1p

phase "install as docs/install.md does"
sudo install -m 0755 "$WORK/gosftpd" /usr/bin/gosftpd
sudo install -m 0644 "$PKG/systemd/gosftpd.service" /usr/lib/systemd/system/gosftpd.service
sudo install -m 0644 "$PKG/gosftpd.sysusers" /usr/lib/sysusers.d/gosftpd.conf
sudo install -m 0644 "$PKG/gosftpd.tmpfiles" /usr/lib/tmpfiles.d/gosftpd.conf
sudo systemd-sysusers gosftpd.conf
sudo systemd-tmpfiles --create gosftpd.conf
sudo install -d -m 0755 /etc/gosftpd
sudo install -m 0640 -g gosftpd "$PKG/config.toml" "$CONFIG"
check "the user gosftpd has the home /" test "$(getent passwd gosftpd | cut -d: -f6)" = /

# The probe of docs/install.md, verbatim: systemd 255 knows
# Type=notify-reload, so the drop-in is not installed.
probe() { # probe TYPE: what systemd-analyze verify says about a unit of TYPE
	local d
	d=$(mktemp -d)
	printf '[Unit]\nDefaultDependencies=no\n[Service]\nType=%s\nExecStart=/bin/true\n' "$1" >"$d/gosftpd-probe.service"
	systemd-analyze verify --man=no "$d/gosftpd-probe.service" 2>&1 || true
	rm -r "$d"
}
if grep -q 'Failed to parse service type' <<<"$(probe notify-reload)"; then
	sudo install -D -m 0644 "$PKG/systemd/legacy-notify.conf" "$DROPINS/legacy-notify.conf"
else
	sudo rm -f "$DROPINS/legacy-notify.conf"
fi
sudo systemctl daemon-reload
check "the probe finds Type=notify-reload: no legacy drop-in" test ! -e "$DROPINS/legacy-notify.conf"
# Against a systemd that lacks the type, here a type no systemd knows, the
# probe reports it.
check "the probe reports an unknown type" grep -q 'Failed to parse service type' <<<"$(probe notify-reload-unknown)"

# Before the first start, the check passes as the service user (the state
# directory does not exist yet; tmpfiles made the log directory).
if out=$(as_gosftpd /usr/bin/gosftpd config validate --check-fs --config "$CONFIG" 2>&1); then
	pass "config validate --check-fs as gosftpd before the first start"
else
	fail "config validate --check-fs as gosftpd: $out"
fi

phase "start: Landlock, capabilities, seccomp"
mark=$(journal_mark)
start
check "Type=notify-reload" test "$(systemctl show -p Type --value gosftpd)" = notify-reload
check "landlock: ABI vN applied" journal_has "$mark" 'landlock: ABI v[2-5] applied'
check "/etc/passwd cannot be opened under Landlock" journal_has "$mark" 'landlock probe.*permission denied'
check "warning: no users configured" journal_has "$mark" 'no users configured'
pid=$(main_pid)
check "CapEff of gosftpd is 0" test "$(proc_status "$pid" CapEff)" = 0000000000000000
check "NoNewPrivs of gosftpd is 1" test "$(proc_status "$pid" NoNewPrivs)" = 1
check "gosftpd runs under a seccomp filter" test "$(proc_status "$pid" Seccomp)" = 2
check "systemd-analyze security of the running unit is at most 1.2" exposure_at_most_1_2
# As root, the check refuses the host key that belongs to gosftpd, which is
# why docs/install.md runs it as gosftpd.
if out=$(sudo /usr/bin/gosftpd config validate --check-fs --config "$CONFIG" 2>&1); then
	fail "config validate --check-fs as root accepted gosftpd's host key"
else
	check "as root, config validate --check-fs refuses gosftpd's host key" \
		grep -q 'must belong to root or to the user running gosftpd' <<<"$out"
fi

phase "add a user, reload, upload"
sudo /usr/bin/gosftpd user add alice --key "$WORK/alice.pub" --access inbox=full --write --config "$CONFIG" >/dev/null
# A mount umask (reloadable) that lets the unit's UMask= show: without it
# systemd's default umask 0022 gives 0644, and only UMask=0027 gives 0640.
sudo sed -i '/^create = true$/a umask = "0002"' "$CONFIG"
sudo systemctl reload gosftpd
check "status after a reload" status_is "configuration reloaded"
printf 'put %s up.bin\nrename up.bin final.bin\ndf\nget final.bin %s\n' "$WORK/payload" "$WORK/back" >"$WORK/upload.batch"
check "sftp upload, rename, df, download" sftp_as alice 2022 "$WORK/upload.batch"
check "the download is the upload" cmp -s "$WORK/payload" "$WORK/back"
check "the upload belongs to gosftpd, mode 0640 (UMask=0027)" \
	test "$(sudo stat -c '%U %a' /srv/sftp/inbox/final.bin)" = "gosftpd 640"
check "the audit log has the upload" sudo grep -q '"event":"fs.upload"' "$AUDIT"

phase "restart with users.d, add a user, reload"
mark=$(journal_mark)
sudo systemctl restart gosftpd
check "landlock applied after the restart" journal_has "$mark" 'landlock: ABI v[2-5] applied'
sudo /usr/bin/gosftpd user add bob --key "$WORK/bob.pub" --access inbox=read --write --config "$CONFIG" >/dev/null
sudo systemctl reload gosftpd
check "status after adding bob" status_is "configuration reloaded"
printf 'ls\n' >"$WORK/ls.batch"
check "bob logs in after the reload" sftp_as bob 2022 "$WORK/ls.batch"

phase "a disk mounted on the mount's directory: Landlock needs a restart"
# A tmpfs stands for a disk mounted on the inbox while gosftpd runs; the
# reload sees it only if it reaches the unit's mount namespace. systemd
# makes that namespace a slave of the machine's, so only a mount below a
# mount with shared propagation reaches it: on a machine systemd makes /
# shared at boot, but a container keeps the private / it was given. The
# check fails as a setup error then, instead of five checks that would
# blame gosftpd. 2 GiB, since min_free_space is 1 GiB. (With sudo: the
# inbox is gosftpd's.)
propagation=$(sudo findmnt -no PROPAGATION --target "$INBOX")
holder=$(sudo findmnt -no TARGET --target "$INBOX")
if [[ ,$propagation, != *,shared,* ]]; then
	fail "setup: $holder, the mount that holds $INBOX, has the propagation \"$propagation\", not shared: a disk mounted while gosftpd runs cannot reach the unit's mount namespace, so this phase cannot test gosftpd here (in a container, run mount --make-rshared / first)"
else
	sudo mount -t tmpfs -o "size=2g,mode=0750,uid=$(id -u gosftpd),gid=$(id -g gosftpd)" gosftpd-ci "$INBOX"
	REMOUNTED=$INBOX
	mark=$(journal_mark)
	sudo systemctl reload gosftpd
	check "status names mounts.inbox.path" status_is "configuration reloaded; restart needed for: mounts.inbox.path"
	check "server.reload: restart_required=mounts.inbox.path" last_reload_is '.restart_required == "mounts.inbox.path"'
	check "the journal says to restart" \
		journal_has "$mark" "mounts\.inbox\.path: $INBOX: outside the Landlock ruleset applied at start; restart gosftpd"
	printf 'put %s remount.bin\n' "$WORK/payload" >"$WORK/remount.batch"
	check "an upload before the restart is refused" refused sftp_as alice 2022 "$WORK/remount.batch"
	mark=$(journal_mark)
	sudo systemctl restart gosftpd
	check "landlock applied after the restart" journal_has "$mark" 'landlock: ABI v[2-5] applied'
	check "an upload after the restart" sftp_as alice 2022 "$WORK/remount.batch"
	check "it is on the tmpfs" test "$(sudo stat -f -c %T "$INBOX/remount.bin")" = tmpfs
	check "it is the upload" sudo cmp -s "$WORK/payload" "$INBOX/remount.bin"
	# Back to the inbox that the phases below use.
	sudo systemctl stop gosftpd
	sudo umount "$INBOX"
	REMOUNTED=
	check "the refused upload left nothing below the mount point" sudo test ! -e "$INBOX/remount.bin"
	sudo rm -f "$INBOX/remount.bin"
	start
fi

phase "host key rotation by reload"
as_gosftpd /usr/bin/gosftpd hostkey rotate --config "$CONFIG" >/dev/null
sudo systemctl reload gosftpd
check "status after announcing the next key" status_is "configuration reloaded"
check "server.reload: ok, restart_required empty" last_reload_is "$reload_ok"

phase "the status line after a reload that needs a restart, and a failed one"
config_with '' # the packaged file, unchanged
sudo sed -i 's/^listen = \[":2022"\]/listen = [":2023"]/' "$CONFIG"
sudo systemctl reload gosftpd
check "status names server.listen" status_is "configuration reloaded; restart needed for: server.listen"
check "systemctl status shows it" status_shown "configuration reloaded; restart needed for: server.listen"
check "server.reload: restart_required=server.listen" last_reload_is '.restart_required == "server.listen"'
config_with 'bogus = = 1'
mark=$(journal_mark)
check "systemctl reload succeeds although the reload fails" sudo systemctl reload gosftpd
check "status after a failed reload" status_is "configuration reload failed, see the log"
check "systemctl status shows it" status_shown "configuration reload failed, see the log"
check "the journal has the reason" journal_has "$mark" 'configuration reload failed'
check "server.reload: result=error" last_reload_is '.result == "error"'
config_with ''
sudo systemctl reload gosftpd
check "status after fixing the file" status_is "configuration reloaded"
check "still serving" sftp_as alice 2022 "$WORK/ls.batch"
stop_within_timeout
check "stop result success" test "$(systemctl show -p Result --value gosftpd)" = success
check "server.stop is the last audit event" last_event_is server.stop

phase "exec hooks: no Landlock, and what a hook leaves behind is killed at stop"
sudo install -d -m 0755 "$HOOKS"
# The hook starts a process in a session of its own, out of reach of the
# process group that gosftpd kills, and waits until it runs.
sudo tee "$HOOKS/spawn" >/dev/null <<'EOF'
#!/bin/sh
PATH=/usr/bin:/bin
setsid sh -c 'echo $$ >/srv/sftp/spawned.pid; exec sleep 600' </dev/null >/dev/null 2>&1 &
while [ ! -s /srv/sftp/spawned.pid ]; do sleep 0.1; done
EOF
sudo chmod 0755 "$HOOKS/spawn"
config_with '
[[hooks]]
name = "spawn"
on = ["fs.upload"]
exec = { argv = ["/usr/local/libexec/gosftpd-ci/spawn"] }'
mark=$(journal_mark)
start
check "landlock: not applied: exec hooks configured" journal_has "$mark" 'landlock: not applied.*exec hooks configured'
printf 'put %s hooked.bin\n' "$WORK/payload" >"$WORK/hook.batch"
check "upload for the hook" sftp_as alice 2022 "$WORK/hook.batch"
for _ in $(seq 50); do sudo test -s /srv/sftp/spawned.pid && break; sleep 0.2; done
child=$(sudo cat /srv/sftp/spawned.pid 2>/dev/null || true)
if [ -n "$child" ] && sudo kill -0 "$child" 2>/dev/null; then
	pass "the hook's setsid child runs (pid $child)"
	check "it is in the unit's cgroup" sudo grep -q gosftpd.service "/proc/$child/cgroup"
	stop_within_timeout
	check "systemd killed it at stop (KillMode=mixed)" gone "$child"
else
	fail "the hook's child did not start"
	sudo systemctl stop gosftpd
fi
sudo rm -f /srv/sftp/spawned.pid

phase "port 22: the capability, and hooks without it"
# Any port below 1024 needs CAP_NET_BIND_SERVICE; 22 itself may be taken by
# the runner's sshd.
sudo mkdir -p "$DROPINS"
sudo tee "$DROPINS/port22.conf" >/dev/null <<'EOF'
[Service]
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
EOF
sudo tee "$HOOKS/caps" >/dev/null <<'EOF'
#!/bin/sh
PATH=/usr/bin:/bin
grep -E '^Cap(Amb|Eff):' /proc/self/status >/srv/sftp/hook-caps.txt
EOF
sudo chmod 0755 "$HOOKS/caps"
config_with '
[[hooks]]
name = "caps"
on = ["fs.upload"]
exec = { argv = ["/usr/local/libexec/gosftpd-ci/caps"] }'
sudo sed -i 's/^listen = \[":2022"\]/listen = ["127.0.0.1:1022"]/' "$CONFIG"
sudo systemctl daemon-reload
start
pid=$(main_pid)
check "gosftpd keeps CAP_NET_BIND_SERVICE (CapEff 0x400)" test "$(proc_status "$pid" CapEff)" = 0000000000000400
check "gosftpd cleared its ambient set" test "$(proc_status "$pid" CapAmb)" = 0000000000000000
check "upload on port 1022" sftp_as alice 1022 "$WORK/hook.batch"
for _ in $(seq 50); do sudo test -s /srv/sftp/hook-caps.txt && break; sleep 0.2; done
caps=$(sudo cat /srv/sftp/hook-caps.txt 2>/dev/null || true)
check "the hook has no effective capability" grep -qx $'CapEff:\t0000000000000000' <<<"$caps"
check "the hook has no ambient capability" grep -qx $'CapAmb:\t0000000000000000' <<<"$caps"
sudo systemctl stop gosftpd
sudo rm -f "$DROPINS/port22.conf" /srv/sftp/hook-caps.txt
config_with ''

phase "a seccomp filter without the Landlock system calls"
sudo tee "$DROPINS/no-landlock.conf" >/dev/null <<'EOF'
[Service]
SystemCallFilter=
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
EOF
sudo systemctl daemon-reload
mark=$(journal_mark)
start
check "EPERM: landlock: not available: blocked by a seccomp filter" \
	journal_has "$mark" 'landlock: not available.*blocked by a seccomp filter'
check "serving" sftp_as alice 2022 "$WORK/ls.batch"
# An empty SystemCallErrorNumber= is the default action: kill.
printf 'SystemCallErrorNumber=\n' | sudo tee -a "$DROPINS/no-landlock.conf" >/dev/null
sudo systemctl daemon-reload
mark=$(journal_mark)
sudo systemctl restart gosftpd
check "kill: landlock: not available: killed by a seccomp filter" \
	journal_has "$mark" 'landlock: not available.*killed by a seccomp filter'
sleep 2
check "the unit stays active with the kill action" test "$(systemctl is-active gosftpd)" = active
check "serving with the kill action" sftp_as alice 2022 "$WORK/ls.batch"
sudo systemctl stop gosftpd
sudo rm -f "$DROPINS/no-landlock.conf"

phase "the drop-in for systemd before 253 works on 255 too"
sudo install -D -m 0644 "$PKG/systemd/legacy-notify.conf" "$DROPINS/legacy-notify.conf"
sudo systemctl daemon-reload
start
check "Type=notify with the drop-in" test "$(systemctl show -p Type --value gosftpd)" = notify
sudo systemctl reload gosftpd
check "status after a reload by kill -HUP" status_is "configuration reloaded"
sudo systemctl stop gosftpd
sudo rm -f "$DROPINS/legacy-notify.conf"
sudo systemctl daemon-reload

phase "upgrade from the interim unit of v0.3's hardening guide"
# The state an upgrader has: the binary in /usr/local/bin, the interim unit
# in /etc/systemd/system, the user's home in the state directory with the
# files useradd --create-home copied from /etc/skel.
sudo install -m 0755 "$WORK/gosftpd" /usr/local/bin/gosftpd
sudo usermod --home /var/lib/gosftpd gosftpd
mapfile -t skel < <(cd /etc/skel && find . -mindepth 1 -maxdepth 1 -printf '%P\n')
for f in "${skel[@]}"; do sudo cp -a "/etc/skel/$f" /var/lib/gosftpd/ && sudo chown -R gosftpd:gosftpd "/var/lib/gosftpd/$f"; done
sudo tee /etc/systemd/system/gosftpd.service >/dev/null <<'EOF'
[Unit]
Description=gosftpd SFTP server
After=network-online.target
Wants=network-online.target
RequiresMountsFor=/srv/sftp

[Service]
User=gosftpd
Group=gosftpd
ExecStart=/usr/local/bin/gosftpd serve --config /etc/gosftpd/config.toml
Restart=on-failure
TimeoutStopSec=45s
LimitNOFILE=65536

NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ReadWritePaths=/srv/sftp /var/lib/gosftpd /var/log/gosftpd
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectHostname=yes
ProtectClock=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
mark=$(journal_mark)
sudo systemctl start gosftpd # Type=simple: returns at once
for _ in $(seq 50); do /usr/bin/gosftpd healthcheck --address 127.0.0.1:2022 >/dev/null 2>&1 && break; sleep 0.2; done
check "the interim unit starts the new binary" /usr/bin/gosftpd healthcheck --address 127.0.0.1:2022
# Its filter has no Landlock calls and kills (no SystemCallErrorNumber=).
check "under the interim unit: landlock: not available: killed by a seccomp filter" \
	journal_has "$mark" 'landlock: not available.*killed by a seccomp filter'
check "the interim unit stays active" test "$(systemctl is-active gosftpd)" = active
check "systemctl cat shows the interim unit" unit_file_is /etc/systemd/system/gosftpd.service

# The steps of docs/install.md.
sudo systemctl disable --now gosftpd
sudo rm /etc/systemd/system/gosftpd.service
sudo systemctl daemon-reload
sudo rm /usr/local/bin/gosftpd
sudo usermod --home / gosftpd
for f in "${skel[@]}"; do sudo rm -rf "/var/lib/gosftpd/$f"; done
check "systemctl cat shows the packaged unit" unit_file_is /usr/lib/systemd/system/gosftpd.service
check "gosftpd in PATH is /usr/bin/gosftpd" test "$(command -v gosftpd)" = /usr/bin/gosftpd
mark=$(journal_mark)
start
check "landlock applied after the upgrade" journal_has "$mark" 'landlock: ABI v[2-5] applied'
# The state directory is gosftpd's own again: finishing the rotation is a
# reload, not a restart.
next_fp=$(sudo ssh-keygen -lf /var/lib/gosftpd/ssh_host_ed25519_key.next.pub | awk '{print $2}') ||
	die "no next host key to finish the rotation with"
as_gosftpd /usr/bin/gosftpd hostkey rotate --finish --config "$CONFIG" >/dev/null
sudo systemctl reload gosftpd
check "status after rotate --finish" status_is "configuration reloaded"
check "server.reload after rotate --finish: ok, restart_required empty" last_reload_is "$reload_ok"
check "the former next key is served" \
	test "$(ssh-keyscan -p 2022 -t ed25519 127.0.0.1 2>/dev/null | ssh-keygen -lf - | awk '{print $2}')" = "$next_fp"
check "alice logs in after rotate --finish" sftp_as alice 2022 "$WORK/ls.batch"

phase "stop"
stop_within_timeout
check "stop result success" test "$(systemctl show -p Result --value gosftpd)" = success
check "server.stop is the last audit event" last_event_is server.stop

echo
if [ "$FAILED" = 0 ]; then echo "all systemd checks passed"; fi
exit "$FAILED"
