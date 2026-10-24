#!/usr/bin/env bash
# The deb, rpm or Arch package on a system with systemd as PID 1, as the CI
# job "packages" runs it (ADR 0012): on the ubuntu-24.04 and
# ubuntu-24.04-arm runners themselves, and in the containers of
# test/packages/*.Dockerfile through test/packages/container.sh.
# - The install: for deb the deb block of docs/install.md (apt install,
#   systemctl enable --now, is-active, config validate --check-fs as
#   gosftpd), run in a directory gosftpd cannot read; for rpm and Arch the
#   same steps with dnf and pacman; the check again from /. Then the owners
#   and modes, the drop-in for systemd before 253 exactly where systemd
#   lacks Type=notify-reload, Landlock, a reload (deb: with procps, which
#   the package depends on), and a user added with --write and a reload
#   while /etc/gosftpd also holds a file of the administrator's, which
#   needs the package's users.d.
# - What an upgrade does to config.toml and users.d after the administrator
#   gave them another group and mode, unedited and edited, per format.
# - An upgrade, as a reinstall: installing the installed version again is
#   a no-op that runs no script. The edited configuration, the user's file,
#   the drop-in and the running process stay, its binary shown as deleted;
#   with needrestart (Ubuntu) too, and without the package's needrestart
#   file needrestart restarts it, so that the check has teeth.
# - Where systemd knows Type=notify-reload: a stand-in probe makes
#   postinstall install the drop-in, which survives the next upgrade (rpm
#   runs the old package's %postun after the new %post) and goes with the
#   upgrade after that, on the real systemd.
# - The removal: the service stopped and disabled, the drop-in deleted, the
#   data kept, and what each format keeps of the configuration.
# - The move from the archive install of docs/install.md, with an edited
#   config.toml, to the package, with the step ADR 0012 gives per format.
#
# Usage: test/packages/run.sh FORMAT DIR V
# FORMAT is deb, rpm or archlinux; DIR holds the packages, the Linux
# archives and checksums.txt of version V (goreleaser-check's artifact
# "packages"). It changes the system: it runs as root on a throwaway
# machine with systemd as PID 1, and refuses to run unless CI=true or
# GOSFTPD_PACKAGES_TEST=1.
# - EXPECT_LEGACY_DROPIN=1: this systemd lacks Type=notify-reload (Debian 12).
# - NEEDRESTART=1: needrestart is installed (the Ubuntu runners).
# - REQUIRE_LANDLOCK=1 (CI): gosftpd must log that it applied Landlock.

# Functions called through check and the EXIT trap are not unreachable.
# shellcheck disable=SC2317,SC2329
set -euo pipefail

if [ $# -ne 3 ] || ! [[ $1 =~ ^(deb|rpm|archlinux)$ ]]; then
	echo "usage: test/packages/run.sh deb|rpm|archlinux DIR V" >&2
	exit 2
fi
FORMAT=$1
DIR=$(cd "$2" && pwd)
V=$3
if [ "${CI:-}" != true ] && [ -z "${GOSFTPD_PACKAGES_TEST:-}" ]; then
	echo "test/packages/run.sh installs and removes gosftpd; run it on a throwaway machine with GOSFTPD_PACKAGES_TEST=1" >&2
	exit 2
fi
if [ "$(id -u)" != 0 ]; then
	echo "test/packages/run.sh runs as root" >&2
	exit 2
fi
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
case $(uname -m) in
x86_64) ARCH=amd64 ;;
aarch64) ARCH=arm64 ;;
*) echo "test/packages/run.sh: no package for $(uname -m)" >&2 && exit 2 ;;
esac
case $FORMAT in
deb) PKG="$DIR/gosftpd_${V}_linux_$ARCH.deb" ;;
rpm) PKG="$DIR/gosftpd_${V}_linux_$ARCH.rpm" ;;
archlinux) PKG="$DIR/gosftpd_${V}_linux_$ARCH.pkg.tar.zst" ;;
esac
ARCHIVE="$DIR/gosftpd_${V}_linux_$ARCH.tar.gz"
CONFIG=/etc/gosftpd/config.toml
DROPIN_DIR=/etc/systemd/system/gosftpd.service.d
DROPIN=$DROPIN_DIR/legacy-notify.conf
TEMPLATE=/usr/share/gosftpd/legacy-notify.conf
NEEDRESTART_CONF=/etc/needrestart/conf.d/gosftpd.conf
EDIT="# edited by test/packages/run.sh"
# A public key without its private half: the user only has to exist.
KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKc40CwB86f5D3mOHaYGvaRgRZjUGQ2S1PgHx8tRTTHV gosftpd-packages-test"
WORK=$(mktemp -d)
# The stand-in probe of the third phase, while it is installed.
STANDIN=
FAILED=0

fail() { echo "FAIL: $*" >&2; FAILED=1; }
pass() { echo "ok:   $*"; }
die() { fail "$*"; exit 1; }
phase() { printf '\n=== %s\n' "$*"; }
on_exit() {
	local status=$?
	if [ "$FAILED" != 0 ] || [ "$status" != 0 ]; then
		echo "--- journal of gosftpd.service" >&2
		journalctl -u gosftpd -n 100 --no-pager >&2 || true
	fi
	if [ -n "$STANDIN" ]; then rm -f "$STANDIN"; fi
	rm -rf "$WORK"
}
trap on_exit EXIT

# check WHAT COMMAND...: pass or fail by the command's exit status.
check() {
	local what=$1
	shift
	if "$@"; then pass "$what"; else fail "$what"; fi
}

# equal WHAT GOT WANT
equal() {
	if [ "$2" = "$3" ]; then pass "$1: $2"; else fail "$1: got \"$2\", want \"$3\""; fi
}

# owner_mode PATH: user:group and the octal mode, or "missing".
owner_mode() { stat -c '%U:%G %a' "$1" 2>/dev/null || echo missing; }
main_pid() { systemctl show -p MainPID --value gosftpd; }
status_text() { systemctl show -p StatusText --value gosftpd; }
# status_is TEXT: the status line becomes TEXT (with the legacy drop-in it
# may come a moment after systemctl reload returns).
status_is() {
	for _ in $(seq 50); do
		[ "$(status_text)" = "$1" ] && return 0
		sleep 0.2
	done
	echo "status: $(status_text)" >&2
	return 1
}
# exe PID: the binary the process runs, " (deleted)" once it was replaced.
exe() { readlink "/proc/$1/exe"; }
# absent PATH: nothing there, not even a symlink whose target is gone (an
# enablement link once the unit was removed).
absent() { [ ! -e "$1" ] && [ ! -L "$1" ]; }
# same FILE1 FILE2: both exist with the same content (EL9 has no cmp).
same() { [ -f "$1" ] && [ -f "$2" ] && [ "$(sha256sum <"$1")" = "$(sha256sum <"$2")" ]; }
user_exists() { getent passwd gosftpd >/dev/null; }
has_edit() { grep -qxF "$EDIT" "$1"; }
not_running() { ! kill -0 "$1" 2>/dev/null; }
# validate DIR: config validate --check-fs as gosftpd, run in DIR; prints
# its output.
validate() { (cd "$1" && runuser -u gosftpd -- gosftpd config validate --check-fs 2>&1); }

pkg_install() {
	case $FORMAT in
	deb) apt-get install -y -q "$@" "$PKG" ;;
	rpm) dnf install -y -q --disablerepo='*' "$PKG" ;;
	archlinux) pacman -U --noconfirm "$@" "$PKG" ;;
	esac </dev/null
}
# pkg_reinstall: the same version again, as an upgrade (the package
# managers run the upgrade scripts).
pkg_reinstall() {
	case $FORMAT in
	deb) apt-get install -y -q --reinstall "$PKG" ;;
	rpm) dnf reinstall -y -q --disablerepo='*' "$PKG" ;;
	archlinux) pacman -U --noconfirm "$PKG" ;;
	esac </dev/null
}
pkg_remove() {
	case $FORMAT in
	deb) apt-get remove -y -q gosftpd ;;
	rpm) dnf remove -y -q --disablerepo='*' gosftpd ;;
	archlinux) pacman -R --noconfirm gosftpd ;;
	esac </dev/null
}
pkg_installed() {
	case $FORMAT in
	deb) [ "$(dpkg-query -W -f='${db:Status-Abbrev}' gosftpd 2>/dev/null)" = "ii " ] ;;
	rpm) rpm -q gosftpd >/dev/null ;;
	archlinux) pacman -Q gosftpd >/dev/null ;;
	esac
}
pkg_removed() { ! pkg_installed; }
pkg_owns() {
	case $FORMAT in
	deb) dpkg -S "$1" >/dev/null ;;
	rpm) rpm -qf "$1" >/dev/null ;;
	archlinux) pacman -Qo "$1" >/dev/null ;;
	esac
}

# landlock: the journal of the service's current run says that gosftpd
# applied Landlock; without REQUIRE_LANDLOCK a kernel without it only skips.
landlock() {
	local log
	log=$(journalctl -o cat --no-pager _SYSTEMD_INVOCATION_ID="$(systemctl show -p InvocationID --value gosftpd)" 2>/dev/null || true)
	if grep -q 'landlock: ABI v[0-9]* applied' <<<"$log"; then
		pass "$(grep -o 'landlock: ABI v[0-9]* applied' <<<"$log" | tail -n 1)"
	elif [ -z "${REQUIRE_LANDLOCK:-}" ] && grep -q 'landlock: not available' <<<"$log"; then
		echo "skip: $(grep -o 'landlock: not available.*' <<<"$log" | tail -n 1 | tr -d '"')"
	else
		fail "no Landlock ruleset: $(grep landlock <<<"$log" | tail -n 3)"
	fi
}

# dropin_expected: the drop-in is where this systemd needs it.
dropin_expected() {
	if [ -n "${EXPECT_LEGACY_DROPIN:-}" ]; then
		check "the drop-in for systemd before 253 is installed" same "$TEMPLATE" "$DROPIN"
		equal "the service type" "$(systemctl show -p Type --value gosftpd)" notify
	else
		check "no drop-in for systemd before 253" absent "$DROPIN_DIR"
		equal "the service type" "$(systemctl show -p Type --value gosftpd)" notify-reload
	fi
}

# running PID: gosftpd is active and its main process is still PID.
running() {
	equal "is-active" "$(systemctl is-active gosftpd || true)" active
	equal "the main process" "$(main_pid)" "$1"
}

phase "the system"
[ -d /run/systemd/system ] || die "systemd is not PID 1 here"
systemctl --version | sed -n 1p
echo "cgroup file system: $(stat -fc %T /sys/fs/cgroup)"
[ -f "$PKG" ] || die "no package $PKG"
[ -f "$ARCHIVE" ] || die "no archive $ARCHIVE"
check "gosftpd is not installed yet" absent /usr/bin/gosftpd

phase "install, enable and start"
# A directory that gosftpd cannot read, as root's home is: config
# validate looks for ./gosftpd.toml there first.
home=$(mktemp -d /root/gosftpd-packages.XXXXXX)
cp "$PKG" "$DIR/checksums.txt" "$home/"
if [ "$FORMAT" = deb ]; then
	(cd "$home" && V=$V "$ROOT/test/docs/run-block.sh" deb) || die "the deb block of docs/install.md failed"
	pass "the deb block of docs/install.md, run in $home"
else
	(cd "$home" && pkg_install) || die "the package did not install"
	systemctl enable --now gosftpd || die "systemctl enable --now gosftpd"
	equal "is-active" "$(systemctl is-active gosftpd || true)" active
fi
check "the package is installed" pkg_installed
users=0
for d in / "$home"; do
	if out=$(validate "$d"); then
		equal "config validate --check-fs as gosftpd, from $d" "$(tail -n 1 <<<"$out")" "$CONFIG: OK (1 mounts, $users users)"
	else
		fail "config validate --check-fs as gosftpd, from $d: $out"
	fi
done
user=$(getent passwd gosftpd || true)
IFS=: read -r _ _ uid _ _ dir shell <<<"$user"
check "the user gosftpd is a system user with the home / and no login shell: $user" \
	test -n "$user" -a "${uid:-1000}" -lt 1000 -a "$dir" = / -a "${shell##*/}" = nologin
equal "$CONFIG" "$(owner_mode "$CONFIG")" "root:gosftpd 640"
equal "/etc/gosftpd/users.d" "$(owner_mode /etc/gosftpd/users.d)" "root:gosftpd 750"
equal "/srv/sftp" "$(owner_mode /srv/sftp)" "gosftpd:gosftpd 750"
equal "/var/log/gosftpd" "$(owner_mode /var/log/gosftpd)" "gosftpd:gosftpd 750"
equal "/var/lib/gosftpd" "$(owner_mode /var/lib/gosftpd)" "gosftpd:gosftpd 700"
equal "enabled" "$(systemctl is-enabled gosftpd || true)" enabled
dropin_expected
landlock
if [ "$FORMAT" = deb ]; then
	equal "procps, which the deb depends on" "$(dpkg-query -W -f='${db:Status-Abbrev}' procps 2>/dev/null || true)" "ii "
fi

phase "reload, and a user added with --write"
check "systemctl reload" systemctl reload gosftpd
check "the status is \"configuration reloaded\"" status_is "configuration reloaded"
# With a file of the administrator's in /etc/gosftpd, the directory is not
# gosftpd's own, and Landlock covers only the include directories that
# exist at the start (ADR 0011): without the package's users.d, the reload
# after the first user add --write fails until a restart.
echo "# the administrator's notes" >/etc/gosftpd/NOTES
systemctl restart gosftpd || die "systemctl restart gosftpd"
gosftpd user add partner --key "$KEY" --access inbox=upload --write --config "$CONFIG" >/dev/null
users=1
equal "users.d/partner.toml" "$(owner_mode /etc/gosftpd/users.d/partner.toml)" "root:gosftpd 640"
check "systemctl reload with the new user" systemctl reload gosftpd
check "the status is \"configuration reloaded\"" status_is "configuration reloaded"
rm /etc/gosftpd/NOTES
out=$(validate /) || fail "config validate --check-fs as gosftpd: $out"
equal "config validate with the user" "$(tail -n 1 <<<"$out")" "$CONFIG: OK (1 mounts, 1 users)"

phase "upgrade: another group and mode on the configuration"
# What ADR 0012 and docs/install.md state: deb keeps a changed owner, group
# and mode; rpm puts root:root 0750 back on users.d at every upgrade or
# reinstall, and rpm and pacman put root:root 0640 back on an unedited
# config.toml; postinstall then gives them the group gosftpd. An edited
# config.toml keeps its owner, group and mode.
USERS_D=/etc/gosftpd/users.d
cp -p "$CONFIG" "$WORK/config.toml"
groupadd -r sftpadmins
admin_group() {
	chgrp sftpadmins "$CONFIG" "$USERS_D"
	chmod 2770 "$USERS_D"
}
case $FORMAT in
deb) config_kept="root:sftpadmins 640" users_d_kept="root:sftpadmins 2770" ;;
rpm) config_kept="root:gosftpd 640" users_d_kept="root:gosftpd 750" ;;
archlinux) config_kept="root:gosftpd 640" users_d_kept="root:sftpadmins 2770" ;;
esac
admin_group
pkg_reinstall || die "the reinstall failed"
equal "an upgrade, $CONFIG unedited" "$(owner_mode "$CONFIG")" "$config_kept"
equal "an upgrade, $USERS_D" "$(owner_mode "$USERS_D")" "$users_d_kept"
echo "$EDIT" >>"$CONFIG"
admin_group
pkg_reinstall || die "the reinstall failed"
equal "an upgrade, $CONFIG edited" "$(owner_mode "$CONFIG")" "root:sftpadmins 640"
equal "an upgrade, $USERS_D" "$(owner_mode "$USERS_D")" "$users_d_kept"
# The package's configuration and owners again ("00": GNU chmod keeps the
# setgid bit of a directory otherwise).
cat "$WORK/config.toml" >"$CONFIG"
chgrp gosftpd "$CONFIG" "$USERS_D"
chmod 00750 "$USERS_D"
groupdel sftpadmins
equal "$CONFIG" "$(owner_mode "$CONFIG")" "root:gosftpd 640"
equal "$USERS_D" "$(owner_mode "$USERS_D")" "root:gosftpd 750"

phase "upgrade: the same package again"
echo "$EDIT" >>"$CONFIG"
pid=$(main_pid)
if [ -n "${NEEDRESTART:-}" ]; then
	equal "needrestart" "$(dpkg-query -W -f='${db:Status-Abbrev}' needrestart 2>/dev/null || true)" "ii "
	check "$NEEDRESTART_CONF is installed" test -f "$NEEDRESTART_CONF"
fi
pkg_reinstall || die "the reinstall failed"
check "the package is installed" pkg_installed
running "$pid"
# The scripts did not restart gosftpd, and it runs the replaced binary:
# needrestart, where it is installed, had a reason to restart it.
equal "the binary of the running gosftpd" "$(exe "$pid")" "/usr/bin/gosftpd (deleted)"
check "$CONFIG keeps the edit" has_edit "$CONFIG"
equal "$CONFIG" "$(owner_mode "$CONFIG")" "root:gosftpd 640"
check "users.d/partner.toml stays" test -f /etc/gosftpd/users.d/partner.toml
equal "enabled" "$(systemctl is-enabled gosftpd || true)" enabled
dropin_expected
if [ -n "${NEEDRESTART:-}" ]; then
	mv "$NEEDRESTART_CONF" "$WORK/needrestart.conf"
	pkg_reinstall || die "the reinstall without $NEEDRESTART_CONF failed"
	mv "$WORK/needrestart.conf" "$NEEDRESTART_CONF"
	new=$(main_pid)
	check "without $NEEDRESTART_CONF, needrestart restarted gosftpd ($pid, now $new)" test "$new" != "$pid" -a "$new" != 0
	equal "is-active" "$(systemctl is-active gosftpd || true)" active
fi
# The operator restarts gosftpd after an upgrade.
systemctl restart gosftpd || die "systemctl restart gosftpd"
pid=$(main_pid)
running "$pid"
equal "the binary after the restart" "$(exe "$pid")" /usr/bin/gosftpd
landlock
check "systemctl reload" systemctl reload gosftpd
check "the status is \"configuration reloaded\"" status_is "configuration reloaded"

if [ -z "${EXPECT_LEGACY_DROPIN:-}" ]; then
	phase "upgrades and the drop-in, where systemd knows Type=notify-reload"
	# Where postinstall looks for systemd-analyze first: apt runs dpkg with
	# PATH=/usr/sbin:/usr/bin:/sbin:/bin (DPkg::Path) and rpm its scripts
	# with PATH=/sbin:/bin:/usr/sbin:/usr/bin, where /sbin is /usr/sbin;
	# pacman passes this script's PATH on, and on Arch /usr/sbin is /usr/bin.
	if [ "$FORMAT" = archlinux ]; then STANDIN=/usr/local/sbin/systemd-analyze; else STANDIN=/usr/sbin/systemd-analyze; fi
	check "nothing at $STANDIN yet" absent "$STANDIN"
	real=$(command -v systemd-analyze)
	[ "$real" != "$STANDIN" ] || die "systemd-analyze is $STANDIN"
	printf '#!/bin/sh\n# test/packages/run.sh: systemd before 253, for the probe of postinstall.\n"%s" "$@"\necho "gosftpd-probe.service:4: Failed to parse service type, ignoring: notify-reload" >&2\n' "$real" >"$STANDIN"
	chmod 0755 "$STANDIN"
	export PATH="${STANDIN%/*}:$PATH"
	pkg_reinstall || die "the reinstall with the stand-in probe failed"
	check "postinstall installed the drop-in for the stand-in probe" same "$TEMPLATE" "$DROPIN"
	equal "the service type" "$(systemctl show -p Type --value gosftpd)" notify
	pkg_reinstall || die "the second reinstall with the stand-in probe failed"
	# rpm: the new %post installs the drop-in, then the old %postun runs.
	check "the next upgrade keeps the drop-in" same "$TEMPLATE" "$DROPIN"
	rm "$STANDIN"
	STANDIN=
	pkg_reinstall || die "the reinstall without the stand-in probe failed"
	check "the upgrade on the real systemd removed the drop-in and its directory" absent "$DROPIN_DIR"
	equal "the service type" "$(systemctl show -p Type --value gosftpd)" notify-reload
	running "$pid"
fi

phase "removal"
# A drop-in to delete: postinstall's on systemd before 253, else one put
# there by hand.
if [ ! -e "$DROPIN" ]; then
	install -D -m 0644 "$TEMPLATE" "$DROPIN"
	systemctl daemon-reload
fi
echo kept >/srv/sftp/inbox/kept.txt
pkg_remove || die "the removal failed"
check "the package is removed" pkg_removed
check "gosftpd stopped" not_running "$pid"
equal "is-active" "$(systemctl is-active gosftpd || true)" inactive
check "the unit is gone" absent /usr/lib/systemd/system/gosftpd.service
check "the binary is gone" absent /usr/bin/gosftpd
check "the service is not enabled" absent /etc/systemd/system/multi-user.target.wants/gosftpd.service
check "the drop-in and its directory are gone" absent "$DROPIN_DIR"
# The package's own directories: rpm removes only those it lists.
for d in /usr/share/gosftpd /usr/share/doc/gosftpd; do
	check "$d is gone" absent "$d"
done
for f in /var/lib/gosftpd/ssh_host_ed25519_key /srv/sftp/inbox/kept.txt /var/log/gosftpd/audit.jsonl /etc/gosftpd/users.d/partner.toml; do
	check "$f stays" test -f "$f"
done
check "the user gosftpd stays" user_exists
case $FORMAT in
deb)
	check "apt remove keeps $CONFIG" has_edit "$CONFIG"
	check "and $NEEDRESTART_CONF" test -f "$NEEDRESTART_CONF"
	apt-get purge -y -q gosftpd </dev/null || die "apt purge failed"
	check "apt purge deletes $CONFIG" absent "$CONFIG"
	check "and $NEEDRESTART_CONF" absent "$NEEDRESTART_CONF"
	# dpkg warns that the directory is not empty and keeps it.
	check "apt purge keeps users.d/partner.toml" test -f /etc/gosftpd/users.d/partner.toml
	;;
rpm)
	check "$CONFIG is gone" absent "$CONFIG"
	check "the edited configuration is $CONFIG.rpmsave" has_edit "$CONFIG.rpmsave"
	;;
archlinux)
	check "$CONFIG is gone" absent "$CONFIG"
	check "the edited configuration is $CONFIG.pacsave" has_edit "$CONFIG.pacsave"
	;;
esac

phase "from the archive install to the package"
# What the removal left in /etc/gosftpd; the user, the host key and the
# data stay, as on a host that ran the archive install.
rm -rf /etc/gosftpd
mkdir "$WORK/archive"
tar -xzf "$ARCHIVE" -C "$WORK/archive"
(
	# The commands of the Install section of docs/install.md.
	cd "$WORK/archive"
	install -m 0755 gosftpd /usr/bin/gosftpd
	install -m 0644 packaging/systemd/gosftpd.service /usr/lib/systemd/system/gosftpd.service
	install -m 0644 packaging/gosftpd.sysusers /usr/lib/sysusers.d/gosftpd.conf
	install -m 0644 packaging/gosftpd.tmpfiles /usr/lib/tmpfiles.d/gosftpd.conf
	systemd-sysusers gosftpd.conf
	systemd-tmpfiles --create gosftpd.conf
	install -d -m 0755 /etc/gosftpd
	install -m 0640 -g gosftpd packaging/config.toml "$CONFIG"
	d=$(mktemp -d)
	printf '[Unit]\nDefaultDependencies=no\n[Service]\nType=notify-reload\nExecStart=/bin/true\n' >"$d/gosftpd-probe.service"
	if systemd-analyze verify --man=no "$d/gosftpd-probe.service" 2>&1 | grep -q 'Failed to parse service type'; then
		install -D -m 0644 packaging/systemd/legacy-notify.conf "$DROPIN"
	else
		rm -f "$DROPIN"
	fi
	rm -r "$d"
	systemctl daemon-reload
)
echo "$EDIT" >>"$CONFIG"
systemctl enable --now gosftpd || die "the archive install did not start"
pid=$(main_pid)
running "$pid"
case $FORMAT in
deb)
	# An edited configuration that no package owns: without
	# --force-confold dpkg asks, and fails without a terminal.
	apt-get -o Dpkg::Options::=--force-confold install -y -q "$PKG" </dev/null ||
		die "apt-get -o Dpkg::Options::=--force-confold install failed"
	new=$CONFIG.dpkg-dist
	;;
rpm)
	pkg_install || die "the package did not install over the archive install"
	new=$CONFIG.rpmnew
	;;
archlinux)
	pkg_install --overwrite /usr/bin/gosftpd --overwrite /usr/lib/systemd/system/gosftpd.service \
		--overwrite /usr/lib/sysusers.d/gosftpd.conf --overwrite /usr/lib/tmpfiles.d/gosftpd.conf ||
		die "pacman -U --overwrite failed"
	new=$CONFIG.pacnew
	;;
esac
check "the package is installed and configured" pkg_installed
for f in /usr/bin/gosftpd /usr/lib/systemd/system/gosftpd.service /usr/lib/sysusers.d/gosftpd.conf /usr/lib/tmpfiles.d/gosftpd.conf; do
	check "the package owns $f" pkg_owns "$f"
done
check "$CONFIG keeps the edit" has_edit "$CONFIG"
equal "$CONFIG" "$(owner_mode "$CONFIG")" "root:gosftpd 640"
check "the package's configuration is $new" same "$WORK/archive/packaging/config.toml" "$new"
equal "/etc/gosftpd/users.d" "$(owner_mode /etc/gosftpd/users.d)" "root:gosftpd 750"
running "$pid"
dropin_expected
systemctl restart gosftpd || die "systemctl restart gosftpd"
running "$(main_pid)"
landlock
out=$(validate /) || fail "config validate --check-fs as gosftpd: $out"
equal "config validate" "$(tail -n 1 <<<"$out")" "$CONFIG: OK (1 mounts, 0 users)"

if [ "$FAILED" != 0 ]; then
	echo "test/packages/run.sh: FAILED" >&2
fi
exit "$FAILED"
