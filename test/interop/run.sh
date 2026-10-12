#!/usr/bin/env bash
# Interop test: real OpenSSH sftp, scp and ssh clients against a freshly
# built gosftpd. Usage: test/interop/run.sh (from anywhere). Needs bash,
# openssh-client and Go. KEEP_WORK=1 keeps the work directory for inspection.
#
# paramiko, rclone and lftp are tested when available (PYTHON with paramiko,
# RCLONE, lftp in PATH); REQUIRE_CLIENTS=1 makes a missing one a failure.
#
# On Linux every server applies Landlock (ADR 0011), so each layout below
# keeps what a reload reads in a directory of its own (docs/security.md).
# A kernel without Landlock skips the Landlock checks; REQUIRE_LANDLOCK=1
# makes that a failure.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
PIDS=()
FAILED=0

cleanup() {
	for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
	wait 2>/dev/null || true
	[ -n "${KEEP_WORK:-}" ] || rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; FAILED=1; }
pass() { echo "ok:   $*"; }
missing() { # missing CLIENT: skip, or fail with REQUIRE_CLIENTS=1
	if [ -n "${REQUIRE_CLIENTS:-}" ]; then fail "$1 is not installed"; else echo "skip: $1 is not installed"; fi
}
PYTHON=${PYTHON:-python3}
RCLONE=${RCLONE:-rclone}

# With GOCOVERDIR set, the binary records coverage there (ROADMAP §8.5), in
# the atomic mode that unit tests with -race use, so that both merge.
COVER=()
if [ -n "${GOCOVERDIR:-}" ]; then COVER=(-cover -covermode=atomic -coverpkg=./...); fi
# Without cgo, as the release binaries are: Landlock then reaches every
# thread through syscall.AllThreadsSyscall.
(cd "$ROOT" && CGO_ENABLED=0 go build "${COVER[@]}" -o "$WORK/gosftpd" ./cmd/gosftpd)
# gosftpd refuses to run as root; containers often are root.
ROOT_FLAG=()
if [ "$(id -u)" = 0 ]; then ROOT_FLAG=(--allow-root); fi
ssh-keygen -q -t ed25519 -N '' -f "$WORK/id_ed25519"
mkdir -p "$WORK/local"
head -c 3000000 /dev/urandom >"$WORK/local/upload.bin"
printf 'short' >"$WORK/local/short.txt"
touch -d '2020-01-02 03:04:05' "$WORK/local/upload.bin"

# landlock_logged NAME LOG [WANT]: the server's log says that Landlock was
# applied, or WANT. It waits for the line: the listeners accept before
# the sandbox step has logged.
landlock_logged() {
	local name=$1 log=$2 want=${3:-landlock: ABI v[2-5] applied}
	for _ in $(seq 100); do
		grep -q 'landlock: \(ABI v[0-9]* applied\|not applied\|not available\|failed\)' "$log" && break
		sleep 0.1
	done
	if grep -q "$want" "$log"; then
		pass "$name: $(grep -o "$want" "$log" | head -n 1)"
	elif [ -z "${REQUIRE_LANDLOCK:-}" ] && grep -q 'landlock: not available' "$log"; then
		echo "skip: $name: $(grep -o 'landlock: not available.*' "$log" | head -n 1)"
	else
		fail "$name: no \"$want\" in the log: $(grep landlock "$log" | head -n 3)"
	fi
}

# start_server NAME POLICY: serves $WORK/NAME on a free port, sets PORT.
# The audit log has a directory of its own, so that it can be rotated by
# rename under Landlock.
start_server() {
	local name=$1 policy=$2
	mkdir -p "$WORK/$name/share" "$WORK/$name/outside" "$WORK/$name/state" "$WORK/$name/audit"
	printf 'original content that is longer than the upload\n' >"$WORK/$name/share/a.txt"
	printf 'secret\n' >"$WORK/$name/outside/secret.txt"
	ln -s ../outside "$WORK/$name/share/evil"
	PORT=$((20000 + RANDOM % 20000))
	"$WORK/gosftpd" serve --dir "$WORK/$name/share" --on-conflict "$policy" \
		--authorized-keys "$WORK/id_ed25519.pub" --state-dir "$WORK/$name/state" \
		--listen "127.0.0.1:$PORT" --audit-output "$WORK/$name/audit/audit.jsonl" "${ROOT_FLAG[@]}" \
		2>"$WORK/$name/server.log" &
	PIDS+=($!)
	for _ in $(seq 100); do
		if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then break; fi
		sleep 0.1
	done
	landlock_logged "$name" "$WORK/$name/server.log"
	"$WORK/gosftpd" hostkey show --state-dir "$WORK/$name/state" --known-hosts "127.0.0.1:$PORT" |
		tail -n 1 >"$WORK/$name/known_hosts"
	OPTS=(-o "UserKnownHostsFile=$WORK/$name/known_hosts" -o StrictHostKeyChecking=yes
		-o IdentitiesOnly=yes -o BatchMode=yes -i "$WORK/id_ed25519")
}

# --- on_conflict=rename: sftp batch -------------------------------------
start_server rename rename
S="$WORK/rename/share"
cat >"$WORK/basic.batch" <<BATCH
pwd
ls
put $WORK/local/upload.bin upload.bin
get upload.bin $WORK/local/download.bin
put $WORK/local/upload.bin a.txt
put -p $WORK/local/upload.bin a.txt
mkdir dir
rename upload.bin dir/moved.bin
ls dir
rm dir/moved.bin
rmdir dir
-get evil/secret.txt $WORK/local/stolen.txt
-reput $WORK/local/short.txt a.txt
-ln -s /etc etc
-ln a.txt hard
BATCH
if sftp -P "$PORT" "${OPTS[@]}" -b "$WORK/basic.batch" alice@127.0.0.1 >"$WORK/transcript.txt" 2>&1; then
	pass "sftp -b basic.batch"
else
	fail "sftp -b basic.batch"; cat "$WORK/transcript.txt" >&2
fi
cmp -s "$WORK/local/upload.bin" "$WORK/local/download.bin" && pass "get returns the uploaded bytes" || fail "download differs"
[ "$(head -c 16 "$S/a.txt")" = "original content" ] && pass "original kept on conflict" || fail "original changed"
cmp -s "$WORK/local/upload.bin" "$S/a (1).txt" && pass "conflict upload went to 'a (1).txt'" || fail "'a (1).txt' missing or wrong"
[ "$(stat -c %Y "$S/a (2).txt")" = "$(stat -c %Y "$WORK/local/upload.bin")" ] &&
	pass "put -p sets mtime on the copy" || fail "put -p mtime not applied to the copy"
[ ! -e "$WORK/local/stolen.txt" ] && pass "symlink escape refused" || fail "file read through a symlink escape"
[ ! -e "$S/a (3).txt" ] && pass "reput refused without creating files" || fail "reput created a file"
[ ! -e "$S/etc" ] && [ ! -e "$S/hard" ] && pass "ln and ln -s refused" || fail "link created"
if grep -qF -e "$S" -e "$WORK/rename/outside" "$WORK/transcript.txt"; then
	fail "host path leaked to the client"; grep -F -e "$S" -e "$WORK/rename/outside" "$WORK/transcript.txt" >&2
else
	pass "no host paths in client output"
fi

# --- scp ----------------------------------------------------------------
scp -q -P "$PORT" "${OPTS[@]}" "$WORK/local/upload.bin" alice@127.0.0.1:scp.bin && pass "scp put exits 0" || fail "scp put"
scp -q -P "$PORT" "${OPTS[@]}" alice@127.0.0.1:scp.bin "$WORK/local/scp-down.bin" && pass "scp get exits 0" || fail "scp get"
cmp -s "$WORK/local/upload.bin" "$WORK/local/scp-down.bin" && pass "scp round trip" || fail "scp round trip differs"

# --- no shell, no exec ----------------------------------------------------
if ssh -p "$PORT" "${OPTS[@]}" alice@127.0.0.1 id >/dev/null 2>&1; then fail "exec allowed"; else pass "exec refused"; fi

# --- audit ----------------------------------------------------------------
A="$WORK/rename/audit"
for ev in conn.accept auth.success session.start fs.upload fs.download fs.rename fs.denied session.end; do
	grep -q "\"event\":\"$ev\"" "$A/audit.jsonl" && pass "audit has $ev" || fail "audit lacks $ev"
done

# --- signals: HUP reloads and reopens the audit log, TERM exits cleanly ----
RENAME_PID=${PIDS[0]}
mv "$A/audit.jsonl" "$A/audit.jsonl.1" # as logrotate does
kill -HUP "$RENAME_PID"
for _ in $(seq 100); do
	if grep -q '"event":"server.reload"' "$A/audit.jsonl" 2>/dev/null; then break; fi
	sleep 0.1
done
kill -0 "$RENAME_PID" 2>/dev/null && pass "SIGHUP does not stop the server" || fail "SIGHUP stopped the server"
grep -q '"event":"server.reload".*"result":"ok"' "$A/audit.jsonl" 2>/dev/null &&
	pass "SIGHUP reloads and reopens the audit log" || fail "no server.reload in the reopened audit log"
kill -TERM "$RENAME_PID"
if wait "$RENAME_PID"; then pass "SIGTERM exits 0"; else fail "SIGTERM exit code $?"; fi
grep -q '"event":"server.stop"' "$A/audit.jsonl" && pass "audit has server.stop" || fail "audit lacks server.stop"

# --- on_conflict=overwrite: scp over a longer file must not keep its tail --
start_server overwrite overwrite
OVERWRITE_PORT=$PORT
scp -q -P "$PORT" "${OPTS[@]}" "$WORK/local/short.txt" alice@127.0.0.1:a.txt && pass "scp overwrite exits 0" || fail "scp overwrite"
cmp -s "$WORK/local/short.txt" "$WORK/overwrite/share/a.txt" &&
	pass "scp overwrite gives an identical file" || fail "scp overwrite left stale bytes: $(od -c "$WORK/overwrite/share/a.txt" | head -3)"

# --- configuration file: users with read, upload and full access ----------
# The configuration, users.d, the CA file and the revocation list live in
# $CE, a directory of their own (ADR 0011): under Landlock its rule covers
# the files that sed -i, user add --write and the steps below replace or
# add. Scratch files and server.log stay in $C.
C="$WORK/cfg"
CE="$C/etc"
mkdir -p "$C/public" "$C/inbox" "$C/state" "$CE/users.d"
printf 'public file\n' >"$C/public/readme.txt"
printf 'existing report\n' >"$C/inbox/report.txt"
printf 'existing document\n' >"$C/inbox/doc.bin"
for u in reader partner admin; do ssh-keygen -q -t ed25519 -N '' -C "$u" -f "$WORK/id_$u"; done
COURIER_PASSWORD='correct horse battery staple'
COURIER_HASH=$(printf '%s\n' "$COURIER_PASSWORD" | "$WORK/gosftpd" user hash-password --stdin)
printf '#!/bin/sh\necho "%s"\n' "$COURIER_PASSWORD" >"$WORK/askpass"; chmod 700 "$WORK/askpass"
PORT=$((20000 + RANDOM % 20000))
while [ "$PORT" = "$OVERWRITE_PORT" ] || [ $((PORT + 1)) = "$OVERWRITE_PORT" ]; do PORT=$((PORT + 2)); done
MPORT=$((PORT + 1)) # the admin listener
cat >"$CE/gosftpd.toml" <<TOML
config_version = 1
include = ["users.d/*.toml"]

[server]
listen = ["127.0.0.1:$PORT"]
host_keys = ["$C/state/host_key"]
host_key_auto_generate = true

[mounts.public]
path = "$C/public"
read_only = true

[mounts.inbox]
path = "$C/inbox"

[mounts.home]
path = "$C/home/{user}"
create = true

[mounts.synced]
path = "$C/synced"
create = true
on_conflict = "version"
versions = { keep = 3 }

[mounts.atomic]
path = "$C/atomic"
create = true
atomic_uploads = true

[users.reader]
authorized_keys = ["$(cat "$WORK/id_reader.pub")"]
access = { public = "read" }

[users.partner]
authorized_keys_file = "$WORK/id_partner.pub"
access = { inbox = "upload" }

[users.admin]
authorized_keys = ["$(cat "$WORK/id_admin.pub")"]
access = { public = "read", inbox = "full", home = "full", synced = "full", atomic = "full" }

[users.courier]
password_hash = "$COURIER_HASH"
access = { inbox = "upload" }

[auth]
methods = ["publickey", "password"]

[audit]
output = "$C/audit.jsonl"

[metrics]
listen = "127.0.0.1:$MPORT"
TOML
chmod 600 "$CE/gosftpd.toml"
"$WORK/gosftpd" config validate --check-fs --config "$CE/gosftpd.toml" >/dev/null && pass "config validate --check-fs" || fail "config validate"
sed 's/^read_only = true/read_onyl = true/' "$CE/gosftpd.toml" >"$C/typo.toml"; chmod 600 "$C/typo.toml"
set +e; "$WORK/gosftpd" config validate --config "$C/typo.toml" 2>"$C/typo.err" >/dev/null; code=$?; set -e
[ "$code" = 2 ] && grep -q 'unknown key mounts.public.read_onyl' "$C/typo.err" &&
	pass "typo in a key: exit 2 naming the key" || fail "typo: exit $code: $(cat "$C/typo.err")"

"$WORK/gosftpd" serve --config "$CE/gosftpd.toml" "${ROOT_FLAG[@]}" 2>"$C/server.log" &
CFG_PID=$!
PIDS+=("$CFG_PID")
for _ in $(seq 100); do
	if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then break; fi
	sleep 0.1
done
landlock_logged config "$C/server.log"
"$WORK/gosftpd" hostkey show --host-key "$C/state/host_key" --known-hosts "127.0.0.1:$PORT" | tail -n 1 >"$C/known_hosts"
as() { # as USER: sftp/scp options for USER
	echo -o "UserKnownHostsFile=$C/known_hosts" -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -o BatchMode=yes -i "$WORK/id_$1"
}

# reader: the only mount is "/", downloads work, uploads do not.
cat >"$C/reader.batch" <<BATCH
get readme.txt $C/readme.got
-put $WORK/local/short.txt new.txt
BATCH
# shellcheck disable=SC2046
sftp -P "$PORT" $(as reader) -b "$C/reader.batch" reader@127.0.0.1 >"$C/reader.out" 2>&1 && pass "reader: sftp batch" || { fail "reader batch"; cat "$C/reader.out" >&2; }
cmp -s "$C/public/readme.txt" "$C/readme.got" && pass "reader: download" || fail "reader: download"
[ ! -e "$C/public/new.txt" ] && grep -q 'Permission denied' "$C/reader.out" && pass "reader: upload denied" || fail "reader: upload not denied"

# partner (upload): new files and renamed copies, no download, no delete.
head -c 1000000 "$WORK/local/upload.bin" >"$WORK/local/half.bin"
cat >"$C/partner.batch" <<BATCH
put $WORK/local/short.txt new.txt
put $WORK/local/short.txt report.txt
-get report.txt $C/report.got
-rm report.txt
put $WORK/local/half.bin part.bin
reput $WORK/local/upload.bin part.bin
put $WORK/local/half.bin doc.bin
reput $WORK/local/upload.bin doc.bin
df -h
ls -l
BATCH
# shellcheck disable=SC2046
sftp -P "$PORT" $(as partner) -b "$C/partner.batch" partner@127.0.0.1 >"$C/partner.out" 2>&1 && pass "partner: sftp batch" || { fail "partner batch"; cat "$C/partner.out" >&2; }
cmp -s "$WORK/local/short.txt" "$C/inbox/new.txt" && pass "partner: upload" || fail "partner: upload"
grep -q 'existing report' "$C/inbox/report.txt" && cmp -s "$WORK/local/short.txt" "$C/inbox/report (1).txt" &&
	pass "partner: conflict kept the original" || fail "partner: conflict"
[ ! -e "$C/report.got" ] && [ -e "$C/inbox/report.txt" ] && pass "partner: download and delete denied" || fail "partner: read or delete allowed"
cmp -s "$WORK/local/upload.bin" "$C/inbox/part.bin" && pass "partner: reput completes a partial upload" || fail "partner: reput result differs"
cmp -s "$WORK/local/upload.bin" "$C/inbox/doc (1).bin" && grep -qx 'existing document' "$C/inbox/doc.bin" &&
	pass "partner: reput after a renamed put completes the copy" || fail "partner: reput after a renamed put: $(ls -l "$C/inbox")"
grep -q 'Avail' "$C/partner.out" && pass "df -h works (statvfs)" || fail "df -h: $(grep -A2 'df -h' "$C/partner.out")"
grep -Eq ' partner +partner ' "$C/partner.out" && ! grep -q " $(id -un) " "$C/partner.out" &&
	pass "ls -l shows virtual owners" || fail "ls -l owners: $(grep -A3 'ls -l' "$C/partner.out")"
# DoD M2: scp into an upload mount works without error messages (FSETSTAT size).
# shellcheck disable=SC2046
if scp -q -P "$PORT" $(as partner) "$WORK/local/upload.bin" partner@127.0.0.1:report.txt 2>"$C/scp.err" && [ ! -s "$C/scp.err" ]; then
	pass "partner: scp exits 0 without messages"
else
	fail "partner: scp: $(cat "$C/scp.err")"
fi
cmp -s "$WORK/local/upload.bin" "$C/inbox/report (2).txt" && pass "partner: scp went to a copy" || fail "partner: scp copy"

# admin: several mounts under /, a personal home created on login.
cat >"$C/admin.batch" <<BATCH
ls /
put $WORK/local/short.txt /home/notes.txt
rm /inbox/new.txt
BATCH
# shellcheck disable=SC2046
sftp -P "$PORT" $(as admin) -b "$C/admin.batch" admin@127.0.0.1 >"$C/admin.out" 2>&1 && pass "admin: sftp batch" || { fail "admin batch"; cat "$C/admin.out" >&2; }
grep -q 'home' "$C/admin.out" && grep -q 'inbox' "$C/admin.out" && grep -q 'public' "$C/admin.out" && pass "admin: sees the mounts" || fail "admin: mounts"
cmp -s "$WORK/local/short.txt" "$C/home/admin/notes.txt" && pass "admin: home created" || fail "admin: home"
[ ! -e "$C/inbox/new.txt" ] && pass "admin: delete" || fail "admin: delete"

# on_conflict=version: the replaced file is kept in the unlisted .versions.
cat >"$C/versions.batch" <<BATCH
put $WORK/local/short.txt /synced/doc.txt
put $WORK/local/upload.bin /synced/doc.txt
ls -a /synced
ls /synced/.versions/doc.txt
-rm /synced/.versions/doc.txt/*
BATCH
# shellcheck disable=SC2046
sftp -P "$PORT" $(as admin) -b "$C/versions.batch" admin@127.0.0.1 >"$C/versions.out" 2>&1 && pass "version: sftp batch" || { fail "version batch"; cat "$C/versions.out" >&2; }
VERSIONS=("$C"/synced/.versions/doc.txt/doc.*.txt)
cmp -s "$WORK/local/upload.bin" "$C/synced/doc.txt" && [ "${#VERSIONS[@]}" = 1 ] && cmp -s "$WORK/local/short.txt" "${VERSIONS[0]}" &&
	pass "version: new content under the name, old one kept" || fail "version: $(ls -laR "$C/synced")"
! grep -q '\.versions$' "$C/versions.out" && grep -q "$(basename "${VERSIONS[0]}")" "$C/versions.out" &&
	pass "version: .versions unlisted but readable by path" || fail "version listing: $(cat "$C/versions.out")"
grep -q 'Permission denied' "$C/versions.out" && [ -e "${VERSIONS[0]}" ] && pass "version: versions cannot be deleted" || fail "version: delete in .versions"
grep -q '"conflict":"versioned".*"version_path":"/synced/.versions/doc.txt/doc\.' "$C/audit.jsonl" &&
	pass "version: audit has version_path" || fail "version: audit lacks version_path"

# atomic_uploads: a client killed mid-upload leaves nothing under the name.
printf 'put %s /atomic/big.bin\n' "$WORK/local/upload.bin" >"$C/atomic.batch"
# shellcheck disable=SC2046
sftp -l 400 -P "$PORT" $(as admin) -b "$C/atomic.batch" admin@127.0.0.1 >/dev/null 2>&1 &
SFTP_PID=$!
temp_files() { compgen -G "$C/atomic/.gosftpd-*.part" >/dev/null; }
for _ in $(seq 100); do temp_files && break; sleep 0.1; done
if temp_files && [ ! -e "$C/atomic/big.bin" ]; then pass "atomic: upload in a hidden temporary file"; else fail "atomic: no temporary file: $(ls -la "$C/atomic")"; fi
kill -9 "$SFTP_PID"; wait "$SFTP_PID" 2>/dev/null || true
for _ in $(seq 100); do temp_files || break; sleep 0.1; done
if ! temp_files && [ ! -e "$C/atomic/big.bin" ]; then pass "atomic: kill -9 of the client leaves no file"; else fail "atomic: left $(ls -la "$C/atomic")"; fi
grep -q '"event":"fs.upload".*"path":"/atomic/big.bin".*"result":"aborted"' "$C/audit.jsonl" &&
	pass "atomic: audit has the aborted upload" || fail "atomic: audit lacks the aborted upload"
# shellcheck disable=SC2046
scp -q -P "$PORT" $(as admin) "$WORK/local/upload.bin" admin@127.0.0.1:/atomic/big.bin && cmp -s "$WORK/local/upload.bin" "$C/atomic/big.bin" &&
	pass "atomic: scp upload" || fail "atomic: scp upload"

# courier: password login (OpenSSH reads the password from SSH_ASKPASS).
# sftp -b sets BatchMode, which disables password prompts; the first value wins.
pw_opts=(-o BatchMode=no -o "UserKnownHostsFile=$C/known_hosts" -o StrictHostKeyChecking=yes -o PreferredAuthentications=password
	-o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1)
printf 'put %s courier.txt\n' "$WORK/local/short.txt" >"$C/courier.batch"
if SSH_ASKPASS="$WORK/askpass" SSH_ASKPASS_REQUIRE=force sftp -P "$PORT" "${pw_opts[@]}" -b "$C/courier.batch" \
	courier@127.0.0.1 </dev/null >"$C/courier.out" 2>&1; then
	cmp -s "$WORK/local/short.txt" "$C/inbox/courier.txt" && pass "courier: password login and upload" || fail "courier: upload"
else
	fail "courier: password login: $(tail -3 "$C/courier.out")"
fi
printf '#!/bin/sh\necho wrong\n' >"$WORK/askpass-wrong"; chmod 700 "$WORK/askpass-wrong"
if SSH_ASKPASS="$WORK/askpass-wrong" SSH_ASKPASS_REQUIRE=force sftp -P "$PORT" "${pw_opts[@]}" -b "$C/courier.batch" \
	courier@127.0.0.1 </dev/null >/dev/null 2>&1; then
	fail "courier: wrong password accepted"
else
	pass "courier: wrong password refused"
fi

# --- paramiko ------------------------------------------------------------
if "$PYTHON" -c 'import paramiko' 2>/dev/null; then
	COURIER_PASSWORD="$COURIER_PASSWORD" "$PYTHON" "$ROOT/test/interop/paramiko_check.py" "$PORT" "$C/known_hosts" "$WORK" "$C/inbox" "$WORK/local/upload.bin" ||
		fail "paramiko checks"
else
	missing paramiko
fi

# --- rclone (sftp backend, no shell) ---------------------------------------
if command -v "$RCLONE" >/dev/null 2>&1; then
	# rclone reads every RCLONE_* variable as a flag.
	for v in $(compgen -e | grep '^RCLONE_' || true); do unset "$v"; done
	mkdir -p "$WORK/local/rc"
	printf 'first\n' >"$WORK/local/rc/a.txt"
	cp "$WORK/local/upload.bin" "$WORK/local/rc/big.bin"
	# remote USER: an on-the-fly rclone remote for USER
	remote() { echo ":sftp,host=127.0.0.1,port=$PORT,user=$1,key_file=$WORK/id_$1,known_hosts_file=$C/known_hosts,shell_type=none:"; }
	RC=("$RCLONE" --config /dev/null --retries 1 --low-level-retries 1)
	# DoD M2: without --inplace into an upload-only mount (temporary name, then rename).
	if "${RC[@]}" copy "$WORK/local/rc" "$(remote partner)rc" 2>"$C/rclone.err"; then
		cmp -s "$WORK/local/rc/big.bin" "$C/inbox/rc/big.bin" && pass "rclone: copy into an upload mount" || fail "rclone: copied file differs"
	else
		fail "rclone copy (upload): $(tail -3 "$C/rclone.err")"
	fi
	if [ -d "$C/inbox/rc" ] && ! ls "$C/inbox/rc" | grep -q partial; then
		pass "rclone: no temporary files left"
	else
		fail "rclone: temporary files left or nothing copied: $(ls "$C/inbox/rc" 2>&1)"
	fi
	# DoD M2: with full access and on_conflict=rename, a changed file must not
	# delete or change the original.
	printf 'second version\n' >"$WORK/local/rc/a.txt"
	if "${RC[@]}" copy "$WORK/local/rc" "$(remote admin)inbox/rc" 2>"$C/rclone2.err"; then
		pass "rclone: copy of a changed file exits 0"
	else
		fail "rclone copy (full): $(tail -3 "$C/rclone2.err")"
	fi
	grep -qx 'first' "$C/inbox/rc/a.txt" && grep -qx 'second version' "$C/inbox/rc/a (1).txt" &&
		pass "rclone: original kept, new version as a copy" || fail "rclone: $(ls "$C/inbox/rc"): $(cat "$C/inbox/rc/a.txt")"
	"${RC[@]}" about "$(remote admin)inbox" >"$C/rclone.about" 2>&1 && grep -q 'Total' "$C/rclone.about" &&
		pass "rclone: about (statvfs)" || fail "rclone about: $(cat "$C/rclone.about")"
	# on_conflict=version: repeated syncs into the mount root keep the name,
	# add no copies and leave the unlisted .versions alone (keep = 3).
	mkdir -p "$WORK/local/sync"
	sync_ok=yes
	for i in 1 2 3 4 5; do
		printf 'version %s\n' "$i" >"$WORK/local/sync/a.txt"
		touch -d "2020-01-0$i 12:00" "$WORK/local/sync/a.txt"
		"${RC[@]}" sync "$WORK/local/sync" "$(remote admin)synced" 2>>"$C/rclone-sync.err" || sync_ok=no
	done
	[ "$sync_ok" = yes ] && pass "rclone: sync x5 into a version mount" || fail "rclone sync: $(tail -3 "$C/rclone-sync.err")"
	[ "$(ls -A "$C/synced" | tr '\n' ' ')" = ".versions a.txt " ] && grep -qx 'version 5' "$C/synced/a.txt" &&
		pass "rclone: sync leaves only the synced file" || fail "rclone sync: $(ls -A "$C/synced")"
	[ "$(cat "$C"/synced/.versions/a.txt/* | sort | tr '\n' ' ')" = "version 2 version 3 version 4 " ] &&
		pass "rclone: the 3 newest versions are kept" || fail "rclone versions: $(ls -A "$C/synced/.versions/a.txt" 2>&1)"
else
	missing rclone
fi

# --- lftp ------------------------------------------------------------------
if command -v lftp >/dev/null 2>&1; then
	LFTP_SSH="ssh -a -x -i $WORK/id_admin -o UserKnownHostsFile=$C/known_hosts -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -o BatchMode=yes"
	if lftp -c "set sftp:connect-program '$LFTP_SSH'; set net:max-retries 1; open -u admin,unused sftp://127.0.0.1:$PORT;
		cd home; put $WORK/local/upload.bin -o lftp.bin; get lftp.bin -o $C/lftp.got; cls -1 /" >"$C/lftp.out" 2>&1; then
		cmp -s "$WORK/local/upload.bin" "$C/home/admin/lftp.bin" && cmp -s "$WORK/local/upload.bin" "$C/lftp.got" &&
			pass "lftp: put and get" || fail "lftp: files differ"
		grep -q 'inbox' "$C/lftp.out" && pass "lftp: listing" || fail "lftp listing: $(cat "$C/lftp.out")"
	else
		fail "lftp: $(tail -3 "$C/lftp.out")"
	fi
else
	missing lftp
fi

# An unknown user is refused.
# shellcheck disable=SC2046
if sftp -P "$PORT" $(as admin) -b "$C/admin.batch" mallory@127.0.0.1 >/dev/null 2>&1; then fail "unknown user accepted"; else pass "unknown user refused"; fi

# --- reload on SIGHUP (ROADMAP M4) ------------------------------------------
reloads() { grep -c '"event":"server.reload"' "$C/audit.jsonl" || true; }
reload_errors() { grep -c '"event":"server.reload".*"result":"error"' "$C/audit.jsonl" || true; }
hup() { # hup: SIGHUP the configuration server and wait for its server.reload event
	local n
	n=$(reloads)
	kill -HUP "$CFG_PID"
	for _ in $(seq 100); do
		if [ "$(reloads)" -gt "$n" ]; then return 0; fi
		sleep 0.1
	done
	return 1
}
ssh-keygen -q -t ed25519 -N '' -C newbie -f "$WORK/id_newbie"
printf 'get readme.txt %s\n' "$C/newbie.got" >"$C/newbie.batch"
echo pwd >"$C/pwd.batch"
# shellcheck disable=SC2046
if sftp -P "$PORT" $(as newbie) -b "$C/newbie.batch" newbie@127.0.0.1 >/dev/null 2>&1; then fail "reload: newbie accepted before it was added"; fi

# A session opened before the reload keeps its configuration.
mkfifo "$C/held.fifo"
# shellcheck disable=SC2046
sftp -P "$PORT" $(as partner) -b - partner@127.0.0.1 <"$C/held.fifo" >"$C/held.out" 2>&1 &
HELD_PID=$!
exec 4>"$C/held.fifo"
echo "put $WORK/local/short.txt held1.txt" >&4
for _ in $(seq 100); do
	if [ -e "$C/inbox/held1.txt" ]; then break; fi
	sleep 0.1
done

# Remove partner, add newbie.
sed -i '/^\[users.partner\]/,/^$/d' "$CE/gosftpd.toml"
cat >>"$CE/gosftpd.toml" <<TOML

[users.newbie]
authorized_keys = ["$(cat "$WORK/id_newbie.pub")"]
access = { public = "read" }
TOML
if hup && grep -q '"event":"server.reload".*"result":"ok"' "$C/audit.jsonl"; then pass "reload: SIGHUP reloads the configuration"; else fail "reload: no successful server.reload"; fi
# shellcheck disable=SC2046
sftp -P "$PORT" $(as newbie) -b "$C/newbie.batch" newbie@127.0.0.1 >/dev/null 2>&1 && cmp -s "$C/public/readme.txt" "$C/newbie.got" &&
	pass "reload: an added user logs in" || fail "reload: added user cannot log in"
# shellcheck disable=SC2046
if sftp -P "$PORT" $(as partner) -b "$C/pwd.batch" partner@127.0.0.1 >/dev/null 2>&1; then fail "reload: removed user accepted"; else pass "reload: a removed user is refused"; fi
echo "put $WORK/local/short.txt held2.txt" >&4
exec 4>&-
if wait "$HELD_PID" && [ -e "$C/inbox/held2.txt" ]; then pass "reload: an open session keeps its configuration"; else fail "reload: open session: $(tail -3 "$C/held.out")"; fi

# user add --write, then disable: each applied by a reload.
ssh-keygen -q -t ed25519 -N '' -C carol -f "$WORK/id_carol"
if "$WORK/gosftpd" user add carol --key "$WORK/id_carol.pub" --access public=read --write --config "$CE/gosftpd.toml" \
	--host 127.0.0.1 >"$C/carol.out" 2>&1 && grep -q "connect: sftp -P $PORT carol@127.0.0.1" "$C/carol.out"; then
	pass "user add --write: file and connection details"
else
	fail "user add --write: $(cat "$C/carol.out")"
fi
hup || fail "reload after user add"
# shellcheck disable=SC2046
sftp -P "$PORT" $(as carol) -b "$C/pwd.batch" carol@127.0.0.1 >/dev/null 2>&1 && pass "user add --write: the user logs in after a reload" || fail "user add --write: carol cannot log in"
"$WORK/gosftpd" user disable carol --config "$CE/gosftpd.toml" >/dev/null || fail "user disable"
hup || fail "reload after user disable"
# shellcheck disable=SC2046
if sftp -P "$PORT" $(as carol) -b "$C/pwd.batch" carol@127.0.0.1 >/dev/null 2>&1; then
	fail "user disable: carol still logs in"
else
	pass "user disable: the login is refused after a reload"
fi
for _ in $(seq 50); do
	if grep -q '"event":"auth.failure".*"reason":"disabled"' "$C/audit.jsonl"; then break; fi
	sleep 0.1
done
grep -q '"event":"auth.failure".*"reason":"disabled"' "$C/audit.jsonl" && pass "user disable: audit has reason disabled" || fail "user disable: no auth.failure with reason disabled"

# --- SSH user certificates (ADR 0007) -----------------------------------------
audit_has() { # audit_has PATTERN: wait until the audit log matches PATTERN
	for _ in $(seq 50); do
		if grep -q "$1" "$C/audit.jsonl"; then return 0; fi
		sleep 0.1
	done
	return 1
}
ssh-keygen -q -t ed25519 -N '' -C user_ca -f "$WORK/user_ca"
for u in dana eve fred; do ssh-keygen -q -t ed25519 -N '' -C "$u" -f "$WORK/id_$u"; done
ssh-keygen -q -s "$WORK/user_ca" -I dana-laptop -n dana -V -5m:+1h -z 42 "$WORK/id_dana.pub"
ssh-keygen -q -s "$WORK/user_ca" -I eve -n mallory -V -5m:+1h "$WORK/id_eve.pub"
ssh-keygen -q -s "$WORK/user_ca" -I fred-sftp -n dana -V -5m:+1h -O force-command=internal-sftp "$WORK/id_fred.pub"
cp "$WORK/user_ca.pub" "$CE/user_ca.pub"
: >"$CE/revoked"
chmod 600 "$CE/user_ca.pub" "$CE/revoked"
sed -i "s|^methods = \[\"publickey\", \"password\"\]|&\ntrusted_user_ca_keys_file = \"$CE/user_ca.pub\"\nrevoked_keys_file = \"$CE/revoked\"|" "$CE/gosftpd.toml"
cat >>"$CE/gosftpd.toml" <<TOML

[users.dana]
access = { public = "read" }
TOML
hup || fail "reload with certificates"
# ssh uses id_dana-cert.pub next to the key by itself.
# shellcheck disable=SC2046
sftp -P "$PORT" $(as dana) -b "$C/pwd.batch" dana@127.0.0.1 >/dev/null 2>&1 && pass "certificate: a certificate from a trusted CA logs in" || fail "certificate: dana cannot log in"
audit_has '"event":"auth.success".*"cert_key_id":"dana-laptop","cert_serial":"42"' && pass "certificate: the audit log names the certificate" || fail "certificate: no cert_key_id and cert_serial in auth.success"
# shellcheck disable=SC2046
if sftp -P "$PORT" $(as eve) -b "$C/pwd.batch" dana@127.0.0.1 >/dev/null 2>&1; then fail "certificate: another principal logged in"; else pass "certificate: another principal is refused"; fi
audit_has '"event":"auth.failure".*"reason":"cert_principal"' && pass "certificate: audit has reason cert_principal" || fail "certificate: no reason cert_principal"
# shellcheck disable=SC2046
sftp -P "$PORT" $(as fred) -b "$C/pwd.batch" dana@127.0.0.1 >/dev/null 2>&1 && pass "certificate: force-command=internal-sftp is accepted" || fail "certificate: force-command=internal-sftp refused"
cat "$WORK/id_dana-cert.pub" >>"$CE/revoked"
hup || fail "reload after revoking"
# shellcheck disable=SC2046
if sftp -P "$PORT" $(as dana) -b "$C/pwd.batch" dana@127.0.0.1 >/dev/null 2>&1; then fail "certificate: a revoked certificate logged in"; else pass "certificate: a revoked certificate is refused after a reload"; fi
audit_has '"event":"auth.failure".*"reason":"key_revoked"' && pass "certificate: audit has reason key_revoked" || fail "certificate: no reason key_revoked"
cp "$CE/revoked" "$C/revoked.txt"
ssh-keygen -q -k -f "$CE/revoked" "$WORK/id_dana.pub"
errors=$(reload_errors)
if hup && [ "$(reload_errors)" -gt "$errors" ] && grep -q 'KRL' "$C/server.log"; then
	pass "certificate: a KRL fails the reload"
else
	fail "certificate: a KRL did not fail the reload"
fi
cp "$C/revoked.txt" "$CE/revoked"
hup || fail "reload with the text revocation list"

# --- host key rotation and host certificates (ADR 0008) -----------------------
# The configuration in $HE and the host keys in $H/state each have a
# directory of their own: under Landlock the rotation's new files and
# renames there need no restart (ADR 0011).
H="$WORK/hk"
HE="$H/etc"
mkdir -p "$H/data" "$H/state" "$HE"
HPORT=$((20000 + RANDOM % 20000))
while [ "$HPORT" = "$PORT" ] || [ "$HPORT" = "$MPORT" ] || [ "$HPORT" = "$OVERWRITE_PORT" ]; do HPORT=$((HPORT + 1)); done
ssh-keygen -q -t ed25519 -N '' -f "$H/state/ed25519"
ssh-keygen -q -t rsa -b 3072 -N '' -f "$H/state/rsa"
cat >"$HE/gosftpd.toml" <<TOML
config_version = 1
[server]
listen = ["127.0.0.1:$HPORT"]
host_keys = ["$H/state/ed25519", "$H/state/rsa"]
[mounts.data]
path = "$H/data"
[users.admin]
authorized_keys = ["$(cat "$WORK/id_admin.pub")"]
access = { data = "full" }
[audit]
output = "$H/audit.jsonl"
TOML
chmod 600 "$HE/gosftpd.toml"
"$WORK/gosftpd" serve --config "$HE/gosftpd.toml" "${ROOT_FLAG[@]}" 2>"$H/server.log" &
HK_PID=$!
PIDS+=("$HK_PID")
for _ in $(seq 100); do
	if (exec 3<>"/dev/tcp/127.0.0.1/$HPORT") 2>/dev/null; then break; fi
	sleep 0.1
done
kill -0 "$HK_PID" 2>/dev/null || fail "host key server did not start: $(cat "$H/server.log")"
landlock_logged "host keys" "$H/server.log"
hk_hup() { # hk_hup: SIGHUP the host key server and wait for its server.reload event
	local n
	n=$(grep -c '"event":"server.reload"' "$H/audit.jsonl" || true)
	kill -HUP "$HK_PID"
	for _ in $(seq 100); do
		[ "$(grep -c '"event":"server.reload"' "$H/audit.jsonl" || true)" -gt "$n" ] && return 0
		sleep 0.1
	done
	return 1
}
fp() { ssh-keygen -lf "$1" | awk '{print $2}'; }
# knows FILE KEY.pub: the known_hosts file FILE has KEY for the server.
knows() { ssh-keygen -l -F "[127.0.0.1]:$HPORT" -f "$1" 2>/dev/null | grep -q "$(fp "$2")"; }
# hk_sftp KNOWN_HOSTS [OPTIONS...]: an sftp session that keeps known_hosts up
# to date, unless OPTIONS say otherwise (ssh takes the first value given).
hk_sftp() {
	local kh=$1
	shift
	sftp -P "$HPORT" "$@" -o "UserKnownHostsFile=$kh" -o StrictHostKeyChecking=yes -o UpdateHostKeys=yes \
		-o IdentitiesOnly=yes -o BatchMode=yes -i "$WORK/id_admin" -b "$C/pwd.batch" admin@127.0.0.1
}
known_line() { echo "[127.0.0.1]:$HPORT $(cut -d' ' -f1,2 "$1")"; }
known_line "$H/state/ed25519.pub" >"$H/kh_ed"
known_line "$H/state/rsa.pub" >"$H/kh_rsa"

# ed25519: the next key is learned before it is used, the old one forgotten after --retire.
"$WORK/gosftpd" hostkey rotate --config "$HE/gosftpd.toml" --host-key "$H/state/ed25519" >"$H/rotate.out" &&
	pass "hostkey rotate: next key created" || fail "hostkey rotate: $(cat "$H/rotate.out")"
hk_hup || fail "reload after hostkey rotate"
hk_sftp "$H/kh_ed" >"$H/sftp1.out" 2>&1 || fail "host keys: sftp during the rotation: $(cat "$H/sftp1.out")"
knows "$H/kh_ed" "$H/state/ed25519.next.pub" && pass "host keys: OpenSSH learned the next key (UpdateHostKeys)" ||
	fail "host keys: the next key is not in known_hosts: $(cat "$H/kh_ed")"
grep -q '"event":"conn.hostkeys_proved"' "$H/audit.jsonl" && pass "host keys: the proof is audited" || fail "host keys: no conn.hostkeys_proved"
cp "$H/state/ed25519.pub" "$H/old_ed25519.pub"
"$WORK/gosftpd" hostkey rotate --finish --config "$HE/gosftpd.toml" --host-key "$H/state/ed25519" >"$H/finish.out" ||
	fail "hostkey rotate --finish: $(cat "$H/finish.out")"
hk_hup || fail "reload after --finish"
known_line "$H/state/ed25519.pub" >"$H/kh_new"
hk_sftp "$H/kh_new" -o UpdateHostKeys=no -o HostKeyAlgorithms=ssh-ed25519 >"$H/sftp2.out" 2>&1 &&
	pass "host keys: after --finish the server uses the new key" || fail "host keys: after --finish: $(cat "$H/sftp2.out")"
hk_sftp "$H/kh_ed" -o HostKeyAlgorithms=ssh-ed25519 >"$H/sftp2b.out" 2>&1 &&
	pass "host keys: a client that learned the key connects without a prompt" || fail "host keys: after --finish: $(cat "$H/sftp2b.out")"
knows "$H/kh_ed" "$H/old_ed25519.pub" && pass "host keys: the previous key stays until --retire" || fail "host keys: the previous key was dropped early"
"$WORK/gosftpd" hostkey rotate --retire --config "$HE/gosftpd.toml" --host-key "$H/state/ed25519" >/dev/null || fail "hostkey rotate --retire"
hk_hup || fail "reload after --retire"
hk_sftp "$H/kh_ed" >/dev/null 2>&1 || fail "host keys: sftp after --retire"
if knows "$H/kh_ed" "$H/old_ed25519.pub"; then fail "host keys: the retired key is still in known_hosts"; else pass "host keys: OpenSSH forgot the retired key"; fi

# RSA, with rsa-sha2-256 negotiated: proofs must use the same hash. A single
# command also checks that a short session waits for the proof.
"$WORK/gosftpd" hostkey rotate --config "$HE/gosftpd.toml" --host-key "$H/state/rsa" >/dev/null || fail "hostkey rotate (rsa)"
hk_hup || fail "reload after hostkey rotate (rsa)"
hk_sftp "$H/kh_rsa" -o HostKeyAlgorithms=rsa-sha2-256 >"$H/sftp3.out" 2>&1 || fail "host keys: sftp with rsa-sha2-256: $(cat "$H/sftp3.out")"
knows "$H/kh_rsa" "$H/state/rsa.next.pub" && pass "host keys: an RSA next key is learned with rsa-sha2-256" ||
	fail "host keys: the RSA next key is not in known_hosts: $(cat "$H/kh_rsa")"
"$WORK/gosftpd" hostkey rotate --abort --config "$HE/gosftpd.toml" --host-key "$H/state/rsa" >/dev/null || fail "hostkey rotate --abort"

# Host certificates: a client that trusts only the CA connects.
ssh-keygen -q -t ed25519 -N '' -C host_ca -f "$WORK/host_ca"
ssh-keygen -q -s "$WORK/host_ca" -h -I gosftpd -n 127.0.0.1 -V -5m:+1h "$H/state/ed25519.pub"
sed -i 's|^host_keys = .*|&\nhost_certificates = true|' "$HE/gosftpd.toml"
hk_hup || fail "reload with host_certificates"
echo "@cert-authority [127.0.0.1]:$HPORT $(cut -d' ' -f1,2 "$WORK/host_ca.pub")" >"$H/kh_ca"
hk_sftp "$H/kh_ca" -o UpdateHostKeys=no >"$H/sftp4.out" 2>&1 && pass "host certificate: a client that trusts the CA connects" ||
	fail "host certificate: $(cat "$H/sftp4.out")"
known_line "$H/state/ed25519.pub" >"$H/kh_plain"
hk_sftp "$H/kh_plain" -o UpdateHostKeys=no >/dev/null 2>&1 && pass "host certificate: OpenSSH that knows the plain key still connects" ||
	fail "host certificate: OpenSSH with the plain key"
if "$PYTHON" -c 'import paramiko' 2>/dev/null; then
	"$PYTHON" - "$HPORT" "$H/kh_plain" "$WORK/id_admin" <<'PY' && pass "host certificate: paramiko with the plain key connects" || fail "host certificate: paramiko with the plain key"
import sys, paramiko
port, kh, key = sys.argv[1], sys.argv[2], sys.argv[3]
c = paramiko.SSHClient()
c.load_host_keys(kh)
c.set_missing_host_key_policy(paramiko.RejectPolicy())
c.connect("127.0.0.1", port=int(port), username="admin", key_filename=key, allow_agent=False, look_for_keys=False, timeout=10)
c.open_sftp().listdir(".")
c.close()
PY
else
	missing paramiko
fi
if command -v "$RCLONE" >/dev/null 2>&1; then
	hk_remote=":sftp,host=127.0.0.1,port=$HPORT,user=admin,key_file=$WORK/id_admin,known_hosts_file=$H/kh_plain,shell_type=none"
	if "$RCLONE" --config /dev/null --retries 1 --low-level-retries 1 lsd "$hk_remote:" >/dev/null 2>"$H/rclone.err"; then
		fail "host certificate: rclone pinned to the plain key connected; the documented breakage is gone, update the docs"
	else
		grep -q 'no authorities for hostname' "$H/rclone.err" && pass "host certificate: rclone pinned to the plain key fails as documented" ||
			fail "host certificate: rclone failed otherwise: $(tail -2 "$H/rclone.err")"
	fi
	"$RCLONE" --config /dev/null --retries 1 --low-level-retries 1 lsd "$hk_remote,host_key_algorithms=ssh-ed25519:" >/dev/null 2>"$H/rclone2.err" &&
		pass "host certificate: rclone with host_key_algorithms connects" || fail "host certificate: rclone with host_key_algorithms: $(tail -2 "$H/rclone2.err")"
else
	missing rclone
fi

# --- Landlock: a configuration next to other files (ADR 0011) -----------------
# The documented outcome of a shared directory: the configuration file gets
# a rule of its own, so sed -i, which replaces the file by rename, fails
# the next reload with the restart hint, and the running configuration
# stays.
L="$WORK/shared"
mkdir -p "$L/data" "$L/state"
LPORT=$((20000 + RANDOM % 20000))
while [ "$LPORT" = "$PORT" ] || [ "$LPORT" = "$MPORT" ] || [ "$LPORT" = "$HPORT" ] || [ "$LPORT" = "$OVERWRITE_PORT" ]; do LPORT=$((LPORT + 1)); done
cat >"$L/gosftpd.toml" <<TOML
config_version = 1
[server]
listen = ["127.0.0.1:$LPORT"]
host_keys = ["$L/state/host_key"]
host_key_auto_generate = true
[mounts.data]
path = "$L/data"
[users.admin]
authorized_keys = ["$(cat "$WORK/id_admin.pub")"]
access = { data = "full" }
[audit]
output = "$L/audit.jsonl"
TOML
chmod 600 "$L/gosftpd.toml"
"$WORK/gosftpd" serve --config "$L/gosftpd.toml" "${ROOT_FLAG[@]}" 2>"$L/server.log" &
SHARED_PID=$!
PIDS+=("$SHARED_PID")
for _ in $(seq 100); do
	if (exec 3<>"/dev/tcp/127.0.0.1/$LPORT") 2>/dev/null; then break; fi
	sleep 0.1
done
landlock_logged shared "$L/server.log"
if grep -q 'landlock: ABI v[2-5] applied' "$L/server.log"; then
	grep -q "configuration: Landlock covers only the file gosftpd.toml in $L, which holds data" "$L/server.log" &&
		pass "shared: the start warns that the configuration's directory is shared" || fail "shared: no start warning: $(grep landlock "$L/server.log")"
	sed -i 's|^access = { data = "full" }|access = { data = "read" }|' "$L/gosftpd.toml"
	kill -HUP "$SHARED_PID"
	for _ in $(seq 100); do
		if grep -q '"event":"server.reload"' "$L/audit.jsonl"; then break; fi
		sleep 0.1
	done
	grep -q '"event":"server.reload","result":"error","reason":"config"' "$L/audit.jsonl" &&
		grep -q 'configuration reload failed.*gosftpd.toml: permission denied (outside the Landlock ruleset applied at start; restart gosftpd)' "$L/server.log" &&
		pass "shared: sed -i of the configuration fails the reload with the restart hint" ||
		fail "shared: reload after sed -i: $(grep -h 'server.reload\|reload failed' "$L/audit.jsonl" "$L/server.log")"
	printf 'put %s /up.txt\n' "$WORK/local/short.txt" >"$L/put.batch"
	"$WORK/gosftpd" hostkey show --host-key "$L/state/host_key" --known-hosts "127.0.0.1:$LPORT" | tail -n 1 >"$L/known_hosts"
	sftp -P "$LPORT" -o "UserKnownHostsFile=$L/known_hosts" -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -o BatchMode=yes \
		-i "$WORK/id_admin" -b "$L/put.batch" admin@127.0.0.1 >"$L/put.out" 2>&1 && cmp -s "$WORK/local/short.txt" "$L/data/up.txt" &&
		pass "shared: the running configuration stays" || fail "shared: upload after the failed reload: $(cat "$L/put.out")"
fi
kill -TERM "$SHARED_PID"
if wait "$SHARED_PID"; then pass "shared: SIGTERM exits 0"; else fail "shared: SIGTERM exit code $?"; fi

# --- admin listener, metrics and healthcheck (ADR 0009) ----------------------
PROMTOOL=${PROMTOOL:-promtool}
M="http://127.0.0.1:$MPORT"
metric() { # metric SERIES: its value in $C/metrics.txt, or nothing
	awk -v s="$1" '$1 == s { print $2 }' "$C/metrics.txt"
}
curl -fsS "$M/metrics" >"$C/metrics.txt" && pass "metrics: /metrics answers" || fail "metrics: /metrics"
if command -v "$PROMTOOL" >/dev/null 2>&1; then
	"$PROMTOOL" check metrics <"$C/metrics.txt" >"$C/promtool.out" 2>&1 && pass "metrics: promtool check metrics" ||
		fail "metrics: promtool check metrics: $(head -5 "$C/promtool.out")"
else
	missing promtool
fi
[ "$(metric 'gosftpd_logins_total{result="success"}')" -gt 0 ] && [ "$(metric 'gosftpd_sftp_operations_total{op="upload",result="ok"}')" -gt 0 ] &&
	[ "$(metric 'gosftpd_config_reloads_total{result="ok"}')" -gt 0 ] && [ "$(metric 'gosftpd_transfer_bytes_total{direction="download"}')" -gt 0 ] &&
	pass "metrics: logins, uploads, reloads and bytes are counted" || fail "metrics: counters: $(grep -v '^#' "$C/metrics.txt" | grep -v ' 0$' | head -30)"
grep -Eq '^gosftpd_(.*)\{[^}]*(alice|admin|partner|127\.0\.0\.1|/)' "$C/metrics.txt" && fail "metrics: a label holds a user, an address or a path" || pass "metrics: no user, address or path in labels"
[ "$(curl -fsS "$M/healthz")" = ok ] && [ "$(curl -fsS "$M/readyz")" = ready ] && pass "metrics: /healthz and /readyz" || fail "metrics: /healthz or /readyz"
[ "$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: rebind.example' "$M/metrics")" = 421 ] && pass "metrics: a foreign Host header gets 421" || fail "metrics: Host check"
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$M/metrics")" = 405 ] && pass "metrics: POST gets 405" || fail "metrics: POST"

accepts=$(grep -c '"event":"conn.accept"' "$C/audit.jsonl")
no_version=$(metric 'gosftpd_connections_total{result="no_version"}')
"$WORK/gosftpd" healthcheck --config "$CE/gosftpd.toml" >"$C/hc.out" 2>&1 && grep -q "^ok: 127.0.0.1:$PORT sent an SSH banner" "$C/hc.out" &&
	pass "healthcheck: the SSH banner of server.listen" || fail "healthcheck: $(cat "$C/hc.out")"
GOSFTPD_LISTEN="127.0.0.1:$PORT" "$WORK/gosftpd" healthcheck --ready >/dev/null 2>&1 && pass "healthcheck: \$GOSFTPD_LISTEN with --ready" || fail "healthcheck: GOSFTPD_LISTEN"
"$WORK/gosftpd" healthcheck --url "$M/readyz" >/dev/null 2>&1 && pass "healthcheck --url /readyz" || fail "healthcheck --url"
set +e; "$WORK/gosftpd" healthcheck --address 127.0.0.1:1 --timeout 2s >/dev/null 2>"$C/hc.err"; code=$?; set -e
[ "$code" = 1 ] && [ "$(wc -l <"$C/hc.err")" = 1 ] && pass "healthcheck: no server is exit 1 with one line" || fail "healthcheck: no server: exit $code: $(cat "$C/hc.err")"
set +e; "$WORK/gosftpd" healthcheck --bogus >/dev/null 2>&1; code=$?; set -e
[ "$code" = 1 ] && pass "healthcheck: a usage error is exit 1, not 2" || fail "healthcheck: usage error exit $code"
curl -fsS "$M/metrics" >"$C/metrics.txt" || true
[ "$(grep -c '"event":"conn.accept"' "$C/audit.jsonl")" = "$accepts" ] && [ "$(metric 'gosftpd_connections_total{result="no_version"}')" -ge $((no_version + 2)) ] &&
	pass "healthcheck: probes leave no audit event and count as no_version" || fail "healthcheck: probes audited or not counted"

# An invalid configuration is refused; the running one stays.
printf '[server\n' >>"$CE/gosftpd.toml"
errors=$(reload_errors)
if hup && [ "$(reload_errors)" -gt "$errors" ] && kill -0 "$CFG_PID" 2>/dev/null; then
	pass "reload: an invalid configuration is refused"
else
	fail "reload: invalid configuration not refused"
fi
rm -f "$C/newbie.got"
# shellcheck disable=SC2046
sftp -P "$PORT" $(as newbie) -b "$C/newbie.batch" newbie@127.0.0.1 >/dev/null 2>&1 && cmp -s "$C/public/readme.txt" "$C/newbie.got" &&
	pass "reload: the running configuration stays after a failed reload" || fail "reload: failed reload changed the configuration"
curl -fsS "$M/metrics" >"$C/metrics.txt" || true
[ "$(metric gosftpd_config_last_reload_successful)" = 0 ] && [ "$(metric 'gosftpd_config_reloads_total{result="error"}')" -gt 0 ] &&
	pass "metrics: a failed reload shows" || fail "metrics: failed reload not shown"

# --- hooks (ADR 0010) ----------------------------------------------------------
# A webhook to a receiver that verifies every signature, and the archive
# script of docs/hooks.md as an exec hook fed hostile names. The
# configuration and the webhook's secret sit in $KE, a directory of their
# own, although the exec hook keeps Landlock off here.
K="$WORK/hooks"
KE="$K/etc"
if "$PYTHON" -c 'import hmac' 2>/dev/null; then
	mkdir -p "$K/inbox" "$K/drop" "$K/archive" "$K/state" "$K/bin" "$KE"
	KPORT=$((20000 + RANDOM % 20000))
	while [ "$KPORT" = "$PORT" ] || [ "$KPORT" = "$MPORT" ] || [ "$KPORT" = "$HPORT" ] || [ "$KPORT" = "$OVERWRITE_PORT" ]; do KPORT=$((KPORT + 1)); done
	"$PYTHON" -c 'import secrets; print(secrets.token_hex(32))' >"$KE/hook.secret"
	chmod 600 "$KE/hook.secret"
	"$PYTHON" "$ROOT/test/interop/hook_receiver.py" "$KE/hook.secret" "$K/receiver.port" "$K/deliveries.jsonl" 2>"$K/receiver.log" &
	PIDS+=($!)
	for _ in $(seq 100); do [ -s "$K/receiver.port" ] && break; sleep 0.1; done
	RPORT=$(cat "$K/receiver.port")
	# The archive script exactly as docs/hooks.md shows it, archiving under $K.
	awk '/^A safe archive script/ { s = 1 } s && /^```sh$/ { c = 1; next } c && /^```$/ { exit } c' "$ROOT/docs/hooks.md" |
		sed "s|/srv/archive|$K/archive|" >"$K/bin/archive-upload"
	chmod 755 "$K/bin/archive-upload"
	grep -q 'mv -n --' "$K/bin/archive-upload" || fail "hooks: no archive script in docs/hooks.md"
	printf 'bystander\n' >"$K/drop/keep.txt"
	cat >"$KE/gosftpd.toml" <<TOML
config_version = 1
[server]
listen = ["127.0.0.1:$KPORT"]
host_keys = ["$K/state/host_key"]
host_key_auto_generate = true
[mounts.inbox]
path = "$K/inbox"
[mounts.drop]
path = "$K/drop"
[users.partner]
authorized_keys_file = "$WORK/id_partner.pub"
access = { inbox = "upload", drop = "upload" }
[audit]
output = "$K/audit.jsonl"
[[hooks]]
name = "notify"
on = ["fs.upload"]
mounts = ["inbox"]
exclude = ["*.filepart", "*.partial"]
webhook = { url = "http://127.0.0.1:$RPORT/hooks/secret-token?k=secret-query", secret_file = "$KE/hook.secret" }
[[hooks]]
name = "archive"
on = ["fs.upload"]
mounts = ["drop"]
exclude = ["*.filepart", "*.partial"]
delay = "1s"
exec = { argv = ["/bin/sh", "$K/bin/archive-upload"], timeout = "30s" }
TOML
	chmod 600 "$KE/gosftpd.toml"
	"$WORK/gosftpd" config validate --check-fs --config "$KE/gosftpd.toml" >/dev/null 2>"$K/validate.err" &&
		pass "hooks: config validate --check-fs" || fail "hooks: config validate: $(cat "$K/validate.err")"
	"$WORK/gosftpd" serve --config "$KE/gosftpd.toml" "${ROOT_FLAG[@]}" 2>"$K/server.log" &
	PIDS+=($!)
	for _ in $(seq 100); do
		if (exec 3<>"/dev/tcp/127.0.0.1/$KPORT") 2>/dev/null; then break; fi
		sleep 0.1
	done
	# An exec hook needs what a fixed ruleset cannot know (ADR 0011).
	landlock_logged hooks "$K/server.log" 'landlock: not applied.*exec hooks configured'
	"$WORK/gosftpd" hostkey show --host-key "$K/state/host_key" --known-hosts "127.0.0.1:$KPORT" | tail -n 1 >"$K/known_hosts"
	deliveries() { [ -f "$K/deliveries.jsonl" ] && wc -l <"$K/deliveries.jsonl" || echo 0; }
	wait_deliveries() { # wait_deliveries N: true once there are N deliveries, and no more a moment later
		for _ in $(seq 200); do [ "$(deliveries)" -ge "$1" ] && break; sleep 0.1; done
		sleep 1
		[ "$(deliveries)" = "$1" ]
	}

	# OpenSSH sftp: one delivery, with the final name.
	printf 'put %s /inbox/report.pdf\n' "$WORK/local/short.txt" >"$K/put.batch"
	sftp -P "$KPORT" -o "UserKnownHostsFile=$K/known_hosts" -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -o BatchMode=yes \
		-i "$WORK/id_partner" -b "$K/put.batch" partner@127.0.0.1 >"$K/put.out" 2>&1 || fail "hooks: sftp put: $(cat "$K/put.out")"
	want=1
	wait_deliveries 1 || fail "hooks: $(deliveries) deliveries after one sftp put, want 1"

	# rclone: a temporary name and a rename, one delivery for the final name.
	if command -v "$RCLONE" >/dev/null 2>&1; then
		for v in $(compgen -e | grep '^RCLONE_' || true); do unset "$v"; done
		mkdir -p "$WORK/local/rc-hook"
		cp "$WORK/local/upload.bin" "$WORK/local/rc-hook/big.bin"
		"$RCLONE" --config /dev/null --retries 1 --low-level-retries 1 copy "$WORK/local/rc-hook" \
			":sftp,host=127.0.0.1,port=$KPORT,user=partner,key_file=$WORK/id_partner,known_hosts_file=$K/known_hosts,shell_type=none:inbox/rc" \
			2>"$K/rclone.err" || fail "hooks: rclone copy: $(tail -3 "$K/rclone.err")"
		want=2
		wait_deliveries 2 || fail "hooks: $(deliveries) deliveries after rclone, want 2"
	else
		missing rclone
	fi
	"$PYTHON" - "$K/deliveries.jsonl" "$want" <<'PY' && pass "hooks: one verified delivery per file, with the final name and the mount" || fail "hooks: deliveries: $(cat "$K/deliveries.jsonl")"
import json, sys
got = [json.loads(line) for line in open(sys.argv[1])]
want = [("fs.upload", "/inbox/report.pdf", None), ("fs.rename", "/inbox/rc/big.bin", True)][: int(sys.argv[2])]
assert len(got) == len(want), got
assert all(d["ok"] and d["user_agent"] == "gosftpd" and d["url_path"] == "/hooks/secret-token?k=secret-query" for d in got), got
assert len({d["delivery"] for d in got}) == len(got), got
for d, (event, final, uploaded) in zip(got, want):
    b = d["body"]
    assert d["event"] == event == b["event"] and b["final_path"] == final and b["mount"] == "inbox", d
    assert b.get("uploaded") == uploaded and b["user"] == "partner" and b["result"] == "ok", d
PY
	if grep -q -e secret-token -e secret-query "$K/server.log"; then fail "hooks: the webhook URL's token is in the log"; else pass "hooks: the URL's token stays out of the log"; fi

	# The archive script gets hostile names (paramiko: OpenSSH sftp cannot
	# send a newline in a name). A name that ran as code would leave a file
	# ending in .injected; one that became an option or a glob would move
	# the wrong files.
	if "$PYTHON" -c 'import paramiko' 2>/dev/null; then
		"$PYTHON" - "$KPORT" "$K/known_hosts" "$WORK/id_partner" <<'PY' || fail "hooks: paramiko upload of hostile names"
import sys, paramiko
port, kh, key = sys.argv[1], sys.argv[2], sys.argv[3]
names = ["*", "a b", "x\ny", "-rf", '$(touch -- "$GOSFTPD_HOST_PATH".inj"ected")', '`touch -- "$GOSFTPD_HOST_PATH".inj"ected"`']
c = paramiko.SSHClient()
c.load_host_keys(kh)
c.set_missing_host_key_policy(paramiko.RejectPolicy())
c.connect("127.0.0.1", port=int(port), username="partner", key_filename=key, allow_agent=False, look_for_keys=False, timeout=10)
s = c.open_sftp()
for n in names:
    with s.open("/drop/" + n, "w") as f:
        f.write(n.encode())
c.close()
PY
		"$PYTHON" - "$K" <<'PY' && pass "hooks: an exec hook from docs/hooks.md moves exactly each uploaded file, whatever its name" || fail "hooks: archive script with hostile names: $(ls -laR "$K/drop" "$K/archive")"
import os, sys, time
k = sys.argv[1]
names = {"*", "a b", "x\ny", "-rf", '$(touch -- "$GOSFTPD_HOST_PATH".inj"ected")', '`touch -- "$GOSFTPD_HOST_PATH".inj"ected"`'}
archive = os.path.join(k, "archive", "partner")
for _ in range(200):
    if os.path.isdir(archive) and len(os.listdir(archive)) >= len(names):
        break
    time.sleep(0.1)
time.sleep(1)
assert set(os.listdir(archive)) == names, os.listdir(archive)
for n in names:
    assert open(os.path.join(archive, n), "rb").read() == n.encode(), n
assert os.listdir(os.path.join(k, "drop")) == ["keep.txt"], os.listdir(os.path.join(k, "drop"))
for root, dirs, files in os.walk(k):
    assert not [f for f in files + dirs if f.endswith(".injected")], (root, files)
PY
	else
		missing paramiko
	fi
	grep -q '"event":"fs.upload","mount":"inbox","path":"/inbox/report.pdf"' "$K/audit.jsonl" && pass "hooks: the audit log has the mount" || fail "hooks: no mount in the audit log"
else
	missing python3
fi

if [ "$FAILED" -ne 0 ]; then
	echo "--- server log (rename)"; cat "$WORK/rename/server.log"
	echo "--- server log (config)"; cat "$C/server.log"
	echo "--- server log (host keys)"; cat "$WORK/hk/server.log"
	echo "--- server log (shared)"; cat "$WORK/shared/server.log"
	if [ -f "$WORK/hooks/server.log" ]; then echo "--- server log (hooks)"; cat "$WORK/hooks/server.log"; fi
	exit 1
fi
echo "all interop checks passed ($(ssh -V 2>&1))"
