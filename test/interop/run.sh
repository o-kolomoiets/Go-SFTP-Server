#!/usr/bin/env bash
# Interop test: real OpenSSH sftp, scp and ssh clients against a freshly
# built gosftpd. Usage: test/interop/run.sh (from anywhere). Needs bash,
# openssh-client and Go. KEEP_WORK=1 keeps the work directory for inspection.
#
# paramiko, rclone and lftp are tested when available (PYTHON with paramiko,
# RCLONE, lftp in PATH); REQUIRE_CLIENTS=1 makes a missing one a failure.
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
(cd "$ROOT" && go build "${COVER[@]}" -o "$WORK/gosftpd" ./cmd/gosftpd)
# gosftpd refuses to run as root; containers often are root.
ROOT_FLAG=()
if [ "$(id -u)" = 0 ]; then ROOT_FLAG=(--allow-root); fi
ssh-keygen -q -t ed25519 -N '' -f "$WORK/id_ed25519"
mkdir -p "$WORK/local"
head -c 3000000 /dev/urandom >"$WORK/local/upload.bin"
printf 'short' >"$WORK/local/short.txt"
touch -d '2020-01-02 03:04:05' "$WORK/local/upload.bin"

# start_server NAME POLICY: serves $WORK/NAME on a free port, sets PORT.
start_server() {
	local name=$1 policy=$2
	mkdir -p "$WORK/$name/share" "$WORK/$name/outside" "$WORK/$name/state"
	printf 'original content that is longer than the upload\n' >"$WORK/$name/share/a.txt"
	printf 'secret\n' >"$WORK/$name/outside/secret.txt"
	ln -s ../outside "$WORK/$name/share/evil"
	PORT=$((20000 + RANDOM % 20000))
	"$WORK/gosftpd" serve --dir "$WORK/$name/share" --on-conflict "$policy" \
		--authorized-keys "$WORK/id_ed25519.pub" --state-dir "$WORK/$name/state" \
		--listen "127.0.0.1:$PORT" --audit-output "$WORK/$name/audit.jsonl" "${ROOT_FLAG[@]}" \
		2>"$WORK/$name/server.log" &
	PIDS+=($!)
	for _ in $(seq 100); do
		if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then break; fi
		sleep 0.1
	done
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
for ev in conn.accept auth.success session.start fs.upload fs.download fs.rename fs.denied session.end; do
	grep -q "\"event\":\"$ev\"" "$WORK/rename/audit.jsonl" && pass "audit has $ev" || fail "audit lacks $ev"
done

# --- signals: HUP reloads and reopens the audit log, TERM exits cleanly ----
RENAME_PID=${PIDS[0]}
mv "$WORK/rename/audit.jsonl" "$WORK/rename/audit.jsonl.1" # as logrotate does
kill -HUP "$RENAME_PID"
for _ in $(seq 100); do
	if grep -q '"event":"server.reload"' "$WORK/rename/audit.jsonl" 2>/dev/null; then break; fi
	sleep 0.1
done
kill -0 "$RENAME_PID" 2>/dev/null && pass "SIGHUP does not stop the server" || fail "SIGHUP stopped the server"
grep -q '"event":"server.reload".*"result":"ok"' "$WORK/rename/audit.jsonl" 2>/dev/null &&
	pass "SIGHUP reloads and reopens the audit log" || fail "no server.reload in the reopened audit log"
kill -TERM "$RENAME_PID"
if wait "$RENAME_PID"; then pass "SIGTERM exits 0"; else fail "SIGTERM exit code $?"; fi
grep -q '"event":"server.stop"' "$WORK/rename/audit.jsonl" && pass "audit has server.stop" || fail "audit lacks server.stop"

# --- on_conflict=overwrite: scp over a longer file must not keep its tail --
start_server overwrite overwrite
OVERWRITE_PORT=$PORT
scp -q -P "$PORT" "${OPTS[@]}" "$WORK/local/short.txt" alice@127.0.0.1:a.txt && pass "scp overwrite exits 0" || fail "scp overwrite"
cmp -s "$WORK/local/short.txt" "$WORK/overwrite/share/a.txt" &&
	pass "scp overwrite gives an identical file" || fail "scp overwrite left stale bytes: $(od -c "$WORK/overwrite/share/a.txt" | head -3)"

# --- configuration file: users with read, upload and full access ----------
C="$WORK/cfg"
mkdir -p "$C/public" "$C/inbox" "$C/state"
printf 'public file\n' >"$C/public/readme.txt"
printf 'existing report\n' >"$C/inbox/report.txt"
printf 'existing document\n' >"$C/inbox/doc.bin"
for u in reader partner admin; do ssh-keygen -q -t ed25519 -N '' -C "$u" -f "$WORK/id_$u"; done
COURIER_PASSWORD='correct horse battery staple'
COURIER_HASH=$(printf '%s\n' "$COURIER_PASSWORD" | "$WORK/gosftpd" user hash-password --stdin)
printf '#!/bin/sh\necho "%s"\n' "$COURIER_PASSWORD" >"$WORK/askpass"; chmod 700 "$WORK/askpass"
PORT=$((20000 + RANDOM % 20000))
cat >"$C/gosftpd.toml" <<TOML
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
TOML
chmod 600 "$C/gosftpd.toml"
"$WORK/gosftpd" config validate --check-fs --config "$C/gosftpd.toml" >/dev/null && pass "config validate --check-fs" || fail "config validate"
sed 's/^read_only = true/read_onyl = true/' "$C/gosftpd.toml" >"$C/typo.toml"; chmod 600 "$C/typo.toml"
set +e; "$WORK/gosftpd" config validate --config "$C/typo.toml" 2>"$C/typo.err" >/dev/null; code=$?; set -e
[ "$code" = 2 ] && grep -q 'unknown key mounts.public.read_onyl' "$C/typo.err" &&
	pass "typo in a key: exit 2 naming the key" || fail "typo: exit $code: $(cat "$C/typo.err")"

"$WORK/gosftpd" serve --config "$C/gosftpd.toml" "${ROOT_FLAG[@]}" 2>"$C/server.log" &
CFG_PID=$!
PIDS+=("$CFG_PID")
for _ in $(seq 100); do
	if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then break; fi
	sleep 0.1
done
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
sed -i '/^\[users.partner\]/,/^$/d' "$C/gosftpd.toml"
cat >>"$C/gosftpd.toml" <<TOML

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
if "$WORK/gosftpd" user add carol --key "$WORK/id_carol.pub" --access public=read --write --config "$C/gosftpd.toml" \
	--host 127.0.0.1 >"$C/carol.out" 2>&1 && grep -q "connect: sftp -P $PORT carol@127.0.0.1" "$C/carol.out"; then
	pass "user add --write: file and connection details"
else
	fail "user add --write: $(cat "$C/carol.out")"
fi
hup || fail "reload after user add"
# shellcheck disable=SC2046
sftp -P "$PORT" $(as carol) -b "$C/pwd.batch" carol@127.0.0.1 >/dev/null 2>&1 && pass "user add --write: the user logs in after a reload" || fail "user add --write: carol cannot log in"
"$WORK/gosftpd" user disable carol --config "$C/gosftpd.toml" >/dev/null || fail "user disable"
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
cp "$WORK/user_ca.pub" "$C/user_ca.pub"
: >"$C/revoked"
chmod 600 "$C/user_ca.pub" "$C/revoked"
sed -i "s|^methods = \[\"publickey\", \"password\"\]|&\ntrusted_user_ca_keys_file = \"$C/user_ca.pub\"\nrevoked_keys_file = \"$C/revoked\"|" "$C/gosftpd.toml"
cat >>"$C/gosftpd.toml" <<TOML

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
cat "$WORK/id_dana-cert.pub" >>"$C/revoked"
hup || fail "reload after revoking"
# shellcheck disable=SC2046
if sftp -P "$PORT" $(as dana) -b "$C/pwd.batch" dana@127.0.0.1 >/dev/null 2>&1; then fail "certificate: a revoked certificate logged in"; else pass "certificate: a revoked certificate is refused after a reload"; fi
audit_has '"event":"auth.failure".*"reason":"key_revoked"' && pass "certificate: audit has reason key_revoked" || fail "certificate: no reason key_revoked"
cp "$C/revoked" "$C/revoked.txt"
ssh-keygen -q -k -f "$C/revoked" "$WORK/id_dana.pub"
errors=$(reload_errors)
if hup && [ "$(reload_errors)" -gt "$errors" ] && grep -q 'KRL' "$C/server.log"; then
	pass "certificate: a KRL fails the reload"
else
	fail "certificate: a KRL did not fail the reload"
fi
cp "$C/revoked.txt" "$C/revoked"
hup || fail "reload with the text revocation list"

# --- host key rotation and host certificates (ADR 0008) -----------------------
H="$WORK/hk"
mkdir -p "$H/data" "$H/state"
HPORT=$((20000 + RANDOM % 20000))
while [ "$HPORT" = "$PORT" ] || [ "$HPORT" = "$OVERWRITE_PORT" ]; do HPORT=$((HPORT + 1)); done
ssh-keygen -q -t ed25519 -N '' -f "$H/state/ed25519"
ssh-keygen -q -t rsa -b 3072 -N '' -f "$H/state/rsa"
cat >"$H/gosftpd.toml" <<TOML
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
chmod 600 "$H/gosftpd.toml"
"$WORK/gosftpd" serve --config "$H/gosftpd.toml" "${ROOT_FLAG[@]}" 2>"$H/server.log" &
HK_PID=$!
PIDS+=("$HK_PID")
for _ in $(seq 100); do
	if (exec 3<>"/dev/tcp/127.0.0.1/$HPORT") 2>/dev/null; then break; fi
	sleep 0.1
done
kill -0 "$HK_PID" 2>/dev/null || fail "host key server did not start: $(cat "$H/server.log")"
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
"$WORK/gosftpd" hostkey rotate --config "$H/gosftpd.toml" --host-key "$H/state/ed25519" >"$H/rotate.out" &&
	pass "hostkey rotate: next key created" || fail "hostkey rotate: $(cat "$H/rotate.out")"
hk_hup || fail "reload after hostkey rotate"
hk_sftp "$H/kh_ed" >"$H/sftp1.out" 2>&1 || fail "host keys: sftp during the rotation: $(cat "$H/sftp1.out")"
knows "$H/kh_ed" "$H/state/ed25519.next.pub" && pass "host keys: OpenSSH learned the next key (UpdateHostKeys)" ||
	fail "host keys: the next key is not in known_hosts: $(cat "$H/kh_ed")"
grep -q '"event":"conn.hostkeys_proved"' "$H/audit.jsonl" && pass "host keys: the proof is audited" || fail "host keys: no conn.hostkeys_proved"
cp "$H/state/ed25519.pub" "$H/old_ed25519.pub"
"$WORK/gosftpd" hostkey rotate --finish --config "$H/gosftpd.toml" --host-key "$H/state/ed25519" >"$H/finish.out" ||
	fail "hostkey rotate --finish: $(cat "$H/finish.out")"
hk_hup || fail "reload after --finish"
known_line "$H/state/ed25519.pub" >"$H/kh_new"
hk_sftp "$H/kh_new" -o UpdateHostKeys=no -o HostKeyAlgorithms=ssh-ed25519 >"$H/sftp2.out" 2>&1 &&
	pass "host keys: after --finish the server uses the new key" || fail "host keys: after --finish: $(cat "$H/sftp2.out")"
hk_sftp "$H/kh_ed" -o HostKeyAlgorithms=ssh-ed25519 >"$H/sftp2b.out" 2>&1 &&
	pass "host keys: a client that learned the key connects without a prompt" || fail "host keys: after --finish: $(cat "$H/sftp2b.out")"
knows "$H/kh_ed" "$H/old_ed25519.pub" && pass "host keys: the previous key stays until --retire" || fail "host keys: the previous key was dropped early"
"$WORK/gosftpd" hostkey rotate --retire --config "$H/gosftpd.toml" --host-key "$H/state/ed25519" >/dev/null || fail "hostkey rotate --retire"
hk_hup || fail "reload after --retire"
hk_sftp "$H/kh_ed" >/dev/null 2>&1 || fail "host keys: sftp after --retire"
if knows "$H/kh_ed" "$H/old_ed25519.pub"; then fail "host keys: the retired key is still in known_hosts"; else pass "host keys: OpenSSH forgot the retired key"; fi

# RSA, with rsa-sha2-256 negotiated: proofs must use the same hash. A single
# command also checks that a short session waits for the proof.
"$WORK/gosftpd" hostkey rotate --config "$H/gosftpd.toml" --host-key "$H/state/rsa" >/dev/null || fail "hostkey rotate (rsa)"
hk_hup || fail "reload after hostkey rotate (rsa)"
hk_sftp "$H/kh_rsa" -o HostKeyAlgorithms=rsa-sha2-256 >"$H/sftp3.out" 2>&1 || fail "host keys: sftp with rsa-sha2-256: $(cat "$H/sftp3.out")"
knows "$H/kh_rsa" "$H/state/rsa.next.pub" && pass "host keys: an RSA next key is learned with rsa-sha2-256" ||
	fail "host keys: the RSA next key is not in known_hosts: $(cat "$H/kh_rsa")"
"$WORK/gosftpd" hostkey rotate --abort --config "$H/gosftpd.toml" --host-key "$H/state/rsa" >/dev/null || fail "hostkey rotate --abort"

# Host certificates: a client that trusts only the CA connects.
ssh-keygen -q -t ed25519 -N '' -C host_ca -f "$WORK/host_ca"
ssh-keygen -q -s "$WORK/host_ca" -h -I gosftpd -n 127.0.0.1 -V -5m:+1h "$H/state/ed25519.pub"
sed -i 's|^host_keys = .*|&\nhost_certificates = true|' "$H/gosftpd.toml"
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

# An invalid configuration is refused; the running one stays.
printf '[server\n' >>"$C/gosftpd.toml"
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

if [ "$FAILED" -ne 0 ]; then
	echo "--- server log (rename)"; cat "$WORK/rename/server.log"
	echo "--- server log (config)"; cat "$C/server.log"
	echo "--- server log (host keys)"; cat "$WORK/hk/server.log"
	exit 1
fi
echo "all interop checks passed ($(ssh -V 2>&1))"
