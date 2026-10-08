#!/usr/bin/env bash
# Interop test: real OpenSSH sftp, scp and ssh clients against a freshly
# built gosftpd. Usage: test/interop/run.sh (from anywhere). Needs bash,
# openssh-client and Go. KEEP_WORK=1 keeps the work directory for inspection.
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

(cd "$ROOT" && go build -o "$WORK/gosftpd" ./cmd/gosftpd)
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
		--listen "127.0.0.1:$PORT" --audit-output "$WORK/$name/audit.jsonl" \
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

# --- signals: HUP is ignored until reload exists, TERM exits cleanly -------
RENAME_PID=${PIDS[0]}
kill -HUP "$RENAME_PID"; sleep 0.5
kill -0 "$RENAME_PID" 2>/dev/null && pass "SIGHUP does not stop the server" || fail "SIGHUP stopped the server"
kill -TERM "$RENAME_PID"
if wait "$RENAME_PID"; then pass "SIGTERM exits 0"; else fail "SIGTERM exit code $?"; fi
grep -q '"event":"server.stop"' "$WORK/rename/audit.jsonl" && pass "audit has server.stop" || fail "audit lacks server.stop"

# --- on_conflict=overwrite: scp over a longer file must not keep its tail --
start_server overwrite overwrite
scp -q -P "$PORT" "${OPTS[@]}" "$WORK/local/short.txt" alice@127.0.0.1:a.txt && pass "scp overwrite exits 0" || fail "scp overwrite"
cmp -s "$WORK/local/short.txt" "$WORK/overwrite/share/a.txt" &&
	pass "scp overwrite gives an identical file" || fail "scp overwrite left stale bytes: $(od -c "$WORK/overwrite/share/a.txt" | head -3)"

# --- configuration file: users with read, upload and full access ----------
C="$WORK/cfg"
mkdir -p "$C/public" "$C/inbox" "$C/state"
printf 'public file\n' >"$C/public/readme.txt"
printf 'existing report\n' >"$C/inbox/report.txt"
for u in reader partner admin; do ssh-keygen -q -t ed25519 -N '' -C "$u" -f "$WORK/id_$u"; done
PORT=$((20000 + RANDOM % 20000))
cat >"$C/gosftpd.toml" <<TOML
config_version = 1

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

[users.reader]
authorized_keys = ["$(cat "$WORK/id_reader.pub")"]
access = { public = "read" }

[users.partner]
authorized_keys_file = "$WORK/id_partner.pub"
access = { inbox = "upload" }

[users.admin]
authorized_keys = ["$(cat "$WORK/id_admin.pub")"]
access = { public = "read", inbox = "full", home = "full" }

[audit]
output = "$C/audit.jsonl"
TOML
chmod 600 "$C/gosftpd.toml"
"$WORK/gosftpd" config validate --check-fs --config "$C/gosftpd.toml" >/dev/null && pass "config validate --check-fs" || fail "config validate"
sed 's/^read_only = true/read_onyl = true/' "$C/gosftpd.toml" >"$C/typo.toml"; chmod 600 "$C/typo.toml"
set +e; "$WORK/gosftpd" config validate --config "$C/typo.toml" 2>"$C/typo.err" >/dev/null; code=$?; set -e
[ "$code" = 2 ] && grep -q 'unknown key mounts.public.read_onyl' "$C/typo.err" &&
	pass "typo in a key: exit 2 naming the key" || fail "typo: exit $code: $(cat "$C/typo.err")"

"$WORK/gosftpd" serve --config "$C/gosftpd.toml" 2>"$C/server.log" &
PIDS+=($!)
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
grep -q 'home' "$C/admin.out" && grep -q 'inbox' "$C/admin.out" && grep -q 'public' "$C/admin.out" && pass "admin: sees three mounts" || fail "admin: mounts"
cmp -s "$WORK/local/short.txt" "$C/home/admin/notes.txt" && pass "admin: home created" || fail "admin: home"
[ ! -e "$C/inbox/new.txt" ] && pass "admin: delete" || fail "admin: delete"

# An unknown user is refused.
# shellcheck disable=SC2046
if sftp -P "$PORT" $(as admin) -b "$C/admin.batch" mallory@127.0.0.1 >/dev/null 2>&1; then fail "unknown user accepted"; else pass "unknown user refused"; fi

if [ "$FAILED" -ne 0 ]; then
	echo "--- server log (rename)"; cat "$WORK/rename/server.log"
	echo "--- server log (config)"; cat "$C/server.log"
	exit 1
fi
echo "all interop checks passed ($(ssh -V 2>&1))"
