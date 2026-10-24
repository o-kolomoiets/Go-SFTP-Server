#!/usr/bin/env bash
# The atmoz step of the docker CI job (ADR 0012): the examples of the
# atmoz/sftp README run against the gosftpd image, with OpenSSH's sftp on
# the host and the changes docs/migrate-from-atmoz.md asks for (-p 2222:2022,
# chown of the mounted files, a bcrypt hash instead of MD5-crypt).
#
# Usage: test/docker/atmoz.sh IMAGE, an image already loaded: the script
# never pulls. Needs bash, docker, openssh-client (sftp, ssh-keygen,
# ssh-keyscan) and, unless run as root, passwordless sudo for chown. It
# runs under umask 002, as the docker CI job's other step does.
# ATMOZ_PORT is the host port (default 2222); KEEP_WORK=1 keeps the work
# directory. REQUIRE_LANDLOCK=1 (CI) fails when gosftpd does not apply
# Landlock in a container.
set -euo pipefail
umask 002

IMAGE=${1:?usage: test/docker/atmoz.sh IMAGE}
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
	echo "$IMAGE is not loaded: test/docker/atmoz.sh never pulls" >&2
	exit 2
fi
PORT=${ATMOZ_PORT:-2222}
WORK="$(mktemp -d)"
NAME="gosftpd-atmoz-$$"
VOLUME="$NAME-home"
FAILED=0
SUDO=()
if [ "$(id -u)" != 0 ]; then SUDO=(sudo -n); fi

cleanup() {
	docker rm -f "$NAME" >/dev/null 2>&1 || true
	docker volume rm "$VOLUME" >/dev/null 2>&1 || true
	[ -n "${KEEP_WORK:-}" ] || "${SUDO[@]}" rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; FAILED=1; }
pass() { echo "ok:   $*"; }

# A bcrypt hash (cost 10) of bcrypt-pass, made with golang.org/x/crypto's
# bcrypt.GenerateFromPassword; htpasswd -bnBC 10 "" PASS gives the same
# kind ($2y$).
# shellcheck disable=SC2016 # a hash, not an expansion
BCRYPT='$2a$10$RcH8D45QEB5BOyLwCaUxK.V9TzVMqA40N/xfDh26xBpuHZLMj5ive'
# Passwords that no message may show.
PW1=atmoz-first-secret
PW2=atmoz-second-secret

# wait_up: waits until the container answers on PORT and records its host
# key in known_hosts; fails when the container stops first.
wait_up() {
	for _ in $(seq 150); do
		if ssh-keyscan -T 2 -p "$PORT" 127.0.0.1 >"$WORK/known_hosts" 2>/dev/null && [ -s "$WORK/known_hosts" ]; then
			return 0
		fi
		if [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" != true ]; then
			echo "--- docker logs $NAME" >&2
			docker logs "$NAME" >&2 2>&1 || true
			return 1
		fi
		sleep 0.2
	done
	return 1
}

# start ARG...: runs a container of IMAGE as NAME, port 2022 published as
# PORT; ARG... are docker run's options, the image and its arguments. The
# container must have applied Landlock; without REQUIRE_LANDLOCK a kernel
# without it is accepted.
start() {
	docker rm -f "$NAME" >/dev/null 2>&1 || true
	docker run -d --name "$NAME" -p "127.0.0.1:$PORT:2022" "$@" >/dev/null
	wait_up || { echo "FAIL: the container did not start: docker run $*" >&2; exit 1; }
	if ! logged 'landlock: ABI v[0-9]* applied' && { [ -n "${REQUIRE_LANDLOCK:-}" ] || ! logged 'landlock: not available'; }; then
		fail "no Landlock ruleset: $(grep landlock "$WORK/log" | head -n 3)"
	fi
}

# healthy: the image's health check passes within 30 s.
healthy() {
	local s
	for _ in $(seq 120); do
		s=$(docker inspect -f '{{.State.Health.Status}}' "$NAME")
		case $s in
		healthy) return 0 ;;
		unhealthy) return 1 ;;
		esac
		sleep 0.25
	done
	return 1
}

# logged PATTERN: the container's output, its audit and operational log,
# holds PATTERN. The log is saved first: grep -q would end docker logs
# with SIGPIPE, which pipefail reports.
logged() {
	docker logs "$NAME" >"$WORK/log" 2>&1
	grep -q -- "$1" "$WORK/log"
}

# started: the container's log holds the audit event server.start, which
# gosftpd writes once its listeners are bound, before it serves. Unlike a
# probe of the port, it still tells after the container has exited.
started() { logged '"event":"server.start"'; }

# no_secrets WHAT: no log shows a password, a spec or a hash.
no_secrets() {
	docker logs "$NAME" >"$WORK/log" 2>&1
	if grep -qF -e "$PW1" -e "$PW2" -e "foo:pass" -e "$BCRYPT" -e 'bcrypt-pass' "$WORK/log"; then
		fail "$1: the log shows a password or a spec"
	else
		pass "$1: no password in the log"
	fi
}

# listing: what the last sftp listed, without the commands it echoed.
listing() { grep -v '^sftp>' "$WORK/sftp.out" | tr '\n' ' ' | sed 's/ $//'; }

# batch LINE...: writes an sftp batch file and prints its path.
batch() {
	printf '%s\n' "$@" >"$WORK/batch"
	echo "$WORK/batch"
}

# sftp_pw USER PASSWORD BATCH: sftp with a password login, through
# SSH_ASKPASS, checking the host key.
sftp_pw() {
	printf '#!/bin/sh\necho %s\n' "$2" >"$WORK/askpass"
	chmod 700 "$WORK/askpass"
	SSH_ASKPASS="$WORK/askpass" SSH_ASKPASS_REQUIRE=force sftp -F /dev/null -P "$PORT" -o BatchMode=no \
		-o "UserKnownHostsFile=$WORK/known_hosts" -o StrictHostKeyChecking=yes -o PreferredAuthentications=password \
		-o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 -b "$3" "$1@127.0.0.1" </dev/null >"$WORK/sftp.out" 2>&1
}

# sftp_key USER KEY BATCH: sftp with a key login, checking the host key.
sftp_key() {
	sftp -F /dev/null -P "$PORT" -o BatchMode=yes -o IdentitiesOnly=yes -i "$2" \
		-o "UserKnownHostsFile=$WORK/known_hosts" -o StrictHostKeyChecking=yes -b "$3" "$1@127.0.0.1" </dev/null >"$WORK/sftp.out" 2>&1
}

# own UID FILE...: chown as the migration guide does.
own() {
	local uid=$1
	shift
	"${SUDO[@]}" chown "$uid:$uid" "$@"
}

mkdir -p "$WORK/local"
printf 'the first upload, which is longer\n' >"$WORK/local/a.txt"
printf 'the second\n' >"$WORK/local/b.txt"

# --- docker run -p 22:22 -d atmoz/sftp foo:pass:::upload -----------------
start "$IMAGE" foo:pass:::upload
healthy && pass "foo:pass:::upload: healthy" || fail "foo:pass:::upload: $(docker inspect -f '{{json .State.Health}}' "$NAME")"
if sftp_pw foo pass "$(batch "put $WORK/local/a.txt upload/a.txt" "put $WORK/local/b.txt upload/a.txt" \
	"get upload/a.txt $WORK/local/got.txt" "-put $WORK/local/a.txt /root.txt" '-mkdir /dir')"; then
	pass "foo:pass:::upload: password login, two uploads of one name"
else
	fail "foo:pass:::upload: $(tail -3 "$WORK/sftp.out")"
fi
sftp_pw foo pass "$(batch 'ls -1 upload')" && [ "$(listing)" = "upload/a.txt" ] && cmp -s "$WORK/local/b.txt" "$WORK/local/got.txt" &&
	pass "foo:pass:::upload: the second upload overwrote the first" || fail "foo:pass:::upload: no overwrite: $(listing)"
sftp_pw foo pass "$(batch 'ls -1')" && [ "$(listing)" = upload ] &&
	pass "foo:pass:::upload: / holds only upload and is read-only" || fail "foo:pass:::upload: / lists $(listing)"
logged 'msg="atmoz mode" users_file=0 arguments=1 sftp_users=0' && logged 'argument 1 (user foo): the password is in plain text' &&
	pass "foo:pass:::upload: atmoz mode logged, with the plain password warning" || fail "foo:pass:::upload: log: $(head -5 "$WORK/log")"
docker kill -s HUP "$NAME" >/dev/null
for _ in $(seq 50); do
	if logged 'msg="SIGHUP ignored"'; then break; fi
	sleep 0.1
done
logged 'msg="SIGHUP ignored"' && sftp_pw foo pass "$(batch 'ls upload')" &&
	pass "foo:pass:::upload: SIGHUP is logged and ignored" || fail "foo:pass:::upload: SIGHUP: $(grep -i hup "$WORK/log")"
no_secrets "foo:pass:::upload"

# --- A user given twice: the first definition wins ------------------------
start "$IMAGE" "foo:$PW1:::upload" "foo:$PW2"
if sftp_pw foo "$PW1" "$(batch 'ls')" && ! sftp_pw foo "$PW2" "$(batch 'ls')" &&
	logged 'argument 2: user foo is already defined by argument 1; skipped, as atmoz skips it'; then
	pass "a user given twice: skipped, with a warning"
else
	fail "a user given twice: $(grep -i defined "$WORK/log")"
fi
no_secrets "a user given twice"

# --- Logging in with SSH keys: each key mounted as a file -----------------
H="$WORK/host"
mkdir -p "$H/share"
ssh-keygen -q -t ed25519 -N '' -C id_rsa -f "$WORK/id_rsa"
ssh-keygen -q -t ed25519 -N '' -C id_other -f "$WORK/id_other"
cp "$WORK/id_rsa.pub" "$WORK/id_other.pub" "$H/"
chmod 0644 "$H/id_rsa.pub" "$H/id_other.pub"
own 0 "$H/id_rsa.pub" "$H/id_other.pub"
own 65532 "$H/share"
start -v "$H/id_rsa.pub:/home/foo/.ssh/keys/id_rsa.pub:ro" -v "$H/id_other.pub:/home/foo/.ssh/keys/id_other.pub:ro" \
	-v "$H/share:/home/foo/share" "$IMAGE" foo::1001
if sftp_key foo "$WORK/id_rsa" "$(batch "put $WORK/local/a.txt share/a.txt")" &&
	sftp_key foo "$WORK/id_other" "$(batch 'ls -1')" && [ "$(listing)" = share ] &&
	"${SUDO[@]}" cmp -s "$WORK/local/a.txt" "$H/share/a.txt"; then
	pass "keys: both keys log in, the existing volume directory is /share"
else
	fail "keys: $(tail -3 "$WORK/sftp.out")"
fi
owner=$("${SUDO[@]}" stat -c %u "$H/share/a.txt")
[ "$owner" = 65532 ] && pass "keys: the upload belongs to 65532" || fail "keys: the upload belongs to $owner"
sftp_pw foo anything "$(batch 'ls')" && fail "keys: foo:: logs in with a password" || pass "keys: foo:: has no password login"

# A key removed on the host is refused after docker restart: the keys are
# read once, at start. The keys directory is mounted whole here: Docker
# recreates a removed single-file source as a directory, and the container
# then fails to start.
mkdir -p "$H/keys"
cp "$WORK/id_rsa.pub" "$WORK/id_other.pub" "$H/keys/"
chmod 0755 "$H/keys"
chmod 0644 "$H/keys/"*
own 0 "$H/keys" "$H/keys/"*
start -v "$H/keys:/home/foo/.ssh/keys:ro" -v "$H/share:/home/foo/share" "$IMAGE" foo::1001
sftp_key foo "$WORK/id_rsa" "$(batch 'ls')" && pass "keys: id_rsa logs in" || fail "keys: id_rsa: $(tail -3 "$WORK/sftp.out")"
"${SUDO[@]}" rm "$H/keys/id_rsa.pub"
docker restart "$NAME" >/dev/null
wait_up || fail "keys: the container did not come back after docker restart"
if ! sftp_key foo "$WORK/id_rsa" "$(batch 'ls')" && sftp_key foo "$WORK/id_other" "$(batch 'ls')"; then
	pass "keys: a key removed on the host is refused after docker restart"
else
	fail "keys: after docker restart: $(tail -3 "$WORK/sftp.out")"
fi
no_secrets "keys"

# --- Store users in config: users.conf and a named volume on /home --------
printf 'foo:123:1001:100\nbar:abc:1002:100\nbaz:xyz:1003:100\n' >"$WORK/users.conf"
chmod 0644 "$WORK/users.conf"
own 0 "$WORK/users.conf"
start -v "$WORK/users.conf:/etc/sftp/users.conf:ro" -v "$VOLUME:/home" "$IMAGE"
if sftp_pw foo 123 "$(batch 'ls')" && sftp_pw baz xyz "$(batch 'ls')" &&
	sftp_pw bar abc "$(batch "-put $WORK/local/a.txt /a.txt" '-mkdir /dir')" &&
	sftp_pw bar abc "$(batch 'ls -1')" && [ -z "$(listing)" ]; then
	pass "users.conf: three users without directories log in to an empty read-only root"
else
	fail "users.conf: $(tail -3 "$WORK/sftp.out")"
fi
logged 'msg="atmoz mode" users_file=3 arguments=0 sftp_users=0' && logged '/etc/sftp/users.conf line 2 (user bar): no directories' &&
	logged 'msg="atmoz mode: the uid and gid of user specs are ignored"' &&
	pass "users.conf: logged with the warnings" || fail "users.conf: log: $(head -8 "$WORK/log")"
# The new volume starts with the image's /home, which holds the base
# image's /home/nonroot (0700, 65532): a directory in /home is not a user.
home=$(docker volume inspect -f '{{.Mountpoint}}' "$VOLUME")
if "${SUDO[@]}" test -d "$home/nonroot" && logged '^auth: .* 3 users,' && ! logged nonroot; then
	pass "users.conf: the volume's nonroot directory is not a user"
else
	fail "users.conf: nonroot: $(grep nonroot "$WORK/log")"
fi
no_secrets "users.conf"

# --- Encrypted password: MD5-crypt is refused, bcrypt works ---------------
# shellcheck disable=SC2016 # the README's hash, not an expansion
MD5='$1$0G2g0GSt$ewU0t6GXG15.0hWoOX8X9.'
code=0
out=$(docker run --rm "$IMAGE" "foo:$MD5:e:1001" 2>&1) || code=$?
if [ "$code" = 2 ] && grep -q "it is an MD5-crypt hash, which gosftpd does not verify" <<<"$out" &&
	grep -q "create a hash with 'gosftpd user hash-password'" <<<"$out" && ! grep -qF "$MD5" <<<"$out"; then
	pass "MD5-crypt (:e): exit 2, with the fix and without the hash"
else
	fail "MD5-crypt (:e): exit $code: $out"
fi
start "$IMAGE" "foo:$BCRYPT:e:::upload"
sftp_pw foo bcrypt-pass "$(batch 'ls')" && pass "bcrypt (:e): password login" || fail "bcrypt (:e): $(tail -3 "$WORK/sftp.out")"
no_secrets "bcrypt (:e)"

# --- SFTP_USERS ---------------------------------------------------------
start -e "SFTP_USERS=foo:$PW1:::upload bar:$PW2:::inbox" "$IMAGE"
if sftp_pw foo "$PW1" "$(batch 'ls -1')" && [ "$(listing)" = upload ] &&
	sftp_pw bar "$PW2" "$(batch 'ls -1')" && [ "$(listing)" = inbox ]; then
	pass "SFTP_USERS: both users log in"
else
	fail "SFTP_USERS: $(tail -3 "$WORK/sftp.out")"
fi
logged 'SFTP_USERS entry 2 (user bar): the password is in plain text' &&
	pass "SFTP_USERS: the plain password warning names the entry" || fail "SFTP_USERS: log: $(head -5 "$WORK/log")"
no_secrets "SFTP_USERS"

# --- Providing your own SSH host key ------------------------------------
ssh-keygen -q -t ed25519 -N '' -f "$WORK/ssh_host_ed25519_key"
chmod 0600 "$WORK/ssh_host_ed25519_key"
own 65532 "$WORK/ssh_host_ed25519_key"
start -v "$WORK/ssh_host_ed25519_key:/etc/ssh/ssh_host_ed25519_key:ro" "$IMAGE" "foo:$PW1:::upload"
want=$(ssh-keygen -lf "$WORK/ssh_host_ed25519_key.pub" | awk '{print $2}')
got=$(ssh-keygen -lf "$WORK/known_hosts" | awk '{print $2}')
[ "$want" = "$got" ] && pass "host key: /etc/ssh/ssh_host_ed25519_key is served" || fail "host key: $got, want $want"

# --- A missing configuration directory with SFTP_USERS: exit 2 ----------
# The container is checked once it has exited, when its port is closed
# whatever it did: the log tells whether it listened. The container of the
# last step listened, and after docker stop the check must still see it.
docker stop "$NAME" >/dev/null
started && pass "a container that listened and exited: its log has server.start" ||
	fail "a container that listened and exited: no server.start in its log: $(head -3 "$WORK/log")"
docker rm -f "$NAME" >/dev/null
docker run -d --name "$NAME" -p "127.0.0.1:$PORT:2022" -v "$WORK/missing:/etc/gosftpd:ro" -e "SFTP_USERS=foo:$PW1:::upload" "$IMAGE" >/dev/null
code=$(docker wait "$NAME")
if [ "$code" = 2 ] && logged '/etc/gosftpd is mounted but holds no config.toml' &&
	! logged 'msg="atmoz mode"' && ! started; then
	pass "missing configuration directory: exit 2 with the hint, never atmoz mode, never listened"
else
	fail "missing configuration directory: exit $code: $(head -3 "$WORK/log")"
fi
no_secrets "missing configuration directory"

# --- A spec after serve: a usage error that does not show it ------------
code=0
out=$(docker run --rm "$IMAGE" serve "foo:$PW1:::upload" 2>&1) || code=$?
if [ "$code" = 2 ] && grep -q "not shown: it looks like an atmoz user spec; give specs directly after the image name, without 'serve'" <<<"$out" &&
	! grep -qF "$PW1" <<<"$out"; then
	pass "serve SPEC: exit 2 without the spec"
else
	fail "serve SPEC: exit $code: $out"
fi

if [ "$FAILED" -ne 0 ]; then
	echo "--- docker logs $NAME"
	docker logs "$NAME" 2>&1 || true
	exit 1
fi
echo "all atmoz checks passed ($IMAGE)"
