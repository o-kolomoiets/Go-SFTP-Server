#!/usr/bin/env bash
# The image against the documented Docker commands, as the CI job "docker"
# runs them on amd64 and arm64 (ADR 0012):
# - the quickstart block of docs/install.md: the container becomes healthy,
#   applies Landlock and takes an sftp upload, stops cleanly, and a new
#   container keeps the host key;
# - a reload: the configuration replaced with sed -i (a new inode) in the
#   mounted directory and docker kill -s HUP; a removed user is refused;
# - the hint: started with -v ./gosftpd:/etc/gosftpd:ro while ./gosftpd
#   does not exist, the container exits 2 with the hint, whose commands are
#   followed (the key placeholder replaced before the chown and chmod) to
#   a healthy container on named volumes;
# - the compose block, with read_only, its image (a digest) overridden by
#   the image under test, run while the Quickstart's container still runs
#   in the Quickstart's directory, as the reader does: it replaces that
#   container and keeps its host key and uploads; and the same after each
#   variant of the Quickstart that install.md gives (named volumes, your
#   own uid), with the setting the compose section gives for it;
# - serve --ephemeral in a container, as ADR 0012 has it: --listen
#   0.0.0.0:2022 with the port mapped, the client key copied out with
#   docker cp (the image has no shell for docker exec).
#
# Usage: test/docker/run.sh IMAGE V
# IMAGE is the image under test, already loaded (in CI the snapshot that
# goreleaser-check saved); V is the version the blocks name as v$V. Every
# reference the run uses is tagged to IMAGE first, so that docker run
# never pulls (a snapshot reports the last release tag, whose real image
# may exist in GHCR), and every container is checked to run IMAGE.
#
# It runs as a user other than root with passwordless sudo and access to
# Docker, under umask 002, as the Quickstart's users do. It uses ports 2022
# (the blocks' own) and 2023, the container names gosftpd, gosftpd-ci-hint
# and gosftpd-ci-ephemeral, the volumes gosftpd-ci-data and
# gosftpd-ci-state and those of the named-volume variant, gosftpd-data and
# gosftpd-state, and the compose projects "quickstart",
# "quickstart-volumes" and "quickstart-uid", and refuses to start when one
# of them is in use; it removes them, the tags it added and its directory
# at the end.
# REQUIRE_LANDLOCK=1 (CI) fails when gosftpd does not apply Landlock, which
# is missing under QEMU, for example. Needs openssh-client and jq.

# Functions called through check and the EXIT trap are not unreachable.
# shellcheck disable=SC2317,SC2329
set -euo pipefail
umask 002

if [ $# -ne 2 ]; then
	echo "usage: test/docker/run.sh IMAGE V" >&2
	exit 2
fi
IMAGE=$1
export V=$2
REPO=ghcr.io/o-kolomoiets/gosftpd
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
if [ "$(id -u)" = 0 ]; then
	echo "run test/docker/run.sh as a user other than root: the Quickstart runs without root" >&2
	exit 2
fi
sudo -n true || { echo "test/docker/run.sh needs passwordless sudo" >&2; exit 2; }

FAILED=0
WORK="$(mktemp -d)"
# HOME for the blocks: the Quickstart reads ~/.ssh/id_ed25519.pub.
BLOCK_HOME="$WORK/home"
KEY="$BLOCK_HOME/.ssh/id_ed25519"
ADDED_TAGS=()
COMPOSE_DIR=
VOLUMES=(gosftpd-ci-data gosftpd-ci-state gosftpd-data gosftpd-state)
# The container whose log a failure prints.
CURRENT=

fail() { echo "FAIL: $*" >&2; FAILED=1; }
pass() { echo "ok:   $*"; }
die() { fail "$*"; exit 1; }
phase() { printf '\n=== %s\n' "$*"; }
on_exit() {
	local status=$?
	if [ -n "$CURRENT" ] && { [ "$FAILED" != 0 ] || [ "$status" != 0 ]; }; then
		echo "--- docker logs $CURRENT" >&2
		docker logs "$CURRENT" >&2 || true
	fi
	docker rm -f gosftpd gosftpd-ci-hint gosftpd-ci-ephemeral >/dev/null 2>&1 || true
	if [ -n "$COMPOSE_DIR" ]; then
		(cd "$COMPOSE_DIR" && docker compose down --volumes --timeout 5 >/dev/null 2>&1) || true
	fi
	docker volume rm "${VOLUMES[@]}" >/dev/null 2>&1 || true
	for t in "${ADDED_TAGS[@]}"; do docker rmi "$t" >/dev/null 2>&1 || true; done
	# The data and state directories belong to 65532.
	sudo rm -rf "$WORK"
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

# wait_healthy CONTAINER: waits up to 60 s for the health check to pass.
wait_healthy() {
	local c=$1 state start=$SECONDS
	CURRENT=$c
	for _ in $(seq 240); do
		state=$(docker inspect -f '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' "$c")
		case $state in
		"running healthy")
			pass "$c is healthy after $((SECONDS - start)) s"
			return 0
			;;
		"running unhealthy" | exited* | dead*) break ;;
		esac
		sleep 0.25
	done
	docker inspect -f '{{json .State.Health}}' "$c" >&2 || true
	die "$c is not healthy: $state"
}

# landlock CONTAINER: the container's log says that Landlock was applied;
# without REQUIRE_LANDLOCK a kernel without it only skips.
landlock() {
	local log
	log=$(logs "$1")
	if grep -q 'landlock: ABI v[0-9]* applied' <<<"$log"; then
		pass "$1: $(grep -o 'landlock: ABI v[0-9]* applied' <<<"$log" | head -n 1)"
	elif [ -z "${REQUIRE_LANDLOCK:-}" ] && grep -q 'landlock: not available' <<<"$log"; then
		echo "skip: $1: $(grep -o 'landlock: not available.*' <<<"$log" | head -n 1 | tr -d '"')"
	else
		fail "$1: no Landlock ruleset: $(grep landlock <<<"$log" | head -n 3)"
	fi
}

# keyscan PORT FILE: writes the server's ed25519 host key to the
# known_hosts FILE and prints its fingerprint.
keyscan() {
	local out
	for _ in $(seq 20); do
		out=$(ssh-keyscan -p "$1" -t ed25519 127.0.0.1 2>/dev/null) && [ -n "$out" ] && break
		sleep 0.5
	done
	[ -n "$out" ] || die "ssh-keyscan found no host key on port $1"
	printf '%s\n' "$out" >"$2"
	ssh-keygen -lf "$2" | awk '{ print $2 }'
}

# sftp_as USER PORT KNOWN_HOSTS COMMAND...: runs the sftp commands as USER
# with the test key, checking the host key against KNOWN_HOSTS.
sftp_as() {
	local user=$1 port=$2 kh=$3
	shift 3
	printf '%s\n' "$@" | sftp -q -b - -F /dev/null -P "$port" -i "$KEY" \
		-o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes \
		-o UserKnownHostsFile="$kh" -o GlobalKnownHostsFile=/dev/null \
		"$user@127.0.0.1"
}

# refused USER PORT KNOWN_HOSTS: USER cannot log in.
refused() { ! sftp_as "$1" "$2" "$3" ls 2>/dev/null; }

# logs CONTAINER: the container's standard output and error.
logs() { docker logs "$1" 2>&1; }

# count PATTERN TEXT: the number of lines of TEXT that match PATTERN.
count() { grep -c -- "$1" <<<"$2" || true; }

# gone CONTAINER: no such container exists.
gone() { ! docker container inspect "$1" >/dev/null 2>&1; }

# image_of CONTAINER: the image ID the container runs.
image_of() { docker inspect -f '{{.Image}}' "$1"; }

# owner_mode PATH: uid:gid and the octal mode, read with sudo.
owner_mode() { sudo stat -c '%u:%g %a' "$1"; }

# tag REF: tags IMAGE as REF, which must not exist yet or be IMAGE already.
tag() {
	local id
	if id=$(docker image inspect -f '{{.Id}}' "$1" 2>/dev/null); then
		[ "$id" = "$IMAGE_ID" ] || die "$1 exists and is another image ($id); remove it first"
		return
	fi
	docker tag "$IMAGE" "$1"
	ADDED_TAGS+=("$1")
}

# compose_files: a stand-in for the release's digests.txt, and an override
# that replaces the image, a digest that a local image cannot be tagged
# with, and never pulls; in the current directory. Prints the digest.
compose_files() {
	local digest=${IMAGE_ID#sha256:}
	printf '%s  %s\n' "$digest" "$REPO:v$V" >digests.txt
	printf 'services:\n  gosftpd:\n    image: %s\n    pull_policy: never\n' "$REPO:v$V" >compose.override.yaml
	echo "$digest"
}

# variant NAME: the quickstart block with the changes that install.md gives
# for its variant NAME (volumes or uid), which its text must still name.
variant() {
	local block text words
	block=$("$ROOT/test/docs/run-block.sh" --print quickstart)
	text=$(tr -s ' \n' '  ' <"$ROOT/docs/install.md")
	# The changes, as install.md words them.
	# shellcheck disable=SC2016
	case $1 in
	volumes)
		words='Leave out `sudo chown 65532:65532 data state` and mount `-v gosftpd-data:/srv/sftp -v gosftpd-state:/var/lib/gosftpd` instead.'
		block=$(sed -e '/^sudo chown 65532:65532 data state$/d' \
			-e 's|-v ./data:/srv/sftp -v ./state:/var/lib/gosftpd|-v gosftpd-data:/srv/sftp -v gosftpd-state:/var/lib/gosftpd|' <<<"$block")
		grep -qF -- '-v gosftpd-data:/srv/sftp -v gosftpd-state:/var/lib/gosftpd' <<<"$block" ||
			die "the volumes variant: the quickstart block has no -v ./data and ./state to replace"
		;;
	uid)
		words='with `--user "$(id -u):$(id -g)"` added to `docker run -d`, needs no `sudo`: leave out both `chown` lines and run `chmod 0600 gosftpd/config.toml` instead.'
		block=$(sed -e '/^sudo chown 65532:65532 data state$/d' \
			-e 's|^sudo chown root:65532 gosftpd/config.toml && sudo chmod 0640 gosftpd/config.toml$|chmod 0600 gosftpd/config.toml|' \
			-e 's|^docker run -d |docker run -d --user "$(id -u):$(id -g)" |' <<<"$block")
		if ! grep -qxF 'chmod 0600 gosftpd/config.toml' <<<"$block" || ! grep -qF -- 'docker run -d --user' <<<"$block"; then
			die "the uid variant: the quickstart block has no chown of gosftpd/config.toml or docker run -d to change"
		fi
		;;
	esac
	grep -qF -- "$words" <<<"$text" || die "install.md no longer gives the $1 variant as: $words"
	! grep -q 'chown 65532:65532 data state' <<<"$block" || die "the $1 variant still gives data and state to 65532"
	[ "$1" != uid ] || ! grep -q 'chown' <<<"$block" || die "the uid variant still has a chown"
	printf '%s\n' "$block"
}

phase "the image and the references the run uses"
IMAGE_ID=$(docker image inspect -f '{{.Id}}' "$IMAGE") || die "$IMAGE is not loaded"
for c in gosftpd gosftpd-ci-hint gosftpd-ci-ephemeral; do
	! docker container inspect "$c" >/dev/null 2>&1 || die "a container $c exists; remove it first"
done
for p in quickstart quickstart-volumes quickstart-uid; do
	[ -z "$(docker ps -aq --filter "label=com.docker.compose.project=$p")" ] ||
		die "the compose project $p has containers; remove them first"
done
for v in "${VOLUMES[@]}"; do
	! docker volume inspect "$v" >/dev/null 2>&1 || die "a volume $v exists; remove it first"
done
for port in 2022 2023; do
	! (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null || die "port $port is in use"
done
arch=$(docker image inspect -f '{{.Architecture}}' "$IMAGE")
info=$(docker run --rm "$IMAGE" version --json)
equal "the binary's platform" "$(jq -r .platform <<<"$info")" "linux/$arch"
version=$(jq -r .version <<<"$info")
# The hint names the binary's own version, or latest for a build that is
# not a release's (internal/cli/hint.go).
if [[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)(\.[0-9]+)?)?$ ]]; then
	HINT_REF="$REPO:$version"
else
	HINT_REF="$REPO:latest"
fi
tag "$REPO:v$V"
tag "$HINT_REF"
pass "$IMAGE (linux/$arch, version $version) tagged $REPO:v$V and $HINT_REF"
mkdir -p "$BLOCK_HOME/.ssh"
ssh-keygen -q -t ed25519 -N '' -C gosftpd-docker-test -f "$KEY"
head -c 2000000 /dev/urandom >"$WORK/upload.bin"

phase "the quickstart block"
QS="$WORK/quickstart"
mkdir "$QS"
cd "$QS"
HOME="$BLOCK_HOME" "$ROOT/test/docs/run-block.sh" quickstart
equal "gosftpd/config.toml" "$(owner_mode gosftpd/config.toml)" "0:65532 640"
equal "data" "$(owner_mode data | cut -d' ' -f1)" "65532:65532"
equal "state" "$(owner_mode state | cut -d' ' -f1)" "65532:65532"
wait_healthy gosftpd
equal "the container's image" "$(image_of gosftpd)" "$IMAGE_ID"
landlock gosftpd
equal "the stop timeout" "$(docker inspect -f '{{.Config.StopTimeout}}' gosftpd)" 40
fp=$(keyscan 2022 "$WORK/known_hosts")
log=$(logs gosftpd)
equal "the logged host key fingerprint" "$(grep -o 'SHA256:[A-Za-z0-9+/]*' <<<"$log" | head -n 1)" "$fp"
equal "host keys generated at the first start" "$(count '(generated' "$log")" 1
check "an sftp upload as alice" sftp_as alice 2022 "$WORK/known_hosts" "put $WORK/upload.bin upload.bin"
check "the upload is in ./data" sudo cmp -s "$WORK/upload.bin" data/upload.bin
equal "its owner" "$(owner_mode data/upload.bin | cut -d' ' -f1)" "65532:65532"

phase "a new container keeps the host key"
start=$SECONDS
docker stop gosftpd >/dev/null
equal "the exit status after docker stop" "$(docker inspect -f '{{.State.ExitCode}}' gosftpd)" 0
check "docker stop took $((SECONDS - start)) s, less than the stop timeout" test $((SECONDS - start)) -lt 40
docker rm gosftpd >/dev/null
# The block's docker run command, as the block runs it.
run_cmd=$("$ROOT/test/docs/run-block.sh" --print quickstart | awk '/^docker run -d / { on = 1 } on { print; if (!/\\$/) exit }')
[ -n "$run_cmd" ] || die "the quickstart block has no docker run -d command"
bash -euo pipefail -c "$run_cmd" >/dev/null
wait_healthy gosftpd
equal "the host key fingerprint" "$(keyscan 2022 "$WORK/known_hosts.2")" "$fp"
equal "host keys generated at the second start" "$(count '(generated' "$(logs gosftpd)")" 0
check "an sftp download as alice, with the first known_hosts" \
	sftp_as alice 2022 "$WORK/known_hosts" "get upload.bin $WORK/download.bin"
check "the download is the upload" cmp -s "$WORK/upload.bin" "$WORK/download.bin"

phase "a reload after sed -i in the mounted directory"
inode=$(stat -c %i gosftpd/config.toml)
sudo sed -i 's/^\[users\.alice\]$/[users.bob]/' gosftpd/config.toml
check "the configuration names bob instead of alice" sudo grep -qx '\[users\.bob\]' gosftpd/config.toml
check "sed -i replaced the file (inode $inode)" test "$(stat -c %i gosftpd/config.toml)" != "$inode"
equal "gosftpd/config.toml" "$(owner_mode gosftpd/config.toml)" "0:65532 640"
reloads=$(count 'configuration reloaded' "$(logs gosftpd)")
docker kill -s HUP gosftpd >/dev/null
for _ in $(seq 40); do
	[ "$(count 'configuration reloaded' "$(logs gosftpd)")" -gt "$reloads" ] && break
	sleep 0.25
done
check "the log says \"configuration reloaded\"" test "$(count 'configuration reloaded' "$(logs gosftpd)")" -gt "$reloads"
check "alice, removed, is refused" refused alice 2022 "$WORK/known_hosts"
check "bob, added, logs in" sftp_as bob 2022 "$WORK/known_hosts" ls
# The container keeps running: the compose block follows the Quickstart.

phase "the hint for a missing host directory, followed"
HINT="$WORK/hint"
mkdir "$HINT"
cd "$HINT"
status=0
docker run --rm -v ./gosftpd:/etc/gosftpd:ro "$REPO:v$V" >out 2>err.docker || status=$?
# Without the platform warning of a docker run under emulation.
grep -v "^WARNING: The requested image's platform" err.docker >err || true
equal "the exit status without a configuration" "$status" 2
equal "./gosftpd, which Docker created" "$(owner_mode gosftpd)" "0:0 755"
equal "the first line" "$(head -n 1 err)" \
	"Error: /etc/gosftpd is mounted but holds no config.toml; check the host path of -v (Docker creates a missing one as an empty directory owned by root)"
check "nothing on standard output" test ! -s out
mapfile -t cmds < <(sed -n 's/^  //p' err)
# The hint's text, which the shell must not expand here.
# shellcheck disable=SC2016
want=(
	'mkdir -p gosftpd && sudo chown "$(id -u):$(id -g)" gosftpd'
	"docker run --rm $HINT_REF config example > gosftpd/config.toml"
	'# replace the key placeholder in gosftpd/config.toml with your public key, then:'
	'sudo chown root:65532 gosftpd/config.toml && sudo chmod 0640 gosftpd/config.toml'
	'docker run ... -v ./gosftpd:/etc/gosftpd:ro ...'
)
if [ "${cmds[*]}" != "${want[*]}" ]; then
	cat err >&2
	die "the hint's commands differ from: $(printf '\n  %s' "${want[@]}")"
fi
pass "the hint's commands name $HINT_REF"
for cmd in "${cmds[@]}"; do
	case $cmd in
	'#'*)
		sed -i "s|<paste your public key[^>]*>|$(cat "$KEY.pub")|" gosftpd/config.toml
		;;
	'docker run ... '*' ...')
		cmd=${cmd#docker run ... }
		cmd="docker run -d --name gosftpd-ci-hint -p 2023:2022 ${cmd% ...} -v gosftpd-ci-data:/srv/sftp -v gosftpd-ci-state:/var/lib/gosftpd $HINT_REF"
		;&
	*)
		echo "+ $cmd"
		bash -euo pipefail -c "$cmd" >/dev/null
		;;
	esac
done
equal "gosftpd/config.toml" "$(owner_mode gosftpd/config.toml)" "0:65532 640"
wait_healthy gosftpd-ci-hint
equal "the container's image" "$(image_of gosftpd-ci-hint)" "$IMAGE_ID"
landlock gosftpd-ci-hint
# A new named volume takes the owner and mode of the image's directory.
for v in gosftpd-ci-data:750 gosftpd-ci-state:700; do
	equal "the volume ${v%:*}" "$(owner_mode "$(docker volume inspect -f '{{.Mountpoint}}' "${v%:*}")")" "65532:65532 ${v#*:}"
done
keyscan 2023 "$WORK/known_hosts.hint" >/dev/null
check "an sftp upload as alice" sftp_as alice 2023 "$WORK/known_hosts.hint" "put $WORK/upload.bin upload.bin"
docker rm -f gosftpd-ci-hint >/dev/null

phase "the compose block, while the Quickstart's container runs"
cd "$QS"
COMPOSE_DIR=$QS
equal "the Quickstart's container" "$(docker inspect -f '{{.State.Status}}' gosftpd)" running
digest=$(compose_files)
HOME="$BLOCK_HOME" "$ROOT/test/docs/run-block.sh" compose
check "the block removed the Quickstart's container" gone gosftpd
equal "the image of compose.yaml" "$(docker compose -f compose.yaml config --images)" "$REPO:v$V@sha256:$digest"
c=$(docker compose ps --format '{{.Name}}' gosftpd)
[ -n "$c" ] || die "docker compose started no container for the service gosftpd"
wait_healthy "$c"
equal "the container's image" "$(image_of "$c")" "$IMAGE_ID"
equal "read_only, cap_drop, security_opt, stop_grace_period, user" \
	"$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}} {{.HostConfig.SecurityOpt}} {{.Config.StopTimeout}} {{.Config.User}}' "$c")" \
	"true [ALL] [no-new-privileges:true] 40 65532:65532"
landlock "$c"
equal "the host key fingerprint, the Quickstart's" "$(keyscan 2022 "$WORK/known_hosts.compose")" "$fp"
equal "host keys generated" "$(count '(generated' "$(logs "$c")")" 0
check "an sftp download as bob of the Quickstart's upload, with the first known_hosts" \
	sftp_as bob 2022 "$WORK/known_hosts" "get upload.bin $WORK/download.compose.bin"
check "the download is the upload" cmp -s "$WORK/upload.bin" "$WORK/download.compose.bin"
check "an sftp upload as bob" sftp_as bob 2022 "$WORK/known_hosts" "put $WORK/upload.bin compose.bin"
check "the upload is in ./data" sudo cmp -s "$WORK/upload.bin" data/compose.bin
docker compose down --volumes >/dev/null 2>&1
COMPOSE_DIR=
CURRENT=

# The Quickstart's variants, each in a directory of its own, then the
# compose block with the setting install.md gives for the variant.
for v in volumes uid; do
	phase "the Quickstart's $v variant, then the compose block"
	dir="$WORK/quickstart-$v"
	mkdir "$dir"
	cd "$dir"
	block=$(variant "$v")
	printf '%s\n' "$block" | sed 's/^/    /'
	HOME="$BLOCK_HOME" bash -euo pipefail -c "$block" >/dev/null
	wait_healthy gosftpd
	equal "the container's image" "$(image_of gosftpd)" "$IMAGE_ID"
	landlock gosftpd
	kh="$WORK/known_hosts.$v"
	fp_v=$(keyscan 2022 "$kh")
	check "an sftp upload as alice" sftp_as alice 2022 "$kh" "put $WORK/upload.bin upload.bin"
	# What the compose section says to set first after the variant.
	case $v in
	volumes)
		settings=(DATA=gosftpd-data STATE=gosftpd-state)
		mp=$(docker volume inspect -f '{{.Mountpoint}}' gosftpd-data)
		check "the upload is in the volume gosftpd-data" sudo cmp -s "$WORK/upload.bin" "$mp/upload.bin"
		;;
	uid)
		settings=("RUN_AS=$(id -u):$(id -g)")
		equal "the upload's owner" "$(owner_mode data/upload.bin | cut -d' ' -f1)" "$(id -u):$(id -g)"
		;;
	esac
	text=$(tr -s ' \n' '  ' <"$ROOT/docs/install.md")
	# shellcheck disable=SC2016
	case $v in
	volumes) words='`DATA=gosftpd-data STATE=gosftpd-state`' ;;
	uid) words='`RUN_AS="$(id -u):$(id -g)"`' ;;
	esac
	grep -qF -- "$words" <<<"$text" || die "install.md's compose section no longer sets $words after the $v variant"
	COMPOSE_DIR=$dir
	compose_files >/dev/null
	env HOME="$BLOCK_HOME" "${settings[@]}" "$ROOT/test/docs/run-block.sh" compose
	check "the block removed the Quickstart's container" gone gosftpd
	c=$(docker compose ps --format '{{.Name}}' gosftpd)
	[ -n "$c" ] || die "docker compose started no container for the service gosftpd"
	wait_healthy "$c"
	equal "the container's image" "$(image_of "$c")" "$IMAGE_ID"
	landlock "$c"
	case $v in
	volumes)
		equal "the volumes of the service" \
			"$(docker inspect -f '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}} {{end}}{{end}}' "$c")" "gosftpd-data gosftpd-state "
		;;
	uid)
		equal "the user of the service" "$(docker inspect -f '{{.Config.User}}' "$c")" "$(id -u):$(id -g)"
		;;
	esac
	equal "the host key fingerprint, the Quickstart's" "$(keyscan 2022 "$kh.compose")" "$fp_v"
	equal "host keys generated" "$(count '(generated' "$(logs "$c")")" 0
	check "an sftp download of the Quickstart's upload" sftp_as alice 2022 "$kh" "get upload.bin $WORK/download.$v.bin"
	check "the download is the upload" cmp -s "$WORK/upload.bin" "$WORK/download.$v.bin"
	docker compose down --volumes >/dev/null 2>&1
	COMPOSE_DIR=
	CURRENT=
done
docker volume rm gosftpd-data gosftpd-state >/dev/null

phase "serve --ephemeral in a container"
# The JSON line names the container's port and 127.0.0.1, which hold on the
# host with the same port mapped there.
docker run -d --name gosftpd-ci-ephemeral -p 127.0.0.1:2022:2022 "$REPO:v$V" serve --ephemeral --listen 0.0.0.0:2022 >/dev/null
wait_healthy gosftpd-ci-ephemeral
equal "the container's image" "$(image_of gosftpd-ci-ephemeral)" "$IMAGE_ID"
landlock gosftpd-ci-ephemeral
line=$(docker logs gosftpd-ci-ephemeral 2>/dev/null)
equal "host, port and user" "$(jq -r '"\(.host) \(.port) \(.user)"' <<<"$line")" "127.0.0.1 2022 test"
jq -r .known_hosts <<<"$line" >"$WORK/known_hosts.ephemeral"
docker cp "gosftpd-ci-ephemeral:$(jq -r .private_key_path <<<"$line")" "$WORK/ephemeral_key"
KEY="$WORK/ephemeral_key" check "an sftp upload as test, with the key docker cp copied and the known_hosts line" \
	sftp_as test 2022 "$WORK/known_hosts.ephemeral" "put $WORK/upload.bin upload.bin"
docker stop gosftpd-ci-ephemeral >/dev/null
equal "the exit status after docker stop" "$(docker inspect -f '{{.State.ExitCode}}' gosftpd-ci-ephemeral)" 0
equal "the lines on standard output" "$(docker logs gosftpd-ci-ephemeral 2>/dev/null | wc -l)" 1
check "the key and the data are removed at the stop" grep -q 'msg="removed the client key' <<<"$(logs gosftpd-ci-ephemeral)"
docker rm gosftpd-ci-ephemeral >/dev/null
CURRENT=

phase "nothing was pulled"
for ref in "$REPO:v$V" "$HINT_REF"; do
	equal "$ref" "$(docker image inspect -f '{{.Id}}' "$ref")" "$IMAGE_ID"
done

if [ "$FAILED" != 0 ]; then
	echo "test/docker/run.sh: FAILED" >&2
fi
exit "$FAILED"
