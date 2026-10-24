#!/usr/bin/env bash
# Runs test/packages/run.sh in a container with systemd as PID 1, then
# test/packages/offline.sh in one of the same image without it (an image
# build), as the CI job "packages" does for Debian 12 and 13, EL9 and Arch
# (ADR 0012). The image is built from test/packages/NAME.Dockerfile; the
# checkout and DIR are mounted read-only; the containers are removed at the
# end.
#
# Usage: test/packages/container.sh NAME FORMAT DIR V
# FORMAT, DIR and V are run.sh's. EXPECT_LEGACY_DROPIN, NEEDRESTART and
# REQUIRE_LANDLOCK are passed on to it. IMAGE names an image to use instead
# of building one, CONTAINER the container (default:
# gosftpd-packages-NAME; the second one gets "-offline" appended). Needs
# Docker and the right to run a privileged container.
set -euo pipefail

if [ $# -ne 4 ] || ! [[ $1 =~ ^[a-z0-9][a-z0-9.-]*$ ]]; then
	echo "usage: test/packages/container.sh NAME FORMAT DIR V" >&2
	exit 2
fi
NAME=$1 FORMAT=$2 V=$4
DIR=$(cd "$3" && pwd)
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CONTAINER=${CONTAINER:-gosftpd-packages-$NAME}
if [ -z "${IMAGE:-}" ]; then
	IMAGE=gosftpd-packages-$NAME
	docker build --quiet --tag "$IMAGE" --file "$ROOT/test/packages/$NAME.Dockerfile" "$ROOT/test/packages" >/dev/null
fi

# systemd needs a writable cgroup2 hierarchy: the host's, or on a host with
# the hybrid layout of cgroup v1 its unified part (systemd 258 and later no
# longer start on v1).
if [ "$(stat -fc %T /sys/fs/cgroup)" = cgroup2fs ]; then
	cgroup=/sys/fs/cgroup
elif [ "$(stat -fc %T /sys/fs/cgroup/unified 2>/dev/null)" = cgroup2fs ]; then
	cgroup=/sys/fs/cgroup/unified
else
	echo "test/packages/container.sh: no cgroup2 file system on this host" >&2
	exit 1
fi

for c in "$CONTAINER" "$CONTAINER-offline"; do
	docker container inspect "$c" >/dev/null 2>&1 && {
		echo "test/packages/container.sh: a container $c exists; remove it first" >&2
		exit 1
	}
done
trap 'docker rm -f -v "$CONTAINER" "$CONTAINER-offline" >/dev/null 2>&1 || true' EXIT
docker run -d --name "$CONTAINER" --privileged --cgroupns=host \
	-v "$cgroup:/sys/fs/cgroup:rw" --tmpfs /run --tmpfs /run/lock \
	-v "$ROOT:/src:ro" -v "$DIR:/packages:ro" "$IMAGE" >/dev/null

# The boot is over once systemd reports running or degraded (a unit that
# needs hardware may fail in a container).
state=
for _ in $(seq 120); do
	state=$(docker exec "$CONTAINER" systemctl is-system-running 2>/dev/null || true)
	case $state in running | degraded) break ;; esac
	sleep 1
done
echo "$NAME ($IMAGE): systemd is $state"
case $state in
running) ;;
degraded) docker exec "$CONTAINER" systemctl --failed --no-pager || true ;;
*)
	docker logs "$CONTAINER" 2>&1 | tail -n 50 >&2
	echo "test/packages/container.sh: systemd did not finish booting in $NAME" >&2
	exit 1
	;;
esac

status=0
docker exec -e GOSFTPD_PACKAGES_TEST=1 -e EXPECT_LEGACY_DROPIN -e NEEDRESTART -e REQUIRE_LANDLOCK \
	"$CONTAINER" /src/test/packages/run.sh "$FORMAT" /packages "$V" || status=$?

# The same image, its command replaced: PID 1 is not systemd.
printf '\n%s (%s): without systemd\n' "$NAME" "$IMAGE"
docker run --rm --name "$CONTAINER-offline" -e GOSFTPD_PACKAGES_TEST=1 \
	-v "$ROOT:/src:ro" -v "$DIR:/packages:ro" "$IMAGE" \
	/src/test/packages/offline.sh "$FORMAT" /packages "$V" || status=$?
exit "$status"
