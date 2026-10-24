#!/usr/bin/env bash
# The deb, rpm or Arch package where systemd does not run, as in an image
# build or a chroot (ADR 0012): test/packages/container.sh runs it in a
# container of the test image whose PID 1 is not systemd. systemctl enable
# and disable work there on the links alone, so a removal must disable the
# service, as it does under systemd: the operator's enablement must not
# survive it, or a later install in that image, or on a host made from it,
# would start at boot without anyone enabling it. An upgrade keeps it.
# The removal also deletes the empty users.d, in every format (in run.sh it
# holds a file and stays).
#
# Usage: test/packages/offline.sh FORMAT DIR V
# FORMAT, DIR and V are test/packages/run.sh's; DIR needs only the package.
# It changes the system: it runs as root in a throwaway container, and
# refuses to run unless CI=true or GOSFTPD_PACKAGES_TEST=1.

# Functions called through check are not unreachable.
# shellcheck disable=SC2317,SC2329
set -euo pipefail

if [ $# -ne 3 ] || ! [[ $1 =~ ^(deb|rpm|archlinux)$ ]]; then
	echo "usage: test/packages/offline.sh deb|rpm|archlinux DIR V" >&2
	exit 2
fi
FORMAT=$1
DIR=$(cd "$2" && pwd)
V=$3
if [ "${CI:-}" != true ] && [ -z "${GOSFTPD_PACKAGES_TEST:-}" ]; then
	echo "test/packages/offline.sh installs and removes gosftpd; run it in a throwaway container with GOSFTPD_PACKAGES_TEST=1" >&2
	exit 2
fi
if [ "$(id -u)" != 0 ]; then
	echo "test/packages/offline.sh runs as root" >&2
	exit 2
fi
case $(uname -m) in
x86_64) ARCH=amd64 ;;
aarch64) ARCH=arm64 ;;
*) echo "test/packages/offline.sh: no package for $(uname -m)" >&2 && exit 2 ;;
esac
case $FORMAT in
deb) PKG="$DIR/gosftpd_${V}_linux_$ARCH.deb" ;;
rpm) PKG="$DIR/gosftpd_${V}_linux_$ARCH.rpm" ;;
archlinux) PKG="$DIR/gosftpd_${V}_linux_$ARCH.pkg.tar.zst" ;;
esac
WANTS=/etc/systemd/system/multi-user.target.wants/gosftpd.service
FAILED=0

fail() { echo "FAIL: $*" >&2; FAILED=1; }
pass() { echo "ok:   $*"; }
die() { fail "$*"; exit 1; }
phase() { printf '\n=== %s\n' "$*"; }
check() {
	local what=$1
	shift
	if "$@"; then pass "$what"; else fail "$what"; fi
}
equal() {
	if [ "$2" = "$3" ]; then pass "$1: $2"; else fail "$1: got \"$2\", want \"$3\""; fi
}
# absent PATH: nothing there, not even a symlink whose target is gone.
absent() { [ ! -e "$1" ] && [ ! -L "$1" ]; }
enabled() { systemctl is-enabled gosftpd.service 2>/dev/null || true; }

# As test/packages/run.sh installs, upgrades and removes.
pkg_install() {
	case $FORMAT in
	deb) apt-get install -y -q "$PKG" ;;
	rpm) dnf install -y -q --disablerepo='*' "$PKG" ;;
	archlinux) pacman -U --noconfirm "$PKG" ;;
	esac </dev/null
}
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

phase "the system"
# The case under test: preremove looks for /run/systemd/system.
[ ! -d /run/systemd/system ] || die "systemd runs here"
command -v systemctl >/dev/null || die "no systemctl here"
systemctl --version | sed -n 1p
echo "PID 1: $(cat /proc/1/comm)"
[ -f "$PKG" ] || die "no package $PKG"

phase "install and enable without systemd"
pkg_install || die "the package did not install"
systemctl enable gosftpd.service || die "systemctl enable gosftpd.service"
check "the service is enabled" test -L "$WANTS"
equal "is-enabled" "$(enabled)" enabled

phase "an upgrade keeps it enabled"
pkg_reinstall || die "the reinstall failed"
check "the service is still enabled" test -L "$WANTS"

phase "the removal disables it"
pkg_remove || die "the removal failed"
check "the removal disabled the service" absent "$WANTS"
check "the removal deleted the empty users.d" absent /etc/gosftpd/users.d
pkg_install || die "the package did not install again"
equal "is-enabled after a new install" "$(enabled)" disabled
pkg_remove || die "the second removal failed"

if [ "$FAILED" != 0 ]; then
	echo "test/packages/offline.sh: FAILED" >&2
fi
exit "$FAILED"
