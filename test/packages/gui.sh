#!/usr/bin/env bash
# A package of gosftpd-gui on a fresh system of its kind, as the CI job
# "gui-packages" runs it (ADR 0013): in the debian-12, debian-13, el9 (with
# EPEL) and arch containers of test/packages, in Fedora's, and on the
# ubuntu-24.04 runner itself.
# - The install, with the system's package manager: its dependencies are
#   the system's Qt 6.
# - gosftpd-gui --version, and the gosftpd it carries at its path (never
#   one found in PATH): its version, the same.
# - No library missing for either binary; Qt's X11 platform plugin
#   present, without which the GUI does not start.
# - The desktop entry, the icon and the notices of ADR 0013's "LGPLv3".
# - The removal: nothing of the package left.
#
# Usage: test/packages/gui.sh FORMAT FILE VERSION
# FORMAT is deb, rpm or archlinux. It changes the system: it refuses to run
# unless CI=true or GOSFTPD_PACKAGES_TEST=1.
set -euo pipefail

if [ $# -ne 3 ] || ! [[ $1 =~ ^(deb|rpm|archlinux)$ ]]; then
	echo "usage: test/packages/gui.sh deb|rpm|archlinux FILE VERSION" >&2
	exit 2
fi
format=$1 file=$(realpath "$2") version=$3
if [ "${CI:-}" != true ] && [ -z "${GOSFTPD_PACKAGES_TEST:-}" ]; then
	echo "test/packages/gui.sh installs and removes gosftpd-gui; run it on a throwaway machine with GOSFTPD_PACKAGES_TEST=1" >&2
	exit 2
fi

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

echo "== install $(basename "$file")"
case $format in
deb)
	apt-get -qq update
	DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends "$file" >/dev/null
	gosftpd=/usr/libexec/gosftpd-gui/gosftpd
	;;
rpm)
	dnf -q -y install "$file" >/dev/null
	gosftpd=/usr/libexec/gosftpd-gui/gosftpd
	;;
archlinux)
	# A full upgrade first: Arch supports no partial upgrade, and the
	# image's libraries may be older than the ones Qt 6 is built against.
	pacman -Sy --noconfirm --needed -q archlinux-keyring >/dev/null
	pacman -Su --noconfirm -q >/dev/null
	pacman -U --noconfirm -q "$file" >/dev/null
	gosftpd=/usr/lib/gosftpd-gui/gosftpd
	;;
esac

echo "== the binaries"
got=$(gosftpd-gui --version)
[ "$got" = "gosftpd-gui $version" ] || fail "gosftpd-gui --version: $got, want gosftpd-gui $version"
[ "$(stat -c %a "$gosftpd")" = 755 ] || fail "$gosftpd: mode $(stat -c %a "$gosftpd")"
got=$("$gosftpd" version)
case $got in "gosftpd $version"*) ;; *) fail "$gosftpd version: $got, want gosftpd $version" ;; esac
for b in /usr/bin/gosftpd-gui "$gosftpd"; do
	if ldd "$b" 2>&1 | grep -q 'not found'; then
		ldd "$b" >&2
		fail "$b: a library is missing"
	fi
done
plugin=$(find /usr/lib* -path '*qt6/plugins/platforms/libqxcb.so' -print -quit 2>/dev/null)
[ -n "$plugin" ] || fail "Qt's X11 platform plugin (libqxcb.so) is not installed: the GUI would not start"
echo "Qt's X11 platform plugin: $plugin"

echo "== the files"
desktop=/usr/share/applications/gosftpd-gui.desktop
grep -qx 'Exec=gosftpd-gui' "$desktop" || fail "$desktop: no Exec=gosftpd-gui"
grep -qx 'Icon=gosftpd-gui' "$desktop" || fail "$desktop: no Icon=gosftpd-gui"
[ -f /usr/share/icons/hicolor/scalable/apps/gosftpd-gui.svg ] || fail "no icon"
for f in NOTICE LGPL-3.0 GPL-3.0 LICENSE THIRD_PARTY_LICENSES THIRD_PARTY_LICENSES.gosftpd; do
	[ -s "/usr/share/doc/gosftpd-gui/$f" ] || fail "/usr/share/doc/gosftpd-gui/$f is missing or empty"
done
grep -q 'github.com/mappu/miqt' /usr/share/doc/gosftpd-gui/THIRD_PARTY_LICENSES || fail "THIRD_PARTY_LICENSES does not name miqt"
if [ "$format" = deb ]; then
	cmp -s /usr/share/doc/gosftpd-gui/copyright /usr/share/doc/gosftpd-gui/NOTICE || fail "the deb's copyright file is not the NOTICE"
fi

echo "== remove"
case $format in
deb) DEBIAN_FRONTEND=noninteractive apt-get -qq purge -y gosftpd-gui >/dev/null ;;
rpm) dnf -q -y remove gosftpd-gui >/dev/null ;;
archlinux) pacman -R --noconfirm -q gosftpd-gui >/dev/null ;;
esac
for p in /usr/bin/gosftpd-gui "$gosftpd" "$(dirname "$gosftpd")" "$desktop" /usr/share/doc/gosftpd-gui; do
	[ ! -e "$p" ] || fail "$p is left after the removal"
done
echo "ok: $(basename "$file")"
