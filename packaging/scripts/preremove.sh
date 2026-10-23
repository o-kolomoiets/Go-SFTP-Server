#!/bin/sh
# gosftpd package: the deb prerm, the rpm %preun and the Arch pre_remove.
# It stops and disables the service when the package is removed, not when
# it is upgraded: deb passes "upgrade" then and rpm passes 1, and pacman runs
# pre_remove only for a removal (ADR 0012).
set -e

case "$1" in
upgrade | failed-upgrade | 1) exit 0 ;;
esac
if [ -d /run/systemd/system ]; then
	systemctl disable --now gosftpd.service >/dev/null 2>&1 || true
fi
