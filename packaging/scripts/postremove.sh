#!/bin/sh
# gosftpd package: the deb postrm, the rpm %postun and the Arch post_remove.
# It deletes the drop-in that postinstall manages once the unit is gone,
# that is on a removal. It tests the unit file, not "$1": on an upgrade rpm
# runs the old package's %postun after the new one's %post, which may just
# have installed the drop-in, and pacman passes post_remove the old version
# (ADR 0012).
set -e

if [ ! -e /usr/lib/systemd/system/gosftpd.service ]; then
	rm -f /etc/systemd/system/gosftpd.service.d/legacy-notify.conf
	rmdir /etc/systemd/system/gosftpd.service.d 2>/dev/null || true
fi
if [ -d /run/systemd/system ]; then
	systemctl daemon-reload || true
fi
