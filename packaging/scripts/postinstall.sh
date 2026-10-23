#!/bin/sh
# gosftpd package: the deb postinst, the rpm %post and the Arch post_install
# and post_upgrade (pacman runs post_upgrade, not post_install, on an
# upgrade). It creates the user and the directories, gives the
# configuration to the group gosftpd and installs or removes the drop-in for
# systemd before 253 (ADR 0011, ADR 0012). It never enables, starts or
# restarts the service: the operator does, also after an upgrade. Each tool
# is used only where it exists, so that the script does not fail without
# systemd (containers, image builds).
set -e

if command -v systemd-sysusers >/dev/null 2>&1; then
	systemd-sysusers gosftpd.conf
fi
if command -v systemd-tmpfiles >/dev/null 2>&1; then
	systemd-tmpfiles --create gosftpd.conf
fi

# The package installs these as root:root (the group does not exist when
# it is unpacked). A group other than root is the administrator's choice
# and stays.
if getent group gosftpd >/dev/null 2>&1; then
	for f in /etc/gosftpd/config.toml /etc/gosftpd/users.d; do
		if [ -e "$f" ] && [ "$(stat -c %g "$f")" = 0 ]; then
			chgrp gosftpd "$f"
		fi
	done
fi

# The offline probe of docs/install.md: systemd that does not know
# Type=notify-reload gets the drop-in, any other loses it (also once
# systemd was upgraded). It needs no running systemd.
dropin=/etc/systemd/system/gosftpd.service.d/legacy-notify.conf
if command -v systemd-analyze >/dev/null 2>&1; then
	d=$(mktemp -d)
	printf '[Unit]\nDefaultDependencies=no\n[Service]\nType=notify-reload\nExecStart=/bin/true\n' >"$d/gosftpd-probe.service"
	if systemd-analyze verify --man=no "$d/gosftpd-probe.service" 2>&1 | grep -q 'Failed to parse service type'; then
		install -D -m 0644 /usr/share/gosftpd/legacy-notify.conf "$dropin"
	else
		rm -f "$dropin"
		rmdir /etc/systemd/system/gosftpd.service.d 2>/dev/null || true
	fi
	rm -r "$d"
fi

if [ -d /run/systemd/system ]; then
	systemctl daemon-reload || true
fi
