#!/usr/bin/env bash
# Offline checks of the systemd unit, the sysusers and the tmpfiles file
# (ADR 0011), for the CI lint job: no running systemd is needed, nothing
# outside a temporary directory is changed. Usage: test/systemd/lint.sh
# (from anywhere). Needs systemd-analyze, systemd-sysusers,
# systemd-tmpfiles, and root or sudo (tmpfiles changes owners).
#
# The exposure score differs between systemd versions (the unit scores 1.2
# on 255, 1.4 on 252), so the CI job runs on a pinned ubuntu-24.04.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PKG="$ROOT/packaging"
WORK="$(mktemp -d)"
FAILED=0

as_root() { if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi; }
trap 'as_root rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $*" >&2; FAILED=1; }
pass() { echo "ok:   $*"; }

systemd-analyze --version | sed -n 1p

# --- exposure: at most 1.2 (--threshold is in tenths) -----------------------
if out=$(systemd-analyze security --offline=true --threshold=12 "$PKG/systemd/gosftpd.service" 2>&1); then
	pass "systemd-analyze security: $(grep -o 'exposure level for.*' <<<"$out")"
else
	fail "systemd-analyze security: exposure above 1.2"; echo "$out" >&2
fi

# --- verify: against a root that holds only systemd's targets and slices, the
# unit and the binary, so that units of the host cannot add messages. verify
# exits 0 on unknown keys, types, system calls and groups, so any output
# fails. ------------------------------------------------------------------------
R="$WORK/verify"
mkdir -p "$R/usr/lib/systemd/system" "$R/usr/bin" "$R/etc/systemd/system/gosftpd.service.d"
cp /usr/lib/systemd/system/*.target /usr/lib/systemd/system/*.slice "$R/usr/lib/systemd/system/"
cp "$PKG/systemd/gosftpd.service" "$R/usr/lib/systemd/system/"
ln -s usr/bin "$R/bin"
# verify checks that ExecStart= and ExecReload= (legacy-notify.conf) name
# executable files; it does not run them.
for f in gosftpd kill; do
	printf '#!/bin/sh\n' >"$R/usr/bin/$f"
	chmod 0755 "$R/usr/bin/$f"
done
verify() { # verify WHAT: systemd-analyze verify must print nothing
	local out
	if out=$(systemd-analyze verify --man=no --root="$R" gosftpd.service 2>&1) && [ -z "$out" ]; then
		pass "systemd-analyze verify: $1"
	else
		fail "systemd-analyze verify: $1"; echo "$out" >&2
	fi
}
verify "the unit"
cp "$PKG/systemd/legacy-notify.conf" "$R/etc/systemd/system/gosftpd.service.d/"
verify "the unit with legacy-notify.conf"
# The check itself: a misspelled key must be reported.
printf '[Service]\nTimeoutStopSecs=45\n' >"$R/etc/systemd/system/gosftpd.service.d/typo.conf"
if [ -n "$(systemd-analyze verify --man=no --root="$R" gosftpd.service 2>&1)" ]; then
	pass "systemd-analyze verify reports a misspelled key"
else
	fail "systemd-analyze verify is silent about a misspelled key: the check above proves nothing"
fi

# --- sysusers and tmpfiles: absolute paths (a relative one is looked up in
# the sysusers.d and tmpfiles.d directories), into an empty root -------------
U="$WORK/install"
mkdir -p "$U"
as_root systemd-sysusers --root="$U" "$PKG/gosftpd.sysusers"
line=$(grep '^gosftpd:' "$U/etc/passwd" || true)
IFS=: read -r _ _ uid gid gecos home shell <<<"$line"
if [ "$gecos" = "gosftpd SFTP server" ] && [ "$home" = / ] && [ "${shell##*/}" = nologin ] && [ "$uid" -lt 1000 ]; then
	pass "systemd-sysusers: $line"
else
	fail "systemd-sysusers: $line (want a system user with the home / and no login shell)"
fi
# An existing root-owned /srv/sftp is taken over, as on a host where it
# existed before.
mkdir -p "$U/srv/sftp"
as_root systemd-tmpfiles --create --root="$U" "$PKG/gosftpd.tmpfiles"
for d in /srv/sftp /var/log/gosftpd; do
	got=$(stat -c '%u:%g %a' "$U$d" 2>/dev/null || echo missing)
	if [ "$got" = "$uid:$gid 750" ]; then
		pass "systemd-tmpfiles: $d $got"
	else
		fail "systemd-tmpfiles: $d is $got, want $uid:$gid 750"
	fi
done

exit $FAILED
