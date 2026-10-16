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
# verify checks that ExecStart= and the like name executable files; it does
# not run them.
stub() { # stub ROOT PATH: an executable file
	mkdir -p "$(dirname "$1$2")"
	printf '#!/bin/sh\n' >"$1$2"
	chmod 0755 "$1$2"
}
verify_root() { # verify_root DIR: a root with the shipped unit
	mkdir -p "$1/usr/lib/systemd/system" "$1/usr/bin" "$1/etc/systemd/system/gosftpd.service.d"
	cp /usr/lib/systemd/system/*.target /usr/lib/systemd/system/*.slice "$1/usr/lib/systemd/system/"
	cp "$PKG/systemd/gosftpd.service" "$1/usr/lib/systemd/system/"
	ln -s usr/bin "$1/bin"
	stub "$1" /usr/bin/gosftpd
	stub "$1" /usr/bin/kill # ExecReload= of legacy-notify.conf
}
R="$WORK/verify"
verify_root "$R"
verify() { # verify WHAT ROOT [UNIT...]: systemd-analyze verify must print nothing
	local what=$1 root=$2 out
	shift 2
	if out=$(systemd-analyze verify --man=no --root="$root" gosftpd.service "$@" 2>&1) && [ -z "$out" ]; then
		pass "systemd-analyze verify: $what"
	else
		fail "systemd-analyze verify: $what"; echo "$out" >&2
	fi
}
verify "the unit" "$R"
cp "$PKG/systemd/legacy-notify.conf" "$R/etc/systemd/system/gosftpd.service.d/"
verify "the unit with legacy-notify.conf" "$R"
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
# Owned by root, as a real root is: systemd-tmpfiles refuses a path that
# goes from a directory of another user to one of root's ("unsafe path
# transition"), and on a CI runner mktemp gives the runner's own.
as_root mkdir -m 0755 "$U"
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
as_root mkdir -p "$U/srv/sftp"
as_root systemd-tmpfiles --create --root="$U" "$PKG/gosftpd.tmpfiles"
for d in /srv/sftp /var/log/gosftpd; do
	got=$(stat -c '%u:%g %a' "$U$d" 2>/dev/null || echo missing)
	if [ "$got" = "$uid:$gid 750" ]; then
		pass "systemd-tmpfiles: $d $got"
	else
		fail "systemd-tmpfiles: $d is $got, want $uid:$gid 750"
	fi
done

# --- the units, drop-ins and tmpfiles files that the documentation shows: a
# code block whose first line is "# /etc/systemd/system/NAME" or
# "# /etc/tmpfiles.d/NAME" is that file. The units are verified together
# with the shipped one; the tmpfiles files are applied to the root above,
# which has the user gosftpd. -----------------------------------------------
DR="$WORK/docs"
verify_root "$DR"
while IFS=$'\t' read -r path line; do
	mkdir -p "$DR$(dirname "$path")"
	printf '%s\n' "$line" >>"$DR$path"
done < <(awk '/^```/ { inside = !inside; path = ""; first = inside; next }
	first { first = 0; if ($0 ~ /^# \/etc\/(systemd\/system|tmpfiles\.d)\/[^ ]+$/) path = substr($0, 3) }
	path != "" { print path "\t" $0 }' "$ROOT"/docs/*.md "$ROOT"/docs/recipes/*.md)
units=()
for f in "$DR"/etc/systemd/system/*.service "$DR"/etc/systemd/system/*.timer; do
	[ -e "$f" ] || continue
	units+=("${f##*/}")
	for p in $(sed -n 's/^Exec[A-Za-z]*=[-@:+!]*\(\/[^ ]*\).*/\1/p' "$f"); do
		[ -e "$DR$p" ] || stub "$DR" "$p"
	done
done
if [ ${#units[@]} = 0 ]; then
	fail "no unit file in the documentation: the extraction above is broken"
fi
verify "the units and drop-ins of the documentation: $(cd "$DR/etc/systemd/system" && find . -type f | sort | sed 's|^\./||' | paste -sd ' ')" "$DR" "${units[@]}"
# The mounts' directories belong to gosftpd, as gosftpd creates them:
# tmpfiles refuses the path from a directory of gosftpd's to one of root's.
as_root install -d -m 0750 -o "$uid" -g "$gid" "$U/srv/sftp/inbox" "$U/srv/sftp/home"
tmpfiles() { # tmpfiles WHAT FILE: --create and --clean must print nothing
	local out
	if out=$(as_root systemd-tmpfiles --create --clean --root="$U" "$2" 2>&1) && [ -z "$out" ]; then
		pass "systemd-tmpfiles: $1"
	else
		fail "systemd-tmpfiles: $1"; echo "$out" >&2
	fi
}
for f in "$DR"/etc/tmpfiles.d/*.conf; do
	[ -e "$f" ] || { fail "no tmpfiles file in the documentation: the extraction above is broken"; continue; }
	tmpfiles "${f#"$DR"} of the documentation" "$f"
done
# The check itself: an invalid age must be reported.
printf 'e /srv/sftp/inbox - - - c:30x\n' >"$WORK/typo.tmpfiles"
if [ -n "$(as_root systemd-tmpfiles --clean --root="$U" "$WORK/typo.tmpfiles" 2>&1)" ]; then
	pass "systemd-tmpfiles reports an invalid age"
else
	fail "systemd-tmpfiles is silent about an invalid age: the check above proves nothing"
fi

exit $FAILED
