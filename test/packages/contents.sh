#!/usr/bin/env bash
# The deb, rpm and Arch packages that GoReleaser built into DIST, for the
# CI job goreleaser-check (ADR 0012). For linux amd64 and arm64, each
# package
# - holds exactly the expected files, owned by root, with their modes and
#   the commit time, and owns its directories (rpm owns only those listed);
# - marks the configuration: config.toml, and in the deb the needrestart
#   file, as conffiles, %config(noreplace) or Arch backup entries;
# - carries packaging/scripts/*.sh as its scripts, and Arch post_upgrade too;
# - names the maintainer without an email address, the deb Depends: procps,
#   rpm the build host gosftpd, and the version with its pre-release.
#
# Usage: test/packages/contents.sh DIST
# DIST is GoReleaser's dist/ of this checkout's HEAD; out/man holds the man
# pages it packaged. Needs dpkg-deb, rpm, GNU tar with zstd, jq and git.
set -euo pipefail

if [ $# -ne 1 ]; then
	echo "usage: test/packages/contents.sh DIST" >&2
	exit 2
fi
DIST=$1
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
V=$(jq -r .version "$DIST/metadata.json")
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
FAILED=0

fail() { echo "FAIL: $*" >&2; FAILED=1; }
pass() { echo "ok:   $*"; }
equal() {
	if [ "$2" = "$3" ]; then pass "$1: $2"; else fail "$1: got \"$2\", want \"$3\""; fi
}
# same WHAT GOT_FILE WANT_FILE: the files are equal, or the diff fails.
same() {
	if diff -u "$3" "$2" >"$WORK/diff"; then
		pass "$1"
	else
		fail "$1 (+ is in the package):"
		cat "$WORK/diff" >&2
	fi
}

# The commit time, as each format lists it.
epoch=$(git -C "$ROOT" log -1 --format=%ct)
mtime=$(TZ=UTC date -d "@$epoch" '+%F %T')
# The version: X.Y.Z, then the pre-release, if any, after the first "-".
base=${V%%-*}
pre=
if [ "$base" != "$V" ]; then pre=${V#*-}; fi

# The entries every package has, as "mode path", directories with a
# trailing slash; each format adds its own below.
{
	echo "-rwxr-xr-x /usr/bin/gosftpd"
	echo "drwxr-xr-x /etc/gosftpd/"
	echo "-rw-r----- /etc/gosftpd/config.toml"
	echo "drwxr-x--- /etc/gosftpd/users.d/"
	echo "-rw-r--r-- /usr/lib/systemd/system/gosftpd.service"
	echo "-rw-r--r-- /usr/lib/sysusers.d/gosftpd.conf"
	echo "-rw-r--r-- /usr/lib/tmpfiles.d/gosftpd.conf"
	echo "drwxr-xr-x /usr/share/gosftpd/"
	echo "-rw-r--r-- /usr/share/gosftpd/legacy-notify.conf"
	echo "drwxr-xr-x /usr/share/doc/gosftpd/"
	echo "-rw-r--r-- /usr/share/doc/gosftpd/LICENSE"
	echo "-rw-r--r-- /usr/share/doc/gosftpd/THIRD_PARTY_LICENSES"
	echo "-rw-r--r-- /usr/share/doc/gosftpd/config.example.toml"
	echo "-rw-r--r-- /usr/share/bash-completion/completions/gosftpd"
	echo "-rw-r--r-- /usr/share/fish/vendor_completions.d/gosftpd.fish"
	(cd "$ROOT/out/man" && for f in *.1.gz; do echo "-rw-r--r-- /usr/share/man/man1/$f"; done)
} >"$WORK/common"
grep -q ' /usr/share/man/man1/gosftpd\.1\.gz$' "$WORK/common" || fail "out/man has no gosftpd.1.gz"

# want FORMAT: the expected entries of the format's package, sorted.
want() {
	cat "$WORK/common"
	case $1 in
	deb)
		echo "-rw-r--r-- /etc/needrestart/conf.d/gosftpd.conf"
		echo "-rw-r--r-- /usr/share/zsh/vendor-completions/_gosftpd"
		;;
	*) echo "-rw-r--r-- /usr/share/zsh/site-functions/_gosftpd" ;;
	esac
}

# entries LIST: of a "mode owner date time path" listing on standard input,
# "mode path" of each entry but the parent directories that deb and Arch
# add; fails for an owner other than root or a time other than the commit's.
entries() {
	awk -v mtime="$mtime" -v list="$1" '
		$2 != "0/0" && $2 != "root/root" && $2 != "root:root" { print list ": owner " $2 ": " $NF > "/dev/stderr"; bad = 1 }
		$3 " " $4 != mtime { print list ": time " $3 " " $4 ": " $NF > "/dev/stderr"; bad = 1 }
		{ print $1, $NF }
		END { exit bad }
	' | grep -Ev ' /(etc|etc/needrestart|etc/needrestart/conf\.d|usr|usr/bin|usr/lib|usr/lib/systemd|usr/lib/systemd/system|usr/lib/sysusers\.d|usr/lib/tmpfiles\.d|usr/share|usr/share/bash-completion|usr/share/bash-completion/completions|usr/share/doc|usr/share/fish|usr/share/fish/vendor_completions\.d|usr/share/man|usr/share/man/man1|usr/share/zsh|usr/share/zsh/vendor-completions|usr/share/zsh/site-functions)/$' |
		LC_ALL=C sort
}

for arch in amd64 arm64; do
	case $arch in amd64) rpmarch=x86_64 pacarch=x86_64 ;; arm64) rpmarch=aarch64 pacarch=aarch64 ;; esac
	deb="$DIST/gosftpd_${V}_linux_$arch.deb"
	rpm="$DIST/gosftpd_${V}_linux_$arch.rpm"
	pac="$DIST/gosftpd_${V}_linux_$arch.pkg.tar.zst"
	for f in "$deb" "$rpm" "$pac"; do
		[ -f "$f" ] || fail "$f is missing"
	done

	echo "--- ${deb##*/}"
	if [ -f "$deb" ]; then
		equal "Version" "$(dpkg-deb -f "$deb" Version)" "$base${pre:+~$pre}"
		equal "Architecture" "$(dpkg-deb -f "$deb" Architecture)" "$arch"
		equal "Maintainer" "$(dpkg-deb -f "$deb" Maintainer)" "gosftpd maintainers"
		equal "Depends" "$(dpkg-deb -f "$deb" Depends)" procps
		want deb | LC_ALL=C sort >"$WORK/want"
		# "drwxr-xr-x root/root 0 2026-10-23 20:45 ./etc/" to "MODE root/root DATE TIME /etc/"
		TZ=UTC dpkg-deb --fsys-tarfile "$deb" | TZ=UTC tar --full-time -tvf - |
			awk '{ sub(/^\./, "", $6); print $1, $2, $4, $5, $6 }' | entries deb >"$WORK/got" || FAILED=1
		same "the files of the deb" "$WORK/got" "$WORK/want"
		dpkg-deb --ctrl-tarfile "$deb" >"$WORK/control.tar"
		equal "control files" "$(tar -tf "$WORK/control.tar" | LC_ALL=C sort | paste -sd ' ')" \
			"./conffiles ./control ./md5sums ./postinst ./postrm ./prerm"
		printf '%s\n' /etc/gosftpd/config.toml /etc/needrestart/conf.d/gosftpd.conf >"$WORK/want"
		tar -xOf "$WORK/control.tar" ./conffiles | LC_ALL=C sort >"$WORK/got"
		same "conffiles" "$WORK/got" "$WORK/want"
		for s in postinst:postinstall prerm:preremove postrm:postremove; do
			tar -xOf "$WORK/control.tar" "./${s%:*}" >"$WORK/got"
			same "${s%:*} is packaging/scripts/${s#*:}.sh" "$WORK/got" "$ROOT/packaging/scripts/${s#*:}.sh"
		done
	fi

	echo "--- ${rpm##*/}"
	if [ -f "$rpm" ]; then
		equal "version, release, arch" "$(rpm -qp --qf '%{VERSION} %{RELEASE} %{ARCH}' "$rpm")" \
			"$base${pre:+~${pre//-/_}} 1 $rpmarch"
		equal "Packager, Vendor, Buildhost" "$(rpm -qp --qf '%{PACKAGER}|%{VENDOR}|%{BUILDHOST}' "$rpm")" \
			"gosftpd maintainers|gosftpd|gosftpd"
		equal "Requires" "$(rpm -qpR "$rpm" | grep -v '^rpmlib(' | paste -sd ' ')" ""
		want rpm | LC_ALL=C sort >"$WORK/want"
		rpm -qp --qf '[%{FILEMODES:perms} %{FILEUSERNAME}:%{FILEGROUPNAME} %{FILEMTIMES} %{FILENAMES}\n]' "$rpm" |
			while read -r mode owner t path; do
				if [ "${mode:0:1}" = d ]; then path=$path/; fi
				echo "$mode $owner $(TZ=UTC date -d "@$t" '+%F %T') $path"
			done | entries rpm >"$WORK/got" || FAILED=1
		same "the files of the rpm" "$WORK/got" "$WORK/want"
		equal "config files" "$(rpm -qp --qf '[%{FILEFLAGS:fflags}|%{FILENAMES}\n]' "$rpm" | awk -F '|' '$1 ~ /c/ { print $1, $2 }' | paste -sd ' ')" \
			"cn /etc/gosftpd/config.toml"
		for s in POSTIN:postinstall PREUN:preremove POSTUN:postremove; do
			rpm -qp --qf "%{${s%:*}}" "$rpm" >"$WORK/got"
			same "%{${s%:*}} is packaging/scripts/${s#*:}.sh" "$WORK/got" "$ROOT/packaging/scripts/${s#*:}.sh"
		done
		equal "scriptlet interpreters" "$(rpm -qp --qf '%{PREINPROG} %{POSTINPROG} %{PREUNPROG} %{POSTUNPROG}' "$rpm")" \
			"(none) /bin/sh /bin/sh /bin/sh"
	fi

	echo "--- ${pac##*/}"
	if [ -f "$pac" ]; then
		tar --zstd -xOf "$pac" .PKGINFO >"$WORK/pkginfo"
		equal "pkgver, arch" "$(awk -F ' = ' '$1 == "pkgver" || $1 == "arch" { print $2 }' "$WORK/pkginfo" | paste -sd ' ')" \
			"$pacarch 0:$base${pre//-/_}-1"
		equal "packager" "$(awk -F ' = ' '$1 == "packager" { print $2 }' "$WORK/pkginfo")" "gosftpd maintainers"
		equal "backup" "$(awk -F ' = ' '$1 == "backup" { print $2 }' "$WORK/pkginfo" | paste -sd ' ')" etc/gosftpd/config.toml
		equal "depend" "$(awk -F ' = ' '$1 == "depend" { print $2 }' "$WORK/pkginfo" | paste -sd ' ')" ""
		want archlinux | LC_ALL=C sort >"$WORK/want"
		TZ=UTC tar --zstd --numeric-owner --full-time -tvf "$pac" |
			awk '$6 !~ /^\./ { print $1, $2, $4, $5, "/" $6 }' | entries archlinux >"$WORK/got" || FAILED=1
		same "the files of the Arch package" "$WORK/got" "$WORK/want"
		tar --zstd -xOf "$pac" .INSTALL >"$WORK/install"
		equal ".INSTALL functions" "$(sed -n 's/^function \([a-z_]*\)() {$/\1/p' "$WORK/install" | LC_ALL=C sort | paste -sd ' ')" \
			"post_install post_remove post_upgrade pre_remove"
		# nfpm puts each script, and a blank line, into a function.
		for s in post_install:postinstall post_upgrade:postinstall pre_remove:preremove post_remove:postremove; do
			awk -v f="function ${s%:*}() {" '$0 == f { on = 1; next } on && $0 == "}" { exit } on' "$WORK/install" |
				sed '$ { /^$/d; }' >"$WORK/got"
			same "${s%:*} is packaging/scripts/${s#*:}.sh" "$WORK/got" "$ROOT/packaging/scripts/${s#*:}.sh"
		done
	fi
done

if [ "$FAILED" != 0 ]; then
	echo "test/packages/contents.sh: FAILED" >&2
fi
exit "$FAILED"
