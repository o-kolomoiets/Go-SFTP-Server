#!/usr/bin/env bash
# The release job's checks of the GUI's Linux packages (ADR 0013,
# "Packaging and signing"). Code that runs in the gui-linux job controls
# what it uploads; only these checks stand between that and the signed
# checksums.txt.
#
# release-gui.sh check DOWNLOADED OUT TAG
#   DOWNLOADED, where the release job downloaded the gui-linux artifact,
#   must hold exactly the four packages of TAG that make gui-packages
#   builds and the SBOM of each (NAME.sbom.json), as regular files and
#   nothing else. They are copied into OUT, a new directory, for
#   GoReleaser's extra_files (GUI_DIR).
# release-gui.sh gosftpd DIR GOSFTPD
#   The gosftpd in each package in DIR, as the package installs it, must be
#   GOSFTPD (dist's Linux amd64 binary) byte for byte. A loose copy in the
#   artifact would prove nothing about the packaged one.
# release-gui.sh checksums DIR CHECKSUMS
#   CHECKSUMS (dist/checksums.txt, which cosign signs and the attestation
#   covers) must list every file in DIR with its SHA-256: GoReleaser passes
#   over an extra_files glob that matches nothing.
set -euo pipefail

me=${0##*/}
usage() {
	echo "usage: $me check DOWNLOADED OUT TAG | gosftpd DIR GOSFTPD | checksums DIR CHECKSUMS" >&2
	exit 2
}

# names TAG: the file names of TAG's packages and SBOMs, one per line, as
# nfpm writes the version into each format: a pre-release after "~" in deb
# and rpm (with "_" for "-" in rpm), and right after the version in Arch.
names() {
	local tag=$1 fedora version base pre
	if ! [[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
		echo "$me: $tag is not a version tag" >&2
		exit 1
	fi
	fedora=$(sed -n 's/^FEDORA_RELEASE=\([0-9][0-9]*\).*/\1/p' "$(dirname "$0")/../../packaging/gui/build.sh")
	if [ -z "$fedora" ]; then
		echo "$me: packaging/gui/build.sh names no FEDORA_RELEASE" >&2
		exit 1
	fi
	version=${tag#v}
	base=${version%%-*}
	pre=${version#"$base"}
	pre=${pre#-}
	local deb=$base rpm=$base arch=$base
	if [ -n "$pre" ]; then
		deb=$base~$pre rpm=$base~${pre//-/_} arch=$base${pre//-/_}
	fi
	local p
	for p in "gosftpd-gui_${deb}-1_amd64.deb" "gosftpd-gui-${rpm}-1.fc${fedora}.x86_64.rpm" \
		"gosftpd-gui-${rpm}-1.el9.x86_64.rpm" "gosftpd-gui-${arch}-1-x86_64.pkg.tar.zst"; do
		printf '%s\n%s\n' "$p" "$p.sbom.json"
	done
}

check() {
	local downloaded=$1 out=$2 tag=$3 status=0 name
	if ! [ -d "$downloaded" ] || [ -L "$downloaded" ]; then
		echo "$me: $downloaded is not a directory" >&2
		exit 1
	fi
	if [ -e "$out" ] || [ -L "$out" ]; then
		echo "$me: $out exists: the files go into a new directory" >&2
		exit 1
	fi
	local list
	list=$(names "$tag")
	local -A want=()
	while IFS= read -r name; do
		want[$name]=1
	done <<<"$list"
	while IFS= read -r -d '' name; do
		name=${name#./}
		local path=$downloaded/$name
		if [ -L "$path" ]; then
			echo "$me: $name: a symbolic link" >&2
			status=1
		elif [ -d "$path" ]; then
			echo "$me: $name: an unexpected directory" >&2
			status=1
		elif ! [ -f "$path" ]; then
			echo "$me: $name: neither a regular file nor a directory" >&2
			status=1
		elif [ -z "${want[$name]:-}" ]; then
			echo "$me: $name: an unexpected file" >&2
			status=1
		fi
	done < <(cd "$downloaded" && find . -mindepth 1 -print0)
	for name in "${!want[@]}"; do
		if ! [ -f "$downloaded/$name" ] || [ -L "$downloaded/$name" ]; then
			echo "$me: $name is missing" >&2
			status=1
		fi
	done
	if [ "$status" -ne 0 ]; then
		echo "$me: $downloaded does not hold exactly the GUI packages of $tag and their SBOMs" >&2
		exit 1
	fi
	mkdir -p "$out"
	for name in "${!want[@]}"; do
		cp "$downloaded/$name" "$out/$name"
	done
	echo "$me: $out holds the ${#want[@]} GUI files of $tag from $downloaded"
}

# packaged FILE: the gosftpd that the package FILE installs, on stdout.
packaged() {
	case $1 in
	*.deb) dpkg-deb --fsys-tarfile "$1" | tar -xO ./usr/libexec/gosftpd-gui/gosftpd ;;
	*.rpm) rpm2cpio "$1" | cpio --quiet -i --to-stdout ./usr/libexec/gosftpd-gui/gosftpd ;;
	*.pkg.tar.zst) tar --zstd -xOf "$1" usr/lib/gosftpd-gui/gosftpd ;;
	esac
}

gosftpd() {
	local dir=$1 binary=$2 status=0 count=0 f tmp
	tmp=$(mktemp)
	for f in "$dir"/*.deb "$dir"/*.rpm "$dir"/*.pkg.tar.zst; do
		[ -e "$f" ] || continue
		count=$((count + 1))
		if ! packaged "$f" >"$tmp"; then
			echo "$me: ${f##*/}: no gosftpd could be taken out" >&2
			status=1
		elif ! cmp -s "$tmp" "$binary"; then
			echo "$me: ${f##*/}: its gosftpd is not $binary" >&2
			status=1
		else
			echo "$me: ${f##*/}: its gosftpd is $binary"
		fi
	done
	rm -f "$tmp"
	if [ "$count" -ne 4 ]; then
		echo "$me: $dir holds $count packages, not 4" >&2
		status=1
	fi
	return "$status"
}

checksums() {
	local dir=$1 sums=$2 status=0 count=0 f line
	for f in "$dir"/*; do
		[ -f "$f" ] || continue
		count=$((count + 1))
		line="$(sha256sum <"$f" | cut -d' ' -f1)  ${f##*/}"
		if ! grep -qxF -- "$line" "$sums"; then
			echo "$me: $sums does not list ${f##*/} with its SHA-256" >&2
			status=1
		fi
	done
	if [ "$count" -eq 0 ]; then
		echo "$me: $dir holds no file" >&2
		status=1
	fi
	[ "$status" -ne 0 ] || echo "$me: $sums lists the $count files of $dir"
	return "$status"
}

case ${1:-}:$# in
check:4) check "$2" "$3" "$4" ;;
gosftpd:3) gosftpd "$2" "$3" ;;
checksums:3) checksums "$2" "$3" ;;
*) usage ;;
esac
