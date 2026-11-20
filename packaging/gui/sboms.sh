#!/usr/bin/env bash
# The SBOMs of the GUI's Linux packages (ADR 0013): for each of the four
# packages in DIR (make gui-packages' out/gui), DIR/PACKAGE.sbom.json, in
# SPDX JSON, written by syft from the files the package installs. syft
# names the Go modules in gosftpd-gui and in the gosftpd it carries; Qt,
# which the packages take from the system, is named in their notices.
# The arguments are GoReleaser's for the server's SBOMs (--enrich all goes
# online), with the package's name and VERSION as the source.
#
# Needs: syft, the version release.yml pins (SYFT, or syft in PATH),
# dpkg-deb, rpm2cpio, cpio, and tar with zstd.
#
# usage: packaging/gui/sboms.sh DIR VERSION
set -euo pipefail

if [ $# -ne 2 ]; then
	echo "usage: packaging/gui/sboms.sh DIR VERSION" >&2
	exit 2
fi
dir=$(realpath "$1")
version=$2
syft=${SYFT:-syft}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

count=0
for f in "$dir"/*.deb "$dir"/*.rpm "$dir"/*.pkg.tar.zst; do
	[ -e "$f" ] || continue
	count=$((count + 1))
	files=$tmp/$count
	mkdir "$files"
	case $f in
	*.deb) dpkg-deb -x "$f" "$files" ;;
	*.rpm) (cd "$files" && rpm2cpio "$f" | cpio --quiet -idm) ;;
	*) tar --zstd -xf "$f" -C "$files" --exclude=.PKGINFO --exclude=.MTREE --exclude=.BUILDINFO ;;
	esac
	"$syft" scan "dir:$files" --source-name gosftpd-gui --source-version "$version" \
		--output "spdx-json=$f.sbom.json" --enrich all
	echo "${f##*/}.sbom.json"
done
if [ "$count" -ne 4 ]; then
	echo "packaging/gui/sboms.sh: $dir holds $count packages, not 4" >&2
	exit 1
fi
