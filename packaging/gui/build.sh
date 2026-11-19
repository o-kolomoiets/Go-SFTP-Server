#!/usr/bin/env bash
# Builds the Linux packages of gosftpd-gui into out/gui (make gui-packages;
# ADR 0013, "Packaging and signing"):
#
#   gosftpd-gui_VERSION_amd64.deb          Debian 12 and later, Ubuntu 24.04
#   gosftpd-gui-VERSION-1.fc44.x86_64.rpm  Fedora 44 and later
#   gosftpd-gui-VERSION-1.el9.x86_64.rpm   EL 9 with EPEL (Qt 6 is in EPEL)
#   gosftpd-gui-VERSION-1-x86_64.pkg.tar.zst  Arch Linux
#
# Each package carries gosftpd, built here as GoReleaser builds it, so that
# the release can compare it with dist/'s byte for byte. The GUI binaries
# are compiled in containers pinned below: the deb's and the Arch package's
# in Debian 12 (Qt 6.4.2, glibc 2.36: a binary of a newer system would not
# start on an older one), the rpms' in Fedora 44 and in EL 9 with EPEL.
#
# Everything is built from a clean clone of the commit (REF, HEAD by
# default), never from the working tree: the binaries record the commit and
# that the tree was clean.
#
# Needs: git, go (the version the release uses), make, docker, and network
# access to the Go module proxy, the images' registries, snapshot.debian.org,
# dl.fedoraproject.org, dl.rockylinux.org and kojipkgs.fedoraproject.org.
#
# usage: packaging/gui/build.sh [REF]
# VERSION overrides the version (default: the tag of REF, or git describe
# --abbrev=12). The release passes the tag it builds, GORELEASER_CURRENT_TAG,
# which is also gosftpd's version in dist/. GOSFTPD_ONLY=1 builds only
# gosftpd, into out/gui/gosftpd: CI compares it with GoReleaser's.
set -euo pipefail

# Pins. Dependabot does not see them: the release checklist lists them, and
# TestChecklistPins checks that it names these values.
DEBIAN_IMAGE=docker.io/library/debian:12@sha256:268fb24c39bca92d326dd83ea3abebe4a3f7751c804ffef23bb6d857dd343ff8
DEBIAN_SNAPSHOT=20261119T000000Z # snapshot.debian.org: the archive as it was then
DEBIAN_QT=6.4.2+dfsg-10
FEDORA_IMAGE=docker.io/library/fedora:44@sha256:15da97ed9aa94dd3d92c3925eb89520f6c80e07ea7ee24cba848d1f8b6912b3e
FEDORA_RELEASE=44 # its release repository, which never changes (in the archive after its end of life): Qt 6.10.2-2.fc44
FEDORA_QT=6.10.2-2.fc44
EL9_IMAGE=docker.io/rockylinux/rockylinux:9-ubi-init@sha256:535cbdf9607fba5db5678d368193661ef3012c35d06782fdb4ed0e27af4af0b4
ROCKY_RELEASE=9.8 # the vault's copy of the minor release, which takes its updates until 9.9 ships:
EL9_GCC=11.5.0-14.el9 # so the compiler, its C++ library and the linker are pinned (and glibc's headers to
EL9_BINUTILS=2.35.2-72.el9 # the image's glibc); the vault keeps every build of the minor release
EL9_KERNEL_HEADERS=5.14.0-687.10.1.el9_8.0.1
EPEL_QT=6.10.3-1.el9 # from Koji, by digest: EPEL keeps only its latest build
EPEL_QT_SHA256="
539a50dfea7fe1eedeeea7c41ee4afdf9ddeb4e41da7499c934d2674d7de5d1d  qt6-qtbase-6.10.3-1.el9.x86_64.rpm
e5af305e7ec8c551d0b72bba492f556ff467d2317b0e78181dfbea6f877cae87  qt6-qtbase-common-6.10.3-1.el9.noarch.rpm
d8f398aaae7b1914186f2f85c6322ac75efd58228fd26681c845ff18da601300  qt6-qtbase-devel-6.10.3-1.el9.x86_64.rpm
a2f30b6ae5519583c0be43e58b9f62f8e5ab58f56b6da035fc798293bf1f1629  qt6-qtbase-gui-6.10.3-1.el9.x86_64.rpm
"
NFPM=v2.48.0

ref=${1:-HEAD}
root=$(git rev-parse --show-toplevel)
commit=$(git -C "$root" rev-parse --verify "$ref^{commit}")
out=$root/out/gui
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "== a clean clone of $commit"
git clone --quiet --no-checkout "$root" "$tmp/src"
git -C "$tmp/src" checkout --quiet --detach "$commit"
src=$tmp/src
tag=$(git -C "$src" describe --tags --exact-match 2>/dev/null || true)
version=${VERSION:-${tag:-$(git -C "$src" describe --tags --always --abbrev=12)}}
epoch=$(git -C "$src" log -1 --format=%ct)
# GoReleaser's .CommitDate: the commit time in UTC, RFC 3339.
commit_date=$(TZ=UTC0 git -C "$src" log -1 --date=format-local:%Y-%m-%dT%H:%M:%SZ --format=%cd)

goroot=$(go env GOROOT)
gomod=$(go env GOMODCACHE)
for m in . gui tools; do
	(cd "$src/$m" && go mod download)
done

echo "== gosftpd $version, as GoReleaser builds it"
mkdir -p "$tmp/bin"
# .goreleaser.yaml's builds: env, flags and ldflags, joined as it joins
# them, and the GOAMD64 GoReleaser sets; GOFLAGS as the environment has it,
# as GoReleaser takes it.
(cd "$src" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 go build -trimpath \
	-ldflags="-s -w -X github.com/o-kolomoiets/go-sftp-server/internal/version.Version=$version -X github.com/o-kolomoiets/go-sftp-server/internal/version.Commit=$commit -X github.com/o-kolomoiets/go-sftp-server/internal/version.Date=$commit_date" \
	-o "$tmp/bin/gosftpd" ./cmd/gosftpd)
if [ -n "${GOSFTPD_ONLY:-}" ]; then
	rm -rf "$out" && mkdir -p "$out" && cp "$tmp/bin/gosftpd" "$out/gosftpd"
	exit 0
fi
(cd "$src" && SOURCE_DATE_EPOCH=$epoch make --no-print-directory generate >/dev/null)

# gui_build IMAGE NAME SETUP: compiles gosftpd-gui in IMAGE after SETUP,
# a shell script that installs Qt 6's development files, g++, pkg-config
# and git. Go and the modules come from this machine, read-only, and no
# build cache is used: a release's builds are cold (ADR 0013).
gui_build() {
	local image=$1 name=$2 setup=$3 after=${4:-}
	echo "== gosftpd-gui for $name, in $image"
	cat >"$tmp/$name.sh" <<-EOF
		set -euo pipefail
		$setup
		export PATH=/goroot/bin:\$PATH HOME=/tmp GOMODCACHE=/gomod GOPROXY=off GOFLAGS=-mod=readonly \
			GOTOOLCHAIN=local GOCACHE=/tmp/gocache GOGC=50 CGO_ENABLED=1 \
			CGO_CFLAGS='-Os -ffunction-sections -fdata-sections' CGO_CXXFLAGS='-Os -ffunction-sections -fdata-sections' \
			CGO_LDFLAGS='-Wl,--gc-sections'
		git config --global --add safe.directory '*'
		cd /src/gui
		go build -trimpath -gcflags=github.com/mappu/miqt/qt6=-c=1 -ldflags='-s -w -X main.version=$version' \
			-o /out/gosftpd-gui ./cmd/gosftpd-gui
		$after
	EOF
	mkdir -p "$tmp/$name"
	docker run --rm --network host \
		-e http_proxy -e https_proxy -e HTTP_PROXY -e HTTPS_PROXY -e no_proxy -e NO_PROXY \
		${CA_BUNDLE:+-v "$CA_BUNDLE:/ca.crt:ro"} \
		-v "$goroot:/goroot:ro" -v "$gomod:/gomod:ro" -v "$src:/src:ro" \
		-v "$tmp/$name:/out" -v "$tmp/$name.sh:/build.sh:ro" \
		"$image" bash /build.sh
}

# A proxy with its own certificate authority (CA_BUNDLE) is trusted in the
# containers too; a release runner has none.
trust_rpm='if [ -f /ca.crt ]; then cp /ca.crt /etc/pki/ca-trust/source/anchors/ && update-ca-trust; fi'
proxy_dnf='if [ -n "${https_proxy:-}" ]; then echo "proxy=$https_proxy" >>/etc/dnf/dnf.conf; fi'

# Debian's image has no certificate authorities: apt fetches over plain
# HTTP, and checks the archive's signatures itself. A proxy that takes only
# HTTPS (with CA_BUNDLE) gets HTTPS.
gui_build "$DEBIAN_IMAGE" debian "
rm -f /etc/apt/sources.list.d/debian.sources
scheme=http
if [ -f /ca.crt ]; then
	scheme=https
	echo 'Acquire::https::CaInfo \"/ca.crt\";' >/etc/apt/apt.conf.d/ca
	[ -z \"\${https_proxy:-}\" ] || echo \"Acquire::https::Proxy \\\"\$https_proxy\\\";\" >/etc/apt/apt.conf.d/proxy
fi
cat >/etc/apt/sources.list <<L
deb [check-valid-until=no] \$scheme://snapshot.debian.org/archive/debian/$DEBIAN_SNAPSHOT bookworm main
deb [check-valid-until=no] \$scheme://snapshot.debian.org/archive/debian-security/$DEBIAN_SNAPSHOT bookworm-security main
L
apt-get -qq update
DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends \
	qt6-base-dev=$DEBIAN_QT g++ pkg-config git ca-certificates >/dev/null
" "
# THIRD_PARTY_LICENSES of the GUI: go-licenses loads the cgo package, so it
# runs where Qt's headers are.
cd /src/gui
GOROOT=/goroot go tool -modfile=../tools/go.mod go-licenses report ./cmd/gosftpd-gui \
	--ignore github.com/o-kolomoiets/go-sftp-server --template=../packaging/third_party_licenses.tpl >/out/THIRD_PARTY_LICENSES
# The template is gosftpd's: its first line names the program.
sed -i '1s/^gosftpd is licensed /gosftpd-gui is licensed /' /out/THIRD_PARTY_LICENSES
grep -q '^gosftpd-gui is licensed ' /out/THIRD_PARTY_LICENSES
"

gui_build "$FEDORA_IMAGE" fedora "
$trust_rpm
rm -f /etc/yum.repos.d/*.repo
cat >/etc/yum.repos.d/fedora.repo <<'R'
[fedora]
name=Fedora $FEDORA_RELEASE
baseurl=https://dl.fedoraproject.org/pub/fedora/linux/releases/$FEDORA_RELEASE/Everything/x86_64/os/,https://dl.fedoraproject.org/pub/archive/fedora/linux/releases/$FEDORA_RELEASE/Everything/x86_64/os/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-$FEDORA_RELEASE-x86_64
R
$proxy_dnf
dnf -q -y --setopt=install_weak_deps=False install qt6-qtbase-devel-$FEDORA_QT gcc-c++ pkgconf-pkg-config git >/dev/null
" ""

gui_build "$EL9_IMAGE" el9 "
$trust_rpm
rm -f /etc/yum.repos.d/*.repo
for r in BaseOS AppStream CRB; do
	printf '[%s]\nname=Rocky %s %s\nbaseurl=https://dl.rockylinux.org/vault/rocky/$ROCKY_RELEASE/%s/x86_64/os/\ngpgcheck=1\ngpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9\n' \"\$r\" $ROCKY_RELEASE \"\$r\" \"\$r\" >>/etc/yum.repos.d/rocky.repo
done
# Qt's other dependencies come from the vault and EPEL as they are; the
# compiler, the linker and the headers they build with are pinned below.
printf '[epel]\nname=EPEL 9\nbaseurl=https://dl.fedoraproject.org/pub/epel/9/Everything/x86_64/\ngpgcheck=1\ngpgkey=https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-9\n' >>/etc/yum.repos.d/rocky.repo
$proxy_dnf
cd /tmp
grep . >qt.sha256 <<'S'
$EPEL_QT_SHA256
S
awk 'NF {print \$2}' qt.sha256 | while read -r f; do
	a=\${f%.rpm}; a=\${a##*.}
	curl -fsSLO https://kojipkgs.fedoraproject.org/packages/qt6-qtbase/${EPEL_QT%-*}/${EPEL_QT##*-}/\$a/\$f
done
sha256sum --check --strict --quiet qt.sha256
glibc=\$(rpm -q --qf '%{VERSION}-%{RELEASE}' glibc)
dnf -q -y --setopt=install_weak_deps=False install gcc-c++-$EL9_GCC gcc-$EL9_GCC cpp-$EL9_GCC libstdc++-devel-$EL9_GCC \
	binutils-$EL9_BINUTILS glibc-devel-\$glibc glibc-headers-\$glibc kernel-headers-$EL9_KERNEL_HEADERS >/dev/null
dnf -q -y --setopt=install_weak_deps=False install ./qt6-qtbase*.rpm pkgconf-pkg-config git >/dev/null
# Still the pinned ones after Qt's install.
rpm -q gcc-c++-$EL9_GCC binutils-$EL9_BINUTILS glibc-devel-\$glibc kernel-headers-$EL9_KERNEL_HEADERS
" ""

echo "== packages"
mkdir -p "$tmp/pkg"
cp "$src/LICENSE" "$tmp/pkg/LICENSE"
cp "$src/out/THIRD_PARTY_LICENSES" "$tmp/pkg/THIRD_PARTY_LICENSES.gosftpd"
cp "$tmp/debian/THIRD_PARTY_LICENSES" "$tmp/pkg/THIRD_PARTY_LICENSES"
{ printf '\n%s\nGo standard library and runtime %s\nLicense: BSD-3-Clause\n\n' \
	================================================================================ "$(go env GOVERSION)" &&
	cat "$goroot/LICENSE"; } >>"$tmp/pkg/THIRD_PARTY_LICENSES"
! grep -qx 'License: Unknown' "$tmp/pkg/THIRD_PARTY_LICENSES" ||
	{ echo "THIRD_PARTY_LICENSES of the GUI: go-licenses could not classify a license" >&2; exit 1; }
rm -rf "$out" && mkdir -p "$out"
nfpm="go run github.com/goreleaser/nfpm/v2/cmd/nfpm@$NFPM"
cp "$src/packaging/gui/nfpm.yaml" "$tmp/nfpm.yaml"
# Arch's: with an epoch (see nfpm.yaml), and its pkgdesc one line, the
# description's first.
{ awk 'd == 1 { print "description: " substr($0, 3); d = 2; next }
	d == 2 && /^  / { next }
	{ d = 0 }
	/^description: [|]-$/ { d = 1; next }
	{ print }' "$src/packaging/gui/nfpm.yaml" && echo 'epoch: "0"'; } >"$tmp/nfpm-archlinux.yaml"
grep -qx 'description: Share folders over SFTP from a window' "$tmp/nfpm-archlinux.yaml"
# package FORMAT BINARY_DIR RELEASE
package() {
	local config=$tmp/nfpm.yaml
	[ "$1" != archlinux ] || config=$tmp/nfpm-archlinux.yaml
	(cd "$src" && GUI_VERSION=$version GUI_BINARY=$tmp/$2/gosftpd-gui GOSFTPD=$tmp/bin/gosftpd PKG=$tmp/pkg \
		GUI_RELEASE=$3 SOURCE_DATE_EPOCH=$epoch $nfpm package --config "$config" --packager "$1" --target "$out/")
}
package deb debian 1
package archlinux debian 1
package rpm fedora 1.fc$FEDORA_RELEASE
package rpm el9 1.el9
(cd "$out" && files=(*) && sha256sum -- "${files[@]}" | tee SHA256SUMS)
