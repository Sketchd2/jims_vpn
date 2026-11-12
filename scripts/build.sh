#!/usr/bin/env bash
# Builds every release artefact into dist/.
#   scripts/build.sh [VERSION]
# Needs: Go, makensis (apt install nsis), curl, unzip. Packages are made with nfpm via "go run".
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-$(git describe --tags --always 2>/dev/null | sed 's/^v//' || echo 0.0.0)}"
case "$VERSION" in [0-9]*) ;; *) VERSION="0.0.0+$VERSION" ;; esac
NFPM="go run github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.41.3"
WINTUN_VERSION=0.14.1
WINTUN_SHA256=07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
LDFLAGS="-s -w -X github.com/sketchd2/jims_vpn/internal/proto.Version=$VERSION"
export CGO_ENABLED=0

rm -rf dist build
mkdir -p dist build

build() { # goos goarch goarm outdir pkgs...
  local os=$1 arch=$2 arm=$3 out=$4; shift 4
  for pkg in "$@"; do
    local flags="$LDFLAGS"
    [ "$pkg" = jvpn-tray ] && flags="$flags -H=windowsgui"
    GOOS=$os GOARCH=$arch GOARM=$arm go build -trimpath -ldflags "$flags" -o "$out/" "./cmd/$pkg"
  done
}

package() { # config bindir pkgarch formats...
  local cfg=$1 bin=$2 arch=$3; shift 3
  sed -e "s|\${VERSION}|$VERSION|; s|\${BIN_DIR}|$bin|; s|\${PKG_ARCH}|$arch|" "packaging/linux/$cfg" > build/nfpm.yaml
  for fmt in "$@"; do
    $NFPM package -f build/nfpm.yaml -p "$fmt" -t dist/ >/dev/null
  done
}

echo "== Linux (version $VERSION)"
build linux amd64 "" build/linux-amd64 jvpn jvpn-hub
build linux arm64 "" build/linux-arm64 jvpn jvpn-hub
build linux arm 6 build/linux-arm jvpn          # ARMv6: runs on every Raspberry Pi, including Zero
for a in amd64 arm64; do
  package nfpm-client.yaml build/linux-$a $a deb archlinux
  package nfpm-hub.yaml build/linux-$a $a deb archlinux
done
package nfpm-client.yaml build/linux-arm arm6 deb archlinux   # .deb: armhf (Raspberry Pi OS 32-bit), Arch: armv6h
package nfpm-client.yaml build/linux-arm arm7 archlinux       # Arch Linux ARM armv7h

echo "== Windows"
build windows amd64 "" build/windows-amd64 jvpn jvpn-tray
if [ ! -f build/wintun.zip ]; then
  curl -fsSL -o build/wintun.zip "https://www.wintun.net/builds/wintun-$WINTUN_VERSION.zip"
fi
echo "$WINTUN_SHA256  build/wintun.zip" | sha256sum -c - >/dev/null
unzip -qjo build/wintun.zip wintun/bin/amd64/wintun.dll -d build/windows-amd64
makensis -V2 -DVERSION="$VERSION" -DSRC="$PWD/build/windows-amd64" -DOUT="$PWD/dist/JimsVPN-$VERSION-setup.exe" packaging/windows/installer.nsi

(cd dist && sha256sum * > SHA256SUMS)
ls -lh dist
