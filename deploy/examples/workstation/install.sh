#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Download a scrim release, check its signature and checksum, and install the
# binary into ~/.local/bin (or $PREFIX/bin).
#
#   VERSION=0.1.0 ./install.sh
#
# Needs curl, cosign 2.4 or later, tar and sha256sum (shasum on macOS). Nothing
# is installed unless cosign verifies checksums.txt against the release
# workflow's identity and the archive matches its signed checksum. The binary it
# replaces is kept as scrim.prev, so a rollback is one mv.
set -euo pipefail

VERSION=${VERSION:-0.4.0} # x-release-please-version
PREFIX=${PREFIX:-$HOME/.local}
OS=${OS:-$(uname -s | tr '[:upper:]' '[:lower:]')}
case "${ARCH:-$(uname -m)}" in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
case "$OS" in
  linux | darwin) ;;
  *) echo "unsupported OS: $OS" >&2; exit 1 ;;
esac

BASE=https://github.com/Heliopsy/scrim/releases/download/v$VERSION
ARCHIVE=scrim_${VERSION}_${OS}_${ARCH}.tar.gz
# The signing identity: the release workflow of Heliopsy/scrim, run from a
# release tag or from main (release-please dispatches it from main).
IDENTITY='^https://github\.com/Heliopsy/scrim/\.github/workflows/release\.yaml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?)$'
ISSUER=https://token.actions.githubusercontent.com

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

for f in "$ARCHIVE" checksums.txt checksums.txt.sigstore.json; do
  curl -fsSLO --retry 3 "$BASE/$f"
done

cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER" \
  checksums.txt

if command -v sha256sum >/dev/null; then
  sha256sum --check --ignore-missing checksums.txt
else
  shasum -a 256 --check --ignore-missing checksums.txt
fi

tar -xzf "$ARCHIVE" ./scrim
mkdir -p "$PREFIX/bin"
if [ -e "$PREFIX/bin/scrim" ]; then
  mv -f "$PREFIX/bin/scrim" "$PREFIX/bin/scrim.prev"
fi
install -m 0755 scrim "$PREFIX/bin/scrim"
"$PREFIX/bin/scrim" version
