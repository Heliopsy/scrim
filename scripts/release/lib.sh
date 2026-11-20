# shellcheck shell=bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Shared by the scripts in scripts/release. Sourced, not run.
#
# Sets ROOT (repository root), loads release.env, and derives the build
# identity every artifact is stamped with:
#
#   SCRIM_VERSION      tag without the leading v, or 0.0.0-dev+<short sha>
#   SCRIM_COMMIT       full commit sha
#   SOURCE_DATE_EPOCH  commit time, the only clock any artifact sees
#   SCRIM_DATE         SOURCE_DATE_EPOCH as RFC 3339 UTC
#
# Each can be set by the caller beforehand; the release workflow does, so every
# job of one run agrees even if they check out at different moments.

set -euo pipefail

ROOT=$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)
export ROOT

while IFS='=' read -r key value; do
  case "$key" in
    '' | '#'*) continue ;;
  esac
  # A caller's value wins, so a test can point the layout somewhere else.
  if [ -z "${!key+x}" ]; then
    export "$key=$value"
  fi
done <"$ROOT/scripts/release/release.env"

: "${SCRIM_COMMIT:=$(git -C "$ROOT" rev-parse HEAD)}"
: "${SOURCE_DATE_EPOCH:=$(git -C "$ROOT" log -1 --format=%ct HEAD)}"
if [ -z "${SCRIM_VERSION:-}" ]; then
  if tag=$(git -C "$ROOT" describe --tags --exact-match --match 'v[0-9]*' HEAD 2>/dev/null); then
    SCRIM_VERSION=${tag#v}
  else
    SCRIM_VERSION=0.0.0-dev+$(git -C "$ROOT" rev-parse --short=12 HEAD)
  fi
fi
SCRIM_VERSION=${SCRIM_VERSION#v}
if date -u -d "@0" >/dev/null 2>&1; then
  SCRIM_DATE=$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)
else
  SCRIM_DATE=$(date -u -r "$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)
fi
export SCRIM_VERSION SCRIM_COMMIT SOURCE_DATE_EPOCH SCRIM_DATE

# The release platforms, as GOOS-GOARCH with the matching Rust target.
SCRIM_PLATFORMS="linux-amd64 linux-arm64 darwin-amd64 darwin-arm64"

rust_target() {
  case "$1" in
    linux-amd64) echo x86_64-unknown-linux-musl ;;
    linux-arm64) echo aarch64-unknown-linux-musl ;;
    darwin-amd64) echo x86_64-apple-darwin ;;
    darwin-arm64) echo aarch64-apple-darwin ;;
    *) die "unsupported platform: $1 (want one of: $SCRIM_PLATFORMS)" ;;
  esac
}

die() {
  echo "error: $*" >&2
  exit 1
}

log() {
  echo "==> $*" >&2
}

sha256() {
  if command -v sha256sum >/dev/null; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# Refuses a binary for the wrong platform or one that would need anything from
# the host beyond the kernel (Linux) or libSystem (macOS). The architecture is
# read from the file header, never from what the build was asked for.
check_binary() {
  local file=$1 platform=$2 got want
  case "$platform" in
    linux-*)
      want=$([ "$platform" = linux-amd64 ] && echo 62 || echo 183)
      got=$(od -An -t u2 -j 18 -N 2 "$file" | tr -d ' ')
      [ "$(head -c 4 "$file" | od -An -t x1 | tr -d ' ')" = 7f454c46 ] || die "$file is not an ELF file"
      [ "$got" = "$want" ] || die "$file has ELF e_machine $got, want $want for $platform"
      if command -v readelf >/dev/null; then
        if readelf -lW "$file" | grep -q 'program interpreter'; then
          die "$file is dynamically linked; release binaries must be static"
        fi
        if readelf -dW "$file" 2>/dev/null | grep -q '(NEEDED)'; then
          die "$file needs shared libraries; release binaries must be static"
        fi
      else
        die "readelf is required to check $file is static"
      fi
      ;;
    darwin-*)
      # Mach-O 64-bit magic (little endian), then cputype: x86_64 0x01000007,
      # arm64 0x0100000c.
      [ "$(head -c 4 "$file" | od -An -t x1 | tr -d ' ')" = cffaedfe ] || die "$file is not a 64-bit Mach-O file"
      want=$([ "$platform" = darwin-amd64 ] && echo 16777223 || echo 16777228)
      got=$(od -An -t u4 -j 4 -N 4 "$file" | tr -d ' ')
      [ "$got" = "$want" ] || die "$file has Mach-O cputype $got, want $want for $platform"
      if command -v otool >/dev/null; then
        if otool -L "$file" | tail -n +2 | grep -v -e '/usr/lib/libSystem' -e '/usr/lib/libresolv' -e '/System/Library/Frameworks/' | grep -q .; then
          otool -L "$file" >&2
          die "$file links libraries outside the base system"
        fi
      fi
      ;;
    *) die "unsupported platform: $platform" ;;
  esac
}
