#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# scripts/release/tools.sh DIR TOOL...
#
# Installs release tools into DIR/bin at the versions release.env pins. TOOL is
# cosign, syft or cargo-auditable.
#
# cosign and syft are GitHub release assets for linux/amd64 and are refused
# unless their sha256 is the pinned one. cargo-auditable is built from crates.io
# with --locked, so its dependency tree is the one its Cargo.lock records and
# every crate is checked against the registry index checksum.
. "$(dirname "$0")/lib.sh"

[ $# -ge 2 ] || die "usage: $0 DIR TOOL..."
dir=$1
shift
mkdir -p "$dir/bin"
dir=$(cd "$dir" && pwd)

fetch() {
  local url=$1 want=$2 dest=$3 got
  curl --fail --silent --show-error --location --retry 5 --retry-all-errors \
    --connect-timeout 20 --max-time 300 -o "$dest" "$url"
  got=$(sha256 "$dest")
  if [ "$got" != "$want" ]; then
    rm -f "$dest"
    die "$url has sha256 $got, pinned $want"
  fi
}

for tool in "$@"; do
  case "$tool" in
    cosign)
      fetch "https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION/cosign-linux-amd64" \
        "$COSIGN_LINUX_AMD64_SHA256" "$dir/bin/cosign"
      chmod 0755 "$dir/bin/cosign"
      ;;
    syft)
      v=${SYFT_VERSION#v}
      fetch "https://github.com/anchore/syft/releases/download/$SYFT_VERSION/syft_${v}_linux_amd64.tar.gz" \
        "$SYFT_LINUX_AMD64_SHA256" "$dir/syft.tar.gz"
      tar -xzf "$dir/syft.tar.gz" -C "$dir/bin" syft
      rm -f "$dir/syft.tar.gz"
      ;;
    cargo-auditable)
      # From dataplane/, so rustup takes the toolchain rust-toolchain.toml pins
      # (a runner without a default toolchain has nothing else to choose).
      (cd "$(dirname "$0")/../../dataplane" && rustup toolchain install >/dev/null &&
        cargo install --locked --quiet --root "$dir" "cargo-auditable@$CARGO_AUDITABLE_VERSION")
      ;;
    *) die "unknown tool: $tool" ;;
  esac
  log "$tool installed in $dir/bin"
done
