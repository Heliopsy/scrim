#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Put rustup on PATH when the runner has none (the ho-z10 pods, and Windows
# arm64 images that ship without it). A pinned
# rustup-init is checked against a pinned sha256 and installed with no default
# toolchain, so dataplane/rust-toolchain.toml still decides the version.
set -euo pipefail
if command -v rustup >/dev/null; then
  rustup --version
  exit 0
fi
# Renovate bumps the version; `just pin-sums` then rewrites the checksums
# from the assets the sha256: lines name.
# renovate: datasource=github-tags depName=rust-lang/rustup
version=1.29.3
exe=""
case "${RUNNER_OS}-${RUNNER_ARCH}" in
  Linux-X64)
    target=x86_64-unknown-linux-gnu
    # sha256: https://static.rust-lang.org/rustup/archive/{version}/x86_64-unknown-linux-gnu/rustup-init
    sum=b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55 ;;
  Linux-ARM64)
    target=aarch64-unknown-linux-gnu
    # sha256: https://static.rust-lang.org/rustup/archive/{version}/aarch64-unknown-linux-gnu/rustup-init
    sum=9f608c142e0e38a78957d0661ba1dfaf0b6fb37184cfaa4b9a0aa57af6184282 ;;
  macOS-ARM64)
    target=aarch64-apple-darwin
    # sha256: https://static.rust-lang.org/rustup/archive/{version}/aarch64-apple-darwin/rustup-init
    sum=63752a1919a3a4793173ec70f8f212621a7ce38ba6a246095984482f4de20f9f ;;
  macOS-X64)
    target=x86_64-apple-darwin
    # sha256: https://static.rust-lang.org/rustup/archive/{version}/x86_64-apple-darwin/rustup-init
    sum=bc107f1fb0228de7fa32413c89c1b305cea9cd256e94b01150cd054128145429 ;;
  Windows-X64)
    target=x86_64-pc-windows-msvc exe=.exe
    # sha256: https://static.rust-lang.org/rustup/archive/{version}/x86_64-pc-windows-msvc/rustup-init.exe
    sum=38027d51d69a5d05493627a0634dbea52d6cd793c8f072d2373d3f4163eec7db ;;
  Windows-ARM64)
    target=aarch64-pc-windows-msvc exe=.exe
    # sha256: https://static.rust-lang.org/rustup/archive/{version}/aarch64-pc-windows-msvc/rustup-init.exe
    sum=407e0d72f81d26a01f9d032b8317908cbb2917ba22765474b682b41390792ad9 ;;
  *)
    echo "::error::no pinned rustup-init for ${RUNNER_OS}-${RUNNER_ARCH}"
    exit 1 ;;
esac
dir="$RUNNER_TEMP/rustup-init-${version}"
mkdir -p "$dir"
curl --fail --silent --show-error --location --retry 5 --retry-all-errors \
  --connect-timeout 20 --max-time 300 -o "$dir/rustup-init$exe" \
  "https://static.rust-lang.org/rustup/archive/${version}/${target}/rustup-init$exe"
if command -v sha256sum >/dev/null; then
  got=$(sha256sum "$dir/rustup-init$exe" | cut -d' ' -f1)
else
  got=$(shasum -a 256 "$dir/rustup-init$exe" | cut -d' ' -f1)
fi
[ "$got" = "$sum" ] || { echo "::error::rustup-init has sha256 $got, pinned $sum"; exit 1; }
chmod +x "$dir/rustup-init$exe"
"$dir/rustup-init$exe" -y --no-modify-path --profile minimal --default-toolchain none
rm -rf "$dir"
echo "${CARGO_HOME:-$HOME/.cargo}/bin" >> "$GITHUB_PATH"
"${CARGO_HOME:-$HOME/.cargo}/bin/rustup" --version
