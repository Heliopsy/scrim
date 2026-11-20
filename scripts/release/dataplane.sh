#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# scripts/release/dataplane.sh PLATFORM OUT
#
# Builds the Rust data plane for one release platform (linux-amd64,
# linux-arm64, darwin-amd64, darwin-arm64) and writes the binary to OUT.
#
# Linux targets are musl and fully static. Each platform is built on a native
# runner of its own OS (both darwin targets on one macOS runner), so no cross
# linker is involved and the toolchain that links is the toolchain that the
# crate's own CI tests with.
#
# Reproducible: --locked, paths remapped out of the binary, symbols stripped,
# one codegen unit, SOURCE_DATE_EPOCH exported for any build script that reads
# it. The dependency list is embedded with cargo-auditable, so `cargo audit bin`
# and syft can read the Rust dependencies out of the shipped file.
#
# SCRIM_RELEASE_NO_AUDITABLE=1 skips cargo-auditable for a quick local build.
# The output is then not the release binary and will not match its checksum.
. "$(dirname "$0")/lib.sh"

[ $# -eq 2 ] || die "usage: $0 PLATFORM OUT"
platform=$1 out=$2
target=$(rust_target "$platform")
manifest="$ROOT/$SCRIM_DATAPLANE_MANIFEST"
[ -f "$manifest" ] || die "no data plane crate at $SCRIM_DATAPLANE_MANIFEST"

if command -v rustup >/dev/null; then
  # Inside the crate so a rust-toolchain.toml there selects the toolchain.
  # rustup no longer installs a missing pinned toolchain on first use everywhere.
  (
    cd "$(dirname "$manifest")"
    rustup show active-toolchain >/dev/null 2>&1 || rustup toolchain install
    rustup target add "$target" >/dev/null
  )
fi

cargo_home=${CARGO_HOME:-$HOME/.cargo}
target_dir=${CARGO_TARGET_DIR:-$ROOT/target/release-build}
# Overrides any rustflags in .cargo/config.toml for this build; the release
# flags are complete on their own.
RUSTFLAGS="--remap-path-prefix=$ROOT=/scrim --remap-path-prefix=$cargo_home=/cargo -C strip=symbols"
case "$target" in
  *-linux-musl) RUSTFLAGS+=" -C target-feature=+crt-static" ;;
esac
export RUSTFLAGS
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
export CARGO_PROFILE_RELEASE_INCREMENTAL=false
export CARGO_PROFILE_RELEASE_DEBUG=0
export CARGO_INCREMENTAL=0
# Read by the crate through option_env! so `scrim-dataplane --version` and the
# protocol handshake report the release version.
export SCRIM_BUILD_VERSION=$SCRIM_VERSION SCRIM_BUILD_COMMIT=$SCRIM_COMMIT

build=(build)
if [ "${SCRIM_RELEASE_NO_AUDITABLE:-}" = 1 ]; then
  log "cargo-auditable skipped: this is not a release build"
else
  cargo auditable --version >/dev/null 2>&1 \
    || die "cargo-auditable is missing: cargo install --locked cargo-auditable@$CARGO_AUDITABLE_VERSION"
  build=(auditable build)
fi

log "data plane $SCRIM_VERSION for $platform ($target)"
cargo "${build[@]}" --release --locked \
  --manifest-path "$manifest" \
  --package "$SCRIM_DATAPLANE_PACKAGE" \
  --bin "$SCRIM_DATAPLANE_BIN" \
  --target "$target" \
  --target-dir "$target_dir"

mkdir -p "$(dirname "$out")"
install -m 0755 "$target_dir/$target/release/$SCRIM_DATAPLANE_BIN" "$out"
check_binary "$out" "$platform"
log "$out $(sha256 "$out")"
