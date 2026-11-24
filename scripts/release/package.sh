#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# scripts/release/package.sh BIN_DIR OUT_DIR
#
# Turns the built binaries into the release assets:
#
#   BIN_DIR/<platform>/scrim
#   BIN_DIR/<platform>/scrim-dataplane
#
# becomes, in OUT_DIR,
#
#   scrim_<version>_<os>_<arch>.tar.gz             scrim, LICENSE, README.md
#   scrim-dataplane_<version>_<os>_<arch>.tar.gz   scrim-dataplane, LICENSE, README.md
#   <archive>.spdx.json                            SBOM per archive (syft)
#   checksums.txt                                  sha256 of every file above
#
# scripts/release/results.sh assemble later adds the release's leak and
# performance results and rewrites checksums.txt to include them.
#
# Archives are byte-reproducible: fixed order, owner, modes and mtime
# (SOURCE_DATE_EPOCH), and gzip without a name or timestamp. SBOMs carry a
# generation time and are not part of the reproducibility guarantee; their
# checksums are still signed with everything else.
#
# SCRIM_RELEASE_NO_SBOM=1 skips the SBOMs when syft is not installed.
. "$(dirname "$0")/lib.sh"

[ $# -eq 2 ] || die "usage: $0 BIN_DIR OUT_DIR"
bin_dir=$1 out=$2
mkdir -p "$out"
out=$(cd "$out" && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

tar --version 2>/dev/null | grep -q 'GNU tar' || die "GNU tar is required for reproducible archives"

archive() {
  local name=$1 dir=$2
  (
    cd "$dir"
    LC_ALL=C tar --sort=name --format=gnu \
      --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
      -cf - . | gzip -n -9 >"$out/$name"
  )
}

sbom() {
  local name=$1 dir=$2
  if [ "${SCRIM_RELEASE_NO_SBOM:-}" = 1 ]; then
    return
  fi
  command -v syft >/dev/null || die "syft is missing (set SCRIM_RELEASE_NO_SBOM=1 to skip SBOMs)"
  SYFT_CHECK_FOR_APP_UPDATE=false syft scan "dir:$dir" \
    --quiet \
    --source-name "${name%.tar.gz}" --source-version "$SCRIM_VERSION" \
    -o "spdx-json=$out/$name.spdx.json"
}

found=0
for platform in $SCRIM_PLATFORMS; do
  src="$bin_dir/$platform"
  if [ ! -d "$src" ]; then
    continue
  fi
  found=1
  os=${platform%-*} arch=${platform#*-}
  for binary in scrim "$SCRIM_DATAPLANE_BIN"; do
    [ -f "$src/$binary" ] || die "missing $src/$binary"
    check_binary "$src/$binary" "$platform"
    dir="$stage/$binary-$platform"
    mkdir -p "$dir"
    chmod 0755 "$dir"
    install -m 0755 "$src/$binary" "$dir/$binary"
    install -m 0644 "$ROOT/LICENSE" "$ROOT/README.md" "$dir/"
    name="${binary}_${SCRIM_VERSION}_${os}_${arch}.tar.gz"
    log "$name"
    archive "$name" "$dir"
    if [ "$binary" = scrim ]; then
      # The data plane inside scrim is an opaque blob to syft. The same bytes
      # are scanned beside it so the SBOM lists the Rust dependencies too.
      install -m 0755 "$src/$SCRIM_DATAPLANE_BIN" "$dir/embedded-$SCRIM_DATAPLANE_BIN"
    fi
    sbom "$name" "$dir"
  done
done
[ "$found" = 1 ] || die "no platform directories under $bin_dir"

write_checksums "$out"
log "$out/checksums.txt"
cat "$out/checksums.txt" >&2
