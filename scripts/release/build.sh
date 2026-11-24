#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# scripts/release/build.sh [PLATFORM...]
#
# Builds the release pair for each PLATFORM (default: this host's) into
# dist/bin/<platform>/: the data plane first, then scrim with that data plane
# embedded. The same two scripts the release workflow runs, one platform at a
# time.
. "$(dirname "$0")/lib.sh"

if [ $# -eq 0 ]; then
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) set -- linux-amd64 ;;
    Linux-aarch64) set -- linux-arm64 ;;
    Darwin-x86_64) set -- darwin-amd64 ;;
    Darwin-arm64) set -- darwin-arm64 ;;
    MINGW*-x86_64 | MSYS*-x86_64) set -- windows-amd64 ;;
    MINGW*-aarch64 | MSYS*-aarch64) set -- windows-arm64 ;;
    *) die "no release platform for $(uname -s) $(uname -m)" ;;
  esac
fi

for platform in "$@"; do
  rust_target "$platform" >/dev/null
  out="$ROOT/dist/bin/$platform" x=$(exe "$platform")
  "$ROOT/scripts/release/dataplane.sh" "$platform" "$out/$SCRIM_DATAPLANE_BIN$x"
  "$ROOT/scripts/release/controlplane.sh" "$platform" "$out/$SCRIM_DATAPLANE_BIN$x" "$out/scrim$x"
done
