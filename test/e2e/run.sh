#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Builds scrim, the debug data plane and one end-to-end test package, then
# runs the package inside test/e2e/sandbox.sh.
#
#   test/e2e/run.sh tools|chain|session|profiles [go test flags, e.g. -test.run TestTools]
#
# SCRIM_DATAPLANE_PATH names a data plane binary to use instead of building
# the debug one.
set -euo pipefail

pkg="${1:?usage: $0 tools|chain|session|profiles [test flags]}"
shift
root="$(cd "$(dirname "$0")/../.." && pwd)"
out="$(mktemp -d "${TMPDIR:-/tmp}/scrim-e2e-bin.XXXXXX")"
trap 'rm -rf "$out"' EXIT

if [ -z "${SCRIM_DATAPLANE_PATH:-}" ]; then
  (cd "$root/dataplane" && cargo build --locked --quiet -p scrim-dataplane)
  SCRIM_DATAPLANE_PATH="${CARGO_TARGET_DIR:-$root/dataplane/target}/debug/scrim-dataplane"
fi
(cd "$root" && go build -o "$out/scrim" . && go test -c -o "$out/e2e.test" "./test/e2e/$pkg")

cd "$root/test/e2e/$pkg"
SCRIM_E2E_SCRIM="$out/scrim" SCRIM_DATAPLANE_PATH="$SCRIM_DATAPLANE_PATH" \
  "$root/test/e2e/sandbox.sh" "$out/e2e.test" -test.v -test.count=1 -test.timeout=15m "$@"
