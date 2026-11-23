#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Builds scrim, the debug data plane and the matrix test binary, then runs the
# end-to-end matrix cells of one store (test/e2e/matrix, tasks.md 16.1).
#
#   test/e2e/matrix/run.sh file|openbao|vault|awssm [go test flags]
#   SCRIM_MATRIX_CELLS="transparent/vault/bedrock mcp-only/vault" test/e2e/matrix/run.sh vault
#
# The store's server runs in rootless podman (containers named scrim-matrix-*,
# removed at the end); the cells run inside test/e2e/sandbox.sh, which needs
# unprivileged user namespaces and nft. SCRIM_DATAPLANE_PATH names a data plane
# binary to use instead of building the debug one; SCRIM_MATRIX_RESULTS a
# directory for one JSON result per cell.
set -euo pipefail

store="${1:?usage: $0 file|openbao|vault|awssm [test flags]}"
shift
root="$(cd "$(dirname "$0")/../../.." && pwd)"
out="$(mktemp -d "${TMPDIR:-/tmp}/scrim-matrix-bin.XXXXXX")"
trap 'rm -rf "$out"' EXIT

for tool in podman nft unshare; do
  command -v "$tool" >/dev/null || { echo "$tool is not installed" >&2; exit 1; }
done
if [ -z "${SCRIM_DATAPLANE_PATH:-}" ]; then
  (cd "$root/dataplane" && cargo build --locked --quiet -p scrim-dataplane)
  SCRIM_DATAPLANE_PATH="${CARGO_TARGET_DIR:-$root/dataplane/target}/debug/scrim-dataplane"
fi
(cd "$root" && go build -o "$out/scrim" . && go test -c -o "$out/matrix.test" ./test/e2e/matrix)

cd "$root/test/e2e/matrix"
SCRIM_MATRIX_STORE="$store" SCRIM_E2E_SCRIM="$out/scrim" SCRIM_DATAPLANE_PATH="$SCRIM_DATAPLANE_PATH" \
  SCRIM_TEST_PODMAN="${SCRIM_TEST_PODMAN:-1}" SCRIM_TEST_CONTAINER_PREFIX=scrim-matrix \
  "$out/matrix.test" -test.run '^TestMatrix$' -test.v -test.count=1 -test.timeout=60m "$@"
