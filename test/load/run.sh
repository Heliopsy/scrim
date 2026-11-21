#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Proxy-level load test (tasks.md 14.3): builds the release data plane, a
# static scrim and the load generator, then runs `scrim-load run`, which
# starts PostgreSQL, Valkey (or NATS) and the replicas in rootless podman and
# removes them afterwards.
#
#   test/load/run.sh [--profile smoke|full] [--out DIR] [scrim-load run flags]
#
# SCRIM_DATAPLANE_PATH names a release data plane to use instead of building
# one; CARGO_TARGET_DIR is honoured. Results land in --out (default
# load-results/): result.json, report.md and every container's log.
# SCRIM_LOAD_CPUPROFILE names a file under --out for a CPU profile of the
# load generator, to check that it is not the bottleneck.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
bin="$(mktemp -d "${TMPDIR:-/tmp}/scrim-load-bin.XXXXXX")"
trap 'rm -rf "$bin"' EXIT

if [ -z "${SCRIM_DATAPLANE_PATH:-}" ]; then
  (cd "$root/dataplane" && cargo build --locked --release --quiet -p scrim-dataplane)
  SCRIM_DATAPLANE_PATH="${CARGO_TARGET_DIR:-$root/dataplane/target}/release/scrim-dataplane"
fi
(cd "$root" && CGO_ENABLED=0 go build -trimpath -o "$bin/scrim" . && CGO_ENABLED=0 go build -trimpath -o "$bin/scrim-load" ./test/load)

cd "$root"
"$bin/scrim-load" run --scrim "$bin/scrim" --dataplane "$SCRIM_DATAPLANE_PATH" --profiles test/load/profiles.json "$@"
