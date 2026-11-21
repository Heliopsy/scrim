#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# The aws CLI through the tool proxy against LocalStack in rootless podman,
# with placeholder keys only (task 10a.2): the e2e_aws test of
# scrim-toolproxy. Needs podman, aws and curl. Removes everything it starts.
#
# LocalStack images after 4.14 refuse to start without a license token; 4.14
# is the last community image (renovate.json keeps it there).
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
image="${LOCALSTACK_IMAGE:-docker.io/localstack/localstack:4.14}"
name="scrim-e2e-localstack-$$"
port="${LOCALSTACK_PORT:-4566}"

for t in podman aws curl cargo; do
  command -v "$t" >/dev/null || { echo "$t is not on PATH" >&2; exit 1; }
done
cleanup() { podman rm -f -v "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT

podman run -d --name "$name" -p "127.0.0.1:$port:4566" \
  -e S3_SKIP_SIGNATURE_VALIDATION=0 "$image" >/dev/null
for _ in $(seq 60); do
  if curl -fsS "http://127.0.0.1:$port/_localstack/health" >/dev/null 2>&1; then break; fi
  sleep 2
done
# localhost.localstack.cloud resolves to 127.0.0.1 and LocalStack serves a
# publicly trusted certificate for it, so the proxy verifies it with the
# system roots.
cd "$root/dataplane"
SCRIM_E2E_AWS_ENDPOINT="https://localhost.localstack.cloud:$port" \
SCRIM_E2E_AWS_CLI="$(command -v aws)" \
  cargo test --locked -p scrim-toolproxy --test e2e_aws -- --ignored --nocapture
