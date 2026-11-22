#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Runs the exec broker's separate-user test as root in a throwaway rootless
# podman container: the broker runs commands as UID 2001 for an agent of UID
# 2002, and the agent's user must not be able to read the command's
# environment. Needs nothing but podman and an image with /bin/sh.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
image=${SCRIM_EXEC_TEST_IMAGE:-docker.io/library/alpine:3.24}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

CGO_ENABLED=0 go test -c -o "$work/execbroker.test" "$root/internal/execbroker"
chmod 0755 "$work" "$work/execbroker.test"

podman run --rm --read-only --name "scrim-exec-separate-user-$$" --user 0 --network none \
  -v "$work:/t:ro" -e SCRIM_TEST_EXEC_UID=2001 -e SCRIM_TEST_AGENT_UID=2002 \
  --entrypoint /t/execbroker.test "$image" -test.run '^TestSeparateUser$' -test.v -test.count=1
