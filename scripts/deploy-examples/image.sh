#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# scripts/deploy-examples/image.sh
#
# Builds the scrim image of this tree with the release recipe (Containerfile,
# from a linux/amd64 binary with the data plane embedded) and prints its
# reference, localhost/scrim-examples:<commit>. The example checks run the
# configs against this build, not a published release: the examples follow
# the tree they live in, including settings no release has yet.
#
# The data plane is built with scripts/release/dataplane.sh (needs rustup and
# musl-tools, as in CI). SCRIM_EXAMPLES_DATAPLANE=<file> takes a linux-amd64
# musl data plane built from this tree some other way (for example
# `cargo build --release` in a rust:alpine container).
# SCRIM_EXAMPLES_DATAPLANE_IMAGE=<image> takes it from a published
# scrim-dataplane image: only for config checks, since an older data plane
# lacks newer boundary fields (Kubernetes identity among them).
#
# Remove the image with `podman rmi <reference>`; check.sh and smoke.sh do
# when they built it themselves.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
ref=localhost/scrim-examples:$(git -C "$root" rev-parse --short=12 HEAD)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/stage/linux-amd64" "$work/stage/state"

dp=$work/scrim-dataplane
if [ -n "${SCRIM_EXAMPLES_DATAPLANE:-}" ]; then
  cp "$SCRIM_EXAMPLES_DATAPLANE" "$dp"
elif [ -n "${SCRIM_EXAMPLES_DATAPLANE_IMAGE:-}" ]; then
  cid=$(podman create --name "scrim-examples-dp-$$" "$SCRIM_EXAMPLES_DATAPLANE_IMAGE")
  podman cp "$cid:/usr/local/bin/scrim-dataplane" "$dp" >&2
  podman rm -f "$cid" >/dev/null
else
  SCRIM_RELEASE_NO_AUDITABLE=1 "$root/scripts/release/dataplane.sh" linux-amd64 "$dp" >&2
fi
"$root/scripts/release/controlplane.sh" linux-amd64 "$dp" "$work/stage/linux-amd64/scrim" >&2
podman build -q --platform linux/amd64 -f "$root/Containerfile" -t "$ref" "$work/stage" >/dev/null
podman run --rm --read-only --network=none --name "scrim-examples-version-$$" "$ref" version >&2
echo "$ref"
