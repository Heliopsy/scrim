#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Runs clang or llvm-strip from scripts/bpf/Containerfile in rootless podman,
# for bpf2go (`just ebpf`): BPF2GO_CC and BPF2GO_STRIP point at the clang and
# llvm-strip links to this script next to it, which pick the tool by name.
#
# The repository is mounted at its own path, so the absolute paths bpf2go
# passes resolve inside the container, and nothing else is: no network, no
# home directory. The image is built once per Containerfile content and tagged
# with its hash (localhost/scrim-bpf-toolchain:<hash>).
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tool="$(basename "$0")"
case "$tool" in
  clang | llvm-strip) ;;
  *) echo "tool.sh: $tool is not clang or llvm-strip" >&2; exit 2 ;;
esac

file="$repo/scripts/bpf/Containerfile"
image="localhost/scrim-bpf-toolchain:$(sha256sum "$file" | cut -c1-16)"
if ! podman image exists "$image"; then
  podman build -q -f "$file" -t "$image" "$repo/scripts/bpf" >/dev/null
fi
exec podman run --rm --network none --security-opt label=disable \
  -v "$repo:$repo" -w "$PWD" "$image" "$tool" "$@"
