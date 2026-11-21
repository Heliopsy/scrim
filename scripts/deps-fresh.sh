#!/usr/bin/env bash
# Dependency freshness gate: fails when a direct dependency is behind its
# latest stable major release.
#
#   scripts/deps-fresh.sh           check go.mod and every Cargo.toml under dataplane/
#   scripts/deps-fresh.sh -h        flags (-go-mod, -cargo-root, -ignore, -jobs)
#
# Go: the direct requires of go.mod and the modules providing its tools, looked
# up on proxy.golang.org, including newer major module paths (/v2, /v3, ...)
# and Deprecated markers (a renamed module). Rust: the registry entries of
# [dependencies], [dev-dependencies], [build-dependencies] and
# [workspace.dependencies], looked up on the crates.io sparse index. A
# post-1.0 dependency must be on the latest major, a 0.x one on the latest
# 0.x minor. Minor and patch lag on a post-1.0 line is Dependabot's job.
#
# Exceptions go in .deps-fresh-ignore, each with an expiry date and a reason;
# an expired entry fails the gate. The checker (scripts/depsfresh) is
# standard-library Go built with the toolchain go.mod names, so the gate
# downloads no tool, and it calls no host but those two registries.
#
#   scripts/deps-fresh.sh -pins     also the pins renovate.json describes and the
#                                   SHA-pinned actions, against GitHub, npm, PyPI,
#                                   go.dev, Helm repositories and container
#                                   registries (GITHUB_TOKEN for the API limit)
#   scripts/deps-fresh.sh -sums     the sha256 next to each pinned release asset
#                                   (-fix rewrites them, -sums-since REF limits
#                                   the check to files changed since REF)
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"
exec go run ./scripts/depsfresh "$@"
