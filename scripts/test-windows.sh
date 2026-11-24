#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# scripts/test-windows.sh [GO TEST FLAGS...]
#
# Runs the Go unit tests on Windows (the CI windows job). Every package runs
# except the ones listed below, each with the reason it cannot run there.
# A package is listed only when what it tests does not exist on Windows;
# a test that fails on Windows for any other reason is a bug to fix, not a
# line to add here. Test files of features that are Unix only carry a
# `//go:build unix` constraint with the reason instead, so the rest of their
# package still runs.
#
# No -race: the race detector needs cgo and a C toolchain on Windows. The
# Linux job runs every package with -race.
set -euo pipefail
cd "$(dirname "$0")/.."

# package (relative to the module) and why it does not run on Windows.
excluded=(
)

declare -A skip=()
for e in "${excluded[@]}"; do
  pkg=${e%%:*}
  skip[github.com/heliopsy/scrim/$pkg]=1
  echo "skipped on Windows: $e"
done

pkgs=()
while IFS= read -r p; do
  [ -n "${skip[$p]:-}" ] || pkgs+=("$p")
done < <(go list ./...)

go test -count=1 "$@" "${pkgs[@]}"
