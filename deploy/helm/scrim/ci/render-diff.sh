#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Before/after render diff: render the chart at a base git ref and in the
# working tree with the same values, and print the difference. A change that
# must not touch existing installs shows no diff for the defaults.
#
#   ci/render-diff.sh [BASE_REF] [VALUES.yaml ...]
#
# Ported from toc-helm-chart-template. BASE_REF defaults to origin/main. Without values files it diffs the
# defaults, every example and ci/all-features-values.yaml. Generated Secret
# values (random on every render without a cluster) and the helm.sh/chart
# label are masked. Exit 1 when anything differs (STRICT=0 prints only).
set -euo pipefail

CHART="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(cd "$CHART/../../.." && pwd)"
REL_PATH="deploy/helm/$(basename "$CHART")"
BASE="${1:-origin/main}"
shift || true
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

cd "$ROOT"
mkdir -p "$OUT/base"
git archive "$BASE" "$REL_PATH" | tar -x -C "$OUT/base"

mask() {
  python3 -c '
import sys, yaml
docs = [d for d in yaml.safe_load_all(sys.stdin) if d]
for d in docs:
    (d.get("metadata", {}).get("labels") or {}).pop("helm.sh/chart", None)
    if d.get("kind") == "Secret" and "data" in d:
        d["data"] = {k: "<masked>" for k in d["data"]}
    if d.get("kind") == "ConfigMap" and d.get("metadata", {}).get("name", "").endswith("scrim-ca"):
        d["data"] = {k: "<masked>" for k in d.get("data") or {}}
    ann = ((d.get("spec") or {}).get("template") or {}).get("metadata", {}).get("annotations") or {}
    ann.pop("checksum/config", None)
    tmpl = ((d.get("spec") or {}).get("template") or {}).get("metadata") or {}
    (tmpl.get("labels") or {}).pop("helm.sh/chart", None)
print(yaml.safe_dump_all(docs, sort_keys=True))'
}

cases=()
if [[ $# -gt 0 ]]; then
  for f in "$@"; do cases+=("$f"); done
else
  cases=("")
  for f in "$CHART"/examples/*.yaml "$CHART"/ci/all-features-values.yaml; do [[ -f "$f" ]] && cases+=("$f"); done
fi

rc=0
for f in "${cases[@]}"; do
  args=()
  [[ -n "$f" ]] && args=(-f "$f")
  label="${f:-defaults}"
  if ! helm template ci "$OUT/base/$REL_PATH" -n ci "${args[@]}" 2>/dev/null | mask > "$OUT/old.yaml"; then
    echo "== $label: the base does not render these values, skipped"
    continue
  fi
  helm template ci "$CHART" -n ci "${args[@]}" | mask > "$OUT/new.yaml"
  if diff -u --label "$BASE" --label "working tree" "$OUT/old.yaml" "$OUT/new.yaml"; then
    echo "== $label: no change"
  else
    echo "== $label: CHANGED"
    rc=1
  fi
done
[[ "${STRICT:-1}" == 1 ]] || rc=0
exit $rc
