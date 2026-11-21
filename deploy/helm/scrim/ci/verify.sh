#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# The chart's gate: the same checks locally (`just helm-test`) and in CI (the
# chart job of .github/workflows/ci.yaml). Ported from toc-helm-chart-template.
#
#   1. values.schema.json (and docs/helm-values.schema.json), docs/helm-values.md
#      and Chart.yaml's artifacthub.io/images are generated from values.yaml
#      and current; the chart's monitoring copies equal deploy/monitoring
#   2. the defaults, every example and every CI case (ci/*-values.yaml) pass
#      `helm lint --strict`, render, and pass kubeconform -strict, CRDs
#      included (schemas from the datreeio CRDs catalog); ci/assert-<case>.py
#      checks a CI case's render where present; examples/flux passes
#      kubeconform with the Flux CRD schemas and its HelmRelease values render
#   3. every pod those renders contain, and every container the Kyverno policy
#      injects, meets Pod Security "restricted" and sets resources
#      (check-pods.py; the sidecar egress guard is its one exception)
#   4. the PrometheusRule's rules pass promtool (when installed)
#   5. the helm-unittest suites in tests/ pass
#   6. test/k8s/golden.sh: golden renders, refused values, `scrim config
#      validate` of every rendered configuration, the scrim-exec launcher
#   7. upgrading from the previous release tag changes no immutable field
#      (upgrade-check.sh; skipped while no release has the chart;
#      SKIP_UPGRADE_CHECK=1)
#   8. `helm package` works
#
#   ci/verify.sh              check
#   ci/verify.sh --generate   rewrite the generated files first
#
# Needs helm, kubeconform, helm-docs, the helm-unittest plugin, python3 with
# PyYAML, go (golden.sh builds scrim; or SCRIM_BIN), promtool optional.
# Network access for the CRD schemas. No cluster: the live install is
# ci/kind-test.sh, which runs in CI.
set -euo pipefail

CHART="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(cd "$CHART/../../.." && pwd)"
NAME="$(sed -n 's/^name: *//p' "$CHART/Chart.yaml")"
# renovate: datasource=github-releases depName=kubernetes/kubernetes extractVersion=^v(?<version>.+)$
K8S_VERSION="${K8S_VERSION:-1.37.2}"
OUT="${OUT:-$(mktemp -d "${TMPDIR:-/tmp}/scrim-verify.XXXXXX")}"
mkdir -p "$OUT"
CRD_CATALOG='https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'
RELEASE=ci
NS=ci

# Helm keeps nothing in your home unless HELM_* already point somewhere.
export HELM_CONFIG_HOME="${HELM_CONFIG_HOME:-$OUT/helm/config}" HELM_CACHE_HOME="${HELM_CACHE_HOME:-$OUT/helm/cache}"

step() { printf '\n==> %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

cd "$ROOT"

helm_docs() {
  helm-docs --chart-search-root deploy/helm --chart-to-generate "deploy/helm/$NAME" \
    --template-files chart-values.md.gotmpl --output-file ../../../docs/helm-values.md \
    --sort-values-order file --skip-version-footer >/dev/null 2>&1
}

if [[ "${1:-}" == --generate ]]; then
  step "regenerate"
  python3 "$CHART/ci/gen-schema.py"
  python3 "$CHART/ci/gen-images.py"
  helm_docs
  cp deploy/monitoring/rules/scrim.rules.yaml "$CHART/monitoring/scrim.rules.yaml"
  cp deploy/monitoring/grafana/scrim-dashboard.json "$CHART/monitoring/scrim-dashboard.json"
fi

step "generated files are current"
python3 "$CHART/ci/gen-schema.py" --check || fail "values.schema.json: run $0 --generate"
python3 "$CHART/ci/gen-images.py" --check || fail "Chart.yaml artifacthub.io/images: run $0 --generate"
before="$OUT/helm-values.md.before"
cp docs/helm-values.md "$before" 2>/dev/null || : > "$before"
helm_docs
cmp -s "$before" docs/helm-values.md \
  || fail "docs/helm-values.md was out of date: helm-docs has rewritten it, review and commit it"
cmp -s deploy/monitoring/rules/scrim.rules.yaml "$CHART/monitoring/scrim.rules.yaml" \
  || fail "monitoring/scrim.rules.yaml differs from deploy/monitoring/rules/scrim.rules.yaml: run $0 --generate"
cmp -s deploy/monitoring/grafana/scrim-dashboard.json "$CHART/monitoring/scrim-dashboard.json" \
  || fail "monitoring/scrim-dashboard.json differs from deploy/monitoring/grafana/scrim-dashboard.json: run $0 --generate"

python3 - "$CHART" <<'PY' || fail "values.yaml and ci/Containerfile.images name different third-party images"
import re, sys, yaml
from pathlib import Path
chart = Path(sys.argv[1])
pinned = set(re.findall(r"^FROM (\S+)", (chart / "ci/Containerfile.images").read_text(), re.M))
listed = set()
for entry in yaml.safe_load(yaml.safe_load((chart / "Chart.yaml").read_text())["annotations"]["artifacthub.io/images"]):
    if entry["name"] != "scrim":
        listed.add(entry["image"])
if pinned != listed:
    print(f"Containerfile.images: {sorted(pinned)}\nChart.yaml images:    {sorted(listed)}", file=sys.stderr)
    sys.exit(1)
PY

cases=("defaults:")
for f in "$CHART"/examples/*.yaml "$CHART"/ci/*-values.yaml; do
  [[ -e "$f" ]] || continue
  cases+=("$(basename "$f" .yaml | sed 's/-values$//'):$f")
done

kc=(kubeconform -strict -summary -kubernetes-version "$K8S_VERSION"
    -schema-location default -schema-location "$CRD_CATALOG")
renders=()
for c in "${cases[@]}"; do
  name="${c%%:*}"
  file="${c#*:}"
  args=()
  [[ -n "$file" ]] && args=(-f "$file")

  step "$name: helm lint --strict"
  helm lint --strict "$CHART" "${args[@]}" >/dev/null || helm lint --strict "$CHART" "${args[@]}"

  step "$name: render + kubeconform"
  helm template "$RELEASE" "$CHART" --namespace "$NS" "${args[@]}" > "$OUT/$name.yaml"
  renders+=("$OUT/$name.yaml")
  "${kc[@]}" "$OUT/$name.yaml"
  if [[ -f "$CHART/ci/assert-$name.py" ]]; then
    step "$name: assertions"
    python3 "$CHART/ci/assert-$name.py" "$OUT/$name.yaml"
  fi
done

step "flux example: kubeconform (Flux CRDs) and its HelmRelease values"
"${kc[@]}" "$CHART"/examples/flux/*.yaml
python3 - "$CHART"/examples/flux/*.yaml > "$OUT/flux-values.yaml" <<'PY'
import sys, yaml
for f in sys.argv[1:]:
    for d in yaml.safe_load_all(open(f)):
        if d and d.get("kind") == "HelmRelease":
            yaml.safe_dump(d["spec"].get("values") or {}, sys.stdout)
PY
helm template "$RELEASE" "$CHART" --namespace "$NS" -f "$OUT/flux-values.yaml" > /dev/null

step "optional objects: off by default"
for kind in ClusterPolicy NetworkPolicy ServiceMonitor PodMonitor PrometheusRule ExternalSecret HorizontalPodAutoscaler; do
  ! grep -q "^kind: $kind\$" "$OUT/defaults.yaml" || fail "the defaults render a $kind"
done

step "pods: Pod Security restricted, resources, automount stated"
python3 "$CHART/ci/check-pods.py" "${renders[@]}"

step "PrometheusRule (promtool)"
if command -v promtool >/dev/null; then
  python3 - "$OUT/all-features.yaml" "$OUT/rules.yaml" <<'PY'
import sys, yaml
doc = next(d for d in yaml.safe_load_all(open(sys.argv[1])) if d and d.get("kind") == "PrometheusRule")
yaml.safe_dump({"groups": doc["spec"]["groups"]}, open(sys.argv[2], "w"))
PY
  promtool check rules "$OUT/rules.yaml"
else
  echo "promtool not installed, PrometheusRule check skipped (CI installs it)"
fi

step "helm-unittest"
helm plugin list 2>/dev/null | grep -q '^unittest' \
  || fail "the helm-unittest plugin is not installed (docs/kubernetes.md, Testing)"
helm unittest --strict "$CHART"

step "golden renders, refusals, scrim config validate, scrim-exec"
"$ROOT/test/k8s/golden.sh"

if [[ "${SKIP_UPGRADE_CHECK:-}" == 1 ]]; then
  step "upgrade check skipped (SKIP_UPGRADE_CHECK=1)"
else
  step "upgrade from the previous release"
  OUT="$OUT" "$CHART/ci/upgrade-check.sh"
fi

step "helm package"
helm package "$CHART" -d "$OUT" >/dev/null
ls "$OUT/$NAME"-*.tgz

printf '\nchart checks green (renders in %s)\n' "$OUT"
