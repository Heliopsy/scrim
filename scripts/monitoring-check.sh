#!/usr/bin/env bash
# Validates the monitoring assets in deploy/monitoring/.
#
#   scripts/monitoring-check.sh             check everything
#   scripts/monitoring-check.sh --generate  regenerate prometheus-rules.yaml and
#                                           grafana/scrim-dashboard.configmap.yaml
#                                           from their sources, then check
#
# promtool comes from PATH, or from a pinned Prometheus release downloaded into
# ${SCRIM_TOOLS_DIR:-<repo>/bin/tools}. SCRIM_MONITORING_PODMAN=1 runs promtool
# from the pinned prom/prometheus image with rootless podman instead.
set -euo pipefail

PROMETHEUS_VERSION=3.16.0
PROMETHEUS_SHA256_LINUX_AMD64=68727009472a2c02e1ff7f062fd5b3e637285bffc8fc2d340c76fb449d6e0f34
PROMETHEUS_SHA256_LINUX_ARM64=fd8571b8162f4020232d886f17340bcf92e1722985ae3b4c1d096157826c0fbe
PROMETHEUS_IMAGE="docker.io/prom/prometheus:v${PROMETHEUS_VERSION}"

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mon="deploy/monitoring"
cd "$repo"

generate=0
case "${1:-}" in
  --generate) generate=1 ;;
  "") ;;
  *) echo "usage: $0 [--generate]" >&2; exit 2 ;;
esac

if [[ "$generate" == 1 ]]; then
  python3 -I - "$mon" <<'PY'
import sys

mon = sys.argv[1]

rules = open(f"{mon}/rules/scrim.rules.yaml", encoding="utf-8").read()
body = "".join(
    ("    " + line) if line.strip() else line
    for line in rules.splitlines(keepends=True)
    if not line.startswith("#")
)
with open(f"{mon}/prometheus-rules.yaml", "w", encoding="utf-8") as f:
    f.write(
        "# Generated from rules/scrim.rules.yaml by scripts/monitoring-check.sh --generate.\n"
        "# Do not edit by hand.\n"
        "apiVersion: monitoring.coreos.com/v1\n"
        "kind: PrometheusRule\n"
        "metadata:\n"
        "  name: scrim\n"
        "  labels:\n"
        "    app.kubernetes.io/name: scrim\n"
        "    app.kubernetes.io/component: monitoring\n"
        "spec:\n" + body
    )

dash = open(f"{mon}/grafana/scrim-dashboard.json", encoding="utf-8").read()
if not dash.endswith("\n"):
    dash += "\n"
with open(f"{mon}/grafana/scrim-dashboard.configmap.yaml", "w", encoding="utf-8") as f:
    f.write(
        "# Generated from scrim-dashboard.json by scripts/monitoring-check.sh --generate.\n"
        "# Do not edit by hand.\n"
        "apiVersion: v1\n"
        "kind: ConfigMap\n"
        "metadata:\n"
        "  name: scrim-grafana-dashboard\n"
        "  labels:\n"
        '    grafana_dashboard: "1"\n'
        "    app.kubernetes.io/name: scrim\n"
        "    app.kubernetes.io/component: monitoring\n"
        "data:\n"
        "  scrim-dashboard.json: |\n"
        + "".join(("    " + l) if l.strip() else l for l in dash.splitlines(keepends=True))
    )
print("generated prometheus-rules.yaml and grafana/scrim-dashboard.configmap.yaml")
PY
fi

# ---------------------------------------------------------------- promtool

promtool_from_release() {
  local tools="${SCRIM_TOOLS_DIR:-$repo/bin/tools}"
  local arch sum
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) arch=linux-amd64; sum="$PROMETHEUS_SHA256_LINUX_AMD64" ;;
    Linux-aarch64 | Linux-arm64) arch=linux-arm64; sum="$PROMETHEUS_SHA256_LINUX_ARM64" ;;
    *) echo "no pinned Prometheus release for $(uname -s)-$(uname -m); put promtool on PATH" >&2; return 1 ;;
  esac
  local dir="$tools/prometheus-${PROMETHEUS_VERSION}.${arch}"
  if [[ ! -x "$dir/promtool" ]]; then
    local tarball="prometheus-${PROMETHEUS_VERSION}.${arch}.tar.gz"
    local url="https://github.com/prometheus/prometheus/releases/download/v${PROMETHEUS_VERSION}/${tarball}"
    local tmp
    tmp="$(mktemp -d)"
    echo "downloading $url" >&2
    curl -fsSL --retry 3 -o "$tmp/$tarball" "$url"
    echo "$sum  $tmp/$tarball" | sha256sum -c --quiet - >&2
    mkdir -p "$tools"
    tar -xzf "$tmp/$tarball" -C "$tmp" "prometheus-${PROMETHEUS_VERSION}.${arch}/promtool"
    mkdir -p "$dir"
    mv "$tmp/prometheus-${PROMETHEUS_VERSION}.${arch}/promtool" "$dir/promtool"
    rm -rf "$tmp"
  fi
  echo "$dir/promtool"
}

if [[ "${SCRIM_MONITORING_PODMAN:-0}" == 1 ]]; then
  promtool() {
    podman run --rm --name scrim-mon-promtool --network none \
      -v "$repo/$mon:/work/$mon:ro,Z" -w /work \
      --entrypoint promtool "$PROMETHEUS_IMAGE" "$@"
  }
elif command -v promtool >/dev/null 2>&1; then
  :
else
  PROMTOOL="$(promtool_from_release)"
  promtool() { "$PROMTOOL" "$@"; }
fi

echo "== promtool $(promtool --version 2>&1 | head -1)"

echo "== promtool check rules"
promtool check rules "$mon/rules/scrim.rules.yaml"

echo "== promtool test rules"
promtool test rules "$mon/rules/tests/scrim.rules.test.yaml"

echo "== promtool check config"
promtool check config "$mon/prometheus/prometheus.yaml"
promtool check config "$mon/prometheus/scrape-config.yaml"

# ---------------------------------------------------------------- structure

echo "== PrometheusRule, dashboard and ConfigMap consistency"
python3 -I - "$mon" <<'PY'
import json
import re
import sys

import yaml

mon = sys.argv[1]
errors = []

# PrometheusRule spec must equal the plain rule file.
plain = yaml.safe_load(open(f"{mon}/rules/scrim.rules.yaml", encoding="utf-8"))
pr = yaml.safe_load(open(f"{mon}/prometheus-rules.yaml", encoding="utf-8"))
if pr.get("apiVersion") != "monitoring.coreos.com/v1" or pr.get("kind") != "PrometheusRule":
    errors.append("prometheus-rules.yaml is not a monitoring.coreos.com/v1 PrometheusRule")
if pr.get("metadata", {}).get("name") != "scrim":
    errors.append("PrometheusRule must be named scrim")
if pr.get("spec") != plain:
    errors.append("PrometheusRule spec differs from rules/scrim.rules.yaml; run with --generate")

# Every alert carries severity and the annotations, runbook anchored on its name.
alerts = []
for group in plain["groups"]:
    for rule in group["rules"]:
        name = rule.get("alert")
        if not name:
            continue
        alerts.append(name)
        if rule.get("labels", {}).get("severity") not in ("info", "warning", "critical"):
            errors.append(f"{name}: severity must be info, warning or critical")
        ann = rule.get("annotations", {})
        for key in ("summary", "description", "runbook_url"):
            if not ann.get(key):
                errors.append(f"{name}: missing annotation {key}")
        want = "https://github.com/heliopsy/scrim/blob/main/docs/monitoring.md#" + name.lower()
        if ann.get("runbook_url") != want:
            errors.append(f"{name}: runbook_url must be {want}")
if len(alerts) != len(set(alerts)):
    errors.append("duplicate alert names")

# Every alert has a firing and a quiet test case.
tests = yaml.safe_load(open(f"{mon}/rules/tests/scrim.rules.test.yaml", encoding="utf-8"))
firing, quiet = set(), set()
for t in tests["tests"]:
    for e in t.get("alert_rule_test", []):
        (firing if e.get("exp_alerts") else quiet).add(e["alertname"])
for name in alerts:
    if name not in firing:
        errors.append(f"{name}: no test case where it fires")
    if name not in quiet:
        errors.append(f"{name}: no test case where it stays quiet")

# Metric names used in PromQL.
KEYWORDS = {
    "sum", "min", "max", "avg", "count", "stddev", "stdvar", "topk", "bottomk", "quantile",
    "count_values", "group", "by", "without", "on", "ignoring", "group_left", "group_right",
    "and", "or", "unless", "bool", "offset", "inf", "nan", "le",
}
ALLOWED = ("scrim_", "go_", "process_")

def metric_names(expr):
    expr = re.sub(r'"(?:[^"\\]|\\.)*"', '""', expr)   # string literals
    expr = re.sub(r"\{[^}]*\}", "{}", expr)            # label matchers
    expr = re.sub(r"\[[^\]]*\]", "[]", expr)           # range selectors
    expr = re.sub(r"\$\{?\w+\}?", "", expr)            # dashboard variables
    expr = re.sub(r"\b(by|without|on|ignoring|group_left|group_right)\s*\([^)]*\)", "", expr)
    names = set()
    for m in re.finditer(r"(?<![\w.])([A-Za-z_:][\w:]*)\s*(\()?", expr):
        word, call = m.group(1), m.group(2)
        if call or word.lower() in KEYWORDS or re.fullmatch(r"\d+[smhdwy]", word):
            continue
        names.add(word)
    return names

def check_expr(where, expr):
    if not expr or not expr.strip():
        errors.append(f"{where}: empty expression")
        return
    for name in metric_names(expr):
        if name != "up" and not name.startswith(ALLOWED):
            errors.append(f"{where}: metric {name} is not scrim_*, up, go_* or process_*")

for group in plain["groups"]:
    for rule in group["rules"]:
        check_expr(f"rule {rule.get('alert') or rule.get('record')}", rule["expr"])

# Dashboard.
raw = open(f"{mon}/grafana/scrim-dashboard.json", encoding="utf-8").read()
dash = json.loads(raw)
if dash.get("uid") != "scrim-overview" or dash.get("title") != "scrim":
    errors.append("dashboard uid must be scrim-overview and title scrim")
if dash.get("schemaVersion", 0) < 39:
    errors.append("dashboard schemaVersion must be 39 or newer")
if "scrim" not in dash.get("tags", []):
    errors.append("dashboard must be tagged scrim")
variables = {v["name"]: v for v in dash.get("templating", {}).get("list", [])}
for v in ("datasource", "job", "instance"):
    if v not in variables:
        errors.append(f"dashboard is missing the {v} variable")
for v in variables.values():
    if v.get("type") == "query":
        q = v.get("query")
        q = q.get("query") if isinstance(q, dict) else q
        m = re.fullmatch(r"\s*label_values\((.*),\s*\w+\s*\)\s*", q or "")
        check_expr(f"variable {v['name']}", m.group(1) if m else q)

def walk(panels):
    for p in panels:
        yield p
        yield from walk(p.get("panels", []))

ids = []
for p in walk(dash.get("panels", [])):
    ids.append(p.get("id"))
    if p.get("type") == "row":
        continue
    where = f"panel {p.get('id')} {p.get('title')!r}"
    if p.get("datasource", {}).get("uid") != "${datasource}":
        errors.append(f"{where}: datasource must be ${{datasource}}")
    targets = p.get("targets", [])
    if not targets:
        errors.append(f"{where}: no targets")
    for t in targets:
        check_expr(where, t.get("expr", ""))
if None in ids or len(ids) != len(set(ids)):
    errors.append("dashboard panel ids must be present and unique")

# ConfigMap embeds the dashboard byte for byte.
cm = yaml.safe_load(open(f"{mon}/grafana/scrim-dashboard.configmap.yaml", encoding="utf-8"))
if cm.get("kind") != "ConfigMap" or cm.get("metadata", {}).get("name") != "scrim-grafana-dashboard":
    errors.append("ConfigMap must be named scrim-grafana-dashboard")
if cm.get("metadata", {}).get("labels", {}).get("grafana_dashboard") != "1":
    errors.append('ConfigMap must carry the label grafana_dashboard: "1"')
if cm.get("data", {}).get("scrim-dashboard.json") != raw:
    errors.append("ConfigMap does not embed grafana/scrim-dashboard.json; run with --generate")

if errors:
    for e in errors:
        print("error:", e, file=sys.stderr)
    sys.exit(1)
panels = sum(1 for p in walk(dash["panels"]) if p.get("type") != "row")
print(f"ok: {len(alerts)} alerts, {panels} panels")
PY

echo "monitoring assets OK"
