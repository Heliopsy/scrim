#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Golden tests of the Helm chart, run by deploy/helm/scrim/ci/verify.sh:
# `helm template` of every values file in golden/cases compared with golden/out, and every file in
# golden/fail must be refused with the message on its `# expect:` line.
# Generated material (the CA, the placeholder key) is masked before comparing.
# Every scrim configuration a case renders is checked with `scrim config
# validate` (unresolvable file: references aside, since the mounts do not
# exist here), the chart's monitoring copies must equal deploy/monitoring, and
# the scrim-exec launcher is run with sh against a fake token.
#
#   test/k8s/golden.sh            compare
#   test/k8s/golden.sh --update   rewrite golden/out
#
# SCRIM_BIN names a scrim binary to validate with; otherwise one is built with go.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
chart="$root/deploy/helm/scrim"
dir="$root/test/k8s/golden"
update=0
[ "${1:-}" = --update ] && update=1

# Helm keeps nothing in your home.
tmp="$(mktemp -d "${TMPDIR:-/tmp}/scrim-golden.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
export HELM_CONFIG_HOME="$tmp/config" HELM_CACHE_HOME="$tmp/cache" HELM_DATA_HOME="$tmp/data"

mask() {
  # Base64 Secret data of generated keys, and the body of every PEM block.
  sed -E 's/^(  (tls\.crt|tls\.key|k1|token): ).*/\1<generated>/' |
    awk '/-----BEGIN /{print; skip=1; next} /-----END /{skip=0} !skip{print}'
}

status=0

# The chart cannot read files outside itself, so it carries copies of the
# monitoring assets; they must not drift.
for pair in "rules/scrim.rules.yaml:scrim.rules.yaml" "grafana/scrim-dashboard.json:scrim-dashboard.json"; do
  src="$root/deploy/monitoring/${pair%%:*}" dst="$chart/monitoring/${pair##*:}"
  if [ "$update" = 1 ]; then
    cp "$src" "$dst"
  elif ! cmp -s "$src" "$dst"; then
    echo "golden: $dst differs from $src (test/k8s/golden.sh --update copies it)" >&2
    status=1
  fi
done

scrim="${SCRIM_BIN:-}"
if [ -z "$scrim" ]; then
  scrim="$tmp/scrim"
  (cd "$root" && CGO_ENABLED=0 go build -o "$scrim" .)
fi

# Writes the block scalars config.yaml and chart.yaml of every ConfigMap that
# has a chart.yaml into $2/<n>-config.yaml and $2/<n>-chart.yaml.
split_configs() {
  awk -v out="$2" '
    function flush() { if (has_chart) { n++; print (user == "" ? "apiVersion: scrim.dev/v1\nkind: Config\n" : user) > (out "/" n "-config.yaml"); print chart > (out "/" n "-chart.yaml"); close(out "/" n "-config.yaml"); close(out "/" n "-chart.yaml") } user = ""; chart = ""; has_chart = 0; cur = "" }
    /^---/ { flush(); next }
    /^  (config|chart)\.yaml: \|/ { cur = ($0 ~ /chart/) ? "chart" : "user"; if (cur == "chart") has_chart = 1; next }
    cur != "" && /^    / { line = substr($0, 5); if (cur == "chart") chart = chart line "\n"; else user = user line "\n"; next }
    cur != "" && /^$/ { if (cur == "chart") chart = chart "\n"; else user = user "\n"; next }
    { cur = "" }
    END { flush() }
  ' "$1"
}

# scrim config validate, minus references to files that only exist in a pod.
validate_configs() {
  local case="$1" cfgdir="$tmp/cfg-$1" f out
  mkdir -p "$cfgdir" "$tmp/home"
  split_configs "$tmp/$case.raw" "$cfgdir"
  for f in "$cfgdir"/*-chart.yaml; do
    [ -e "$f" ] || continue
    out="$(env -i PATH="$PATH" HOME="$tmp/home" SCRIM_CONFIG="${f%-chart.yaml}-config.yaml:$f" "$scrim" config validate 2>&1)" || true
    if grep '^error:' <<<"$out" | grep -v 'reference file:[^ ]*: no such file or directory' | grep -q .; then
      echo "golden: $case: scrim refuses the configuration the chart renders:" >&2
      grep '^error:' <<<"$out" | grep -v 'reference file:[^ ]*: no such file or directory' >&2
      status=1
    fi
  done
}

mkdir -p "$dir/out"
for values in "$dir"/cases/*.yaml; do
  case="$(basename "$values" .yaml)"
  helm template scrim "$chart" -n scrim -f "$values" > "$tmp/$case.raw"
  mask < "$tmp/$case.raw" > "$tmp/$case.yaml"
  validate_configs "$case"
  if [ "$update" = 1 ]; then
    cp "$tmp/$case.yaml" "$dir/out/$case.yaml"
  elif ! diff -u "$dir/out/$case.yaml" "$tmp/$case.yaml"; then
    echo "golden: $case differs (test/k8s/golden.sh --update after checking the diff)" >&2
    status=1
  fi
done
for values in "$dir"/fail/*.yaml; do
  case="$(basename "$values" .yaml)"
  want="$(sed -n 's/^# expect: //p' "$values")"
  if out="$(helm template scrim "$chart" -n scrim -f "$values" 2>&1)"; then
    echo "golden: fail/$case rendered, want an error containing: $want" >&2
    status=1
  elif ! grep -qF "$want" <<<"$out"; then
    echo "golden: fail/$case: got $out, want: $want" >&2
    status=1
  fi
done

# The scrim-exec launcher: the token goes into the proxy variables as the
# password of the proxy user k8s and into x-scrim-session, replacing any
# session header of the agent's own and keeping its other headers.
awk '/^  scrim-exec: \|/ {on = 1; next} on && /^    / {print substr($0, 5); next} on && /^$/ {print ""; next} on {exit}' \
  "$tmp/identity.raw" > "$tmp/scrim-exec"
printf 'fake.token-%s' "$$" > "$tmp/token"
out="$(env -i PATH="$PATH" SCRIM_K8S_TOKEN_FILE="$tmp/token" HTTPS_PROXY=http://scrim.scrim.svc:9791 \
  http_proxy=http://127.0.0.1:9791 HTTP_PROXY=http://user:pw@other:1 \
  ANTHROPIC_CUSTOM_HEADERS="$(printf 'x-team: a b\nX-Scrim-Session: stale')" sh "$tmp/scrim-exec" env)"
tok="fake.token-$$"
for want in "HTTPS_PROXY=http://k8s:$tok@scrim.scrim.svc:9791" "http_proxy=http://k8s:$tok@127.0.0.1:9791" \
  "HTTP_PROXY=http://user:pw@other:1" "GIT_HTTP_PROXY_AUTHMETHOD=basic" "ANTHROPIC_CUSTOM_HEADERS=x-team: a b" \
  "x-scrim-session: $tok"; do
  grep -qxF "$want" <<<"$out" || { echo "golden: scrim-exec: no line $want in its environment" >&2; status=1; }
done
if grep -q stale <<<"$out"; then
  echo "golden: scrim-exec kept the agent's own session header" >&2; status=1
fi
if env -i PATH="$PATH" SCRIM_K8S_TOKEN_FILE="$tmp/missing" sh "$tmp/scrim-exec" true 2>/dev/null; then
  echo "golden: scrim-exec ran without a token" >&2; status=1
fi

[ "$status" = 0 ] && echo "golden: $(ls "$dir"/cases/*.yaml | wc -l) cases, $(ls "$dir"/fail/*.yaml | wc -l) refusals ok"
exit "$status"
