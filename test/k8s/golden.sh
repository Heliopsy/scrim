#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Golden tests of the Helm chart: `helm lint`, then `helm template` of every
# values file in golden/cases compared with golden/out, and every file in
# golden/fail must be refused with the message on its `# expect:` line.
# Generated material (the CA, the placeholder key) is masked before comparing.
#
#   test/k8s/golden.sh            compare
#   test/k8s/golden.sh --update   rewrite golden/out
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
  sed -E 's/^(  (tls\.crt|tls\.key|k1): ).*/\1<generated>/' |
    awk '/-----BEGIN /{print; skip=1; next} /-----END /{skip=0} !skip{print}'
}

helm lint "$chart" --strict >/dev/null
helm lint "$chart" --strict -f "$dir/cases/metrics-on.yaml" >/dev/null

status=0

# Every documented value (a key after a `# --` comment in values.yaml) is in
# the README's table.
while read -r key; do
  grep -qF "| \`$key\` |" "$chart/README.md" || { echo "golden: $key is not in deploy/helm/scrim/README.md" >&2; status=1; }
done < <(awk '
  /^ *# -- / {doc = 1; next}
  /^ *#/ {next}
  /^ *[A-Za-z0-9_]+:/ {
    match($0, /^ */); depth = RLENGTH / 2
    key = $1; sub(/:.*/, "", key)
    path[depth] = key
    if (doc) { p = path[0]; for (i = 1; i <= depth; i++) p = p "." path[i]; print p }
    doc = 0; next
  }
  {doc = 0}
' "$chart/values.yaml")

mkdir -p "$dir/out"
for values in "$dir"/cases/*.yaml; do
  case="$(basename "$values" .yaml)"
  helm template scrim "$chart" -n scrim -f "$values" | mask > "$tmp/$case.yaml"
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
[ "$status" = 0 ] && echo "golden: $(ls "$dir"/cases/*.yaml | wc -l) cases, $(ls "$dir"/fail/*.yaml | wc -l) refusals ok"
exit "$status"
