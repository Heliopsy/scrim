#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Static upgrade check: render the previous release's chart and the working
# tree with the same values and fail on changes `helm upgrade` cannot apply
# (selectors, StatefulSet serviceName and volumeClaimTemplates, PVC specs,
# headless Services, non-hook Job templates). check-upgrade.py has the list.
#
# The previous chart is, in order:
#   PREV_CHART  a chart reference helm can read: a .tgz, a directory, or an
#               oci:// reference (with PREV_VERSION; needs `helm registry login`)
#   PREV_REF    a git ref whose deploy/helm/scrim is used (default: the newest
#               vX.Y.Z tag on origin)
# With neither, no release tag yet, or a newest tag that predates the chart,
# the check is skipped. Ported from toc-helm-chart-template.
#
# Cases: the defaults, every example as the previous release shipped it, and
# ci/install-values.yaml. Both charts are stamped with distinct versions
# first, as a real release changes the helm.sh/chart and version labels.
# Needs helm, git, python3 with PyYAML. No cluster.
set -euo pipefail

CHART="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(cd "$CHART/../../.." && pwd)"
NAME="$(sed -n 's/^name: *//p' "$CHART/Chart.yaml")"
REL_PATH="deploy/helm/$(basename "$CHART")"
OUT="${OUT:-$(mktemp -d)}/upgrade"
RELEASE=ci
NS=ci

step() { printf '\n==> %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
stamp() {
  sed -i -e "s/^version:.*/version: $2/" "$1/Chart.yaml"
}

cd "$ROOT"
rm -rf "$OUT" && mkdir -p "$OUT/prev"

prev_examples=""
if [[ -n "${PREV_CHART:-}" ]]; then
  if [[ "$PREV_CHART" == oci://* ]]; then
    helm pull "$PREV_CHART" ${PREV_VERSION:+--version "$PREV_VERSION"} --untar -d "$OUT/prev" >/dev/null
    PREV="$OUT/prev/$NAME"
  elif [[ -f "$PREV_CHART" ]]; then
    tar -xzf "$PREV_CHART" -C "$OUT/prev"
    PREV="$OUT/prev/$NAME"
  else
    PREV="$PREV_CHART"
  fi
  label="$PREV_CHART${PREV_VERSION:+ $PREV_VERSION}"
else
  REF="${PREV_REF:-}"
  if [[ -z "$REF" ]]; then
    # ls-remote, not `git tag`: CI checkouts are shallow and carry no tags.
    REF="$(git ls-remote --tags --refs origin 'v*' 2>/dev/null | sed 's#.*refs/tags/##' \
      | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n1 || true)"
  fi
  if [[ -z "$REF" ]]; then
    echo "no vX.Y.Z release tag yet: nothing to upgrade from, skipped"
    exit 0
  fi
  if ! git rev-parse -q --verify "$REF^{commit}" >/dev/null; then
    git fetch -q --depth 1 origin "refs/tags/$REF:refs/tags/$REF" || fail "cannot fetch $REF"
  fi
  if ! git cat-file -e "$REF:$REL_PATH/Chart.yaml" 2>/dev/null; then
    echo "$REF has no $REL_PATH (the chart came later): nothing to upgrade from, skipped"
    exit 0
  fi
  git archive "$REF" "$REL_PATH" | tar -x -C "$OUT/prev"
  PREV="$OUT/prev/$REL_PATH"
  label="$REF"
  prev_examples="$PREV/examples"
  [[ "$REF" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)$ ]] && stamp "$PREV" "${BASH_REMATCH[1]}"
fi
NEXT="$OUT/next/$NAME"
mkdir -p "$OUT/next" && cp -r "$CHART" "$NEXT"
stamp "$NEXT" "${NEXT_VERSION:-99.0.0-upgrade-check}"
step "previous chart: $label, next: ${NEXT_VERSION:-99.0.0-upgrade-check}"

cases=("defaults:")
if [[ -n "$prev_examples" && -d "$prev_examples" ]]; then
  for f in "$prev_examples"/*.yaml; do [[ -f "$f" ]] && cases+=("$(basename "$f" .yaml):$f"); done
fi
cases+=("install-values:$CHART/ci/install-values.yaml")

rc=0
for c in "${cases[@]}"; do
  name="${c%%:*}"
  file="${c#*:}"
  args=()
  [[ -n "$file" ]] && args=(-f "$file")
  step "$name"
  if ! helm template "$RELEASE" "$PREV" -n "$NS" "${args[@]}" > "$OUT/$name.old.yaml" 2> "$OUT/$name.old.err"; then
    echo "previous chart does not render these values, skipped: $(tail -n1 "$OUT/$name.old.err")"
    continue
  fi
  helm template "$RELEASE" "$NEXT" -n "$NS" "${args[@]}" > "$OUT/$name.new.yaml" \
    || fail "$name: the working tree does not render values the previous release accepted"
  python3 "$CHART/ci/check-upgrade.py" "$OUT/$name.old.yaml" "$OUT/$name.new.yaml" || rc=1
done

[[ $rc -eq 0 ]] || fail "immutable fields change on upgrade from $label (renders in $OUT)"
printf '\nupgrade check green against %s\n' "$label"
