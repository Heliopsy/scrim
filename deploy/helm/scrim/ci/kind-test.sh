#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Live chart test on a throwaway kind cluster, ported from
# toc-helm-chart-template. Runs in CI (the chart-kind job of
# .github/workflows/ci.yaml, a GitHub-hosted runner). test/k8s/e2e.sh is the
# full end-to-end test on rootless podman for a workstation.
#
#   1. ct install: install ci/install-values.yaml and
#      ci/install-issuer-values.yaml, each into a fresh namespace with the
#      scrim image built from this commit, wait for every pod, run `helm test`
#      (the listeners, and the issuer's discovery and JWKS, answer through
#      their Services), uninstall
#   2. upgrade (once a release tag has the chart): install that release's
#      chart, `helm upgrade` to the working tree with the same values and
#      image, `helm test` again. Helm refuses an upgrade that changes an
#      immutable field, so a green upgrade proves those too.
#
# SCRIM_IMAGE (required) is a local image reference, SCRIM_IMAGE_ARCHIVE an
# OCI or docker archive of it that kind loads. KIND_PROVIDER picks kind's node
# runtime (podman by default; CI sets docker, the runtime GitHub's runners
# start kind on). A private kubeconfig, so no other cluster is ever touched.
# Knobs: CLUSTER, KIND_NODE_IMAGE, KEEP_CLUSTER=1, SKIP_INSTALL=1,
# SKIP_UPGRADE=1, PREV_REF.
set -euo pipefail

CHART="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(cd "$CHART/../../.." && pwd)"
NAME="$(sed -n 's/^name: *//p' "$CHART/Chart.yaml")"
REL_PATH="deploy/helm/$(basename "$CHART")"
CLUSTER="${CLUSTER:-scrim-chart-tests}"
CTX="kind-$CLUSTER"
# kind v0.33.0's node image for the Kubernetes minor verify.sh validates against
# (kind publishes one node image per minor with each release).
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-docker.io/kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5}"
KIND_PROVIDER="${KIND_PROVIDER:-podman}"
OUT="${OUT:-$(mktemp -d)}/kind"
: "${SCRIM_IMAGE:?set SCRIM_IMAGE to the image to test (repository:tag)}"
: "${SCRIM_IMAGE_ARCHIVE:?set SCRIM_IMAGE_ARCHIVE to an archive of it}"

step() { printf '\n==> %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
kind_() { env KIND_EXPERIMENTAL_PROVIDER="$KIND_PROVIDER" kind "$@"; }

for t in kind ct helm kubectl "$KIND_PROVIDER" git; do
  command -v "$t" >/dev/null || fail "$t is not on PATH"
done
cd "$ROOT"
mkdir -p "$OUT"
chmod 700 "$OUT"
export KUBECONFIG="$OUT/kubeconfig"

cleanup() {
  local rc=$?
  if [[ "${KEEP_CLUSTER:-}" == 1 ]]; then
    echo "cluster $CLUSTER kept (KUBECONFIG=$KUBECONFIG)"
  else
    kind_ delete cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG" >/dev/null 2>&1 || true
  fi
  exit $rc
}
trap cleanup EXIT

step "kind cluster $CLUSTER ($KIND_NODE_IMAGE)"
kind_ create cluster --name "$CLUSTER" --image "$KIND_NODE_IMAGE" --kubeconfig "$KUBECONFIG" --wait 120s
# ct has no context flag: the private kubeconfig holds this one cluster only.
kubectl config use-context "$CTX" >/dev/null
kubectl --context "$CTX" get nodes -o wide
kind_ load image-archive "$SCRIM_IMAGE_ARCHIVE" --name "$CLUSTER"

repo="${SCRIM_IMAGE%:*}"
tag="${SCRIM_IMAGE##*:}"
registry="${repo%%/*}"
repository="${repo#*/}"
image_args=(--set "image.registry=$registry" --set "image.repository=$repository" --set "image.tag=$tag"
  --set image.pullPolicy=Never)

if [[ "${SKIP_INSTALL:-}" != 1 ]]; then
  step "ct install"
  # ct installs every ci/*-values.yaml; the others are render-only cases
  # (CRDs, stores, Secrets assumed), so ct runs on a copy of the chart that
  # keeps the install*-values.yaml cases alone.
  rm -rf "$OUT/ct" && mkdir -p "$OUT/ct/charts"
  cp -r "$CHART" "$OUT/ct/charts/$NAME"
  find "$OUT/ct/charts/$NAME/ci" -name '*-values.yaml' ! -name 'install*-values.yaml' -delete
  ( cd "$OUT/ct" && ct install --config "$CHART/ci/ct.yaml" --charts "charts/$NAME" \
      --helm-extra-set-args "${image_args[*]}" )
fi

if [[ "${SKIP_UPGRADE:-}" != 1 ]]; then
  REF="${PREV_REF:-$(git ls-remote --tags --refs origin 'v*' 2>/dev/null | sed 's#.*refs/tags/##' \
    | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n1 || true)}"
  [[ -z "$REF" ]] || git rev-parse -q --verify "$REF^{commit}" >/dev/null \
    || git fetch -q --depth 1 origin "refs/tags/$REF:refs/tags/$REF" || true
  if [[ -z "$REF" ]] || ! git cat-file -e "$REF:$REL_PATH/Chart.yaml" 2>/dev/null; then
    step "upgrade skipped: no release tag has the chart yet"
  else
    NS=scrim-chart-upgrade
    REL=upgrade
    H=(helm --kube-context "$CTX")
    K=(kubectl --context "$CTX")
    vals=(-f "$CHART/ci/install-values.yaml" "${image_args[@]}")
    mkdir -p "$OUT/prev"
    git archive "$REF" "$REL_PATH" | tar -x -C "$OUT/prev"
    PREV="$OUT/prev/$REL_PATH"
    step "upgrade: install $REF"
    "${H[@]}" install "$REL" "$PREV" -n "$NS" --create-namespace "${vals[@]}" --wait --timeout 10m
    step "upgrade: helm upgrade to the working tree"
    "${H[@]}" upgrade "$REL" "$CHART" -n "$NS" "${vals[@]}" --wait --timeout 10m
    "${H[@]}" test "$REL" -n "$NS" --timeout 5m
    "${H[@]}" uninstall "$REL" -n "$NS" --wait --timeout 5m
    "${K[@]}" delete namespace "$NS" --wait --timeout 3m
    echo "upgrade from $REF: no immutable-field error, helm test green"
  fi
fi

printf '\nkind chart tests green\n'
