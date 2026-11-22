#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# kubectl with certificate authentication through the tool proxy against a
# throwaway kind cluster on rootless podman (task 10a.4): the e2e_kube test of
# scrim-toolproxy. A private kubeconfig, so no other cluster is touched; the
# cluster is deleted at the end. Needs kind, kubectl and podman.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cluster="${CLUSTER:-scrim-e2e-toolproxy}"
# The kind node image of deploy/helm/scrim/ci/kind-test.sh.
node="${KIND_NODE_IMAGE:-docker.io/kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5}"
out="$(mktemp -d "${TMPDIR:-/tmp}/scrim-e2e-kube.XXXXXX")"
chmod 700 "$out"
kubeconfig="$out/kubeconfig"

for t in kind kubectl podman cargo; do
  command -v "$t" >/dev/null || { echo "$t is not on PATH" >&2; exit 1; }
done
cleanup() {
  KIND_EXPERIMENTAL_PROVIDER=podman kind delete cluster --name "$cluster" --kubeconfig "$kubeconfig" >/dev/null 2>&1 || true
  rm -rf "$out"
}
trap cleanup EXIT

# Clients do not send loopback addresses through a proxy: the agent's
# kubeconfig names kind-api.scrim.test, which the API server certificate must
# carry.
cat >"$out/cluster.yaml" <<'YAML'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  apiServerAddress: 127.0.0.1
kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      certSANs:
        - kind-api.scrim.test
YAML
KIND_EXPERIMENTAL_PROVIDER=podman kind create cluster --name "$cluster" --image "$node" \
  --config "$out/cluster.yaml" --kubeconfig "$kubeconfig" --wait 120s
kubectl --kubeconfig "$kubeconfig" --context "kind-$cluster" get nodes

cd "$root/dataplane"
SCRIM_E2E_KUBECONFIG="$kubeconfig" SCRIM_E2E_KUBE_CONTEXT="kind-$cluster" \
SCRIM_E2E_KUBECTL="$(command -v kubectl)" \
  cargo test --locked -p scrim-toolproxy --test e2e_kube -- --ignored --nocapture
