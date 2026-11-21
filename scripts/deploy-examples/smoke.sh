#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# scripts/deploy-examples/smoke.sh [TOOLS_DIR]
#
# Runs the container examples for real with rootless podman, the way
# docs/deploy shows them, and checks each one the way the docs tell a user to:
# readiness, `scrim status`, `scrim doctor`, and a canary request whose
# capture holds the placeholder and not the value. The canary goes to
# api.anthropic.com with an invalid key, so it needs network access but no
# account; Anthropic answers 401.
#
#   podman run    deploy/examples/podman/run.sh
#   kube play     deploy/examples/podman/kube/scrim.yaml
#   compose       deploy/examples/podman/compose/compose.yaml (podman-compose)
#   Deployment    deploy/examples/kubernetes/raw/ ConfigMap and Deployment,
#                 through `podman kube play`
#
# Each runs the scrim image of this tree in place of the release tag the
# example names: SCRIM_EXAMPLES_IMAGE, or one image.sh builds and removes.
# Everything is named scrim-examples-* and removed on exit, volumes and
# secrets included. Ports 9790 to 9792 on 127.0.0.1 must be free.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
while IFS='=' read -r key value; do
  case "$key" in '' | '#'*) continue ;; esac
  if [ -z "${!key+x}" ]; then export "$key=$value"; fi
done <"$here/tools.env"
tools=$(cd "${1:-$root/.tools/deploy-examples}" && pwd)
export PATH="$tools/bin:$tools/venv/bin:$PATH"
ex=$root/deploy/examples
work=$(mktemp -d)
canary=example-$(openssl rand -hex 12)
built=""

cleanup() {
  podman ps -aq --filter name=scrim-examples- | xargs -r podman rm -f -v >/dev/null 2>&1 || true
  podman pod ps -q --filter name=scrim-examples- | xargs -r podman pod rm -f >/dev/null 2>&1 || true
  podman volume ls -q --filter name=scrim-examples- | xargs -r podman volume rm -f >/dev/null 2>&1 || true
  podman secret ls --format '{{.Name}}' | grep '^scrim-examples-' | xargs -r podman secret rm >/dev/null 2>&1 || true
  podman network ls --format '{{.Name}}' | grep '^scrim-examples-' | xargs -r podman network rm -f >/dev/null 2>&1 || true
  rm -rf "$work"
  [ -z "$built" ] || podman rmi -f "$built" >/dev/null 2>&1 || true
}
trap cleanup EXIT
if [ -n "${SCRIM_EXAMPLES_IMAGE:-}" ]; then
  image=$SCRIM_EXAMPLES_IMAGE
else
  image=$("$here/image.sh")
  built=$image
fi
# The examples' own image line, pointed at that image.
use_image="s#image: ghcr.io/heliopsy/scrim:.*#image: $image#"

# wait_ready CONTAINER
wait_ready() {
  for _ in $(seq 60); do
    curl -fsS http://127.0.0.1:9792/readyz >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "scrim did not become ready; last log lines of $1:" >&2
  podman logs --tail 20 "$1" >&2 || true
  return 1
}

# check CONTAINER: status, doctor, and the canary request through the base URL.
check() {
  local c=$1 code
  wait_ready "$c"
  podman exec "$c" scrim status >"$work/status.txt"
  grep -q 'redaction  *active' "$work/status.txt"
  grep -Eq 'snapshot [0-9]+, 1 values' "$work/status.txt"
  podman exec "$c" scrim doctor
  code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9790/anthropic/v1/messages \
    -H 'x-api-key: not-a-real-key' -H 'anthropic-version: 2023-06-01' -H 'content-type: application/json' \
    -d "{\"model\":\"claude-sonnet-4-5\",\"max_tokens\":16,\"messages\":[{\"role\":\"user\",\"content\":\"canary $canary\"}]}")
  [ "$code" = 401 ] || { echo "canary request: HTTP $code, want 401 from Anthropic" >&2; return 1; }
}

# capture CONTAINER: copy the capture directory out and look for the canary.
capture() {
  local c=$1
  rm -rf "$work/capture"
  podman cp "$c:/var/lib/scrim/capture" "$work/capture"
  if grep -rqF "$canary" "$work/capture"; then
    echo "the canary value reached the provider" >&2
    return 1
  fi
  grep -rq '⟦scrim:github:' "$work/capture"/*.request.body
  echo "capture: placeholder present, value absent"
}

echo "== podman run (run.sh, capture on)"
printf '%s' "$canary" | podman secret create scrim-examples-gh - >/dev/null
(
  cd "$ex/podman"
  NAME=scrim-examples-run VOLUME=scrim-examples-state SECRET=scrim-examples-gh IMAGE=$image ./run.sh >/dev/null
)
podman rm -f scrim-examples-run >/dev/null
# The same container again with capture mode on, as the verify section shows.
(
  cd "$ex/podman"
  # shellcheck disable=SC2016 # the sed program matches the script's literal "$IMAGE"
  sed 's#"$IMAGE" proxy#-e SCRIM_PROXY_CAPTURE_DIR=/var/lib/scrim/capture "$IMAGE" proxy#' run.sh >"$work/run-capture.sh"
  NAME=scrim-examples-run VOLUME=scrim-examples-state SECRET=scrim-examples-gh IMAGE=$image bash "$work/run-capture.sh" >/dev/null
)
check scrim-examples-run
capture scrim-examples-run
for _ in $(seq 30); do
  [ "$(podman inspect -f '{{.State.Health.Status}}' scrim-examples-run)" = healthy ] && break
  podman healthcheck run scrim-examples-run >/dev/null 2>&1 || true
  sleep 1
done
[ "$(podman inspect -f '{{.State.Health.Status}}' scrim-examples-run)" = healthy ]
podman rm -f -v scrim-examples-run >/dev/null

echo "== podman kube play"
sed -e 's/name: scrim-agent-secrets/name: scrim-examples-kube-secrets/' \
  -e "s/UkVQTEFDRS1NRQ==/$(printf '%s' "$canary" | base64 -w0)/" \
  "$ex/podman/kube/secret.example.yaml" | podman kube play - >/dev/null
sed -e 's/^  name: scrim$/  name: scrim-examples-kube/' \
  -e 's/secretName: scrim-agent-secrets/secretName: scrim-examples-kube-secrets/' \
  -e 's/claimName: scrim-state/claimName: scrim-examples-kube-state/' \
  -e 's/name: scrim-config/name: scrim-examples-kube-config/' -e "$use_image" \
  "$ex/podman/kube/scrim.yaml" >"$work/kube.yaml"
podman kube play "$work/kube.yaml" >/dev/null
check scrim-examples-kube-scrim
podman kube down --force "$work/kube.yaml" >/dev/null

echo "== compose"
(
  cd "$ex/podman/compose"
  sed -e 's/^name: scrim$/name: scrim-examples-compose/' -e 's/container_name: scrim$/container_name: scrim-examples-compose/' \
    -e "$use_image" compose.yaml >"$work/compose.yaml"
  cp config.yaml "$work/config.yaml"
  cd "$work"
  SCRIM_SECRET_GITHUB_TOKEN=$canary podman-compose -f compose.yaml up -d >/dev/null 2>&1
)
check scrim-examples-compose
(cd "$work" && SCRIM_SECRET_GITHUB_TOKEN=x podman-compose -f compose.yaml down -v >/dev/null 2>&1)

echo "== Kubernetes raw Deployment through podman kube play"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$work/tls.key" -out "$work/tls.crt" -days 2 -subj "/CN=smoke" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" 2>/dev/null
cat >"$work/secrets.yaml" <<EOF
apiVersion: v1
kind: Secret
metadata: {name: scrim-examples-agent}
data:
  github-token: $(printf '%s' "$canary" | base64 -w0)
---
apiVersion: v1
kind: Secret
metadata: {name: scrim-examples-keys}
data:
  placeholder-k1: $(openssl rand -hex 32 | tr -d '\n' | base64 -w0)
  approvals-signing-key: $(openssl rand -hex 32 | tr -d '\n' | base64 -w0)
---
apiVersion: v1
kind: Secret
metadata: {name: scrim-examples-ca}
type: kubernetes.io/tls
data:
  tls.crt: $(base64 -w0 "$work/tls.crt")
  tls.key: $(base64 -w0 "$work/tls.key")
EOF
podman kube play "$work/secrets.yaml" >/dev/null
# podman mounts Secret files as root, so the pod reads them through mode 0444
# here; in a cluster fsGroup gives scrim's group 0440.
{
  cat "$ex/kubernetes/raw/20-configmap.yaml"
  echo '---'
  cat "$ex/kubernetes/raw/30-deployment.yaml"
} | sed -e 's/namespace: scrim$//' -e 's/name: scrim-config/name: scrim-examples-raw-config/' \
  -e 's/secretName: scrim-agent-secrets/secretName: scrim-examples-agent/' \
  -e 's/secretName: scrim-keys/secretName: scrim-examples-keys/' \
  -e 's/secretName: scrim-ca/secretName: scrim-examples-ca/' \
  -e 's/defaultMode: 0440/defaultMode: 0444/' -e "$use_image" \
  -e 's/^  name: scrim$/  name: scrim-examples-raw/' >"$work/raw.yaml"
podman kube play --publish 127.0.0.1:9790:9790 --publish 127.0.0.1:9792:9792 "$work/raw.yaml" >/dev/null
check scrim-examples-raw-pod-scrim
podman exec scrim-examples-raw-pod-scrim scrim ca export | openssl x509 -noout -subject | grep -q 'CN *= *smoke'
podman kube down --force "$work/raw.yaml" >/dev/null

echo
echo "container examples ran and redacted"
