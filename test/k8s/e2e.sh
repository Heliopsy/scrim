#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Kubernetes end-to-end test of the Helm chart (tasks.md 12.3), in a kind
# cluster on rootless podman with Calico enforcing NetworkPolicy, Kyverno
# injecting agent pods, OpenBao in dev mode as the store and the fake model
# provider as the upstream. For a central agent pod and a sidecar agent pod
# it asserts that:
#
#   - the provider sees placeholders only, never the secret the agent sent;
#   - the agent pod cannot reach the provider or the tool host directly;
#   - an agent process started through scrim-exec is identified by its
#     projected service account token (TokenReview), the credential is
#     injected toward its bound host by the built-in rule, and the agent gets
#     the placeholder back, not the value;
#   - the same request without scrim-exec is an unknown caller and gets no
#     injection;
#   - scrim logs in to OpenBao with its own service account token (no static
#     store credential), and the agent's token reaches neither the provider
#     nor scrim's logs;
#   - a placeholder sent toward an unbound host is refused and nothing
#     reaches that host;
#   - no secret value appears in scrim's logs;
#   - Kyverno refuses a labelled pod in a namespace the chart did not prepare.
#
# It never touches another cluster or your kubeconfig: the cluster's
# kubeconfig lives in a temporary directory and every command names it.
# Everything it creates (cluster, images, network, archives) is removed at
# the end unless SCRIM_K8S_KEEP=1.
#
# Environment:
#   SCRIM_K8S_CLUSTER          cluster name (default scrim-k8s-e2e)
#   SCRIM_K8S_KEEP=1           keep the cluster and images for debugging
#   SCRIM_K8S_REUSE=1          reuse a running cluster of that name (implies a
#                              cluster you created with this script)
#   SCRIM_K8S_DATAPLANE_IMAGE  image to take the data plane from when
#                              internal/dataplane/embedded/scrim-dataplane is
#                              missing (default the release's scrim-dataplane)
#   SCRIM_K8S_MIN_FREE_GB      refuse to start below this much free disk (6)
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
here="$root/test/k8s"
name="${SCRIM_K8S_CLUSTER:-scrim-k8s-e2e}"
ctx="kind-$name"
# A tag per run, so a reused cluster rolls the new images out.
tag="e2e-$(date +%s)"
img_scrim="localhost/scrim-k8s-scrim:$tag"
img_testbin="localhost/scrim-k8s-testbin:$tag"
img_tools="localhost/scrim-k8s-tools:$tag"
dp_image="${SCRIM_K8S_DATAPLANE_IMAGE:-ghcr.io/heliopsy/scrim-dataplane:0.1.0}"
calico_version="v3.30.3"
calico_sha256="9382d2b27a76f40c170454b408653e6d71e2205ef0aef069e942bb690e7381d0"
kyverno_chart_version="3.5.2"
openbao_image="quay.io/openbao/openbao:2.4.1@sha256:597f62847dd382382056a1d6704d50465908c2040038c4611832a23269a67112"
embed="$root/internal/dataplane/embedded/scrim-dataplane"

export KIND_EXPERIMENTAL_PROVIDER=podman

work="$(mktemp -d "${TMPDIR:-/tmp}/scrim-k8s.XXXXXX")"
kubeconfig="$work/kubeconfig"
# Helm keeps its repositories and caches here, not in your home.
export HELM_CONFIG_HOME="$work/helm/config" HELM_CACHE_HOME="$work/helm/cache" HELM_DATA_HOME="$work/helm/data"
export HELM_REPOSITORY_CONFIG="$HELM_CONFIG_HOME/repositories.yaml" HELM_REPOSITORY_CACHE="$HELM_CACHE_HOME/repository"

created_embed=0
created_network=0
failed=1

log() { printf '== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'ok   %s\n' "$*"; }

k() { timeout 30 kubectl --kubeconfig "$kubeconfig" --context "$ctx" "$@"; }
kwait() { local t="$1"; shift; timeout "$t" kubectl --kubeconfig "$kubeconfig" --context "$ctx" "$@"; }
hl() { timeout 300 helm --kubeconfig "$kubeconfig" --kube-context "$ctx" "$@"; }

cleanup() {
  local rc=$?
  set +e
  if [ "$failed" = 1 ] && [ -s "$kubeconfig" ]; then
    log "diagnostics"
    k get pods -A -o wide
    k -n scrim logs deploy/scrim --tail=60 2>/dev/null
    k -n agents logs agent-sidecar -c scrim --tail=60 2>/dev/null
    k get events -A --sort-by=.lastTimestamp 2>/dev/null | tail -30
  fi
  if [ "${SCRIM_K8S_KEEP:-0}" = 1 ]; then
    log "kept cluster $name (kubeconfig $kubeconfig) and images; delete with: KIND_EXPERIMENTAL_PROVIDER=podman kind delete cluster --name $name"
  else
    log "cleanup"
    kind delete cluster --name "$name" --kubeconfig "$kubeconfig" >/dev/null 2>&1
    podman rmi -f "$img_scrim" "$img_testbin" "$img_tools" >/dev/null 2>&1
    if [ "$created_network" = 1 ]; then podman network rm kind >/dev/null 2>&1; fi
    rm -rf "$work"
  fi
  if [ "$created_embed" = 1 ]; then rm -f "$embed"; fi
  exit "$rc"
}
trap cleanup EXIT

for tool in kind kubectl helm podman openssl go jq curl; do
  command -v "$tool" >/dev/null || fail "$tool is not installed"
done
free_kb="$(df -Pk "$HOME" | awk 'NR==2 {print $4}')"
if [ "$free_kb" -lt $(( ${SCRIM_K8S_MIN_FREE_GB:-6} * 1024 * 1024 )) ]; then
  fail "less than ${SCRIM_K8S_MIN_FREE_GB:-6} GB free under $HOME"
fi
if [ "$(podman info --format '{{.Host.Security.Rootless}}')" != true ]; then
  fail "podman is not rootless; this test only runs on rootless podman"
fi

# ---------------------------------------------------------------- images

log "build images"
if [ ! -s "$embed" ]; then
  # The data plane of a release is byte-identical to the one embedded in its
  # scrim binary (deployment spec), so the published image can stand in for a
  # local `cargo build --release` as long as the boundary protocol matches.
  cid="$(podman create --name "scrim-k8s-dp-$$" "$dp_image")"
  podman cp "$cid:/usr/local/bin/scrim-dataplane" "$embed"
  podman rm -f "$cid" >/dev/null
  created_embed=1
fi
mkdir -p "$work/stage/linux-amd64" "$work/stage/state" "$work/testbin"
(cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -tags embed_dataplane \
  -ldflags "-s -w -X github.com/heliopsy/scrim/internal/version.Version=0.0.0-k8s-e2e" \
  -o "$work/stage/linux-amd64/scrim" .)
(cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$work/testbin/scrim-fakeprovider" ./internal/testing/fakeprovider/cmd/scrim-fakeprovider)
(cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$work/testbin/toolhost" ./test/k8s/toolhost)
# The release image recipe, from the binary just built.
podman build -q --platform linux/amd64 -f "$root/Containerfile" -t "$img_scrim" "$work/stage" >/dev/null
podman build -q --platform linux/amd64 -f "$here/Containerfile.testbin" -t "$img_testbin" "$work/testbin" >/dev/null
podman build -q --platform linux/amd64 -f "$here/Containerfile.tools" -t "$img_tools" "$here" >/dev/null

# ---------------------------------------------------------------- cluster

if [ "${SCRIM_K8S_REUSE:-0}" = 1 ] && kind get clusters 2>/dev/null | grep -qx "$name"; then
  log "reuse cluster $name"
  kind get kubeconfig --name "$name" > "$kubeconfig"
else
  log "create cluster $name (rootless podman)"
  podman network exists kind || created_network=1
  kind create cluster --name "$name" --config "$here/kind.yaml" --kubeconfig "$kubeconfig" --wait 0s
  curl -fsSL -o "$work/calico.yaml" "https://raw.githubusercontent.com/projectcalico/calico/$calico_version/manifests/calico.yaml"
  echo "$calico_sha256  $work/calico.yaml" | sha256sum -c --quiet -
  k apply -f "$work/calico.yaml" >/dev/null
  kwait 400 -n kube-system rollout status ds/calico-node --timeout=380s
  kwait 300 -n kube-system rollout status deploy/coredns --timeout=280s
  log "install Kyverno"
  hl install kyverno kyverno --repo https://kyverno.github.io/kyverno/ --version "$kyverno_chart_version" \
    -n kyverno --create-namespace --set reportsController.enabled=false --set cleanupController.enabled=false \
    --wait --timeout 280s >/dev/null
fi
chmod 0600 "$kubeconfig"

log "load images"
for i in "$img_scrim" "$img_testbin" "$img_tools"; do
  podman save -q -o "$work/image.tar" "$i"
  kind load image-archive "$work/image.tar" --name "$name" >/dev/null
  rm -f "$work/image.tar"
done

# ---------------------------------------------------------------- fixtures

log "fixtures"
for ns in scrim scrim-e2e agents; do
  k create namespace "$ns" --dry-run=client -o yaml | k apply -f - >/dev/null
done

# Values generated now, never written to the repository.
bao_token="e2e-root-$(openssl rand -hex 16)"
tool_token="ghp_e2e$(openssl rand -hex 18)"
llm_secret="sk-e2e-$(openssl rand -hex 20)"

# Tool host TLS: a test CA scrim trusts through upstreamCA, and a leaf for the
# bound name and for a second, unbound name of the same server.
(
  cd "$work"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout testca.key -out testca.pem \
    -days 1 -subj /CN=scrim-k8s-e2e-test-ca 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout toolhost.key -out toolhost.csr \
    -subj /CN=toolhost 2>/dev/null
  printf 'subjectAltName=DNS:toolhost.scrim-e2e.svc.cluster.local,DNS:unbound.scrim-e2e.svc.cluster.local\n' > ext
  openssl x509 -req -in toolhost.csr -CA testca.pem -CAkey testca.key -CAcreateserial -out toolhost.crt \
    -days 1 -extfile ext 2>/dev/null
)
k -n scrim-e2e create secret tls toolhost-tls --cert="$work/toolhost.crt" --key="$work/toolhost.key" \
  --dry-run=client -o yaml | k apply -f - >/dev/null
for ns in scrim agents; do
  k -n "$ns" create configmap e2e-upstream-ca --from-file=ca.crt="$work/testca.pem" \
    --dry-run=client -o yaml | k apply -f - >/dev/null
done
# The root token exists only in the store's own namespace, for the setup below.
printf %s "$bao_token" > "$work/bao-token"
k -n scrim-e2e create secret generic openbao-root --from-file=token="$work/bao-token" \
  --dry-run=client -o yaml | k apply -f - >/dev/null
rm -f "$work/bao-token"

sed -e "s|@TESTBIN@|$img_testbin|g" -e "s|@OPENBAO@|$openbao_image|g" "$here/fixtures.yaml" | k apply -f - >/dev/null
# A reused cluster keeps the previous run's pods, which hold the previous root token.
k -n scrim-e2e rollout restart deploy/openbao deploy/fakeprovider deploy/toolhost >/dev/null
kwait 300 -n scrim-e2e rollout status deploy/openbao --timeout=280s
kwait 120 -n scrim-e2e rollout status deploy/fakeprovider --timeout=100s
kwait 120 -n scrim-e2e rollout status deploy/toolhost --timeout=100s

# Kubernetes auth: scrim (central) and the sidecars (the agents' default
# service account) log in with a projected token for the audience openbao.
# The dev server starts empty on every rollout, so nothing here exists yet.
bao_sh() { k -n scrim-e2e exec -i deploy/openbao -- sh -c "export BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=\"\$(cat /run/secrets/bao/token)\"; $1"; }
bao_sh 'bao auth enable kubernetes' >/dev/null
bao_sh 'bao write auth/kubernetes/config kubernetes_host=https://kubernetes.default.svc' >/dev/null
printf 'path "secret/data/e2e/*" { capabilities = ["read"] }\npath "secret/metadata/e2e" { capabilities = ["list"] }\npath "secret/metadata/e2e/*" { capabilities = ["read", "list"] }\npath "secret/detailed-metadata/e2e/*" { capabilities = ["list"] }\n' |
  bao_sh 'bao policy write scrim-e2e -' >/dev/null
bao_sh 'bao write auth/kubernetes/role/scrim bound_service_account_names=scrim,default bound_service_account_namespaces=scrim,agents audience=openbao token_policies=scrim-e2e token_ttl=20m' >/dev/null

# Values go in on stdin (`field=-`), not on a command line.
printf %s "$tool_token" | k -n scrim-e2e exec -i deploy/openbao -- sh -c \
  'BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN="$(cat /run/secrets/bao/token)" bao kv put -mount=secret e2e/tool token=-' >/dev/null
printf %s "$llm_secret" | k -n scrim-e2e exec -i deploy/openbao -- sh -c \
  'BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN="$(cat /run/secrets/bao/token)" bao kv put -mount=secret e2e/llm value=-' >/dev/null

# ---------------------------------------------------------------- chart

log "install the chart"
hl upgrade --install scrim "$root/deploy/helm/scrim" -n scrim -f "$here/values-e2e.yaml" \
  --set image.repository="${img_scrim%:*}" --set image.tag="$tag" \
  --set sidecar.egressGuard.image="$img_tools" \
  --set 'agents.namespaces={agents}' --wait --timeout 240s >/dev/null
kwait 120 wait --for=condition=Ready clusterpolicy/scrim-scrim-inject --timeout=100s >/dev/null

log "agent pods"
k -n agents delete pod agent-central agent-sidecar --ignore-not-found --wait=true >/dev/null
for mode in central sidecar; do
  sed -e "s|@TOOLS@|$img_tools|g" -e "s|@MODE@|$mode|g" "$here/agent.yaml" | k -n agents apply -f - >/dev/null
done
kwait 240 -n agents wait --for=condition=Ready pod/agent-central pod/agent-sidecar --timeout=220s >/dev/null

# ---------------------------------------------------------------- checks

fake() { k get --raw "/api/v1/namespaces/scrim-e2e/services/http:fakeprovider:18089/proxy/_fake/$1"; }
received() { k get --raw "/api/v1/namespaces/scrim-e2e/services/http:toolhost-control:8080/proxy/_received"; }
in_agent() { local pod="$1"; shift; k -n agents exec "$pod" -c agent -- "$@"; }
# The same, identified to scrim by the pod's projected token.
as_agent() { local pod="$1"; shift; k -n agents exec "$pod" -c agent -- /etc/scrim/trust/scrim-exec "$@"; }
injected() {
  received | jq --arg h "toolhost.scrim-e2e.svc.cluster.local" --arg a "Bearer $tool_token" \
    'map(select((.host | split(":")[0]) == $h and .authorization == $a)) | length'
}
agent_tokens=()

for mode in central sidecar; do
  pod="agent-$mode"
  log "$mode: $pod"

  env_out="$(in_agent "$pod" printenv)"
  for v in ANTHROPIC_BASE_URL OPENAI_BASE_URL HTTPS_PROXY NO_PROXY NODE_EXTRA_CA_CERTS SSL_CERT_FILE \
    REQUESTS_CA_BUNDLE GIT_SSL_CAINFO CODEX_CA_CERTIFICATE SCRIM_K8S_TOKEN_FILE; do
    grep -q "^$v=" <<<"$env_out" || fail "$mode: $v is not set in the agent"
  done
  pass "$mode: injected environment"
  agent_tokens+=("$(in_agent "$pod" sh -c 'cat "$SCRIM_K8S_TOKEN_FILE"')")
  [ -n "${agent_tokens[-1]}" ] || fail "$mode: no projected token in the agent"
  # scrim-exec puts the token in the proxy URL and the session header.
  as_agent "$pod" sh -c 'case $HTTPS_PROXY in http://k8s:*@*) ;; *) exit 1 ;; esac; case $ANTHROPIC_CUSTOM_HEADERS in *x-scrim-session:*) ;; *) exit 1 ;; esac' \
    || fail "$mode: scrim-exec did not set the identity"

  # 1. The provider sees placeholders only.
  before="$(fake exchanges | jq 'length')"
  body="$(jq -cn --arg s "$llm_secret" '{model:"claude-sonnet-4-5",max_tokens:32,messages:[{role:"user",content:("the key is " + $s + ", deploy it")}]}')"
  # With the session header, which the base-URL listener strips.
  status="$(as_agent "$pod" sh -c 'curl -sS -o /dev/null -w "%{http_code}" "$ANTHROPIC_BASE_URL/v1/messages" \
    -H "$ANTHROPIC_CUSTOM_HEADERS" \
    -H "content-type: application/json" -H "anthropic-version: 2023-06-01" -H "x-api-key: agent-own-key" -d "$1"' _ "$body")"
  [ "$status" = 200 ] || fail "$mode: the base URL answered $status"
  ex="$(fake exchanges)"
  [ "$(jq 'length' <<<"$ex")" -gt "$before" ] || fail "$mode: the provider saw no request"
  # Bodies are base64 in the JSON; check them decoded too.
  if grep -qF "$llm_secret" <<<"$ex" || jq -r '.[].body | (try @base64d catch .)' <<<"$ex" | grep -qF "$llm_secret"; then
    fail "$mode: the provider received the secret"
  fi
  jq -e '.[-1].placeholders | length > 0' <<<"$ex" >/dev/null || fail "$mode: no placeholder in what the provider saw"
  if grep -qF "${agent_tokens[-1]}" <<<"$ex"; then fail "$mode: the provider received the agent's token"; fi
  pass "$mode: provider saw placeholders only"

  # The same through the forward proxy, toward the provider's own host name
  # would need DNS for api.anthropic.com; the base URL covers model traffic.

  # 2. No direct route to the provider or the tool host.
  if in_agent "$pod" curl -sS -m 5 --noproxy '*' -o /dev/null http://fakeprovider.scrim-e2e.svc.cluster.local:18089/_fake/health 2>/dev/null; then
    fail "$mode: the agent reached the provider directly"
  fi
  if in_agent "$pod" curl -sS -m 5 --noproxy '*' -o /dev/null http://toolhost-control.scrim-e2e.svc.cluster.local:8080/healthz 2>/dev/null; then
    fail "$mode: the agent reached the tool host directly"
  fi
  pass "$mode: direct egress blocked"

  # 3. Without scrim-exec the caller is unknown: no injection.
  before="$(injected)"
  reply="$(in_agent "$pod" curl -sS -m 20 -H 'Authorization: Bearer SCRIM_TOOL_TOKEN' https://toolhost.scrim-e2e.svc.cluster.local/api || true)"
  if grep -qF "$tool_token" <<<"$reply"; then fail "$mode: the agent got the value back"; fi
  [ "$(injected)" = "$before" ] || fail "$mode: an unidentified caller got the credential injected"
  pass "$mode: unidentified caller gets no injection"

  # 4. Identified: injection toward the bound host; the agent gets the placeholder back.
  reply="$(as_agent "$pod" curl -sS -m 20 -H 'Authorization: Bearer SCRIM_TOOL_TOKEN' https://toolhost.scrim-e2e.svc.cluster.local/api)"
  if grep -qF "$tool_token" <<<"$reply"; then fail "$mode: the agent got the injected value back"; fi
  grep -q 'SCRIM_TOOL_TOKEN\|scrim:' <<<"$reply" || fail "$mode: unexpected tool reply: $reply"
  [ "$(injected)" -gt "$before" ] || fail "$mode: the tool host did not receive the injected credential"
  pass "$mode: identified agent, credential injected toward the bound host"

  # 5. Refused toward an unbound host, and nothing reaches it.
  code="$(as_agent "$pod" curl -sS -m 20 -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer SCRIM_TOOL_TOKEN' \
    https://unbound.scrim-e2e.svc.cluster.local/api)"
  [ "$code" = 403 ] || fail "$mode: unbound host answered $code, want 403"
  got="$(received)"
  if jq -e 'map(select(.host | startswith("unbound."))) | length > 0' <<<"$got" >/dev/null; then
    fail "$mode: a request reached the unbound host"
  fi
  pass "$mode: refused toward an unbound host"
done

log "logs and admission"
logs="$(k -n scrim logs deploy/scrim --tail=-1; k -n agents logs agent-sidecar -c scrim --tail=-1)"
for v in "$llm_secret" "$tool_token" "$bao_token" "${agent_tokens[@]}"; do
  if grep -qF "$v" <<<"$logs"; then fail "a secret value or an agent token is in scrim's logs"; fi
done
pass "no secret value or agent token in scrim's logs"

k create namespace scrim-e2e-unprepared --dry-run=client -o yaml | k apply -f - >/dev/null
if sed -e "s|@TOOLS@|$img_tools|g" -e "s|@MODE@|central|g" "$here/agent.yaml" | k -n scrim-e2e-unprepared apply -f - >/dev/null 2>&1; then
  fail "Kyverno admitted a labelled pod in an unprepared namespace"
fi
pass "labelled pod refused outside the prepared namespaces"

failed=0
log "PASS"
