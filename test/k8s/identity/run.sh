#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Kubernetes identity test in kind on rootless podman (tasks 12.1, 12.2, 12.2c, 12.4).
#
#   test/k8s/identity/run.sh
#
# Builds scrim and the test helper into local images, creates the kind cluster
# scrim-k8sid, and checks:
#
#   - scrim logs in to OpenBao with its own projected service account token
#     (Kubernetes auth): the cluster holds no static store credential;
#   - two agent pods with different service accounts are identified by their
#     projected scrim-audience tokens and get different outcomes, from scrim's
#     rules and from the OpenBao role bound to each service account
#     (passthrough);
#   - a pod's default API token (wrong audience) is refused;
#   - two scrim replicas share one PostgreSQL: both serve, both audit there,
#     and break-glass engaged on one replica applies on the other;
#   - no agent token or credential appears in scrim's logs.
#
# Everything it creates is removed on exit (KEEP=1 keeps the cluster for
# debugging). Nothing outside the kind cluster is touched: kind and kubectl
# use a kubeconfig in the work directory, never ~/.kube/config, and every
# kubectl call names --context kind-scrim-k8sid.
#
# Environment:
#   KIND                 kind binary (default: kind)
#   SCRIM_DATAPLANE_BIN  scrim-dataplane to put in the image (default: build a debug one)
#   SCRIM_BASE_IMAGE     base of the scrim image (default: the Containerfile's distroless base)
#   TOOLS_BASE_IMAGE     base of the helper image (default: docker.io/library/alpine:3.22)
#   OPENBAO_IMAGE, POSTGRES_IMAGE  images loaded into the cluster
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
name=scrim-k8sid
ctx=kind-$name
KIND=${KIND:-kind}
export KIND_EXPERIMENTAL_PROVIDER=podman
SCRIM_BASE_IMAGE=${SCRIM_BASE_IMAGE:-gcr.io/distroless/static-debian13:nonroot}
TOOLS_BASE_IMAGE=${TOOLS_BASE_IMAGE:-docker.io/library/alpine:3.22}
export OPENBAO_IMAGE=${OPENBAO_IMAGE:-quay.io/openbao/openbao:2.7.3}
export POSTGRES_IMAGE=${POSTGRES_IMAGE:-docker.io/library/postgres:18.6-alpine3.24}
export SCRIM_IMAGE=localhost/scrim-k8sid-scrim:test
export TOOLS_IMAGE=localhost/scrim-k8sid-tools:test

# WORKDIR holds build contexts and generated keys; podman itself keeps the
# default TMPDIR (its socket paths must stay short).
work=$(mktemp -d "${WORKDIR:-${TMPDIR:-/tmp}}/scrim-k8sid.XXXXXX")
fails=0
# kind and kubectl use a kubeconfig of their own, so the user's
# ~/.kube/config (and its current context) is never touched.
export KUBECONFIG=$work/kubeconfig

log() { printf '\n== %s\n' "$*"; }
ok() { printf '   ok    %s\n' "$*"; }
bad() { printf '   FAIL  %s\n' "$*"; fails=$((fails + 1)); }
k() { timeout 30 kubectl --context "$ctx" "$@"; }

cleanup() {
  set +e
  if [ "${KEEP:-0}" != 1 ]; then
    log "cleanup"
    "$KIND" delete cluster --name "$name" --kubeconfig "$KUBECONFIG" >/dev/null 2>&1
    podman rmi -f "$SCRIM_IMAGE" "$TOOLS_IMAGE" >/dev/null 2>&1
    rm -rf "$work"
  else
    echo "kept: cluster $name, KUBECONFIG=$KUBECONFIG"
  fi
}
trap cleanup EXIT

free_gb() { df -Pk "$root" | awk 'NR==2 {print int($4 / 1048576)}'; }
if [ "$(free_gb)" -lt 6 ]; then
  echo "less than 6 GB free; not starting" >&2
  exit 1
fi
for tool in podman kubectl openssl envsubst "$KIND"; do
  command -v "$tool" >/dev/null || { echo "$tool not found" >&2; exit 1; }
done

log "build"
mkdir -p "$work/scrim" "$work/tools"
(cd "$root" && CGO_ENABLED=0 go build -trimpath -o "$work/scrim/scrim" . &&
  CGO_ENABLED=0 go build -trimpath -o "$work/tools/k8sid" ./test/k8s/identity/k8sid)
dp=${SCRIM_DATAPLANE_BIN:-}
if [ -z "$dp" ]; then
  (cd "$root/dataplane" && cargo build --locked -p scrim-dataplane)
  dp=${CARGO_TARGET_DIR:-$root/dataplane/target}/debug/scrim-dataplane
fi
install -m 0755 "$dp" "$work/scrim/scrim-dataplane"
strip "$work/scrim/scrim-dataplane" 2>/dev/null || true
# A glibc data plane (a local build) gets its libraries next to it; the
# release build is static musl and needs none.
libs=""
if ldd "$work/scrim/scrim-dataplane" >/dev/null 2>&1; then
  mkdir -p "$work/scrim/lib"
  for l in $(ldd "$work/scrim/scrim-dataplane" | awk '/=> \// {print $3} /^\t\/lib/ {print $1}'); do
    cp -L "$l" "$work/scrim/lib/"
  done
  libs='COPY lib/ld-linux-x86-64.so.2 /lib64/ld-linux-x86-64.so.2
COPY lib/ /lib/x86_64-linux-gnu/'
fi
cat >"$work/scrim/Containerfile" <<EOF
FROM $SCRIM_BASE_IMAGE
$libs
COPY scrim /usr/local/bin/scrim
COPY scrim-dataplane /usr/local/bin/scrim-dataplane
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/scrim"]
EOF
cat >"$work/tools/Containerfile" <<EOF
FROM $TOOLS_BASE_IMAGE
COPY k8sid /usr/local/bin/k8sid
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/k8sid"]
EOF
podman build -q -t "$SCRIM_IMAGE" "$work/scrim" >/dev/null
podman build -q -t "$TOOLS_IMAGE" "$work/tools" >/dev/null
rm -f "$work/scrim/scrim" "$work/scrim/scrim-dataplane" "$work/tools/k8sid"
rm -rf "$work/scrim/lib"
ok "images $SCRIM_IMAGE $TOOLS_IMAGE"

log "kind cluster $name (rootless podman)"
systemd-run --scope --user --quiet -p Delegate=yes "$KIND" create cluster --name "$name" --kubeconfig "$KUBECONFIG" --wait 120s >/dev/null
[ "$(timeout 30 kubectl config get-contexts -o name | grep -cx "$ctx")" = 1 ] || { echo "no context $ctx" >&2; exit 1; }
echo "   context $ctx"
for img in "$SCRIM_IMAGE" "$TOOLS_IMAGE" "$OPENBAO_IMAGE" "$POSTGRES_IMAGE"; do
  podman image exists "$img" || podman pull -q "$img" >/dev/null
  podman save -q -o "$work/img.tar" "$img"
  "$KIND" load image-archive "$work/img.tar" --name "$name" >/dev/null
  rm -f "$work/img.tar"
done
# The node holds its own copies now.
podman rmi -f "$SCRIM_IMAGE" "$TOOLS_IMAGE" >/dev/null 2>&1 || true
ok "images loaded"

log "generated material"
rnd() { openssl rand -hex "$1"; }
root_token=root-$(rnd 16)
pg_password=$(rnd 16)
key_a=sk-a-$(rnd 16)
key_b=sk-b-$(rnd 16)
pki=$work/pki
mkdir -p "$pki"
# scrim's tool-proxy CA, shared by both replicas.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$pki/scrim-ca.key" 2>/dev/null
openssl req -x509 -new -key "$pki/scrim-ca.key" -subj "/CN=scrim-k8sid test CA" -days 2 \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign -out "$pki/scrim-ca.crt" 2>/dev/null
# The fake tool API's CA and certificate.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$pki/api-ca.key" 2>/dev/null
openssl req -x509 -new -key "$pki/api-ca.key" -subj "/CN=fakeapi CA" -days 2 \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign -out "$pki/api-ca.crt" 2>/dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$pki/api.key" 2>/dev/null
openssl req -new -key "$pki/api.key" -subj "/CN=fakeapi.agents.svc" -out "$pki/api.csr" 2>/dev/null
printf 'subjectAltName=DNS:fakeapi.agents.svc\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' >"$pki/ext"
openssl x509 -req -in "$pki/api.csr" -CA "$pki/api-ca.crt" -CAkey "$pki/api-ca.key" -CAcreateserial -days 2 \
  -extfile "$pki/ext" -out "$pki/api.crt" 2>/dev/null
openssl rand 32 >"$pki/k1"

log "deploy"
# Namespaces first, then the secrets the manifests reference.
envsubst <"$here/manifests.yaml" | k apply -f - --dry-run=client -o name >/dev/null
k create namespace scrim >/dev/null
k create namespace agents >/dev/null
k -n scrim create secret generic openbao-root --from-literal=token="$root_token" >/dev/null
k -n scrim create secret generic postgres --from-literal=password="$pg_password" \
  --from-literal=dsn="postgres://scrim:$pg_password@postgres.scrim.svc:5432/scrim?sslmode=disable" >/dev/null
k -n scrim create secret generic scrim-ca --from-file=ca.crt="$pki/scrim-ca.crt" --from-file=ca.key="$pki/scrim-ca.key" >/dev/null
k -n scrim create secret generic scrim-keys --from-file=k1="$pki/k1" >/dev/null
k -n scrim create configmap fakeapi-ca --from-file=ca.crt="$pki/api-ca.crt" >/dev/null
k -n agents create configmap scrim-ca-public --from-file=ca.crt="$pki/scrim-ca.crt" >/dev/null
k -n agents create secret tls fakeapi-tls --cert="$pki/api.crt" --key="$pki/api.key" >/dev/null
k -n agents create secret generic fakeapi-keys --from-literal=a="$key_a" --from-literal=b="$key_b" >/dev/null
rm -f "$pki"/*.key
# Everything but scrim, which needs OpenBao configured first.
envsubst <"$here/manifests.yaml" >"$work/all.yaml"
k apply -f "$work/all.yaml" >/dev/null
k -n scrim scale deployment scrim --replicas=0 >/dev/null
timeout 200 kubectl --context "$ctx" -n scrim wait --for=condition=Ready pod/openbao pod/postgres --timeout=180s >/dev/null

log "OpenBao: Kubernetes auth, policies, roles, secrets"
bao() { k -n scrim exec openbao -- env BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN="$root_token" bao "$@"; }
for _ in $(seq 30); do bao status >/dev/null 2>&1 && break; sleep 1; done
bao secrets enable -path=kv kv-v2 >/dev/null
bao auth enable kubernetes >/dev/null
bao write auth/kubernetes/config kubernetes_host=https://kubernetes.default.svc >/dev/null
printf 'path "kv/data/agents/*" { capabilities = ["read"] }\npath "kv/metadata/agents" { capabilities = ["list"] }\npath "kv/metadata/agents/*" { capabilities = ["read", "list"] }\npath "kv/detailed-metadata/agents/*" { capabilities = ["list"] }\n' |
  k -n scrim exec -i openbao -- env BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN="$root_token" bao policy write scrim - >/dev/null
for a in a b; do
  printf 'path "kv/data/agents/%s/*" { capabilities = ["read"] }\n' "$a" |
    k -n scrim exec -i openbao -- env BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN="$root_token" bao policy write "agent-$a" - >/dev/null
  bao write "auth/kubernetes/role/agents-agent-$a" bound_service_account_names="agent-$a" \
    bound_service_account_namespaces=agents audience=scrim token_policies="agent-$a" token_ttl=10m >/dev/null
done
bao write auth/kubernetes/role/scrim bound_service_account_names=scrim bound_service_account_namespaces=scrim \
  audience=openbao token_policies=scrim token_ttl=20m >/dev/null
bao kv put -mount=kv agents/a/token value="$key_a" >/dev/null
bao kv put -mount=kv agents/b/token value="$key_b" >/dev/null
ok "configured"

log "scrim: two replicas"
k -n scrim scale deployment scrim --replicas=2 >/dev/null
if ! timeout 200 kubectl --context "$ctx" -n scrim rollout status deployment/scrim --timeout=180s >/dev/null; then
  k -n scrim get pods -o wide || true
  for p in $(k -n scrim get pods -l app=scrim -o name); do k -n scrim logs "$p" --tail=40 || true; done
  exit 1
fi
mapfile -t scrims < <(k -n scrim get pods -l app=scrim -o jsonpath='{range .items[*]}{.metadata.name}={.status.podIP}{"\n"}{end}')
[ "${#scrims[@]}" = 2 ] || { echo "want 2 scrim pods, have ${#scrims[@]}" >&2; exit 1; }
ok "${scrims[*]}"

# No static store credential: the scrim namespace holds only the PostgreSQL
# DSN, the tool-proxy CA, the placeholder key and OpenBao's dev root token
# (used by this script only, never mounted into scrim).
mounted=$(k -n scrim get deployment scrim -o jsonpath='{.spec.template.spec.volumes[*].secret.secretName} {.spec.template.spec.containers[*].env[*].valueFrom.secretKeyRef.name}')
case " $mounted " in
  *openbao-root*) bad "scrim mounts the OpenBao root token" ;;
  *) ok "scrim mounts no store credential (secrets: $mounted)" ;;
esac

agent() { # agent POD SCRIM_IP METHOD PLACEHOLDER [TOKEN_FILE]
  local env="PROXY_HOST=$2:3128"
  [ -n "${5:-}" ] && env="$env TOKEN_FILE=$5"
  k -n agents exec "$1" -- env $env k8sid agent "$3" https://fakeapi.agents.svc/v1/thing "$4"
}
expect() { # expect DESCRIPTION WANT_STATUS WANT_BODY_SUBSTRING GOT
  local got=$4
  if [[ $got == "status=$2 "* && $got == *"$3"* ]]; then ok "$1: $got"; else bad "$1: want status=$2 ~$3, got $got"; fi
}

log "identity and policy per service account, through each replica"
# The pods run without probes: wait until each data plane answers and its
# first store load is done (a refused injection before that is a 503).
for s in "${scrims[@]}"; do
  for _ in $(seq 60); do
    got=$(agent agent-a "${s#*=}" GET SCRIM_A_KEY 2>/dev/null || true)
    [[ $got == "status=0 "* || $got == "status=503 "* || -z $got ]] || break
    sleep 1
  done
done
for s in "${scrims[@]}"; do
  ip=${s#*=}
  pod=${s%%=*}
  expect "[$pod] agent-a GET with key-a (scrim allows, role agents-agent-a allows)" 200 "body=a" "$(agent agent-a "$ip" GET SCRIM_A_KEY)"
  expect "[$pod] agent-b GET with key-b" 200 "body=b" "$(agent agent-b "$ip" GET SCRIM_B_KEY)"
  expect "[$pod] agent-b GET with key-a (OpenBao role agents-agent-b refuses)" 403 "policy_denied" "$(agent agent-b "$ip" GET SCRIM_A_KEY)"
  expect "[$pod] agent-a GET with key-b (OpenBao role agents-agent-a refuses)" 403 "policy_denied" "$(agent agent-a "$ip" GET SCRIM_B_KEY)"
  expect "[$pod] agent-a POST with key-a (scrim rule no-post-for-agent-a)" 403 "agent-a may not POST" "$(agent agent-a "$ip" POST SCRIM_A_KEY)"
  expect "[$pod] agent-b POST with key-b" 200 "body=b" "$(agent agent-b "$ip" POST SCRIM_B_KEY)"
  expect "[$pod] agent-a with its default API token (wrong audience)" 403 "policy_denied" \
    "$(agent agent-a "$ip" GET SCRIM_A_KEY /var/run/secrets/kubernetes.io/serviceaccount/token)"
done

log "break-glass across replicas"
a_pod=${scrims[0]%%=*}
b_ip=${scrims[1]#*=}
k -n scrim exec "$a_pod" -- scrim deny-all on --reason "k8sid test" >/dev/null
deadline=$((SECONDS + 10))
got=""
while [ $SECONDS -lt $deadline ]; do
  got=$(agent agent-b "$b_ip" GET SCRIM_B_KEY)
  [[ $got == "status=403 "* ]] && break
  sleep 0.5
done
expect "engaged on ${a_pod}, refused on the other replica" 403 "" "$got"
k -n scrim exec "$a_pod" -- scrim deny-all off --reason "k8sid test" >/dev/null
deadline=$((SECONDS + 10))
while [ $SECONDS -lt $deadline ]; do
  got=$(agent agent-b "$b_ip" GET SCRIM_B_KEY)
  [[ $got == "status=200 "* ]] && break
  sleep 0.5
done
expect "released on ${a_pod}, allowed again on the other replica" 200 "body=b" "$got"

log "shared audit in PostgreSQL"
psql() { k -n scrim exec postgres -- psql -U scrim -d scrim -tA -c "$1"; }
n=$(psql "SELECT count(*) FROM audit_log WHERE action = 'decision' AND attrs LIKE '%\"caller\":\"kubernetes\"%'")
# 6 identified requests per replica, plus the warm-up and break-glass ones.
[ "$n" -ge 12 ] && ok "$n decisions by Kubernetes callers" || bad "only $n decisions by Kubernetes callers"
n=$(psql "SELECT count(*) FROM audit_log WHERE action = 'decision' AND attrs LIKE '%\"store_identity\":\"kubernetes\"%'")
[ "$n" -ge 1 ] && ok "$n decisions checked with the agent's own OpenBao identity" || bad "no decision used the agent's store identity"
n=$(psql "SELECT count(*) FROM audit_log WHERE action = 'decision' AND attrs LIKE '%\"caller\":\"refused\"%'")
[ "$n" -ge 2 ] && ok "$n refused tokens audited" || bad "refused tokens not audited ($n)"
n=$(psql "SELECT count(DISTINCT subject) FROM audit_log WHERE action = 'config.reloaded'")
echo "   config digests reported: $n"

log "no token or credential in scrim's logs"
tok_a=$(k -n agents exec agent-a -- cat /var/run/secrets/tokens/scrim)
tok_b=$(k -n agents exec agent-b -- cat /var/run/secrets/tokens/scrim)
logs=$(for s in "${scrims[@]}"; do k -n scrim logs "${s%%=*}"; done)
leaked=0
for v in "$tok_a" "$tok_b" "$key_a" "$key_b" "$root_token" "$pg_password"; do
  if [[ $logs == *"${v: -24}"* ]]; then leaked=1; fi
done
[ $leaked = 0 ] && ok "$(wc -l <<<"$logs") log lines checked" || bad "a token or credential is in scrim's logs"
fake=$(k -n agents logs fakeapi)
[[ $fake != *SCRIM_* ]] && ok "the fake API never received a placeholder" || bad "a placeholder reached the fake API"

log "result"
if [ $fails -gt 0 ]; then
  echo "$fails check(s) failed"
  exit 1
fi
echo "all checks passed"
