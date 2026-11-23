#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# End-to-end test of the edge forwarder (tasks.md 12.5) in a kind cluster:
# the Helm chart with a central scrim and edge.enabled, Kyverno injecting the
# forwarder into an agent pod, PostgreSQL and a throwaway sshd with a bare git
# repository as the outside world. From the agent pod it asserts that:
#
#   - Kyverno added the forwarder as a native sidecar, SSH_AUTH_SOCK and
#     SCRIM_API_SOCKET, and the agent (UID 1000) can use the sockets of the
#     forwarder (UID 65532);
#   - the agent cannot reach PostgreSQL itself (only the SSH session to the
#     git server is its own, networkPolicy.agentEgress);
#   - the forwarder's ssh-agent answers, and `git push` over SSH succeeds
#     with a key only the central scrim's store holds, signed centrally;
#   - a push as another user, whose signature no rule allows, fails and the
#     server keeps the first commit;
#   - `psql` through the forwarded port, with only the placeholder as the
#     password, logs in as scrim's database user and runs a query;
#   - an exec broker call through the agent API socket runs centrally with the
#     real value (its SHA-256 matches) and returns the value as a placeholder;
#   - with the central scrim scaled to zero every endpoint refuses, and works
#     again once it is back, without restarting the pod;
#   - no secret value is in the agent's output, the forwarder's logs or
#     scrim's logs, and the pod's filesystem holds no key.
#
# It never touches another cluster or your kubeconfig: the cluster's
# kubeconfig lives in a temporary directory and every command names it.
# Everything it creates (cluster, images, network, files) is removed at the end
# unless SCRIM_EDGE_KEEP=1.
#
# Environment:
#   SCRIM_EDGE_CLUSTER          cluster name (default scrim-edge-e2e)
#   SCRIM_EDGE_KEEP=1           keep the cluster and images for debugging
#   (internal/dataplane/embedded/scrim-dataplane is built with
#   scripts/release/dataplane.sh when it is missing, and removed again)
#   SCRIM_EDGE_MIN_FREE_GB      refuse to start below this much free disk (5)
#   KIND_EXPERIMENTAL_PROVIDER  podman (default) locally; CI sets docker
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
here="$root/test/k8s/edge"
name="${SCRIM_EDGE_CLUSTER:-scrim-edge-e2e}"
ctx="kind-$name"
tag="e2e-$(date +%s)"
img_base="localhost/scrim-edge-base:$tag"
img_scrim="localhost/scrim-edge-scrim:$tag"
img_tools="localhost/scrim-edge-tools:$tag"
postgres_image="docker.io/library/postgres:19.0-alpine3.24@sha256:8b0ff4cdf221f0c53d7fcda681d3b461be725c492cd881c5ec9c0ad25023f188"
# renovate: datasource=helm depName=kyverno registryUrl=https://kyverno.github.io/kyverno/
kyverno_chart_version="3.10.0"
embed="$root/internal/dataplane/embedded/scrim-dataplane"
export KIND_EXPERIMENTAL_PROVIDER="${KIND_EXPERIMENTAL_PROVIDER:-podman}"
# Images are always built with podman; kind's node runs on its provider.
node_engine="$KIND_EXPERIMENTAL_PROVIDER"

work="$(mktemp -d "${TMPDIR:-/tmp}/scrim-edge.XXXXXX")"
kubeconfig="$work/kubeconfig"
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
in_agent() { kwait 120 -n agents exec agent-edge -c agent -- "$@"; }

cleanup() {
  local rc=$?
  set +e
  if [ "$failed" = 1 ] && [ -s "$kubeconfig" ]; then
    log "diagnostics"
    k get pods -A -o wide
    k -n scrim logs deploy/scrim --tail=80 2>/dev/null
    k -n agents logs agent-edge -c scrim-edge --tail=40 2>/dev/null
    k -n agents describe pod agent-edge 2>/dev/null | tail -30
    k get events -A --sort-by=.lastTimestamp 2>/dev/null | tail -30
  fi
  if [ "${SCRIM_EDGE_KEEP:-0}" = 1 ]; then
    log "kept cluster $name (kubeconfig $kubeconfig); delete with: KIND_EXPERIMENTAL_PROVIDER=$KIND_EXPERIMENTAL_PROVIDER kind delete cluster --name $name"
  else
    log "cleanup"
    kind delete cluster --name "$name" --kubeconfig "$kubeconfig" >/dev/null 2>&1
    podman rmi -f "$img_scrim" "$img_base" "$img_tools" >/dev/null 2>&1
    if [ "$created_network" = 1 ]; then "$node_engine" network rm kind >/dev/null 2>&1; fi
    rm -rf "$work"
  fi
  if [ "$created_embed" = 1 ]; then rm -f "$embed"; fi
  exit "$rc"
}
trap cleanup EXIT

for tool in kind kubectl helm podman "$node_engine" go jq ssh-keygen openssl sha256sum; do
  command -v "$tool" >/dev/null || fail "$tool is not installed"
done
free_kb="$(df -Pk "$work" | awk 'NR==2 {print $4}')"
if [ "$free_kb" -lt $(( ${SCRIM_EDGE_MIN_FREE_GB:-5} * 1024 * 1024 )) ]; then
  fail "less than ${SCRIM_EDGE_MIN_FREE_GB:-5} GB free under $work"
fi
if [ "$node_engine" = podman ] && [ "$(podman info --format '{{.Host.Security.Rootless}}')" != true ]; then
  fail "podman is not rootless; this test only runs on rootless podman"
fi

# ---------------------------------------------------------------- images

log "build images"
if [ ! -s "$embed" ]; then
  # Built from this tree: the release's data plane may predate the snapshot
  # this control plane sends.
  command -v cargo >/dev/null || fail "$embed is missing and cargo is not installed to build it"
  "$root/scripts/release/dataplane.sh" linux-amd64 "$embed"
  created_embed=1
fi
mkdir -p "$work/stage/linux-amd64" "$work/stage/state" "$work/probe"
(cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -tags embed_dataplane \
  -ldflags "-s -w -X github.com/heliopsy/scrim/internal/version.Version=0.0.0-edge-e2e" \
  -o "$work/stage/linux-amd64/scrim" .)
(cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$work/probe/execprobe" ./test/k8s/edge/execprobe)
# The release image recipe, from the binary just built, plus the exec probe.
podman build -q --platform linux/amd64 -f "$root/Containerfile" -t "$img_base" "$work/stage" >/dev/null
podman build -q --platform linux/amd64 --build-arg "BASE=$img_base" -f "$here/Containerfile.scrim" -t "$img_scrim" "$work/probe" >/dev/null
podman build -q --platform linux/amd64 -f "$here/Containerfile.tools" -t "$img_tools" "$here" >/dev/null

# ---------------------------------------------------------------- cluster

log "create cluster $name ($KIND_EXPERIMENTAL_PROVIDER)"
"$node_engine" network inspect kind >/dev/null 2>&1 || created_network=1
# kindnet enforces NetworkPolicy from kind 0.24 on.
kind create cluster --name "$name" --kubeconfig "$kubeconfig" --wait 0s
chmod 0600 "$kubeconfig"
kwait 300 -n kube-system rollout status deploy/coredns --timeout=280s
log "install Kyverno (chart $kyverno_chart_version)"
hl install kyverno kyverno --repo https://kyverno.github.io/kyverno/ --version "$kyverno_chart_version" \
  -n kyverno --create-namespace --set reportsController.enabled=false --set cleanupController.enabled=false \
  --set backgroundController.enabled=false --wait --timeout 280s >/dev/null

log "load images"
for i in "$img_scrim" "$img_tools"; do
  podman save -q -o "$work/image.tar" "$i"
  kind load image-archive "$work/image.tar" --name "$name" >/dev/null
  rm -f "$work/image.tar"
done

# ---------------------------------------------------------------- fixtures

log "fixtures"
for ns in scrim scrim-edge-e2e agents; do
  k create namespace "$ns" --dry-run=client -o yaml | k apply -f - >/dev/null
done

# Generated now, never written to the repository. The user key exists only in
# the Secret the central scrim mounts; the agent pod never sees it.
db_password="pg-e2e-$(openssl rand -hex 16)"
ssh-keygen -q -t ed25519 -N '' -C scrim-edge-e2e -f "$work/user_key"
ssh-keygen -q -t ed25519 -N '' -C gitserver -f "$work/host_key"
user_key_body="$(sed -n '2p' "$work/user_key")"
printf 'gitserver %s\n' "$(cut -d' ' -f1-2 "$work/host_key.pub")" > "$work/scrim_known_hosts"
printf %s "$db_password" > "$work/db-password"
k -n scrim create secret generic edge-e2e --from-file=ssh-key="$work/user_key" \
  --from-file=db-password="$work/db-password" --from-file=known_hosts="$work/scrim_known_hosts" \
  --dry-run=client -o yaml | k apply -f - >/dev/null
k -n scrim-edge-e2e create secret generic postgres --from-file=password="$work/db-password" \
  --dry-run=client -o yaml | k apply -f - >/dev/null
k -n scrim-edge-e2e create secret generic gitserver --from-file=ssh_host_ed25519_key="$work/host_key" \
  --from-file=authorized_keys="$work/user_key.pub" --dry-run=client -o yaml | k apply -f - >/dev/null
rm -f "$work/user_key" "$work/db-password" "$work/host_key"

sed -e "s|@TOOLS@|$img_tools|g" -e "s|@POSTGRES@|$postgres_image|g" "$here/fixtures.yaml" | k apply -f - >/dev/null
kwait 300 -n scrim-edge-e2e rollout status deploy/postgres --timeout=280s
kwait 120 -n scrim-edge-e2e rollout status deploy/gitserver --timeout=100s

# ---------------------------------------------------------------- chart

log "install the chart"
values=(-f "$here/values.yaml")
have_exec=0
if grep -q '^    "exec": {' "$root/schema/config-v1.json"; then
  have_exec=1
  values+=(-f "$here/values-exec.yaml")
fi
hl upgrade --install scrim "$root/deploy/helm/scrim" -n scrim "${values[@]}" \
  --set image.registry=localhost --set image.repository="$(basename "${img_scrim%:*}")" --set image.tag="$tag" \
  --set 'agents.namespaces={agents}' --set tests.enabled=false --wait --timeout 240s >/dev/null
for p in validatingpolicy/scrim-scrim-require-prepared-namespace mutatingpolicy/scrim-scrim-inject-central; do
  kwait 120 wait --for=jsonpath='{.status.conditionStatus.ready}'=true "$p" --timeout=100s >/dev/null
done

log "agent pod"
sed -e "s|@TOOLS@|$img_tools|g" "$here/agent.yaml" | k -n agents apply -f - >/dev/null
# Ready means the forwarder's startup probe passed: the central scrim accepted the pod's token.
kwait 240 -n agents wait --for=condition=Ready pod/agent-edge --timeout=220s >/dev/null

# ---------------------------------------------------------------- checks

outputs=""
record() { outputs+="$1"$'\n'; }

log "injection"
pod_json="$(k -n agents get pod agent-edge -o json)"
jq -e '.spec.initContainers[] | select(.name == "scrim-edge" and .restartPolicy == "Always")' <<<"$pod_json" >/dev/null ||
  fail "no native scrim-edge sidecar in the agent pod"
if jq -e '.spec.initContainers[] | select(.name == "scrim-edge") | .volumeMounts[] | select(.name | test("ca$|keys|secret"))' \
  <<<"$pod_json" >/dev/null; then
  fail "the forwarder mounts a secret volume"
fi
env_out="$(in_agent printenv)"
grep -qx 'SSH_AUTH_SOCK=/run/scrim-edge/ssh-agent.sock' <<<"$env_out" || fail "SSH_AUTH_SOCK is not the forwarder's"
grep -qx 'SCRIM_API_SOCKET=/run/scrim-edge/api.sock' <<<"$env_out" || fail "SCRIM_API_SOCKET is not the forwarder's"
pass "forwarder injected as a native sidecar with SSH_AUTH_SOCK and SCRIM_API_SOCKET"

log "no direct route to the database"
if in_agent nc -z -w 5 postgres.scrim-edge-e2e.svc.cluster.local 5432 2>/dev/null; then
  fail "the agent reached PostgreSQL directly"
fi
pass "the agent pod cannot reach the database itself"

log "ssh-agent and git over SSH"
# Listing without a host binding (ssh-add sends none) offers no key: the rule
# names the host. The agent answers, though: "no identities", not an error.
ssh_add() { in_agent ssh-add -L 2>&1 || true; }
agent_answers() { grep -q 'The agent has no identities' <<<"$(ssh_add)"; }
agent_answers || fail "the forwarder's ssh-agent does not answer: $(ssh_add)"
pass "the forwarder's ssh-agent answers, and offers no key outside a host-bound login"

# The agent's own known_hosts names the server by its Service name; scrim's names it gitserver.
host_line="gitserver.scrim-edge-e2e.svc.cluster.local $(cut -d' ' -f1-2 "$work/host_key.pub")"
git_env='export GIT_SSH_COMMAND="ssh -F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/tmp/known_hosts"
export GIT_AUTHOR_NAME=e2e GIT_AUTHOR_EMAIL=e2e@scrim.test GIT_COMMITTER_NAME=e2e GIT_COMMITTER_EMAIL=e2e@scrim.test'
in_agent sh -c "printf '%s\n' \"\$1\" > /tmp/known_hosts" _ "$host_line"
out="$(in_agent sh -c "$git_env
set -e
rm -rf /tmp/work && git init -q -b main /tmp/work && cd /tmp/work
echo first > file.txt && git add file.txt && git commit -q -m first
git push -q ssh://git@gitserver.scrim-edge-e2e.svc.cluster.local/srv/repo.git main 2>&1")" ||
  fail "git push over SSH through the forwarder failed: $out"
record "$out"
server_log() { kwait 60 -n scrim-edge-e2e exec deploy/gitserver -- git --git-dir=/srv/repo.git log --format=%s main 2>/dev/null; }
[ "$(server_log)" = first ] || fail "the git server does not have the pushed commit"
pass "git push over SSH succeeds, signed by the central scrim"

if out="$(in_agent sh -c "$git_env
set -e
cd /tmp/work && echo second > file.txt && git commit -q -am second
git push -q ssh://git2@gitserver.scrim-edge-e2e.svc.cluster.local/srv/repo.git main 2>&1")"; then
  fail "a push whose signature policy denies went through"
fi
record "$out"
grep -q 'Permission denied' <<<"$out" || fail "the denied push failed for another reason: $out"
[ "$(server_log)" = first ] || fail "the git server changed after the denied push"
pass "a signature no rule allows fails the push"

log "database"
whoami="$(in_agent curl -sS --unix-socket /run/scrim-edge/api.sock http://scrim/v1/whoami)"
[ "$(jq -r '.agent + " " + .source' <<<"$whoami")" = "agents/default kubernetes" ] ||
  fail "the agent API through the forwarder answered: $whoami"
pass "the agent API through the forwarder knows the pod as agents/default"
# The catalog's declared placeholder: all the agent ever holds.
placeholder=SCRIM_DB_PASSWORD
out="$(in_agent env PGPASSWORD="$placeholder" psql -X -A -t -h 127.0.0.1 -p 5432 -U anything -d app \
  -c 'select current_user, 6 * 7' 2>&1)" || fail "psql through the forwarded port failed: $out"
record "$out"
[ "$out" = "app|42" ] || fail "psql through the forwarded port answered: $out"
pass "psql by placeholder through the forwarded port logs in as scrim's database user"

log "exec broker"
if [ "$have_exec" = 1 ]; then
want_sum="$(printf %s "$db_password" | sha256sum | cut -d' ' -f1)"
out="$(in_agent curl -sS --unix-socket /run/scrim-edge/api.sock -X POST http://scrim/v1/exec \
  -H 'content-type: application/json' -d '{"command":["execprobe"],"env":{"PROBE_SECRET":"SCRIM_DB_PASSWORD"}}')"
record "$out"
jq -e '.exit_code == 0' <<<"$out" >/dev/null || fail "the exec call failed: $out"
grep -q "sha256=$want_sum" <<<"$(jq -r .stdout <<<"$out")" || fail "the command did not get the real value centrally: $out"
if grep -q "value=$db_password" <<<"$(jq -r .stdout <<<"$out")"; then fail "the exec output carried the value"; fi
jq -e '.redactions >= 1' <<<"$out" >/dev/null || fail "the exec output was not redacted: $out"
pass "exec runs centrally with the real value and returns it as a placeholder"
else
  printf 'skip exec: this tree has no exec broker (exec.* in schema/config-v1.json)\n'
fi

log "fail closed"
k -n scrim scale deploy/scrim --replicas=0 >/dev/null
kwait 120 -n scrim wait --for=delete pod -l app.kubernetes.io/component=proxy --timeout=100s >/dev/null 2>&1 || true
if agent_answers; then fail "ssh-agent answered with the central scrim down"; fi
grep -q "error fetching identities" <<<"$(ssh_add)" || fail "ssh-add did not report the refused connection"
if in_agent env PGPASSWORD=x PGCONNECT_TIMEOUT=15 psql -X -h 127.0.0.1 -p 5432 -U a -d app -c 'select 1' >/dev/null 2>&1; then
  fail "psql worked with the central scrim down"
fi
code="$(in_agent curl -sS -o /dev/null -w '%{http_code}' --unix-socket /run/scrim-edge/api.sock http://scrim/v1/whoami)"
[ "$code" = 503 ] || fail "the agent API answered $code with the central scrim down, want 503"
pass "every endpoint refuses while the central scrim is down"
k -n scrim scale deploy/scrim --replicas=1 >/dev/null
kwait 200 -n scrim rollout status deploy/scrim --timeout=180s >/dev/null
for _ in $(seq 1 30); do
  agent_answers && break
  sleep 2
done
agent_answers || fail "ssh-agent did not recover once the central scrim was back"
out="$(in_agent env PGPASSWORD="$placeholder" psql -X -A -t -h 127.0.0.1 -p 5432 -U anything -d app -c 'select 1' 2>&1)" ||
  fail "psql did not recover: $out"
pass "the forwarder recovers without a restart"

log "logs and the pod's filesystem"
logs="$(k -n scrim logs deploy/scrim --tail=-1; k -n agents logs agent-edge -c scrim-edge --tail=-1)"
for v in "$db_password" "$user_key_body"; do
  if grep -qF "$v" <<<"$logs" || grep -qF "$v" <<<"$outputs"; then
    fail "a secret value reached a log or the agent's output"
  fi
done
if in_agent sh -c 'grep -rl "OPENSSH PRIVATE KEY" /tmp /run/scrim-edge /etc/scrim 2>/dev/null' | grep -q .; then
  fail "a private key is in the agent pod"
fi
pass "no secret value in logs or agent output, and no key in the pod"

failed=0
log "PASS"
