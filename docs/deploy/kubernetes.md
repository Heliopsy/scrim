# Kubernetes

A central scrim Deployment that agent pods reach through a Service. Three ways to describe it:

| Way | Use it when |
| --- | --- |
| [Raw manifests](#raw-manifests) | you apply YAML yourself, or want to read exactly what runs |
| [Kustomize](#kustomize) | you keep per-environment differences (dev, staging, prod) as overlays |
| [Helm](helm.md) | you want the chart's sidecar mode, Kyverno injection, NetworkPolicy and Kubernetes identity |

The [Helm chart](helm.md) is the full-featured path. The raw manifests and the kustomize base are
plain Kubernetes for the central mode only: no admission policy, no Kubernetes identity. Every
command passes `--context` explicitly; none of them relies on your current context.

Files: [`deploy/examples/kubernetes/`](../../deploy/examples/kubernetes/).

## Prerequisites

- Kubernetes 1.29 or later and `kubectl`; `kustomize` 5 (or `kubectl -k`) for the overlays.
- A CNI that enforces NetworkPolicy if you use the NetworkPolicy files.
- `openssl` to generate the placeholder key and CA.
- For more than one replica, PostgreSQL and a Secret holding its DSN.

## What gets deployed

| Object | Why |
| --- | --- |
| Namespace `scrim` | Pod Security `restricted` enforced |
| ServiceAccount `scrim` | no API token mounted |
| ConfigMap `scrim-config` | the config file; the same format as on a workstation, with `profile: k8s` |
| Deployment `scrim` | `scrim proxy`, read-only root filesystem, UID 65532, probes on `/livez` and `/readyz` |
| Service `scrim` | ports 9790 (base URL) and 9791 (forward proxy), ClusterIP |
| PodDisruptionBudget `scrim` | at most one replica down during a drain |
| NetworkPolicy (optional) | agent pods labelled `scrim.dev/agent: "true"` in `agents` reach only scrim and DNS |

Three Secrets come from outside the manifests, so no value is ever in git:

| Secret | Keys | Why it must be shared and stable |
| --- | --- | --- |
| `scrim-keys` | `placeholder-k1`, `approvals-signing-key` | every replica and every restart must make the same placeholders and accept the same decision links |
| `scrim-ca` | `tls.crt`, `tls.key` (PKCS#8) | agents trust this CA; a generated one would change at every restart |
| `scrim-agent-secrets` | one key per secret scrim redacts | read by the file store as `files://agents/<key>` |

[`create-secrets.sh`](../../deploy/examples/kubernetes/raw/create-secrets.sh) generates the first
two locally and creates all three, printing no value. In GitOps setups they come from SOPS or
External Secrets instead ([gitops-secrets.md](gitops-secrets.md)).

## Raw manifests

```sh
CONTEXT=my-cluster
kubectl --context "$CONTEXT" apply -f deploy/examples/kubernetes/raw/00-namespace.yaml
CONTEXT=$CONTEXT SECRETS_DIR=~/scrim-agent-secrets deploy/examples/kubernetes/raw/create-secrets.sh
kubectl --context "$CONTEXT" apply -f deploy/examples/kubernetes/raw/
```

`SECRETS_DIR` holds one file per secret, named as the catalog refers to it (`github-token`).
`60-networkpolicy.yaml` assumes the agents run in the namespace `agents`; edit the namespace and
labels to yours, or leave the file out. Agent pods then use:

```yaml
env:
  - name: ANTHROPIC_BASE_URL
    value: http://scrim.scrim.svc:9790/anthropic
  - name: OPENAI_BASE_URL
    value: http://scrim.scrim.svc:9790/openai/v1
```

For tool traffic through the forward proxy, also set `HTTPS_PROXY=http://scrim.scrim.svc:9791`
and mount the CA certificate (`kubectl --context "$CONTEXT" -n scrim get secret scrim-ca -o
jsonpath='{.data.tls\.crt}' | base64 -d` is public) with `NODE_EXTRA_CA_CERTS` or `SSL_CERT_FILE`
pointing at it. The Helm chart does that wiring for labelled pods.

Agent pods reach scrim without a `scrim run` session and without a service account token scrim
can check, so they are unknown callers: their provider requests are redacted like everyone's, and
nothing is injected for them. The config sets `identity.kubernetes.enabled: false`, which the `k8s`
profile turns on, because these manifests give scrim no API token and no TokenReview binding.
Kubernetes identity (a projected token per agent pod, the `scrim-exec` launcher, the TokenReview
binding) is wired by the [Helm chart](helm.md#central-mode); use it when agents need credentials
injected.

`SECRETS_DIR` must hold at least one file. scrim refuses to start while a redact target loads
nothing, so an empty `scrim-agent-secrets` leaves the pod in CrashLoopBackOff with an error naming
`files://agents/*`.

## Kustomize

[`kustomize/base`](../../deploy/examples/kubernetes/kustomize/base/) is the raw Deployment, Service
and PodDisruptionBudget, with the config file generated into a ConfigMap whose name changes with
its content, so a config change rolls the pods. The base config ends with:

```yaml
include:
  - overlay-*.yaml
```

so overlays and components add settings by adding files to the ConfigMap, without patching YAML
inside YAML.

| Overlay | Replicas | State | NetworkPolicy | Image |
| --- | --- | --- | --- | --- |
| `overlays/dev` | 1 | memory | no | rewritten by Flux image automation |
| `overlays/staging` | 2 | PostgreSQL | yes | the release |
| `overlays/prod` | 3, spread over nodes, PDB `minAvailable: 2` | PostgreSQL | yes | the release, with a `digest:` line for the digest `cosign verify` printed |

The components in `kustomize/components/` are `postgres` (adds `overlay-postgres.yaml` with
`state.backend: postgres` and `events.backend: postgres`, and mounts the Secret `scrim-postgres`,
key `dsn`) and `networkpolicy`. The staging and prod overlays set `deployment.replicas` to their
replica count, and scrim refuses to start with more than one replica unless state and events are
both on PostgreSQL. Change the two numbers together.

```sh
CONTEXT=my-cluster
kustomize build deploy/examples/kubernetes/kustomize/overlays/staging | less
kubectl --context "$CONTEXT" apply -f deploy/examples/kubernetes/kustomize/base/namespace.yaml
CONTEXT=$CONTEXT SECRETS_DIR=~/scrim-agent-secrets deploy/examples/kubernetes/raw/create-secrets.sh
kubectl --context "$CONTEXT" -n scrim create secret generic scrim-postgres --from-file=dsn=./dsn
kubectl --context "$CONTEXT" apply -k deploy/examples/kubernetes/kustomize/overlays/staging
```

With PostgreSQL, replicas share approvals, grants, sessions and the audit log; the placeholder
key Secret makes their placeholders identical. The DSN file holds
`postgres://scrim:<password>@<host>:5432/scrim?sslmode=verify-full`; create it from your secret
manager and delete it afterwards.

## Verify

```sh
CONTEXT=my-cluster
timeout 30 kubectl --context "$CONTEXT" -n scrim rollout status deploy/scrim
timeout 30 kubectl --context "$CONTEXT" -n scrim exec deploy/scrim -- scrim status
timeout 30 kubectl --context "$CONTEXT" -n scrim exec deploy/scrim -- scrim doctor
```

`scrim status` shows `profile: k8s`, the state backend and `snapshot N, M values` for the data
plane. Then send the canary request from inside the cluster, from a pod the NetworkPolicy lets
through:

```sh
timeout 60 kubectl --context "$CONTEXT" -n agents run scrim-canary --rm -i --restart=Never \
  --labels scrim.dev/agent=true --image=docker.io/curlimages/curl:8.23.0 -- \
  curl -s -o /dev/null -w '%{http_code}\n' http://scrim.scrim.svc:9790/anthropic/v1/messages \
  -H 'x-api-key: not-a-real-key' -H 'anthropic-version: 2023-06-01' -H 'content-type: application/json' \
  -d '{"model":"claude-sonnet-4-5","max_tokens":16,"messages":[{"role":"user","content":"canary"}]}'
```

It prints `401`: the request went through scrim to Anthropic. With the NetworkPolicy on, the same
pod calling `https://api.anthropic.com` directly times out. To look at what the provider received,
set `proxy.capture.dir: /var/lib/scrim/capture` in an overlay file for a test environment and copy
the directory out with `kubectl cp`; capture mode writes your prompts to the pod's disk, so leave
it off in production.

## Metrics

The base serves only `/livez` and `/readyz` on port 9792. To expose `/metrics` there, add an
overlay file with `metrics.enabled: true` and a bearer token, which scrim requires on a listener
outside loopback:

```yaml
apiVersion: scrim.dev/v1
kind: Config
metrics:
  enabled: true
  auth:
    token: file:/run/secrets/scrim-keys/metrics-token
```

Add a `metrics-token` key (`openssl rand -hex 32`) to `scrim-keys`, and let Prometheus reach port
9792 if the NetworkPolicy is on. Metric meanings, alerts and the dashboard are in
[monitoring.md](../monitoring.md); the Helm chart wires all of this with `metrics.enabled`.

## Upgrade and roll back

Change the image tag (or digest) and apply. The Deployment rolls one pod at a time
(`maxUnavailable: 0`), and a pod is ready only once its data plane holds a snapshot.

<!-- x-release-please-start-version -->
```sh
kubectl --context "$CONTEXT" -n scrim set image deploy/scrim scrim=ghcr.io/heliopsy/scrim:1.4.0   # raw
kustomize edit set image ghcr.io/heliopsy/scrim:1.4.0   # in the overlay directory, then apply -k
kubectl --context "$CONTEXT" -n scrim rollout undo deploy/scrim                                    # roll back
```
<!-- x-release-please-end -->

In GitOps setups the rollback is a revert of the commit that changed the tag. PostgreSQL schema
migrations are forward only: rolling back across one needs the database restored from before the
upgrade.

## Uninstall

```sh
kubectl --context "$CONTEXT" delete -k deploy/examples/kubernetes/kustomize/overlays/staging   # or -f raw/
kubectl --context "$CONTEXT" -n scrim delete secret scrim-keys scrim-ca scrim-agent-secrets scrim-postgres
kubectl --context "$CONTEXT" delete namespace scrim
```
