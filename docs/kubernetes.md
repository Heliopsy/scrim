# Kubernetes

scrim runs in Kubernetes from the Helm chart in [`deploy/helm/scrim`](../deploy/helm/scrim). Agent
pods are configured to use it by a label, without changing their images, and NetworkPolicies keep
them from reaching model providers or tool APIs except through scrim. This is interception method 5
([interception.md](interception.md#5-kubernetes-transparent)).

Spec: `openspec/changes/scrim-v1/specs/deployment` (Helm chart, network policy, agent pod injection)
and `specs/interception` (Kubernetes injection), design D8, D9 and D11.

## Two modes

| | Central | Sidecar |
| --- | --- | --- |
| What runs | a Deployment of `scrim proxy` behind a Service | a full `scrim proxy` inside each agent pod, on loopback |
| Agent pod label | `scrim.dev/inject: central` | `scrim.dev/inject: sidecar` |
| Agents reach scrim at | `http://<release>-scrim.<namespace>.svc:9790` and `:9791` | `http://127.0.0.1:9790` and `:9791` |
| Secret values live in | the scrim pods only | every agent pod's scrim container |
| Store credentials and CA key | in scrim's namespace | copied into every agent namespace |
| State | memory (one replica) or PostgreSQL (several) | memory, per pod |
| Approvals and grants | shared across replicas with PostgreSQL | per pod; lost when the pod goes |
| What keeps the agent from going around scrim | NetworkPolicy: the pod reaches scrim and DNS only | the egress guard (nftables in the pod) plus NetworkPolicy |
| Needs | a CNI that enforces NetworkPolicy | the same, and `NET_ADMIN` for the guard's init container |

Central is the default and the one to start with. The value dictionary, the CA key and the store
credentials stay in one place, the agent pods hold nothing secret, and NetworkPolicy alone enforces
the path. Sidecar mode suits clusters that do not want a shared service in the request path, or
agent pods that must keep working when the central scrim is unreachable, at the cost of spreading
values and credentials over every agent pod.

### Why the sidecar is a full `scrim proxy`

Design D11 publishes the data plane on its own (`ghcr.io/heliopsy/scrim-dataplane`) for sidecars
that need it without a control plane per pod. That needs a network transport between a sidecar
data plane and a remote control plane: the data plane inherits its one socket from the control
plane that starts it, and no remote transport, authentication or snapshot delivery over the network
is specified. Until it is, the sidecar runs the release `scrim` image, so the pod has its own
control plane and data plane over the inherited socket exactly as on a laptop. The cost is a second
process and the stores' credentials in every agent namespace; nothing new is trusted over the
network.

### Why the sidecar needs the egress guard

A NetworkPolicy applies to the whole pod. The in-pod scrim has to reach providers, stores and tool
hosts, so the pod's policy must allow them, and then the agent container can reach them too: every
container of a pod shares one network namespace. The egress guard is an init container that installs
an nftables table in that namespace: loopback, replies and DNS pass, and new outbound connections
pass only from UID 65532, the user the scrim container runs as. Everything else is rejected. The
agent's own containers must therefore not run as UID 65532 and must not have `NET_ADMIN` (they
could flush the table). The guard's image is yours to choose (`sidecar.egressGuard.image`, any image
with `sh` and `nft`); the chart refuses sidecar mode without one unless you turn the guard off and
accept that agents can bypass scrim toward whatever the pod's policy allows.

The guard's container runs as root with only `NET_ADMIN` and exits before the agent starts. Pod
Security Admission `baseline` and `restricted` refuse `NET_ADMIN`, so agent namespaces in sidecar
mode need `privileged`, or an exemption for that init container.

## Install

Requirements: Kubernetes 1.29 or later, a CNI that enforces NetworkPolicy (Calico, Cilium, Antrea,
kube-network-policies; kindnet only from kind 0.24 on, plain flannel never), Kyverno 1.13 or later
for injection by label, and PostgreSQL for more than one replica.

```sh
kubectl --context <ctx> create namespace scrim
kubectl --context <ctx> -n scrim create secret generic scrim-openbao --from-file=token=./bao-token
helm --kube-context <ctx> install scrim deploy/helm/scrim -n scrim -f values.yaml
```

A minimal `values.yaml` for central mode with OpenBao, two agent namespaces, Kyverno and
NetworkPolicy:

```yaml
config:
  stores:
    bao:
      kind: openbao
      address: https://bao.example.com:8200
      token: file:/run/secrets/scrim/bao/token
      redact: ["bao://kv/agents/*"]
  catalog:
    entries:
      github:
        ref: bao://kv/agents/github#token
        hosts: [api.github.com]
        placeholder: SCRIM_GITHUB_TOKEN
        inject: ["header:Authorization"]
secretMounts:
  - name: bao
    secretName: scrim-openbao
agents:
  namespaces: [agents, ci]
kyverno:
  enabled: true
networkPolicy:
  enabled: true
  scrimEgress:
    - ports: [{port: 443, protocol: TCP}]           # providers, GitHub, OpenBao
```

`config` takes scrim's configuration file as it is; the chart adds `apiVersion` and `kind`. Secret
values never go into values: settings that hold a credential take a `file:` reference to a Secret
mounted with `secretMounts` (or `env:` with `extraEnv` and `secretKeyRef`), and the chart refuses a
literal in the credential fields of `config.stores`. Every value is listed in the
[chart README](../deploy/helm/scrim/README.md#values).

### What the chart sets

These settings are written to a second file, `chart.yaml`, read after yours, so they win:

| Setting | Central | Sidecar |
| --- | --- | --- |
| `profile` | `k8s` | `k8s` |
| `proxy.listen`, `proxy.forward-listen` | `0.0.0.0:9790`, `0.0.0.0:9791` | `127.0.0.1:9790`, `127.0.0.1:9791` |
| `metrics.listen` | `0.0.0.0:9792` (health for the probes; `/metrics` reachable only as NetworkPolicy allows) | the same |
| `api.socket`, `admin.url` | `/run/scrim/api.sock`, `unix:/run/scrim/admin.sock` (or TCP with `admin.tcp`) | the same, Unix only |
| `state.backend` | `state.backend` value, the DSN from `state.postgres.dsnSecret` | `memory` |
| `tool-proxy.ca.cert-file`, `tool-proxy.ca.key` | the CA Secret | its copy in the agent namespace |
| `redaction.placeholder-keys` | the key Secret | its copy |
| `proxy.upstream-ca-file` | from `upstreamCA` | the same ConfigMap name in the agent namespace |
| `policy.rules-file` | from `policyRules` | the same |
| `log.level`, `log.format` | from `log` | the same |

The container runs as UID 65532 with a read-only root filesystem, no capabilities, no privilege
escalation and the RuntimeDefault seccomp profile. State, sockets and temporary files are
`emptyDir` volumes. The data plane runs from memory (`memfd`), as on a laptop. It cannot lock its
memory without `CAP_IPC_LOCK` and an unlimited memlock limit, so it logs a warning that values may
be swapped; nodes without swap, the Kubernetes default, do not swap.

### The CA

The tool proxy signs a leaf certificate for each host it intercepts with scrim's CA, and agents
trust that CA. Every replica and sidecar must use the same one, so the chart never lets scrim
generate its own per pod:

- `ca.create: true` (default): Helm generates an Ed25519 CA on the first install into the Secret
  `<release>-scrim-ca`, marked `helm.sh/resource-policy: keep`, and reads it back with `lookup` on
  every upgrade. GitOps tools that render with `helm template` (Argo CD, Flux with
  `postRenderers` off is fine) have no `lookup`: they would generate a new CA on every render.
  Use `ca.existingSecret` with those.
- `ca.existingSecret`: a `kubernetes.io/tls` Secret with `tls.crt` and a PKCS#8 `tls.key`, for
  example from cert-manager with `privateKey.encoding: PKCS8` and `isCA: true`. Set
  `ca.certificate` to the public PEM when rendering without cluster access. scrim never rotates an
  operator CA ([ca.md](ca.md#bringing-your-own-ca)).

The certificate is published as the ConfigMap `scrim-ca` (`ca.configMapName`) in the release
namespace and in every agent namespace, with `scrim-ca.pem` (the CA) and `ca-bundle.pem` (the CA
plus `ca.extraTrustedCerts`). The bundle has no public roots: an agent pod reaches only scrim, so
every TLS connection it makes ends at a scrim leaf. Add the CAs of cluster services you let agents
reach directly to `ca.extraTrustedCerts`.

### Placeholder keys

Placeholders are an HMAC of the value, so every replica and sidecar needs the same keys, or a
conversation started on one replica stops matching on another. The chart generates a 64-byte key
into `<release>-scrim-placeholder-keys` the same way as the CA, or takes `placeholderKeys.existingSecret`
with the key versions listed in `placeholderKeys.keys` (highest is current; keep older versions
while conversations made with them may continue).

### Upstream trust

The data plane trusts the system and Mozilla roots for providers and tool hosts. A tool host with a
private CA, or a proxy that inspects TLS on the way out, needs its CA added: put a PEM bundle in a
ConfigMap and set `upstreamCA.configMap` and `upstreamCA.key`. The chart mounts it and sets
`proxy.upstream-ca-file`. In sidecar mode the ConfigMap must exist under the same name in each agent
namespace.

## Agent pods

### With Kyverno

Label the pod, nothing else:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: reviewer
  namespace: agents
  labels:
    scrim.dev/inject: central        # or sidecar
spec:
  containers:
    - name: agent
      image: ghcr.io/example/agent:1
```

The ClusterPolicy (`kyverno.enabled`) mutates Pods only, at creation (controllers are left as
written, so a Deployment in Git does not drift), and adds to every container:

| Variable | Central value | Sidecar value |
| --- | --- | --- |
| `ANTHROPIC_BASE_URL` | `http://<svc>:9790/anthropic` | `http://127.0.0.1:9790/anthropic` |
| `OPENAI_BASE_URL` | `http://<svc>:9790/openai/v1` | `http://127.0.0.1:9790/openai/v1` |
| `HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY`, `http_proxy` | `http://<svc>:9791` | `http://127.0.0.1:9791` |
| `NO_PROXY`, `no_proxy` | loopback, the scrim Service names, `agents.noProxy` | loopback, `agents.noProxy` |
| `NODE_EXTRA_CA_CERTS` | `/etc/scrim/trust/scrim-ca.pem` | the same |
| `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `AWS_CA_BUNDLE`, `PIP_CERT`, `NPM_CONFIG_CAFILE`, `CARGO_HTTP_CAINFO`, `DENO_CERT`, `CODEX_CA_CERTIFICATE` | `/etc/scrim/trust/ca-bundle.pem` | the same |

`<svc>` is `<release>-scrim.<namespace>.svc.<clusterDomain>`. These are the variables `scrim run`
sets for an agent on a laptop (`internal/run`), with the Service in place of loopback. The `scrim-ca`
ConfigMap is mounted at `agents.trustPath` (`/etc/scrim/trust`). An injected variable replaces one
of the same name in the pod spec. In sidecar mode the policy also adds the egress guard and the scrim
container as a native sidecar (an init container with `restartPolicy: Always`), whose startup probe
waits for `/readyz`, so the agent starts only once its scrim is ready.

A labelled pod in a namespace not listed in `agents.namespaces`, or with a label value other than
`central` or `sidecar` (for the modes enabled), is refused: its CA, environment and NetworkPolicies
would be missing. With `kyverno.failurePolicy: Fail` (default) labelled pods are refused while
Kyverno is down, rather than started unconfigured.

MCP registration is not injected. `scrim mcp` talks to the agent API over a Unix socket in scrim's
pod; reaching it from an agent pod needs the edge forwarder (tasks.md 12.5).

### Without Kyverno

The chart writes the same environment into a ConfigMap in each agent namespace,
`<release>-scrim-agent-env` (and `-agent-env-sidecar`). Reference it and mount the CA yourself:

```yaml
spec:
  containers:
    - name: agent
      image: ghcr.io/example/agent:1
      envFrom:
        - configMapRef:
            name: scrim-agent-env       # <release>-scrim-agent-env
      volumeMounts:
        - name: scrim-trust
          mountPath: /etc/scrim/trust
          readOnly: true
  volumes:
    - name: scrim-trust
      configMap:
        name: scrim-ca
```

Keep the `scrim.dev/inject: central` label so the NetworkPolicy applies. `env` entries in the
container win over `envFrom`, so remove any `ANTHROPIC_BASE_URL` or proxy variables the spec already
sets. Sidecar mode without Kyverno means copying the sidecar and guard containers from
`helm template --show-only templates/kyverno.yaml` into your pod spec.

## NetworkPolicy

`networkPolicy.enabled` creates, for a CNI that enforces NetworkPolicy:

| Policy | Namespace | Selects | Allows |
| --- | --- | --- | --- |
| `<release>-scrim` | release | scrim pods | ingress to 9790 and 9791 from pods labelled `central` in `agents.namespaces`; to the metrics port from `networkPolicy.prometheus` when `metrics.enabled`; to the admin port from `networkPolicy.adminFrom` when `admin.tcp.enabled`. Egress to DNS and `networkPolicy.scrimEgress` |
| `<release>-scrim-agents-central` | each agent namespace | pods labelled `central` | egress to the scrim pods on 9790 and 9791, and DNS. Nothing else |
| `<release>-scrim-agents-sidecar` | each agent namespace | pods labelled `sidecar` | egress to DNS and `networkPolicy.sidecarEgress` (what the in-pod scrim needs; the guard keeps the agent off it) |

`scrimEgress` and `sidecarEgress` default to TCP 443 anywhere. Narrow them to your providers, stores,
tool hosts and PostgreSQL where your CNI supports it (CIDRs, or FQDN policies with Cilium or Calico
Enterprise as separate objects). DNS goes to `networkPolicy.dns` (kube-dns in kube-system by
default; change the selectors for NodeLocal DNSCache or another resolver).

A NetworkPolicy that the CNI does not enforce is silently ignored. Check before relying on it: from
a pod labelled `central`, `curl -m 5 --noproxy '*' https://api.anthropic.com` must fail.

The agent policies only restrict egress. Ingress to agent pods is left to you; in sidecar mode the
sidecar's health and metrics port (9792) is reachable on the pod IP.

## Identity

On `main` scrim identifies callers over TCP only by session tokens, which `scrim run` mints on a
laptop. An agent pod has none, so every agent pod is an **unknown caller**: provider requests are
redacted and forwarded as for anyone, but the built-in injection rule serves only known agents, so
credentials are injected only where a policy rule allows it explicitly:

```yaml
policyRules:
  rules:
    - name: agents-github
      decision: allow
      when: op == "inject" && dest.host == "api.github.com"
```

Such a rule applies to every caller that can reach scrim. In central mode that is what the
NetworkPolicy limits to labelled pods in the agent namespaces; in sidecar mode it is the pod's own
agent.

Per-pod identity arrives with TokenReview (tasks.md 12.2): agent pods present a projected service
account token with a scrim audience and are identified as `namespace/serviceaccount` with the pod
name attached. The chart's side is ready: `identity.kubernetes.enabled` binds scrim's
ServiceAccount to `system:auth-delegator`, mounts its token, and has the Kyverno policy add a
projected token with `identity.kubernetes.audience` at `identity.kubernetes.tokenPath` to agent
containers. The scrim settings that read it come with that work; until then the flag only prepares
the cluster side.

Store authentication with scrim's own service account (OpenBao or Vault Kubernetes auth, Infisical
Kubernetes auth, tasks.md 12.4) uses `storeAuth.serviceAccountToken`, which mounts a projected token
with the store's audience for the store configuration to reference. Until that lands use static
credentials by reference (token, AppRole, Infisical machine identity) as above.

## Scaling and state

One replica with `state.backend: memory` is the default: approvals and grants live in the pod and
are lost on restart (pending requests are denied, never allowed). For several replicas or the HPA,
use PostgreSQL:

```yaml
state:
  backend: postgres
  postgres:
    dsnSecret: {name: scrim-pg, key: dsn}     # postgres://user:pass@host/db?sslmode=verify-full
central:
  pdb: {minAvailable: 1}
  autoscaling:
    enabled: true
    minReplicas: 2
    maxReplicas: 10
```

The chart refuses more than one replica on the memory backend. Replicas share the CA and the
placeholder keys through their Secrets, so any replica produces and resolves the same placeholders.
Propagation of approvals and grants between replicas through Postgres notify is tasks.md 12.1.

`central.autoscaling.streams` adds a Pods metric of concurrent proxied streams per replica (default
name `scrim_proxy_active_streams`) for a metrics adapter such as prometheus-adapter to serve. CPU
alone works without an adapter.

## Metrics and monitoring

The health endpoints (`/livez`, `/readyz`) are always served on port 9792 for the probes.
`metrics.enabled` exposes `/metrics` there through the Service, turns on scrim's `metrics.enabled`
setting and opens the NetworkPolicy to `networkPolicy.prometheus`. Then, each off by default:

| Value | Creates |
| --- | --- |
| `serviceMonitor.enabled` | a ServiceMonitor for central scrim |
| `podMonitor.enabled` | a PodMonitor per agent namespace for sidecars |
| `prometheusRule.enabled` | a PrometheusRule from the chart's `monitoring/prometheus-rules.yaml` plus `prometheusRule.groups` |
| `grafanaDashboard.enabled` | a ConfigMap with the dashboard, labelled `grafana_dashboard: "1"` for the Grafana sidecar |

`metrics.authSecret` makes scrapers present a bearer token (scrim's `metrics.auth`); the monitors
reference the same Secret. The metrics settings `metrics.enabled`, `metrics.path` and `metrics.auth`
and the bundled rules and dashboard come with the metrics work; with a scrim release that predates
it, leave `metrics.enabled` off (the health port still serves `/metrics` inside the pod).

## Upgrades

- The CA and placeholder key Secrets are kept across upgrades and uninstalls
  (`helm.sh/resource-policy: keep`). Delete them by hand only together with every agent's trust in
  the CA.
- Config changes roll the Deployment (a checksum of the ConfigMap is a pod annotation). scrim also
  reloads file changes itself while `config.watch` is on, but the chart's mount is a ConfigMap
  volume, which kubelet updates with a delay; the roll is what makes it immediate.
- Sidecars pick up changes when their pod is recreated. Kyverno mutates at creation only.
- The default `RollingUpdate` (`maxSurge: 1`, `maxUnavailable: 0`) keeps a ready replica during the
  roll. With the memory backend, pending approvals on the old pod are denied when it stops.

## Troubleshooting

| Symptom | Look at |
| --- | --- |
| scrim pod never ready | `kubectl logs deploy/<release>-scrim`: `snapshot rejected` names the data plane's reason; `/readyz` lists failing checks (`kubectl exec deploy/<release>-scrim -- scrim status`) |
| `store <name>` failing in `/readyz` | the store address, the Secret behind the reference, `networkPolicy.scrimEgress` |
| agent gets `403 unbound_destination` | the credential's `hosts` binding does not name the host (with its port if not 443) |
| agent gets `403 policy_denied ... rule default` | no policy rule allows injection for unknown callers; see [Identity](#identity) |
| TLS errors in the agent | the pod lacks the `scrim-ca` mount or the variables (label, namespace listed, Kyverno running), or the runtime ignores them ([CA trust per runtime](interception.md#ca-trust-per-runtime)) |
| TLS errors in scrim toward a tool host | the host's CA is private: `upstreamCA` |
| agent reaches a provider directly | the CNI does not enforce NetworkPolicy, or the pod lacks the label; in sidecar mode the guard is off or the agent runs as UID 65532 |
| labelled pod refused at creation | the namespace is not in `agents.namespaces`, or the label value is not an enabled mode |
| sidecar pod stuck in `Init` | `kubectl logs <pod> -c scrim-egress-guard` and `-c scrim`; the CA and key Secrets must exist in the agent namespace |

## Testing

`just helm-test` lints the chart, compares `helm template` of every case in `test/k8s/golden/cases`
with `test/k8s/golden/out`, checks the values in `test/k8s/golden/fail` are refused, and that every
value is in the chart README.

`just k8s-e2e` (`test/k8s/e2e.sh`) creates a kind cluster on rootless podman
(`KIND_EXPERIMENTAL_PROVIDER=podman`) with Calico, installs Kyverno, OpenBao in dev mode, the fake
model provider, a TLS tool host and the chart, then starts one agent pod per mode and asserts:

- the provider receives placeholders, never the secret the agent sent;
- the agent cannot reach the provider or the tool host directly;
- the credential is injected toward its bound host and the agent gets the placeholder back;
- a placeholder sent toward an unbound name of the same server is refused and nothing reaches it;
- no secret value is in scrim's logs, and Kyverno refuses a labelled pod in an unprepared namespace.

It uses its own kubeconfig in a temporary directory and removes the cluster, its images and the
`kind` network it created. It needs about 4 GB of disk. `SCRIM_K8S_KEEP=1` keeps the cluster for
debugging and `SCRIM_K8S_REUSE=1` reuses it.

Rootless kind needs cgroup v2 with the cpu, memory and pids controllers delegated to the user
(`cat /sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/cgroup.controllers`). If
podman fails with `failed to mount runtime directory for rootless netns`, the rootless network
namespace's directory under `$XDG_RUNTIME_DIR/libpod/tmp/rootless-netns/run` lost its
`user/<uid>` entry; recreate it with `mkdir -p -m 0700
"$XDG_RUNTIME_DIR/libpod/tmp/rootless-netns/run/user/$(id -u)"`.

## Not covered yet

- Publishing and signing the chart (OCI registry, cosign), part of the release pipeline.
- Transparent redirection for agents that ignore the injected variables (an init container or CNI
  that redirects with `NET_ADMIN`). The egress guard rejects such traffic instead of redirecting it.
- MCP registration in agent pods and the edge forwarder for ssh-agent and database ports (12.5).
- A standalone `scrim-dataplane` sidecar with a remote control plane (no transport is specified).
- Per-pod identity and store Kubernetes auth (12.2, 12.2c, 12.4): values and RBAC are in place.
