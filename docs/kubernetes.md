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
| Store login and CA key | scrim's service account (or credentials in scrim's namespace) | the agent pod's service account (or credentials copied into every agent namespace) |
| State and events | memory and local (one replica) or PostgreSQL (several) | memory and local, per pod |
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

From the registry (each release from the first one with the chart), verifying the keyless
signature first:

```sh
cosign verify ghcr.io/heliopsy/charts/scrim:<version> \
  --certificate-identity-regexp '^https://github\.com/Heliopsy/scrim/\.github/workflows/release\.yaml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
helm --kube-context <ctx> install scrim oci://ghcr.io/heliopsy/charts/scrim --version <version> \
  -n scrim --create-namespace -f values.yaml
helm --kube-context <ctx> test scrim -n scrim
```

The SBOM (`cosign verify-attestation --type spdxjson`) and the SLSA provenance (`gh attestation
verify oci://ghcr.io/heliopsy/charts/scrim@<digest> --repo Heliopsy/scrim`) are attached to the
same digest. With Flux, start from `deploy/helm/scrim/examples/flux`: an OCIRepository that
verifies the signature by its workflow identity, and a HelmRelease. Every value is described in
[helm-values.md](helm-values.md).

Requirements: Kubernetes 1.29 or later, a CNI that enforces NetworkPolicy (Calico, Cilium, Antrea,
kube-network-policies; kindnet only from kind 0.24 on, plain flannel never), Kyverno 1.13 or later
for injection by label, and PostgreSQL for more than one replica. From a checkout instead of the
registry:

```sh
kubectl --context <ctx> create namespace scrim
helm --kube-context <ctx> install scrim deploy/helm/scrim -n scrim -f values.yaml
```

A minimal `values.yaml` for central mode with OpenBao (scrim logs in with its own service account,
so no store credential exists in the cluster), two agent namespaces, Kyverno and NetworkPolicy:

```yaml
storeAuth:
  serviceAccountToken: {enabled: true, audience: openbao}
config:
  stores:
    bao:
      kind: openbao
      address: https://bao.example.com:8200
      auth:
        method: kubernetes
        kubernetes: {role: scrim, token-file: /var/run/secrets/scrim/store-token}
      redact: ["bao://kv/agents/*"]
  catalog:
    entries:
      github:
        ref: bao://kv/agents/github#token
        hosts: [api.github.com]
        placeholder: SCRIM_GITHUB_TOKEN
        inject: ["header:Authorization"]
agents:
  namespaces: [agents, ci]
kyverno:
  enabled: true
networkPolicy:
  enabled: true
  scrimEgress:
    - ports: [{port: 443, protocol: TCP}]           # providers, GitHub, OpenBao
```

The OpenBao role `scrim` binds scrim's service account (`scrim-proxy` in namespace `scrim` for the release `scrim`) with audience
`openbao` ([stores/openbao.md](stores/openbao.md#kubernetes-auth)); in sidecar mode it must also bind
the agent pods' service accounts, since each in-pod scrim logs in as its pod. Infisical works the
same way with `auth.method: kubernetes-auth`.

`config` takes scrim's configuration file as it is; the chart adds `apiVersion` and `kind`. Secret
values never go into values: settings that hold a credential take a `file:` reference to a Secret
mounted with `secretMounts` (or `env:` with `central.extraEnv` and `secretKeyRef`), and the chart refuses a
literal in the credential fields of `config.stores` and in `config.identity.store-credentials`.
Every value is listed in the [chart README](../deploy/helm/scrim/README.md#values).

Every store needs `redact` targets that match at least one secret when scrim first loads it. A target
that matches nothing (a misspelt path or pattern) stops scrim at start-up with an error naming it, so
the pod goes into CrashLoopBackOff instead of running with redaction that protects nothing. Set
`redaction.allow-empty-targets: true` in `config` only for a store that is legitimately empty at
first; status then reports the target as degraded. The chart's default `config` has no store and so
redacts nothing until you add one.

### What the chart sets

These settings are written to a second file, `chart.yaml`, read after yours, so they win:

| Setting | Central | Sidecar |
| --- | --- | --- |
| `profile` | `k8s` | `k8s` |
| `proxy.listen`, `proxy.forward-listen` | `0.0.0.0:9790`, `0.0.0.0:9791` | `127.0.0.1:9790`, `127.0.0.1:9791` |
| `metrics.listen` | `0.0.0.0:9792` (health for the probes; `/metrics` only with `metrics.enabled`) | the same |
| `metrics.enabled`, `metrics.path`, `metrics.auth.token`, `metrics.allow-unauthenticated-remote` | from `metrics` | the same |
| `identity.kubernetes.*` | from `identity.kubernetes`; scrim's own API token is the pod's mounted service account | the same, with the pod's API token from a projected volume only the scrim container mounts |
| `api.socket`, `admin.url` | `/run/scrim/api.sock`, `unix:/run/scrim/admin.sock` (or TCP with `admin.tcp`) | the same, Unix only |
| `state.backend`, `events.backend` | `postgres` and `postgres` with `postgres.enabled` (the DSN from the Secret slot `postgres`), else `memory` and `local` | `memory`, `local` |
| `deployment.replicas` | `central.replicaCount`, or `central.autoscaling.maxReplicas` with the HPA | `1` |
| `tool-proxy.ca.cert-file`, `tool-proxy.ca.key` | the CA Secret | its copy in the agent namespace |
| `redaction.placeholder-keys` | the key Secret | its copy |
| `dataplane.upstream-ca-file` | from `upstreamCA` | the same ConfigMap name in the agent namespace |
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
`dataplane.upstream-ca-file`, which the control plane passes to the data plane once, when it starts
it. In sidecar mode the ConfigMap must exist under the same name in each agent
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
| `SCRIM_K8S_TOKEN_FILE` (with `identity.kubernetes.enabled`) | `identity.kubernetes.tokenPath` | the same |

`<svc>` is `<release>-scrim.<namespace>.svc.<global.clusterDomain>`. These are the variables `scrim run`
sets for an agent on a laptop (`internal/run`), with the Service in place of loopback. The `scrim-ca`
ConfigMap is mounted at `agents.trustPath` (`/etc/scrim/trust`), with the `scrim-exec` launcher when
identity is on, and the projected identity token at `identity.kubernetes.tokenPath`
([Identity](#identity)). An injected variable replaces one
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
    - name: scrim-identity
      mountPath: /var/run/secrets/scrim
      readOnly: true
  volumes:
    - name: scrim-trust
      configMap:
        name: scrim-ca
        items:
          - {key: scrim-ca.pem, path: scrim-ca.pem}
          - {key: ca-bundle.pem, path: ca-bundle.pem}
          - {key: scrim-exec, path: scrim-exec, mode: 0555}
    - name: scrim-identity
      projected:
        defaultMode: 0444
        sources:
          - serviceAccountToken: {audience: scrim, expirationSeconds: 3600, path: token}
```

Keep the `scrim.dev/inject: central` label so the NetworkPolicy applies. `env` entries in the
container win over `envFrom`, so remove any `ANTHROPIC_BASE_URL` or proxy variables the spec already
sets. Sidecar mode without Kyverno means copying the sidecar and guard containers from
`helm template --show-only templates/kyverno.yaml` into your pod spec.

## NetworkPolicy

`networkPolicy.enabled` creates, for a CNI that enforces NetworkPolicy:

| Policy | Namespace | Selects | Allows |
| --- | --- | --- | --- |
| `<release>-scrim` | release | scrim pods | ingress to 9790 and 9791 from pods labelled `central` in `agents.namespaces`; to the metrics port from `networkPolicy.prometheus` when `metrics.enabled`; to the admin port from `networkPolicy.adminFrom` when `admin.tcp.enabled`. Egress to DNS, the API server (`networkPolicy.apiServerEgress`, for TokenReview) and `networkPolicy.scrimEgress` |
| `<release>-scrim-agents-central` | each agent namespace | pods labelled `central` | egress to the scrim pods on 9790 and 9791, and DNS. Nothing else |
| `<release>-scrim-agents-sidecar` | each agent namespace | pods labelled `sidecar` | egress to DNS, the API server (`networkPolicy.apiServerEgress`) and `networkPolicy.sidecarEgress` (what the in-pod scrim needs; the guard keeps the agent off it) |

`scrimEgress` and `sidecarEgress` default to TCP 443 anywhere, `apiServerEgress` to TCP 443 and
6443 anywhere: policies match the API server's endpoint, often port 6443 on the control plane nodes,
not the `kubernetes` Service port. Narrow them to your providers, stores,
tool hosts and PostgreSQL where your CNI supports it (CIDRs, or FQDN policies with Cilium or Calico
Enterprise as separate objects). DNS goes to `networkPolicy.dns` (kube-dns in kube-system by
default; change the selectors for NodeLocal DNSCache or another resolver).

A NetworkPolicy that the CNI does not enforce is silently ignored. Check before relying on it: from
a pod labelled `central`, `curl -m 5 --noproxy '*' https://api.anthropic.com` must fail.

The agent policies only restrict egress. Ingress to agent pods is left to you; in sidecar mode the
sidecar's health and metrics port (9792) is reachable on the pod IP.

## Identity

`identity.kubernetes.enabled` (on by default) identifies agent pods by their service account. The
chart turns on scrim's `identity.kubernetes` settings, gives scrim a ClusterRole that may only
create TokenReviews, and has the Kyverno policy add to every agent container a projected token for
`identity.kubernetes.audience` (`scrim`) at `identity.kubernetes.tokenPath`, the variable
`SCRIM_K8S_TOKEN_FILE` naming it, and the launcher `scrim-exec` in the trust mount
([identity.md](identity.md#kubernetes-service-accounts)).

An agent sends the token where scrim expects a caller's token (design D14): the password of the
proxy user `k8s` in `HTTPS_PROXY`, and `x-scrim-session` on the base URL. A pod's environment is
fixed when the container starts and cannot read a file, so `scrim-exec` does it: it reads the token,
sets the four proxy variables to `http://k8s:<token>@<host>:<port>`, adds `x-scrim-session: <token>`
to `ANTHROPIC_CUSTOM_HEADERS` (keeping headers already there, replacing a session header of its
own), sets `GIT_HTTP_PROXY_AUTHMETHOD=basic` so git sends the credentials with every CONNECT, and
runs the command:

```yaml
containers:
  - name: agent
    image: ghcr.io/example/agent:1
    command: [/etc/scrim/trust/scrim-exec, claude, -p, "review the open pull requests"]
```

It is POSIX `sh` with no other tools, so it works on a read-only root filesystem; the image needs
`/bin/sh`. Clients without a custom-header setting (Codex, curl) are identified on the forward proxy
only, which is where injection happens.

scrim verifies the token with TokenReview, caches it for `identity.kubernetes.cache-ttl`, and names
the agent `<namespace>/<service account>` unless `identity.kubernetes.agents` maps it
(`identity.kubernetes.unmapped: unknown` makes unmapped accounts unknown). The built-in rule
`builtin.inject-bound` then injects credentials toward their bound hosts for that agent, and policy
rules can match `agent.id`, `agent.labels.namespace`, `agent.labels.service_account` and
`agent.labels.pod`. A process started without `scrim-exec`, or a pod without the label, is an
unknown caller: its provider requests are redacted as for anyone, and nothing is injected for it.
Every token scrim verifies joins the redaction set, so one that ends up in a tool result reaches the
provider as a placeholder.

`scrim-exec` reads the token when the command starts. The kubelet rotates the file, but the process
keeps the token it was started with, which stops working after
`identity.kubernetes.expirationSeconds` (one hour by default). Raise it for agents that run longer
in one process, or restart them.

In central mode the TokenReview binding is for scrim's own service account, and scrim uses the
token Kubernetes mounts for it. In sidecar mode each in-pod scrim runs as the agent pod's service
account: the binding names the group `system:serviceaccounts:<namespace>` of every agent namespace,
and the policy mounts a projected API token and the cluster CA into the scrim container only
(`/var/run/secrets/scrim/kube-api`). Either way the role allows creating TokenReviews and nothing
else. Set `identity.kubernetes.tokenReviewRBAC: false` to manage the binding yourself.

### Store identity

`storeAuth.serviceAccountToken` mounts a projected token with the store's audience into scrim (and
into each sidecar), for OpenBao `auth.method: kubernetes` or Infisical `kubernetes-auth` with
`auth.kubernetes.token-file` pointing at it; scrim reads the file again at every login. Per-agent
store checks with the calling pod's own token are scrim settings and go in `config`:

```yaml
config:
  identity:
    store-login:
      bao: "kubernetes role:{namespace}-{service_account}"
```

With that, every injection of a `bao` secret is also checked against the OpenBao role of the calling
pod ([identity.md](identity.md#store-identity-per-agent)). The agent token's audience
(`identity.kubernetes.audience`) must be one the role accepts.

## Secrets the chart mounts

The credentials the chart itself wires in are Secret slots (the shared helpers of
`templates/_helpers.tpl`): `postgres` (key `dsn`), `admin` (key `token`, for `admin.tcp`) and
`metrics` (key `token`). A slot's Secret is the one named in `secrets.existing.<slot>`, or an
ExternalSecret the chart renders from `secrets.externalSecrets.data.<slot>`, or, for `metrics`
only, a Secret the chart generates on first install and keeps (`helm.sh/resource-policy: keep`).
`secrets.keys.<slot>` renames the keys of an existing Secret. No value ever comes from values.yaml.
Store credentials are scrim settings and take `file:` references to `secretMounts`, or better none
at all with [store login](#store-identity).

## Scaling and state

One replica with in-memory state is the default: approvals and grants live in the pod and are lost
on restart (pending requests are denied, never allowed). For several replicas or the HPA, use
PostgreSQL. `postgres.enabled` sets both `state.backend: postgres` and `events.backend: postgres`
(LISTEN/NOTIFY on the same database, so an approval decided on one replica reaches the request
waiting on another), and the chart sets `deployment.replicas`, which makes scrim itself refuse to
start with more than one replica on anything else:

```yaml
postgres:
  enabled: true
secrets:
  existing:
    postgres: scrim-pg            # key dsn: postgres://user:pass@host/db?sslmode=verify-full
central:
  pdb: {minAvailable: 1}
  autoscaling:
    enabled: true
    minReplicas: 2
    maxReplicas: 10
```

`global.ha.enabled` is the shortcut: `global.ha.replicas` (2) replicas, a PDB that keeps one,
preferred anti-affinity on the node and a zone spread (ScheduleAnyway, so a single-zone cluster
still schedules). It needs `postgres.enabled` like any other replica count above one. The chart
refuses more than one replica, the HPA or `global.ha` without `postgres.enabled`, and an HPA with
`minReplicas` below 2. Replicas share the
CA and the placeholder keys through their Secrets, so any replica produces and resolves the same
placeholders.

`central.autoscaling.connections` adds a Pods metric of open data plane connections per replica,
`scrim_dataplane_connections_active` summed over its `listener` label
([monitoring.md](monitoring.md)), for a metrics adapter such as prometheus-adapter to serve. It
needs `metrics.enabled`. CPU alone works without an adapter.

## Metrics and monitoring

The health endpoints (`/livez`, `/readyz`) are always served on port 9792 for the probes.
`metrics.enabled` exposes `/metrics` there through the Service, turns on scrim's `metrics.enabled`
setting and opens the NetworkPolicy to `networkPolicy.prometheus`. Then, each off by default:

| Value | Creates |
| --- | --- |
| `serviceMonitor.enabled` | a ServiceMonitor for central scrim |
| `podMonitor.enabled` | a PodMonitor per agent namespace for sidecars |
| `prometheusRule.enabled` | a PrometheusRule with the alert rules of `deploy/monitoring/rules/scrim.rules.yaml` plus `prometheusRule.groups` |
| `grafanaDashboard.enabled` | a ConfigMap with `deploy/monitoring/grafana/scrim-dashboard.json`, labelled `grafana_dashboard: "1"` for the Grafana sidecar |

The chart carries copies of the rules and the dashboard in `deploy/helm/scrim/monitoring/`, since
Helm cannot read files outside the chart; `just helm-test` fails when they differ from
`deploy/monitoring/`. Metric meanings and alert runbooks are in [monitoring.md](monitoring.md).

The metrics listener is on the pod IP, so scrim requires a bearer token there:
the Secret slot `metrics` (key `token`) becomes `metrics.auth.token`, and the monitors present the
same Secret. The chart generates the token on first install and keeps it; `secrets.existing.metrics`
or an ExternalSecret supplies your own. `metrics.allowUnauthenticatedRemote` drops the token and
turns on scrim's weakening `metrics.allow-unauthenticated-remote` (logged at start-up and in `scrim
status`); pair that with `networkPolicy.enabled`, so only `networkPolicy.prometheus` reaches the
port. In sidecar mode the token Secret must exist in every agent namespace, so the chart wants
`secrets.existing.metrics` there.

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
| agent gets `403 policy_denied ... rule default` | the agent was not started through `scrim-exec`, or its token was refused (scrim's log has `caller=refused` and the reason); see [Identity](#identity) |
| scrim logs `tokenreviews.authentication.k8s.io is forbidden` | `identity.kubernetes.tokenReviewRBAC` is off, or the binding names another service account |
| TokenReview times out | `networkPolicy.apiServerEgress` does not match the API server's endpoint address and port |
| pod in CrashLoopBackOff, log names a redact target | the target matches no secret; fix the path or pattern ([Install](#install)) |
| TLS errors in the agent | the pod lacks the `scrim-ca` mount or the variables (label, namespace listed, Kyverno running), or the runtime ignores them ([CA trust per runtime](interception.md#ca-trust-per-runtime)) |
| TLS errors in scrim toward a tool host | the host's CA is private: `upstreamCA` |
| agent reaches a provider directly | the CNI does not enforce NetworkPolicy, or the pod lacks the label; in sidecar mode the guard is off or the agent runs as UID 65532 |
| labelled pod refused at creation | the namespace is not in `agents.namespaces`, or the label value is not an enabled mode |
| sidecar pod stuck in `Init` | `kubectl logs <pod> -c scrim-egress-guard` and `-c scrim`; the CA and key Secrets must exist in the agent namespace |

## Testing

`just helm-test` runs `deploy/helm/scrim/ci/verify.sh`, the chart's whole gate, the same in CI:

- the generated files are current: `values.schema.json` and `docs/helm-values.schema.json`
  (`ci/gen-schema.py`), [helm-values.md](helm-values.md) (helm-docs), Chart.yaml's
  `artifacthub.io/images` (`ci/gen-images.py`) and the chart's copies of `deploy/monitoring`;
  `just helm-generate` rewrites them;
- `helm lint --strict`, `helm template` and `kubeconform -strict` (CRDs from the datreeio
  catalog) for the defaults, every example and every `ci/*-values.yaml` case, with
  `ci/assert-all-features.py` and `ci/assert-ha.py` on theirs, and the Flux example;
- every rendered pod, and every container the Kyverno policy injects, against Pod Security
  "restricted" with requests and a memory limit (`ci/check-pods.py`); the egress guard is the one
  documented exception;
- `promtool check rules` on the PrometheusRule;
- the helm-unittest suites in `deploy/helm/scrim/tests` (every template and every refusal);
- `test/k8s/golden.sh`: golden `helm template` output of `test/k8s/golden/cases`, the refusals in
  `test/k8s/golden/fail`, `scrim config validate` on every configuration a case renders, and
  `scrim-exec` under `sh` with a fake token;
- the upgrade check against the newest release tag that has the chart (`ci/upgrade-check.sh`);
- `helm package`.

`just helm-tools` installs the pinned tools (helm, kubeconform, helm-docs, ct, kind, kubectl,
promtool, the helm-unittest plugin) into `bin/helm-tools`. CI runs the gate on Helm 3 and Helm 4,
`ct lint`, and `ci/kind-test.sh`: `ct install` of `ci/install-values.yaml` with the image built
from the commit, `helm test`, and an upgrade from the previous chart once a release has one.
`just helm-render-diff` shows what an existing install would see change against a git ref.

`just k8s-e2e` (`test/k8s/e2e.sh`) creates a kind cluster on rootless podman
(`KIND_EXPERIMENTAL_PROVIDER=podman`) with Calico, installs Kyverno, OpenBao in dev mode, the fake
model provider, a TLS tool host and the chart, then starts one agent pod per mode and asserts:

- scrim and every sidecar log in to OpenBao with their own service account token, with no static
  store credential;
- the provider receives placeholders, never the secret the agent sent, nor the agent's token;
- the agent cannot reach the provider or the tool host directly;
- an agent command run through `scrim-exec` is identified with TokenReview, and the built-in rule
  injects the credential toward its bound host, while the same request without `scrim-exec` gets
  nothing; the agent gets the placeholder back;
- a placeholder sent toward an unbound name of the same server is refused and nothing reaches it;
- no secret value or agent token is in scrim's logs, and Kyverno refuses a labelled pod in an
  unprepared namespace.

It uses its own kubeconfig in a temporary directory and removes the cluster, its images and the
`kind` network it created. It needs about 10 GB of free disk while it runs. `SCRIM_K8S_KEEP=1` keeps the cluster for
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
- The chart lives in `oci://ghcr.io/heliopsy/charts/scrim` from the first release after it
  merged; earlier releases have no chart.
- A standalone `scrim-dataplane` sidecar with a remote control plane (no transport is specified).
- Agents that cannot be started through a shell launcher get no identity. A long-running agent
  keeps the token it started with ([Identity](#identity)).
