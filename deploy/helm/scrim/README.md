# scrim Helm chart

Deploys [scrim](https://github.com/Heliopsy/scrim) in Kubernetes: a central `scrim proxy`
Deployment that agent pods reach over a Service, an optional in-pod scrim (sidecar mode), a Kyverno
policy that configures labelled agent pods, and NetworkPolicies that keep agent pods from reaching
providers except through scrim. The full guide is [docs/kubernetes.md](../../../docs/kubernetes.md).

The chart is not published to a registry yet; install it from a checkout:

```sh
helm install scrim deploy/helm/scrim -n scrim --create-namespace -f values.yaml
```

Kubernetes 1.29 or later (sidecar mode uses native sidecar containers). NetworkPolicy needs a CNI
that enforces it (Calico, Cilium, Antrea, kube-network-policies; not kindnet before 0.24 or plain
flannel). The Kyverno policy needs Kyverno 1.13 or later.

## What it creates

| Resource | When | Purpose |
| --- | --- | --- |
| Deployment, Service, PodDisruptionBudget, ServiceAccount | `central.enabled` (default) | `scrim proxy` with the LLM base URL (9790), forward proxy (9791) and health/metrics (9792) |
| HorizontalPodAutoscaler | `central.autoscaling.enabled` | CPU and, with a metrics adapter, open data plane connections per replica |
| ConfigMap `<release>-scrim-config` | central | `config.yaml` from `config`, `chart.yaml` with the settings the chart owns, `policy.yaml` from `policyRules` |
| Secret `<release>-scrim-ca` | `ca.create` (default) | the interception CA, generated once and kept |
| Secret `<release>-scrim-placeholder-keys` | `placeholderKeys.create` (default) | the placeholder key every replica shares |
| ConfigMap `scrim-ca` | release namespace and every `agents.namespaces` entry | the CA certificate for agents: `scrim-ca.pem`, `ca-bundle.pem`, and the `scrim-exec` launcher with `identity.kubernetes.enabled` |
| ConfigMap `<release>-scrim-agent-env` | every agent namespace, central | the agent environment, for `envFrom` without Kyverno |
| ConfigMaps and Secrets `*-sidecar-*`, `*-agent-env-sidecar` | every agent namespace, `sidecar.enabled` | the in-pod scrim's configuration, CA and keys |
| ClusterPolicy | `kyverno.enabled` | injects labelled pods, refuses them outside the prepared namespaces |
| NetworkPolicies | `networkPolicy.enabled` | scrim's ingress and egress, agent pods' egress |
| ServiceMonitor, PodMonitor, PrometheusRule, dashboard ConfigMap | their `enabled` values, with `metrics.enabled` | Prometheus Operator and Grafana |
| ClusterRole and ClusterRoleBinding `<release>-scrim-<namespace>-tokenreview` | `identity.kubernetes.enabled` (default) | create TokenReviews only, for scrim's service account and, in sidecar mode, the service accounts of the agent namespaces |

## Secrets are references

`config` is scrim's own configuration file format. Settings that hold a credential take a reference
(`file:`, `env:`, `cred:` or a store reference), never a value, and the chart refuses a literal in
the credential fields of `config.stores`, in `config.admin.token` and in
`config.identity.store-credentials`. Mount the Secrets that hold them with `secretMounts` and
reference the files. Better still, let scrim log in to the store with its own service account
(`storeAuth`, below), so no static store credential exists.

The chart refuses `config.state`, `config.events`, `config.deployment`, `config.metrics` and
`config.identity.kubernetes`: it sets them from the `postgres`, `central`, `metrics` and
`identity` values. Static credentials look like this:

```yaml
secretMounts:
  - name: bao
    secretName: scrim-openbao-approle      # keys role-id, secret-id
config:
  stores:
    bao:
      kind: openbao
      address: https://bao.example.com:8200
      auth: {method: approle}
      role-id: file:/run/secrets/scrim/bao/role-id
      secret-id: file:/run/secrets/scrim/bao/secret-id
      redact: ["bao://kv/agents/*"]
```

The PostgreSQL DSN (`postgres.dsnSecret`), the admin token (`admin.tcp.tokenSecret`) and the
metrics token (`metrics.authSecret`) are Secret references in values; the chart mounts them and
writes the `file:` reference itself.

## Store login with scrim's service account

With `storeAuth.serviceAccountToken.enabled`, scrim (and every sidecar) gets a projected token for
the store's audience at `storeAuth.serviceAccountToken.path`, and the store logs scrim in with it
(OpenBao Kubernetes auth, Infisical Kubernetes auth). Per-agent store checks with the calling pod's
own token go in `config.identity.store-login`:

```yaml
storeAuth:
  serviceAccountToken: {enabled: true, audience: openbao}
config:
  stores:
    bao:
      kind: openbao
      address: https://bao.example.com:8200
      auth:
        method: kubernetes            # Infisical: kubernetes-auth with auth.kubernetes.identity-id
        kubernetes: {role: scrim, token-file: /var/run/secrets/scrim/store-token}
      redact: ["bao://kv/agents/*"]
  identity:
    store-login:
      bao: "kubernetes role:{namespace}-{service_account}"
```

## Redact targets

Every store needs `redact` targets that match at least one secret on the first load. A target
that matches nothing stops scrim at start-up with an error naming it (a pod in CrashLoopBackOff),
because redaction would protect nothing; `redaction.allow-empty-targets: true` in `config` starts
anyway and reports the target as degraded. The chart's default `config` has no store, so nothing
is redacted until you configure one.

## Agent identity

`identity.kubernetes.enabled` (default on) gives every labelled agent container a projected token
for `identity.kubernetes.audience` at `identity.kubernetes.tokenPath`, `SCRIM_K8S_TOKEN_FILE`
naming it, and the launcher `<agents.trustPath>/scrim-exec`. Run the agent through it:

```yaml
containers:
  - name: agent
    command: [/etc/scrim/trust/scrim-exec, claude, --print, "..."]
```

`scrim-exec` reads the token and puts it where scrim expects a caller's token (design D14): as the
password of the proxy user `k8s` in `HTTPS_PROXY` and the other proxy variables, and as
`x-scrim-session` in `ANTHROPIC_CUSTOM_HEADERS` for the base URL. scrim verifies it with
TokenReview, so the built-in rule injects credentials toward their bound hosts for that agent. A
process started without it is an unknown caller: redaction applies, injection does not. It needs
`/bin/sh` in the agent image.

## Values

| Key | Default | Description |
| --- | --- | --- |
| `nameOverride` | `""` | Overrides the chart name in resource names. |
| `fullnameOverride` | `""` | Overrides the full resource name prefix (default: release name, plus "-scrim" unless it already contains it). |
| `commonLabels` | `{}` | Labels added to every resource. |
| `clusterDomain` | `"cluster.local"` | Kubernetes cluster DNS domain, used in the Service addresses agents get. |
| `image.repository` | `"ghcr.io/heliopsy/scrim"` | scrim image (control plane with the data plane embedded). |
| `image.tag` | `""` | Image tag; empty means the chart's appVersion. |
| `image.digest` | `""` | Image digest (sha256:...); when set it is used instead of the tag. |
| `image.pullPolicy` | `"IfNotPresent"` | Image pull policy. |
| `imagePullSecrets` | `[]` | Pull secrets for the scrim image, by name. |
| `config` | `{}` | scrim configuration, the same file format as `scrim --config` (apiVersion and kind are added). Secret-valued settings take references (env:, file:, cred:, a store reference), never literals; the chart refuses known credential fields that hold a literal. Settings the chart owns (listeners, sockets, state, events, identity, metrics, CA, placeholder keys) are set in a second file that wins. Every store needs `redact` targets that match at least one secret: a target that loads nothing stops start-up (redaction.allow-empty-targets weakens that). |
| `existingConfigMap` | `""` | Name of an existing ConfigMap holding the scrim configuration under `config.yaml`, used instead of `config`. |
| `policyRules` | `{}` | Policy rules file (YAML object with `default` and `rules`, see docs/policy.md). Empty means no rules file: built-in defaults apply. |
| `secretMounts` | `[]` | Secrets mounted read-only into scrim at /run/secrets/scrim/<name>/<key>, for `file:` references in `config`. Each item: {name, secretName, items (optional, as in a Secret volume)}. |
| `extraEnv` | `[]` | Extra environment variables for the scrim container (use valueFrom.secretKeyRef with `env:` references; never put secret values here). |
| `extraVolumes` | `[]` | Extra volumes for the scrim pod (central mode). |
| `extraVolumeMounts` | `[]` | Extra volume mounts for the scrim container (central mode). |
| `log.level` | `"info"` | Log level: debug, info, warn or error. |
| `log.format` | `"json"` | Log format: json or text. |
| `upstreamCA.configMap` | `""` | ConfigMap in the release namespace with a PEM bundle of extra roots for upstream TLS (private tool hosts, corporate TLS inspection). System and Mozilla roots stay trusted. |
| `upstreamCA.key` | `"ca.crt"` | Key of the bundle in that ConfigMap. |
| `ca.create` | `true` | Generate a CA with Helm on first install and keep it (Secret with helm.sh/resource-policy: keep, reused on upgrade through lookup). Ed25519, PKCS#8. Ignored when existingSecret is set. |
| `ca.validityDays` | `730` | Validity of a generated CA in days. |
| `ca.existingSecret` | `""` | Existing kubernetes.io/tls Secret with the CA: `tls.crt` and a PKCS#8 `tls.key` (cert-manager: privateKey.encoding PKCS8). scrim never rotates it. |
| `ca.certificate` | `""` | PEM certificate of existingSecret, published to agents. Empty reads it from the Secret with lookup at install time (not available to `helm template`). |
| `ca.extraTrustedCerts` | `""` | Extra PEM certificates appended to the agents' ca-bundle.pem (for cluster services agents reach outside the proxy). |
| `ca.configMapName` | `"scrim-ca"` | Name of the ConfigMap with the public CA (scrim-ca.pem, ca-bundle.pem) in the release namespace and every agent namespace. |
| `placeholderKeys.create` | `true` | Generate a 64-byte key on first install and keep it (reused on upgrade through lookup). Ignored when existingSecret is set. |
| `placeholderKeys.existingSecret` | `""` | Existing Secret holding the keys. |
| `placeholderKeys.keys` | `[{"name": "k1", "version": 1, "key": "k1"}]` | Keys of existingSecret: list of {name, version, key} (key = data key in the Secret). The highest version is current. |
| `postgres.enabled` | `false` | Use PostgreSQL for state (approvals, grants, sessions) and for events between replicas (LISTEN/NOTIFY). Off: in-memory state in one replica; a restart loses approvals and grants. |
| `postgres.dsnSecret` | `{"name": "", "key": "dsn"}` | Secret holding the DSN (postgres://user:pass@host/db?sslmode=verify-full). |
| `postgres.maxConns` | `16` | Connection pool size per replica. |
| `serviceAccount.create` | `true` | Create a ServiceAccount for scrim. |
| `serviceAccount.name` | `""` | Name; empty means the full name. |
| `serviceAccount.annotations` | `{}` | Annotations (for cloud workload identity toward stores). |
| `serviceAccount.automountToken` | `false` | Mount the API token even without identity.kubernetes (identity mounts it anyway, for TokenReview). |
| `identity.kubernetes.enabled` | `true` | Identify agent pods by their projected token. Renders the TokenReview RBAC, mounts scrim's own API token and gives agent pods the token, SCRIM_K8S_TOKEN_FILE and the scrim-exec launcher. Off: every agent pod is an unknown caller, which the built-in rules do not inject credentials for. |
| `identity.kubernetes.audience` | `"scrim"` | Audience of the projected agent token (identity.kubernetes.audience); tokens with another audience, such as the pod's default API token, are refused. |
| `identity.kubernetes.expirationSeconds` | `3600` | Lifetime of the projected agent token in seconds. The kubelet rotates the file, but scrim-exec reads it when the agent starts: an agent process that runs longer than this loses its identity (injection is refused) until it is restarted. |
| `identity.kubernetes.tokenPath` | `"/var/run/secrets/scrim/token"` | Where the token is mounted in agent containers. |
| `identity.kubernetes.tokenReviewRBAC` | `true` | Create a ClusterRole that may only create TokenReviews and bind it to scrim's service account (central) and to the service accounts of agents.namespaces (sidecar). |
| `identity.kubernetes.agents` | `{}` | Agents by service account (identity.kubernetes.agents): agent name to selectors `sa:NAMESPACE/NAME` (globs allowed), `scope:`, `label:K=V`. |
| `identity.kubernetes.unmapped` | `"derive"` | What a service account no rule maps becomes: derive (NAMESPACE/NAME) or unknown. |
| `storeAuth.serviceAccountToken` | `see values.yaml` | Mount a projected service account token for store login (central scrim and sidecars). |
| `storeAuth.serviceAccountToken.audience` | `"vault"` | Audience the store expects (OpenBao: the role's audience, often "vault"). |
| `storeAuth.serviceAccountToken.expirationSeconds` | `3600` | Lifetime in seconds. scrim reads the file again at every login. |
| `storeAuth.serviceAccountToken.path` | `"/var/run/secrets/scrim/store-token"` | Mount path; reference it as `auth.kubernetes.token-file` in the store configuration. |
| `central.enabled` | `true` | Deploy the central scrim. |
| `central.replicaCount` | `1` | Replicas when autoscaling is off. More than one needs postgres.enabled. |
| `central.strategy` | `see values.yaml` | Deployment update strategy. |
| `central.resources` | `see values.yaml` | Resources of the scrim container. |
| `central.podAnnotations` | `{}` | Pod annotations. |
| `central.podLabels` | `{}` | Pod labels. |
| `central.podSecurityContext` | `see values.yaml` | Pod security context. |
| `central.securityContext` | `see values.yaml` | Container security context. |
| `central.terminationGracePeriodSeconds` | `30` | Grace period; scrim finishes in-flight requests for up to 15s on SIGTERM. |
| `central.livenessProbe` | `see values.yaml` | Liveness probe on /livez. |
| `central.readinessProbe` | `see values.yaml` | Readiness probe on /readyz (the data plane holds a snapshot and every listener is bound). |
| `central.startupProbe` | `see values.yaml` | Startup probe on /livez. |
| `central.nodeSelector` | `{}` | Node selector. |
| `central.tolerations` | `[]` | Tolerations. |
| `central.affinity` | `{}` | Affinity. |
| `central.topologySpreadConstraints` | `[]` | Topology spread constraints. |
| `central.priorityClassName` | `""` | Priority class. |
| `central.service.type` | `"ClusterIP"` | Service type. Keep ClusterIP: the listeners serve plain HTTP and the forward proxy. |
| `central.service.annotations` | `{}` | Service annotations. |
| `central.service.llmPort` | `9790` | LLM base URL port (agents use http://<service>:<port>/anthropic and /openai/v1). |
| `central.service.forwardPort` | `9791` | Forward proxy port (HTTPS_PROXY). |
| `central.pdb.enabled` | `true` | Create a PodDisruptionBudget. |
| `central.pdb.maxUnavailable` | `1` | maxUnavailable (used when minAvailable is empty). |
| `central.pdb.minAvailable` | `""` | minAvailable; set it instead of maxUnavailable with several replicas. |
| `central.autoscaling.enabled` | `false` | Create a HorizontalPodAutoscaler (needs postgres.enabled). |
| `central.autoscaling.minReplicas` | `2` | Fewest replicas. |
| `central.autoscaling.maxReplicas` | `10` | Most replicas. |
| `central.autoscaling.targetCPUUtilizationPercentage` | `70` | Target average CPU utilisation in percent; empty disables the CPU metric. |
| `central.autoscaling.connections.enabled` | `false` | Add the connections metric. |
| `central.autoscaling.connections.metricName` | `"scrim_dataplane_connections_active"` | Metric name as the adapter exposes it. |
| `central.autoscaling.connections.targetAverageValue` | `"50"` | Target average open connections per replica. |
| `central.autoscaling.behavior` | `{}` | HPA scaling behavior. |
| `admin.tcp.enabled` | `false` | Serve the admin API on a TCP port of the Service. |
| `admin.tcp.port` | `9793` | Port. |
| `admin.tcp.tokenSecret` | `{"name": "", "key": "token"}` | Secret with the bearer token (at least 16 bytes). |
| `metrics.enabled` | `false` | Expose metrics (Service port, monitors, NetworkPolicy scrape rule) and turn on scrim's metrics.enabled setting. |
| `metrics.port` | `9792` | Port of the metrics and health listener (metrics.listen on the pod IP). |
| `metrics.path` | `"/metrics"` | Metrics path (metrics.path). |
| `metrics.authSecret` | `{"name": "", "key": "token"}` | Secret with a bearer token (at least 16 bytes) scrapers must present (metrics.auth.token). Required with metrics.enabled unless allowUnauthenticatedRemote is set. |
| `metrics.allowUnauthenticatedRemote` | `false` | Serve metrics without a token (metrics.allow-unauthenticated-remote, a weakening scrim logs at start-up): anyone who reaches the port reads them. Pair it with networkPolicy. |
| `serviceMonitor.enabled` | `false` | Create a Prometheus Operator ServiceMonitor for central scrim (needs metrics.enabled). |
| `serviceMonitor.labels` | `{}` | Extra labels (for the Prometheus serviceMonitorSelector). |
| `serviceMonitor.interval` | `"30s"` | Scrape interval. |
| `serviceMonitor.scrapeTimeout` | `"10s"` | Scrape timeout. |
| `podMonitor.enabled` | `false` | Create a PodMonitor per agent namespace for sidecars (needs metrics.enabled and sidecar.enabled). |
| `podMonitor.labels` | `{}` | Extra labels. |
| `podMonitor.interval` | `"30s"` | Scrape interval. |
| `prometheusRule.enabled` | `false` | Create a PrometheusRule from the chart's monitoring/scrim.rules.yaml (a copy of deploy/monitoring/rules/scrim.rules.yaml) plus `groups`. |
| `prometheusRule.labels` | `{}` | Extra labels. |
| `prometheusRule.groups` | `[]` | Extra rule groups. |
| `grafanaDashboard.enabled` | `false` | Create a ConfigMap with the dashboard JSON, labelled for the Grafana sidecar. |
| `grafanaDashboard.labels` | `{"grafana_dashboard": "1"}` | Labels; the Grafana sidecar picks up grafana_dashboard: "1" by default. |
| `grafanaDashboard.annotations` | `{}` | Annotations (for example grafana_folder). |
| `grafanaDashboard.json` | `""` | Dashboard JSON; empty uses the chart's monitoring/scrim-dashboard.json (a copy of deploy/monitoring/grafana/scrim-dashboard.json). |
| `agents.label` | `"scrim.dev/inject"` | Label that marks agent pods. Value `central` uses the central Service, `sidecar` adds an in-pod scrim. |
| `agents.namespaces` | `[]` | Namespaces agent pods run in. The chart creates the public CA ConfigMap, the agent env ConfigMaps, NetworkPolicies and sidecar resources there before any pod starts. |
| `agents.noProxy` | `[]` | Extra NO_PROXY entries for agents (hosts reached without scrim; they also need a NetworkPolicy egress rule). |
| `agents.extraEnv` | `[]` | Extra environment variables for agent containers. |
| `agents.trustPath` | `"/etc/scrim/trust"` | Mount path of the CA files in agent containers. |
| `kyverno.enabled` | `false` | Install the ClusterPolicy (needs Kyverno 1.13 or later). |
| `kyverno.failurePolicy` | `"Fail"` | Refuse labelled pods when Kyverno cannot process them. |
| `networkPolicy.enabled` | `false` | Create NetworkPolicies (needs a CNI that enforces them). |
| `networkPolicy.dns` | `see values.yaml` | Pod and namespace selectors of the cluster DNS. |
| `networkPolicy.scrimEgress` | `[{"ports": [{"port": 443, "protocol": "TCP"}]}]` | Egress rules of central scrim besides DNS (providers, stores, tool hosts, PostgreSQL). The default allows HTTPS anywhere. |
| `networkPolicy.apiServerEgress` | `see values.yaml` | Egress to the Kubernetes API server, for TokenReview (identity.kubernetes) from central scrim and sidecar pods. Policies see the API server's endpoint port, often 6443, not the Service port. Narrow it with `to` (the API server's addresses) where you can. |
| `networkPolicy.sidecarEgress` | `[{"ports": [{"port": 443, "protocol": "TCP"}]}]` | Egress rules of sidecar agent pods besides DNS (what the in-pod scrim must reach). |
| `networkPolicy.prometheus` | `see values.yaml` | Where Prometheus scrapes from (used when metrics.enabled). |
| `networkPolicy.adminFrom` | `[]` | Peers allowed to the admin TCP port (NetworkPolicy `from` entries). |
| `sidecar.enabled` | `false` | Render the per-namespace sidecar resources and the sidecar injection rule. |
| `sidecar.resources` | `see values.yaml` | Resources of the sidecar. |
| `sidecar.securityContext` | `see values.yaml` | Container security context of the sidecar (it runs as UID 65532; the egress guard lets only that UID out). |
| `sidecar.secretMounts` | `[]` | Secrets (that must exist in every agent namespace) mounted into the sidecar, as secretMounts. |
| `sidecar.caSecretName` | `"scrim-sidecar-ca"` | Name of the CA Secret in agent namespaces. Created by the chart when ca.create is on; otherwise provide it in each namespace. |
| `sidecar.keysSecretName` | `"scrim-sidecar-keys"` | Name of the placeholder key Secret in agent namespaces (same rule as caSecretName). |
| `sidecar.egressGuard.enabled` | `true` | Install the guard. Without it the agent can reach whatever the pod's NetworkPolicy allows. |
| `sidecar.egressGuard.image` | `""` | Image with the `nft` binary and a shell, required when enabled. |
| `sidecar.egressGuard.pullPolicy` | `"IfNotPresent"` | Pull policy. |

## Tests

`just helm-test` runs `helm lint` and the golden tests in `test/k8s/golden` (`helm template` of
each case compared with its expected output, and the values the chart must refuse).
`just k8s-e2e` runs the end-to-end test in kind on rootless podman
([docs/kubernetes.md](../../../docs/kubernetes.md#testing)).
