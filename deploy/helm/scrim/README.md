# scrim Helm chart

Deploys [scrim](https://github.com/Heliopsy/scrim) in Kubernetes: a central `scrim proxy`
Deployment that agent pods reach over a Service, an optional in-pod scrim (sidecar mode), a Kyverno
policy that configures labelled agent pods, and NetworkPolicies that keep agent pods from reaching
providers except through scrim. The full guide is [docs/kubernetes.md](../../../docs/kubernetes.md).

Each scrim release publishes the chart at the release version, signed keyless like the images
(docs/kubernetes.md, Install, shows how to verify it):

```sh
helm install scrim oci://ghcr.io/heliopsy/charts/scrim --version <version> -n scrim --create-namespace -f values.yaml
helm test scrim -n scrim
```

From a checkout: `helm install scrim deploy/helm/scrim ...`. Every value is described in
[docs/helm-values.md](../../../docs/helm-values.md), generated from values.yaml; the closed schema
with descriptions is [docs/helm-values.schema.json](../../../docs/helm-values.schema.json).
`examples/production.yaml` and `examples/flux/` are places to start.

Kubernetes 1.29 or later (sidecar mode uses native sidecar containers). NetworkPolicy needs a CNI
that enforces it (Calico, Cilium, Antrea, kube-network-policies; not kindnet before 0.24 or plain
flannel). The Kyverno policy needs Kyverno 1.13 to 1.19.

## What it creates

| Resource | When | Purpose |
| --- | --- | --- |
| Deployment, Service, PodDisruptionBudget `<release>-scrim`, ServiceAccount `<release>-scrim-proxy` | `central.enabled` (default) | `scrim proxy` with the LLM base URL (9790), forward proxy (9791) and health/metrics (9792) |
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
| Secret `<release>-scrim-metrics` | `metrics.enabled`, no `secrets.existing.metrics` | the generated metrics bearer token, kept |
| ExternalSecrets `<release>-scrim-<slot>` | `secrets.externalSecrets` | the Secret slots from your secret store |
| ConfigMaps `<release>-scrim-<key>`, `extraObjects` | `extraConfigMaps`, `extraObjects` | your own objects, rendered through tpl |
| Pods `<release>-scrim-test-*` | `tests.enabled` (default), on `helm test` | the LLM listener and forward proxy answer through the Service; `/readyz` with metrics on |

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

The PostgreSQL DSN, the admin token and the metrics token are Secret slots (`postgres`, `admin`,
`metrics`): `secrets.existing.<slot>` names a Secret you manage, `secrets.externalSecrets.data.<slot>`
renders an ExternalSecret, and the metrics token alone is generated when neither is set. The chart
mounts the slot and writes the `file:` reference itself.

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

## Built from the chart template

The chart follows the Origami Corporation's chart template (toc-helm-chart-template): the shared
component library `templates/_component.tpl` (`chart.std.*`: ServiceAccount, container, pod
template, Deployment, Service, PDB, HPA, NetworkPolicy) and the helpers in
`templates/_helpers.tpl` (names, labels, image references with digest, Secret slots,
`extraConfigMaps`, `objectMetadata`, Reflector and kubernetes-replicator annotations),
`templates/_ha.tpl` (`global.ha`), `validate.yaml`, `extra-configmaps.yaml`, `extra-objects.yaml`,
`NOTES.txt`, helm test pods, the generated closed schema and values reference, helm-unittest
suites, `ci/verify.sh` as the one gate, `render-diff.sh`, the upgrade check and ct on kind. Central
scrim is rendered through `chart.std.component` with every extension hook (`extraArgs`,
`extraEnv`, `extraEnvFrom`, `extraVolumes`, `extraVolumeMounts`, `extraContainers`,
`extraInitContainers`, `central.networkPolicy.extraFrom` / `extraIngress` / `extraEgress`, the pod
options and `lifecycle`), and `global.*` defaults that `central.*` overrides.

Where scrim differs from the template, and why:

| Template | scrim | Why |
| --- | --- | --- |
| `secrets.values.<slot>`, `extraSecrets` and the registry pull Secret take values from values.yaml | left out | the chart takes no credential values at all (deployment spec, "Chart values hold no secrets"); use `secrets.existing`, ExternalSecrets or `secretMounts` |
| every object named `<fullname>-<component>` | the Deployment, Service, PDB, HPA and NetworkPolicy keep `<fullname>` (`chart.std.workload`, `service`, `pdb`, `hpa` and `networkPolicy` take a `name`) | agents reach `http://<release>-scrim.<namespace>.svc`; the ServiceAccount is `<fullname>-proxy` |
| `chart.std.hpa` scales on CPU and memory | also `extraMetrics` and `behavior` | the connections metric from a metrics adapter (`central.autoscaling.connections`) |
| `networkPolicies.*`, an optional namespace-wide default deny | `networkPolicy.*`, per-pod policies for scrim and for agent pods in every agent namespace, no namespace-wide deny | agent pods must reach scrim and DNS only, which is stricter and narrower than a default deny in scrim's namespace; the release namespace is often shared |
| ServiceMonitor and PodMonitor together fail the render | allowed; a ServiceMonitor without central scrim or a PodMonitor without sidecars fails | the ServiceMonitor scrapes central scrim and the PodMonitor the sidecars: they never scrape the same pod |
| every pod passes Pod Security "restricted" | every chart-rendered pod does, and so does the injected sidecar; the egress guard init container does not | it installs the nftables egress guard as root with `NET_ADMIN` and exits; `ci/check-pods.py` lists it as the one exception, and sidecar namespaces need `privileged` or an exemption |
| `global.ha` sets a PDB with `minAvailable: 1` | scrim's PDB is on by default with `maxUnavailable: 1`, which `global.ha` keeps | with two replicas both keep one; with one replica `minAvailable: 1` would block every node drain |
| `central.enableServiceLinks` null | `false` | other Services' addresses stay out of scrim's environment |
| CA, placeholder keys as generic generated slots | scrim's own generators (`ca.*`, `placeholderKeys.*`) | the same CA and key are copied into every agent namespace for sidecars, which a slot cannot do |
| the image pinned by digest | `image.digest` empty, the tag is the release's appVersion | the chart is released with the image of the same version; set `image.digest` to pin it |
| Renovate keeps digests and tool versions current | Dependabot (`ci/Containerfile.images` for the test image), tools pinned by version and sha256 in `ci/tools.sh` and `scripts/release/release.env` | scrim uses Dependabot, which cannot read values.yaml or workflow `env:` |
| a key-signed release with an optional keyless signature, git-cliff release notes | keyless only, with the images' identity, from scrim's release workflow; release-please versions the chart | one signing identity for every scrim artifact; no key to keep |
| proprietary licence | AGPL-3.0-only, like the rest of scrim | |

## Tests

`just helm-test` runs `ci/verify.sh`, the chart's whole gate (generated files, lint, kubeconform,
Pod Security, promtool, helm-unittest, the golden tests in `test/k8s/golden`, the upgrade check,
`helm package`); `just helm-tools` installs the pinned tools it needs and `just helm-generate`
rewrites the generated files after a values change. CI also runs `ct lint` and `ct install` on
kind. `just k8s-e2e` runs the end-to-end test in kind on rootless podman
([docs/kubernetes.md](../../../docs/kubernetes.md#testing)).
