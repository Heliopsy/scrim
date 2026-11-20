# Helm

The chart in [`deploy/helm/scrim`](../../deploy/helm/scrim/) deploys scrim in central mode (a
Deployment behind a Service) or sidecar mode (a scrim inside each agent pod), with Kyverno
injection by label, NetworkPolicies, PostgreSQL state and autoscaling. This page is a set of values
files to start from; [kubernetes.md](../kubernetes.md) is the reference for what the chart does and
the [chart README](../../deploy/helm/scrim/README.md) lists every value.

Files: [`deploy/examples/kubernetes/helm/`](../../deploy/examples/kubernetes/helm/).

## Prerequisites

- Kubernetes 1.29 or later, Helm 3 or 4.
- Kyverno 1.13 or later for injection by label, a CNI that enforces NetworkPolicy, PostgreSQL for
  more than one replica.
- The chart from a release tag that contains it: no chart repository or OCI chart is published
  yet, so install from a checkout.

```sh
git clone --branch v0.2.0 --depth 1 https://github.com/Heliopsy/scrim
cd scrim
```

## Values files

Each file covers one concern. Combine them with several `-f`; later files win.

| File | What it sets |
| --- | --- |
| [`values-central.yaml`](../../deploy/examples/kubernetes/helm/values-central.yaml) | central mode, OpenBao as the store with its token from a Secret, the GitHub catalog entry, an injection rule for agent pods |
| [`values-injection.yaml`](../../deploy/examples/kubernetes/helm/values-injection.yaml) | the Kyverno policy that configures pods labelled `scrim.dev/inject: central` |
| [`values-networkpolicy.yaml`](../../deploy/examples/kubernetes/helm/values-networkpolicy.yaml) | agent pods reach only scrim and DNS; scrim reaches HTTPS, OpenBao and PostgreSQL |
| [`values-postgres.yaml`](../../deploy/examples/kubernetes/helm/values-postgres.yaml) | PostgreSQL state, an HPA from 2 to 6 replicas, spread over nodes |
| [`values-sidecar.yaml`](../../deploy/examples/kubernetes/helm/values-sidecar.yaml) | sidecar mode with the nftables egress guard, central off |
| [`values-gitops.yaml`](../../deploy/examples/kubernetes/helm/values-gitops.yaml) | the CA and placeholder key from existing Secrets, for tools that render with `helm template` (Argo CD) |

Secret values never go into values. Credentials are `file:` references to Secrets the chart mounts
(`secretMounts`, `state.postgres.dsnSecret`), and the chart refuses a literal in the credential
fields of `config.stores`. The CA and the placeholder key are generated on first install and kept
across upgrades; to bring your own, set `ca.existingSecret` and `placeholderKeys.existingSecret`.

## Central mode

```sh
CONTEXT=my-cluster
kubectl --context "$CONTEXT" create namespace scrim
kubectl --context "$CONTEXT" -n scrim create secret generic scrim-openbao --from-file=token=./bao-token
kubectl --context "$CONTEXT" -n scrim create secret generic scrim-postgres --from-file=dsn=./dsn
EX=deploy/examples/kubernetes/helm
helm --kube-context "$CONTEXT" upgrade --install scrim deploy/helm/scrim -n scrim \
  -f "$EX/values-central.yaml" -f "$EX/values-injection.yaml" \
  -f "$EX/values-networkpolicy.yaml" -f "$EX/values-postgres.yaml"
```

Delete `bao-token` and `dsn` once the Secrets exist, or create the Secrets with SOPS or External
Secrets instead ([gitops-secrets.md](gitops-secrets.md)).

Agent pods then need only the label:

```yaml
metadata:
  namespace: agents
  labels:
    scrim.dev/inject: central
```

Kyverno adds the base URLs, `HTTPS_PROXY`, `NO_PROXY` and the CA bundle when the pod is created.
Without Kyverno, reference the ConfigMap `scrim-agent-env` the chart writes into each agent
namespace ([kubernetes.md](../kubernetes.md#without-kyverno)).

### Credential injection for agent pods

Agent pods reach scrim over TCP without a `scrim run` session, so scrim sees them as unknown
callers. Provider requests are redacted for every caller, but the built-in injection rule serves
only identified agents. `values-central.yaml` therefore carries a policy rule:

```yaml
policyRules:
  rules:
    - name: agents-github-read
      decision: allow
      when: op == "inject" && secret.name == "github" && dest.method in ["GET", "HEAD"]
```

It applies to every caller that can reach scrim, which the NetworkPolicy narrows to labelled pods
in the agent namespaces. Per-pod identity from service account tokens (`identity.kubernetes`) and
store login with scrim's own service account (`storeAuth`) come with the Kubernetes identity
release; the chart's values for them are in place, and the reference is
[kubernetes.md](../kubernetes.md#identity).

## Sidecar mode

```sh
podman build -t registry.example.com/platform/nft:3.22 "$EX/egress-guard"
podman push registry.example.com/platform/nft:3.22
helm --kube-context "$CONTEXT" upgrade --install scrim deploy/helm/scrim -n scrim -f "$EX/values-sidecar.yaml"
kubectl --context "$CONTEXT" -n agents create secret generic scrim-openbao --from-file=token=./bao-token
```

Label agent pods `scrim.dev/inject: sidecar`. Each one gets its own scrim as a native sidecar and an
init container that installs the egress guard; the namespace needs Pod Security `privileged` (or
an exemption) for that init container's `NET_ADMIN`. The store token must exist in every agent
namespace, which is why central mode is the default.

## Verify

```sh
CONTEXT=my-cluster
timeout 30 helm --kube-context "$CONTEXT" -n scrim status scrim
timeout 30 kubectl --context "$CONTEXT" -n scrim rollout status deploy/scrim
timeout 30 kubectl --context "$CONTEXT" -n scrim exec deploy/scrim -- scrim status
timeout 30 kubectl --context "$CONTEXT" -n scrim exec deploy/scrim -- scrim doctor
```

A labelled pod shows the injected environment:

```sh
timeout 60 kubectl --context "$CONTEXT" -n agents run scrim-canary --rm -i --restart=Never \
  --labels scrim.dev/inject=central --image=docker.io/curlimages/curl:8.17.0 -- \
  sh -c 'echo "$ANTHROPIC_BASE_URL"; curl -s -o /dev/null -w "%{http_code}\n" "$ANTHROPIC_BASE_URL/v1/messages" \
    -H "x-api-key: not-a-real-key" -H "anthropic-version: 2023-06-01" -H "content-type: application/json" \
    -d "{\"model\":\"claude-sonnet-4-5\",\"max_tokens\":16,\"messages\":[{\"role\":\"user\",\"content\":\"canary\"}]}"'
```

It prints `http://scrim.scrim.svc.cluster.local:9790/anthropic` and `401`, Anthropic refusing the
fake key behind scrim. With `values-networkpolicy.yaml`, the same pod calling
`https://api.anthropic.com` directly gets no connection.

## Upgrade and roll back

```sh
git -C scrim fetch --tags && git -C scrim checkout v0.2.1
helm --kube-context "$CONTEXT" upgrade scrim scrim/deploy/helm/scrim -n scrim --reuse-values
helm --kube-context "$CONTEXT" -n scrim history scrim
helm --kube-context "$CONTEXT" -n scrim rollback scrim <revision>
```

The chart's `appVersion` is the image tag unless `image.tag` or `image.digest` is set; pin
`image.digest` to the digest `cosign verify` printed for production. A rollback across a
PostgreSQL schema change needs the database restored too.

## Uninstall

```sh
helm --kube-context "$CONTEXT" -n scrim uninstall scrim
kubectl --context "$CONTEXT" -n scrim delete secret scrim-openbao scrim-postgres
kubectl --context "$CONTEXT" delete namespace scrim
```

The CA and placeholder key Secrets have `helm.sh/resource-policy: keep` and survive the uninstall,
so a reinstall keeps the agents' CA trust; deleting the namespace removes them.
