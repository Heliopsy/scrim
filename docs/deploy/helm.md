# Helm

The chart in [`deploy/helm/scrim`](../../deploy/helm/scrim/) deploys scrim in central mode (a
Deployment behind a Service) or sidecar mode (a scrim inside each agent pod), with Kyverno
injection by label, Kubernetes identity for agent pods, NetworkPolicies, PostgreSQL state,
autoscaling and metrics. This page is a short path through it with values files to start from.
[kubernetes.md](../kubernetes.md) is the reference for what the chart does, and
[helm-values.md](../helm-values.md) lists every value.

Files: [`deploy/examples/kubernetes/helm/`](../../deploy/examples/kubernetes/helm/) and the chart's
own [`examples/`](../../deploy/helm/scrim/examples/).

## Prerequisites

- Kubernetes 1.29 or later, Helm 3.8 or later (OCI charts), cosign to check the chart signature.
- Kyverno 1.13 or later for injection by label, a CNI that enforces NetworkPolicy, PostgreSQL for
  more than one replica.
- A store scrim can log in to with its service account: OpenBao or Vault with Kubernetes auth, or
  Infisical with Kubernetes auth. Static credentials work too ([chart
  README](../../deploy/helm/scrim/README.md#secrets-are-references)).

Every release from 0.2.0 on publishes the chart as `oci://ghcr.io/heliopsy/charts/scrim`, signed
keyless by the release workflow. Check the signature before installing
([kubernetes.md](../kubernetes.md#install)):

```sh
VERSION=0.2.0
cosign verify "ghcr.io/heliopsy/charts/scrim:$VERSION" \
  --certificate-identity-regexp '^https://github\.com/Heliopsy/scrim/\.github/workflows/release\.yaml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Values files

| File | What it sets |
| --- | --- |
| [`values-central.yaml`](../../deploy/examples/kubernetes/helm/values-central.yaml) | central mode with one replica, OpenBao with Kubernetes auth, the GitHub catalog entry, Kyverno injection and NetworkPolicy for the namespace `agents` |
| [`values-sidecar.yaml`](../../deploy/examples/kubernetes/helm/values-sidecar.yaml) | sidecar mode with the nftables egress guard, central off |
| [`values-gitops.yaml`](../../deploy/examples/kubernetes/helm/values-gitops.yaml) | the CA and placeholder key from existing Secrets, for tools that render with `helm template` (Argo CD) |
| [`production.yaml`](../../deploy/helm/scrim/examples/production.yaml) (the chart's) | three or more replicas on PostgreSQL under `global.ha`, the HPA, narrowed NetworkPolicies, metrics with a ServiceMonitor, alert rules and the dashboard |

Combine them with several `-f`; later files win. Secret values never go into values: the chart
refuses a literal in the credential fields of `config.stores`, and the PostgreSQL DSN, the admin
token and the metrics token are Secret slots (`secrets.existing.<slot>` or an ExternalSecret,
[kubernetes.md](../kubernetes.md#secrets-the-chart-mounts)). The CA and the placeholder key are
generated on first install and kept across upgrades; to bring your own, set `ca.existingSecret`
and `placeholderKeys.existingSecret`.

Every store needs `redact` targets that match at least one secret on the first load. A target that
matches nothing stops scrim at start-up with an error naming it, and the pod goes into
CrashLoopBackOff. Check the path against your store before the first install.

## Central mode

The OpenBao role `scrim` binds the service account `scrim-proxy` in namespace `scrim` with audience
`openbao` ([stores/openbao.md](../stores/openbao.md#kubernetes-auth)). Then:

```sh
CONTEXT=my-cluster
EX=deploy/examples/kubernetes/helm
helm --kube-context "$CONTEXT" upgrade --install scrim oci://ghcr.io/heliopsy/charts/scrim \
  --version "$VERSION" -n scrim --create-namespace -f "$EX/values-central.yaml"
helm --kube-context "$CONTEXT" test scrim -n scrim
```

From a checkout, use `deploy/helm/scrim` in place of the OCI reference and drop `--version`.

Agent pods need the label, and the agent runs through the `scrim-exec` launcher the chart mounts,
so scrim knows which pod is calling:

```yaml
metadata:
  namespace: agents
  labels:
    scrim.dev/inject: central
spec:
  containers:
    - name: agent
      image: ghcr.io/example/agent:1
      command: [/etc/scrim/trust/scrim-exec, claude, -p, "review the open pull requests"]
```

Kyverno adds the base URLs, `HTTPS_PROXY`, `NO_PROXY`, the CA bundle and a projected service
account token when the pod is created. `scrim-exec` hands that token to scrim with every request,
scrim checks it with a TokenReview and names the agent `<namespace>/<service account>`, and the
built-in rule injects the GitHub token toward `api.github.com` for it. No policy rule is needed. A
process started without `scrim-exec` is an unknown caller: its provider requests are redacted, and
nothing is injected for it. [kubernetes.md](../kubernetes.md#identity) has the details, including
agents that run longer than the token's hour.

Without Kyverno, reference the ConfigMap `scrim-agent-env` the chart writes into each agent
namespace and mount the CA and token yourself
([kubernetes.md](../kubernetes.md#without-kyverno)).

For several replicas, start from the chart's `production.yaml`: PostgreSQL and `global.ha`, with
the DSN in a Secret of yours:

```sh
kubectl --context "$CONTEXT" -n scrim create secret generic scrim-postgres --from-file=dsn=./dsn
helm --kube-context "$CONTEXT" upgrade --install scrim oci://ghcr.io/heliopsy/charts/scrim \
  --version "$VERSION" -n scrim -f deploy/helm/scrim/examples/production.yaml
```

Delete `dsn` once the Secret exists, or create the Secret with SOPS or External Secrets instead
([gitops-secrets.md](gitops-secrets.md)).

## Sidecar mode

```sh
podman build -t registry.example.com/platform/nft:3.22 "$EX/egress-guard"
podman push registry.example.com/platform/nft:3.22
helm --kube-context "$CONTEXT" upgrade --install scrim oci://ghcr.io/heliopsy/charts/scrim \
  --version "$VERSION" -n scrim --create-namespace -f "$EX/values-sidecar.yaml"
```

Label agent pods `scrim.dev/inject: sidecar`. Each one gets its own scrim as a native sidecar and an
init container that installs the egress guard; the namespace needs Pod Security `privileged` (or
an exemption) for that init container's `NET_ADMIN`. Each in-pod scrim logs in to OpenBao as the
agent pod's service account, so the OpenBao role must bind those accounts too, and the values and
the CA key end up in every agent pod. That is why central mode is the default.

## Verify

```sh
timeout 30 helm --kube-context "$CONTEXT" -n scrim status scrim
timeout 30 kubectl --context "$CONTEXT" -n scrim rollout status deploy/scrim
timeout 30 kubectl --context "$CONTEXT" -n scrim exec deploy/scrim -- scrim status
timeout 30 kubectl --context "$CONTEXT" -n scrim exec deploy/scrim -- scrim doctor
```

`scrim status` lists each store and how many values each redact target holds. A labelled pod shows
the injected environment and reaches the provider through scrim:

```sh
timeout 60 kubectl --context "$CONTEXT" -n agents run scrim-canary --rm -i --restart=Never \
  --labels scrim.dev/inject=central --image=docker.io/curlimages/curl:8.17.0 -- \
  sh -c 'echo "$ANTHROPIC_BASE_URL"; curl -s -o /dev/null -w "%{http_code}\n" "$ANTHROPIC_BASE_URL/v1/messages" \
    -H "x-api-key: not-a-real-key" -H "anthropic-version: 2023-06-01" -H "content-type: application/json" \
    -d "{\"model\":\"claude-sonnet-4-5\",\"max_tokens\":16,\"messages\":[{\"role\":\"user\",\"content\":\"canary\"}]}"'
```

It prints `http://scrim.scrim.svc.cluster.local:9790/anthropic` and `401`, Anthropic refusing the
fake key behind scrim. With NetworkPolicy on, the same pod calling `https://api.anthropic.com`
directly gets no connection.

## Upgrade and roll back

```sh
helm --kube-context "$CONTEXT" upgrade scrim oci://ghcr.io/heliopsy/charts/scrim --version 0.2.1 \
  -n scrim --reuse-values
helm --kube-context "$CONTEXT" -n scrim history scrim
helm --kube-context "$CONTEXT" -n scrim rollback scrim <revision>
```

The chart's `appVersion` is the image tag unless `image.tag` or `image.digest` is set; pin
`image.digest` to the digest `cosign verify` printed for production. From a checkout, `just
helm-render-diff <ref>` shows what the rendered objects change against an older git ref. A
rollback across a PostgreSQL schema change needs the database restored too.

## Uninstall

```sh
helm --kube-context "$CONTEXT" -n scrim uninstall scrim
kubectl --context "$CONTEXT" -n scrim delete secret scrim-postgres
kubectl --context "$CONTEXT" delete namespace scrim
```

The CA, placeholder key and metrics token Secrets have `helm.sh/resource-policy: keep` and survive
the uninstall, so a reinstall keeps the agents' CA trust; deleting the namespace removes them.
