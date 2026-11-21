# Argo CD

scrim managed by [Argo CD](https://argo-cd.readthedocs.io) from a Git repository of your own
(`https://github.com/example-org/fleet` in the examples; replace it).

| File | What it is |
| --- | --- |
| [`appproject.yaml`](../../deploy/examples/argocd/appproject.yaml) | the AppProject `scrim`: the chart and fleet repositories, the `scrim` and `agents` namespaces, and the cluster-scoped kinds scrim needs |
| [`application-helm.yaml`](../../deploy/examples/argocd/application-helm.yaml) | scrim from the OCI chart at a release version, values from fleet (multiple sources) |
| [`repository-scrim-charts.yaml`](../../deploy/examples/argocd/repository-scrim-charts.yaml) | registers `ghcr.io/heliopsy/charts` as an OCI Helm repository, no credential |
| [`application-kustomize.yaml`](../../deploy/examples/argocd/application-kustomize.yaml) | scrim from a kustomize overlay in fleet |
| [`applicationset.yaml`](../../deploy/examples/argocd/applicationset.yaml) | one Application per cluster labelled `scrim.dev/env`, rolled out dev, then staging, then prod |
| [`root.yaml`](../../deploy/examples/argocd/root.yaml) | app of apps that installs Kyverno, the policy, the Secrets and scrim in sync-wave order |
| [`kyverno.yaml`](../../deploy/examples/argocd/kyverno.yaml), [`policies.yaml`](../../deploy/examples/argocd/policies.yaml), [`external-secrets.yaml`](../../deploy/examples/argocd/external-secrets.yaml) | the children of `root.yaml` |
| [`image-updater.yaml`](../../deploy/examples/argocd/image-updater.yaml) | Argo CD Image Updater for the dev Application |

## Prerequisites

- Argo CD 2.13 or later (multiple sources, ApplicationSet progressive syncs) in the `argocd`
  namespace, with each target cluster registered.
- External Secrets Operator and an OpenBao it can read, for the Secrets
  ([gitops-secrets.md](gitops-secrets.md)). Argo CD has no built-in SOPS; use a plugin such as
  KSOPS if you prefer SOPS.
- For the ApplicationSet rollout, progressive syncs on in the ApplicationSet controller
  (`applicationsetcontroller.enable.progressive.syncs: "true"` in `argocd-cmd-params-cm`).

## Layout of the fleet repository

```text
fleet/
  argocd/       appproject.yaml, root.yaml, kyverno.yaml, policies.yaml,
                external-secrets.yaml, application-helm.yaml,
                repository-scrim-charts.yaml                   (deploy/examples/argocd)
  kyverno/      verify-scrim-images.yaml                       (deploy/examples/kyverno)
  secrets/external-secrets/                                    (deploy/examples/secrets/external-secrets)
  scrim/
    helm/values.yaml                                           (deploy/examples/kubernetes/helm/values-central.yaml)
    helm/values-gitops.yaml                                    (deploy/examples/kubernetes/helm/values-gitops.yaml)
    base/ components/ overlays/                                (deploy/examples/kubernetes/kustomize)
```

## Sync waves: CRDs and policy before workloads

[`root.yaml`](../../deploy/examples/argocd/root.yaml) syncs `argocd/` of fleet. Each child
Application carries a sync wave, and Argo CD starts a wave only once the previous one is synced and
healthy:

| Wave | Application | Why first |
| --- | --- | --- |
| -3 | `kyverno` | installs the Kyverno CRDs the policy needs |
| -2 | `scrim-policies` | the image signature policy must be in place before any scrim pod is admitted |
| -1 | `scrim-secrets` | `scrim-keys`, `scrim-ca` and `scrim-postgres` must exist before the pods mount them |
| 0 | `scrim` | the Helm Application |

```sh
CONTEXT=argocd-cluster
kubectl --context "$CONTEXT" -n argocd apply -f deploy/examples/argocd/appproject.yaml
kubectl --context "$CONTEXT" -n argocd apply -f deploy/examples/argocd/root.yaml
```

The chart's injection ClusterPolicy (`kyverno.enabled`) needs the CRDs from wave -3 as well.

## Helm Application

[`application-helm.yaml`](../../deploy/examples/argocd/application-helm.yaml) takes the chart from
the OCI repository each release publishes to (`ghcr.io/heliopsy/charts`, chart `scrim`, 0.2.0 and
later) and the values from fleet through a `$values` reference, so values changes are reviewed in
fleet and the chart version is one line.
[`repository-scrim-charts.yaml`](../../deploy/examples/argocd/repository-scrim-charts.yaml)
registers the repository with `enableOCI`. Argo CD does not check the chart's cosign signature;
check it when you move `targetRevision` ([kubernetes.md](../kubernetes.md#install)). The Kyverno
policy of wave -2 checks every scrim image at admission.

Argo CD renders charts with `helm template`, which has no `lookup`, so the CA and placeholder key
the chart generates would be new at every sync.
[`values-gitops.yaml`](../../deploy/examples/kubernetes/helm/values-gitops.yaml) takes both from
the Secrets `scrim-ca` and `scrim-keys` that wave -1 creates, with the CA's public PEM pasted in.
With `metrics.enabled`, also name a metrics token Secret in `secrets.existing.metrics`.

The Application turns on the server-side diff (`argocd.argoproj.io/compare-options:
ServerSideDiff=true`). Kyverno fills in defaults on the chart's injection ClusterPolicy, and the
default client-side diff then shows the policy OutOfSync after every sync.

```yaml
sources:
  - repoURL: ghcr.io/heliopsy/charts
    chart: scrim
    targetRevision: 0.2.0
    helm:
      valueFiles:
        - $values/scrim/helm/values.yaml
        - $values/scrim/helm/values-gitops.yaml
  - repoURL: https://github.com/example-org/fleet
    targetRevision: main
    ref: values
```

To take the chart from git instead, replace the first source's `chart` with `path:
deploy/helm/scrim`, its `repoURL` with `https://github.com/Heliopsy/scrim` and `targetRevision`
with a release tag such as `v0.2.0`.

## Kustomize Application and ApplicationSet

[`application-kustomize.yaml`](../../deploy/examples/argocd/application-kustomize.yaml) syncs one
overlay to one cluster (`destination.name: staging`).
[`applicationset.yaml`](../../deploy/examples/argocd/applicationset.yaml) generates the same for
every registered cluster whose cluster Secret has the label `scrim.dev/env`:

```sh
argocd --kube-context "$CONTEXT" cluster add dev-cluster --label scrim.dev/env=dev
argocd --kube-context "$CONTEXT" cluster add prod-eu --label scrim.dev/env=prod
kubectl --context "$CONTEXT" -n argocd apply -f deploy/examples/argocd/applicationset.yaml
```

Its `RollingSync` strategy syncs the dev Applications first, then staging, then prod one cluster at
a time, and stops when a step does not become healthy. A new image tag therefore reaches prod only
after dev and staging are healthy with it. Promotion between environments that pin different tags
(the overlays do) stays a pull request in fleet.

## Image updates

[`image-updater.yaml`](../../deploy/examples/argocd/image-updater.yaml) is an `ImageUpdater` for
Argo CD Image Updater 1.x. It watches `ghcr.io/heliopsy/scrim` for `0.x` releases and commits the
new tag to `scrim/overlays/dev` in fleet (git write-back), for the Application `scrim-dev` only.

Image Updater verifies cosign signatures only against a public key, and scrim releases are signed
keyless, so the signature check is the Kyverno policy at admission
([`kyverno/verify-scrim-images.yaml`](../../deploy/examples/kyverno/verify-scrim-images.yaml),
wave -2): an image the release workflow did not sign never starts.

If you run Renovate already, use it instead of Image Updater; [renovate.md](renovate.md) bumps the
image, the chart tag in `application-helm.yaml` and the overlays with one pull request per release.

## Verify

```sh
timeout 30 argocd --kube-context "$CONTEXT" app list -p scrim
timeout 30 argocd --kube-context "$CONTEXT" app get scrim          # Synced, Healthy
timeout 30 argocd --kube-context "$CONTEXT" appset get scrim       # the rollout steps
timeout 30 kubectl --context <workload-cluster> -n scrim exec deploy/scrim -- scrim status
```

Then the canary request from [helm.md](helm.md#verify) or [kubernetes.md](kubernetes.md#verify).

## Upgrade, roll back, uninstall

- Upgrade: change `targetRevision` (the chart version) or the overlay's image tag (Kustomize) in
  fleet.
- Roll back: revert the commit; `argocd app rollback scrim <history id>` works too, but
  self-heal puts Git's version back unless you suspend automated sync first.
- Uninstall: delete the Application (or remove it from `argocd/`). The
  `resources-finalizer.argocd.argoproj.io` finalizer deletes what it created. `scrim-ca` and
  `scrim-keys` stay: their ExternalSecrets have `deletionPolicy: Retain`, so agents keep trusting
  the same CA after a reinstall.
