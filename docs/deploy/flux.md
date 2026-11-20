# Flux

scrim managed by [Flux](https://fluxcd.io) from a Git repository of your own (called `fleet`
below). Two paths, pick one per cluster:

| Path | Source of the manifests | Use it when |
| --- | --- | --- |
| [HelmRelease](#helmrelease) | the chart in this repository's release tags | you want the chart's injection, NetworkPolicy and sidecar mode |
| [Kustomization](#kustomization-and-staged-rollout) | the kustomize overlays, copied into `fleet` | you want plain manifests you can read in a diff, staged dev, staging, prod |

Both use the same pieces: a source for scrim, the Secrets from SOPS or External Secrets
([gitops-secrets.md](gitops-secrets.md)), image automation for the dev cluster, and an admission
policy that refuses unsigned scrim images.

Files: [`deploy/examples/flux/`](../../deploy/examples/flux/) and
[`deploy/examples/kyverno/`](../../deploy/examples/kyverno/).

## Prerequisites

- Flux 2.7 or later, bootstrapped into each cluster (`flux bootstrap github ...`), with the
  image automation controllers for the dev cluster (`--components-extra
  image-reflector-controller,image-automation-controller`).
- An age key for SOPS in each cluster, as the Secret `sops-age` in `flux-system`
  ([gitops-secrets.md](gitops-secrets.md#sops-with-age)).
- Kyverno 1.13 or later for the image signature policy.

## Layout of the fleet repository

```text
fleet/
  clusters/
    dev/        scrim.yaml (flux/clusters/dev), image-automation.yaml (flux/image-automation)
    staging/    scrim.yaml (flux/clusters/staging)
    prod/       scrim.yaml (flux/clusters/prod), scrim-image.yaml (flux/sources)
  scrim/        a copy of deploy/examples/kubernetes/kustomize (base, components, overlays)
  secrets/
    dev/ staging/ prod/   SOPS-encrypted Secrets (deploy/examples/secrets/sops)
  kyverno/      verify-scrim-images.yaml (deploy/examples/kyverno)
```

`flux bootstrap` points each cluster at its `clusters/<env>/` directory, and the Kustomizations
use bootstrap's own `flux-system` GitRepository. If scrim's files live in another repository, add
[`sources/fleet.yaml`](../../deploy/examples/flux/sources/fleet.yaml) and change the
Kustomizations' `sourceRef` to `name: fleet`.

## HelmRelease

[`sources/scrim-chart.yaml`](../../deploy/examples/flux/sources/scrim-chart.yaml) is a
GitRepository of this repository that follows release tags (`>=0.2.0 <1.0.0`) and fetches only
`deploy/helm/scrim`. The release pipeline publishes no OCI chart yet; when it does, an
OCIRepository with `verify` replaces it.

[`helm/helmrelease.yaml`](../../deploy/examples/flux/helm/helmrelease.yaml) installs the chart
from it, with the values in a ConfigMap generated from
[`helm/values.yaml`](../../deploy/examples/flux/helm/values.yaml) (the central-mode values from
[helm.md](helm.md)). Upgrades that fail roll back on their own (`remediation.strategy: rollback`),
and drift detection puts back anything changed by hand.

[`clusters/scrim-helm.yaml`](../../deploy/examples/flux/clusters/scrim-helm.yaml) is the Flux
Kustomization that applies `flux/helm/`, copied to `scrim-helm/` in fleet, after `scrim-secrets`
and `scrim-policies`. Put it and `sources/scrim-chart.yaml` in `clusters/<env>/`, in place of the
`scrim` Kustomization of `clusters/<env>/scrim.yaml`.

## Kustomization and staged rollout

[`clusters/<env>/scrim.yaml`](../../deploy/examples/flux/clusters/) holds three Flux
Kustomizations per cluster: `scrim-secrets` decrypts and applies `secrets/<env>` with SOPS,
`scrim-policies` applies the image signature policy from `kyverno/`, and `scrim` applies
`scrim/overlays/<env>` once both are ready, waiting for the rollout (`wait: true`).

The three environments differ only in their overlay, so a change moves through them as commits:

1. A new scrim release appears. In dev, image automation commits the new tag into
   `scrim/overlays/dev/kustomization.yaml` (see below); Flux rolls it out.
2. When dev is healthy, a pull request copies the tag into `scrim/overlays/staging`. Renovate can
   open it ([renovate.md](renovate.md)).
3. After staging, the same for `scrim/overlays/prod`, where the image is pinned by digest.

A rollback is `git revert` of the promoting commit. Flux applies the previous overlay and
Kubernetes rolls the Deployment back.

If you would rather promote by branch, point the prod cluster's GitRepository at a `prod` branch
and merge into it; the overlays stay the same.

## Image automation

[`image-automation/scrim.yaml`](../../deploy/examples/flux/image-automation/scrim.yaml), for the
dev cluster only:

| Object | Does |
| --- | --- |
| ImageRepository `scrim` | lists the tags of `ghcr.io/heliopsy/scrim` every hour, ignoring signature and digest tags |
| ImagePolicy `scrim` | the newest release tag in `>=0.1.0 <1.0.0`; pre-releases and the moving `0.1` and `latest` tags are filtered out |
| ImageUpdateAutomation `scrim-dev` | rewrites the line marked `{"$imagepolicy": "flux-system:scrim:tag"}` under `scrim/overlays/dev` and pushes the commit to `main` |

The marker is already in the dev overlay:

```yaml
images:
  - name: ghcr.io/heliopsy/scrim
    newTag: 0.1.0 # {"$imagepolicy": "flux-system:scrim:tag"}
```

The deploy key bootstrap created must have write access for the automation to push.

## Image signature verification

Releases are signed keyless with cosign by the release workflow
(`https://github.com/Heliopsy/scrim/.github/workflows/release.yaml`). Two places check it:

- [`kyverno/verify-scrim-images.yaml`](../../deploy/examples/kyverno/verify-scrim-images.yaml), a
  Kyverno ClusterPolicy, refuses any pod with a `ghcr.io/heliopsy/scrim` or `scrim-dataplane` image
  that this identity did not sign, and rewrites the tag to the verified digest. This is the
  enforcement. The `scrim-policies` Kustomization applies it before scrim (add it to
  `scrim-helm`'s `dependsOn` too), so the first scrim pod is checked.
- [`sources/scrim-image.yaml`](../../deploy/examples/flux/sources/scrim-image.yaml), an
  OCIRepository with `verify.provider: cosign` and `matchOIDCIdentity` for the same identity,
  follows the same tag range and turns not Ready, with an event and an alert, when a release does
  not verify. Image automation itself does not check signatures.

The identity to match:

```yaml
matchOIDCIdentity:
  - issuer: ^https://token\.actions\.githubusercontent\.com$
    subject: ^https://github\.com/Heliopsy/scrim/\.github/workflows/release\.yaml@refs/(heads/main|tags/v.+)$
```

v0.1.0 was signed from `refs/heads/main` (release-please dispatches the workflow on `main`); a
hand-pushed tag signs from `refs/tags/v...`. Both are this repository's release workflow.

## Verify

```sh
CONTEXT=my-cluster
timeout 30 flux --context "$CONTEXT" get sources git
timeout 30 flux --context "$CONTEXT" get sources oci scrim-image   # READY True: the signature verified
timeout 30 flux --context "$CONTEXT" get kustomizations
timeout 30 flux --context "$CONTEXT" get helmreleases -n scrim     # for the Helm path
timeout 30 flux --context "$CONTEXT" get images all                # dev: the policy's latest tag
timeout 30 kubectl --context "$CONTEXT" -n scrim exec deploy/scrim -- scrim status
```

Then the canary request from [kubernetes.md](kubernetes.md#verify) or [helm.md](helm.md#verify).
Force a reconcile after a commit with `flux --context "$CONTEXT" reconcile kustomization scrim
--with-source`, and after a release with `flux --context "$CONTEXT" reconcile image repository
scrim`.

## Upgrade, roll back, uninstall

- Upgrade: dev by image automation, staging and prod by pull request; the Helm path by the
  GitRepository's semver range (a new release tag) or a changed range.
- Roll back: revert the commit. For the Helm path, a failed upgrade rolls back by itself; to go
  back on purpose, narrow the semver range (`ref.tag: v0.2.0`) and commit.
- Pause: `flux --context "$CONTEXT" suspend kustomization scrim` (and `resume`).
- Uninstall: remove `clusters/<env>/scrim.yaml` from fleet and commit. `prune: true` deletes what
  the Kustomization applied, the namespace included.
