# Renovate

[`renovate.json`](../../deploy/examples/renovate/renovate.json) keeps every place a scrim version is
written up to date in a fleet repository, with one pull request per scrim release:

| Where | Manager |
| --- | --- |
| `newTag` and `digest` in kustomize overlays | `kustomize`, with digests pinned |
| `ref.tag` of Flux GitRepository and OCIRepository sources (the chart's OCIRepository once you pin it to a tag), HelmRelease chart versions | `flux` |
| `targetRevision` of the Argo CD Applications, the OCI chart `ghcr.io/heliopsy/charts/scrim` included | `argocd` |
| `VERSION=` in install scripts and cloud-init, `scrim_version` in Ansible defaults | a regex manager on GitHub releases |

Patch releases for the dev overlay merge themselves; staging and prod wait for review, which is the
promotion step of the staged rollout ([flux.md](flux.md#kustomization-and-staged-rollout)).

Copy it to the root of the fleet repository as `renovate.json`, or merge its `customManagers` and
`packageRules` into the configuration you have. Check it with Renovate's validator before
committing:

```sh
npx --yes --package renovate@44.257.7 -- renovate-config-validator renovate.json
```

With Renovate in place, Flux image automation and Argo CD Image Updater are optional: Renovate
opens the same change as a reviewed pull request. Neither checks signatures; the Kyverno policy
([flux.md](flux.md#image-signature-verification)) does that at admission.
