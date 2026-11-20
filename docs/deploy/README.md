# Deploying scrim

One binary and one config format everywhere: a config file validated on a laptop works in a
container, a systemd unit and the Helm chart. These pages are worked examples; every file they
show is in [`deploy/examples/`](../../deploy/examples/) and checked in CI (see
[How the examples are checked](#how-the-examples-are-checked)).

## Which way

| Situation | Way | Page |
| --- | --- | --- |
| You run Claude Code or Codex on your own machine | binary, `scrim run -- claude` | [workstation.md](workstation.md) |
| Same, and scrim should keep running between agents | binary, user unit | [vm.md](vm.md#user-service) |
| A shared VM, CI runner or jump host, set up by hand | `scrim install --system` | [vm.md](vm.md#scrim-install) |
| Hosts built from images or managed as code, units written by you | plain systemd units | [vm.md](vm.md#plain-unit-files) |
| Cloud instances that must come up with scrim running | cloud-init user data | [vm.md](vm.md#cloud-init) |
| Hosts managed with Ansible | the `scrim` role | [vm.md](vm.md#ansible) |
| A container host, rootless podman | `podman run`, Quadlet, `podman kube play`, compose | [containers.md](containers.md) |
| Agents in Kubernetes, you apply YAML yourself | raw manifests | [kubernetes.md](kubernetes.md#raw-manifests) |
| Same, with dev, staging and prod differences | Kustomize base and overlays | [kubernetes.md](kubernetes.md#kustomize) |
| Agents in Kubernetes, injection by label, NetworkPolicy, sidecars | Helm chart | [helm.md](helm.md) |
| Clusters managed by Flux | HelmRelease or Kustomization, image automation | [flux.md](flux.md) |
| Clusters managed by Argo CD | Applications, ApplicationSet, sync waves | [argocd.md](argocd.md) |
| Store credentials, keys and the CA in a GitOps repository | SOPS, External Secrets | [gitops-secrets.md](gitops-secrets.md) |
| Version bumps as pull requests | Renovate | [renovate.md](renovate.md) |

Rules of thumb:

- Agents on the same machine as you: workstation or user unit. `scrim run` gives each agent its own
  session, so credential injection and MCP tools work without policy changes.
- Agents running as other users, or the CA key and state out of the agents' reach: system unit.
- Agents in containers or pods reach scrim over the network as base URL and forward proxy. Their
  provider traffic is redacted like everyone's; credential injection for them needs an explicit
  policy rule until Kubernetes identity ships ([helm.md](helm.md#credential-injection-for-agent-pods)).
- In Kubernetes, start with the Helm chart in central mode. The raw manifests and the kustomize
  base are central mode without the chart's injection and NetworkPolicy wiring.

## What every page has

When to use it, prerequisites, the example, how to check that it works, upgrade and rollback, and
uninstall. The checks are the same everywhere:

1. `scrim status` and `scrim doctor`. `scrim status` reports `DEGRADED` while break-glass, capture
   mode or direct-egress blocking are inactive; those lines are expected unless you enforce
   interception.
2. `/readyz` on the metrics listener where one is configured.
3. A canary request: a fake value in a message to `/anthropic/v1/messages` with an invalid API key.
   Anthropic answers 401, which shows the request went through scrim to the provider, and capture
   mode shows the placeholder in place of the value.

Reference pages: [install.md](../install.md) (verifying releases), [running.md](../running.md)
(the daemon), [service.md](../service.md) (`scrim install`), [kubernetes.md](../kubernetes.md)
(the Helm chart), [configuration.md](../configuration.md) (every setting).

## How the examples are checked

`just deploy-examples-check` runs on every pull request that touches `deploy/`, `docs/deploy/` or
`scripts/deploy-examples/` (workflow `deploy-examples.yaml`). The tools are pinned by version and
sha256 in [`scripts/deploy-examples/tools.env`](../../scripts/deploy-examples/tools.env).

| Check | Covers |
| --- | --- |
| `scrim config validate` in the release image, with the mounts each example gives it | every config file: workstation, systemd, OpenBao drop-in, podman, compose, the raw ConfigMap, each kustomize overlay's ConfigMap, the config each Helm values file renders |
| kubeconform `-strict`, Kubernetes 1.34 schemas and the CRD catalog, both pinned by commit | raw manifests, kube play YAML, kustomize overlays, rendered Helm values, Flux, Argo CD, Kyverno and External Secrets objects |
| `helm lint --strict` and `helm template` | each values file |
| `kustomize build` | the overlays and every kustomization in the Flux and secrets examples |
| `systemd-analyze verify` in a scratch root, any warning fails | the system unit, with and without the OpenBao drop-in, the user unit, the unit Quadlet generates |
| `quadlet -dryrun` | the Quadlet files |
| `cloud-init schema` (cloud-init 26.2 in a pinned Ubuntu image) | the user data |
| `ansible-playbook --syntax-check`, `ansible-lint` (production profile) | the playbook and role |
| `podman-compose config` | the compose file |
| shellcheck, JSON parse | the scripts, the Renovate config |
| copy comparison | cloud-init's embedded files, the Ansible role's unit and default config, the kube play ConfigMap, the kustomize base, Flux's Helm values; every SOPS example is encrypted |

`just deploy-examples-smoke` then runs the container examples for real under rootless podman:
`run.sh`, the kube play Pod, the compose file and the raw Deployment through `podman kube play`,
each checked with `scrim status`, `scrim doctor`, `/readyz` and the canary request, with the
capture searched for the canary value.

Not run in CI: the systemd units under a real systemd, cloud-init on an instance, the Ansible role
against a host, and the Flux and Argo CD objects in a cluster. Those are checked for syntax and
schema only.
