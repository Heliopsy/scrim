# scrim documentation

User documentation for scrim. The [project README](../README.md) explains what scrim does and how
to start. The behaviour contract, with every requirement and scenario, is the OpenSpec change in
[`openspec/changes/scrim-v1`](../openspec/changes/scrim-v1/).

## Design

| Page | Covers |
| --- | --- |
| [architecture.md](architecture.md) | Components, the data plane boundary, request, tool, approval and snapshot flows, trust boundaries and deployments, with diagrams |
| [interception.md](interception.md) | The seven ways agent traffic reaches scrim, managed settings as enforcement, CA trust per runtime, choosing and combining methods, verifying |

## Getting started

| Page | Covers |
| --- | --- |
| [install.md](install.md) | Release archives, signature and provenance checks, container images, reproducible builds |
| [running.md](running.md) | `scrim proxy`: the daemon, its listeners and sockets, snapshots, capture mode, shutdown, a systemd unit |
| [kubernetes.md](kubernetes.md) | The Helm chart: central and sidecar modes, Kyverno injection, NetworkPolicy, CA and keys, identity, scaling, monitoring, troubleshooting |
| [helm-values.md](helm-values.md) | Every Helm chart value (generated from values.yaml); the schema is [helm-values.schema.json](helm-values.schema.json) |
| [service.md](service.md) | `scrim install` and `scrim uninstall`: user unit, hardened system unit, Quadlet, upgrade, logs, the VM test |
| [configuration.md](configuration.md) | Config files, `SCRIM_*` environment variables, flags, precedence, profiles, reload and every setting |

## Deployment

Worked examples with tested files in [`deploy/examples`](../deploy/examples/), and a table of which
way fits which situation: [deploy/README.md](deploy/README.md).

| Page | Covers |
| --- | --- |
| [deploy/workstation.md](deploy/workstation.md) | Signed binary install, config, CA trust, `scrim run` for Claude Code and Codex |
| [deploy/vm.md](deploy/vm.md) | `scrim install`, plain systemd units, cloud-init user data, the Ansible role |
| [deploy/containers.md](deploy/containers.md) | Rootless `podman run`, Quadlet, `podman kube play`, compose |
| [deploy/kubernetes.md](deploy/kubernetes.md) | Raw manifests, Kustomize base with dev, staging and prod overlays |
| [deploy/helm.md](deploy/helm.md) | Helm values for central and sidecar mode, PostgreSQL, injection, NetworkPolicy |
| [deploy/flux.md](deploy/flux.md) | Flux sources, HelmRelease, Kustomizations, image automation, signature checks, staged rollout |
| [deploy/argocd.md](deploy/argocd.md) | Argo CD Applications, ApplicationSet, sync waves, Image Updater |
| [deploy/gitops-secrets.md](deploy/gitops-secrets.md) | Which credential goes where; SOPS with age, External Secrets with OpenBao |
| [deploy/renovate.md](deploy/renovate.md) | Renovate configuration for scrim versions |

## Secrets

| Page | Covers |
| --- | --- |
| [stores/README.md](stores/README.md) | Store adapters, the capability matrix, references, freshness and outages |
| [stores/openbao.md](stores/openbao.md) | OpenBao and Vault-compatible KV v2 |
| [stores/vault.md](stores/vault.md) | HashiCorp Vault: KV v1 and v2, namespaces, dynamic secrets leased per grant |
| [stores/infisical.md](stores/infisical.md) | Infisical |
| [stores/gcp.md](stores/gcp.md) | Google Secret Manager, workload identity |
| [stores/azure.md](stores/azure.md) | Azure Key Vault, workload identity |
| [stores/vaultwarden.md](stores/vaultwarden.md) | Vaultwarden and Bitwarden-compatible servers, client-side decryption |
| [stores/local.md](stores/local.md) | Environment variables and files |
| [catalog.md](catalog.md) | Logical names, host bindings, declared placeholders, profiles and bulk mapping |
| [ca.md](ca.md) | The tool proxy's interception CA: where it lives, rotation, export, per-user trust install and uninstall |

## Agents

| Page | Covers |
| --- | --- |
| [cli-tools.md](cli-tools.md) | Tool profiles: gh, git, kubectl, aws, terraform and other CLIs with placeholder credentials |
| [run.md](run.md) | `scrim run`: what it sets for Claude Code, Codex and other agents, failing closed, signals |
| [providers/README.md](providers/README.md) | Cloud provider routes: Bedrock, Claude Platform on AWS, Foundry and Vertex, authenticated by scrim after redaction |
| [agent-tools.md](agent-tools.md) | The MCP server, `scrim secret` commands and the human entry page |
| [identity.md](identity.md) | How scrim knows which agent is calling: peer credentials and session tokens |

## Policy

| Page | Covers |
| --- | --- |
| [policy.md](policy.md) | CEL rules, the variables a rule can see, checking and evaluating rule files |
| [approvals.md](approvals.md) | Approvals, decision links, notifiers, just-in-time grants and break-glass |

## Operations and assurance

| Page | Covers |
| --- | --- |
| [state-and-observability.md](state-and-observability.md) | State backends, the audit log, metrics, traces, health, `scrim status` and `scrim doctor` |
| [monitoring.md](monitoring.md) | Prometheus metrics behind `metrics.enabled`, every metric, alert runbooks, the Grafana dashboard, scrape config and endpoint security |
| [leak-assurance.md](leak-assurance.md) | The leak suite, the bypass matrix, running it yourself and known limitations |

Security issues go through [SECURITY.md](../SECURITY.md), not public issues.
