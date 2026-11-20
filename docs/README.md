# scrim documentation

User documentation for scrim. The [project README](../README.md) explains what scrim does and how
to start. The behaviour contract, with every requirement and scenario, is the OpenSpec change in
[`openspec/changes/scrim-v1`](../openspec/changes/scrim-v1/).

## Getting started

| Page | Covers |
|---|---|
| [install.md](install.md) | Release archives, signature and provenance checks, container images, reproducible builds |
| [configuration.md](configuration.md) | Config files, `SCRIM_*` environment variables, flags, precedence, profiles, reload and every setting |

## Secrets

| Page | Covers |
|---|---|
| [stores/README.md](stores/README.md) | Store adapters, the capability matrix, references, freshness and outages |
| [stores/openbao.md](stores/openbao.md) | OpenBao and Vault-compatible KV v2 |
| [stores/infisical.md](stores/infisical.md) | Infisical |
| [stores/vaultwarden.md](stores/vaultwarden.md) | Vaultwarden and Bitwarden-compatible servers, client-side decryption |
| [stores/local.md](stores/local.md) | Environment variables and files |
| [catalog.md](catalog.md) | Logical names, host bindings, declared placeholders, profiles and bulk mapping |

## Agents

| Page | Covers |
|---|---|
| [agent-tools.md](agent-tools.md) | The MCP server, `scrim secret` commands and the human entry page |
| [identity.md](identity.md) | How scrim knows which agent is calling: peer credentials and session tokens |

## Policy

| Page | Covers |
|---|---|
| [policy.md](policy.md) | CEL rules, the variables a rule can see, checking and evaluating rule files |
| [approvals.md](approvals.md) | Approvals, decision links, notifiers, just-in-time grants and break-glass |

## Operations and assurance

| Page | Covers |
|---|---|
| [state-and-observability.md](state-and-observability.md) | State backends, the audit log, metrics, traces, health, `scrim status` and `scrim doctor` |
| [leak-assurance.md](leak-assurance.md) | The leak suite, the bypass matrix, running it yourself and known limitations |

Security issues go through [SECURITY.md](../SECURITY.md), not public issues.
