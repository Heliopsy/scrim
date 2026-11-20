## Why

AI coding agents read `.env` files, logs, configs and command output, and everything they read is
sent to the model provider as context. Secrets leak to Anthropic, OpenAI and every proxy in between
without anyone deciding to share them. The existing tools each cover a slice (credential-injecting
proxies, regex redaction gateways, value-returning MCP servers, store-specific approval flows), none
combines them, and none works the same way across stores, agents, a laptop and a cluster.

scrim v1 is the first release: a single component that keeps every known secret value away from
model providers, lets agents keep using those secrets through placeholders, and lets them request,
create and capture secrets under human approval without ever reading a value.

## What Changes

- New: an LLM proxy in front of every supported provider API that replaces known secret values with
  deterministic placeholders on the way out, checks the result with an independent guard, refuses
  the request on any failure, and resolves placeholders on the way back under a per-tool policy.
- New: credential injection at the network edge. A credential is bound to the hosts it belongs to,
  stays a placeholder inside the agent's commands, and is swapped in only on outbound connections to
  those hosts, through an HTTPS tool proxy, an exec broker, an ssh-agent and database auth proxies.
- New: store adapters behind one reference scheme, with read, list, watch and write and a declared
  capability matrix: Vaultwarden, Infisical and OpenBao (the reference stores every release is
  tested against), HashiCorp Vault, AWS Secrets Manager and SSM Parameter Store, Google Secret
  Manager, Azure Key Vault, 1Password, Bitwarden Secrets Manager, Doppler, Kubernetes Secrets and
  local sources, plus a plugin interface for more.
- New: agent tools over MCP and the CLI to list secret names, request access, generate secrets,
  capture command output into a store, and ask a human to enter a value. No tool returns a value.
- New: a policy engine (allow, deny, ask) over agent, secret, provider, destination and tool, with
  approvals pushed to notifiers, just-in-time grants that expire, and one audit log.
- New: agent identity from Unix socket peer credentials, session tokens, Kubernetes service account
  tokens and optional mTLS.
- New: interception modes so users can choose how agents reach scrim: wrapper, base URL, forward
  proxy, transparent (nftables, eBPF), DNS, Kubernetes injection, managed agent settings and hooks.
- New: one configuration contract, every setting settable by file, `SCRIM_*` environment variable
  and flag, validated against a versioned schema and reloadable without restart.
- New: state backends (memory, SQLite, PostgreSQL), event and rate-limit backends (local, Postgres
  notify, Valkey, NATS) and audit sinks (database, OTLP, Loki, Kafka).
- New: observability without secrets, packaging for binary, container, systemd/Quadlet, Helm and
  Kubernetes policies, a latency budget enforced as a release gate, and a leak-assurance suite
  (capture mode, audit harness, bypass matrix, fuzzing) that users can run themselves.

## Capabilities

### New Capabilities

- `llm-proxy`: provider API routing and codecs, streaming, upstream chaining (for example through a
  context-compression proxy), unknown-field handling, fail-closed behaviour and capture mode.
- `redaction`: known-value matching with encoded variants, placeholder format, fallback detectors,
  the independent guard, placeholder resolution under the tool policy, context-aware escaping, and
  byte-stability for prompt caching and signed content.
- `credential-injection`: host-bound credentials, the HTTPS tool proxy and its CA, response capture,
  the exec broker, the ssh-agent and database auth proxies.
- `secret-stores`: the store adapter contract, reference scheme, the built-in adapters and their
  capability matrix, watching for changes, write-only behaviour toward agents, the conformance
  suite and store plugins.
- `agent-tools`: the MCP server and agent-facing CLI commands for listing, requesting, generating,
  capturing and human entry of secrets.
- `policy-approvals`: rules, decisions, approval flow, notifiers, just-in-time grants and the audit
  log.
- `agent-identity`: how scrim knows which agent is calling, on a machine and in a cluster.
- `interception`: every way an agent's traffic can reach scrim and how each fails closed.
- `configuration`: the file, environment and flag contract, schema, validation and reload.
- `state-and-scaling`: state, event, rate-limit and audit backends, and multi-replica behaviour.
- `observability`: logs, metrics, traces and health endpoints, all free of secret values.
- `deployment`: binary, container image, systemd/Quadlet units, Helm chart and Kubernetes policies.
- `performance`: the latency and throughput budget and how it is enforced.
- `leak-assurance`: capture mode, the audit harness, the bypass matrix and the leak suite as release
  gates.

### Modified Capabilities

None. This is the first change.

## Impact

- New repository `heliopsy/scrim`, AGPL-3.0 with a CLA.
- New binary `scrim`, container image and Helm chart.
- Depends on the secret stores a user already runs and, optionally, ntfy or another notifier,
  PostgreSQL, Valkey or NATS.
- Changes nothing in agents themselves; agents are pointed at scrim through one of the interception
  modes.
- Go control plane and Rust data plane, shipped as one file, decided by the benchmark in
  `bench/redact-bench` (design D1, D11). No requirement depends on the language.
