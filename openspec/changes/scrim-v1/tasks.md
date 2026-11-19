# Tasks

Milestones: M0 proves the hot path (groups 1-3), M1 makes scrim usable for one agent on one
machine (groups 4-9), M2 covers more stores, providers and Kubernetes (groups 10-13), M3 adds large
deployments and the remaining edge modes (groups 14-16).

## 1. Language decision and toolchain

- [ ] 1.1 Record the `redact-bench` result and the chosen language split in design.md D1; verify: the decision rule's inputs (CPU per GB, p99, p999) are quoted with a link to the benchmark README
- [ ] 1.2 Add the build toolchain, `justfile` (`build`, `test`, `check`, `bench`, `fuzz`, `spec`) and language-specific sections of AGENTS.md; verify: `just check` passes on an empty skeleton
- [ ] 1.3 Add CI: lint, unit tests, `openspec validate --all --strict`, gitleaks, CodeQL, dependency review, Scorecard, release-please, every action pinned by SHA; verify: CI green on a no-op PR
- [ ] 1.4 Add the release pipeline (static binaries, container image, SBOM, signatures, provenance); verify: a pre-release tag produces signed artifacts that `cosign verify` accepts

## 2. Redaction core

- [ ] 2.1 Value dictionary with encoded variants (raw, JSON-escaped, base64 std/url at three alignments, hex, URL-encoded) and minimum-length rule; verify: table tests per variant and per edge length
- [ ] 2.2 Multi-pattern matcher over raw request bytes with atomic rebuild and swap; verify: concurrent requests during rebuild never block and never miss a value present before and after the swap
- [ ] 2.3 Deterministic placeholders with versioned key and rotation; verify: same value gives same bytes across processes; old-key placeholders still resolve after rotation
- [ ] 2.4 Independent guard over exact outgoing bytes (separate code from 2.2), repair or withhold; verify: a value the redactor is made to miss is caught by the guard in tests
- [ ] 2.5 Fallback detectors (pattern rules, entropy), configurable; verify: rule fixtures and false-positive corpus thresholds
- [ ] 2.6 Fuzz targets for matcher, variants and guard; verify: fuzzing runs in CI for a fixed budget with zero findings

## 3. Anthropic Messages proxy (M0 exit)

- [ ] 3.1 Base-URL listener and Anthropic Messages codec, agent auth passed through, unknown request fields redacted; verify: recorded request fixtures round-trip with only allowlisted fields untouched
- [ ] 3.2 Streaming restorer with per-block holdback, split placeholders and byte-identical thinking and signature content; verify: property test restore(redact(x)) and recorded stream fixtures
- [ ] 3.3 Fail-closed error path; verify: injected redaction or guard errors return the documented error and nothing reaches the fake upstream
- [ ] 3.4 Capture mode; verify: captured requests are byte-identical to what the fake upstream received
- [ ] 3.5 Upstream chaining through caveman with redaction first; verify: caveman's store holds placeholders only, and placeholders survive compression in an end-to-end run
- [ ] 3.6 Latency budget gate; verify: CI fails when p99 per request or per chunk exceeds the configured budget on the reference fixtures

## 4. Configuration

- [ ] 4.1 Schema-versioned config file, `SCRIM_*` environment mapping, flags, precedence and search order; verify: precedence table tests and generated JSON Schema committed
- [ ] 4.2 Secret-valued settings by reference (file, env, store ref, systemd credential); verify: literal secrets rejected where a reference is required
- [ ] 4.3 `scrim config validate` and `scrim config show --effective` with provenance and masking; verify: golden output tests
- [ ] 4.4 Hot reload with atomic apply or full rejection; verify: an invalid edit keeps the old config and reports why
- [ ] 4.5 Weakening settings named, warned at start-up and shown in status; verify: test per weakening setting

## 5. State, audit and observability

- [ ] 5.1 Memory, SQLite and PostgreSQL state backends behind one interface, migrations; verify: the same contract suite passes on all three, PostgreSQL in podman
- [ ] 5.2 Audit log (metadata only) written with the state change it records; verify: a failure between the two writes leaves neither
- [ ] 5.3 Structured logs, metrics, traces and health endpoints with a secret-free type for values; verify: a test that seeds known values and greps every log, metric and trace output for them
- [ ] 5.4 `scrim status` and `scrim doctor`; verify: reports active protections, interception mode, degraded stores and weakened settings in fixture setups

## 6. OpenBao and Infisical adapters

- [ ] 6.1 Store adapter contract, capability declaration, reference scheme parser and the shared conformance suite; verify: the suite runs against a fake adapter and fails on a deliberately broken one
- [ ] 6.2 OpenBao adapter (AppRole, KV v2 read, list, watch, write without read); verify: contract suite against OpenBao dev mode in podman
- [ ] 6.3 Infisical adapter (Universal Auth, read, list, watch, write); verify: contract suite against a local Infisical in podman
- [ ] 6.4 Store outage behaviour (last known set, fail closed for injection, degraded status); verify: tests that stop the store mid-run

## 7. Policy, approvals and grants

- [ ] 7.1 Rule language and evaluation (allow, deny, ask, default); verify: rule table tests and a compiled snapshot used by the data plane
- [ ] 7.2 Approval flow with timeout deny and single-use signed decision links; verify: replayed or expired links are refused
- [ ] 7.3 ntfy notifier with action buttons and terminal `scrim approve`; verify: end-to-end approve and deny against a local ntfy in podman
- [ ] 7.4 JIT grants (ttl, max ttl, scope, use count, revoke); verify: expiry and revocation take effect on the next request
- [ ] 7.5 Break-glass deny-all switch; verify: every path refuses while it is set

## 8. Identity and agent tools

- [ ] 8.1 Unix socket peer credentials and session tokens from `scrim run`; verify: one agent cannot use another's token or grants
- [ ] 8.2 MCP server (stdio) with secrets_list, secret_request, secret_gen, secret_capture, secret_ask_human, approval_status, grants_list; verify: no tool schema accepts a value and no response contains one, checked against seeded values
- [ ] 8.3 Agent-facing CLI equivalents including `scrim secret put --stdin` that never echoes; verify: golden tests and a pipe test with the value absent from all output
- [ ] 8.4 Human entry page for secret_ask_human; verify: the agent receives only stored or declined

## 9. Restore policy, wrapper and leak assurance (M1 exit)

- [ ] 9.1 Per-tool restore policy, tool aliases, display modes, `scrim share` and `scrim reveal`; verify: policy tests per tool role, including none for unknown and network-capable tools
- [ ] 9.2 Context-aware escaping and no restore where output becomes code; verify: injection test suite and an escaping fuzzer that executes commands with zero code execution
- [ ] 9.3 `scrim run -- <agent>` wrapper for Claude Code and Codex; verify: real agent CLIs complete a task through scrim against a fake model
- [ ] 9.4 Bypass matrix as a regression gate; verify: every transform is blocked, withheld or redacted
- [ ] 9.5 `scrim audit` harness with leak checker stricter than the redactor and cache-hit reporting; verify: CI runs it with zero leaks
- [ ] 9.6 User documentation for M1 (install, run, configure, verify with capture, limitations); verify: every documented command is exercised by a docs test

## 10. Credential injection

- [ ] 10.1 Host binding for credentials in configuration and policy; verify: a placeholder toward an unbound host is refused and audited
- [ ] 10.2 HTTPS tool proxy with CA generation, rotation and trust installation; verify: injection works toward bound hosts for curl, git and a Node client
- [ ] 10.3 Response capture rules; verify: a token returned by a fake API is stored and the agent sees a placeholder
- [ ] 10.4 Exec broker as a separate identity with allowlisted commands; verify: an allowed command runs with the secret, a transform command is blocked

## 11. Vaultwarden and more providers

- [ ] 11.1 Vaultwarden adapter with client-side decryption and unlock key by reference; verify: contract suite against Vaultwarden in podman
- [ ] 11.2 OpenAI Chat Completions and Responses codecs; verify: recorded fixtures and Codex end-to-end run
- [ ] 11.3 Gemini codec; verify: recorded fixtures
- [ ] 11.4 Bedrock, Vertex, Foundry and Claude Platform on AWS with re-signing after redaction; verify: Claude Code end-to-end against faithful fake upstreams

## 11a. More stores

- [ ] 11a.1 HashiCorp Vault adapter (KV v1/v2, namespaces, token, AppRole, Kubernetes, JWT, dynamic leases); verify: conformance suite against Vault dev mode in podman, lease revoked when the grant ends
- [ ] 11a.2 AWS Secrets Manager and SSM Parameter Store adapters with ambient identity and version/stage selectors; verify: conformance suite against LocalStack in podman
- [ ] 11a.3 Google Secret Manager and Azure Key Vault adapters with workload identity; verify: conformance suite against the services or compatible fakes
- [ ] 11a.4 1Password, Bitwarden Secrets Manager and Doppler adapters; verify: conformance suite against each service's test account or recorded fixtures
- [ ] 11a.5 Kubernetes Secrets adapter and local sources (env, file, SOPS file, OS keyring) with read-only capabilities declared where applicable; verify: conformance suite in kind and locally, writes to read-only sources refused

## 12. Shared state and Kubernetes

- [ ] 12.1 Postgres-notify events for multiple replicas; verify: two replicas sharing one PostgreSQL agree on grants and approvals
- [ ] 12.2 Kubernetes service account identity; verify: TokenReview-based identity in kind
- [ ] 12.3 Helm chart (Deployment, Service, PDB, HPA, NetworkPolicy) and Kyverno injection policy; verify: agent pod in kind reaches providers only through scrim
- [ ] 12.4 OpenBao and Infisical Kubernetes auth; verify: no static store credentials in the kind test

## 13. Local service and persistent interception (M2 exit)

- [ ] 13.1 systemd unit and Quadlet with a dedicated user, `scrim install` and `scrim uninstall`; verify: uninstall leaves no trace in a VM test
- [ ] 13.2 Forward proxy listener; verify: an agent with HTTPS_PROXY set is redacted
- [ ] 13.3 Transparent mode with nftables per UID or cgroup and SNI routing; verify: an unconfigured agent is redacted and cannot reach providers directly
- [ ] 13.4 Managed agent settings mode; verify: Claude Code refuses any endpoint but scrim

## 14. Large deployments

- [ ] 14.1 Valkey and NATS event backends, Valkey rate limits; verify: contract suites and a multi-replica load test
- [ ] 14.2 Audit sinks OTLP, Loki and Kafka with backpressure policy; verify: a slow sink never drops silently
- [ ] 14.3 Proxy-level load test at 1,000 concurrent streams; verify: published numbers meet the performance spec

## 15. Remaining edge modes

- [ ] 15.1 eBPF cgroup interception with a privileged loader; verify: per-cgroup redirect and direct-egress denial on a test kernel
- [ ] 15.2 DNS override mode; verify: an agent resolving the provider host reaches scrim
- [ ] 15.3 Agent hooks mode reported as partial; verify: status shows partial protection
- [ ] 15.4 ssh-agent with keys from stores and per-signature approval; verify: git over SSH works and a denied signature fails
- [ ] 15.5 Database auth proxies and the read-only database tool with bound parameters; verify: Postgres and MySQL queries by placeholder, writes refused
- [ ] 15.6 Store and notifier plugins with a documented contract; verify: an example plugin passes the contract suites

## 16. Release

- [ ] 16.1 End-to-end matrix across interception modes, stores and providers; verify: CI matrix green with zero leaks
- [ ] 16.2 v1.0.0 documentation, limitations and published performance and leak results; verify: docs tests pass and results are attached to the release

## Workflow follow-up

- Archive `scrim-v1` once 16.2 is done, so its specs become the main specs.
