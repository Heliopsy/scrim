# Tasks

Milestones: M0 proves the hot path (groups 1-3), M1 makes scrim usable for one agent on one
machine (groups 4-9), M2 covers more stores, providers and Kubernetes (groups 10-13), M3 adds large
deployments and the remaining edge modes (groups 14-16).

Release v0.1.0 ships M0 and M1 plus 10.1 to 10.3, 11.1, 11.2, the env and file sources of 11a.5
and 13.2. Everything else stays open for later releases; v1.0.0 is group 16.

## 1. Language decision and toolchain

- [x] 1.1 Record the `redact-bench` result and the chosen language split in design.md D1; verify: the decision rule's inputs (CPU per GB, p99, p999) are quoted with a link to the benchmark README
- [x] 1.2 Add the build toolchain, `justfile` (`build`, `test`, `check`, `bench`, `fuzz`, `spec`) and language-specific sections of AGENTS.md; verify: `just check` passes on an empty skeleton
- [x] 1.3 Add CI: lint, unit tests, `openspec validate --all --strict`, gitleaks, CodeQL, dependency review, Scorecard, release-please, every action pinned by SHA; verify: CI green on a no-op PR
- [x] 1.3a Dependency freshness gate (`just deps-fresh`, CI job `deps-fresh` and a weekly run): direct Go and Rust dependencies on their latest stable major, dated exceptions in `.deps-fresh-ignore`; verify: the gate fails on the 0.x crates main required before the cargo major bump and passes after it
- [x] 1.3b Pinned tools, images, toolchains and actions kept current: Renovate for every pin outside `go.mod` and the Cargo manifests (Dependabot keeps those and the actions), `just pins-fresh` weekly with a 14-day grace period, sha256 URLs next to each pinned checksum, `just pin-sums` and the `pin-sums` CI job; verify: the pin check fails on a release older than the grace period, the annotation test fails on an annotation renovate.json cannot see, and the sums check fails on a stale checksum and passes after `-fix`
- [x] 1.4 Add the release pipeline (static binaries, container image, SBOM, signatures, provenance); verify: a pre-release tag produces signed artifacts that `cosign verify` accepts

## 2. Redaction core

- [x] 2.0 Hash-window prefilter matcher for large sets with Aho-Corasick for small sets (design D13); verify: identical output to the reference matcher on every fixture and at least 500 MB/s single core at 10,000 secrets

- [x] 2.1 Value dictionary with encoded variants (raw, JSON-escaped, base64 std/url at three alignments, hex, URL-encoded) and minimum-length rule; verify: table tests per variant and per edge length
- [x] 2.2 Multi-pattern matcher over raw request bytes with atomic rebuild and swap; verify: concurrent requests during rebuild never block and never miss a value present before and after the swap
- [x] 2.3 Deterministic placeholders with versioned key and rotation; verify: same value gives same bytes across processes; old-key placeholders still resolve after rotation
- [x] 2.4 Independent guard over exact outgoing bytes (separate code from 2.2), repair or withhold; verify: a value the redactor is made to miss is caught by the guard in tests
- [x] 2.5 Fallback detectors (pattern rules, entropy), configurable; verify: rule fixtures and false-positive corpus thresholds
- [x] 2.6 Fuzz targets for matcher, variants and guard; verify: fuzzing runs in CI for a fixed budget with zero findings (`.github/workflows/fuzz.yaml`: every cargo-fuzz target 60 s on data plane changes, 15 min weekly, reproducers uploaded)
- [x] 2.7 Nested JSON (JSON text in JSON strings) to `redaction.json_depth` in the variants and the guard, and no restore of a value escaping changes inside a quoted part of tool-call arguments; verify: OpenAI Chat tool-call arguments and a three-level tool result redacted by the real engine, the guard alone catches every style mix to the depth

## 3. Anthropic Messages proxy (M0 exit)

- [x] 3.1 Base-URL listener and Anthropic Messages codec, agent auth passed through, unknown request fields redacted; verify: recorded request fixtures round-trip with only allowlisted fields untouched
- [x] 3.2 Streaming restorer with per-block holdback, split placeholders and byte-identical thinking and signature content; verify: property test restore(redact(x)) and recorded stream fixtures
- [x] 3.3 Fail-closed error path; verify: injected redaction or guard errors return the documented error and nothing reaches the fake upstream
- [x] 3.4 Capture mode; verify: captured requests are byte-identical to what the fake upstream received
- [x] 3.5 Upstream chaining through caveman with redaction first; verify: caveman's store holds placeholders only, and placeholders survive compression in an end-to-end run
- [x] 3.6 Latency budget gate; verify: CI fails when p99 per request or per chunk exceeds the configured budget on the reference fixtures
- [x] 3.7 Request target and headers redacted and guarded like the body, only `authorization` and `x-api-key` passed through; verify: the leak gate's `header` and `query` rows are redacted for every transform the guard decodes, and an end-to-end request with secrets in a custom header and a percent-encoded query parameter reaches the fake provider with placeholders only
- [x] 3.8 Placeholders in header values leave in percent form (`%E2%9F%A6...%E2%9F%A7`), which resolves, restores percent-encoded and is read by the guard; verify: a header redacted or guard-repaired holds only visible ASCII and a fake provider that rejects obs-text accepts it
- [x] 3.9 WebSocket and other protocol upgrades refused with 501 `upgrade_unsupported` before anything else; verify: a handshake by base URL or through the forward proxy is refused in under 100 ms and the fake provider receives nothing

## 4. Configuration

- [x] 4.1 Schema-versioned config file, `SCRIM_*` environment mapping, flags, precedence and search order; verify: precedence table tests and generated JSON Schema committed
- [x] 4.2 Secret-valued settings by reference (file, env, store ref, systemd credential); verify: literal secrets rejected where a reference is required
- [x] 4.3 `scrim config validate` and `scrim config show --effective` with provenance and masking; verify: golden output tests
- [x] 4.4 Hot reload with atomic apply or full rejection; verify: an invalid edit keeps the old config and reports why
- [x] 4.5 Weakening settings named, warned at start-up and shown in status; verify: test per weakening setting

## 5. State, audit and observability

- [x] 5.1 Memory, SQLite and PostgreSQL state backends behind one interface, migrations; verify: the same contract suite passes on all three, PostgreSQL in podman
- [x] 5.2 Audit log (metadata only) written with the state change it records; verify: a failure between the two writes leaves neither
- [x] 5.3 Structured logs, metrics, traces and health endpoints with a secret-free type for values; verify: a test that seeds known values and greps every log, metric and trace output for them
- [x] 5.4 `scrim status` and `scrim doctor`; verify: reports active protections, interception mode, degraded stores and weakened settings in fixture setups
- [x] 5.5 Prometheus monitoring behind `metrics.enabled`: control-plane metrics, data plane metrics over the `Metrics` call, bearer token for non-loopback listeners; verify: daemon end-to-end test scrapes the expected series after traffic through the real data plane and greps the page for every seeded value and encoding
- [x] 5.6 Monitoring assets (alert rules with promtool tests, Grafana dashboard, scrape config) and runbooks in `docs/monitoring.md`; verify: `scripts/monitoring-check.sh` in CI

## 6. OpenBao and Infisical adapters

- [x] 6.1 Store adapter contract, capability declaration, reference scheme parser and the shared conformance suite; verify: the suite runs against a fake adapter and fails on a deliberately broken one
- [x] 6.2 OpenBao adapter (AppRole, KV v2 read, list, watch, write without read); verify: contract suite against OpenBao dev mode in podman
- [x] 6.3 Infisical adapter (Universal Auth, read, list, watch, write); verify: contract suite against a local Infisical in podman
- [x] 6.3a Secret catalog: logical names, bindings, declared placeholders, reference placeholders without a catalog; verify: rules, profiles and MCP tools accept catalog names and a literal value in a catalog fails validation
- [x] 6.3b Per-environment and bulk prefix mapping with collision checks; verify: one placeholder resolves to different references per profile and colliding templates fail
- [x] 6.3c Catalog from store metadata, catalog files, environment and hot reload, with `scrim catalog show` and `scrim catalog suggest`; verify: OpenBao custom metadata binds a host and suggestions are printed, never applied
- [x] 6.4 Store outage behaviour (last known set, fail closed for injection, degraded status); verify: tests that stop the store mid-run
- [x] 6.5 Redact target globs (`APP_*` on env and file) and per-target value counts; a target that loads nothing stops start-up unless `redaction.allow-empty-targets` is on, and status never reports redaction active with an empty target; verify: the README quickstart config redacts `SCRIM_SECRET_X` through the real data plane, an empty target stops the daemon naming it, and with the setting the store is degraded with the target at 0 values

## 7. Policy, approvals and grants

- [x] 7.1 Rule language and evaluation (allow, deny, ask, default); verify: rule table tests and a compiled snapshot used by the data plane (data plane: `scrim-policy` passes every conformance vector and a differential property test against a port of the Go reference; `scrim-dataplane` evaluates it per request for `inject` and `llm.forward` and asks over the `Asks` stream within `Policy.ask_timeout_millis`, which the control plane fills from `approvals.timeout` or the longest per-rule approval timeout; `gate.Answer` decides `llm.forward` with the data plane's forward semantics, checked by `TestForwardConformance`)
- [x] 7.2 Approval flow with timeout deny and single-use signed decision links; verify: replayed or expired links are refused
- [x] 7.3 ntfy notifier with action buttons and terminal `scrim approve`; verify: end-to-end approve and deny against a local ntfy in podman
- [x] 7.4 JIT grants (ttl, max ttl, scope, use count, revoke); verify: expiry and revocation take effect on the next request
- [x] 7.5 Break-glass deny-all switch; verify: every path refuses while it is set

## 8. Identity and agent tools

- [x] 8.1 Unix socket peer credentials and session tokens from `scrim run`; verify: one agent cannot use another's token or grants (data plane: reads Unix peer credentials and the session a request names, `Proxy-Authorization` user or `x-scrim-session`, and sends them as `AskCaller` with a per-ask proof of the token (design D14); `scrim run` names the session on its proxy URL and in Claude Code's `ANTHROPIC_CUSTOM_HEADERS`, and `gate.Answer` verifies the session or maps the peer and evaluates with that identity, checked end to end by `internal/daemon` `TestEndToEndSessionIdentity`)
- [x] 8.2 MCP server (stdio) with secrets_list, secret_request, secret_gen, secret_capture, secret_ask_human, approval_status, grants_list; verify: no tool schema accepts a value and no response contains one, checked against seeded values
- [x] 8.3 Agent-facing CLI equivalents including `scrim secret put --stdin` that never echoes; verify: golden tests and a pipe test with the value absent from all output
- [x] 8.4 Human entry page for secret_ask_human; verify: the agent receives only stored or declined

## 9. Restore policy, wrapper and leak assurance (M1 exit)

- [x] 9.1 Per-tool restore policy, tool aliases, display modes, `scrim share` and `scrim reveal`; verify: policy tests per tool role, including none for unknown and network-capable tools (data plane: `scrim-policy` `RestoreEngine`, settings in `Snapshot.restore`, wired into the data plane with shell and edit tool calls restored escaped; the CLI commands and the control plane filling `Snapshot.restore` follow)
- [x] 9.2 Context-aware escaping and no restore where output becomes code; verify: injection test suite and an escaping fuzzer that executes commands with zero code execution (`scrim-policy` `escape`, `tests/escape_exec.rs` runs commands under `unshare -rn`)
- [x] 9.3 `scrim run -- <agent>` wrapper for Claude Code and Codex; verify: real agent CLIs complete a task through scrim against a fake model (`just e2e-session`: Claude Code and Codex against the real `scrim proxy`, CI job `e2e-agents`)
- [x] 9.4 Bypass matrix as a regression gate; verify: every transform is blocked, withheld or redacted
- [x] 9.5 `scrim audit` harness with leak checker stricter than the redactor and cache-hit reporting; verify: CI runs it with zero leaks
- [x] 9.6 User documentation for M1 (install, run, configure, verify with capture, limitations); verify: every documented command is exercised by a docs test (`just docs-test`, CI job `docs-commands`: every shell block in the README, install, run, running, configuration, agent-tools and ca docs runs as written in the sandbox or names why it cannot)

## 10. Credential injection

- [x] 10.1 Host binding for credentials in configuration and policy; verify: a placeholder toward an unbound host is refused and audited
- [x] 10.2 HTTPS tool proxy with CA generation, rotation and trust installation; verify: injection works toward bound hosts for curl, git and a Node client
- [x] 10.1a Unresolved placeholders toward bound hosts refused with `credential_unavailable` (unknown generated or reference placeholders, and declared placeholders of catalog credentials whose value has not loaded, sent as `Snapshot.unavailable`); verify: scrim-toolproxy and the data plane end-to-end test refuse every form and nothing reaches the host, look-alike text passes
- [x] 10.2a User-declared placeholders mapped to references and bound hosts; verify: a config file with `SCRIM_ACME_KEY` works against a fake API and duplicate declarations fail validation
- [x] 10.2b Substitution in URL, headers, cookies, form, JSON and multipart bodies with decompression, length, digest and re-signing; verify: gzip, chunked and HTTP/2 fixtures reach the fake upstream valid and unsupported encodings are refused
- [x] 10.2c Redaction of tool-proxy responses, including streamed and compressed bodies; verify: an echoing fake API and a create-resource fake return only placeholders to the agent
- [x] 10.3 Response capture rules; verify: a token returned by a fake API is stored and the agent sees a placeholder
- [ ] 10.4 Exec broker as a separate identity with allowlisted commands; verify: an allowed command runs with the secret, a transform command is blocked

## 10a. Command-line tools

- [ ] 10a.1 Tool profiles with generated placeholder env and config files, removed at session end; verify: gh, git over HTTPS, kubectl, helm, npm and docker login work through `scrim run` with no real value in the session
- [ ] 10a.2 AWS SigV4 re-signing toward bound endpoints; verify: `aws s3 ls` and `aws sts get-caller-identity` succeed against LocalStack with placeholder keys, unbound region refused
- [ ] 10a.3 Format-preserving placeholders; verify: a client that checks the token prefix sends the placeholder and the guard still catches it
- [ ] 10a.4 Upstream client certificates; verify: kubectl with certificate auth in kind
- [ ] 10a.6 Environment override mapping per profile; verify: each built-in profile's tool reads only the generated placeholder config in a session test
- [ ] 10a.7 Linux session filesystem view (mount namespace, placeholder or hidden credential paths); verify: a tool reading `~/.aws/credentials` via the password-database home sees the placeholder and `cat` of a real key file fails
- [ ] 10a.8 macOS and no-namespace fallback with gaps reported; verify: status lists the fallback on macOS CI
- [ ] 10a.9 Credential helpers for git, docker, AWS `credential_process` and kubectl exec; verify: each tool authenticates through its helper and only placeholders are returned
- [ ] 10a.10 Credential-printing commands show placeholders; verify: `gh auth token`, `aws configure get`, `kubectl config view --raw` print no real value in a session
- [ ] 10a.11 Project file scan, registration, watch and move-to-store offer; verify: a fixture `.env` key is redacted from the first request and moved only after confirmation
- [ ] 10a.5 Profiles for terraform and OpenTofu, gcloud, az, pip and twine, cargo, hcloud, doctl; verify: one end-to-end command per profile against a fake or test endpoint

## 11. Vaultwarden and more providers

- [x] 11.1 Vaultwarden adapter with client-side decryption and unlock key by reference; verify: contract suite against Vaultwarden in podman
- [x] 11.2 OpenAI Chat Completions and Responses codecs; verify: recorded fixtures and Codex end-to-end run (`TestCodexSession` in `test/e2e/session`)
- [ ] 11.3 Gemini codec; verify: recorded fixtures
- [ ] 11.4 Bedrock, Vertex, Foundry and Claude Platform on AWS with re-signing after redaction; verify: Claude Code end-to-end against faithful fake upstreams

## 11a. More stores

- [ ] 11a.1 HashiCorp Vault adapter (KV v1/v2, namespaces, token, AppRole, Kubernetes, JWT, dynamic leases); verify: conformance suite against Vault dev mode in podman, lease revoked when the grant ends
- [ ] 11a.2 AWS Secrets Manager and SSM Parameter Store adapters with ambient identity and version/stage selectors; verify: conformance suite against LocalStack in podman
- [ ] 11a.3 Google Secret Manager and Azure Key Vault adapters with workload identity; verify: conformance suite against the services or compatible fakes
- [ ] 11a.4 1Password, Bitwarden Secrets Manager and Doppler adapters; verify: conformance suite against each service's test account or recorded fixtures
- [x] 11a.5 Local env and file sources with read-only capabilities declared; verify: conformance suite locally, writes to read-only sources refused
- [ ] 11a.5b Kubernetes Secrets adapter and local SOPS-file and OS keyring sources with read-only capabilities declared where applicable; verify: conformance suite in kind and locally, writes to read-only sources refused

## 12. Shared state and Kubernetes

- [x] 12.1 Postgres-notify events for multiple replicas; verify: two replicas sharing one PostgreSQL agree on grants and approvals
- [x] 12.2 Kubernetes service account identity; verify: TokenReview-based identity in kind
- [x] 12.2e Verified service account tokens in the redaction set until they expire, redaction only; verify: a pod's token in a tool result reaches the fake provider as `⟦scrim:scrim-kubernetes-credential:…⟧` through the real data plane, and the default JWT detector matches a projected token's shape
- [ ] 12.2a scrim as identity provider: per-session signed tokens, discovery document, signing keys, rotation; verify: OpenBao JWT auth accepts scrim tokens and rejects expired or wrong-audience ones
- [ ] 12.2b Per-agent store identity with token exchange (Vault and OpenBao JWT, AWS web identity, Google federation, Azure federated credentials, Infisical OIDC) and the intersection rule; verify: one agent is denied by store policy that another passes, and CloudTrail-style audit shows the agent's session name against LocalStack
- [x] 12.2c Kubernetes service account passthrough and static per-agent fallback reported in doctor; verify: two agent pods with different service accounts get different OpenBao policies in kind
- [ ] 12.2d Separate redaction identity and the stricter per-agent redaction option marked as weakening; verify: a value the agent cannot use is still redacted
- [x] 12.3 Helm chart (Deployment, Service, PDB, HPA, NetworkPolicy) and Kyverno injection policy; verify: agent pod in kind reaches providers only through scrim
- [x] 12.3a Chart on the shared chart template (component library, Secret slots, `global.ha`, closed generated schema, helm test, helm-unittest), published to `oci://ghcr.io/heliopsy/charts/scrim` signed keyless with SBOM and provenance; verify: `deploy/helm/scrim/ci/verify.sh` on Helm 3 and 4, `ct install` on kind in CI
- [x] 12.3b Kyverno policies on `policies.kyverno.io/v1` (MutatingPolicy, ValidatingPolicy, ImageValidatingPolicy) for Kyverno 1.17 and later, Kyverno pin removed; verify: `test/k8s/e2e.sh` on the latest Kyverno injects both modes, refuses a pod in an unprepared namespace, leaves a labelled Deployment as written, admits the signed release image and refuses an unsigned one
- [x] 12.4 OpenBao and Infisical Kubernetes auth; verify: no static store credentials in the kind test
- [ ] 12.5 Edge forwarder for ssh-agent, localhost database ports and the exec broker in agent pods; verify: `git push` over SSH and `psql` from an agent pod with a central scrim in kind

## 13. Local service and persistent interception (M2 exit)

- [x] 13.1 systemd unit and Quadlet with a dedicated user, `scrim install` and `scrim uninstall`; verify: uninstall leaves no trace in a VM test (`test/service/vm-test.sh`: system and user units in a systemd container; Quadlet in unit tests)
- [x] 13.2 Forward proxy listener; verify: an agent with HTTPS_PROXY set is redacted
- [x] 13.2a `chatgpt.com` and `ab.chatgpt.com` routed to the LLM proxy (Responses codec for `/responses`, generic JSON elsewhere); verify: CONNECT to either through the forward proxy reaches the fake provider with placeholders only
- [ ] 13.3 Transparent mode with nftables per UID or cgroup and SNI routing; verify: an unconfigured agent is redacted and cannot reach providers directly
- [ ] 13.4 Managed agent settings mode; verify: Claude Code refuses any endpoint but scrim
- [ ] 13.5 System trust store and Java truststore installation for the modes that need them; verify: a Java client and a system-store client trust scrim in transparent mode, and uninstall reverts both
  - progress: the system trust store (`update-ca-certificates`, `update-ca-trust`) is installed and reverted by `scrim install --system`, and a system-store client trusts scrim through the forward proxy in the VM test; Java truststore and transparent mode open
- [x] 13.6 Deployment guides with tested examples for every target and GitOps tool (docs/deploy, deploy/examples); verify: `just deploy-examples-check` and `just deploy-examples-smoke` pass in CI

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
