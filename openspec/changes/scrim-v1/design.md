## Context

See proposal.md for why scrim exists and what v1 covers. The requirements live in the capability
specs under `specs/`. This document records how the pieces fit and why each choice was made.

Constraints that shape the design:

- The model provider must never receive a known secret value, and the agent must keep working as
  if nothing were in between. Both halves are requirements, so a design that blocks or degrades the
  agent is as wrong as one that leaks.
- Users already run Vaultwarden, Infisical and OpenBao. scrim brokers them and does not replace
  them.
- One binary and one configuration format must serve a laptop and a large Kubernetes deployment.
- The sister project heliopsy/tix sets the engineering conventions: one service layer behind every
  access path, mutations with their audit entry and event in one transaction, OpenSpec first.

## Goals / Non-Goals

**Goals:**

- Exact matching of known values, not guessing, as the primary defence; detectors only as a net.
- A data plane whose added latency is invisible next to model latency, enforced by CI.
- The same policy, approval and audit path for every way a secret can be touched: LLM traffic,
  tool traffic, exec, SSH, database and MCP.
- Every setting reachable from file, environment and flag.

**Non-Goals:**

- Personal data (names, addresses) as a first-class target. The detector interface leaves room for
  it later; v1 is about secrets.
- Protecting the agent's local transcript on disk. The user's machine is trusted; this is a
  documented limitation.
- Replacing a secret store, or offering its own long-term secret storage beyond the stores it
  brokers.
- Scanning images and other binary content for secrets in v1. The policy is block or pass, and the
  limitation is documented.

## Decisions

### D1. Control plane and data plane are separate components, possibly in different languages

```
┌─────────────────────────────────┐   local socket    ┌──────────────────────────────────┐
│ control plane                   │ ────────────────▶ │ data plane                       │
│ CLI, admin API, MCP, approval UI│  value dictionary │ LLM proxy + provider codecs      │
│ policy, approvals, grants       │  policy snapshot  │ redactor + independent guard     │
│ store adapters, audit, events   │  decisions        │ tool proxy, exec, ssh, db modes  │
│ identity, configuration         │ ◀──────────────── │ interception listeners           │
└─────────────────────────────────┘  events, "ask"    └──────────────────────────────────┘
```

The data plane handles every byte of agent traffic and must be fast and boring. The control plane
handles decisions, stores and people and changes often. Splitting them keeps the hot path small
enough to fuzz exhaustively and lets each half use the language that suits it.

**Language: Go control plane, Rust data plane.** `bench/redact-bench` implements the same
redactor and stream restorer in Go and Rust, plus a combined variant (Go control plane driving a
Rust data plane over the real boundary), and measures them single-core and at proxy level. Full
results are in `bench/redact-bench/results/summary.md`. The rule agreed before seeing numbers: if
Rust is at least 3x better on CPU per GB or clearly better on tail latency, the data plane is Rust
and the control plane Go; otherwise everything is Go.

| Input (10,000 secrets unless noted) | Go | Rust | Ratio |
|---|---|---|---|
| Redact, single core, 10 secrets | 225 to 245 MB/s | 3,300 to 4,450 MB/s | 16 to 18x |
| Redact, single core, 1,000 secrets | 130 to 215 MB/s | 250 to 415 MB/s | 1.8 to 1.9x |
| Redact, single core, 10,000 secrets | 27 to 32 MB/s | 87 to 102 MB/s | 3.0 to 3.5x |
| Stream restore per chunk | 24 µs | 5.4 µs | 4.4x |
| Proxy CPU per GB, paced streams, 10 / 1,000 conns | 96 / 37 s | 42 / 13.6 s | 2.3 / 2.7x |
| Proxy CPU per GB, 1 MB bodies unpaced, 10 conns | 35.7 s | 12.2 s | 2.9x |
| Added p99, paced streams, 10 conns | 57 ms | 12 ms | 4.8x |
| Resident memory | 1.6 to 3.1 GB | 335 MB | about 5x |
| 1 MB bodies unpaced, 1,000 conns | collapsed | 177 req/s | |

CPU per GB lands just under 3x at proxy level; tail latency, memory and behaviour under overload
are clearly better, so the rule selects the split. The combined variant ran at 95 to 106% of pure
Rust throughput with equal CPU per GB when the data plane decides locally from a pushed snapshot
and batches audit, so the boundary costs nothing measurable. Synchronous per-request calls across
it cost 15 to 30% of throughput, which is why the data plane never waits on the control plane on
the hot path (D7, D12).

The control plane is Go to reuse tix's capability registry, store layer, auth, MCP and CI, and
because most store clients (OpenBao, Vault, Infisical, Kubernetes, the cloud SDKs) are Go-first.

Caveats recorded with the result: the benchmark machine carried unrelated load; the Go proxy
buffered whole response bodies, which penalises Go at proxy level but not in the single-core
numbers; and neither language met the first 1 ms per 1 MB target at 10,000 secrets (Rust about
10 ms). That is an algorithm problem, addressed in D13; the performance spec now sets a budget
that can be measured and tightened.

Alternatives considered: all Rust (same data-plane speed as the split, but rewrites the control
plane tix already solved and loses the Go store SDKs); all Go (simplest build, but 5x the memory
per replica, slow matcher rebuilds and collapse under overload); Rust linked into the Go process
through cgo (one process, but no isolation between the halves and no speed advantage over D11).

### D2. Match the raw bytes, never decode the request

The redactor runs one multi-pattern automaton over the raw request bytes. Every known value is
compiled with its encoded variants: JSON-escaped, base64 at all three alignments, base64url, hex,
URL-encoded. Decoding the JSON body would cost more than the matching and would re-serialise the
body, breaking byte stability.

Responses are different: streamed events are small, so the restorer decodes each delta string,
resolves placeholders and re-encodes, with a holdback of at most one placeholder length per content
block so a placeholder split across chunks is still found.

The automaton is rebuilt off the request path whenever the value set changes and swapped in
atomically. Requests never wait for a rebuild.

### D3. Deterministic placeholders, versioned key

`⟦scrim:<ref-slug>:<hmac>⟧`, where the HMAC is over the value with a versioned placeholder key.
The same value always yields the same bytes, which keeps prompt caching working and means replicas
need no shared lookup table: any replica holding the key and the dictionary resolves any
placeholder. Rotation adds a key version; old placeholders keep resolving until their conversations
end. The format is chosen to survive context compression (tested against caveman) and to be
unambiguous in shell, JSON and code.

### D4. Two independent checks before anything leaves

The redactor and the guard share no matching code. The guard scans the exact outgoing bytes,
decoding transforms the redactor does not attempt, and either repairs or withholds. Any error in
either refuses the request. Unknown request fields are redacted by default, because a provider can
add a field that carries data (Claude Code's `safeguards` field carried the home directory).

### D5. Credentials are injected at the network edge, never restored into commands

Restoring a credential into a `curl` command lets a prompt-injected model send it anywhere. So a
credential stays a placeholder in every command, file and tool argument. It becomes the real value
only inside the tool proxy, exec broker, ssh-agent or database proxy, and only toward the hosts the
credential is bound to. Display-type values (data the agent needs to read or keep in a file it
already has) follow the per-tool restore policy instead, with context-aware escaping. This is the
lesson taken from veil's tool policy, applied to credentials.

The tool proxy (`dataplane/crates/scrim-toolproxy`) checks bindings against the connection it
opens, not against what the request claims: the Host header, `:authority` and TLS server name must
match the CONNECT target, so a shared front end cannot route an injected token to another tenant.
Every placeholder in a request is checked before any is substituted, and each value is encoded for
the syntax it lands in (percent-encoding in URLs and forms, string escaping in JSON, per part in
multipart). CA rotation serves leaves with a cross certificate during the overlap, so clients that
trust only the previous CA keep working without a second leaf cache.

### D6. Stores are brokered, and scrim enforces write-only itself

scrim is the only holder of store credentials. Agents call scrim, never the store, so write-only,
approvals and grants work the same on every store regardless of the store's own permission model
(Infisical's free tier has no custom roles, Vaultwarden has none at all). Native features are used
where they add something: OpenBao control groups for paths that need a second gate, Kubernetes auth
for credential-free store login in clusters.

Vaultwarden is zero-knowledge, so the adapter decrypts client-side with an unlock key supplied at
start. The recommended setup is a dedicated Vaultwarden account or organisation for agents, so a
compromised scrim exposes that and not a personal vault.

### D7. Policy in an expression language, one decision path

Rules are expressions over agent, secret, provider, destination and tool, evaluated in the control
plane and pushed to the data plane as a compiled snapshot. The data plane decides allow and deny
locally; only "ask" crosses back to the control plane, which creates the approval, notifies, waits
and records the grant. Approvals deny on timeout. JIT grants are pre-approvals with a ttl, checked
by the same path. Candidates for the expression language are CEL and Rego; the choice follows D1.

### D8. Interception is a set of listeners in front of one engine

Base URL and Unix socket, forward proxy (CONNECT), transparent (original-destination, routed by
SNI) and an SNI listener on 443 all feed the same provider codecs. Enforcement that agents cannot
bypass comes from the host (nftables per UID or cgroup, eBPF cgroup connect hooks), the cluster
(NetworkPolicy, injection by label) or the agent (managed settings pinning the endpoint). Hooks are
a separate adapter calling the engine's local API and are reported as partial protection.

eBPF is an option, not a dependency: it gives per-cgroup redirection and direct-egress denial
without UID games, but needs a privileged loader and Linux. TLS interception and CA trust are still
required; eBPF only moves the traffic.

### D9. State is pluggable and holds no values

Memory, SQLite and PostgreSQL behind one interface, chosen in configuration. SQLite is an embedded
file, not a service, and the local default. Events (local, Postgres notify, Valkey, NATS),
rate limits (local, Valkey) and audit sinks (database, OTLP, Loki, Kafka) are independent choices
so a large deployment can scale each separately. No backend ever stores a secret value or a
placeholder-to-value mapping; values live in process memory only, wiped after use.

### D10. One configuration contract

Every setting has a dotted key, settable by file, `SCRIM_*` environment variable and flag, with
flag > environment > file > default. The schema is versioned and published; `scrim config show
--effective` shows where each value came from. Secret-valued settings take references instead of
literals. Settings that weaken an invariant say so in their name and are reported at start-up and
in status.

### D11. One file to install, two processes at runtime

The release binary `scrim` is the Go control plane with the Rust data plane binary embedded. On
start it runs the data plane as a child process: on Linux from memory (`memfd_create` and
`fexecve`), falling back to a file in `$XDG_RUNTIME_DIR` checked against the embedded hash when
`vm.memfd_noexec` forbids it; on macOS from the user cache directory, also hash-checked. The child
inherits one end of a socketpair and nothing else. Separate processes keep the halves isolated:
the data plane holds the value dictionary, runs with fewer privileges and locked memory, and a
crash on either side makes the other refuse traffic.

The data plane is also published on its own (`scrim-dataplane` binary and image) for Kubernetes
sidecars and edge forwarders, which need it and not a control plane per pod. Both come from the
same build.

### D12. The boundary is protobuf over the inherited socket, off the hot path

The control plane and data plane talk gRPC over the inherited socketpair, schema in
`proto/scrim/dataplane/v1`, generated code committed for Go and Rust. The control plane pushes
versioned snapshots (value dictionary, placeholder keys, compiled policy, routes, bindings) and the
data plane acknowledges the version it applied. The data plane streams audit events in batches and
sends "ask" decisions, the only call that waits, and only for requests a rule sends to a human.
Every message carries the protocol version; a mismatch refuses to start.

### D13. Matching stays near constant speed as the secret set grows

Aho-Corasick slows from GB/s to about 100 MB/s as the set grows past a few hundred values. Since
every value is at least the minimum length (default 8 bytes), the matcher hashes each 8-byte
window of the body, checks the hash against a set built from every value's and variant's first 8
bytes, and verifies candidates exactly. The set check is a few instructions per byte whatever the
set size. Aho-Corasick remains for small sets, where its SIMD prefilter is faster, and as the
reference implementation in tests; the two must produce identical output on every fixture.

## Risks / Trade-offs

- [An agent invents a transform the guard does not decode] → the bypass matrix grows with every
  finding and gates releases; credentials are never restored into commands, so the remaining risk
  is mostly display-type values.
- [Context compression rewrites a placeholder] → placeholder format tested against caveman in the
  first milestone; a mangled placeholder fails to resolve, which is safe but visible.
- [Provider adds an undocumented field or event type] → unknown fields redacted by default, unknown
  stream events passed through the guard, recorded fixtures refreshed per release.
- [TLS interception breaks a client that pins certificates] → the client fails closed; documented
  per agent.
- [Value dictionary in memory on every data-plane replica] → central deployment preferred over
  sidecars; memory locked and wiped; dedicated agent accounts in stores limit blast radius.
- [Short secrets cause false positives or are missed] → minimum length configurable; short values
  matched only in exact and encoded forms; documented.
- [Two languages] → the boundary is a small versioned protocol, tested from both sides; the data
  plane stays narrow.
- [Running an embedded binary from memory is blocked by hardening] → hash-checked file fallback,
  and the standalone data plane binary for locked-down hosts.
- [Store outage] → keep the last known redaction set, fail closed for injection when a value is
  unavailable, report degraded.

## Migration Plan

New product, nothing to migrate. Rollout per user: install, `scrim doctor`, run one agent through
`scrim run`, check `scrim proxy --capture`, then switch to a persistent interception mode.
`scrim uninstall` reverts every system change it made (CA trust, nftables or eBPF programs, managed
settings, units).

## Open Questions

- Exact placeholder alphabet and length, settled by the caveman survival test in the first
  milestone. Changing it does not change any requirement.
- Which notifier ships first after ntfy (Telegram or generic webhook), decided by first users.
