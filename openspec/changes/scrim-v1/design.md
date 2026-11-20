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
by the same path.

**Language: CEL** (`cel.dev/cel-go`). It is typed, so a misspelt field fails at load time; it is
side-effect free and cost-bounded; and its `&&`/`||` treat errors the way a fail-closed rule needs
(`false && error` is false, `true || error` is true). Rego was the alternative; it is a larger
language for a problem that is mostly string matching, and its Go-only runtime gives the data plane
nothing either way. Rules see `op`, `agent`, `secret`, `provider`, `dest`, `tool` and `now`, plus a
`glob` function whose syntax is small enough to implement identically in both halves.

**Ordered evaluation.** Every rule is evaluated. Among matches deny wins over ask over allow; within
the winning effect the first rule in file order is the one reported and whose settings (approval
timeout, notifiers, grant ttl, max ttl, uses, scope) apply. No match applies `policy.default`
(deny). A rule whose expression errors on a request (a missing label) counts as matching if it
denies or asks and as not matching if it allows, so an error can only tighten the outcome.

**The data plane does not run CEL.** The control plane lowers each rule into disjunctive normal
form over conditions the data plane evaluates with plain string operations: `in` (equality), prefix,
suffix, contains, glob and has-key on the fields the data plane knows. Anything else (`now`,
regular expressions, field-to-field comparisons, macros, string functions, or a rule whose DNF
exceeds 64 clauses) becomes a residual part of its clause. The data plane evaluates every rule to
match, no match or unknown with the same three-valued logic as CEL, then takes, for deny, ask and
allow in that order, the first rule at that level that is not a no-match: unknown sends the request
to the control plane; deny denies; ask goes to the control plane; allow allows unless the rule has a
side effect (a grant ttl), which also goes to the control plane. The data plane therefore decides
locally only when its answer is exactly the control plane's, same effect and same rule; a
residual rule costs a control-plane call only when it could change the outcome. The table travels
in `Policy.table` (`table_format` 1); the reference evaluator is Go (`policy.Snapshot.Evaluate`), a
fuzz target cross-checks it against CEL, and `internal/policy/testdata/conformance.json` holds
vectors the Rust evaluator must reproduce.

**Grants and approvals stay in the control plane.** A grant can only turn an ask into an allow, so
the data plane only ever needs a grant after it has already decided to ask; the control plane
re-evaluates the full rule set, then checks grants (read from the state backend on every use, so
expiry, revocation and use counts take effect on the next request on every replica sharing the
backend), then raises an approval. Decisions come back through single-use links: an HMAC-SHA256
token over approval ID, action, expiry and notifier, signed with `approvals.signing-key` (shared by
replicas, rotatable by key ID). An approval leaves pending once, so the first decision settles it
and every later token is refused. A waiting operation re-reads its approval every
`approvals.poll-interval`, which bounds how long a decision recorded on another replica takes to
release it.

**Notifiers only deliver.** ntfy buttons post to the decision links. The generic webhook speaks
nono's approval webhook v1 (submit, then poll) so one approval service can serve nono and scrim; a
grant or denial from it settles through the same token check, and any error settles nothing and
leaves the approval to expire. The terminal path is `scrim approve` / `scrim deny` over the admin
API.

**Break-glass** state is the newest `breakglass.engaged` or `breakglass.released` audit entry, so it
is durable with the backend, shared between replicas (each re-reads it every
`policy.deny-all-refresh`) and cannot change without an audit entry. While it is set the snapshot
carries `break_glass`, the engine denies, grants are not honoured, approvals cannot be created or
approved, and pending ones are denied.

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

Metrics follow the same rule. With `metrics.enabled` the data plane aggregates its own counters and
fixed-bucket histograms in process (atomics only on the request path, one route lookup per request)
and the control plane reads them with the `Metrics` call once per Prometheus scrape, then serves
them next to its own on its one endpoint, scrubbed with the rest. A separate loopback `/metrics` on
the data plane was rejected: it would be a second listener in the process that holds the values, a
second port to authenticate and scrape, and a second place to scrub. Pull per scrape keeps the cost
off the hot path (nothing is formatted or sent between scrapes) and needs no new stream. The call
is additive: an older data plane answers UNIMPLEMENTED, which the control plane reads as "no data
plane metrics", so the protocol stays 1. Labels are bounded by construction (routes, codecs, codes,
enumerations, a cap per series set) and checked again by the control plane against an allowlist.

### D13. Matching stays near constant speed as the secret set grows

Aho-Corasick slows from GB/s to about 100 MB/s as the set grows past a few hundred values. Since
every value is at least the minimum length (default 8 bytes), the matcher hashes each 8-byte
window of the body, checks the hash against a set built from every value's and variant's first 8
bytes, and verifies candidates exactly. The set check is a few instructions per byte whatever the
set size. Aho-Corasick remains for small sets, where its SIMD prefilter is faster, and as the
reference implementation in tests; the two must produce identical output on every fixture.

### D14. Data-plane callers are verified by a per-ask proof of the session token

The data plane takes a caller only from the transport and holds no session verifiers, so it cannot
tell a session from a claim. A session id alone is public (audit entries, status), so the control
plane needs proof that the request carried the token. Two ways were considered:

- **Session id plus a peer check.** The control plane would map the client's TCP connection to a
  process and check it descends from the session's root. That keeps the token entirely out of the
  data plane, but it needs a socket-to-process lookup that only Linux offers without privileges
  (`/proc/net/tcp`), leaves macOS sessions unverifiable, and over the forward proxy proves nothing
  more than the session id on any platform where the lookup fails.
- **A digest of the token in the ask.** Chosen. Clients send the token where it never reaches an
  upstream: the password of `Proxy-Authorization` (`HTTPS_PROXY=http://<id>:<token>@...`, the header
  ends at the proxy) or the value of `x-scrim-session` (stripped by the base-URL listener). On
  arrival the data plane reduces the token to its verifier `v = SHA-256("scrim session token
  v1\0" || secret)` (what the control plane stores) and drops it: the token is never logged, kept
  past the request head or forwarded, and `v` lives in a zeroed type with a redacting `Debug`. An
  ask carries `session_proof = HMAC-SHA256(v, "scrim session proof v1\0" || session id || "\0" ||
  ask id || deadline)`, an additive field of `AskCaller` (protocol stays 1). The control plane
  recomputes it from the stored hash, then checks the session is active and, over a Unix socket,
  that the peer is the session's user and in its process tree. The proof is bound to one ask, so a
  logged proof cannot be replayed for another, and it reveals neither the token nor `v`.

A caller that names a session without a valid proof, or whose session is revoked, expired or used
outside its tree, is evaluated as unknown (deny-leaning) and audited with the reason; it never
falls back to its peer mapping. A Unix peer without a session is the innermost active session of
its user whose tree it is in, else its `identity.peers` mapping. Over TCP the process tree cannot
be checked, so a same-user process that reads the token from an agent's environment can act as
that session there; the agent API and Unix sockets still enforce the tree. The data plane gets no
session or peer map, so every rule on the agent of a request that names a session costs one ask.

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
- Which chat notifier ships after ntfy and the webhook (Telegram or Slack), decided by first users.
