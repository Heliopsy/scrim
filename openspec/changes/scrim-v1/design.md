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

**Language: pending the benchmark.** `redact-bench` implements the same redactor and stream
restorer in Go and Rust and measures CPU per GB, p99 and p999 at proxy level. The rule agreed
before seeing numbers: if Rust is at least 3x better on CPU per GB or clearly better on tail
latency, the data plane is Rust and the control plane Go (the Linkerd split); otherwise everything
is Go. The control plane is Go either way, to reuse tix's capability registry, store layer, auth,
MCP and CI. The two halves talk over a versioned local protocol whether or not they share a
language, so the split exists even in an all-Go build and the data plane can move later.

Alternatives considered: all Rust (fastest, but rewrites everything tix already solved); a single
Go process with no internal boundary (simplest, but welds the hot path to the control plane and
removes the option to move it).

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
- [Two languages if the benchmark picks the split] → the boundary is a small versioned protocol,
  tested from both sides; the data plane stays narrow.
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
