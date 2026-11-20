## Purpose

Defines where scrim keeps its non-secret state (approvals, grants, sessions, audit), how events and
rate limits are shared, and how scrim behaves with one process or many replicas, without ever
persisting a secret value.

## ADDED Requirements

### Requirement: Selectable state backend

scrim SHALL support the state backends `memory`, `sqlite` and `postgres`, selected by
`state.backend`. The default SHALL be `sqlite` for local profiles and SHALL be stated per profile.

#### Scenario: Choose postgres

- **WHEN** `state.backend` is `postgres` and `state.postgres.dsn` resolves
- **THEN** approvals, grants, sessions and audit metadata are stored in PostgreSQL

### Requirement: Memory backend writes nothing to disk

With the `memory` backend scrim SHALL write no state to disk, and a restart SHALL lose pending
approvals, grants and audit history. Pending requests SHALL then be denied, never allowed.

#### Scenario: Restart with memory backend

- **WHEN** scrim with `state.backend: memory` restarts while an approval is pending
- **THEN** the waiting request is denied
- **AND** previously granted just-in-time access must be requested again

### Requirement: SQLite backend is local and single-process

The `sqlite` backend SHALL store state in one file, by default under `$XDG_STATE_HOME/scrim/`, and
SHALL refuse to run when another scrim process holds the same file.

#### Scenario: Second process on the same file

- **WHEN** a second scrim process starts with the same SQLite file
- **THEN** it refuses to start and names the file and the holding process

#### Scenario: Status while the daemon holds the file

- **WHEN** `scrim status` runs while a scrim process holds the SQLite file
- **THEN** it reports the state backend as in use by that process instead of failing

### Requirement: SQLite on a network filesystem

scrim SHALL detect when the SQLite file is on a network or shared filesystem and SHALL refuse to
start, unless `state.sqlite.allow-network-filesystem` is set, in which case it SHALL warn at start-up
and in status.

#### Scenario: NFS path

- **WHEN** the SQLite file path is on an NFS mount
- **THEN** scrim refuses to start and suggests the postgres backend

### Requirement: No secret value in any backend

No state backend, event backend, rate-limit backend or audit sink SHALL ever receive a secret value
or a mapping from placeholder to value. Only references, placeholders, identities, decisions and
metadata SHALL be stored or sent.

#### Scenario: Inspect stored state

- **WHEN** a test seeds known secrets, runs traffic and then dumps every backend and sink
- **THEN** no known secret value, in any supported encoding, appears in the dump

#### Scenario: Value in a free-text field

- **WHEN** a caller passes a known secret value inside a reason, target or attribute of a state change
- **THEN** the stored row holds a redacted marker in its place

### Requirement: Versioned automatic migrations

scrim SHALL apply schema migrations automatically and in order at start-up, SHALL record the applied
version, and SHALL refuse to start against a schema newer than it understands.

#### Scenario: Replicas start together

- **WHEN** several replicas start at once against an unmigrated PostgreSQL database
- **THEN** the migrations are applied once and every replica starts at the same schema version

#### Scenario: Downgrade attempt

- **WHEN** an older scrim starts against a database migrated by a newer release
- **THEN** it refuses to start and names both schema versions

### Requirement: Stateless placeholder resolution across replicas

Placeholder generation and resolution SHALL depend only on the shared placeholder key and the
secret values each replica loads, so any replica SHALL produce and resolve the same placeholders
without shared lookup state.

#### Scenario: Request and reply on different replicas

- **WHEN** a request is redacted on replica A and a later turn is handled by replica B
- **THEN** replica B produces identical placeholders for the same values and resolves them

### Requirement: Consistent approvals and grants across replicas

With a shared backend, an approval decision or grant change SHALL take effect on every replica within
a documented bound, and a revoked grant SHALL never be honoured after that bound.

#### Scenario: Revoke on one replica

- **WHEN** an operator revokes a grant through replica A
- **THEN** replica B refuses requests relying on that grant within the documented bound

#### Scenario: Last use of a grant through two replicas

- **WHEN** two replicas try to use the last remaining use of a grant at the same time
- **THEN** exactly one use succeeds and the other is refused as unusable

### Requirement: Ordered event outbox

Events SHALL be written to an outbox in the same transaction as the state change they announce, and
a reader that follows the outbox by increasing event ID SHALL see every committed event exactly
once, even when transactions on different replicas commit in a different order than they started.

#### Scenario: Concurrent writers on two replicas

- **WHEN** two replicas commit events concurrently while a third reader tails the outbox by ID
- **THEN** the reader sees every event exactly once and never an ID lower than one it has already seen

### Requirement: Pending approvals survive replica loss

With a durable backend, a pending approval SHALL survive the loss of the replica that created it, and
a decision made afterwards SHALL be applied by whichever replica the waiting agent is connected to,
or the request SHALL be denied if no replica holds it.

#### Scenario: Replica dies while waiting

- **WHEN** the replica holding a waiting request dies and the user then approves
- **THEN** the approval is recorded
- **AND** the agent's retried request is honoured under the resulting grant

### Requirement: Selectable event backend

scrim SHALL distribute internal events (decisions, grant changes, store refreshes, config reloads)
through `events.backend`: `local`, `postgres` (listen/notify), `valkey` or `nats`. Multi-replica
deployments SHALL reject `local` at start-up.

#### Scenario: Multiple replicas with local events

- **WHEN** scrim is configured with more than one replica and `events.backend: local`
- **THEN** start-up fails with an error naming `events.backend`

### Requirement: Selectable rate-limit backend

Per-agent rate limits and budgets SHALL be enforced through `ratelimit.backend`: `local` (per
replica, documented as approximate across replicas) or `valkey` (shared, exact).

#### Scenario: Shared limit

- **WHEN** `ratelimit.backend` is `valkey` and an agent exceeds its limit through two replicas combined
- **THEN** further requests from that agent are refused with a rate-limit error

### Requirement: Multiple audit sinks

scrim SHALL write audit events to one or more sinks configured together: `db`, `otlp`, `loki`,
`kafka`. Each event SHALL be delivered to every configured sink.

#### Scenario: Two sinks

- **WHEN** audit sinks `db` and `otlp` are configured
- **THEN** every audit event appears in both

### Requirement: Audit backpressure is explicit

When an audit sink is slow or unavailable, scrim SHALL apply the configured policy per sink: `block`
(requests wait, bounded by a timeout, then fail closed) or `drop` (events dropped and counted). Drops
SHALL be exposed as a metric and in status; events SHALL never be dropped silently.

#### Scenario: Drop policy under outage

- **WHEN** the `kafka` sink is unreachable and its policy is `drop`
- **THEN** requests continue
- **AND** the dropped-event counter for `kafka` increases and status reports the sink as degraded

#### Scenario: Block policy under outage

- **WHEN** the `db` sink is unreachable beyond its timeout and its policy is `block`
- **THEN** requests that would emit audit events are refused, not forwarded unaudited
