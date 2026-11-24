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
SHALL refuse to run when another scrim process holds the same file. `scrim status` and `scrim
doctor` SHALL open the file read-only, without taking the process lock and without creating or
migrating it, so they never stop a scrim process from starting.

#### Scenario: Second process on the same file

- **WHEN** a second scrim process starts with the same SQLite file
- **THEN** it refuses to start and names the file and the holding process

#### Scenario: Status while the daemon holds the file

- **WHEN** `scrim status` runs while a scrim process holds the SQLite file
- **THEN** it reports the state backend as in use by that process instead of failing

#### Scenario: Status while the daemon is starting

- **WHEN** `scrim status` has the SQLite file open and the daemon starts at that moment
- **THEN** the daemon takes the lock and opens the file, and status still reports the schema version

#### Scenario: Status before the first start

- **WHEN** `scrim status` runs and the SQLite file does not exist yet
- **THEN** it reports the file as not created yet and creates nothing

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

### Requirement: Status reads PostgreSQL state read-only

`scrim status` and `scrim doctor` SHALL open the `postgres` backend in sessions with
`default_transaction_read_only=on`, SHALL NOT migrate it, run DDL, write to it or take the advisory
locks the daemons use, and SHALL report the database's schema version against the version the binary
expects. Only a starting scrim daemon SHALL migrate the schema. When the schema is at the expected
version, status SHALL report the backend as it does for a migrated database.

#### Scenario: Status before any daemon started

- **WHEN** `scrim status` runs against an empty PostgreSQL database
- **THEN** it reports the schema as not created yet and creates nothing

#### Scenario: Status against an older schema

- **WHEN** `scrim status` runs against a schema older than its binary expects, as during a rolling
  upgrade
- **THEN** it reports the schema as behind, says a daemon will migrate it, and leaves it unchanged

#### Scenario: Status against a newer schema

- **WHEN** `scrim status` runs against a schema migrated by a newer release
- **THEN** it reports the state backend as unhealthy and names both schema versions

#### Scenario: Status with a read-only role

- **WHEN** `state.postgres.dsn` names a role that can only read the scrim tables
- **THEN** `scrim status` reports the schema version and a healthy backend

#### Scenario: Daemon migrating while status runs

- **WHEN** a daemon holds the migration lock or migrates while `scrim status` is connected
- **THEN** neither waits for the other, and status reports the version the daemon migrated to

### Requirement: Stateless placeholder resolution across replicas

Placeholder generation and resolution SHALL depend only on the shared placeholder key and the
secret values each replica loads, so any replica SHALL produce and resolve the same placeholders
without shared lookup state.

#### Scenario: Request and reply on different replicas

- **WHEN** a request is redacted on replica A and a later turn is handled by replica B
- **THEN** replica B produces identical placeholders for the same values and resolves them

### Requirement: Consistent approvals and grants across replicas

With a shared backend, an approval decision or grant change SHALL take effect on every replica within
a documented bound, and a revoked grant SHALL never be honoured after that bound. Grants and sessions
SHALL be read from the state backend on every use, so a revocation SHALL be refused on the next
request on every replica; neither half SHALL cache an allow answer or a grant between requests.

#### Scenario: Revoke on one replica

- **WHEN** an operator revokes a grant through replica A
- **THEN** replica B refuses the next request relying on that grant

#### Scenario: Revoke a session on one replica

- **WHEN** an operator revokes a `scrim run` session through replica A
- **THEN** replica B refuses the session token on its next request

### Requirement: Decisions reach the waiting replica by event

With `events.backend: postgres`, a decision recorded on one replica SHALL release the operation held
for it on another replica as soon as the `approval.decided` event is delivered, without waiting for
`approvals.poll-interval`.

#### Scenario: Decision on another replica

- **WHEN** a request is held for approval on replica B and the approval is decided on replica A
- **THEN** replica B releases the request within the event delivery bound, well before
  `approvals.poll-interval`

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
through `events.backend`: `local`, `postgres` (listen/notify), `valkey` or `nats`. `local` SHALL read
the outbox every `events.poll-interval` and at once after a commit made by the same process. `postgres`
SHALL send a notification inside the transaction that writes the outbox, SHALL listen on a dedicated
connection, and SHALL require `state.backend: postgres`.

#### Scenario: Break-glass reaches another replica

- **WHEN** `events.backend` is `postgres` and an operator engages break-glass through replica A
- **THEN** replica B denies, pushes a snapshot with break-glass set to its data plane and denies its
  pending approvals, without waiting for `policy.deny-all-refresh`

### Requirement: Valkey and NATS events

With `events.backend` `valkey` or `nats`, each replica SHALL publish a wake-up carrying no data on a
Valkey channel (`events.valkey.channel`) or NATS subject (`events.nats.subject`) after each of its
commits that emitted an event, SHALL subscribe to it, and SHALL publish a wake-up that could not be
sent once its connection is back. Every events backend SHALL pass one shared contract suite.

#### Scenario: Decision through Valkey

- **WHEN** `events.backend` is `valkey`, three replicas share PostgreSQL state, and approvals held on
  each replica are decided concurrently on another
- **THEN** every held request is released with that decision within the event delivery bound
- **AND** every replica delivers every outbox event exactly once, in the same order

#### Scenario: Commit while cut off from NATS

- **WHEN** `events.backend` is `nats` and replica A commits an event while its connection to NATS is
  down
- **THEN** replica B delivers the event once A's connection is back, without waiting for its poll

### Requirement: Replica count is declared

The number of replicas SHALL be declared by `deployment.replicas`. With more than one, start-up SHALL
reject `local` events and a state backend that is not shared (`memory`, `sqlite`), naming the setting.

#### Scenario: Multiple replicas with local events

- **WHEN** scrim is configured with more than one replica and `events.backend: local`
- **THEN** start-up fails with an error naming `events.backend`

#### Scenario: Multiple replicas with unshared state

- **WHEN** scrim is configured with more than one replica, `events.backend: postgres` and
  `state.backend: sqlite`
- **THEN** start-up fails with an error naming `state.backend`

### Requirement: No event lost when the listener drops

Every events backend SHALL deliver by following the outbox from the newest event at start-up, and
notifications SHALL be wake-ups only. A replica SHALL read the outbox from the last event it delivered
after every listener (re)connection and on every notification, SHALL poll the outbox every
`events.poll-interval` while the listener is down, and SHALL reconnect with bounded, jittered
backoff. Each event SHALL be delivered to a replica's subscribers once, in ID order.

#### Scenario: Event committed while the listener is down

- **WHEN** a replica's listening connection is terminated and another replica commits an event
  before it reconnects
- **THEN** the event is delivered once the listener reconnects, even though its notification was lost

### Requirement: Replicas detect configuration drift

Each replica SHALL record a `config.reloaded` audit entry and event when it starts serving and after
each reload, whose subject is a digest of its effective configuration that reveals no setting value.
A replica that receives a different digest from a peer SHALL log a warning naming both digests.

#### Scenario: Replicas with different configurations

- **WHEN** replica B starts with a configuration different from replica A's
- **THEN** replica A logs a warning with both configuration digests
- **AND** neither the audit entry nor the event contains a setting value

### Requirement: Selectable rate-limit backend

Per-agent rate limits and budgets SHALL be enforced through `ratelimit.backend`: `local` (per
replica, documented as approximate across replicas) or `valkey` (shared, exact).

#### Scenario: Shared limit

- **WHEN** `ratelimit.backend` is `valkey` and an agent exceeds its limit through two replicas combined
- **THEN** further requests from that agent are refused with a rate-limit error

### Requirement: Rate-limited operations

Three classes SHALL be limited per agent, each with a rate, an interval and a burst
(`ratelimit.<class>.*`, a rate of 0 turning it off): `agent-api` (every agent tool call), `approvals`
(every approval created) and `asks` (every `secret_ask_human`). A request the backend cannot decide
SHALL be refused. Backend keys SHALL be a hash of class and agent. Both backends SHALL pass one
contract suite.

#### Scenario: Agent API limit

- **WHEN** an agent calls agent tools faster than `ratelimit.agent-api.*` allows
- **THEN** the call past the burst is refused with `rate_limited` (HTTP 429 on the local API) and audited
- **AND** other agents are not affected

#### Scenario: Limiter unreachable

- **WHEN** `ratelimit.backend` is `valkey` and Valkey does not answer
- **THEN** limited requests are refused, not let through

### Requirement: Multiple audit sinks

scrim SHALL write audit events to one or more sinks configured together: `db`, `otlp`, `loki`,
`kafka`. Each event SHALL be delivered to every configured sink. The `db` sink SHALL always be
written; the others SHALL be additive copies, each fed from its own bounded queue, receiving the
machine-readable audit record after every string has passed the value scrubber.

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

### Requirement: Audit sink losses are counted

A failed write to an external audit sink SHALL be retried with backoff until the sink takes it. Only
a batch the sink rejects as invalid, a `drop` queue overflow and entries still queued at shutdown
SHALL leave a queue undelivered, each counted in `scrim_audit_sink_dropped_total` by reason and
logged.

#### Scenario: Paused sink under drop

- **WHEN** a `loki`, `otlp` or `kafka` sink with policy `drop` stops answering without closing its
  connections
- **THEN** no audited operation waits for it
- **AND** delivered plus dropped entries equal the entries written, and once the sink answers again it
  receives every queued entry

#### Scenario: Paused sink under block

- **WHEN** a sink with policy `block` stops answering and its queue is full
- **THEN** the next audited operation waits up to `audit.<sink>.timeout`, is refused and leaves no
  state change, and `scrim_audit_sink_refused_total` increases
