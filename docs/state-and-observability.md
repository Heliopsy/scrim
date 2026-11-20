# State, audit and observability

scrim keeps approvals, grants, sessions, the audit log and an event outbox in a state backend. None
of it is a secret value: rows hold identities, references, decisions and times. Settings are in the
[configuration reference](configuration.md#settings-reference).

## State backends

| `state.backend` | Use | Where |
| --- | --- | --- |
| `memory` | throwaway runs, tests | process memory; a restart loses everything, pending approvals end denied and `scrim run` sessions end |
| `sqlite` | one scrim on one machine | `state.sqlite.path`, default `$XDG_STATE_HOME/scrim/state.db` |
| `postgres` | shared and multi-replica deployments | `state.postgres.dsn`, a reference such as `env:SCRIM_PG_DSN` |

Defaults per profile: `local` (the default profile) uses `sqlite`; `ci` and `k8s` use `memory` (set
`postgres` for shared state in Kubernetes). The SQLite path follows the environment scrim was
started with, so a service or a test with its own `XDG_STATE_HOME` never touches the user's file.

While `scrim proxy` holds the SQLite file, commands that open state themselves (`scrim catalog`,
`scrim api serve`) cannot open it; `scrim status` reports it as in use, and operator commands go
through the admin API instead.

### SQLite

- WAL journal, `synchronous=NORMAL`, 5 s busy timeout.
- One writer: write transactions go through a single connection and begin `IMMEDIATE`, so writers
  queue in scrim instead of failing with `SQLITE_BUSY`. Reads use a separate pool.
- One process per file: scrim holds an exclusive lock on `state.db.lock` for its lifetime. A second
  process refuses to start and names the file and the holding PID.
- The directory is created `0700` and the file `0600`.
- A file on NFS, SMB, sshfs or another network filesystem is refused. The weakening setting
  `state.sqlite.allow-network-filesystem` overrides that; it is logged at start-up and listed by
  `scrim status`.

### PostgreSQL

- A pgx v5 pool (`state.postgres.max-conns`, default 16); start-up fails after
  `state.postgres.connect-timeout` (15 s) if the server does not answer.
- The DSN is a secret reference. Errors and `scrim status` show `postgres://user@host:port/db`
  without the password.
- Replicas starting together migrate once, under an advisory lock.
- Events are written to the outbox under a transaction advisory lock, so event IDs become visible
  in commit order. A replica tailing the outbox by ID never misses an event that committed late,
  for example a grant revocation made through another replica. The same transaction sends a
  `NOTIFY` for `events.backend: postgres` ([Replicas and events](#replicas-and-events)).
- A grant's last use is a single conditional `UPDATE`: two replicas cannot both take it.
- Sessions are shared: a `scrim run` token minted through one replica is accepted by every other,
  and revoking an agent's sessions is one conditional `UPDATE`.
- Audit IDs are unique and increasing per transaction but, unlike event IDs, not guaranteed to be
  visible in commit order. Page the audit log with `--before`, not as a live tail.

## Replicas and events

Several control plane replicas can share one PostgreSQL database. Each replica follows the event
outbox (rows written in the same transaction as the change they announce) by increasing ID, from
the newest event when it starts, and acts on what other replicas did:

| Event | What a replica does |
| --- | --- |
| `approval.decided` | releases the requests it holds for that approval at once |
| `breakglass.changed` | re-reads the deny-all state, pushes a snapshot to its data plane and denies its pending approvals |
| `config.reloaded` | logs a warning when a peer announces a configuration digest different from its own |
| `grant.changed`, `session.revoked` | nothing: grants and sessions are read from the database on every request, so a revocation made on one replica is refused on every replica's next request |

The data plane keeps no allow answer and no grant between requests: every operation that needs one
asks the control plane again, so it adds nothing to these bounds.

`events.backend` decides how a replica learns that there is something new in the outbox:

| `events.backend` | How | Replicas |
| --- | --- | --- |
| `local` (default) | reads the outbox every `events.poll-interval` (1 s), and at once after a commit made by this process | one |
| `postgres` | every outbox write sends a `NOTIFY` on the channel `scrim_events`, delivered on commit to a dedicated `LISTEN` connection (`application_name` `scrim-events`, outside the pool) on every replica | any; needs `state.backend: postgres` |

A notification carries nothing; the outbox is the record. A replica reads the outbox from the last
event it delivered when it starts, after every listener (re)connection and on every notification,
so each event is delivered once and in order, and a notification lost with a connection loses no
event. While the listener is connected the outbox is also read once a minute as a safety net.

`deployment.replicas` (default 1) states how many replicas share the configuration; the Helm chart
sets it. With more than 1, start-up fails when `events.backend` is `local` or `state.backend` is
`memory` or `sqlite`, naming the setting to change.

Bounds on how long a change made on one replica takes to act on another:

| Situation | Bound |
| --- | --- |
| `postgres`, listener connected | the commit plus one round trip; tens of milliseconds on a local network |
| `postgres`, listener down | `events.poll-interval` while it reconnects (backoff 250 ms doubling to 30 s), then everything missed is read on reconnect |
| `local`, one replica | at once for changes the process made itself, otherwise `events.poll-interval` |
| no event read at all | `approvals.poll-interval` for a held request and `policy.deny-all-refresh` for break-glass, which every replica still polls |

When the listener's connection drops, the replica logs a warning, sets `scrim_events_listener_up` to
0, polls the outbox every `events.poll-interval` and reconnects with jittered backoff; it also
checks an idle connection every 30 s, so one that died silently is noticed. `scrim_events_last_id`
is the newest event a replica delivered and `scrim_events_delivered_total{kind}` counts deliveries;
replicas whose `scrim_events_last_id` stays apart are not reading the outbox.

Each replica records `config.reloaded` (an audit entry and an event) when it starts serving and
after each reload. Its subject is `sha256:` and 16 hex digits over every setting's key and effective
value, with secret-ref settings in their reference form: it identifies a configuration without
revealing any of it. A replica that sees a peer announce another digest logs `replicas run different
configurations` once per digest; during a rolling update that is expected.

### Migrations

Each SQL backend embeds its migrations (`internal/state/<backend>/migrations/NNNN_name.sql`), applied
in order at start-up, each in its own transaction with its `schema_migrations` row. They are forward
only. A database migrated by a newer scrim is refused with both schema versions in the message.

| Version | Change |
| --- | --- |
| 1 | approvals, grants, sessions, audit log, events |
| 2 | sessions keep what `scrim run` binds them to (user, root process, scopes, name, end reason), so they survive a restart |

### No values in state

SQL backends pass every stored string through the process scrubber, so a value that slipped into a
reason, target, attribute, session name or label is stored as `[scrim:redacted]`. Sessions store
the hash of the token's secret part, never the token. The leak tests write such rows and then
search the SQLite file and WAL bytes, and a JSON dump of every PostgreSQL table, for the values.

## Audit log

Every state change made with `state.Apply` writes its audit entry and events in the same
transaction: a failure between the writes leaves none of them, and a change without an audit entry
is refused. Entries carry the action, actor, agent, reference, decision (`allow`, `deny`, `ask`),
rule, outcome (`ok`, `refused`, `failed`, `pending`), target, subject, request ID, reason and
metadata attributes.

```sh
scrim audit log --agent claude-laptop --decision ask --since 1h
scrim audit log --ref 'bao://kv/gh#token' --outcome refused -o json
scrim audit log --limit 50 --before 1234    # next older page
```

Results are newest first. `--since` and `--until` take an RFC 3339 time or a duration ago. The admin
API mounts the same query as `auditlog.Handler` with the filters as query parameters.

## Logs

`log.format` is `text` or `json`, `log.level` one of `debug`, `info`, `warn`, `error`. Every record
has `time`, `level`, `component` and `msg`, and `agent`, `request_id`, `trace_id`, `span_id` when
known. Values never reach a log line: `secret.Value` prints as its marker, byte slices print as their
length, every message and attribute is scrubbed at write time (including attributes bound before a
value was loaded), and the finished line is scrubbed again.

## Metrics and health

`metrics.listen` (empty disables) serves:

| Path | Meaning |
| --- | --- |
| `/healthz`, `/livez` | the process answers |
| `/readyz` | scrim can redact safely; failing checks are named, 503 otherwise |
| `/metrics` | Prometheus text format, scrubbed as a whole |

| Metric | Labels |
| --- | --- |
| `scrim_redaction_replacements_total` | provider, rule, agent |
| `scrim_guard_repairs_total` | provider, rule, agent |
| `scrim_guard_refusals_total` | provider, agent |
| `scrim_detector_fallback_hits_total` | provider, rule, agent |
| `scrim_proxy_added_latency_seconds` | provider, stage (redaction, guard, resolution) |
| `scrim_proxy_chunk_added_latency_seconds` | provider, stage |
| `scrim_store_up`, `scrim_store_degraded`, `scrim_store_values_loaded`, `scrim_store_last_refresh_timestamp_seconds` | store |
| `scrim_approval_outcomes_total` | rule, notifier, outcome |
| `scrim_approval_wait_seconds` | rule, notifier |
| `scrim_audit_delivered_total`, `scrim_audit_dropped_total` | sink |
| `scrim_state_up` | backend |
| `scrim_state_transaction_seconds` | backend, kind (view, update) |
| `scrim_config_weakened_settings` | setting |

## Traces

With `tracing.endpoint` set (an OTLP/HTTP URL such as `http://127.0.0.1:4318`) scrim exports spans
named `scrim.redaction`, `scrim.guard`, `scrim.upstream`, `scrim.resolution`, `scrim.policy` and
`scrim.approval_wait`, as children of an incoming W3C `traceparent`. `tracing.sample-ratio` samples
new root traces. Span names, attributes, events and statuses are scrubbed before export. Without an
endpoint nothing is exported and trace context is still propagated.

## `scrim status` and `scrim doctor`

`scrim status` reports the version, profile, configuration (files, version, last reload, settings
pending a restart), interception modes, protections, providers, stores, the state backend, audit
sinks, the data plane, everything degraded and every weakened setting. `-o json` (or `--json`) puts
weakened settings under `weakened_protections`. A component this process cannot check is reported
as not reported and degraded, never healthy. While a daemon holds the SQLite file, status reports
it as in use by that process.

`scrim doctor` turns the same report into checks, adds the state location permissions for SQLite
and any checks other areas contribute (CA trust per runtime, interception rules), prints each
problem with a fix and exits non-zero when one fails.
