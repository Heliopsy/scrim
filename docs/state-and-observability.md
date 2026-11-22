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
  process refuses to start and names the file and the holding PID. `scrim status` and `scrim
  doctor` open the file read-only and take no lock, so running them while the service starts
  never makes it fail; before the first start they report the file as not created yet.
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

Several control plane replicas can share one PostgreSQL database; Valkey or NATS can carry the
wake-ups between them. Each replica follows the event
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
| `valkey` | after each of its commits that emitted an event, a replica publishes an empty hint on the Valkey channel `events.valkey.channel` (`scrim:events`); every replica holds a subscription to it on a dedicated connection | any; state still needs `postgres` |
| `nats` | the same over the NATS subject `events.nats.subject` (`scrim.events`), core pub/sub | any; state still needs `postgres` |

With `valkey` and `nats` the database does no `LISTEN`/`NOTIFY` work, which moves the wake-up
traffic of many replicas off PostgreSQL. A hint published while the replica is cut off from Valkey
or NATS is sent once the connection is back (NATS buffers it in the client, the Valkey publisher
retries with backoff). A replica that dies between its commit and the publish leaves a hint unsent:
the others then read the event at their next safety read, within a minute. The connection settings
are `valkey.*` (addresses, user, password reference, database, TLS) and `nats.*` (servers, token,
user and password, credentials file, TLS); [configuration](configuration.md#settings-reference)
lists them.

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
| `valkey` or `nats`, subscribed | the commit, one publish and one delivery; under 10 ms in the contract suite on one host |
| `postgres`, `valkey` or `nats`, listener down | `events.poll-interval` while it reconnects (backoff 250 ms doubling to 30 s), then everything missed is read on reconnect |
| `valkey` or `nats`, committing replica died before publishing | one minute, the safety read of every connected replica |
| `local`, one replica | at once for changes the process made itself, otherwise `events.poll-interval` |
| no event read at all | `approvals.poll-interval` for a held request and `policy.deny-all-refresh` for break-glass, which every replica still polls |

Every events backend passes one contract suite (`internal/events/eventstest`), run against the
in-memory reference, PostgreSQL, Valkey and NATS in containers: cross-replica delivery with only the
backend to carry it, concurrent writers on three replicas delivered once and in the same order
everywhere, catch-up after a replica's listener is cut and held down, a commit made while the
committing replica is cut off, and polling while down. `TestReplicasLoad` (`internal/daemon`) runs
three daemons on one PostgreSQL database with Valkey and then NATS events, decides approvals held on
every replica from another replica, revokes the resulting grants on a third, and checks that every
replica delivered exactly the outbox.

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

### Rate limits

Per-agent rate limits protect the agent API, the approval flow and the people behind asks. Each
class has a rate per interval and a burst; a rate of 0 turns it off:

| Class | Counts | Default |
| --- | --- | --- |
| `ratelimit.agent-api.*` | every agent tool call (local API and MCP) | 600 per minute, burst 120 |
| `ratelimit.approvals.*` | every approval created for an agent, by `secret_request` or a proxied request policy holds | 60 per hour, burst 10 |
| `ratelimit.asks.*` | every `secret_ask_human` | 30 per hour, burst 5 |

A refused call answers `rate_limited` (HTTP 429 on the local API) with the time to retry and is
audited with outcome `refused`; a refused approval denies the request with the same reason.

| `ratelimit.backend` | Where the counters live | Across replicas |
| --- | --- | --- |
| `local` (default) | process memory | approximate: with N replicas an agent can get up to N times each limit |
| `valkey` | Valkey (`valkey.*`), keys under `ratelimit.valkey.prefix` | exact: one Lua script reads Valkey's clock, decides and updates atomically |

Both implement the generic cell rate algorithm: one timestamp per key, which expires once the limit
has fully recovered. Keys are a hash of the class and the agent, so Valkey never sees an agent name.
When the backend cannot answer, the request is refused (`scrim_ratelimit_decisions_total{result="error"}`
counts it), never let through.

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

## Load test

`test/load` is the proxy-level load test (tasks.md 14.3): what several replicas on one PostgreSQL
database with Valkey or NATS events sustain, what scrim adds to each request while they do, and
whether redaction, restore, injection and approvals stay correct under that load.

```sh
just load-test                          # smoke: 60 streams for 30 s
just load-test full                     # 1,000 streams for 3 min; wants a whole machine
just load-test smoke --events nats --out /tmp/load
```

`test/load/run.sh` builds the release data plane, a static `scrim` and the load generator, then
starts everything in rootless podman containers named `scrim-load-<run>-*`, each capped in memory
(no swap) and CPU, on the host network, and removes them at the end: PostgreSQL, Valkey or NATS,
the replicas (the `distroless/cc` image with the binaries mounted read-only) and the load generator.
The run refuses to start when podman has no memory controller. Results land in `--out` (default
`load-results/`): `result.json` (every measurement, the conditions and each threshold),
`report.md` and every container's log.

The load generator holds a fake Anthropic provider and a fake HTTPS tool API, so both ends of every
request share one clock. Each simulated agent loops through the replicas round robin, the way a
load balancer would send its requests:

1. A streamed provider request of `body_kb` with `secrets_per_request` of the 1,000 bulk values
   (one also base64-encoded), one display value and the agent's credential, each behind a marker,
   carrying the session token of a session minted through one of the replicas. The provider checks
   every byte it received for any seeded value in raw, base64, base64url, hex and URL-encoded form,
   learns the placeholders, and streams a reply that uses them, in `chunk_runes` deltas every
   `chunk_interval`, ending in a `Bash` tool call that carries the credential's placeholder.
2. The agent checks the reply: the display value is restored in the text, the bulk credentials and
   the credential in the shell command stay placeholders.
3. It runs the tool call through the forward proxy of the next replica. The tool API checks that it
   received the credential's real value and nothing else seeded, and echoes the `Authorization`
   header back; the agent must see its placeholder in the echo.

Next to them, approval workers each own one credential under an `ask` rule. Every round, a request
is held on one replica, approved (three rounds in four) or denied through the admin API of a
second, and the grant an approval leaves is revoked through a third. The next round must be held
again. All poll intervals are 50 s and the ask times out after 40 s, so only an event delivered
from another replica can release a held request within the 10 s the test allows.

The run fails on any of these, whatever the thresholds say:

- a seeded value (or a session or admin token) at the provider, at the tool API, back at the agent,
  or in a replica's log;
- a display value not restored, or a credential restored, in a reply;
- a tool request that reached the API without its real credential;
- a held request not released by the decision made on another replica within 10 s, a round that
  was not held (a revoked grant honoured), or a failed decide or revoke;
- replicas whose newest delivered outbox event differs once the traffic stops.

Watched failing: with the bulk values left out of the redaction set (`--sabotage leak`) the run
fails with every bulk value seen at the provider and the restore checks failing; with each replica
configured alone on `events.backend: local` (`--sabotage events`) the run fails on a request
released only by its 40 s ask timeout and on replicas that disagree on the outbox.

### Thresholds

`test/load/profiles.json` holds the run sizes and the thresholds, as configuration (performance
spec). Correctness limits are zero and never loosen. The others, and why:

| Threshold | smoke | full | Why |
| --- | --- | --- | --- |
| scrim's request added p99 | 5 ms | 5 ms | the performance spec's request budget, read from scrim's own `scrim_dataplane_request_added_seconds` (stage `total`, all replicas, the difference between scrapes at the start and end of the window); 5 ms is a bucket bound, so the check is that 99% of requests fell in it |
| scrim's restore per chunk p99 | 50 µs | 50 µs | the spec's chunk budget, from `scrim_dataplane_restore_chunk_seconds` the same way |
| client-observed added p99 | 50 ms | 50 ms | what an agent sees: client time minus the provider's own time, including the loopback hops, queueing in a CPU-capped replica and the load generator's scheduling. A model's first token takes hundreds of milliseconds to seconds, so 50 ms stays invisible next to it; the full run measures about a third of it |
| approval release p99 | 1 s | 1 s | events deliver in milliseconds; 1 s leaves room for a loaded runner and is still 50 times shorter than the polls, so a pass means events released the requests |
| error rate | 0.1% | 0.1% | transport errors under load; wrong answers are counted by the zero limits instead |
| mean open streams | 80% of target | 80% of target | an agent has no stream open between turns (tool call, think time); below 80% the system is not holding the target concurrency |
| provider requests/s | 20 | 50 | the full shape (14 s turns, 1 s between them, 1,000 agents) gives about 66/s; 50 catches a stall |
| replica memory | 90% of the limit, no OOM kill | same | a replica near its limit would be killed in production |
| memory per stream | 4 MiB | 512 KiB | anonymous memory growth of a replica over its idle value per stream it carries; small runs are dominated by fixed costs (the CI smoke run measures 1.8 MiB at 20 streams per replica, the full run 0.2 MiB at 333), hence the looser smoke limit |

### Latest numbers

From the pull request run of the full profile on GitHub-hosted `ubuntu-24.04` runners (4 vCPU,
16 GB, kernel 7.0 on Azure; podman 4.9.3), 2026-11-21, commit 6303e56: three replicas each capped at
1 CPU and 1 GiB, PostgreSQL at 1 CPU, the load generator at 1.5 CPU, all on the one runner. 1,000
concurrent streams (mean 932 open), 100 sessions, 24 approval workers, 3 minutes after 20 s warm-up,
32 KB requests with 8 of 1,000 bulk secrets, replies of about 170 deltas, one every 80 ms. Both runs
passed every check.

| | Valkey events | NATS events |
| --- | --- | --- |
| provider requests/s (and tool requests/s) | 67.7 | 67.7 |
| stream events/s | 10,042 | 10,040 |
| errors | 0 of 26,523 | 0 of 26,520 |
| leaks, restore failures (of 64,000 checks), injection failures (of 14,600) | 0, 0, 0 | 0, 0, 0 |
| approvals released across replicas, grants revoked on a third | 2,376, 1,800 | 2,376, 1,800 |
| scrim request added p99 (within 5 ms) | 2.48 ms (99.98%) | 4.30 ms (99.55%) |
| scrim restore per chunk p99 (within 50 µs) | 22.4 µs (99.88%) | 23.7 µs (99.66%) |
| client-observed added, p50 / p95 / p99 | 1.71 / 4.27 / 17.40 ms | 1.60 / 7.65 / 15.33 ms |
| added before the provider sees the request, p99 | 10.20 ms | 10.76 ms |
| added to the first streamed byte, p99 | 5.16 ms | 5.47 ms |
| tool request through the forward proxy, p50 / p99 | 2.17 / 11.05 ms | 2.01 / 16.84 ms |
| approval decided on one replica to release on another, p50 / p99 / max | 3.57 / 11.89 / 45.46 ms | 2.96 / 18.41 / 39.26 ms |
| CPU per replica, mean / max | 0.25 / 0.34 cores | 0.25 / 0.48 cores |
| memory per replica, max (anonymous; idle before the load) | 149 MiB (133; 68) | 145 MiB (128; 59) |
| memory per stream | 205 KiB | 219 KiB |
| replica CPU per provider request, its tool call and approvals included | 11.0 ms | 11.0 ms |
| PostgreSQL CPU mean / max | 0.19 / 0.56 cores | 0.18 / 0.65 cores |

A three-replica deployment at this traffic needs about a quarter of a core and 150 MiB per
replica: above the chart's requests (100m, 128Mi) and below its 512Mi memory limit, so raise
`central.resources.requests` to match before relying on them for scheduling.

The smoke profile runs on every pull request that touches the request path; `result.json` and
`report.md` of every run are uploaded as workflow artifacts, and the job summary shows the report.

On a busy 36-thread desktop (the author's), the same smoke profile measured the restore per chunk
p99 at 75 to 85 µs, above the budget, while a 250-stream run on the same machine passed it at 46 µs:
the chunk tail is sensitive to other load on the host, so judge it on a quiet machine or CI.

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

### External audit sinks

`audit.sinks` adds copies of the audit log to `otlp`, `loki` and `kafka`; `db`, the state backend's
audit log, is always written. Each external sink receives every entry as the JSON record
`scrim audit log -o json` prints, after every string has passed the value scrubber:

| Sink | Settings | What it sends |
| --- | --- | --- |
| `otlp` | `audit.otlp.endpoint` (OTLP/HTTP, `/v1/logs` added), `audit.otlp.token` | one log record per entry: body the JSON record, event name `scrim.audit`, attributes `scrim.audit.action`, `.id`, `.outcome`, `.decision`, `scrim.agent.id`, resource `service.name=scrim` |
| `loki` | `audit.loki.url`, `.tenant`, `.username`, `.password`, `.labels` | one stream `{service_name="scrim", source="audit"}` plus the static labels, one line per entry |
| `kafka` | `audit.kafka.brokers`, `.topic` (`scrim-audit`), `.tls`, `.sasl-mechanism`, `.username`, `.password` | one record per entry keyed by agent (one agent's entries stay in order), acknowledged by every in-sync replica, idempotent |

Every write transaction that appends audit entries hands them to the sinks before it commits. Each
sink has its own bounded queue (`audit.<sink>.queue-size`, 10000) and one writer that sends batches
(`audit.<sink>.batch-size`, 500) and retries a failed one with backoff (100 ms doubling to 10 s)
until the sink takes it, so a slow sink never slows another. `audit.<sink>.policy` decides what
happens when the queue is full:

| Policy | Queue full | Counted in |
| --- | --- | --- |
| `drop` (default) | the operation goes through; the entries that do not fit are dropped and stay in the database audit log only | `scrim_audit_sink_dropped_total{reason="queue_full"}` |
| `block` | the transaction waits for room up to `audit.<sink>.timeout` (5 s), then is refused and rolls back: the change is not made | `scrim_audit_sink_refused_total` |

Nothing leaves a queue without a count: a batch the sink rejects as invalid (Loki 400, 413 or 422, a
Kafka record too large) is dropped with `reason="rejected"`, and entries still queued when scrim
stops, after up to 10 s of draining, with `reason="shutdown"`. Each loss is also logged, at most
every 10 s per sink. Delivery is at least once: a write that timed out may still land, and the retry
sends it again. `scrim status` lists each sink with its policy, queue and drops, and marks it degraded
while its writes fail, while its queue is over 80% full and once it has dropped or refused anything.

The sinks are tested against Loki, an OpenTelemetry collector and Redpanda in containers, including
a frozen sink (`podman pause`): under `drop` no write waits and delivered plus dropped equals what
was written; under `block` the write past a full queue is refused after the timeout; once the sink
answers again it receives every queued entry. The leak test searches the exact bytes each sink sends
for planted values in every encoding.

## Logs

`log.format` is `text` or `json`, `log.level` one of `debug`, `info`, `warn`, `error`. Every record
has `time`, `level`, `component` and `msg`, and `agent`, `request_id`, `trace_id`, `span_id` when
known. Values never reach a log line: `secret.Value` prints as its marker, byte slices print as their
length, every message and attribute is scrubbed at write time (including attributes bound before a
value was loaded), and the finished line is scrubbed again.

## Metrics and health

The health endpoints are served on `metrics.listen` (default `127.0.0.1:9792`) whenever metrics
are enabled (`metrics.enabled`, `scrim proxy --metrics`) or `metrics.listen` is set explicitly:

| Path | Meaning |
| --- | --- |
| `/healthz`, `/livez` | the process answers |
| `/readyz` | scrim can redact safely; failing checks are named, 503 otherwise |
| `metrics.path` (`/metrics`) | Prometheus text format, scrubbed as a whole; only while `metrics.enabled` |

Every metric, the data plane's included, its labels, the alert rules with their runbooks, the
dashboard and the security of the endpoint are in [monitoring.md](monitoring.md).

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
