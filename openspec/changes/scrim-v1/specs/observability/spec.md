## Purpose

Defines the logs, metrics, traces, health endpoints and diagnostic commands scrim exposes so
operators can see what it protects and how it performs, while guaranteeing that no telemetry ever
carries a secret value.

## ADDED Requirements

### Requirement: No secret values in telemetry

Logs, metrics labels, trace attributes, health responses, status output and error messages SHALL
never contain a secret value or a placeholder-to-value mapping. A telemetry write that would include
one SHALL be replaced by a redacted marker.

#### Scenario: Error mentions a value

- **WHEN** an upstream error message echoes a known secret value
- **THEN** the logged and returned message contains a redacted marker instead of the value

#### Scenario: Leak test over telemetry

- **WHEN** the leak suite seeds known secrets, runs traffic and collects all logs, metrics and traces
- **THEN** no known secret value appears in any encoding

#### Scenario: Metrics page after traffic

- **WHEN** metrics are enabled, traffic carrying seeded secrets passes through the real data plane and `/metrics` is scraped
- **THEN** the page holds the expected data plane series and no seeded value, reference or agent credential in any encoding

### Requirement: Structured logs

scrim SHALL emit structured logs (JSON or a documented text form, chosen by `log.format`) with a level
set by `log.level`, each record carrying a timestamp, component, agent identity where known and
request correlation id.

#### Scenario: JSON logs

- **WHEN** `log.format` is `json`
- **THEN** every log line is one JSON object with `time`, `level`, `component` and `msg`, plus `agent`, `request_id`, `trace_id` and `span_id` when known

### Requirement: Metrics endpoint

scrim SHALL expose metrics in the Prometheus exposition format behind the feature flag
`metrics.enabled` (default false), on `metrics.listen` (default `127.0.0.1:9792`) at `metrics.path`
(default `/metrics`). With the flag on and `metrics.listen` empty, start-up SHALL fail.
`scrim proxy --metrics[=ADDR]` SHALL turn the flag on for one run.

#### Scenario: Scrape metrics

- **WHEN** `metrics.enabled` is true and a scraper requests `metrics.path`
- **THEN** it receives scrim's metrics in Prometheus format

#### Scenario: Metrics off by default

- **WHEN** `metrics.enabled` is false and `metrics.listen` is not set
- **THEN** no metrics listener is bound and the data plane measures nothing

### Requirement: Metrics endpoint authentication

A `metrics.listen` that is not a loopback address SHALL require a bearer token
(`metrics.auth.token`, a secret reference of at least 16 bytes) unless the weakening setting
`metrics.allow-unauthenticated-remote` is set. The health endpoints SHALL never require the token.

#### Scenario: Remote listener needs a token

- **WHEN** `metrics.enabled` is true, `metrics.listen` is `0.0.0.0:9792` and neither `metrics.auth.token` nor `metrics.allow-unauthenticated-remote` is set
- **THEN** start-up fails naming both settings

#### Scenario: Token checked

- **WHEN** `metrics.auth.token` is set and a scraper presents no token or a wrong one
- **THEN** `metrics.path` answers 401 without detail and the health endpoints still answer

### Requirement: Health without metrics

With `metrics.enabled` false, a `metrics.listen` set explicitly SHALL serve the health endpoints
only and log once that metrics are off; otherwise no listener SHALL be bound.

#### Scenario: Health only without the flag

- **WHEN** `metrics.enabled` is false and `metrics.listen` is set explicitly
- **THEN** `/healthz`, `/livez` and `/readyz` are served there, `metrics.path` answers 404, and one log line says metrics are off

### Requirement: Data plane metrics

The data plane SHALL aggregate its own metrics in process (atomics, fixed buckets) only when started
with metrics on, open no listener for them, and hand them over through the boundary call `Metrics`,
which the control plane makes once per scrape and serves under `scrim_dataplane_*`. It SHALL measure
at least the data plane series `docs/monitoring.md` lists.

#### Scenario: Data plane series after traffic

- **WHEN** metrics are enabled and one request is forwarded and one refused through a base-URL listener
- **THEN** `scrim_dataplane_requests_total` shows one of each for that route and provider, the refusal is counted under its `x-scrim-error` code and the added-latency histogram has observations for every stage

#### Scenario: Older data plane

- **WHEN** the data plane answers the Metrics call with UNIMPLEMENTED or reports metrics disabled
- **THEN** the control plane serves its own metrics and `scrim_dataplane_metrics_up` is 0

### Requirement: Bounded metric labels

Metric label values SHALL be configured names (routes, stores, rules, agents), provider codecs,
error codes and fixed enumerations only, never a reference, placeholder, host, path or value. The
data plane SHALL cap distinct values per series set; the control plane SHALL drop a data plane family
whose name does not start with `scrim_dataplane_` or whose label names are not on its allowlist,
and SHALL scrub and shorten every label value.

#### Scenario: Foreign label refused

- **WHEN** a data plane family carries a label name outside the allowlist
- **THEN** the control plane drops that family

### Requirement: Control plane metrics

The control plane SHALL expose the series `docs/monitoring.md` lists, at least: build info, data
plane up and restarts, approvals pending and the oldest pending age, active grants and grant uses,
active sessions, asks by outcome and latency, store refresh duration, errors and staleness, snapshot
builds and pushes by result, configuration reloads by result, state health and CA expiry.

#### Scenario: Approval backlog visible

- **WHEN** an approval is pending
- **THEN** `scrim_approvals_pending` counts it and `scrim_approvals_oldest_pending_age_seconds` grows until it is decided

#### Scenario: Rejected reload counted

- **WHEN** a configuration reload is rejected
- **THEN** `scrim_config_reloads_total{result="rejected"}` increases by one

### Requirement: Monitoring assets

scrim SHALL ship Prometheus alerting rules (as a plain rule file and a `PrometheusRule`), unit tests
for those rules, a Grafana dashboard and a scrape configuration example under `deploy/monitoring/`,
validated in CI with `promtool check rules`, `promtool test rules` and `promtool check config`. Every
alert SHALL link to a runbook section in `docs/monitoring.md`.

#### Scenario: Rules tested

- **WHEN** CI runs the monitoring check
- **THEN** every alert has at least one firing and one quiet test case and all of them pass

### Requirement: Redaction and guard counters

scrim SHALL count redactions, guard repairs, guard refusals and fallback-detector hits, labelled by
provider, rule and agent, without labels that carry secret references beyond their configured name.
The control plane SHALL derive these from data plane events; the data plane's own counters
(`scrim_dataplane_*`) carry route and provider instead of agent.

#### Scenario: Guard refusal is counted

- **WHEN** the guard refuses an outbound request
- **THEN** the guard-refusal counter for that provider and agent increases by one

### Requirement: Added latency histograms

scrim SHALL record, in the data plane, histograms of the latency it adds per request, separately for
redaction, guard and their total, and of the time restore adds per streamed chunk, per route and
provider, with bucket bounds on the performance budgets (5 ms and 10 ms per request, 50 µs per
chunk).

#### Scenario: Latency visible per provider

- **WHEN** traffic flows to two providers
- **THEN** `scrim_dataplane_request_added_seconds` and `scrim_dataplane_restore_chunk_seconds` have series for each provider separately

### Requirement: Store health and freshness

scrim SHALL expose for each configured store whether it is reachable, when its values were last
refreshed, and how many values are loaded, and SHALL mark a store degraded after a configurable
staleness.

#### Scenario: Store unreachable

- **WHEN** a configured store cannot be reached beyond its staleness limit
- **THEN** its health metric reports it unhealthy and status reports it degraded

### Requirement: Approval metrics

scrim SHALL expose counts of approvals requested, approved, denied and timed out, and a histogram of
approval wait time, per policy rule and notifier.

#### Scenario: Timeout counted

- **WHEN** an approval times out
- **THEN** the timed-out counter for that rule increases and the wait time is recorded

### Requirement: Distributed tracing

scrim SHALL emit traces over OTLP when `tracing.endpoint` is set, propagating incoming trace context,
with spans for redaction, guard, upstream call, resolution, policy and approval wait.

#### Scenario: Tracing disabled

- **WHEN** `tracing.endpoint` is empty
- **THEN** no span is exported and incoming W3C trace context is still passed on to upstream calls

#### Scenario: Trace context propagated

- **WHEN** a request arrives with a W3C trace context header and tracing is enabled
- **THEN** scrim's spans are children of the incoming trace

### Requirement: Liveness and readiness

scrim SHALL serve a liveness endpoint that reflects only whether the process works, and a readiness
endpoint that fails while it cannot redact safely (for example no secrets loaded for a required
store, or the state backend unavailable).

#### Scenario: Health endpoints

- **WHEN** metrics are enabled, or `metrics.listen` is set explicitly
- **THEN** `/healthz` (alias `/livez`) and `/readyz` are served on that address, plus `metrics.path` while metrics are enabled, each response scrubbed of known values

#### Scenario: Not ready without secrets

- **WHEN** a required store has never been loaded successfully
- **THEN** the readiness endpoint reports not ready and names the store

### Requirement: Status command

`scrim status` SHALL report the running version, active interception modes, active protections,
configured providers and stores with their health, degraded components and every weakened setting in
effect, in human and machine-readable form.

#### Scenario: Status shows the configuration state

- **WHEN** the last configuration reload was rejected or a restart-only setting changed
- **THEN** `scrim status` shows the rejected reload with its reasons and the settings pending a restart, and lists the configuration as degraded after a rejected reload

#### Scenario: Status never claims unchecked health

- **WHEN** a component such as the data plane cannot be checked by the process running `scrim status`
- **THEN** it is reported as not reported and degraded, never as healthy

#### Scenario: Status shows weakened protection

- **WHEN** a weakening setting is active
- **THEN** `scrim status` lists it under weakened protections
- **AND** `scrim status -o json` includes it in a dedicated field

### Requirement: Doctor command

`scrim doctor` SHALL check the local setup (CA trust per runtime, interception rules in place, agent
configuration pointing at scrim, file permissions, state location, store reachability) and print each
problem with a suggested fix, exiting non-zero when any check fails.

#### Scenario: CA not trusted

- **WHEN** transparent mode is active and a supported runtime does not trust scrim's CA
- **THEN** `scrim doctor` reports the runtime and the command to fix it, and exits non-zero
