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

### Requirement: Structured logs

scrim SHALL emit structured logs (JSON or a documented text form, chosen by `log.format`) with a level
set by `log.level`, each record carrying a timestamp, component, agent identity where known and
request correlation id.

#### Scenario: JSON logs

- **WHEN** `log.format` is `json`
- **THEN** every log line is one JSON object with `time`, `level`, `component` and `msg`, plus `agent`, `request_id`, `trace_id` and `span_id` when known

### Requirement: Metrics endpoint

scrim SHALL expose metrics on a configurable endpoint in the Prometheus exposition format, disabled
or bound to loopback by default per profile.

#### Scenario: Scrape metrics

- **WHEN** a scraper requests the metrics endpoint
- **THEN** it receives scrim's metrics in Prometheus format

### Requirement: Redaction and guard counters

scrim SHALL count redactions, guard repairs, guard refusals and fallback-detector hits, labelled by
provider, rule and agent, without labels that carry secret references beyond their configured name.

#### Scenario: Guard refusal is counted

- **WHEN** the guard refuses an outbound request
- **THEN** the guard-refusal counter for that provider and agent increases by one

### Requirement: Added latency histograms

scrim SHALL record histograms of the latency it adds per request and per streamed chunk, separately
for redaction, guard and resolution, per provider.

#### Scenario: Latency visible per provider

- **WHEN** traffic flows to two providers
- **THEN** added-latency histograms exist for each provider separately

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

- **WHEN** `metrics.listen` is set
- **THEN** `/healthz` (alias `/livez`), `/readyz` and `/metrics` are served on that address, each response scrubbed of known values

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
