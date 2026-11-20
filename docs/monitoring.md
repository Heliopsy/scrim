# Monitoring

scrim exposes Prometheus metrics for the control plane and the data plane on one endpoint, ships
alert rules with tests, a Grafana dashboard and a scrape configuration in
[`deploy/monitoring/`](../deploy/monitoring/), and documents a runbook for every alert below.
Health endpoints and logs are in [state-and-observability.md](state-and-observability.md).

## Turning it on

Metrics are off by default. While they are off nothing is measured on the request path: the data
plane takes no timestamps and the control plane's instruments return at once.

```sh
scrim proxy --metrics                    # 127.0.0.1:9792/metrics for this run
scrim proxy --metrics=127.0.0.1:9900     # also sets metrics.listen
SCRIM_METRICS_ENABLED=true scrim proxy   # same as metrics.enabled: true in the config file
```

```yaml
metrics:
  enabled: true
  listen: 127.0.0.1:9792    # default
  path: /metrics            # default
  auth:
    token: env:SCRIM_METRICS_TOKEN   # needed for a non-loopback listen
```

| Setting | Default | Meaning |
| --- | --- | --- |
| `metrics.enabled` | `false` | the feature flag; `--metrics` on `scrim proxy` |
| `metrics.listen` | `127.0.0.1:9792` | address of the metrics and health endpoints; empty with the flag on is an error |
| `metrics.path` | `/metrics` | path of the Prometheus endpoint |
| `metrics.auth.token` | none | reference to a bearer token of at least 16 bytes |
| `metrics.allow-unauthenticated-remote` | `false` | weakening: serve a non-loopback listener without a token |

Every setting also has its `SCRIM_*` environment variable (`SCRIM_METRICS_ENABLED`,
`SCRIM_METRICS_LISTEN`, `SCRIM_METRICS_PATH`, `SCRIM_METRICS_AUTH_TOKEN`) and is listed in the
[configuration reference](configuration.md#settings-reference). All of them need a restart.

With `metrics.enabled` false and `metrics.listen` set explicitly (as configurations written before
the flag existed do), scrim keeps serving `/healthz`, `/livez` and `/readyz` there, answers 404 on
the metrics path and logs once that metrics are off.

## Security of the endpoint

- On loopback no token is needed. Any other address (`0.0.0.0`, a pod IP, an empty host) refuses to
  start without `metrics.auth.token`, unless `metrics.allow-unauthenticated-remote` is set. That
  setting is a weakening: it is logged at start-up, listed by `scrim status` and exported as
  `scrim_config_weakened_settings`.
- The token is compared in constant time; a missing or wrong token gets 401 with no detail. The
  health endpoints never need it, so probes work without a secret.
- No label or help text carries a secret value, a reference, a placeholder, a host, a path or an
  agent credential. Labels are configured names (route, store, rule, agent, sink, setting), provider
  codecs, error codes and fixed enumerations. The data plane caps distinct values per series set
  (routes at 256, codes at 64; the rest go to `_other`). The control plane drops any data plane
  family not named `scrim_dataplane_*` or using a label name outside its allowlist, scrubs and
  shortens every label value, and scrubs the whole page again before it is served.
- The daemon end-to-end test sends traffic carrying a generated secret through the real data plane,
  scrapes `/metrics` and fails if the secret, the agent's key or the reference appears in raw,
  base64, base64url, hex, URL-encoded or upper-case form.
- Terminate TLS in front of a remote listener (a sidecar, an ingress, a mesh); scrim serves plain
  HTTP.

## How the data plane's metrics get there

The data plane aggregates its numbers in process: relaxed atomic counters and fixed-bucket
histograms, one route lookup per request, no allocation per chunk. Nothing is formatted or sent
between scrapes. On every scrape the control plane calls the data plane's `Metrics` RPC over the
socket they already share and serves the families next to its own. The data plane opens no port.
If the call fails, or the data plane is older than the call, the control plane still serves its own
metrics and `scrim_dataplane_metrics_up` is 0.

Cost, from the latency gate (`cargo bench -p scrim-llm --bench latency_gate`, a shared 16-thread
host under load average 16): per request with 1,000 secrets and hits, the p50 difference between
metrics off and on was within noise (+0.1 µs at 100 KB, -67 µs and -53 µs at 1 MB and 4 MB); per
streamed chunk, +0.08 µs at p50 (0.67 µs to 0.74 µs) against a 50 µs budget.

## Metrics

Histograms expose `_bucket`, `_sum` and `_count`. Times are seconds, sizes bytes.

### Data plane

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `scrim_dataplane_requests_total` | counter | route, provider, outcome (`forwarded`, `refused`) | LLM proxy requests |
| `scrim_dataplane_request_added_seconds` | histogram | route, provider, stage (`redaction`, `guard`, `total`) | latency scrim adds before a request leaves; `total` also covers the request target and headers, and excludes reading the body and the upstream. Buckets 50 µs to 50 ms, with 5 ms and 10 ms on bounds |
| `scrim_dataplane_request_body_bytes` | histogram | route, provider | request body size as received; 1 KiB to 16 MiB |
| `scrim_dataplane_redaction_hits_total` | counter | source (`llm`, `toolproxy`), route, provider, class (`value`, `detector`) | values replaced: a known value, or a fallback detector match |
| `scrim_dataplane_guard_actions_total` | counter | source, route, provider, action (`repaired`, `withheld`) | requests the guard repaired, requests or responses it withheld |
| `scrim_dataplane_refusals_total` | counter | source, route, provider, code | refusals by their `x-scrim-error` code (`guard_refused`, `not_ready`, `no_route`, `policy_denied`, `unbound_destination`, `interception_refused`, ...) |
| `scrim_dataplane_restore_chunk_seconds` | histogram | route, provider | time placeholder restore adds per streamed chunk; 1 µs to 1 ms, 50 µs on a bound |
| `scrim_dataplane_restored_total` | counter | route, provider, result (`resolved`, `kept`) | placeholders in responses |
| `scrim_dataplane_upstream_seconds` | histogram | route, provider | time to the upstream's response headers; 50 ms to 120 s |
| `scrim_dataplane_upstream_responses_total` | counter | route, provider, status_class (`1xx` to `5xx`) | upstream responses |
| `scrim_dataplane_upstream_errors_total` | counter | route, provider, kind (`connect`, `failed`, `chain_unavailable`) | upstream calls that failed |
| `scrim_dataplane_injections_total` | counter | outcome (`allowed`, `denied`, `unbound`) | tool-proxy credential injections; `unbound` covers unbound credentials, destinations and locations |
| `scrim_dataplane_captures_total` | counter | outcome (`stored`, `failed`) | values capture rules took from responses |
| `scrim_dataplane_connections_total` | counter | listener (`base_url`, `unix`, `tool_proxy`, `forward_proxy`) | connections accepted |
| `scrim_dataplane_connections_active` | gauge | listener | connections open now |
| `scrim_dataplane_snapshot_applies_total` | counter | result (`applied`, `rejected`) | snapshots applied |
| `scrim_dataplane_snapshot_apply_seconds` | histogram | | time to validate, build and publish a snapshot |
| `scrim_dataplane_snapshot_version` | gauge | | snapshot in force |
| `scrim_dataplane_values` | gauge | | values in the dictionary in force |
| `scrim_dataplane_events_dropped_total` | counter | | audit events lost because the control plane fell behind |

An empty `route` on a refusal is a request no route matched; `route` and `provider` are empty for
`source="toolproxy"`.

### Control plane

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `scrim_build_info` | gauge | version, commit | always 1 |
| `scrim_dataplane_up` | gauge | | 1 while the data plane runs with a snapshot |
| `scrim_dataplane_restarts_total` | counter | | data plane restarts after the first start |
| `scrim_dataplane_metrics_up` | gauge | | 1 when this scrape read the data plane's metrics |
| `scrim_redaction_replacements_total` | counter | provider, rule, agent | replacements, from data plane events |
| `scrim_guard_repairs_total` | counter | provider, rule, agent | guard repairs, from events |
| `scrim_guard_refusals_total` | counter | provider, agent | guard refusals, from events |
| `scrim_detector_fallback_hits_total` | counter | provider, rule, agent | fallback detector hits, from events |
| `scrim_store_up` | gauge | store | 1 when the store answered its last check |
| `scrim_store_degraded` | gauge | store | 1 when the last refresh failed and values may be stale |
| `scrim_store_values_loaded` | gauge | store | values held for redaction |
| `scrim_store_last_refresh_timestamp_seconds` | gauge | store | last successful refresh |
| `scrim_store_staleness_seconds` | gauge | store | seconds since the last successful refresh, at scrape time |
| `scrim_store_refresh_duration_seconds` | histogram | store | one full refresh |
| `scrim_store_refresh_errors_total` | counter | store | failed refreshes |
| `scrim_approvals_requested_total` | counter | rule | approvals requested |
| `scrim_approvals_settled_total` | counter | rule, outcome (`approved`, `denied`, `expired`), via | approvals decided |
| `scrim_approvals_wait_seconds` | histogram | rule, outcome | request to decision |
| `scrim_approvals_notifications_total` | counter | notifier, result | notifications sent |
| `scrim_approvals_pending` | gauge | | approvals waiting now |
| `scrim_approvals_oldest_pending_age_seconds` | gauge | | age of the oldest, 0 when none |
| `scrim_grants_active` | gauge | | grants usable now |
| `scrim_grants_uses_total` | counter | rule | grant uses |
| `scrim_sessions_active` | gauge | | agent sessions not ended |
| `scrim_asks_total` | counter | outcome (`allow`, `deny`) | asks from the data plane |
| `scrim_ask_duration_seconds` | histogram | outcome | time to answer an ask, approval waits included |
| `scrim_snapshot_builds_total` | counter | result (`ok`, `error`) | snapshots built |
| `scrim_snapshot_build_duration_seconds` | histogram | | time to build one |
| `scrim_snapshot_pushes_total` | counter | result (`ok`, `error`) | snapshots sent to the data plane |
| `scrim_snapshot_push_duration_seconds` | histogram | | time the data plane took to apply one |
| `scrim_snapshot_entries` | gauge | kind (`values`, `placeholder_keys`, `routes`, `listeners`, `policy_rules`, `ca_certificates`) | size of the last snapshot pushed |
| `scrim_snapshot_version` | gauge | | last version applied |
| `scrim_config_reloads_total` | counter | result (`applied`, `unchanged`, `rejected`) | configuration reloads |
| `scrim_config_weakened_settings` | gauge | setting | 1 per weakening setting in effect |
| `scrim_audit_delivered_total` | counter | sink | audit entries written |
| `scrim_audit_dropped_total` | counter | sink | audit entries lost |
| `scrim_state_up` | gauge | backend | 1 when the state backend answered |
| `scrim_state_transaction_seconds` | histogram | backend, kind (`view`, `update`) | state transactions |
| `scrim_ca_certificate_not_after_timestamp_seconds` | gauge | generation (`current`, `previous`) | tool-proxy CA expiry |

Go runtime (`go_*`) and process (`process_*`) metrics come with them. Approval, grant and session
gauges read the state backend at most every 5 s.

## Scraping

[`deploy/monitoring/prometheus/scrape-config.yaml`](../deploy/monitoring/prometheus/scrape-config.yaml):

```yaml
scrape_configs:
  - job_name: scrim
    scrape_interval: 15s
    metrics_path: /metrics
    static_configs:
      - targets: ["127.0.0.1:9792"]
    # For a non-loopback listener with metrics.auth.token:
    # authorization:
    #   type: Bearer
    #   credentials_file: /etc/prometheus/scrim-metrics-token
```

In Kubernetes, a `ServiceMonitor` or `PodMonitor` from the Helm chart does the same.

## Dashboard

[`deploy/monitoring/grafana/scrim-dashboard.json`](../deploy/monitoring/grafana/scrim-dashboard.json)
(uid `scrim-overview`) has rows for overview, requests, added latency against the 5 ms budget, body
sizes, redaction and guard, responses, upstreams, the tool proxy, listeners, stores, approvals and
sessions, and the control plane. Import it in the Grafana UI, or apply the ConfigMap next to it,
which carries the sidecar label `grafana_dashboard: "1"`. See
[`deploy/monitoring/README.md`](../deploy/monitoring/README.md).

## Alerts

The rules are in [`deploy/monitoring/rules/scrim.rules.yaml`](../deploy/monitoring/rules/scrim.rules.yaml)
and, for prometheus-operator, `deploy/monitoring/prometheus-rules.yaml`. `scripts/monitoring-check.sh`
validates both and runs the rule tests; CI runs it on every change.

### ScrimDown

Critical. Prometheus cannot scrape scrim for 2 minutes. Check that `scrim proxy` runs
(`systemctl --user status scrim`, `kubectl get pods`), that `metrics.enabled` is true and
`metrics.listen` is what the scrape config targets, and that a token is configured on both sides
for a remote listener (401 in the target's last error means a wrong token).

### ScrimDataPlaneDown

Critical. The control plane runs but its data plane has no snapshot or is not running for a
minute; all agent traffic is refused (fail closed). Look at the daemon log for `data plane stopped`
and the reason, and at `scrim status`. A protocol mismatch stops it permanently: the control plane
and data plane come from different builds.

### ScrimDataPlaneRestarting

Warning. More than two restarts in 15 minutes. Each restart refuses traffic until the next snapshot.
Look for crashes in the relayed data plane log (`component=dataplane`), memory limits (locked
memory, cgroup OOM) and snapshot rejections.

### ScrimDataPlaneMetricsUnavailable

Warning. The control plane could not read the data plane's metrics for 5 minutes, so the
`scrim_dataplane_*` series are missing. Usually the data plane is down (see above) or older than
the control plane; a slow data plane times out after 2 s.

### ScrimGuardWithholdingSpike

Warning. More than 5 requests or responses withheld by the guard in 10 minutes. The guard refuses
when the redactor missed a known value it could not repair: nothing leaked, but agents see errors.
Find the route and code in `scrim_dataplane_refusals_total{code="guard_refused"}` and the audit log
(`scrim audit log --decision deny --since 1h`), and check whether a new encoding of a value is in
use.

### ScrimRefusalRatioHigh

Warning. Over 5% of LLM requests refused for 10 minutes. Group `scrim_dataplane_refusals_total` by
`code`: `not_ready` points at stores or the data plane, `policy_denied` at the rules,
`unsupported_encoding` at a client sending compressed bodies, `upstream_unavailable` at the
provider or a chained proxy.

### ScrimRedactionLatencyOverBudget

Warning. The p99 latency scrim adds (stage `total`) is above 5 ms for 15 minutes on a route. Look
at `scrim_dataplane_request_body_bytes` (bigger bodies cost more), `scrim_dataplane_values` (more
secrets), the `redaction` and `guard` stages separately, and CPU pressure on the host.

### ScrimRestoreChunkLatencyOverBudget

Warning. The p99 time restore adds per streamed chunk is above 50 µs for 15 minutes. Usually CPU
pressure; a large placeholder set or very large chunks also show here.

### ScrimStoreDegraded

Critical. A store's last refresh failed and it is past its staleness limit for 5 minutes: changes
there do not reach redaction or injection. `scrim status` names the store and the last error.

### ScrimStoreUnreachable

Warning. A store has not answered its checks for 10 minutes. Check network, credentials and the
store itself; values already loaded stay in force until they expire.

### ScrimStoreStale

Warning. A store has not refreshed successfully for over an hour. A rotated secret may not be
redacted yet. Check `scrim_store_refresh_errors_total` and the daemon log.

### ScrimApprovalBacklog

Warning. More than 10 approvals pending for 15 minutes, or the oldest pending for over 15 minutes.
Agents are blocked waiting. Check that notifications are delivered
(`scrim_approvals_notifications_total{result!="ok"}`) and decide or deny with `scrim approve`.

### ScrimSnapshotPushFailing

Critical. Snapshot pushes failed and none succeeded for 15 minutes, so the data plane runs on an
old snapshot: new secrets, rules or bindings are not in force. The daemon log names the rejection
reason; `scrim_snapshot_builds_total{result="error"}` separates build failures from data plane
rejections.

### ScrimConfigReloadRejected

Warning. A configuration reload was rejected in the last 30 minutes; the previous configuration is
still in force. `scrim status` shows the problems; fix the file and send SIGHUP or save again.

### ScrimAuditDropping

Warning. Audit entries were dropped in 15 minutes. Check the state backend (`scrim_state_up`,
transaction latency) and `scrim_dataplane_events_dropped_total`, which counts events lost before
they reached the control plane.

### ScrimWeakenedSetting

Info. A weakening setting has been in effect for an hour. Confirm it is intended; `scrim status`
lists every weakened protection.

### ScrimCAExpiringSoon

Warning. The current tool-proxy CA expires in under 14 days. Rotation is automatic for the CA scrim
generates; an operator-supplied CA must be replaced (see [ca.md](ca.md)).

### ScrimCAExpiringCritical

Critical. The current tool-proxy CA expires in under 2 days, or has expired: agents' TLS to the
tool proxy will fail. Rotate or replace it now and redistribute the trust bundle.
