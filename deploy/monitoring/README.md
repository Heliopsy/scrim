# Monitoring assets

Prometheus rules and a Grafana dashboard for scrim. Metric meanings and the alert runbooks are in
[docs/monitoring.md](../../docs/monitoring.md).

| File | What it is |
| --- | --- |
| `rules/scrim.rules.yaml` | Alerting rules as a plain Prometheus rule file. The source of truth. |
| `rules/tests/scrim.rules.test.yaml` | `promtool test rules` cases: one where each alert fires, one where it stays quiet. |
| `prometheus-rules.yaml` | The same groups as a prometheus-operator `PrometheusRule` named `scrim`. Generated. |
| `prometheus/scrape-config.yaml` | Example `scrape_configs` for the `scrim` job on `127.0.0.1:9792`. |
| `prometheus/prometheus.yaml` | Minimal full Prometheus config that loads the scrape job and the rules. |
| `grafana/scrim-dashboard.json` | Grafana dashboard, uid `scrim-overview`. |
| `grafana/scrim-dashboard.configmap.yaml` | The dashboard in a ConfigMap for the Grafana sidecar. Generated. |

## Scraping

scrim serves `/metrics` on `metrics.listen` (default `127.0.0.1:9792`). The data plane's metrics,
prefixed `scrim_dataplane_`, come through the same endpoint. A non-loopback listener needs a bearer
token: uncomment the `authorization` block in `prometheus/scrape-config.yaml` and point
`credentials_file` at a file holding the token.

## Loading the rules

Plain Prometheus: copy `rules/scrim.rules.yaml` next to your config and list it under
`rule_files`, as `prometheus/prometheus.yaml` does.

prometheus-operator:

```sh
kubectl apply -n monitoring -f deploy/monitoring/prometheus-rules.yaml
```

Add labels to its metadata if your `Prometheus` resource selects rules by label
(`ruleSelector`).

`ScrimApprovalBacklog` is one alert for two conditions: more than 10 approvals pending for the
whole last 15 minutes, or the oldest pending approval older than 15 minutes. `ScrimCAExpiringSoon`
(under 14 days) and `ScrimCAExpiringCritical` (under 2 days or expired) both fire in the last two
days; inhibit the warning in Alertmanager if you only want one.

## Importing the dashboard

In the Grafana UI: Dashboards, New, Import, upload `grafana/scrim-dashboard.json` and pick a
Prometheus data source. The `job` and `instance` variables come from `scrim_build_info`.

With the Grafana sidecar (kube-prometheus-stack and similar), apply the ConfigMap in a namespace
the sidecar watches. It carries the label `grafana_dashboard: "1"`:

```sh
kubectl apply -n monitoring -f deploy/monitoring/grafana/scrim-dashboard.configmap.yaml
```

## Checking and regenerating

```sh
scripts/monitoring-check.sh             # validate everything
scripts/monitoring-check.sh --generate  # rewrite the generated files, then validate
```

The check runs `promtool check rules`, `promtool test rules` and `promtool check config`, verifies
that the `PrometheusRule` spec equals the plain rule file and that the ConfigMap embeds the
dashboard byte for byte, and lints the dashboard: unique panel ids, no empty queries, and only
`scrim_*`, `up`, `go_*` and `process_*` metrics. Edit `rules/scrim.rules.yaml` and
`grafana/scrim-dashboard.json`, never the generated files.

promtool comes from `PATH`, or the script downloads a pinned, checksummed Prometheus release into
`bin/tools` (override with `SCRIM_TOOLS_DIR`). `SCRIM_MONITORING_PODMAN=1` runs promtool from the
pinned `prom/prometheus` image with rootless podman instead.
