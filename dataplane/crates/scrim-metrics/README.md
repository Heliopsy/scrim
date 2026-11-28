# scrim-metrics

Metric primitives the data plane aggregates in process: counters, gauges, fixed-bucket histograms
and label-keyed series maps. `scrim-llm` (`src/metrics.rs`) and `scrim-dataplane`
(`src/metrics.rs`) record into them on the request path; when the control plane scrapes, the data
plane turns them into `Family` values and returns them over the `Metrics` call, and the control
plane serves them on its own metrics endpoint. Nothing is measured unless the control plane starts
the data plane with `SCRIM_DP_METRICS=1` (`metrics.enabled`). The crate has no dependencies.

Docs: [monitoring](../../../docs/monitoring.md#how-the-data-planes-metrics-get-there).

## Public API

- `Counter`, `Gauge` (with `track` for an in-flight count held by a guard), `Histogram` over one of
  the static bucket sets (`REQUEST_LATENCY`, `CHUNK_LATENCY`, `UPSTREAM_LATENCY`,
  `APPLY_LATENCY`, `BODY_BYTES`). Recording is one relaxed atomic operation, with no lock and no
  allocation.
- `Labelled<T>`: series keyed by a label value, read under an uncontended read lock. The number of
  label values is capped; past the cap new values share the `OVERFLOW` (`_other`) series, so a
  label cannot grow memory without bound.
- `Family`, `Sample`, `Kind`: what one scrape returns, built with `Family::counter`, `gauge`,
  `histogram` and filled with `value`, `count` and `observed`.

Label values must be route names, codec names, refusal codes or other fixed enumerations, never a
reference, placeholder, host or value. The control plane scrubs the page again before serving it.

## Tests

```sh
cd dataplane
cargo test -p scrim-metrics
```
