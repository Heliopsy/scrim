## Why

The latency gate failed 1.2.0's last fix (#171) on one throughput budget (310 MB/s against
400 MB/s, after the slowdown stretch) on the shared ho-z10 runner; the rerun passed with the same
code. The same happened to the 1.1.0 release. A merge queue that does not rerun failed jobs then
left the pull request red for hours. A slower build misses its budgets in every run; a busy
runner rarely misses twice in a row.

## What Changes

- New: when a budget is missed, the gate runs once more in a fresh process and fails only when
  that confirm run misses a budget too. Both reports are printed; the confirm run's JSON has
  `first_run_failures`. `SCRIM_PERF_CONFIRM=0` fails on the first miss.
- The gate reports the release version from `SCRIM_VERSION` when set, so the regression report no
  longer labels both runs with the crate version (0.1.0).

## Impact

- Affected specs: performance (Latency gate confirm run, added).
- Affected code: dataplane/crates/scrim-llm/benches/latency_gate.rs, docs/performance.md.
