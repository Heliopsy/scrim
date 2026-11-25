## Why

The regression check compares a run of the latency gate with the previous release's single run.
On the shared ho-z10 runner set, 14 runs of the same code on the same CPU spread 2.5 to 4 times per
measurement, calibration included. The check failed main and pull requests at random (three
failures on #166, each on a measurement it does not touch) and would block every release, while
any threshold wide enough to pass would no longer catch a regression.

## What Changes

- New: `regression.enforce` in `benches/budget.json`. False reports regressions without failing;
  absent means true. It is set to false, with the measured spread as its reason.
- The release still runs the comparison and publishes `latency-regression.md`; the absolute budgets
  of the latency gate remain the hard gate.
- docs/performance.md and the release results summary say so.

## Impact

- Affected specs: performance (Regression gate).
- Affected code: scripts/perfgate, dataplane/crates/scrim-llm/benches/budget.json,
  scripts/release/results.sh, docs/performance.md.
