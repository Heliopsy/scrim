# Gate the production engine and regressions against the previous release

## Why

Two entries of docs/limitations.md. The latency gate measured added request latency with a
stand-in engine (a simple Aho-Corasick redactor and guard), and only reported those numbers; the
production engine's latency was published with each release but nothing failed on it. And
performance was checked against fixed budgets only, while the performance spec asks for a release
to fail when a budgeted measurement regresses against the previous release.

The gate was also flaky on the shared ho-z10 runner: the 1 MB proxy overhead missed its 3 ms p99
budget by 0.01 to 0.4 ms now and then at a median near 0.8 ms, because a few samples per round had
waited for the CPU.

## What Changes

- The latency gate measures the production engine (`scrim-redact` through `scrim_llm::core`):
  proxy overhead with the engine wired in (engine time subtracted), added request latency through
  `outgoing::prepare` for 10, 1,000 and 10,000 secrets on the redaction benchmark's bodies, the
  redaction core on its own (`Snapshot::protect`, single-thread redaction throughput, restore per
  chunk), the proxy's chunk restore with production placeholders, and metrics on and off. The
  stand-in engine sections are gone.
- Budgets for the production engine and the core in `budget.json`, enforced, each with its
  reason. The engine budgets are set from what the guard does today (about 25 ms per 1 MB at the
  median on ho-z10), above the spec's initial 5 ms and 10 ms targets; docs/limitations.md says so.
- Robust measurement: rounds, median of per-round nearest-rank percentiles, and samples during
  which the measuring thread waited more than 50 µs for a CPU (Linux run-queue delay) dropped and
  counted; a round with more than half dropped keeps all samples and is reported as busy.
- Machine-readable results (`SCRIM_PERF_JSON`), published with each release as
  `scrim_<version>_results_latency-gate.json`.
- `scripts/perfgate` compares two runs: gated measurements, medians of rounds taken relative to a
  calibration workload timed before each round (the runner's clock speed varies), a threshold
  widened by the runs' spread and capped, unit floors, only on the same runner class and CPU. Settings in
  the `regression` object of `budget.json`.
- `scripts/release/results.sh baseline` fetches the previous release's JSON and verifies it with
  cosign over `checksums.txt` and the file's checksum; `results.sh regression` compares. The
  release workflow runs it in a new `results-regression` job and publishes
  `scrim_<version>_results_latency-regression.md`; CI runs it after the latency gate against the
  newest release.
- docs/performance.md: how the gate measures, the budgets, the regression check, how to read and
  reproduce the numbers.

## Impact

- Specs: performance (modified: Added request latency budget, Regression gate, Results published per
  release; added: Measurement robust to machine load, Verified regression baseline).
- Code: `dataplane/crates/scrim-llm/benches/latency_gate.rs`, `benches/budget.json`,
  `scripts/perfgate`, `scripts/release/results.sh`, `.github/workflows/ci.yaml`,
  `.github/workflows/release.yaml`.
- No change to the data plane or control plane binaries.
- The first release with this change has no baseline (releases up to 1.0.0 publish no JSON); its
  regression report says so and passes.
