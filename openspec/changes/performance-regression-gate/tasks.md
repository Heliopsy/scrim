# Tasks

## 1. Latency gate on the production engine

- [x] 1.1 Wire `CoreEngine` into the gate: proxy overhead with the engine (engine time subtracted), added request latency for 10, 1,000 and 10,000 secrets on the redaction benchmark's bodies, chunk restore with production placeholders, metrics on and off
- [x] 1.2 Measure the redaction core on its own: `Snapshot::protect`, single-thread redaction throughput, `BlockRestorer` per chunk
- [x] 1.3 Budgets for the production engine and the core in `budget.json`, enforced, with their reasons
- [x] 1.4 Rounds, median of per-round percentiles, run-queue filter with busy rounds; check under a CPU hog that the old gate fails and the new one does not
- [x] 1.5 `SCRIM_PERF_JSON` results with rounds, machine and runner class; `SCRIM_PERF_ONLY` sections

## 2. Regression check

- [x] 2.1 `scripts/perfgate` with tests: noise-aware threshold, floors, direction, runner and machine match, exit codes
- [x] 2.2 `results.sh baseline`: previous release, cosign over `checksums.txt`, file checksum; no baseline reported, not failed
- [x] 2.3 `results.sh regression` and `assemble` publish the JSON and the regression report
- [x] 2.4 Release workflow `results-regression` job; CI `latency-regression` job
- [ ] 2.5 Calibrate the engine budgets from the ho-z10 CI runs

## 3. Docs

- [x] 3.1 docs/performance.md; README, leak-assurance, scrim-llm README
- [x] 3.2 docs/limitations.md: replace the two entries
