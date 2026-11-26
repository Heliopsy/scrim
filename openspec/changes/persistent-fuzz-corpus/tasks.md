## 1. Seeds

- [x] 1.1 `scrim-redact` seeds from the provider fixtures and leak scenarios (`tests/fuzz_seeds.rs`, `fuzz/seeds`)
- [x] 1.2 `sigv4` seeds from AWS's SigV4 suite (`scrim-toolproxy/tests/fuzz_seeds.rs`)
- [x] 1.3 Go seeds: `FuzzChecker`, `FuzzGlob`, `FuzzParseRef` read the fixtures and conformance vectors

## 2. Corpus and runs

- [x] 2.1 `scripts/fuzz.sh`: `targets` (all, or those a change touches), `corpus-fetch`, `run` for cargo-fuzz and Go, `corpus-export`, `corpus-push`
- [x] 2.2 `fuzz.yaml`: plan, pull request 5 minutes on touched targets, nightly 1 hour, corpus push job
- [x] 2.3 `release.yaml`: every target from the corpus, matrix from `scripts/fuzz.sh targets`
- [x] 2.4 `scripts/fuzz.sh run` fails on a stale lockfile; `scrim-toolproxy/fuzz/Cargo.lock` updated

## 3. Results and docs

- [x] 3.1 `scripts/release/results.sh`: corpus size, seeds, findings, hours behind the corpus, corpus commit
- [x] 3.2 docs/leak-assurance.md (Fuzzing, finding to regression test), docs/limitations.md, CONTRIBUTING.md, AGENTS.md, scrim-redact README
