## Why

Every fuzzing run started from an empty corpus: 60 seconds per target on a pull request, 15
minutes weekly, 10 minutes in the release, and nothing kept between runs (docs/limitations.md). The
coverage a run reached was lost when it ended, the targets never saw the request and stream shapes
the fixtures hold, and the Go fuzz tests only ran as unit tests over their seeds.

## What Changes

- Seeds per target, built from the fixtures (recorded provider requests and streams, the leak suite's
  scenarios, AWS's SigV4 suite, the policy conformance vectors) and committed; a test fails when a
  fixture changes and the seeds do not.
- A persistent corpus on the `fuzz-corpus` branch: every run starts from it; the nightly run
  minimises it (`cargo fuzz cmin`) and pushes it from a job that builds nothing and holds the
  workflow's only write token.
- Nightly: every target for 1 hour, cargo-fuzz and Go. Pull requests: 5 minutes on the targets whose
  code they change. Release: 10 minutes per target from the corpus, with the Go targets added.
- Release results report each target's corpus size, seeds, findings and the fuzzing hours behind its
  corpus, with the corpus commit.
- A finding fails the job and uploads its input; the process that turns it into a regression test
  is documented.
- `scripts/fuzz.sh` ignored a failing `cargo fetch --locked`, which hid a stale
  `scrim-toolproxy/fuzz/Cargo.lock`; it now fails, and the lockfile is updated.
- ClusterFuzzLite was considered and not adopted: its actions run images by a mutable tag, build
  with OSS-Fuzz's toolchains instead of the repository's pins, convert Go fuzz tests by rewriting
  test files, and keep the corpus in expiring artifacts or a repository reached with a personal
  access token.

## Impact

- Affected specs: leak-assurance (Persistent fuzzing corpus, Fuzzing schedule, Fuzz seeds from
  fixtures, Fuzz findings become regression tests, Fuzzing results report the corpus; added).
- Affected code: scripts/fuzz.sh, .github/workflows/fuzz.yaml, .github/workflows/release.yaml,
  scripts/release/results.sh, dataplane/crates/{scrim-redact,scrim-toolproxy}/tests/fuzz_seeds.rs
  and fuzz/seeds, the Go fuzz tests' seeds.
- Docs: docs/leak-assurance.md (Fuzzing), docs/limitations.md, CONTRIBUTING.md, AGENTS.md,
  dataplane/crates/scrim-redact/README.md.
- Owner: the nightly corpus job pushes to `fuzz-corpus` with `GITHUB_TOKEN`; a ruleset that covers
  every branch must let it (or the job fails and the corpus stays as it was).
