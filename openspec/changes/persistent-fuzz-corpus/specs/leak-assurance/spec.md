## ADDED Requirements

### Requirement: Persistent fuzzing corpus

Every fuzzing run SHALL start from a persistent corpus of earlier runs' inputs kept outside the main
branch. Only the scheduled run SHALL write it, minimised, from a job that runs no build or test code
and accepts only plain input files of known targets; pull requests and releases SHALL only read it.
When the corpus cannot be fetched, a run SHALL start from the committed seeds and say so.

#### Scenario: Nightly run keeps what it found

- **WHEN** the nightly run of a target finds inputs that reach new code
- **THEN** the next run of that target, in a pull request or a release, starts with them

#### Scenario: Pull request cannot write the corpus

- **WHEN** a pull request's fuzzing jobs run
- **THEN** they hold a read-only token and the corpus is unchanged afterwards

### Requirement: Fuzzing schedule

Every fuzz target, data plane and control plane, SHALL be fuzzed for at least one hour each night,
for five minutes on each pull request that changes code the target builds, and for ten minutes in
each release on the commit released.

#### Scenario: Pull request touches the guard

- **WHEN** a pull request changes the redaction crate
- **THEN** every fuzz target that builds the redaction crate runs for five minutes on it

### Requirement: Fuzz seeds from fixtures

Each fuzz target SHALL have committed seed inputs built from the repository's fixtures (recorded
provider exchanges, leak scenarios, protocol test suites), with generated test values in place of
secrets, and a test SHALL fail when the fixtures change and the committed seeds do not.

#### Scenario: Fixture changed

- **WHEN** a recorded provider fixture changes and the seeds are not rewritten
- **THEN** the seed test fails and names the seed that differs

### Requirement: Fuzz findings become regression tests

A fuzzing finding SHALL fail its job and keep the input as an artifact. Before the fix is merged the
input SHALL be committed as a regression input every later run of the target reads first, and as a
test the ordinary test suite runs.

#### Scenario: Crash in a pull request

- **WHEN** a fuzz target crashes during a pull request's run
- **THEN** the check fails and the crashing input is downloadable from the run

### Requirement: Fuzzing results report the corpus

A release's fuzzing results SHALL give, per target, the seconds and runs of the release's own
fuzzing, the corpus size it started and ended with, and the fuzzing hours behind that corpus, and
SHALL name the corpus version used or say that none could be fetched.

#### Scenario: Release results

- **WHEN** a user opens a release's fuzzing results
- **THEN** they see each target's corpus size and the hours of fuzzing behind it
