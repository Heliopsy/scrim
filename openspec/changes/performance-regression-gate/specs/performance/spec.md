## MODIFIED Requirements

### Requirement: Added request latency budget

The latency scrim adds to a request (redaction and guard, excluding the upstream) SHALL stay below a
configured p99 target, initially 5 ms for 1 MB bodies with 1,000 secrets and 10 ms with 10,000
secrets on the reference machine. The target tightens as the matcher improves and never loosens
without a recorded reason. It SHALL be measured with the production redaction engine.

#### Scenario: Budget met

- **WHEN** the benchmark measures a 1 MB body with 1,000 secrets
- **THEN** the p99 added latency is below the configured target

#### Scenario: Budget met with metrics on

- **WHEN** the benchmark measures the same request and chunk paths with metrics enabled
- **THEN** the p99 added latency is still below the configured targets, and the report shows the difference to metrics off

#### Scenario: Budget met with a large set

- **WHEN** the benchmark measures a 1 MB body with 10,000 secrets
- **THEN** the p99 added latency is below the configured large-set target

#### Scenario: Production engine measured

- **WHEN** the benchmark measures added request latency
- **THEN** the redactor and guard measured are those the data plane ships, built with its default configuration

### Requirement: Regression gate

A release SHALL fail when any budgeted measurement regresses beyond a configured threshold against the
previous release on the same reference conditions. Targets and thresholds SHALL be configuration, not
code. The comparison SHALL use the medians of repeated rounds, with the threshold widened by the
spread of the two runs' rounds up to a configured cap. The same comparison SHALL run in CI against
the newest release.

#### Scenario: Regression blocks release

- **WHEN** p99 added latency regresses by more than the threshold
- **THEN** the release pipeline fails and names the measurement

#### Scenario: Slower clock is not a regression

- **WHEN** every measurement and the calibration workload of a run are slower by the same factor
- **THEN** no measurement regresses

#### Scenario: Noise is not a regression

- **WHEN** one round of a measurement is slow and the median of the rounds is within the threshold
- **THEN** the measurement does not regress

### Requirement: Results published per release

Each release SHALL publish its benchmark results and reference conditions alongside its artifacts,
as a report, as machine-readable results with every measurement's rounds, and as the report of the
comparison with the previous release.

#### Scenario: Compare releases

- **WHEN** a user opens a release's assets
- **THEN** a benchmark report for that release is attached

#### Scenario: Machine-readable results

- **WHEN** the next release runs its regression check
- **THEN** it reads the previous release's published machine-readable results

## ADDED Requirements

### Requirement: Measurement robust to machine load

Each budgeted measurement SHALL run in repeated rounds, and the value compared with its budget SHALL
be the median of the rounds. Where the platform reports it, a sample during which the measuring
thread waited for a CPU beyond a small bound SHALL be dropped and counted in the report. Each round
SHALL record the time of a fixed calibration workload run just before it.

#### Scenario: Load from other processes

- **WHEN** another process takes the measuring thread's CPU during some samples
- **THEN** those samples are dropped and counted, and the gate's result does not depend on them

#### Scenario: Saturated machine

- **WHEN** most samples of a round would be dropped
- **THEN** the round keeps all its samples and the report marks it busy

### Requirement: Verified regression baseline

The regression check SHALL use the previous release's results only after the release's signed
checksums verify and the results file matches them. It SHALL NOT compare runs measured on different
reference conditions (runner class, CPU model, CPU count, architecture).

#### Scenario: Unverified baseline

- **WHEN** the previous release's results do not match its signed checksums
- **THEN** the check fails instead of comparing

#### Scenario: Different reference machine

- **WHEN** the baseline was measured on another runner class or CPU
- **THEN** nothing is compared and the report names the difference
