## MODIFIED Requirements

### Requirement: Added request latency budget

The latency scrim adds to a request (redaction and guard, excluding the upstream) SHALL stay below a
configured p99 target, initially 5 ms for 1 MB bodies with 1,000 secrets and 10 ms with 10,000
secrets on the reference machine. The target tightens as the matcher improves and never loosens
without a recorded reason. The latency SHALL be measured with the production redaction engine
behind the LLM proxy, not a stand-in. Each measurement SHALL run in repeated rounds, and the value
compared with the target SHALL be the median of the rounds' p99. Where the platform reports it, a
sample during which the measuring thread waited for a CPU beyond a small bound SHALL be dropped and
counted in the report; a round in which most samples were dropped SHALL keep all of them and be
reported as busy.

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

#### Scenario: Load from other processes

- **WHEN** another process takes the measuring thread's CPU during some samples
- **THEN** those samples are dropped and counted, and the gate's result does not depend on them

### Requirement: Regression gate

A release SHALL fail when any budgeted measurement regresses beyond a configured threshold against the
previous release on the same reference conditions. Targets and thresholds SHALL be configuration, not
code. The comparison SHALL use the medians of repeated rounds and SHALL widen the threshold by the
spread the two runs' rounds show, up to a configured cap. The previous release's results SHALL be
used only after its signed checksums verify and the results file matches them. Runs on different
reference conditions (runner class, CPU model, CPU count, architecture) SHALL NOT be compared, and
the report SHALL say why. The same comparison SHALL run in CI against the newest release.

#### Scenario: Regression blocks release

- **WHEN** p99 added latency regresses by more than the threshold
- **THEN** the release pipeline fails and names the measurement

#### Scenario: Noise is not a regression

- **WHEN** one round of a measurement is slow and the median of the rounds is within the threshold
- **THEN** the measurement does not regress

#### Scenario: Unverified baseline

- **WHEN** the previous release's results do not match its signed checksums
- **THEN** the check fails instead of comparing

#### Scenario: Different reference machine

- **WHEN** the baseline was measured on another runner class or CPU
- **THEN** nothing is compared and the report names the difference

### Requirement: Results published per release

Each release SHALL publish its benchmark results and reference conditions alongside its artifacts,
as a report and as machine-readable results that record every measurement's rounds, the machine and
the runner class, and the report of the comparison with the previous release.

#### Scenario: Compare releases

- **WHEN** a user opens a release's assets
- **THEN** a benchmark report for that release is attached

#### Scenario: Machine-readable results

- **WHEN** the next release runs its regression check
- **THEN** it reads the previous release's published machine-readable results
