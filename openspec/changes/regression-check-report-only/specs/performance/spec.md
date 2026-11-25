## MODIFIED Requirements

### Requirement: Regression gate

A release SHALL fail when any budgeted measurement regresses beyond a configured threshold against the
previous release on the same reference conditions, unless the configuration marks the comparison
report only. Targets, thresholds and enforcement SHALL be configuration, not code. The comparison
SHALL use the medians of repeated rounds, with the threshold widened by the spread of the two runs'
rounds up to a configured cap, and SHALL run in CI against the newest release.

#### Scenario: Regression blocks release

- **WHEN** p99 added latency regresses by more than the threshold and the comparison is enforced
- **THEN** the release pipeline fails and names the measurement

#### Scenario: Report only

- **WHEN** the comparison is configured report only and a measurement regresses
- **THEN** the release proceeds and its published regression report names the measurement
