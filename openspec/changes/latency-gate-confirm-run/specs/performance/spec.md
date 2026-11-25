## ADDED Requirements

### Requirement: Latency gate confirm run

When the latency gate misses a budget it SHALL measure everything once more in a fresh process and
fail only when that confirm run misses a budget too, naming the measurement. Both runs' reports
SHALL be kept, and the confirm run's results SHALL list the first run's misses.

#### Scenario: Busy runner

- **WHEN** a first run misses a budget and the confirm run meets every budget
- **THEN** the gate passes and its report shows the first run's misses

#### Scenario: Slower build

- **WHEN** both runs miss a budget
- **THEN** the gate fails and names the measurement the confirm run missed
