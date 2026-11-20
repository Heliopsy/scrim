## Purpose

Defines the latency, throughput and memory budget scrim must meet on the request path, the
conditions under which it is measured, and how regressions are stopped before a release.

## ADDED Requirements

### Requirement: Benchmark conditions

Performance SHALL be measured on published reference conditions: request bodies of about 100 KB, 1 MB
and 4 MB, with and without hits; secret sets of 10, 1,000 and 10,000 values with all encoded variants;
recorded streaming responses chunked at realistic boundaries; and a documented machine.

#### Scenario: Conditions recorded with results

- **WHEN** the benchmark suite runs
- **THEN** its report states body sizes, secret counts, hardware and versions for every number

### Requirement: Added request latency budget

The latency scrim adds to a request (redaction and guard, excluding the upstream) SHALL stay below a
configured p99 target, initially 5 ms for 1 MB bodies with 1,000 secrets and 10 ms with 10,000
secrets on the reference machine. The target tightens as the matcher improves and never loosens
without a recorded reason.

#### Scenario: Budget met

- **WHEN** the benchmark measures a 1 MB body with 1,000 secrets
- **THEN** the p99 added latency is below the configured target

#### Scenario: Budget met with a large set

- **WHEN** the benchmark measures a 1 MB body with 10,000 secrets
- **THEN** the p99 added latency is below the configured large-set target

### Requirement: Streamed chunk budget

The time scrim adds per streamed response chunk SHALL stay below a configured p99 target, initially
50 µs per chunk.

#### Scenario: Chunk budget met

- **WHEN** the benchmark replays a recorded stream of 20,000 events
- **THEN** the p99 time added per chunk is below the configured target

### Requirement: First byte not delayed beyond holdback

scrim SHALL forward streamed bytes as soon as they cannot be part of a placeholder, holding back no
more than one placeholder length minus one byte per content block.

#### Scenario: Plain text streams through

- **WHEN** an upstream streams text that contains no placeholder prefix
- **THEN** each chunk is forwarded without waiting for following chunks

### Requirement: Bounded memory per stream

Memory held per concurrent stream SHALL be bounded by a documented formula of holdback size and
buffer limits, independent of total stream length.

#### Scenario: Long stream

- **WHEN** a single stream runs for 1 GB of output
- **THEN** scrim's memory for that stream stays within the documented bound

### Requirement: Matcher rebuild off the request path

Changes to the set of known secrets SHALL be applied by building a new matcher in the background and
swapping it in atomically. No request SHALL wait for a rebuild, and each request SHALL use one
consistent matcher from start to end.

#### Scenario: Rebuild under load

- **WHEN** 10,000 secrets change while requests are in flight
- **THEN** in-flight requests complete with the matcher they started with
- **AND** request latency during the rebuild stays within budget

### Requirement: Throughput per core

scrim SHALL publish its sustained redaction throughput per core for each reference body size, and SHALL
meet a configured minimum.

#### Scenario: Throughput reported

- **WHEN** the benchmark suite runs
- **THEN** it reports MB/s per core for each body size and fails if below the configured minimum

### Requirement: Regression gate

A release SHALL fail when any budgeted measurement regresses beyond a configured threshold against the
previous release on the same reference conditions. Targets and thresholds SHALL be configuration, not
code.

#### Scenario: Regression blocks release

- **WHEN** p99 added latency regresses by more than the threshold
- **THEN** the release pipeline fails and names the measurement

### Requirement: Results published per release

Each release SHALL publish its benchmark results and reference conditions alongside its artifacts.

#### Scenario: Compare releases

- **WHEN** a user opens a release's assets
- **THEN** a benchmark report for that release is attached
