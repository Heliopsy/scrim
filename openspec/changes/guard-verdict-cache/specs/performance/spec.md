## ADDED Requirements

### Requirement: Guard verdict cache

The guard SHALL remember, per redaction set, which segments of bodies it found clean, as hashes
only, and SHALL check only the segments of a body it has not found clean before. Segments SHALL be
cut where no occurrence of a value can cross. A finding SHALL fall back to checking the whole body,
so verdicts are the same with the cache on or off. `redaction.guard-cache` SHALL turn it off.

#### Scenario: Next turn of a conversation

- **WHEN** an agent's next request repeats the previous body and adds one exchange
- **THEN** the guard checks only the new segments and reaches the verdict a whole check reaches

#### Scenario: Value across a cached and a new segment

- **WHEN** part of a value ends a segment found clean before and the rest starts a new one
- **THEN** the guard finds the value wherever a whole check of the body finds it

#### Scenario: Set changes

- **WHEN** a new snapshot changes the redaction set
- **THEN** no segment is reused from before the change

#### Scenario: Nothing kept but hashes

- **WHEN** the cache holds segments
- **THEN** it holds their BLAKE3 hashes and nothing of the bytes or values, at most the configured number per set

## MODIFIED Requirements

### Requirement: Added request latency budget

The latency scrim adds to a request (redaction and guard, excluding the upstream) SHALL stay below a
configured p99 target, initially 5 ms for 1 MB bodies with 1,000 secrets and 10 ms with 10,000
secrets on the reference machine, measured on an agent's next turn: the previous 1 MB request
again plus one new exchange. Requests seen for the first time SHALL have their own budget. Targets
tighten as the matcher improves and never loosen without a recorded reason.

#### Scenario: Budget met

- **WHEN** the benchmark measures the next turn of a 1 MB conversation with 1,000 secrets
- **THEN** the p99 added latency is below the configured target

#### Scenario: Budget met with metrics on

- **WHEN** the benchmark measures the same request and chunk paths with metrics enabled
- **THEN** the p99 added latency is still below the configured targets, and the report shows the difference to metrics off

#### Scenario: Budget met with a large set

- **WHEN** the benchmark measures the next turn of a 1 MB conversation with 10,000 secrets
- **THEN** the p99 added latency is below the configured large-set target

#### Scenario: First sight

- **WHEN** the benchmark measures a 1 MB body the guard has not seen, with the cache cleared
- **THEN** the p99 added latency is below the configured first-sight target
