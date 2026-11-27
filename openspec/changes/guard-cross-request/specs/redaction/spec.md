## ADDED Requirements

### Requirement: Split value across the requests of a session

With the `cross-request` guard transform, on by default, the guard SHALL remember per session which
short pieces of which value each request sent, never their bytes, and SHALL repair the pieces of a
request that, with pieces of the same value sent earlier in the session, cover the value as the
within-request rule requires. Only pieces that read as random SHALL count. Requests of other
sessions SHALL never combine.

#### Scenario: Pieces over three requests

- **WHEN** one session sends three requests chained by `previous_response_id`, each holding one 13-byte piece of a 40-byte known value
- **THEN** the third request is forwarded with its piece replaced and the guard reports the `cross-request` view

#### Scenario: Another session

- **WHEN** two sessions each send one 19-byte piece of the same 40-byte known value
- **THEN** neither request is repaired

#### Scenario: Pieces that read as words

- **WHEN** a session sends the three words of a known value `Providence-Waterfall-Harmonica` in separate requests
- **THEN** the guard reports nothing

### Requirement: Bounded cross-request memory

The cross-request memory SHALL hold at most 256 pieces per session and 1,024 sessions, SHALL forget
a piece 30 minutes after it was last seen, and SHALL start empty with every new snapshot and in
every replica.

#### Scenario: Expired piece

- **WHEN** a session sends the second piece of a value more than 30 minutes after the first
- **THEN** the guard reports nothing

#### Scenario: New snapshot

- **WHEN** the redaction set changes between the first and the second piece
- **THEN** the guard reports nothing
