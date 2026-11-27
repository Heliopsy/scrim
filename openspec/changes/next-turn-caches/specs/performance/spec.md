## ADDED Requirements

### Requirement: Redactor segment cache

The redactor SHALL remember, per redaction set, the hashes of body segments in which it replaced
nothing, and SHALL copy such segments unchanged on later bodies. Segments SHALL be cut only where
no value pattern and no detector match can cross. Hashes of a segment's input SHALL never be kept
when it holds a replacement. Output SHALL be byte for byte the same with the cache on or off.
`redaction.redactor-cache` SHALL turn it off.

#### Scenario: Next turn of a conversation

- **WHEN** an agent's next request repeats the previous body and adds one exchange
- **THEN** only segments not known clean are redacted, and the output equals redacting the whole body

#### Scenario: Detector match near a cut

- **WHEN** a detector anchor whose match could reach across a boundary sits next to it
- **THEN** the boundary is not used as a cut and the detection is the one the whole body gives

#### Scenario: Set changes

- **WHEN** a new snapshot changes the redaction set
- **THEN** no segment is reused from before the change

### Requirement: Codec plan cache

The LLM proxy SHALL remember, per redaction set, plans of conversation elements already planned, as
hashes, lengths and offsets only, and SHALL step over a remembered element when the same bytes
start an element of the same array. Plans and errors SHALL be the same with the cache on or off.
`redaction.redactor-cache` SHALL turn it off.

#### Scenario: Known messages skipped

- **WHEN** a request repeats the messages of an earlier one
- **THEN** those messages are not parsed again and the plan equals the plan of a full parse

#### Scenario: Malformed body

- **WHEN** a body holds remembered messages and invalid JSON or invalid UTF-8 elsewhere
- **THEN** it is refused with the error a full parse reports
