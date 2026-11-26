## ADDED Requirements

### Requirement: Guard transforms

The guard SHALL also read the outgoing bytes through optional transforms switched by name with
`redaction.guard.disable` and `redaction.guard.enable`: `confusables`, `spelled-out` and
`split-fragments` on by default, `base85` and `compressed` off. Turning a default transform off
SHALL be a weakening setting, and an unknown name SHALL be a configuration error.

#### Scenario: Look-alike letters

- **WHEN** a tool result holds a known value with Cyrillic look-alikes for some of its letters
- **THEN** the guard repairs the request and reports the `confusable` view

#### Scenario: Value spelled in the NATO alphabet

- **WHEN** a tool result spells a known value as NATO, digit and symbol words separated by spaces
- **THEN** the guard repairs the request and reports the `spelled` view

#### Scenario: Transform turned off

- **WHEN** `redaction.guard.disable` names `confusables`
- **THEN** the look-alike form passes the guard and `scrim status` lists the setting as weakened

### Requirement: Split value within one request

The guard SHALL treat pieces of a known value of at least the minimum length, found in at least two
places of one request, as the value when together they cover all of it but its last
`min(7, length / 4)` bytes, and SHALL repair each piece. Pieces that arrive in separate requests
SHALL each be checked alone.

#### Scenario: Value in three fields

- **WHEN** a request holds a 26-byte known value split into pieces of 9, 9 and 8 bytes in three fields
- **THEN** each piece is replaced and the request is forwarded repaired

#### Scenario: One short piece

- **WHEN** a request holds a single 9-byte piece of a 26-byte known value
- **THEN** the guard reports nothing

### Requirement: Compressed documents

With `compressed` enabled, the guard SHALL inflate gzip, zlib, zstd, brotli and raw deflate
streams in base64 runs, within 64 MiB per request, and SHALL replace a run whose inflated text holds
a known value.

#### Scenario: gzip piped to base64

- **WHEN** `compressed` is enabled and a tool result holds `gzip -c .env | base64` of a file with a known value
- **THEN** the base64 run is replaced and the guard reports the `compressed` view
