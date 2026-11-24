## ADDED Requirements

### Requirement: Weakening values

A weakening setting with more than one safe value (for example `redaction.binary`, whose `scan` and
`block` are safe and whose `pass` weakens) SHALL name its weakening values, and SHALL be logged and
reported as weakened only while it holds one of them. No built-in profile SHALL set a weakening
value.

#### Scenario: Only the weakening value is reported

- **WHEN** `redaction.binary` is set to `block`
- **THEN** neither `scrim status` nor `scrim doctor` reports it as weakened
- **AND** when it is set to `pass`, both report it as weakened

#### Scenario: Profiles cannot weaken

- **WHEN** a built-in profile sets a setting to one of its weakening values
- **THEN** registering the setting fails
