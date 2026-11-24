## MODIFIED Requirements

### Requirement: Explicitly named weakening settings

Every setting that weakens a security invariant SHALL be named for what it weakens (for example
`redaction.allow-unredacted-on-error`), SHALL default to the safe value, SHALL log a warning at
start-up and on reload while active, and SHALL be listed in `scrim status`. A setting with more than
one safe value (for example `redaction.binary`, whose `scan` and `block` are safe and whose `pass`
weakens) SHALL name its weakening values, and SHALL be reported as weakened only while it holds one
of them; no built-in profile SHALL set a weakening value.

#### Scenario: Weakened setting is visible

- **WHEN** a setting that weakens an invariant is enabled
- **THEN** scrim logs a warning at start-up naming it
- **AND** `scrim status` lists it under weakened protections

#### Scenario: Only the weakening value is reported

- **WHEN** `redaction.binary` is set to `block`
- **THEN** neither `scrim status` nor `scrim doctor` reports it as weakened
- **AND** when it is set to `pass`, both report it as weakened
