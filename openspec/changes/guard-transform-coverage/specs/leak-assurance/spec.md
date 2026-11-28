## ADDED Requirements

### Requirement: Guard transform rows

The bypass matrix SHALL run a row for each guard transform's form. Forms a default transform reads
(`homoglyphs`, `fullwidth`, `zero-width-scattered`, `unicode-tags`, `nato-spelling`) SHALL expect
`guard` and be gated; forms read only by a transform that is off by default SHALL be limitation
rows whose note names the setting.

#### Scenario: Tag characters

- **WHEN** the gate sends a known value written as Unicode tag characters in a tool result
- **THEN** the request is repaired or refused and the row passes

#### Scenario: Compressed form by default

- **WHEN** the gate runs the `gzip-base64` row with default settings
- **THEN** the row is reported as a limitation, not gated, and its note names `redaction.guard.enable: [compressed]`
