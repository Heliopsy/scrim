## ADDED Requirements

### Requirement: Unknown-secret rows

The bypass matrix SHALL include `unknown-secret` rows: for each provider API, a tool result holding
a value in a known format that is in no store, generated at run time and never written to the seed
file. Rows for formats the redaction spec's known-format detectors cover SHALL expect `redacted`
and gate; rows for formats no detector covers SHALL be `limitation` rows with the reason in their
note.

#### Scenario: Cloud key in no store

- **WHEN** the matrix sends a tool result with an AWS secret access key that no store holds through `scrim proxy`
- **THEN** the key does not reach the fake model and a placeholder does

#### Scenario: Pass-through stand-in

- **WHEN** the matrix runs against `builtin:passthrough` or `builtin:naive`
- **THEN** every unknown-secret row reports a leak, since neither stand-in knows the value
