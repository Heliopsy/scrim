## ADDED Requirements

### Requirement: Referenced content is scanned before it leaves

Content an agent references by URL SHALL reach the provider only after scrim fetched it and ran the
redactor and the guard over it as over an inline part, so the bytes scanned are the bytes the model
sees. The provider SHALL NOT be left to fetch referenced content unless `redaction.remote-attachments`
is `pass`.

#### Scenario: Text file by URL

- **WHEN** an Anthropic document block references a plain-text URL whose content holds a known value
- **THEN** the provider receives the text inline with the value replaced by its placeholder

#### Scenario: Weakening reported

- **WHEN** `redaction.remote-attachments` is `pass` or `redaction.remote-attachments-allowed-networks` is not empty
- **THEN** `scrim status` and `scrim doctor` list the setting as weakened
