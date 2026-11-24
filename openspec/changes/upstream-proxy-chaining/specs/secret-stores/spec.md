## ADDED Requirements

### Requirement: Environment proxy password is one of scrim's own credentials

The system SHALL treat the password in the user info of an upstream proxy URL it took from its
environment like its secret-ref settings: in the redaction set with no reference and no bound
host, never injected, and left out with a warning when shorter than 8 bytes.

#### Scenario: Proxy password from the environment

- **WHEN** scrim was started with `HTTPS_PROXY=http://user:<password>@proxy.corp:3128` and an agent
  sends that password to a provider
- **THEN** the provider receives a placeholder in its place
- **AND** the password appears in no log line, status output or error
