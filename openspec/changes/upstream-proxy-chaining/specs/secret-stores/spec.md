## MODIFIED Requirements

### Requirement: Scrim's own credentials are never exposed

The system SHALL put every secret-ref setting and collection secret field it has resolved in the
redaction set, whatever reference it was read through, along with the password inside
`state.postgres.dsn`, each key of a PEM bundle on their own, and the password in the user info of
an upstream proxy URL scrim took from its environment. These values SHALL carry no reference and
no bound host and SHALL never be injected. A reload that changes one SHALL replace it in the set.
A value shorter than 8 bytes SHALL be left out and logged by setting name.

#### Scenario: Notifier token pasted into a prompt

- **WHEN** `notify.ntfy.token` is `file:/run/secrets/ntfy` and an agent pastes that token into a
  model request
- **THEN** the provider receives a placeholder in its place
- **AND** the token appears in no log line

#### Scenario: Database password inside the state DSN

- **WHEN** `state.postgres.dsn` is `postgres://scrim:<password>@db/scrim` and an agent sends only the
  password to a provider
- **THEN** the provider receives a placeholder in place of the password

#### Scenario: Weak password in the state DSN

- **WHEN** `state.postgres.dsn` is `postgres://postgres:load@db/scrim`
- **THEN** the DSN is redacted but `load` is not, so text that merely contains it is untouched
- **AND** a warning names `state.postgres.dsn`

#### Scenario: Rotated by a reload

- **WHEN** the file behind `notify.ntfy.token` gets a new token and the configuration is reloaded
- **THEN** the new token is redacted from the next provider request

#### Scenario: Proxy password from the environment

- **WHEN** scrim was started with `HTTPS_PROXY=http://user:<password>@proxy.corp:3128` and an agent
  sends that password to a provider
- **THEN** the provider receives a placeholder in its place
- **AND** the password appears in no log line, status output or error
