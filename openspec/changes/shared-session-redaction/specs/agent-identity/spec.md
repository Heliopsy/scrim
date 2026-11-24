## MODIFIED Requirements

### Requirement: Stricter per-agent redaction is weakening

The stricter option, `redaction.limit-to-agent-identity`, SHALL be off by default and reported as
weakening in logs, `scrim status` and `scrim doctor`. It SHALL leave out only values the store
refused that agent's identity, and only for provider requests carrying a token of that agent's
session that has not been revoked; every other caller and path SHALL keep the whole redaction set.
With shared session tokens (state-and-scaling "Every replica redacts scrim's own tokens") the
narrowing SHALL apply on every replica alike, and a revocation made through any replica SHALL end it
on every replica.

#### Scenario: Stricter option narrows only proven sessions

- **WHEN** `redaction.limit-to-agent-identity` is on and OpenBao refuses `agent-a`'s credential
  for `kv/prod/payments`
- **THEN** a provider request from a session of `agent-a` that carries its token is not redacted
  for the payments value and is still redacted for `kv/agents/a`
- **AND** the same request with no session, a bare session id or a token of that session id with
  another secret is redacted for both
- **AND** start-up logs a warning naming the setting, and `scrim status` and `scrim doctor` report
  it as weakened

#### Scenario: Unknown answers stay redacted

- **WHEN** `redaction.limit-to-agent-identity` is on and the check of a value as `agent-a` fails or
  has not run yet
- **THEN** the value is redacted from `agent-a`'s sessions

#### Scenario: Session minted on another replica

- **WHEN** `redaction.limit-to-agent-identity` is on, two replicas share PostgreSQL state, and a
  session of `agent-a` minted through replica A sends a request through replica B
- **THEN** B narrows the request's redaction as A would

#### Scenario: Revoked session

- **WHEN** a session with narrowed redaction is revoked
- **THEN** its requests get the whole redaction set on every replica
