## MODIFIED Requirements

### Requirement: No secret value in any backend

No state backend, event backend, rate-limit backend or audit sink SHALL ever receive a secret value
or a mapping from placeholder to value. Only references, placeholders, identities, decisions and
metadata SHALL be stored or sent. The one exception SHALL be scrim's own tokens shared between
replicas (session tokens, verified Kubernetes service account tokens and issued identity tokens),
which the state backend SHALL hold only sealed with AES-256-GCM under a key derived from the
placeholder keys, never in plaintext, and which SHALL never be sent to an events backend in any
form.

#### Scenario: Inspect stored state

- **WHEN** a test seeds known secrets, runs traffic and then dumps every backend and sink
- **THEN** no known secret value, in any supported encoding, appears in the dump

#### Scenario: Value in a free-text field

- **WHEN** a caller passes a known secret value inside a reason, target or attribute of a state change
- **THEN** the stored row holds a redacted marker in its place

#### Scenario: Shared tokens in the dump

- **WHEN** several replicas share PostgreSQL state, a session is minted and a service account token
  is verified, and the state database is dumped
- **THEN** neither token appears in the dump in plaintext or in any supported encoding
- **AND** the outbox holds the row ID of each shared token and nothing derived from its value but a
  keyed hash

### Requirement: Replica count is declared

The number of replicas SHALL be declared by `deployment.replicas`. With more than one, start-up SHALL
reject `local` events, a state backend that is not shared (`memory`, `sqlite`) and an empty
`redaction.placeholder-keys`, naming the setting.

#### Scenario: Multiple replicas with local events

- **WHEN** scrim is configured with more than one replica and `events.backend: local`
- **THEN** start-up fails with an error naming `events.backend`

#### Scenario: Multiple replicas with unshared state

- **WHEN** scrim is configured with more than one replica, `events.backend: postgres` and
  `state.backend: sqlite`
- **THEN** start-up fails with an error naming `state.backend`

#### Scenario: Multiple replicas without shared placeholder keys

- **WHEN** scrim is configured with more than one replica, shared state and events, and no
  `redaction.placeholder-keys`
- **THEN** start-up fails with an error naming `redaction.placeholder-keys`

## ADDED Requirements

### Requirement: Every replica redacts scrim's own tokens

With `state.backend: postgres` and `redaction.placeholder-keys` set, every session token scrim
mints, every Kubernetes service account token it verifies and every identity token its issuer signs
SHALL be written to the state backend sealed, with an outbox event naming the row. Every replica
SHALL add each live shared token to its redaction set once the event is delivered, and SHALL load
every live shared token before it reports ready.

#### Scenario: Session minted on another replica

- **WHEN** a session is minted through replica A and the agent sends its token to a provider through
  replica B
- **THEN** the provider receives a placeholder for the token, never the token
- **AND** this holds with `events.backend` `postgres`, `valkey` and `nats`

#### Scenario: Service account and issuer tokens

- **WHEN** replica A verifies a service account token or its issuer signs an identity token
- **THEN** replica B's redaction set holds the token within the event delivery bound

#### Scenario: Replica started later

- **WHEN** replica B starts after replica A minted a session that is still live
- **THEN** B's first snapshot already holds the session's token

### Requirement: Shared tokens expire and fail safe

A shared token SHALL leave every replica's redaction set when it expires, and expired rows SHALL be
deleted. A revoked session's token SHALL stay in every replica's redaction set until it expires. A
row that cannot be opened SHALL be skipped and logged by row ID, never added. A failed write SHALL
NOT refuse the mint and SHALL be retried until it succeeds or the token expires.

#### Scenario: Token expires

- **WHEN** a shared token's expiry passes
- **THEN** every replica removes it from its redaction set and the row is deleted

#### Scenario: Revoked session

- **WHEN** a session minted through replica A is revoked through replica B
- **THEN** every replica keeps its token in the redaction set until it expires and drops the session
  from narrowed redaction at once

#### Scenario: Unreadable row

- **WHEN** a shared row was sealed under a placeholder key version this replica does not hold
- **THEN** the replica logs the row ID and key version, adds nothing and keeps serving

#### Scenario: Write fails

- **WHEN** the state backend refuses the write of a newly minted session token
- **THEN** the mint succeeds, the minting replica redacts the token, and the write is retried until
  it succeeds
