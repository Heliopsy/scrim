## Purpose

Lets scrim read, watch and write secrets in the stores a user already runs (Vaultwarden, Infisical,
OpenBao and plugins) behind one reference scheme, while agents never read a value back.

## ADDED Requirements

### Requirement: One reference scheme across stores

The system SHALL address every secret with a reference of the form `<scheme>://<store-path>[#<field>]`,
where the scheme names a configured store instance (`vw://`, `inf://`, `bao://` or a plugin scheme)
and the optional field selector picks one field of a multi-field secret. A reference that does not
parse, or names an unconfigured store, SHALL be rejected with an error that contains no value.

#### Scenario: Reference with a field selector

- **WHEN** a rule binds `bao://kv/agents/github#token`
- **THEN** scrim resolves only the `token` field of that OpenBao secret

#### Scenario: Unknown scheme is rejected

- **WHEN** configuration or a tool call uses `xyz://foo`
- **THEN** scrim rejects it with an error naming the unknown scheme
- **AND** no store is contacted

### Requirement: Several stores at once

The system SHALL support any number of configured store instances at the same time, including several
instances of the same kind, each with its own name, credentials and scheme alias. Each secret SHALL
live in exactly one store instance; scrim SHALL NOT mirror values between stores.

#### Scenario: Vaultwarden, Infisical and OpenBao together

- **WHEN** one store of each kind is configured
- **THEN** secrets from all three are redacted, injectable and listable by reference
- **AND** a failure of one store does not stop the others from serving

#### Scenario: Two instances of one kind

- **WHEN** two OpenBao instances are configured as `bao-prod://` and `bao-dev://`
- **THEN** references to each resolve only against their own instance

### Requirement: Known values load into the redaction set

The system SHALL read the values of every secret that its configuration marks for redaction from
every configured store at start-up and on refresh, and add them to the redaction set. Until the first
load of a store completes, requests whose routing depends on that store SHALL be refused rather than
forwarded with an incomplete redaction set.

#### Scenario: Start-up before stores are loaded

- **WHEN** an agent sends a provider request while a configured store has not finished its first load
- **THEN** the request is refused with an error saying redaction is not ready
- **AND** nothing is forwarded to the provider

### Requirement: Values are held in memory only

The system SHALL keep secret values only in process memory. Values SHALL NOT be written to the state
backend, the audit log, caches on disk, swap-visible temporary files, logs, metrics or traces. Memory
holding a value SHALL be cleared when the value is dropped from the cache.

#### Scenario: State backend contains no values

- **WHEN** scrim has loaded secrets and served requests with a SQLite or PostgreSQL state backend
- **THEN** a search of the database for any loaded value, in any of its encoded forms, finds nothing

### Requirement: Watch and refresh

The system SHALL refresh each store on a configurable interval with random jitter, and SHALL use a
store's change notification or version metadata where available to fetch only what changed. A
refreshed redaction set SHALL take effect for new requests without a restart.

#### Scenario: Rotated secret is picked up

- **WHEN** a secret is rotated in its store
- **THEN** within one refresh interval plus jitter, both the new value and the previous value are
  redacted
- **AND** the previous value stays in the redaction set for a configurable retention period

#### Scenario: Refreshes are spread out

- **WHEN** several replicas or stores refresh on the same interval
- **THEN** their refresh times are offset by jitter rather than aligned

### Requirement: Store outage keeps the last known redaction set

The system SHALL keep redacting with the last successfully loaded values of a store when that store
becomes unreachable, and SHALL report the store as degraded through health endpoints and metrics.
Redaction SHALL NOT be weakened by an outage.

#### Scenario: Store goes down after loading

- **WHEN** a store that loaded successfully becomes unreachable
- **THEN** values previously loaded from it are still redacted in every provider request
- **AND** the store is reported as degraded

### Requirement: Injection fails closed when a value is unavailable

The system SHALL refuse any operation that needs a value it cannot currently obtain, such as injecting
a credential that was never loaded or whose store is locked. It SHALL NOT substitute an empty string,
a stale value past its configured staleness limit, or the placeholder itself toward the destination.

#### Scenario: Credential unavailable at injection

- **WHEN** an outbound request needs a credential whose value is not in memory and its store is down
- **THEN** the outbound request is refused with an error naming the reference
- **AND** no request reaches the destination

### Requirement: Agents see names, never values

The system SHALL expose to agents only references, names and non-secret metadata (store, type,
bound hosts, created and updated times). No path available to an agent SHALL return a value, whatever
the store's own permission model allows for scrim's credentials.

#### Scenario: Listing secrets

- **WHEN** an agent lists secrets
- **THEN** it receives references and metadata only

#### Scenario: Store grants scrim full read access

- **WHEN** scrim's machine identity in a store can read every value
- **THEN** agents still have no operation that returns a value

### Requirement: Write and generate into a chosen store

The system SHALL write new secrets and new versions of existing secrets to the store a rule or request
names, and SHALL use a configurable default target store per rule when none is named. A write that
the target store rejects SHALL fail with an error that contains no value, and the value SHALL be
dropped from memory.

#### Scenario: Default target store

- **WHEN** an agent generates a secret without naming a store and the matching rule's default target
  is `bao://kv/agents/`
- **THEN** the secret is written under that path and the agent receives its reference

#### Scenario: Write rejected by the store

- **WHEN** the target store refuses the write
- **THEN** the agent receives an error with the reference and the store's reason, without the value

### Requirement: New and written values are redacted at once

The system SHALL add every value it writes or generates to the redaction set before reporting the
write as successful, so the value is redacted in any later provider request even before the next
refresh.

#### Scenario: Captured token appears in a later tool result

- **WHEN** an agent captures a token into a store and a later command prints that token
- **THEN** the provider receives the placeholder, not the token

### Requirement: Vaultwarden adapter

The system SHALL read and write Vaultwarden and Bitwarden-compatible vaults, decrypting and encrypting
items locally, since the server never holds plaintext. It SHALL support selecting items by
organisation, collection, folder or item, and SHALL map item fields (password, username, notes,
custom fields) to field selectors.

#### Scenario: Reading a custom field

- **WHEN** a rule binds `vw://Agents/GitHub#token` and the item has a custom field `token`
- **THEN** scrim decrypts and loads that field's value

### Requirement: Vaultwarden unlock key supplied at start

The system SHALL obtain the Vaultwarden unlock material at start from a configured source: the OS
keyring, a file readable only by scrim, a Kubernetes secret or a systemd credential. While the vault is
locked, the store SHALL be reported as locked, and operations needing its values SHALL fail closed.

#### Scenario: Missing unlock key

- **WHEN** scrim starts and the configured unlock source is empty or unreadable
- **THEN** the Vaultwarden store is reported as locked
- **AND** requests that depend on its values are refused

#### Scenario: Dedicated agent account

- **WHEN** an operator runs `scrim doctor` and the Vaultwarden account in use also holds unrelated
  personal items
- **THEN** scrim warns that a dedicated agent account or organisation is recommended

### Requirement: Infisical adapter

The system SHALL read and write Infisical secrets by project, environment, folder and key, and SHALL
authenticate with Universal Auth or Kubernetes Auth machine identities. Write-only behaviour toward
agents SHALL be enforced by scrim, so it SHALL NOT depend on Infisical's paid custom roles.

#### Scenario: Free tier self-hosted Infisical

- **WHEN** scrim uses an Infisical machine identity with the built-in full-access role
- **THEN** agents can create secrets through scrim but have no operation that reads them back

### Requirement: OpenBao adapter

The system SHALL read and write OpenBao (and Vault-compatible) KV version 2 secrets, authenticating
with AppRole or Kubernetes auth, and SHALL support write paths where scrim's own token has create,
update and patch without read.

#### Scenario: Write-only path

- **WHEN** scrim's token can create but not read under `kv/agents/inbox/`
- **THEN** a secret captured into that path is stored
- **AND** scrim reports it as write-only and does not try to load it into the redaction set from the
  store, keeping only the value it just wrote

### Requirement: OpenBao control groups for configured paths

The system SHALL support OpenBao control groups on configured paths: when a read or write is held by a
control group, scrim SHALL treat it as a pending approval, notify through its own notifiers, and
complete the operation only after the control group is authorised. A control group that expires SHALL
fail the operation closed.

#### Scenario: Read held by a control group

- **WHEN** a break-glass path requires a control-group approval
- **THEN** the operation waits, the approver is notified, and the value is used only after
  authorisation

### Requirement: Store plugins

The system SHALL load additional store adapters as plugins through a documented, versioned contract
covering read, list, watch, write and health. A plugin SHALL run with only the configuration of its
own store, and a plugin crash SHALL be reported as that store being degraded without stopping scrim.

#### Scenario: Plugin crashes

- **WHEN** a store plugin process exits unexpectedly
- **THEN** that store is reported as degraded and restarted with backoff
- **AND** the last known values from it are still redacted

### Requirement: Scrim's store credentials are never exposed

The system SHALL treat its own credentials to secret stores (tokens, AppRole secret IDs, client
secrets, unlock keys) as secret values: they SHALL be redacted in provider traffic and SHALL NOT be
returned by any API, tool, log, metric, trace or audit entry.

#### Scenario: Agent reads scrim's configuration

- **WHEN** an agent with filesystem access prints a scrim configuration that references credentials
- **THEN** the credentials are referenced by source, not inline, or are redacted in the provider
  request
