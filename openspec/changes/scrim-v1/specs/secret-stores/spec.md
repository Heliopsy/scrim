## Purpose

Lets scrim read, watch and write secrets in the stores a user already runs (Vaultwarden, Infisical,
OpenBao and plugins) behind one reference scheme, while agents never read a value back.

## ADDED Requirements

### Requirement: One reference scheme across stores

The system SHALL address every secret with a reference of the form `<scheme>://<store-path>[#<field>]`,
where the scheme names a configured store instance (for example `vw://`, `inf://`, `bao://`, `vault://`,
`aws-sm://`, `aws-ssm://`, `gcp-sm://`, `azure-kv://`, `op://` or a plugin scheme)
and the optional field selector picks one field of a multi-field secret. A reference that does not
parse, or names an unconfigured store, SHALL be rejected with an error that contains no value.

#### Scenario: Reference with a field selector

- **WHEN** a rule binds `bao://kv/agents/github#token`
- **THEN** scrim resolves only the `token` field of that OpenBao secret

#### Scenario: Unknown scheme is rejected

- **WHEN** configuration or a tool call uses `xyz://foo`
- **THEN** scrim rejects it with an error naming the unknown scheme
- **AND** no store is contacted

#### Scenario: Selector the store cannot honour

- **WHEN** a reference carries a selector its store does not support, such as `bao://kv/x?stage=AWSPREVIOUS`
- **THEN** scrim rejects the reference with an error naming the selector
- **AND** it does not fall back to the current version

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

### Requirement: Redact targets name secrets, folders or globs

A redact target SHALL be one secret, every secret under a folder (`<folder>/*`), or a glob: a
target ending in `*` right after part of a name, matching every secret whose path starts with the
text before the `*`. A `*` anywhere else SHALL be refused at configuration time, so a pattern is
never read as a literal secret name. A glob SHALL be accepted only on a store that declares glob
listing (env and file).

#### Scenario: Name-prefix glob on the env store

- **WHEN** an env store with `prefix: SCRIM_SECRET_` has `redact: [local://SCRIM_SECRET_*]` and `SCRIM_SECRET_X` is set
- **THEN** the value of `SCRIM_SECRET_X` is loaded into the redaction set and redacted from provider requests
- **AND** variables outside the prefix, such as `SCRIM_SECRETX` or `HOME`, are not loaded

#### Scenario: Glob on a store that cannot expand it

- **WHEN** an OpenBao store has `redact: [bao://kv/app-*]`
- **THEN** `scrim config validate` and start-up fail with an error naming the target and saying the store does not match names by a trailing `*`

### Requirement: Empty redact targets refuse start-up

Every redact target SHALL report how many values it holds. A target that holds no value after the
store's first successful load SHALL keep the store not ready and fail start-up with an error naming
the target, unless the weakening setting `redaction.allow-empty-targets` is on. An unreachable store
is an outage, not an empty target, and keeps the not-ready behaviour.

#### Scenario: A target that matches nothing

- **WHEN** a store has `redact: [env://SCRIM_SECRET_NOTHING_*]` and no variable matches
- **THEN** start-up fails with an error naming `env://SCRIM_SECRET_NOTHING_*` and the setting that allows it
- **AND** no provider request is forwarded

#### Scenario: Empty target explicitly allowed

- **WHEN** the same configuration runs with `redaction.allow-empty-targets: true`
- **THEN** scrim starts and logs a warning for the weakening setting
- **AND** `scrim status` lists the setting under weakened protections and the store as degraded with the target at 0 values

### Requirement: Status never claims redaction for an empty target

`scrim status` and `scrim doctor` SHALL show the value count of every redact target, and SHALL NOT
report redaction as active, or a store as healthy, while one of its targets holds 0 values.

#### Scenario: Status with an empty target

- **WHEN** a daemon runs with an empty target allowed by `redaction.allow-empty-targets`
- **THEN** `scrim status` shows the target at 0 values, the store as degraded and the redaction protection as inactive, naming the target
- **AND** `scrim doctor` warns that the target protects nothing

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
- **AND** only the new value is injectable, and the data plane accepts the snapshot that carries both

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

#### Scenario: Rotated value survives an outage

- **WHEN** a secret was rotated, then its store became unreachable
- **THEN** both the current and the previous value stay redacted until the retention period ends

### Requirement: Injection fails closed when a value is unavailable

The system SHALL refuse any operation that needs a value it cannot currently obtain, such as injecting
a credential that was never loaded or whose store is locked. It SHALL NOT substitute an empty string,
a stale value past its configured staleness limit, or the placeholder itself toward the destination.

#### Scenario: Credential unavailable at injection

- **WHEN** an outbound request needs a credential whose value is not in memory and its store is down
- **THEN** the outbound request is refused with an error naming the reference
- **AND** no request reaches the destination

#### Scenario: Value past the staleness limit

- **WHEN** a credential was loaded, its store has been unreachable for longer than the configured
  staleness limit, and an outbound request needs it
- **THEN** the request is refused with an error naming the reference
- **AND** the value is still redacted

#### Scenario: Placeholder of a value that has not loaded

- **WHEN** a store has not delivered a catalog credential yet and a tool request toward its bound host carries its placeholder
- **THEN** the request is refused with `credential_unavailable` and the placeholder is not forwarded as text

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

#### Scenario: Value redacted while the write is in flight

- **WHEN** scrim writes a captured value and the store has not answered yet
- **THEN** the value is already in the redaction set
- **AND** if the store then refuses the write, the value is removed from memory

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

#### Scenario: Tampered ciphertext

- **WHEN** an item's encrypted field fails MAC verification, or uses an unauthenticated legacy
  encryption type
- **THEN** scrim refuses to decrypt it and the read fails with an error that contains no value
- **AND** nothing from that field enters the redaction set or is injected

#### Scenario: Item outside the configured scope

- **WHEN** the Vaultwarden store is configured with scope `Agents` and a reference names
  `vw://Personal/Bank`
- **THEN** the read fails as not found and the write is refused
- **AND** scrim does not decrypt the item

#### Scenario: Ambiguous item path

- **WHEN** two items match `vw://Agents/Deploy`, one personal and one in organisation `Acme`
- **THEN** the unqualified reference is refused as ambiguous
- **AND** `vw://Agents/Deploy?org=Acme` resolves the organisation item

### Requirement: Vaultwarden unlock key supplied at start

The system SHALL obtain the Vaultwarden unlock material at start from a configured source: the OS
keyring, a file readable only by scrim, a Kubernetes secret or a systemd credential. While the vault is
locked, the store SHALL be reported as locked, and operations needing its values SHALL fail closed.

#### Scenario: Missing unlock key

- **WHEN** scrim starts and the configured unlock source is empty or unreadable
- **THEN** the Vaultwarden store is reported as locked
- **AND** requests that depend on its values are refused

#### Scenario: Unlock key given as a literal

- **WHEN** the Vaultwarden store's unlock setting holds a literal instead of a reference
- **THEN** configuration validation fails without echoing the literal
- **AND** the store is not opened

#### Scenario: Dedicated agent account

- **WHEN** an operator runs `scrim doctor` and the Vaultwarden account in use also holds unrelated
  personal items
- **THEN** scrim warns that a dedicated agent account or organisation is recommended

### Requirement: Vaultwarden native labels

The Vaultwarden adapter SHALL report where an item lives and what it is as labels under the reserved
prefix `vaultwarden.` (organisation, ownership, collections and permissions, folder and ancestors,
type, flags, URI hosts, field presence, dates). A multi-valued attribute SHALL carry its values
comma-joined plus one presence key per value, so a rule matches the item's real location whatever
path its reference uses.

#### Scenario: Collection rule matches through any path

- **WHEN** an item is in collections `Prod` and `Shared` and a rule asks for any secret with
  `"vaultwarden.collection.Prod" in secret.labels`
- **THEN** the rule matches the item whether it is referenced as `vw://Prod/DB` or
  `vw://Shared/DB`
- **AND** the item carries `vaultwarden.collection = "Prod,Shared"` and both presence keys

#### Scenario: Nested folder matches its ancestors

- **WHEN** an item is in the folder `Agents/CI`
- **THEN** it carries `vaultwarden.folder.Agents` and `vaultwarden.folder.Agents/CI`, so a rule on
  folder `Agents` also matches it

### Requirement: Vaultwarden labels carry no values and cannot be forged

Text custom fields that are not `scrim.*` labels SHALL be reported as `vaultwarden.meta.<key>`
only when the operator enables it, and doctor SHALL warn while it is on. A meta label whose value
equals or contains a secret value of an in-scope item SHALL NOT be reported, and items outside the
scope SHALL NOT be decrypted for it. Hidden fields, passwords, TOTP seeds, notes and key material
SHALL never become labels. Native labels SHALL override any user-supplied label.

#### Scenario: Meta labels are off by default

- **WHEN** a Vaultwarden store is configured without `meta-labels`
- **THEN** no `vaultwarden.meta.*` label is reported
- **AND** with `meta-labels: true`, `scrim doctor` warns that text fields are visible as labels

#### Scenario: Meta label repeating a secret is dropped

- **WHEN** `meta-labels` is on and a text custom field holds a value that equals or contains a
  password, hidden field, TOTP seed, note or key of any item inside the configured scope
- **THEN** that field is not reported as a label

#### Scenario: Meta guard stays inside the scope

- **WHEN** `meta-labels` is on and the store has a scope
- **THEN** the guard decrypts no item outside the scope, and no text field of such an item becomes a
  label

#### Scenario: Native label cannot be forged

- **WHEN** someone who can edit an organisation item adds a text custom field named
  `vaultwarden.org` with the value `Evil`
- **THEN** `vaultwarden.org` still reports the organisation the item is in
- **AND** the field is reported only as `vaultwarden.meta.vaultwarden.org`

#### Scenario: Hidden fields never become labels

- **WHEN** an item has a hidden custom field `token`, a password and login URIs with user info,
  paths or queries
- **THEN** no label contains the token, the password or anything of the URIs but their host names

### Requirement: Vaultwarden write labels

The Vaultwarden adapter SHALL expose the native labels a write leaves on the item before the write
happens, so `store.write` rules can match its destination.

#### Scenario: Write rule sees where a new item lands

- **WHEN** a `store.write` rule asks for writes into organisation `Acme` and an agent writes
  `vw://Prod/New?org=Acme`, which does not exist yet
- **THEN** the rule sees `vaultwarden.org = "Acme"` and `vaultwarden.collection.Prod` before the
  item is created

### Requirement: Vaultwarden labels read without values

The Vaultwarden adapter SHALL return an existing item's metadata and labels without decrypting any
of its field values, from the index of the last sync after checking the server's revision date. The
labels SHALL be the ones a read of the item reports, the meta label guard and its scope included, and
a lookup SHALL fail wherever a read fails for the item itself (locked, unreachable, outside the
scope, ambiguous, no such field).

#### Scenario: Write to an item outside every redaction set

- **WHEN** an agent writes to `vw://Prod/DB?org=Acme`, which exists but is in no redaction set
- **THEN** the write rule sees the item's `vaultwarden.*` labels exactly as a read would report them
- **AND** no field value of the item is decrypted for the lookup, so an item whose password does not
  decrypt still has its labels

#### Scenario: Locked store

- **WHEN** the store is locked and a rule needs an item's labels
- **THEN** the lookup fails and the request is decided with its labels unknown

### Requirement: Bitwarden Secrets Manager adapter

The system SHALL read, list, watch and write Bitwarden Secrets Manager secrets by project name or ID
and key, or by secret ID, logging in as a machine account with its access token. Keys, values, notes
and project names SHALL be encrypted and decrypted by scrim with the organization key the login
yields, so Bitwarden only ever receives ciphertext, and the protocol steps SHALL be pinned by
known-answer tests against vectors from the official SDK.

#### Scenario: Read through a project name

- **WHEN** scrim reads `bws://prod/db/PASSWORD` with a machine account that can read project `prod`
- **THEN** it returns the decrypted value of key `db/PASSWORD` in that project as the field `value`
- **AND** the note is returned only for `bws://prod/db/PASSWORD#note`

#### Scenario: Write into a read-only project

- **WHEN** an agent writes `bws://prod/NEW` and the machine account may only read `prod`
- **THEN** the write fails with permission denied naming the store and reference, although Bitwarden
  answers it with not found

### Requirement: Bitwarden Secrets Manager names that are not unique

Secrets Manager allows several secrets with one key and several projects with one name. A read,
write or label lookup through a name that matches more than one SHALL fail as an invalid reference
naming the IDs to use instead, and SHALL NOT pick one. A listing SHALL return secrets that share a
key by their ID.

#### Scenario: Two secrets share a key

- **WHEN** project `app` holds two secrets with key `TOKEN` and an agent reads `bws://app/TOKEN`
- **THEN** the read fails as an invalid reference naming both secret IDs
- **AND** listing `bws://app` returns both as `bws://<secret-id>` so a redact target still loads them

### Requirement: Bitwarden Secrets Manager labels without values

The adapter SHALL label every secret with `bws.org`, `bws.id`, `bws.key`, its projects as
`bws.project` and `bws.project-id` with presence keys, and `bws.created` and `bws.updated`. The
labels of an existing secret SHALL come from the secret identifier list without fetching its value,
SHALL equal those a read reports, and SHALL NOT contain the value or the note. A write target SHALL
be labelled from its reference alone.

#### Scenario: Labels of a write target

- **WHEN** a rule asks for writes into project `prod` and an agent creates `bws://prod/NEW`
- **THEN** the write is decided on `bws.project.prod = true` before the secret exists, and asks

#### Scenario: Labels hold no value or note

- **WHEN** a secret has a value and a note and a rule needs its labels
- **THEN** no secret is fetched and neither the value nor the note appears in any label

### Requirement: Infisical adapter

The system SHALL read and write Infisical secrets by project, environment, folder and key, and SHALL
authenticate with Universal Auth or Kubernetes Auth machine identities. Write-only behaviour toward
agents SHALL be enforced by scrim, so it SHALL NOT depend on Infisical's paid custom roles.

#### Scenario: Free tier self-hosted Infisical

- **WHEN** scrim uses an Infisical machine identity with the built-in full-access role
- **THEN** agents can create secrets through scrim but have no operation that reads them back

### Requirement: Infisical native policy labels

The Infisical adapter SHALL label every secret it reads or lists with Infisical's own attributes
under `infisical.<attr>` (organisation, project, environment, folder with its ancestors, key, path,
type, version, times, tags, rotation, reminder and import source), writing a multi-valued attribute
as a comma-joined key plus one presence key per value.

#### Scenario: Policy matches project, environment, folder and tag

- **WHEN** a rule asks for secrets of project `payments` that are in environment `prod`, under folder
  `/db` or tagged `pci`, and an agent reads `inf://payments/dev/db/primary/PASSWORD`
- **THEN** the secret carries `infisical.project.slug = payments`, `infisical.environment = dev`,
  `infisical.folder.db = true` and `infisical.folder.db.primary = true`, and the read asks

#### Scenario: Imported secret

- **WHEN** folder `/app` of `prod` imports `/shared` of `dev` and scrim reads
  `inf://payments/prod/app/SHARED_KEY` from the import
- **THEN** the secret carries `infisical.imported = true`, `infisical.import.environment = dev` and
  `infisical.import.path = /shared`, while `infisical.environment` stays `prod`

### Requirement: Infisical write targets are labelled before they exist

The Infisical adapter SHALL report the labels a secret written at a reference would get, without
contacting Infisical, so `store.write` rules can match on them.

#### Scenario: Write rules see the target's labels

- **WHEN** a rule asks for writes under `/db` and an agent creates `inf://payments/dev/db/NEW`
- **THEN** the write is decided on `infisical.folder.db = true` before the secret exists, and asks

### Requirement: Infisical hidden values are refused

A read of an Infisical secret SHALL fail as a permission error when Infisical marks the value hidden
(`secretValueHidden: true`), and SHALL wipe the mask unread. The mask SHALL NOT be used as the value.

#### Scenario: Identity may describe but not read

- **WHEN** Infisical answers a read with `secretValueHidden: true` and its mask in the value field
- **THEN** the read fails with permission denied naming the store and reference, and nothing is
  loaded into a redaction set

### Requirement: Infisical labels read without values

The Infisical adapter SHALL return an existing secret's metadata and labels through a request that
asks Infisical not to return the value (`viewSecretValue=false`, references not expanded), and SHALL
wipe whatever arrives in the value field unread. The labels SHALL be the ones a read reports, and a
lookup SHALL fail wherever a read fails.

#### Scenario: Labels of an existing secret

- **WHEN** a rule needs the labels of `inf://payments/prod/db/PASSWORD`, which exists but is in no
  redaction set
- **THEN** scrim asks Infisical for the secret with `viewSecretValue=false` and the labels equal those
  a read reports, tags, metadata and import source included

#### Scenario: Infisical unreachable

- **WHEN** Infisical does not answer the lookup
- **THEN** the lookup fails and the request is decided with its labels unknown

### Requirement: Infisical metadata cannot forge native labels

Unencrypted Infisical secret metadata SHALL appear under `infisical.meta.<key>` and under its own
key. A user-supplied key in the `infisical.` namespace SHALL NOT set or override a native label, and
a write SHALL NOT store such keys as metadata.

#### Scenario: Metadata cannot forge a native label

- **WHEN** a secret in `prod` carries metadata `infisical.environment = dev` and
  `infisical.tag.pci = false`
- **THEN** its labels say `infisical.environment = prod`, have no `infisical.tag.pci` key unless the
  secret is tagged `pci`, and show the entries as `infisical.meta.infisical.environment` and
  `infisical.meta.infisical.tag.pci`

### Requirement: Infisical labels hold no value

Labels from the Infisical adapter SHALL NOT contain a secret value, the secret comment, the reminder
note or the value of an encrypted metadata entry.

#### Scenario: Labels hold no value

- **WHEN** a secret has a value, a comment, a reminder note and an encrypted metadata entry
- **THEN** none of them appears in any label key or value, and the encrypted entry is listed by key
  only in `infisical.encrypted-meta`

### Requirement: SOPS file source

The system SHALL provide a read-only `sops` source for SOPS-encrypted YAML, JSON, dotenv and INI files
under a configured root, addressed as `<instance>://<path under root>[#key-path]`, a key path joining
map keys and list positions with `/`. It SHALL decrypt only with the age identities its configuration
names, never with ambient sops key locations, and SHALL declare read, list, watch and glob, refusing
writes as read-only.

#### Scenario: Decrypt with the configured age key

- **WHEN** `prod/app.yaml` under the root was encrypted by sops for the age recipient of the identity
  `age-identity` names
- **THEN** reading `team://prod/app.yaml#db/password` returns the decrypted value of `db.password`
- **AND** a file encrypted only for another recipient is refused with a permission error naming the
  store and reference, without any value

#### Scenario: Write refused as read-only

- **WHEN** a rule targets a `sops` instance for `secret_capture` or `secret_gen`
- **THEN** the call is refused with an error saying the sops source is read-only
- **AND** nothing is written under the root

### Requirement: SOPS files are authenticated before use

The `sops` source SHALL verify a file's MAC over all of its values before returning any of them, and
SHALL refuse a file whose MAC or values do not authenticate.

#### Scenario: MAC failure refused

- **WHEN** a value, the order of values, an unencrypted leaf or the MAC of a SOPS file was changed by
  anything but sops
- **THEN** the read fails with a permission error and no value of that file is returned

### Requirement: SOPS native labels

The `sops` source SHALL label every secret with its file's plaintext sops metadata under
`sops.<attribute>` keys, read without decrypting, and the labels SHALL never hold a secret value.

#### Scenario: Labels from sops metadata

- **WHEN** a policy rule needs the labels of a SOPS file encrypted for two age recipients
- **THEN** the labels include `sops.path`, `sops.format`, `sops.version`, `sops.lastmodified` and
  `sops.age-recipient` with one presence key per recipient, read without the age key
- **AND** no label key or value contains a decrypted value or the age identity

### Requirement: OpenBao adapter

The system SHALL read and write OpenBao (and Vault-compatible) KV version 2 secrets, authenticating
with AppRole or Kubernetes auth, and SHALL support write paths where scrim's own token has create,
update and patch without read.

#### Scenario: Write-only path

- **WHEN** scrim's token can create but not read under `kv/agents/inbox/`
- **THEN** a secret captured into that path is stored
- **AND** scrim reports it as write-only and does not try to load it into the redaction set from the
  store, keeping only the value it just wrote

### Requirement: OpenBao native labels

The OpenBao adapter SHALL label every secret it reads, lists or writes with what OpenBao reports
about it, under `openbao.<attribute>` keys: mount, engine, namespace, path and its folders and
segments, versions and version settings, times, deletion state, and mount description, options and
settings. A list attribute SHALL be stored comma-joined and as one presence key per value. Labels
SHALL never hold a secret value.

#### Scenario: Ancestor folders match

- **WHEN** scrim reads `bao://kv-prod/prod/eu/db`
- **THEN** its labels hold `openbao.mount: kv-prod`, `openbao.path: prod/eu/db`,
  `openbao.ancestors: prod,prod/eu`, `openbao.ancestors.prod: "true"` and
  `openbao.ancestors.prod/eu: "true"`
- **AND** a rule matching `"openbao.ancestors.prod" in secret.labels` matches it

#### Scenario: No value in labels

- **WHEN** scrim reads, lists and writes a secret holding a generated value
- **THEN** no label key or value contains that value

### Requirement: OpenBao custom metadata labels cannot forge native keys

The OpenBao adapter SHALL label KV v2 custom metadata as `openbao.meta.<key>` and, unless the key
starts with `openbao.` or `store.`, under its own key as well. Custom metadata SHALL NOT overwrite a
native key. Custom metadata keys SHALL be folded to lowercase ASCII letters, digits, `-` and `_` in
dot-separated segments; presence keys SHALL carry their value verbatim.

#### Scenario: Custom metadata cannot forge native keys

- **WHEN** a secret under mount `kv-prod` has custom metadata `openbao.mount = kv-dev` and
  `team = payments`
- **THEN** its labels hold `openbao.mount: kv-prod`, `openbao.meta.openbao.mount: kv-dev`,
  `openbao.meta.team: payments` and `team: payments`

### Requirement: OpenBao label lookups are optional

A request the OpenBao adapter makes only for labels (secret metadata on read, mount information)
SHALL NOT fail the operation or force a new login when it is refused or fails; the labels that
depended on it SHALL be left out. Configuration SHALL be able to turn these requests off.

#### Scenario: Forbidden metadata lookups degrade

- **WHEN** scrim's token may read a secret's data but not its metadata or its mount
- **THEN** the read succeeds with the value
- **AND** the labels that need metadata, such as `openbao.current_version` and
  `openbao.max_versions`, are absent while `openbao.mount`, `openbao.path` and `openbao.version`
  are present
- **AND** scrim does not log in again because of the refusal

#### Scenario: Label lookups turned off

- **WHEN** `labels.lookups` is false
- **THEN** a read makes no request besides the data read
- **AND** its labels still hold the mount, path and version labels

### Requirement: OpenBao scheduled deletion is not deletion

The OpenBao adapter SHALL treat a version as deleted only once its deletion time has passed.

#### Scenario: Scheduled deletion is not deletion

- **WHEN** the current version has a deletion time in the future, set by `delete_version_after`
- **THEN** it is read and listed as usual, with that time in `openbao.deletion_time`

### Requirement: OpenBao paths are escaped once

The OpenBao adapter SHALL send a secret path to OpenBao with each segment escaped exactly once, so
OpenBao stores and finds the secret under the name in its reference.

#### Scenario: Path with a space

- **WHEN** scrim writes `bao://kv/agents/git hub`
- **THEN** OpenBao receives the path `kv/data/agents/git%20hub` and stores the secret as
  `agents/git hub`

### Requirement: OpenBao secrets under the legacy double-escaped name

When a secret is not found under its name and the name contains characters that need escaping, the
OpenBao adapter SHALL look it up under the name releases up to 0.4.0 stored it under (each segment
escaped once more), use it if it exists, and log one warning per secret naming both paths and no
value. A secret under the correct name SHALL take precedence.

#### Scenario: Secret under the legacy double-escaped name

- **WHEN** a secret written by an earlier release exists only as `agents/git%20hub` and scrim reads
  `bao://kv/agents/git hub` twice
- **THEN** both reads return it
- **AND** one warning names `kv/agents/git hub` and `kv/agents/git%20hub` and no value

### Requirement: OpenBao metadata without values

The OpenBao adapter SHALL implement the metadata read of "Metadata without values" from the KV v2
metadata endpoint, returning the labels, version and times a read would return without reading
the secret's data. It SHALL miss the same versions a read misses and refuse the same references,
write-only paths included. When the store refuses the metadata read, it SHALL fall back to reading
the secret and wiping every value; any other failure SHALL be returned as an error.

#### Scenario: Labels of an existing secret without its value

- **WHEN** a policy decision needs the labels of `bao://kv-prod/prod/eu/db`, which is in no
  redaction set
- **THEN** scrim requests `kv-prod/metadata/prod/eu/db` and not `kv-prod/data/prod/eu/db`
- **AND** the labels equal the labels a read of the secret reports

#### Scenario: Metadata refused

- **WHEN** scrim's token may read the secret's data but not its metadata
- **THEN** scrim reads the secret, wipes the values, and uses the labels of that read

#### Scenario: Store failure

- **WHEN** the metadata read fails with a server error
- **THEN** the lookup fails with the store unavailable and the data is not read

### Requirement: Store login with the pod's Kubernetes service account

When scrim runs in Kubernetes, the OpenBao adapter (`auth.method: kubernetes`) and the Infisical
adapter (`auth.method: kubernetes-auth`) SHALL log in with the service account token of scrim's own
pod, so that no static store credential exists in the cluster for scrim. A static credential (token,
role ID, secret ID, client ID or client secret) configured alongside one of these methods SHALL be
refused at validation. A refused login SHALL be reported as a permission error naming the store.

#### Scenario: No static store credential in the cluster

- **WHEN** scrim is deployed in a cluster with OpenBao Kubernetes auth bound to its service account
  name, namespace and audience
- **THEN** scrim reads and writes secrets with the token it obtains at login
- **AND** the scrim configuration and the cluster hold no OpenBao token, role ID or secret ID

#### Scenario: Static credential left in the configuration

- **WHEN** a store uses `auth.method: kubernetes` and the configuration also sets `secret-id`
- **THEN** validation fails naming the option, without echoing its value

#### Scenario: Wrong role

- **WHEN** the configured OpenBao role does not exist or is not bound to scrim's service account
- **THEN** the store reports a permission error naming the store
- **AND** no service account token or session token appears in the error

### Requirement: Service account token read at every login

The adapters SHALL read the configured service account token file again at every login, never only
at start-up, and SHALL hold its content only as a secret value that is wiped once the login request
is sent. Neither the service account token nor the session token a login issues SHALL appear in any
error, log, audit entry or test output.

#### Scenario: Rotated service account token

- **WHEN** the kubelet rotates the projected token in the token file and scrim next logs in
- **THEN** the login presents the new token, not the one read at start-up

#### Scenario: Unreadable token file

- **WHEN** the token file is missing or empty at login
- **THEN** the store reports a permission error naming the option and the file
- **AND** the store is not contacted

### Requirement: Store login tokens are renewed before they expire

The OpenBao adapter SHALL renew a renewable login token with renew-self at two thirds of its TTL,
and SHALL log in again instead when the token is not renewable, when renewal fails or is refused, or
when a renewal is capped by the max TTL. The Infisical adapter SHALL log in again before the access
token's `expiresIn` runs out. Both SHALL log in again once when the store refuses a token as expired
or revoked, and report a second refusal as a permission error.

#### Scenario: OpenBao token renewed

- **WHEN** two thirds of a renewable login token's TTL have passed
- **THEN** scrim renews the token with renew-self and keeps using it

#### Scenario: Renewal refused

- **WHEN** renew-self fails, or comes back capped by the token's max TTL and that lease is used up
- **THEN** scrim logs in again instead of renewing, with Kubernetes auth presenting a freshly read
  service account token

#### Scenario: Revoked token

- **WHEN** the store refuses scrim's session token on a read
- **THEN** scrim logs in once and retries the read
- **AND** a second refusal is reported as a permission error

### Requirement: OpenBao control groups for configured paths

The system SHALL support OpenBao control groups on configured paths: when a read or write is held by a
control group, scrim SHALL treat it as a pending approval, notify through its own notifiers, and
complete the operation only after the control group is authorised. A control group that expires SHALL
fail the operation closed.

#### Scenario: Read held by a control group

- **WHEN** a break-glass path requires a control-group approval
- **THEN** the operation waits, the approver is notified, and the value is used only after
  authorisation

### Requirement: Kubernetes Secrets adapter

The system SHALL read Secrets from a Kubernetes cluster, each data key a field, addressed as
`<instance>://<namespace>/<name>` or, for an instance confined to one namespace, `<instance>://<name>`,
with each dot of a Secret name written as `/`. It SHALL use only the namespaces the configuration
lists and SHALL refuse any other before calling the API server.

#### Scenario: Namespace outside the instance

- **WHEN** an instance lists `namespaces: [agents]` and a reference names `kube-system/token`
- **THEN** the read or write is refused with a permission error naming the reference, before any API
  call

### Requirement: Kubernetes cluster named explicitly

The Kubernetes adapter SHALL authenticate with the pod's service account, or with a kubeconfig file
and a context that are both named in the configuration. It SHALL NOT use `KUBECONFIG`,
`~/.kube/config` or a kubeconfig's current context.

#### Scenario: Kubeconfig context named explicitly

- **WHEN** an instance sets `auth.method: kubeconfig` and `auth.kubeconfig` without `auth.context`
- **THEN** configuration validation fails naming `auth.context`
- **AND** with a context named, scrim connects to that context's cluster even when the file's
  current context and `KUBECONFIG` point elsewhere

### Requirement: Kubernetes source read-only by default

The Kubernetes adapter SHALL be read-only unless the configuration sets `writable: true`. A read-only
instance SHALL NOT declare write and SHALL refuse a write before any API call.

#### Scenario: Read-only by default

- **WHEN** an agent writes `k8s://prod/new-token` and the instance does not set `writable: true`
- **THEN** the write is refused with an error saying the kubernetes source is read-only
- **AND** no request reaches the API server and the caller's value is not wiped

### Requirement: Kubernetes watch

The Kubernetes adapter SHALL watch through the API server's metadata-only watch, resuming from the
last resource version, and SHALL list again and report the difference when that version has expired
or the API server was unreachable.

#### Scenario: Watch survives an outage

- **WHEN** the API server becomes unreachable while a watch runs and comes back
- **THEN** a Secret created after it came back is reported as changed on the same watch

### Requirement: Kubernetes labels cannot be forged

The Kubernetes adapter SHALL label a Secret with `kubernetes.namespace`, `kubernetes.name` and
`kubernetes.type`, and SHALL file its labels and annotations as `kubernetes.meta.label.<key>` and
`kubernetes.meta.annotation.<key>`, never over a native key. Annotations whose key starts with
`scrim.` SHALL also be reported under their own key, and write labels SHALL be stored as such
annotations.

#### Scenario: Labels cannot forge native keys

- **WHEN** a Secret in namespace `dev` carries the label `kubernetes.namespace: prod`
- **THEN** its labels hold `kubernetes.namespace: dev` and
  `kubernetes.meta.label.kubernetes.namespace: prod`

### Requirement: Kubernetes labels hold no data

The Kubernetes adapter SHALL NOT read the `kubectl.kubernetes.io/last-applied-configuration`
annotation into a label. Its metadata lookups, list and watch SHALL use requests that return no
Secret data, and a metadata lookup SHALL report the labels a read reports.

#### Scenario: Applied data stays out of labels

- **WHEN** a Secret was created with `kubectl apply`, so its last-applied annotation holds its data
- **THEN** no label key or value contains that data
- **AND** a metadata lookup of the Secret returns the labels a read returns

### Requirement: Built-in store adapters

The system SHALL ship adapters for Vaultwarden, Infisical, OpenBao, HashiCorp Vault, AWS Secrets
Manager, AWS SSM Parameter Store, Google Secret Manager, Azure Key Vault, 1Password, Bitwarden Secrets
Manager, Doppler, Kubernetes Secrets, and the local sources env, file, SOPS-encrypted file and OS
keyring. Several instances of one adapter SHALL be configurable side by side under different names.

#### Scenario: Two Vault clusters and AWS at once

- **WHEN** configuration defines `vault-eu://`, `vault-us://` and `aws-sm://` store instances
- **THEN** references to each resolve against their own store with their own credentials

### Requirement: Adapters declare their capabilities

Every adapter SHALL declare which operations it supports (read, list, watch, write, generate, dynamic
credentials, glob listing). An operation the target store does not support SHALL be refused with an error naming
the store and the operation, before any partial write, and `scrim doctor` SHALL show the capability
matrix of every configured store.

#### Scenario: Write to a read-only source

- **WHEN** a rule targets `env://` for `secret_gen`
- **THEN** the call is refused with an error saying the env source is read-only
- **AND** nothing is generated or stored

### Requirement: HashiCorp Vault adapter

The Vault adapter SHALL support KV versions 1 and 2, namespaces, and the token, AppRole, Kubernetes,
JWT/OIDC and cloud IAM auth methods. Dynamic secrets SHALL be leased, renewed while in use, revoked
when the grant ends, and redacted from the moment they are issued.

#### Scenario: Dynamic database credential

- **WHEN** an agent is granted a credential from a Vault database secrets engine for 30 minutes
- **THEN** scrim obtains a lease, injects the credential toward its bound host and redacts it
- **AND** revokes the lease when the grant expires

### Requirement: Cloud secret managers use workload identity

The AWS, Google and Azure adapters SHALL authenticate with the platform's ambient identity
(instance or task roles, IRSA or EKS Pod Identity, GKE Workload Identity, Azure Workload Identity)
without static keys, and SHALL accept explicit credentials only by reference. Version and stage
selectors SHALL be supported in references.

#### Scenario: AWS Secrets Manager from an EKS pod

- **WHEN** scrim runs in EKS with a pod identity allowed to read `agents/*`
- **THEN** `aws-sm://agents/github#token` resolves without any access key in configuration

#### Scenario: Pinned version

- **WHEN** a reference names `aws-sm://agents/github?stage=AWSPREVIOUS`
- **THEN** the previous version is used and the current one is still redacted

### Requirement: Adapter conformance suite

Every adapter, built-in or plugin, SHALL pass one shared conformance suite covering read, list,
watch, write-only behaviour toward agents, outage handling and error messages without values. The
suite SHALL run in CI against each store or a compatible emulator.

#### Scenario: New adapter is added

- **WHEN** an adapter is contributed
- **THEN** it is accepted only with a passing conformance run recorded in CI

#### Scenario: Suite catches a broken adapter

- **WHEN** the conformance suite runs against an adapter that leaks a value into an error, ignores a
  field selector, reports a missing secret as an outage, or serves a cached copy during an outage
- **THEN** the case aimed at that fault fails

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

#### Scenario: Session token issued by the store

- **WHEN** scrim logs in to OpenBao with AppRole and receives a client token
- **THEN** that token is added to the redaction set like scrim's configured credentials

### Requirement: Store-native metadata labels

Each adapter SHALL describe where a secret lives in its store as labels without values: native
attributes under `<kind>.` (`vaultwarden.org`, `openbao.mount`), a multi-valued attribute as one
comma-joined key plus one presence key per value (`vaultwarden.collection.Prod`), and metadata store
users can edit under `<kind>.meta.<key>`. A native label SHALL always win over user-editable
metadata. The local stores SHALL report native labels too (`env.variable`, `file.path`).

#### Scenario: Secret in two collections

- **WHEN** a Vaultwarden item belongs to collections Prod and Shared
- **THEN** its labels hold `vaultwarden.collection=Prod,Shared`, `vaultwarden.collection.Prod=true` and `vaultwarden.collection.Shared=true`

#### Scenario: Custom field named like a native label

- **WHEN** a store user adds a custom field `vaultwarden.collection.Prod` to an item outside Prod
- **THEN** the item's labels hold `vaultwarden.meta.vaultwarden.collection.prod` and not `vaultwarden.collection.Prod`

### Requirement: Generic store labels

The system SHALL add the labels `store.name`, `store.kind`, `store.path`, `store.container` and
`store.field` to every secret of every store, SHALL replace any `store.*` label an adapter reports,
and SHALL drop labels an adapter reports under another adapter kind's prefix.

#### Scenario: Adapter reports a store label

- **WHEN** an adapter's metadata for a secret carries `store.kind=other`
- **THEN** the secret's labels hold the instance's real kind

### Requirement: Derived labels per store

A store instance's `labels` option SHALL derive labels from its native and generic labels: a copy
(`team: vaultwarden.org`), a constant (`{value: prod}`), a constant set when another label exists
(`{from, value}`), and a regular-expression match with submatch expansion (`{from, regex, value}`).
Derived labels SHALL never replace a native or `store.*` label, and a name under `store.`, `scrim.`
or an adapter kind's prefix SHALL be rejected when configuration loads.

#### Scenario: Team from the organisation

- **WHEN** a Vaultwarden store sets `labels: {team: vaultwarden.org}` and an item belongs to organisation Acme
- **THEN** the item's labels hold `team=Acme`

#### Scenario: Derived label claims a native name

- **WHEN** a store's `labels` option names a label `vaultwarden.org`
- **THEN** configuration validation fails naming `labels.vaultwarden.org`

### Requirement: Metadata without values

An adapter that can return a secret's metadata without its values SHALL offer it, and the system
SHALL use it to label a secret that is not in a redaction set. Where an adapter cannot, the system
SHALL read the secret and wipe every value before the lookup returns, and SHALL cache nothing beyond
what the refresher holds.

#### Scenario: Fallback read

- **WHEN** an adapter without a metadata read is asked for the labels of a secret outside every redaction set
- **THEN** the secret is read, every value read is wiped before the labels are used, and no value is kept

### Requirement: Labels of a new item

Before a secret exists, the system SHALL label a write or generate target with the generic `store.*`
labels derived from its reference, the store's derived labels, and any native labels its adapter can
tell from the reference alone.

#### Scenario: Write to a new path

- **WHEN** an agent writes `bao://kv/prod/app/token`, which does not exist yet
- **THEN** the policy request carries `store.container=kv/prod/app` and `store.kind=openbao`

### Requirement: Listing a secret's labels

`scrim catalog labels <name|reference>` SHALL print every label a secret has as rules see it, with
where each comes from (store, native, user, scrim, derived), reading the secret's metadata and never
its value; for a secret the store does not hold yet it SHALL print the labels a new item there would
get. `scrim catalog show <name>` SHALL print the entry with its secret's labels.

#### Scenario: Operator writes a rule

- **WHEN** an operator runs `scrim catalog labels github`
- **THEN** the labels of the secret `github` names are printed, and no value appears in the output

### Requirement: Optional secret catalog

The system SHALL support an optional catalog that maps logical secret names (for example `github`) to
a store reference, its bound hosts, its injection locations, its tool profiles and any user-declared
placeholder. Without a catalog, store references work directly; the catalog only adds names,
bindings and placeholders on top.

#### Scenario: Logical name used everywhere

- **WHEN** the catalog maps `github` to `bao://kv/agents/github#token` bound to `api.github.com`
- **THEN** rules, tool profiles, MCP tools and placeholders can all say `github` instead of the reference

#### Scenario: No catalog

- **WHEN** no catalog is configured and a file contains `{{scrim:bao://kv/agents/github#token}}`
- **THEN** the reference placeholder resolves without any mapping
- **AND** injection still requires a host binding from configuration or store metadata

### Requirement: Per-environment mapping

A catalog entry SHALL be able to resolve to different store references by environment, agent,
namespace or profile, so the same placeholder in the same file points at a development secret in one
session and a production secret in another. The selection SHALL be visible in `scrim catalog show`.

#### Scenario: Same placeholder, two environments

- **WHEN** `SCRIM_DB_PASSWORD` maps to `bao://kv/dev/db#password` for profile `dev` and to
  `aws-sm://prod/db#password` for profile `prod`
- **THEN** a session started with catalog profile `dev` (`--catalog-profile dev`) injects the development password and never the
  production one

#### Scenario: No mapping for the selected profile

- **WHEN** `SCRIM_DB_PASSWORD` maps references only for profiles `dev` and `prod` and has no default,
  and a session runs with profile `staging`
- **THEN** the placeholder is unresolved in that session and nothing is injected for it
- **AND** scrim does not fall back to either profile's reference

#### Scenario: Two variants match equally

- **WHEN** an entry has one variant for profile `prod` and another for namespace `build`, and a
  session has both
- **THEN** catalog validation fails for that session, naming the entry

### Requirement: Bulk mapping by prefix

A catalog entry SHALL be able to map every secret under a store prefix at once, deriving each
placeholder name from a template (for example `inf://acme/prod/*` to `SCRIM_ACME_{NAME}`), with
shared host bindings. Name collisions SHALL fail validation.

#### Scenario: Prefix mapping

- **WHEN** `inf://acme/prod/*` holds `API_KEY` and `WEBHOOK_SECRET` and is mapped with the template
  `SCRIM_ACME_{NAME}`
- **THEN** `SCRIM_ACME_API_KEY` and `SCRIM_ACME_WEBHOOK_SECRET` both resolve

### Requirement: Mapping from store metadata

Where a store supports metadata on secrets (tags, labels, custom metadata), the system SHALL read
configured keys such as `scrim.hosts`, `scrim.placeholder` and `scrim.profiles` and treat them as
catalog entries, so bindings can live next to the secret. Catalog file entries SHALL take precedence,
and conflicts SHALL be reported.

#### Scenario: Binding stored with the secret

- **WHEN** an OpenBao secret has custom metadata `scrim.hosts=api.github.com`
- **THEN** it is bound to `api.github.com` without a catalog file entry

#### Scenario: Metadata disagrees with the catalog file

- **WHEN** a catalog file binds a secret to `api.github.com` and the secret's metadata says
  `scrim.hosts=evil.example`
- **THEN** the catalog file's binding is used
- **AND** the disagreement is reported as a warning

### Requirement: Catalog sources

The catalog SHALL be loadable from the configuration file, separate catalog files, environment
variables and, in Kubernetes, from cluster resources, following the configuration precedence rules,
and SHALL be reloaded without restart. A catalog SHALL never contain secret values.

#### Scenario: Value in a catalog file

- **WHEN** a catalog entry contains something that looks like a literal secret instead of a reference
- **THEN** validation fails and the catalog is not loaded
- **AND** the error names the entry and field without quoting the literal

#### Scenario: Invalid catalog on reload

- **WHEN** a catalog file is edited while scrim runs and the new version fails validation
- **THEN** the previous catalog stays in effect and the rejection is logged

### Requirement: Catalog suggestions

`scrim catalog suggest` SHALL propose catalog entries from the project scan, configured tool profiles
and store contents (names only), for the user to accept or edit. Suggestions SHALL never be applied
automatically.

#### Scenario: Suggest from a project

- **WHEN** the user runs `scrim catalog suggest` in a project whose `.env` references three APIs
- **THEN** three draft entries with placeholder names, candidate references and hosts are printed
