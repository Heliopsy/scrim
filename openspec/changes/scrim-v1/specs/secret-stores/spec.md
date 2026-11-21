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

### Requirement: OpenBao adapter

The system SHALL read and write OpenBao (and Vault-compatible) KV version 2 secrets, authenticating
with AppRole or Kubernetes auth, and SHALL support write paths where scrim's own token has create,
update and patch without read.

#### Scenario: Write-only path

- **WHEN** scrim's token can create but not read under `kv/agents/inbox/`
- **THEN** a secret captured into that path is stored
- **AND** scrim reports it as write-only and does not try to load it into the redaction set from the
  store, keeping only the value it just wrote

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
