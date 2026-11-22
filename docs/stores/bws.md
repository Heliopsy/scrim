# Bitwarden Secrets Manager

The `bws` adapter reads, lists, watches and writes secrets in Bitwarden Secrets Manager, on
Bitwarden's US or EU cloud or a self-hosted Bitwarden server. scrim logs in as a machine account with
its access token and is the only holder of that token. Agents never call Bitwarden: they ask scrim,
which enforces write-only toward agents itself.

This is Secrets Manager, Bitwarden's product for machine secrets. For items in a Bitwarden or
Vaultwarden password vault, use the [Vaultwarden](vaultwarden.md) adapter.

## Capabilities

| Kind  | read | list | watch | write | generate | dynamic |
|-------|------|------|-------|-------|----------|---------|
| `bws` | yes  | yes  | yes   | yes   | no       | no      |

Listing accepts globs (`APP_*`). Watch polls; see [Watch](#watch).

## References

```text
<scheme>://<project>/<key>[#value|#note]
<scheme>://<secret-id>[#value|#note]
```

- `<scheme>` is the store instance name (or one of its aliases), for example `bws://`.
- `<project>` is the project name as shown in the web app, or the project ID.
- `<key>` is the secret's key, as written. A key may contain `/`: everything after the project is
  the key, so `bws://prod/db/PASSWORD` is key `db/PASSWORD` in project `prod`.
- `<secret-id>` addresses one secret by its ID, whatever its key or project. Use it for a secret in
  no project, for one whose key is shared, or for a key that contains `#` or `?`.
- A secret's value is the field `value`, and a read without a field returns only that. Its note is
  the field `note`: it is free text that may hold anything, so it is never loaded unless a reference
  asks for `#note` and it never becomes a label. Any other field reads as not found.
- Secrets Manager keeps no versions a machine account can read, so selectors (`?version=`) are
  refused rather than ignored.

### Names Secrets Manager does not keep unique

Secrets Manager allows two secrets with the same key, even in one project, and two projects with the
same name. scrim never guesses between them:

- A read, write or label lookup through a key or project name that matches more than one secret or
  project fails as an invalid reference. The error names the IDs to use instead, for example
  `2 secrets in project 8f0d... share this key; address one by ID (1c7e..., 9a42...)`.
- A listing returns the secrets that share a key by ID (`bws://1c7e...`) and all others by key, so a
  redact target still loads every value. A listing through an ambiguous project name returns nothing;
  list it by ID.

### Listing

A listing prefix starts with a project and may add a key prefix:

| Prefix | Lists |
| --- | --- |
| `bws://prod` or `bws://prod/*` | every secret in project `prod` |
| `bws://prod/db` | key `db` and every key under `db/` |
| `bws://prod/APP_*` | every key starting with `APP_` |
| `bws://<secret-id>` | that one secret |

A glob in the project part is refused. Listing never fetches a value: it reads the organisation's
secret identifiers (IDs, encrypted keys, projects and revision dates) and decrypts only the key and
project names.

## Setup

1. In the Secrets Manager web app, open **Machine accounts** and create one, for example `scrim`.
2. Under **Projects**, give it access to each project scrim should serve: **Can read** for projects
   scrim only reads from (redaction and injection), **Can read, write** for a project scrim writes
   captured and generated secrets into.
3. Under **Access tokens**, create a token. Store it where scrim reads credentials from: a file
   readable only by scrim, a systemd credential, a Kubernetes secret or an environment variable.

### Least privilege

The machine account sees exactly the projects and secrets it was granted, and Bitwarden enforces
read and write separately. Lay projects out so that a project scrim reads from is **Can read** only,
and point rules' default write target at one dedicated **Can read, write** project, for example
`bws://agents-inbox/`. A write into a read-only project is refused by Bitwarden as well as by scrim.
scrim creates secrets only inside a project, never unassigned ones, and never creates, renames or
deletes projects.

## Configuration

Each instance is configured under `stores.<instance>`. The generic keys every store takes (`kind`,
`aliases`, `redact`, `refresh.*`, `labels`) are handled by scrim; the keys below are the adapter's
own. Every key can also be set as an environment variable: `SCRIM_` followed by the full key
upper-cased, with dots and dashes as `_`. Unknown keys fail validation and name the closest known key.

```yaml
stores:
  bws:
    kind: bws
    token: file:/run/credentials/scrim/bws-access-token
    redact: [bws://prod]
```

| Key | Environment variable (instance `bws`) | Type | Default | Meaning |
| ----- | ---------------------------------------- | ------ | --------- | --------- |
| `stores.<name>.token` | `SCRIM_STORES_BWS_TOKEN` | secret reference | required | The machine account access token (`0.<id>.<secret>:<key>`). `file:`, `env:`, a systemd credential or a store reference. It is resolved at the first login, not at start-up validation. |
| `stores.<name>.api-url` | `SCRIM_STORES_BWS_API_URL` | URL | `https://api.bitwarden.com` | API service. The EU cloud is `https://api.bitwarden.eu`. |
| `stores.<name>.identity-url` | `SCRIM_STORES_BWS_IDENTITY_URL` | URL | `https://identity.bitwarden.com` | Identity service. The EU cloud is `https://identity.bitwarden.eu`. |
| `stores.<name>.server-url` | `SCRIM_STORES_BWS_SERVER_URL` | URL | none | Self-hosted shorthand, as the `bws` CLI's `--server-url`: the API at `<server-url>/api` and identity at `<server-url>/identity`. Cannot be combined with `api-url` or `identity-url`. |
| `stores.<name>.timeout` | `SCRIM_STORES_BWS_TIMEOUT` | duration | `10s` | Per-request timeout. A timed-out request counts as the store being unavailable. |
| `stores.<name>.tls.ca-file` | `SCRIM_STORES_BWS_TLS_CA_FILE` | path | system roots | PEM bundle to verify a self-hosted server with. |
| `stores.<name>.watch.interval` | `SCRIM_STORES_BWS_WATCH_INTERVAL` | duration | `30s` | How often the identifier list is polled for changes, with +-20% jitter. |
| `stores.<name>.watch.max-backoff` | `SCRIM_STORES_BWS_WATCH_MAX_BACKOFF` | duration | `5m` | Longest wait between polls while Bitwarden keeps failing. |

scrim logs in when it first needs to, and again a little before the bearer token expires or when the
API answers 401. The access token, its client secret and key parts on their own, and the current
bearer token are added to the redaction set. No error quotes any of them.

## Policy labels

Every secret the adapter reads or lists carries these labels, which rules match as `secret.labels`
([policy.md](../policy.md#labels-from-stores)):

| Key | Example | Meaning |
| --- | --- | --- |
| `bws.org` | `f4e44a7f-...` | Organization ID. |
| `bws.id` | `1c7e...` | Secret ID. |
| `bws.key` | `db/PASSWORD` | Secret key, as written. |
| `bws.project` | `prod` | Project name, comma-joined if there are several. |
| `bws.project.<name>` | `bws.project.prod` = `true` | One per project. |
| `bws.project-id`, `bws.project-id.<id>` | | The same by project ID. |
| `bws.created`, `bws.updated` | `2026-03-01T09:12:44.1234567Z` | Creation and revision dates (UTC). |

Bitwarden currently allows one project per secret, but the API returns a list, so `bws.project` is
declared multi-valued and always has its presence key. Secrets Manager has no user-editable metadata
other than the note, which may hold a secret, so there are no `bws.meta.*` labels and nobody can
forge a `bws.*` label by editing a secret.

A write is decided on labels known before the secret exists: `bws://prod/db/NEW` gets
`bws.project = prod`, `bws.project.prod = true` and `bws.key = db/NEW`; a project written as an ID
gets `bws.project-id` instead, and `bws://<secret-id>` gets `bws.id`.

Labels of an existing secret that is in no redaction set (for a write to it) are read from the
identifier list without fetching the value. They are the labels a read reports.

### Example rules

Anything in project `prod` needs a human, for reads, writes and injection alike; everything else in
the store is allowed:

<!-- policy-example -->
```yaml
default: deny
rules:
  - name: bws-prod
    decision: ask
    reason: secrets in the prod project need a human
    when: >-
      op in ["store.read", "store.write", "inject"] && secret.store == "bws" &&
      "bws.project.prod" in secret.labels
  - name: bws-rest
    decision: allow
    when: op in ["store.read", "store.write"] && secret.store == "bws"
```

More patterns:

```cel
secret.labels["bws.key"].startsWith("db/")                         // keys under db/
"bws.project-id.8f0d2c6e-5a7b-4c1d-9e3f-2a1b0c9d8e7f" in secret.labels  // a project by ID
timestamp(secret.labels["bws.updated"]) < now - duration("2160h")  // not rotated in 90 days
```

## Writes

The value, and a note if the write gives a `note` field, are encrypted with the organization key
before they leave scrim. Bitwarden only ever receives ciphertext, as with its own clients.

- A write to an existing secret replaces its value and keeps its key, project and note (sent back as
  the ciphertext it already has, never decrypted), unless the write gives a note.
- A write to a new key creates it in the project the reference names, with an empty note unless one
  is given. The project must exist and the machine account must be able to write to it; Bitwarden
  answers a refused write with "not found", which scrim reports as permission denied.
- `create-only` writes fail with a conflict if the secret exists.
- Values Bitwarden's own clients would reject are refused before anything is sent: an empty value,
  invalid UTF-8, more than 25 000 characters, or a value whose ciphertext exceeds the server's
  35 000-character limit. A key that is empty, longer than 500 characters, or starts or ends with
  whitespace (which Bitwarden clients trim) is refused as an invalid reference.

Writes from one scrim are serialised. Secrets Manager does not keep keys unique, so two writers
elsewhere (another scrim replica, a person in the web app) creating the same new key at the same
moment can leave two secrets with that key; scrim then refuses the name as ambiguous until one is
removed.

## Watch

Secrets Manager has no change feed for machine accounts, so the adapter polls the secret identifier
list every `watch.interval` and reports a secret as changed when its revision date or ID changes, and
as deleted when it disappears. The list holds no values. The sync endpoint
(`/organizations/<id>/secrets/sync`) is not used: whenever anything changed it returns every secret
with its encrypted value, and it does not report deletions.

## Cryptography

The official Go SDK (`github.com/bitwarden/sdk-go`) wraps the Rust SDK through cgo and prebuilt
static libraries, which scrim's `CGO_ENABLED=0` builds cannot link, and passes values as Go
strings. The adapter implements the protocol in Go instead:

1. The access token `0.<id>.<client secret>:<base64 key>` is parsed as in the SDK's
   `AccessToken::from_str`. Its 16-byte key is stretched with `derive_shareable_key`: HMAC-SHA256
   keyed with `bitwarden-accesstoken` over the key, then HKDF-SHA256 expand with info
   `sm-access-token` to a 64-byte AES-256-CBC-HMAC-SHA256 key.
2. The login (`POST <identity>/connect/token`, `grant_type=client_credentials`, `scope=api.secrets`)
   returns a bearer token and an `encrypted_payload`, which that key decrypts to
   `{"encryptionKey": "<organization key>"}`. The organization ID is the bearer token's
   `organization` claim.
3. Keys, values, notes and project names are type 2 encrypted strings under the organization key,
   handled by the same `bwcrypto` package as the Vaultwarden adapter: the MAC is verified before
   anything is decrypted, and only authenticated types are accepted.

Known-answer tests pin each step to vectors from the official SDK's own tests and to the login
response and ciphertexts recorded in its fake server (`internal/stores/bws/crypto_test.go`).

## Errors

| Situation | Error kind |
| --- | --- |
| Access token malformed, revoked or for another product | permission denied (at the first use, naming the option) |
| Project or key not found, or not visible to the machine account | not found |
| Write to a project the machine account may only read | permission denied |
| Key or project name shared by several, or a bad reference | invalid reference, naming the IDs |
| Value Bitwarden clients cannot store | unsupported |
| Bitwarden unreachable, 5xx, rate limited, or a ciphertext that does not verify | unavailable |

## Limitations

- The bearer token goes into an HTTP `Authorization` header, which Go's HTTP client takes as a
  string. That string lives only for the request but cannot be wiped like scrim's own value type.
  Values never become strings: they are decrypted straight into scrim's secret type.
- Each read lists the organization's projects and secret identifiers to resolve the name, then
  fetches the one secret. A store with thousands of secrets and many redact targets makes many such
  calls per refresh; prefer one project-wide redact target to many single references.
- Secrets in no project are reachable by ID only and never listed.
- Organization keys other than 64-byte AES-256-CBC-HMAC-SHA256 keys are refused.
- Secret versions, the trash and project management are not used. Per-agent store identity is not
  implemented: a store configured for it refuses every use.

## Testing

There is no Secrets Manager emulator to run in podman (Vaultwarden does not implement it) and no test
account in CI, so the conformance suite runs against an in-process fake in
`internal/stores/bws/fake_test.go`, with every other test of the package:

```sh
go test -race ./internal/stores/bws/
```

The fake serves the official SDK's recorded login response and ciphertexts, so a login really derives
the access token key and decrypts the organization key, and it stores only the ciphertext scrim
sends. Its request and response shapes, the 404 for a refused authorisation, the one-project limit,
the ciphertext length limits and the update rule that keeps an unchanged project out of the answer
come from Bitwarden's server source. It does not reproduce rate limits, event logs, access policies
on single secrets, secret versions or the server's exact validation messages.
