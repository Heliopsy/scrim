# Vaultwarden store

The `vaultwarden` adapter reads and writes secrets in [Vaultwarden](https://github.com/dani-garcia/vaultwarden)
and other Bitwarden-compatible servers. The server is zero-knowledge, so scrim decrypts and encrypts
items itself with the account's master password, which it reads from a reference at start.

## Use a dedicated account or organisation

Whatever account scrim logs in to, scrim can decrypt every item that account can see. Create a
Vaultwarden account for agents, or an organisation whose collections hold only agent secrets, and
give scrim that account. A compromised scrim then exposes the agent secrets and not your personal
vault (design D6).

If the account must hold other items, set `scope` to the folders or collections scrim may use.
Items outside the scope are invisible to every read, list and write. `scrim doctor` warns when no
scope is set, or when the account holds items outside it.

## Configuration

```yaml
stores:
  vw:
    kind: vaultwarden
    url: https://vault.example.com
    # API key login (preferred). Find it under Settings > Security > Keys > API key.
    client-id: user.4f0c1c2e-0000-0000-0000-000000000000
    client-secret: file:/run/credentials/scrim/vw-client-secret
    # The master password, always by reference, never inline.
    unlock: file:/run/credentials/scrim/vw-master-password
    scope: [Agents]
```

| Option | Default | Meaning |
| --- | --- | --- |
| `url` | required | Server base URL. Plain `http://` is refused except to a loopback address. |
| `client-id`, `client-secret` | | Personal API key. `client-secret` is a reference. Preferred over password login, and it works with two-factor authentication enabled. |
| `email` | | Account email. Without an API key, scrim logs in with the master password (no two-factor support). With an API key, scrim checks the account matches. |
| `unlock` | required | Reference to the master password: a file readable only by scrim (`file:`), the OS keyring, a systemd credential, a Kubernetes secret mounted as a file, or a store reference. A literal is refused. |
| `scope` | whole vault | Path prefixes scrim may use. |
| `poll-interval` | `30s` | How often watch checks the account revision date. |
| `timeout` | `30s` | Per-request timeout. |
| `device-id` | derived | Device identifier shown in the account's device list. By default it is derived from the instance name, URL and account, so restarts reuse one device. |
| `ca-file` | | Extra PEM roots for a server with a private CA. |
| `allow-insecure-http` | `false` | Allows plain `http://` to a non-loopback host. Tokens then cross the network in clear text. |

A `file:` unlock reference that is readable by group or others is refused and the store reports
itself as locked.

## Locked store

If the unlock reference is missing, empty, unreadable or does not decrypt the account key, the store
is **locked**: health reports it, and every operation that needs a value fails with `store locked`.
Nothing is injected from a locked store. scrim retries the unlock at most every five seconds.

## References

```text
vw://<folder or collection>/<item name>[?org=<organisation>][#<field>]
vw://<item name>#<field>                       item with no folder or collection
```

- `vw://Agents/GitHub#token` is the custom field `token` of the item `GitHub` in the folder or
  collection `Agents`.
- `?org=Acme` (organisation name or id) restricts the lookup to that organisation. A path that
  matches more than one item is refused as ambiguous; rename one item or add `?org=`.
- Folder and collection names are full names, so a nested folder `Agents/CI` is part of the path:
  `vw://Agents/CI/deploy-key`.
- Trashed items are ignored.

Field selectors:

| Selector | Item types | Source |
| --- | --- | --- |
| `username`, `password`, `totp` | login | the login fields (`totp` is the seed) |
| `notes` | all | the item notes |
| `private-key`, `public-key` | SSH key | the key fields |
| any other name | all | the custom field of that name (on login items, a custom field named like a built-in is shadowed) |

Without a selector, a read returns every field that has a value.

## Catalog labels

Custom fields whose names start with `scrim.` are catalog metadata, not values. They are returned
as labels and never loaded into the redaction set, so a binding can live with the item:

| Custom field | Example |
| --- | --- |
| `scrim.hosts` | `api.github.com,uploads.github.com` |
| `scrim.placeholder` | `SCRIM_GITHUB_TOKEN` |
| `scrim.profiles` | `dev,ci` |

Use text fields for labels; their values are visible to anyone reading the catalog.

## Writes

scrim creates and updates login items. On an existing item it replaces only the fields it was given
and keeps everything else (other fields, URIs, password history, attachments), so rotating a
password keeps the username. `username`, `password` and `totp` go to the login fields, `notes` to
the notes, any other name to a hidden custom field. Writes send the last revision date scrim saw, so
a concurrent edit in another client is refused instead of overwritten.

A new item without `?org=` goes into the personal vault, in the folder named by the path prefix,
which scrim creates if needed. With `?org=` it goes into the existing collection named by the
prefix; scrim does not create collections.

## Watch

The adapter checks the account revision date (one small request) every `poll-interval` and syncs
only when it changed. Every read also checks it, so a server outage is reported as `store
unavailable` instead of being hidden behind the last sync; the refresher then keeps redacting the
last known values.

## Cryptography

- KDF: PBKDF2-SHA256 or Argon2id, with the parameters the server reports, bounded to the ranges the
  official clients accept (a server asking for more is refused).
- The master key is stretched with HKDF-Expand-SHA256 (`enc`, `mac`) and decrypts the user key. The
  user key decrypts the RSA private key, which unwraps organisation keys (RSA-OAEP, types 3 and 4).
  Items with their own item key are supported.
- Symmetric data is accepted only as type 2 (AES-256-CBC with HMAC-SHA256). The MAC is verified in
  constant time before decryption. Unauthenticated legacy types 0 and 1 are refused; an account
  still using them must rotate its encryption key in a Bitwarden client.
- Primitives come from the Go standard library and `golang.org/x/crypto`.
- Values are decrypted only when read and returned in scrim's secret type; the adapter caches no
  values. The user and organisation keys stay in memory while the store is unlocked and are wiped on
  close. Go's `net/http` and `crypto/pbkdf2` take strings, so the bearer token and the password
  pass through short-lived copies that cannot be wiped; RSA private keys are parsed only while
  organisation keys are unwrapped.

## Testing

`go test ./internal/stores/vaultwarden/...` runs the shared conformance suite against a throwaway
Vaultwarden (`docker.io/vaultwarden/server:1.37.5`, override with `SCRIM_VW_IMAGE`) in rootless
podman, with accounts registered through the API using client-side key derivation (PBKDF2,
Argon2id, password login, an organisation, items with per-item keys). The container is named
`scrim-vw-<random>` and removed afterwards. Without podman, or with `-short` or
`SCRIM_TEST_PODMAN=0`, the run is skipped with a reason; `SCRIM_TEST_PODMAN=1` makes a failed image
pull an error. `SCRIM_TEST_BW_CLI=1` also checks that the official Bitwarden CLI (`bw`) decrypts
items scrim wrote.
