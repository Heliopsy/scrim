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
| `meta-labels` | `false` | Reports text custom fields as `vaultwarden.meta.<key>` labels (see [Meta labels](#meta-labels)). Weakens confidentiality if any text field holds a secret; `scrim doctor` warns while it is on. |

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

## Native labels

Besides the `scrim.*` labels, every item carries labels that describe where it lives and what it
is, read from the vault itself. Policy rules see them as `secret.labels`, so a rule can follow the
item's real organisation, collection or folder instead of the spelling of its reference: an item in
two collections matches a `Prod` rule whether an agent asks for `vw://Prod/DB` or `vw://Shared/DB`.

Native keys are reserved. They are computed from the sync data after everything else and replace
any label of the same name, so someone who can edit an item cannot forge `vaultwarden.org` with a
custom field. No label carries a secret value: hidden fields, passwords, TOTP seeds, notes, SSH and
card or identity data never become labels, and of the login URIs only the host names are kept.

| Key | Values | Meaning |
| --- | --- | --- |
| `vaultwarden.id` | id | Item id. |
| `vaultwarden.name` | text | Item name. |
| `vaultwarden.type` | `login`, `note`, `card`, `identity`, `ssh-key` | Item type. |
| `vaultwarden.owner` | `personal`, `org` | Personal vault or organisation. |
| `vaultwarden.org` | text | Organisation name (organisation items). |
| `vaultwarden.org.id` | id | Organisation id (organisation items). |
| `vaultwarden.org.role` | `owner`, `admin`, `manager`, `user`, `custom` | This account's role in the organisation. |
| `vaultwarden.collection` | names, comma-joined | Collections the item is in and this account can see. |
| `vaultwarden.collection.<name>` | `true` | One per collection, name verbatim, and per ancestor of a nested collection. |
| `vaultwarden.collection-id`, `vaultwarden.collection-id.<id>` | ids / `true` | Collection ids, same shape. |
| `vaultwarden.collection-read-only`, `.<name>` | names / `true` | Collections of the item that are read-only for this account. |
| `vaultwarden.collection-hide-passwords`, `.<name>` | names / `true` | Collections of the item where passwords are hidden from this account. |
| `vaultwarden.collection-manage`, `.<name>` | names / `true` | Collections of the item this account manages (servers that report it). |
| `vaultwarden.folder` | text | Full folder name, for example `Agents/CI` (personal folders only). |
| `vaultwarden.folder.<name>` | `true` | The folder and each ancestor, verbatim: `Agents` and `Agents/CI`. |
| `vaultwarden.folder-id` | id | Folder id. |
| `vaultwarden.uri-host`, `vaultwarden.uri-host.<host>` | hosts / `true` | Host names of the login URIs, lowercased, without ports, paths, queries or user info. URIs matched as regular expressions are skipped. |
| `vaultwarden.has-username`, `has-password`, `has-totp`, `has-passkey` | `true`, `false` | Whether a login item has the field (never its value). Login items only. |
| `vaultwarden.has-notes`, `has-attachments` | `true`, `false` | Whether the item has notes or attachments. |
| `vaultwarden.favorite` | `true`, `false` | Marked as favorite by this account. |
| `vaultwarden.reprompt` | `true`, `false` | Master password re-prompt is on. |
| `vaultwarden.item-key` | `true`, `false` | The item is encrypted with its own item key. |
| `vaultwarden.edit`, `vaultwarden.view-password` | `true`, `false` | This account may edit the item / see its password (when the server reports it). |
| `vaultwarden.revision-date`, `creation-date`, `password-revision-date` | RFC 3339 | As reported by the server. |
| `vaultwarden.meta.<key>` | text | Only with `meta-labels: true`: a text custom field that is not a `scrim.*` label (see [Meta labels](#meta-labels)). |

Keys that are absent have no value: a personal item has no `vaultwarden.org`, an item outside any
folder no `vaultwarden.folder`. Trashed items are invisible to scrim, so there is no trash label.

### Key names

The shape is the one every scrim store adapter uses for native labels. A presence key carries the
value verbatim after the attribute (`vaultwarden.collection.Shared/Team A`), so matching is exact
and case-sensitive; CEL string keys may hold spaces, slashes and any other character. A nested
folder or collection also gets a presence key for each ancestor. The comma-joined value lists the
item's own folder or collections, verbatim and sorted; a name that itself contains a comma makes
that value ambiguous, so match on the presence keys or on ids.

`vaultwarden.meta.<key>` folds the field name: ASCII letters are lowercased, ASCII letters, digits,
`-` and `_` are kept, dots separate segments (empty ones are dropped), and every other character
becomes `_`. Two fields that fold to the same key keep the first one.

| Name | Keys |
| --- | --- |
| collection `Prod` | `vaultwarden.collection.Prod` |
| collection `Shared/Team A` | `vaultwarden.collection.Shared`, `vaultwarden.collection.Shared/Team A` |
| folder `Agents/CI` | `vaultwarden.folder.Agents`, `vaultwarden.folder.Agents/CI` |
| text field `Owner Team` | `vaultwarden.meta.owner_team` |
| text field `vaultwarden.org` | `vaultwarden.meta.vaultwarden.org` (never `vaultwarden.org`) |

### Meta labels

Text custom fields are often used for things a policy wants to match (an environment, an owning
team), but just as often for tokens. Labels show up in policy views and audit entries, so scrim
reports text fields only when the store sets `meta-labels: true`, and `scrim doctor` warns for as
long as it is on.

When it is on, a text custom field that is not a `scrim.*` label becomes `vaultwarden.meta.<key>`
(at most 256 bytes; the first field of a key wins). Hidden, boolean and linked fields are never
reported. As a second guard, scrim decrypts the secret values of every item of the account
(passwords, usernames, TOTP seeds, notes, SSH keys and hidden custom fields, in or outside the
scope) after each sync and drops any meta label whose value equals or contains one of them; values
are compared one at a time and wiped. If any of those values fails to decrypt, no meta labels are
reported at all. The guard catches a secret copied into a text field next to its hidden original;
a secret that lives only in a text field is still reported, so keep secrets in hidden fields.

### Example policy

```yaml
rules:
  # Anything in the Prod collection, the Agents folder tree or organisation Acme asks first.
  - name: vw-prod-ask
    decision: ask
    when: >-
      "vaultwarden.collection.Prod" in secret.labels ||
      "vaultwarden.folder.Agents" in secret.labels ||
      ("vaultwarden.org" in secret.labels && secret.labels["vaultwarden.org"] == "Acme")
  # Any write into an organisation asks, wherever the reference points.
  - name: vw-org-write-ask
    decision: ask
    when: op == "store.write" && "vaultwarden.org.id" in secret.labels
  # Items with master password re-prompt are never used without a human.
  - name: vw-reprompt
    decision: ask
    when: '"vaultwarden.reprompt" in secret.labels && secret.labels["vaultwarden.reprompt"] == "true"'
```

Guard optional keys with `in` or `has()`: a rule that reads a missing label fails, and a failing ask
or deny rule counts as matching (see the policy guide).

For a write, the labels are those of the item being updated, or, for a new item, those it will get:
the organisation from `?org=`, the collection (with `?org=`) or the folder (without) from the path
prefix. A `store.write` rule therefore sees `vaultwarden.collection.Prod` for
`vw://Prod/New?org=Acme` before the item exists.

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
`scrim-vw-<random>` (`SCRIM_VW_CONTAINER_PREFIX` changes the prefix) and removed afterwards.
Without podman, or with `-short` or `SCRIM_TEST_PODMAN=0`, the run is skipped with a reason;
`SCRIM_TEST_PODMAN=1` makes a failed image pull an error. `SCRIM_TEST_BW_CLI=1` also checks that
the official Bitwarden CLI (`bw`) decrypts items scrim wrote.
