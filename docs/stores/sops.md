# SOPS-encrypted files

A read-only store adapter for secrets kept in [SOPS](https://getsops.io) files, the encrypted YAML,
JSON, dotenv and INI files many teams commit next to their code. scrim decrypts them with an age key
you give it, loads the values into the redaction set and can inject them toward bound hosts like any
other store's. scrim never writes to these files.

## Capabilities

<!-- BEGIN GENERATED STORE CAPABILITIES kinds=sops -->

| Kind | read | list | watch | write | glob | dynamic | per-agent check | `identity.store-login` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `sops` | yes | yes | yes | no | yes | no | no | none |

The columns are explained under [Capabilities](README.md#capabilities).

<!-- END GENERATED STORE CAPABILITIES -->

A write or generate targeting the source is refused before anything is touched, with an error such
as `store team: write team://app/new.yaml: operation not supported by this store: store team is
read-only`. Edit the files with `sops` itself and let scrim pick up the change, or pick a writable
store as the default target of rules that capture or generate secrets.

## Configuration

```yaml
stores:
  team:
    kind: sops
    root: /srv/app/secrets
    age-identity: file:/run/credentials/scrim/age-key.txt
    format: auto
    max-size: 1MiB
    watch:
      interval: 10s
    redact:
      - team://prod/*
```

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `stores.<name>.kind` | string | | `sops` |
| `stores.<name>.root` | path | required | Absolute directory every reference resolves under. Opened at start-up; a missing root stops start-up. |
| `stores.<name>.age-identity` | reference | required | The age identities that decrypt the files, in age's identity file format (one `AGE-SECRET-KEY-1...` per line, `#` comments allowed): `file:/path`, `env:NAME`, `cred:NAME` or a reference into another store. |
| `stores.<name>.format` | string | `auto` | `auto`, `yaml`, `json`, `dotenv` or `ini`. |
| `stores.<name>.max-size` | size | `1MiB` | Larger files are refused. Accepts bytes or `KiB`, `MiB`, `GiB`, `KB`, `MB`, `GB`. |
| `stores.<name>.watch.interval` | duration | `10s` | How often watched files are checked. Each poll is offset by up to 10% of random jitter. |

Every key can also be set from the environment, `SCRIM_` followed by the full key upper-cased with
dots and dashes as `_` (`stores.team.age-identity` is `SCRIM_STORES_TEAM_AGE_IDENTITY`). Unknown
keys fail validation and name the closest known key.

## Key handling

- scrim uses only the identity `age-identity` names. It never reads `SOPS_AGE_KEY`,
  `SOPS_AGE_KEY_FILE`, `~/.config/sops/age/keys.txt` or SSH keys on its own. To use one of those,
  point `age-identity` at it explicitly (`file:/home/scrim/.config/sops/age/keys.txt`,
  `env:SOPS_AGE_KEY`).
- `age-identity` is a credential field: it is resolved when the store is first used, masked in
  `scrim config show`, and a literal key in the config file is warned about. An identity that
  cannot be resolved or does not parse reports the store as `locked` (`scrim doctor`, `/readyz`),
  and nothing is decrypted.
- The resolved identity is wiped once parsed. scrim keeps each `AGE-SECRET-KEY-` line in memory,
  wiped when the store closes, and adds it to the redaction set, so an agent that finds the key
  cannot send it to a model provider. The age library keeps its own parsed copy of the key for as
  long as the store is open.
- Give scrim a key of its own: add its recipient (`age-keygen -y key.txt`) to the files' recipients
  in `.sops.yaml` and run `sops updatekeys`, rather than sharing a person's key.

<!-- docs-test: skip: needs the sops and age binaries -->
```sh
age-keygen -o /run/credentials/scrim/age-key.txt
sops updatekeys --yes prod/app.yaml
```

Only age recipients are supported. A file encrypted only to PGP, a cloud KMS or Vault transit keys,
or split into several key groups with Shamir secret sharing, is refused as unsupported; add an age
recipient to it.

## Formats

The format comes from the file name under `auto`: `.yaml` and `.yml` are YAML, `.json` is JSON,
names ending in `.env` or starting with `.env` are dotenv, `.ini` is INI, and anything else is read
as JSON, which is how sops stores binary files (`sops encrypt cert.pem` writes a JSON document whose
one key, `data`, holds the file). Set `format` when every file under `root` has one format whatever
its name.

The files must be as sops wrote them. scrim implements SOPS decryption itself, compatible with
sops 3: it opens the data key with age, decrypts every value with AES-256-GCM bound to its key path,
and recomputes the file's MAC over every value. A file whose MAC does not match, or whose values were
moved, edited, added or removed by anything but sops, is refused with a permission error, and none
of its values is returned. The encryption rules sops records in the file (`unencrypted_suffix`,
`encrypted_suffix`, `unencrypted_regex`, `encrypted_regex`, `mac_only_encrypted`) are honoured.

Not supported: `encrypted_comment_regex` and `unencrypted_comment_regex`, YAML files with several
documents, and INI values in triple quotes or backquotes. Such files are refused as unsupported.

## References and key paths

References: `team://<path under root>[#key-path]`, for example `team://prod/app.yaml` (every value
in the file) or `team://prod/app.yaml#db/password` (one). Paths are always relative to `root`. A
reference with a `..` segment or an absolute path is rejected as invalid, and a symlink that
resolves outside `root` is refused as a permission error. Version selectors are refused.

A field is the key path of an encrypted value in the decrypted document:

- Map keys and list positions joined by `/`: `db/password`, `servers/0/token`, `servers/1`.
  List positions count from 0 as the decrypted file shows them (sops keeps comments inside lists
  as hidden items; they are not counted).
- A key that contains `/` or `~` is escaped as in JSON Pointer (RFC 6901): `~` as `~0`, `/` as `~1`.
  The key `api.example.com/v1` is the field `api.example.com~1v1`; dots need no escaping.
- dotenv files have one level: `team://prod/.env#DATABASE_PASSWORD`.
- INI fields are `section/key`: `team://prod/app.ini#database/password`. Keys before the first
  section are in the `DEFAULT` section (`DEFAULT/key`).
- Numbers and booleans sops encrypted are returned as the decrypted document shows them (`5432`,
  `1.5`, `true`).
- Values sops left unencrypted (keys ending in `_unencrypted` by default, or outside an
  `encrypted_regex`) are covered by the MAC but are not fields: they are not secrets, and reading
  one is not found. Empty strings and `null` are not fields either.

## Listing and watch

Listing walks the prefix directory recursively and returns every SOPS file, with its field names and
labels read from the file's plaintext metadata: nothing is decrypted to list. Files that parse but
carry no `sops` metadata (`.sops.yaml`, a plain README) are left out; a file that does not parse is
listed, so reading it reports the error. A listed secret's version is its modification time and
size.

A trailing `*` right after part of a name is a glob over paths under `root`, as in the
[file source](local.md#file): `team://prod/app-*` covers `prod/app-db.yaml` and
`prod/app-cache/token.json`.

Watch polls (see `watch.interval`). It reports a file as changed when its size, modification time
or content changes, and as deleted when it disappears. Content is compared through a keyed digest of
the encrypted file held only in memory, with a random key per process; the digest is never shown or
stored. A poll that fails reports nothing and keeps the previous state.

## Labels

Every SOPS secret carries native labels for policy rules (see [labels](README.md#labels)), all taken
from the file's plaintext metadata, never from a value:

| Key | Meaning |
| --- | --- |
| `sops.root` | The configured root. |
| `sops.path` | Absolute path of the file. |
| `sops.format` | `yaml`, `json`, `dotenv` or `ini`. |
| `sops.version` | sops version that last wrote the file. |
| `sops.lastmodified` | When sops last wrote the file (RFC 3339). |
| `sops.key-type` | Kinds of master keys in the file: `age`, `pgp`, `kms`, `gcp-kms`, `azure-kv`, `hc-vault`, `hckms` (multi-valued). |
| `sops.age-recipient` | age recipients (multi-valued: `"sops.age-recipient.age1..." in secret.labels`). |
| `sops.pgp-fingerprint` | PGP fingerprints (multi-valued). |
| `sops.mac-only-encrypted` | `true` when the MAC covers only encrypted values. |
| `sops.unencrypted-suffix`, `sops.encrypted-suffix`, `sops.unencrypted-regex`, `sops.encrypted-regex` | The file's encryption rule. |
| `sops.key-groups`, `sops.shamir-threshold` | Set for files split into several key groups. |

```yaml
rules:
  # Secrets from production SOPS files, or files a given key can open, must be approved.
  - name: prod-sops-asks
    decision: ask
    when: >-
      secret.store == "team" && (
        secret.labels["sops.path"].startsWith("/srv/app/secrets/prod/") ||
        "sops.age-recipient.age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq" in secret.labels)
```

## Least privilege

- Run scrim as its own user with its own age key, readable only by that user (mode `0600`), for
  example as a systemd credential (`cred:age-key`).
- Point `root` at the directory that holds the SOPS files, not at a whole repository checkout: every
  file under it can be listed by name.
- Agents never read these values back through scrim. They see references, key paths and labels only.

## Limitations

- Read-only. Edit with `sops`; scrim notices on the next poll or refresh.
- Files are read whole into memory (up to `max-size`). The file buffer and the decrypted values are
  wiped once the fields are copied out. Encrypted floats and timestamps are re-formatted through a
  short-lived Go string to verify the MAC, and the unencrypted parts of a file pass through the YAML,
  JSON or INI parser as strings.
- The previous value of a rotated secret is kept only through scrim's own retention of old values in
  the redaction set.
