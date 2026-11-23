# 1Password

The `onepassword` adapter reads, lists, watches and writes 1Password items through a
[1Password Connect](https://developer.1password.com/docs/connect/) server you run. scrim holds the
Connect token; agents never talk to Connect. They ask scrim, which enforces write-only toward agents
itself.

## Capabilities

| Kind          | read | list | watch | write | generate | dynamic |
|---------------|------|------|-------|-------|----------|---------|
| `onepassword` | yes  | yes  | yes   | yes   | no       | no      |

Watch polls the item listing; see [Watch](#watch). Listing accepts a trailing `*` (glob).

### Why Connect and not service accounts

1Password service accounts are reachable only through 1Password's SDKs. The Go SDK
(`github.com/1password/onepassword-sdk-go`, checked at v0.4.1) needs no CGO: it runs a WebAssembly
core on wazero. scrim does not use it because:

- it returns every secret value as a Go string, which cannot be wiped, where scrim keeps values in
  wiped memory from the HTTP body on;
- its core only talks to 1Password's own domains, hard-coded in the module, so it cannot be tested
  against a fake or an emulator, and there is no public test account;
- it embeds about 9 MB of WebAssembly for what amounts to a few REST calls.

Connect has a documented REST API that scrim talks to with a small client of its own. If you only
have service accounts today, run a Connect server next to scrim: it syncs the vaults you share with
it and serves them locally.

## References

```text
<scheme>://<vault>/<item>[#[<section>/]<field>]
```

This is the `op://<vault>/<item>/[<section>/]<field>` form of the 1Password CLI with the field moved
after `#`: `op://Prod/GitHub/API/token` is `op://Prod/GitHub#API/token` when the instance is named
`op`.

- `<vault>` is the vault name or its ID. A name is looked up with Connect's `name eq` filter and
  cached for `vault-cache-ttl`.
- `<item>` is the item title or its ID, and is everything after the vault: titles may contain `/`,
  so `op://Prod/agents/github` is the item titled `agents/github`. scrim treats `/` in titles as
  folders for listing and the `store.container` label.
- `#<field>` selects one field. Without it a read returns every field that has a value.
- Several items with the same title cannot be read by title: the read is refused as ambiguous and
  you use the item ID instead. Listing reports such items by ID.
- Connect serves only the current version of an item, so selectors such as `?version=` are refused.

### Field names

A field is named by its label, or `<section>/<label>` when it is in a section with a label. Fields
in the unnamed default section (the built-in username, password and notes, and custom fields added
without a section) are named by label alone, so a login item reads as `username`, `password`,
`notesPlain` and so on. A field without a label is named by its ID. When two fields of one item would
get the same name, each is named by its field ID, so a whole-item read never drops one.

A selector after `#` matches, in order: a field with exactly that name; for `<section>/<field>`, the
field whose section label or ID and whose label or ID match; otherwise any field whose label or ID is
the selector. More than one match is refused as ambiguous: name the section or use the field ID.
Fields without a value are not part of the secret and read as not found. One-time password fields
return their `otpauth://` URI; the current code Connect computes is never read. Files are not
supported.

A listing prefix is a vault, optionally followed by a title prefix: `op://Prod` lists the vault,
`op://Prod/agents` the items titled `agents` or `agents/...`, `op://Prod/agents*` every title that
starts with `agents`. Listing never asks Connect for a value.

## Setup

1. Deploy a Connect server and create an access token for scrim
   ([1Password docs](https://developer.1password.com/docs/connect/get-started/)). Give the token
   only the vaults scrim serves, read-only for vaults scrim only reads from, read and write for the
   vault scrim writes captured and generated secrets into.
2. Store the token where scrim reads credentials from: a file readable only by scrim, a systemd
   credential, a Kubernetes secret or an environment variable.
3. Keep Connect on a private network next to scrim, or behind TLS (`tls.ca-file` for a private CA).

## Configuration

```yaml
stores:
  op:
    kind: onepassword
    address: http://op-connect:8080
    token: file:/run/credentials/scrim/op-connect-token
    redact: [op://Prod/agents]
```

| Key | Environment variable (instance `op`) | Type | Default | Meaning |
| ----- | ---------------------------------------- | ------ | --------- | --------- |
| `stores.<name>.address` | `SCRIM_STORES_OP_ADDRESS` | URL | required | Base URL of the Connect server (without `/v1`). |
| `stores.<name>.token` | `SCRIM_STORES_OP_TOKEN` | secret reference | required | The Connect access token. Resolved at the first request, again after a 401 so a rotated token file is picked up, and added to the redaction set. |
| `stores.<name>.timeout` | `SCRIM_STORES_OP_TIMEOUT` | duration | `10s` | Per-request timeout. A timed-out request counts as the store being unavailable. |
| `stores.<name>.tls.ca-file` | `SCRIM_STORES_OP_TLS_CA_FILE` | path | system roots | PEM bundle to verify the server with. |
| `stores.<name>.watch.interval` | `SCRIM_STORES_OP_WATCH_INTERVAL` | duration | `30s` | How often the item listing is polled for changes, with +-20% jitter. |
| `stores.<name>.watch.max-backoff` | `SCRIM_STORES_OP_WATCH_MAX_BACKOFF` | duration | `5m` | Longest wait between polls while Connect keeps failing. |
| `stores.<name>.write.category` | `SCRIM_STORES_OP_WRITE_CATEGORY` | string | `API_CREDENTIAL` | Category of the items scrim creates, any Connect item category except `CUSTOM` and `DOCUMENT`. |
| `stores.<name>.vault-cache-ttl` | `SCRIM_STORES_OP_VAULT_CACHE_TTL` | duration | `5m` | How long a vault name's lookup is reused. |

## Writes

A write to an item that does not exist creates it in the vault, with `write.category`, the rest of
the path as its title, and every field `CONCEALED`. A field named `<section>/<field>` goes into that
section, created if needed. scrim never creates vaults.

A write to an existing item sets the named fields, keeping their type and purpose, and adds fields
that do not exist yet. Everything else on the item (other fields, sections, URLs, tags, files) is
sent back unchanged, so rotating a password keeps the username. Connect stores the result as a new
version.

- A create-only write is refused when an item with that title exists. The check is a lookup right
  before the create, so two writers racing on one new title can both create an item; reads of that
  title are then refused as ambiguous until one is removed.
- 1Password has no place for scrim's labels, so a write that carries labels is refused rather than
  dropping them.
- Values must be valid UTF-8; 1Password stores text only.

## Watch

Connect has no change feed. scrim polls the vault's item listing, which carries titles, versions and
update times but no fields, every `watch.interval`, and reports created, changed and deleted items.
While Connect is down, polls back off up to `watch.max-backoff`; the watch stays open and catches up
when Connect is back.

## Policy labels

Every label comes from the vault and the item listing, so a read, a listing and a metadata lookup
report the same labels and none of them needs a value from Connect.

| Label | Meaning |
| --- | --- |
| `onepassword.vault`, `onepassword.vault-id`, `onepassword.vault-type` | Vault name, ID and type (`USER_CREATED`, `PERSONAL`, ...). |
| `onepassword.item`, `onepassword.item-id` | Item title and ID. |
| `onepassword.category` | Item category (`LOGIN`, `API_CREDENTIAL`, ...). |
| `onepassword.tag`, `onepassword.tag.<tag>` | Tags, comma-joined, plus one presence key per tag and per parent of a nested tag (`team/payments` also sets `onepassword.tag.team`). |
| `onepassword.url-host`, `onepassword.url-host.<host>` | Host names of the item's URLs. |
| `onepassword.favorite` | `true` or `false`. |
| `onepassword.version` | Item version. |
| `onepassword.created`, `onepassword.updated` | Times, RFC 3339 UTC. |
| `onepassword.last-edited-by` | ID of the user who last edited the item. |

Tags are the only attribute an item editor picks freely, and they only ever land under
`onepassword.tag`. 1Password has no other user-defined item metadata, so the adapter sets no
`onepassword.meta.*` keys. Field values, notes, section and field contents and one-time codes are
never labels. Before an item exists, a `store.write` rule sees `onepassword.vault`, `onepassword.item`
and `onepassword.category` (the configured one) from the reference alone, plus the vault ID once
the vault has been looked up.

A rule that allows reads of production CI credentials only:

```cel
secret.labels["onepassword.vault"] == "Prod" && "onepassword.tag.ci" in secret.labels
```

## Errors

| Connect answer | scrim error |
| --- | --- |
| 401, 403 (bad token, vault not in the token's scope, read-only token) | permission denied |
| 404, or no item with that title | not found |
| several items with that title, several fields matching a selector | invalid reference |
| 429, 5xx, timeout, connection refused | store unavailable |

Connect's own message is kept, trimmed, unless it contains a value from the request.

## Testing and fidelity

The adapter passes the conformance suite against an in-process fake Connect server
(`internal/stores/onepassword/fake_test.go`) built from the Connect OpenAPI document (1.8.1) and the
item shapes in `testdata`. There is no Connect container to run without a real 1Password account, so
the fake has not been compared with a live server. It does not reproduce:

- Connect's exact 400 messages and validation rules, rate limits, and the delay while Connect syncs
  with 1Password.com;
- case or Unicode folding in `name eq` and `title eq` filters (the fake matches exactly; scrim also
  re-checks the exact name when Connect returns several);
- whether 1Password normalises stored values (whitespace, line endings) or coerces field types: the
  fake stores values byte for byte, so the value fidelity cases prove scrim's encoding, not
  1Password's storage;
- the template fields 1Password may add to a new item of a category;
- `PATCH`, files and the activity endpoint, which the adapter does not use.
