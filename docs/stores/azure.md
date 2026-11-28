# Azure Key Vault

The `azkv` adapter reads, lists, watches and writes secrets in an Azure Key Vault. scrim
authenticates with its platform identity (workload identity on AKS, a managed identity on a VM, App
Service or Container Apps) or with a service principal's client secret or certificate, and is the
only holder of that identity. Agents never call Key Vault: they ask scrim, which enforces write-only
toward agents itself, so one identity with the **Key Vault Secrets Officer** role is enough.

Managed HSM pools hold keys, not secrets, and are out of scope. Certificates are reachable only
through the secret Key Vault keeps for each certificate, read-only, labelled `azkv.managed=true`.

## Capabilities

<!-- BEGIN GENERATED STORE CAPABILITIES kinds=azkv -->

| Kind | read | list | watch | write | glob | dynamic | per-agent check | `identity.store-login` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `azkv` | yes | yes | yes | yes, not with `read-only: true` | yes | no | yes | `azure-federated` |

The columns are explained under [Capabilities](README.md#capabilities).

<!-- END GENERATED STORE CAPABILITIES -->

Watch polls; see [Watch and refresh](#watch-and-refresh). Listing also takes globs (`kv://APP-*`).
With `read-only: true` the store declares no write.

An agent's own Entra ID identity, from `azure-federated` token exchange or a static access token
per agent, is checked before an injection or restore by reading the secret as that identity, with
the value wiped ([Agent identity](../identity.md#store-identity-per-agent)).

## References

```text
<scheme>://<path>[?version=<id>][#<field>]
```

- `<scheme>` is the store instance name (or one of its aliases), for example `kv://`.
- The path's segments joined with the path separator (`--` by default) are the secret's name in
  the vault: `kv://agents/github` is the secret `agents--github`, and `kv://github-token` the
  secret `github-token`. Key Vault names hold only letters, digits and `-`, up to 127 characters, so
  a segment holding anything else, the separator itself, or starting or ending with `-` is refused.
  A secret whose name does not map back to a path (`a---b`) is left out of listings.
- `?version=<id>` reads an older version by its Key Vault version ID (32 hexadecimal characters).
  Without it the current version is read. Any other selector is refused rather than ignored.
- With `format: raw` (the default) a secret holds one value, exposed as the field `value`; `#value`
  is accepted, any other field reads as not found and a write with any other field is refused. With
  `format: json` the value is a JSON object whose members are the fields (`#username`,
  `#password`), and scrim writes it with content type `application/json`.

A listing prefix selects a path and everything under it: `kv://agents` lists `agents--github` and
`agents--ci--deploy` but not `agents-old`. A trailing `/*` is the same as the folder, and a `*`
right after part of a name is a glob over the start of the path (`kv://APP-*`). Listing never asks
Key Vault for values.

## Setup

The vault must use the Azure RBAC permission model (the default for new vaults). With access
policies instead, grant the same operations in a policy.

1. Pick the identity scrim runs as: the AKS workload identity of scrim's service account, the
   managed identity of the VM or app, or an app registration with a client secret or certificate.
2. Assign it a role on the vault (or narrower, on single secrets):
   - **Key Vault Secrets User** where scrim only reads (secrets for redaction and injection). Writes
     are then refused by Key Vault as well as by scrim.
   - **Key Vault Secrets Officer** where scrim writes captured and generated secrets. It can also
     delete secrets, which scrim never does.
3. Set `vault-url` to the vault's URI from its overview page.

Least privilege:

- Keep secrets scrim must not see in another vault: role assignments on a vault are the coarse
  boundary, and a vault per trust level is the layout Microsoft recommends.
- scrim's health check and watch list the vault, so assign the role on the vault, not only on single
  secrets.
- Turn on purge protection. scrim never deletes or purges, and a soft-deleted name cannot be written
  until it is recovered or purged (scrim reports that as a conflict).

Agents only ever get references and metadata from scrim, never a value.

## Configuration

Each instance is configured under `stores.<instance>`. The generic keys (`kind`, `aliases`, `redact`,
`refresh.*`, `labels`) are shared by every store; the keys below are the adapter's own. Every key can
also be set as an environment variable: `SCRIM_` followed by the full key upper-cased, with dots and
dashes as `_`. Unknown keys fail validation and name the closest known key.

```yaml
stores:
  kv:
    kind: azkv
    vault-url: https://scrim-agents.vault.azure.net
    auth:
      method: workload-identity
    write-only-paths: [inbox]
    redact: ["kv://agents/*"]
```

| Key | Environment variable (instance `kv`) | Type | Default | Meaning |
| ----- | ---------------------------------------- | ------ | --------- | --------- |
| `stores.<name>.vault-url` | `SCRIM_STORES_KV_VAULT_URL` | URL | required | The vault's URI, `https://<vault>.vault.azure.net` (or the sovereign cloud's domain). https only, no path. |
| `stores.<name>.auth.method` | `SCRIM_STORES_KV_AUTH_METHOD` | string | `default` | `default`, `workload-identity`, `managed-identity`, `client-secret`, `client-certificate` or `access-token`; see [Authentication](#authentication). |
| `stores.<name>.tenant-id` | `SCRIM_STORES_KV_TENANT_ID` | string | from the environment | Microsoft Entra tenant ID. Required for `client-secret` and `client-certificate`. |
| `stores.<name>.client-id` | `SCRIM_STORES_KV_CLIENT_ID` | secret reference | from the environment | Application (client) ID of the app registration or user-assigned managed identity. Not secret, but taken as a reference like other credential fields (a literal is fine). |
| `stores.<name>.client-secret` | `SCRIM_STORES_KV_CLIENT_SECRET` | secret reference | none | Client secret, for `client-secret`. |
| `stores.<name>.certificate` | `SCRIM_STORES_KV_CERTIFICATE` | secret reference | none | PEM (certificate and unencrypted private key) or PKCS#12, for `client-certificate`. |
| `stores.<name>.password` | `SCRIM_STORES_KV_PASSWORD` | secret reference | none | Password of a PKCS#12 `certificate`. |
| `stores.<name>.token` | `SCRIM_STORES_KV_TOKEN` | secret reference | none | A Key Vault access token, for `access-token`. Short-lived; for tests and one-off runs. |
| `stores.<name>.auth.token-file` | `SCRIM_STORES_KV_AUTH_TOKEN_FILE` | path | `AZURE_FEDERATED_TOKEN_FILE` | Federated token file, for `workload-identity`. |
| `stores.<name>.cloud` | `SCRIM_STORES_KV_CLOUD` | string | `public` | `public`, `china` or `usgov`: which Microsoft Entra authority to log in at. |
| `stores.<name>.authority-host` | `SCRIM_STORES_KV_AUTHORITY_HOST` | URL | from `cloud` | A custom Entra authority (Azure Stack). Instance discovery is turned off for it, so name only an authority you trust. |
| `stores.<name>.format` | `SCRIM_STORES_KV_FORMAT` | string | `raw` | `raw` (one field `value`) or `json` (a JSON object of fields). |
| `stores.<name>.path-separator` | `SCRIM_STORES_KV_PATH_SEPARATOR` | string | `--` | What a `/` in a reference path becomes in a secret name. Dashes only. |
| `stores.<name>.read-only` | `SCRIM_STORES_KV_READ_ONLY` | bool | `false` | Declare no write capability; writes are refused before Key Vault is contacted. |
| `stores.<name>.write-only-paths` | `SCRIM_STORES_KV_WRITE_ONLY_PATHS` | list | none | Path prefixes scrim writes but never reads back; only the value scrim wrote is redacted. |
| `stores.<name>.timeout` | `SCRIM_STORES_KV_TIMEOUT` | duration | `10s` | Per-request timeout. A timed-out request counts as the store being unavailable. |
| `stores.<name>.tls.ca-file` | `SCRIM_STORES_KV_TLS_CA_FILE` | path | system roots | PEM bundle to verify the vault and the authority with, for a private CA. |
| `stores.<name>.watch.interval` | `SCRIM_STORES_KV_WATCH_INTERVAL` | duration | `30s` | How often the listing is polled for changes, with +-20% jitter. |
| `stores.<name>.watch.max-backoff` | `SCRIM_STORES_KV_WATCH_MAX_BACKOFF` | duration | `5m` | Longest wait between polls while Key Vault keeps failing. |

An option the chosen method does not use (a client secret with `workload-identity`, say) fails
validation, so a credential is never configured and silently ignored.

## Authentication

scrim uses [azidentity](https://learn.microsoft.com/azure/developer/go/azure-sdk-authentication),
the Azure SDK's credential library:

| Method | What it uses |
| --- | --- |
| `default` | `DefaultAzureCredential`: the `AZURE_*` environment variables (client secret, certificate), workload identity, managed identity, then the Azure CLI and Azure Developer CLI logins. Convenient on a workstation; prefer a specific method in production, so a missing identity fails instead of falling through to a developer login. |
| `workload-identity` | AKS workload identity: the federated service account token in `auth.token-file` (the webhook sets `AZURE_FEDERATED_TOKEN_FILE`, `AZURE_TENANT_ID` and `AZURE_CLIENT_ID`). No secret in the cluster. |
| `managed-identity` | The system-assigned managed identity, or the user-assigned one `client-id` names. |
| `client-secret` | An app registration's client secret. |
| `client-certificate` | An app registration's certificate. |
| `access-token` | A token you obtained yourself (`az account get-access-token --resource https://vault.azure.net`). It is not renewed. |

scrim does not know the vault's tenant or token audience up front. Its first request goes out without
a token or body, and Key Vault answers 401 with a challenge naming the authority and the resource, as
it does for the Azure SDK. scrim checks that the resource is a parent domain of the vault's host
(`vault.azure.net` for `<vault>.vault.azure.net`) and refuses the challenge otherwise, so a host
posing as the vault cannot obtain a token for another resource. It then asks azidentity for a token
for that resource and the vault's tenant; a credential configured for a different tenant refuses.
The token is cached until five minutes before it expires. A 401 to a token drops it and follows the
new challenge once, including a continuous access evaluation claims challenge.

The access token, the client secret, the certificate and its password are added to the redaction
set. None of them appears in an error: a refused login is reported as a permission error naming the
store, with Entra's error code. The token and the client secret pass through azidentity and net/http
as Go strings, which cannot be wiped; the secret values in the vault never do.

## Policy labels

Every secret the adapter reads or lists carries labels describing where it lives in Key Vault, so
[policy rules](../policy.md) can match on them through `secret.labels`. Labels are metadata: they
never hold a secret value. Attributes are those of the version read, or of the current version in a
listing.

| Key | Example | Meaning |
| --- | --- | --- |
| `azkv.vault` | `scrim-agents` | Vault name, the first label of the vault's host. |
| `azkv.vault-host` | `scrim-agents.vault.azure.net` | Vault host. |
| `azkv.name` | `agents--github` | Secret name in the vault. |
| `azkv.version` | `4387e9f3d6e14c459867679a90fd0f79` | Version ID. Reads only: a listing names no version. |
| `azkv.content-type` | `application/json` | Content type, when set. |
| `azkv.enabled` | `true` / `false` | Enabled attribute. A disabled current version reads as not found. |
| `azkv.created`, `azkv.updated` | `2026-03-04T05:06:07Z` | Creation and last update time of the version, RFC 3339 in UTC. |
| `azkv.expires`, `azkv.not-before` | `2027-01-01T00:00:00Z` | Expiry and activation time, when set. scrim does not refuse a read because of them; a rule can. |
| `azkv.recovery-level` | `Recoverable+Purgeable` | Deletion recovery level of the vault. |
| `azkv.recoverable-days` | `90` | Soft-delete retention in days. |
| `azkv.managed` | `true` / `false` | The secret backs a Key Vault certificate and is managed by it. |
| `azkv.meta.<key>` | `azkv.meta.team` = `payments` | A tag on the version, key normalised as for every store, value as stored. |

Tags are also copied under their own key, so `scrim.hosts`, `scrim.placeholder` and the other
[catalog](../catalog.md) keys work as tags. A tag in the `azkv.` namespace (in any case) is never
copied to the top level and never overrides a native key: a tag `azkv.enabled = false` on an enabled
secret shows up as `azkv.meta.azkv.enabled` and leaves `azkv.enabled` at `true`. Anyone allowed to set
a secret can set its tags, so rules that grant access should match native keys.

<!-- policy-example -->
```yaml
default: deny
rules:
  - name: payments-vault-asks
    decision: ask
    reason: secrets of the payments team need a human
    when: >-
      op in ["store.read", "store.write", "inject"] && secret.store == "kv" &&
      "azkv.meta.team" in secret.labels && secret.labels["azkv.meta.team"] == "payments"
  - name: certificates-never
    decision: deny
    when: secret.store == "kv" && secret.labels["azkv.managed"] == "true"
  - name: kv-rest
    decision: allow
    when: op in ["store.read", "store.write"] && secret.store == "kv"
```

An ask or deny rule that indexes a label the secret does not have fails, and a failing ask or deny
rule counts as matching, so test optional keys such as tags with `in` first.

More patterns:

```cel
secret.labels["azkv.name"].startsWith("agents--")                       // under kv://agents
secret.labels["azkv.vault"] == "scrim-agents"                           // one vault of several
"azkv.expires" in secret.labels && timestamp(secret.labels["azkv.expires"]) < now  // expired
timestamp(secret.labels["azkv.updated"]) < now - duration("2160h")      // not rotated in 90 days
```

For `store.write`, the adapter tells scrim which labels a secret at the target reference would get
(`azkv.vault`, `azkv.vault-host`, `azkv.name`, `azkv.enabled`, `azkv.managed`, and
`azkv.content-type` in format json) without contacting Key Vault.

A label lookup for a secret outside the redaction set (a write to an existing secret, say) lists the
secret's versions, which Key Vault returns without values, and takes the current one (the most
recently created) or the pinned one. Its labels equal a read's. Key Vault times have one-second
resolution, so when two versions were created in the same second the current one cannot be told
apart, and the lookup leaves `azkv.version` out rather than guess.

## Writes

A write creates a new version. Key Vault keeps tags and content type per version, so a write without
labels carries the current version's tags and content type over; a write with labels stores them as
the new version's tags (labels in the `azkv.` namespace are dropped). Key Vault allows 15 tags.

Key Vault has no conditional create. A create-only write checks the secret does not exist first; a
secret created by someone else between that check and the write gets a new version instead of a
conflict (older versions are kept). A value over 25 KiB, or that is not valid UTF-8, is refused before
anything is sent.

## Watch and refresh

Watch polls the secrets listing every `watch.interval` (names and attributes only, never values) and
reports a secret as changed when its current version's update time, enabled flag, content type or
tags change. Key Vault times have one-second resolution, so a version written in the same second as
the one before would look the same: while a secret's update time is within two seconds of the vault's
own clock (the listing's `Date` header), every poll reports it as changed, until it settles. A
spurious change costs one read; a missed one would keep a rotated value out of the redaction set
until the next full refresh.

A secrets listing names no version, so listings report none, and the refresher reads every listed
secret on each full refresh (`refresh.interval`), one request per secret. Errors back off up to
`watch.max-backoff`; the watch survives an outage.

| Situation | Reported as |
| --- | --- |
| Vault unreachable, 429 or 5xx | unavailable |
| 401/403 (no role, wrong tenant, refused login) | permission denied |
| Missing secret or version, disabled version | not found |
| Name held by a soft-deleted secret, create-only write of an existing secret | conflict |

## Testing and fidelity

There is no Key Vault emulator. The adapter is tested against an in-process fake
(`internal/stores/azkv/fake_test.go`) that serves the Key Vault secrets REST API 7.5, the Microsoft
Entra discovery and token endpoints and the App Service managed identity endpoint over TLS, and runs
the shared conformance suite in both formats, the client-secret, client-certificate, workload
identity, managed identity and access-token logins through the real azidentity, and the challenge
checks. It follows the documented behaviour: the 401 challenge, one-second times, versions per write,
tags and content type per version, pages of 25 with `nextLink`, soft delete holding the name (409),
403 `SecretDisabled`, the error envelope.

What the fake does not reproduce: real RBAC evaluation (writes are refused by name prefix), token
signatures and claims (Entra tokens are opaque strings, a certificate assertion is accepted unsigned),
throttling, the order of a versions listing (undocumented; the fake sorts by version ID, and the
adapter does not depend on it), private endpoints and firewall rules, recovery and purge, and
certificate-backed secrets beyond the `managed` flag. Run against a real vault before relying on a
role layout.
