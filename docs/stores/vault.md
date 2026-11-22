# HashiCorp Vault

The `vault` adapter reads, lists, watches and writes secrets in HashiCorp Vault's KV secrets
engines, version 1 and 2, and issues dynamic secrets (database, AWS, PKI and other engines) for
grants, holding each credential's lease only as long as the grant lasts. It authenticates with a
token, AppRole, the scrim pod's Kubernetes service account, or a JWT, and sends a namespace with
every request for Vault Enterprise.

It shares its HTTP client, authentication and token renewal with the [openbao](openbao.md) adapter,
so everything said there about logins, renewal, redirects and escaping holds here too. Use `openbao`
for OpenBao and `vault` for Vault; both can be configured at once.

## References

```text
vault://<mount>/<path>[?version=<n>][#<field>]

vault://secret/agents/github#token         the token field of a KV v2 secret
vault://secret/agents/github?version=3     every field of version 3 (KV v2 only)
vault://legacy/agents/github#token         a KV v1 secret: same form, no versions
vault://secret/agents/*                    (redact targets only) every secret under secret/agents
vault://database/creds/readonly            a dynamic secret, issued for a grant
vault://pki/issue/web?common_name=app.example.com
```

The adapter finds the mount of each reference, its type and its KV version by asking
`sys/internal/ui/mounts/<path>`, which Vault answers for any token with a capability under the
mount. It asks once per mount every 5 minutes and remembers a refusal for as long. When the lookup is
refused or turned off (`mounts.detect: false`), the options decide: a reference's mount is the
longest entry of `mounts` or `kv-v1-mounts` it starts with, otherwise its first segment; mounts in
`kv-v1-mounts` are KV v1, paths under `dynamic-paths` are dynamic, and everything else is KV v2.

`version` is the only selector on KV v2, and KV v1 takes none: any other selector is refused rather
than ignored. On a dynamic path, selectors are the parameters of the request (see
[Dynamic secrets](#dynamic-secrets)). Path segments are escaped once, so `vault://secret/git hub`
lives in Vault under `git hub`.

## Capabilities

| read | list | watch | write | generate | dynamic |
|------|------|-------|-------|----------|---------|
| yes  | yes  | yes   | yes   | no       | yes     |

- **Read** returns every field, or the one the reference names. Strings are used as they are;
  numbers, booleans and objects as their JSON text. A KV v2 version that is deleted or destroyed is
  not found; one whose deletion is only scheduled (`delete_version_after`) is still readable.
- **List** walks a folder recursively and returns names and metadata only, never values. On KV v2
  it lists `metadata/` and reads each secret's metadata; deleted and destroyed secrets are left out.
  On KV v1 it lists the folder.
- **Watch** polls every `watch.interval` (with ±20% jitter) and reports changed and deleted
  secrets. On KV v2 it compares versions from the metadata, never reading a value. KV v1 keeps no
  versions, so each poll reads the secrets under the prefix and compares a keyed hash of their
  fields (the key is random per process and never leaves memory). Use a longer interval on large
  KV v1 trees. A failing poll backs off up to `watch.max-backoff` and the watch carries on.
- **Write** on KV v2 creates a new version with `POST <mount>/data/<path>`, needing `create` or
  `update` but never `read`; create-only writes use check-and-set version 0, and labels go to the
  secret's custom metadata. On KV v1 a write replaces the secret. KV v1 has no check-and-set, so a
  create-only write lists the folder first and refuses if the name is there (a writer racing
  between the two still wins), and it has no custom metadata, so a write with labels is refused
  rather than stored without them.
- **Metadata without values**: when policy needs the labels of an existing secret, the adapter
  reads KV v2 metadata, or lists the KV v1 folder to see that the name exists. If the store refuses
  that, it reads the secret and wipes the values at once.

## Dynamic secrets

A reference into a mount that is not KV (`database/`, `aws/`, `pki/`, ...), or under one of
`dynamic-paths`, names a dynamic secret. It is never read, listed or written as a stored secret:
those operations are refused. Instead scrim asks Vault for a new credential for a grant, and keeps
its lease for as long as the grant lasts:

1. The credential is requested with `GET <path>`, or with `POST <path>` and the reference's
   selectors as parameters when it has any (`pki/issue/web?common_name=app.example.com`). Its
   values are redacted from the moment they arrive.
2. Every `leases.check-interval`, and before each renewal, scrim checks the grant. While the grant
   is usable, the lease is renewed with `sys/leases/renew` two thirds into its TTL, asking for
   `leases.increment` (by default the TTL Vault first gave), but never for more than the grant has
   left.
3. When the grant is revoked, expires or is used up, or deny-all is engaged, scrim revokes the lease
   with `sys/leases/revoke`. Vault then revokes the credential in the target system: the database
   engine drops the user, the AWS engine deletes the access key.

Because renewals never go past the grant's expiry, a credential whose revocation fails (Vault
unreachable at that moment) still lapses when the grant ends. A credential Vault issues without a
lease (a PKI role without `generate_lease`) is refused and wiped, since scrim could not revoke it.
When scrim stops, it revokes the leases it holds (`leases.revoke-on-close`); turn that off to let
them lapse on their own TTL instead.

A renewal that reaches the role's `max_ttl` comes back shorter than asked for, and the credential
ends then even if the grant lasts longer. Set the role's `max_ttl` to at least `grants.max-ttl`.

Issued secrets carry the [labels](#labels) of their mount and path plus `vault.dynamic`,
`vault.lease_duration`, `vault.lease_renewable` and `vault.lease_holder` (`grant:<id>`). The lease
ID appears in logs when a renewal or revocation fails. It names the engine path and is not a
credential.

## Namespaces

`namespace` is sent as `X-Vault-Namespace` with every request, and `auth.namespace`, when set, with
logins instead, for an auth method mounted in a parent namespace (log in at `team-a`, read secrets
in `team-a/eu`). References are relative to the namespace. Both are Vault Enterprise features;
Vault community edition ignores the header.

## Labels

Every secret carries labels under `vault.` that describe it in Vault's terms. They are the same
attributes as OpenBao's, under `vault.` instead of `openbao.`; see the
[OpenBao key table](openbao.md#keys) for each key and its source:

- from the reference and options: `vault.mount`, `vault.path`, `vault.name`, `vault.folder`,
  `vault.ancestors` (list), `vault.segments` (list), `vault.namespace`, `vault.namespaces` (list);
- `vault.engine`: `kv-v2`, `kv-v1`, or the mount type of a dynamic secret (`database`);
- KV v2 data and metadata: `vault.version`, `vault.current_version`, `vault.oldest_version`,
  `vault.max_versions`, `vault.versions`, `vault.deleted_versions`, `vault.destroyed_versions`,
  `vault.cas_required`, `vault.delete_version_after`, `vault.created_time`, `vault.updated_time`,
  `vault.version_created_time`, `vault.deletion_time`, `vault.destroyed`;
- the mount: `vault.mount_type`, `vault.mount_version`, `vault.mount_description`,
  `vault.mount_accessor`, `vault.mount_plugin_version`, `vault.mount_local`, `vault.mount_seal_wrap`,
  `vault.mount_external_entropy_access`, `vault.mount_option.<option>`,
  `vault.mount_config.<setting>`;
- KV v2 custom metadata: `vault.meta.<key>`, and under its own key unless it starts with `vault.`
  or `store.`;
- dynamic secrets: `vault.dynamic`, `vault.lease_duration`, `vault.lease_renewable`,
  `vault.lease_holder`.

KV v1 secrets have no version or custom metadata labels. Custom metadata never replaces a native
key: a custom key `vault.engine` shows up as `vault.meta.vault.engine`. Mount labels come from the
mount lookup at no extra cost; with `mounts.detect: false` they need `labels.lookups`, which asks
`sys/internal/ui/mounts/<mount>` and then `sys/mounts/<mount>`. Labels never hold a value.

## Configuration

```yaml
stores:
  vault:
    kind: vault
    address: https://vault.example.com:8200
    namespace: team-a/eu
    auth: {method: approle}
    role-id: file:/run/secrets/vault-role-id
    secret-id: file:/run/secrets/vault-secret-id
    write-only-paths: [secret/agents/inbox]
    redact: ["vault://secret/agents/*"]
```

| Key | Default | Meaning |
| ----- | --------- | --------- |
| `address` | required | `http://` or `https://` URL of the API. |
| `namespace` | none | Vault Enterprise namespace, sent as `X-Vault-Namespace`. |
| `auth.namespace` | `namespace` | Namespace sent with logins, when the auth method is mounted elsewhere. |
| `auth.method` | `token` | `token`, `approle`, `kubernetes` or `jwt`. |
| `token` | required for `token` | Token reference. |
| `role-id`, `secret-id` | required for `approle` | AppRole role ID and secret ID references. |
| `auth.approle.mount` | `approle` | Where the AppRole auth method is mounted. |
| `auth.kubernetes.role` | required for `kubernetes` | Kubernetes auth role to log in as. |
| `auth.kubernetes.mount` | `kubernetes` | Where the Kubernetes auth method is mounted. |
| `auth.kubernetes.token-file` | `/var/run/secrets/kubernetes.io/serviceaccount/token` | Service account token, read again at every login. |
| `auth.jwt.role` | required for `jwt` | JWT auth role to log in as. |
| `auth.jwt.mount` | `jwt` | Where the JWT auth method is mounted. |
| `auth.jwt.token-file` | none | File holding the JWT, read again at every login. Exactly one of this and `jwt`. |
| `jwt` | none | JWT reference (`env:`, `file:`, ...), resolved again at every login. |
| `mounts` | none | Mounts that span several path segments, for when the mount lookup is refused. |
| `kv-v1-mounts` | none | KV v1 mounts, for when the mount lookup is refused. |
| `dynamic-paths` | none | Path prefixes (mount included) of dynamic secrets, for when the mount lookup is refused. |
| `mounts.detect` | `true` | Look each reference's mount up with `sys/internal/ui/mounts`. |
| `timeout` | `10s` | Per-request timeout. |
| `tls.ca-file` | system roots | PEM bundle to verify the server with. |
| `tls.server-name` | from address | TLS server name to verify. |
| `watch.interval` | `30s` | Poll period for watch. |
| `watch.max-backoff` | `5m` | Longest wait between polls while the store fails. |
| `write-only-paths` | none | Path prefixes (mount included) that scrim writes but never reads back. |
| `labels.lookups` | `true` | Make the optional requests that fill labels: KV v2 metadata on read, and mount information when detection is off. |
| `leases.check-interval` | `10s` | How often the grant behind each held lease is checked. |
| `leases.increment` | the first TTL | Renewal asked for, never past the grant's expiry. |
| `leases.revoke-on-close` | `true` | Revoke every held lease when scrim stops. |
| `leases.revoke-timeout` | `10s` | How long one revocation may take. |

Keys are relative to `stores.<name>.` and can be set from the environment as with every store
(`SCRIM_STORES_VAULT_ADDRESS` for an instance named `vault`). The common keys (`kind`, `aliases`,
`redact`, `refresh.*`) are in the [stores overview](README.md). Unknown keys fail validation and
name the closest known key.

JWT auth fits CI systems and workload identity providers that hand out short-lived OIDC tokens:
configure a `jwt` auth role bound to the token's audience and subject, and point
`auth.jwt.token-file` at where the platform writes the token. Kubernetes auth works as described for
[OpenBao](openbao.md#kubernetes-auth). Login tokens are renewed and replaced as described in the
[OpenBao configuration](openbao.md#configuration); every token, role ID, secret ID and JWT stays
out of errors and logs, and the session token is redacted with scrim's other store credentials.

## Least privilege

```hcl
# scrim.hcl
path "secret/data/agents/*"      { capabilities = ["create", "read", "update"] }
path "secret/metadata/agents/*"  { capabilities = ["list", "read", "update"] }

# Write without read: agents store secrets here, scrim never reads them back.
path "secret/data/agents/inbox/*"     { capabilities = ["create", "update"] }
path "secret/metadata/agents/inbox/*" { capabilities = ["list"] }

# KV v1
path "legacy/agents/*" { capabilities = ["create", "read", "update", "list"] }

# Dynamic secrets and their leases
path "database/creds/readonly" { capabilities = ["read"] }
path "sys/leases/renew"        { capabilities = ["update"] }
path "sys/leases/revoke"       { capabilities = ["update"] }
```

`update` on `secret/metadata/...` is only needed to store labels. Without `sys/leases/revoke`, a
credential lapses at the grant's expiry instead of the moment the grant is revoked. No policy is
needed for the mount lookup: Vault answers `sys/internal/ui/mounts` for any path the token has a
capability under.

## Testing

The adapter's tests run the shared conformance suite against KV v2 and KV v1 mounts of Vault in dev
mode (rootless podman, `docker.io/hashicorp/vault`, with a PostgreSQL for the database engine), log
in with AppRole, a token and a JWT, and issue database credentials for grants, checking the lease is
renewed past its TTL and revoked, and the PostgreSQL role dropped, once the grant is revoked or
expires. Vault is under the Business Source License, which allows running it to test against.
Point `SCRIM_TEST_VAULT_ADDR` and `SCRIM_TEST_VAULT_TOKEN` at another server to run the suite
there (without the outage and database tests).
