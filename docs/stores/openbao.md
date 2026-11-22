# OpenBao

The `openbao` adapter reads, lists, watches and writes secrets in an OpenBao KV version 2 secrets
engine. It also works with HashiCorp Vault's KV v2 engine, though Vault's own features
(namespaces aside) get a separate `vault` adapter later. Authentication is by token, by AppRole, or
in a Kubernetes cluster by the scrim pod's own service account
([Kubernetes auth](#kubernetes-auth)), so no static store credential exists in the cluster.

## References

```text
bao://<mount>/<path>[?version=<n>][#<field>]

bao://kv/agents/github#token        the token field of kv/agents/github
bao://kv/agents/github?version=3    every field of version 3
bao://kv/agents/*                   (redact targets only) every secret under kv/agents
```

The first path segment is the mount. A mount that spans several segments (`teams/kv`) must be
listed in `mounts` so the adapter knows where the mount ends. `version` is the only selector; any
other selector is refused rather than ignored, so a pinned reference never silently resolves to
another version. String fields are used as they are. Numbers, booleans and objects are used as
their JSON text.

### Names that need escaping

A path segment with a space or another character that is not allowed in a URL path as it is
(`bao://kv/agents/git hub`) is sent to OpenBao escaped once, so the secret lives in OpenBao under
the name you wrote: `bao kv get -mount=kv 'agents/git hub'` finds it.

Releases up to 0.4.0 escaped such paths twice. OpenBao decoded them once and stored the secret under
an escaped copy of its name: scrim wrote `agents/git hub` as `agents/git%20hub`. Those secrets
still work. When a read finds nothing under the correct name and the name has characters that
needed escaping, scrim looks the secret up under the old name, uses it if it is there, and logs one
warning per secret naming both paths (never a value). A secret under the correct name always wins.
This lookup will be removed in a later release, so move each secret the warning names:

```sh
bao kv get -mount=kv -format=json -field=data 'agents/git%20hub' \
  | bao kv put -mount=kv 'agents/git hub' -
bao kv metadata delete -mount=kv 'agents/git%20hub'
```

`kv put` copies the current version only. Copy custom metadata (`scrim.hosts`, labels) with
`bao kv metadata put -custom-metadata=...` before deleting the old name. A policy that grants paths
by their exact names needs the correct names too.

## Capabilities

| read | list | watch | write | generate | dynamic |
|------|------|-------|-------|----------|---------|
| yes  | yes  | yes   | yes   | no       | no      |

- **List** walks a folder recursively and returns names and metadata only (version, times,
  [labels](#labels)), never values. Soft-deleted and destroyed secrets are left out; a version
  whose deletion is only scheduled (by `delete_version_after`) is still live.
- **Watch** polls version metadata every `watch.interval` (with ±20% jitter) and reports changed
  and deleted secrets. On OpenBao one `LIST .../detailed-metadata/<folder>` per folder returns
  every key's version, so a poll costs a few requests however many secrets there are. On Vault,
  which lacks that endpoint, the adapter falls back to reading each secret's metadata. A failing
  poll backs off exponentially up to `watch.max-backoff` and the watch carries on.
- **Write** creates a new version with `POST <mount>/data/<path>`. It needs `create` (new secret)
  or `update` (new version), never `read`. Create-only writes use check-and-set version 0.
  Labels are written to the secret's custom metadata.

## Labels

Every secret the adapter reads, lists or writes carries labels that describe it in OpenBao's own
terms: its mount, namespace, path, versions, settings and custom metadata. Policy rules see them as
`secret.labels` ([policy.md](../policy.md)), so a rule can match on anything the store knows about
a secret, not only on its reference. Labels hold metadata only, never a value.

### Keys

Native keys start with `openbao.`. A list attribute is stored twice: comma-joined under its key, and
as one presence key per value set to `"true"`, so both `"openbao.ancestors.prod" in secret.labels`
and `secret.labels["openbao.ancestors"].split(",")` work, and the data plane can decide on presence
keys without CEL.

| Key | Example | Source | Meaning |
| --- | --- | --- | --- |
| `openbao.mount` | `kv-prod` | reference | Mount path, without the trailing slash. Always set. |
| `openbao.engine` | `kv-v2` | mount, else `kv-v2` | Secrets engine: `kv-v2` or `kv-v1` for KV, otherwise the mount type. The adapter speaks KV v2, so this is `kv-v2` when the mount cannot be read. |
| `openbao.namespace` | `team-a/eu` | `namespace` option | Configured namespace. Absent without one. |
| `openbao.namespaces` (list) | `team-a,team-a/eu` | `namespace` option | The namespace and every parent namespace: `openbao.namespaces.team-a` matches `team-a` and everything in it. |
| `openbao.path` | `prod/eu/db` | reference | Path inside the mount. |
| `openbao.name` | `db` | reference | Last path segment. |
| `openbao.folder` | `prod/eu` | reference | Parent folder. Absent at the top of the mount. |
| `openbao.ancestors` (list) | `prod,prod/eu` | reference | Every folder above the secret: `openbao.ancestors.prod` and `openbao.ancestors.prod/eu` are both set for `prod/eu/db`. Absent at the top of the mount. |
| `openbao.segments` (list) | `prod,eu,db` | reference | Every path segment, wherever it sits: `openbao.segments.eu`. |
| `openbao.version` | `3` | data or metadata | Version described: the one read (also with `?version=`), the current one in a list, the one written. |
| `openbao.current_version` | `3` | metadata | Current version. |
| `openbao.oldest_version` | `2` | metadata | Oldest version kept. Absent while it is 0. |
| `openbao.max_versions` | `5` | metadata | Versions kept for this secret; `0` means the mount's setting. |
| `openbao.versions` | `3` | metadata | Number of versions on record. |
| `openbao.deleted_versions` | `1` | metadata | Versions soft-deleted (deletion time passed, not destroyed). |
| `openbao.destroyed_versions` | `1` | metadata | Versions destroyed. |
| `openbao.cas_required` | `true` | metadata | Whether writes must use check-and-set. |
| `openbao.delete_version_after` | `720h0m0s` | metadata | Secret's automatic deletion delay; `0s` means none. |
| `openbao.created_time` | `2026-01-01T00:00:00Z` | metadata | When the secret was created. |
| `openbao.updated_time` | `2026-03-01T00:00:00Z` | metadata | When its last version was written. |
| `openbao.version_created_time` | `2026-03-01T00:00:00Z` | data or metadata | When the described version was written. |
| `openbao.deletion_time` | `2026-03-31T00:00:00Z` | data or metadata | Deletion time of the described version: in the future when `delete_version_after` scheduled it. Absent when none. |
| `openbao.destroyed` | `false` | data or metadata | Whether the described version is destroyed. |
| `openbao.mount_type` | `kv` | mount | Mount type. |
| `openbao.mount_version` | `2` | mount | The mount's `version` option. |
| `openbao.mount_description` | `Production` | mount | Mount description. |
| `openbao.mount_accessor` | `kv_1a2b3c4d` | mount | Mount accessor. |
| `openbao.mount_plugin_version` | `v2.0.0` | mount | Plugin version, when the mount reports one. |
| `openbao.mount_local` | `false` | mount | Whether the mount is local (not replicated). |
| `openbao.mount_seal_wrap` | `false` | mount | Whether seal wrapping is on. |
| `openbao.mount_external_entropy_access` | `false` | mount | Whether the mount has external entropy access. |
| `openbao.mount_option.<option>` | `openbao.mount_option.version: 2` | mount | Each mount option. |
| `openbao.mount_config.<setting>` | `openbao.mount_config.listing_visibility: hidden` | mount | Each mount tuning setting (`default_lease_ttl`, `max_lease_ttl`, `listing_visibility`, ...); lists are comma-joined. |
| `openbao.meta.<key>` | `openbao.meta.team: payments` | custom metadata | Each custom metadata entry. |
| `<key>` | `scrim.hosts: api.example.com` | custom metadata | Each custom metadata entry under its own key, as before, unless the key starts with `openbao.`. |

Where the sources come from:

- **reference** and the `namespace` option: always present.
- **data**: the data read itself (`<mount>/data/<path>`), which every read makes anyway.
- **metadata**: `<mount>/metadata/<path>`. A list gets it from `detailed-metadata` (or the per-secret
  metadata reads of the fallback) at no extra cost. A read makes one extra `GET` of it.
- **mount**: `sys/internal/ui/mounts/<mount>`, which OpenBao answers for any token with a capability
  under the mount, then `sys/mounts/<mount>`, which needs `read` on that path. Looked up at most once
  per mount every 5 minutes; a refusal is remembered for the same time.

These extra requests are optional. When the store refuses one, or it fails, the read or list goes
ahead and the labels that depended on it are missing, so a rule that matches on them does not
match. A refused lookup never triggers a new login. A write reports the labels it knows without
asking: the reference, the version it created, the custom metadata it stored and mount labels
already cached. To stop the extra requests altogether (no refusals in the store's audit log, one
request per read), set `labels.lookups: false`; metadata and mount labels are then present only
where a list returns them anyway.

### Normalisation

Keys follow the convention every store adapter shares. Attribute names are fixed, lowercase ASCII,
dot-separated. A part of a key that comes from store data and names something (a custom metadata
key, a mount option or setting name) is folded: ASCII letters are lowercased, every character other
than `a-z`, `0-9`, `-` and `_` becomes `_`, dots separate segments and empty segments are dropped.
`Cost Center` becomes `openbao.meta.cost_center`, `team/owner` becomes `openbao.meta.team_owner`.
When two custom metadata keys fold to the same key, the first in byte order wins (`TEAM` before
`team`).

The value part of a presence key is the value verbatim, so `openbao.ancestors.Prod/EU` is set for
`Prod/EU/db` and a rule matches folders exactly, case included. Values are never changed. A comma
inside a path segment makes the comma-joined list ambiguous; the presence keys stay exact.

### Native keys cannot be forged

Native keys are set first and custom metadata never overwrites them. A custom metadata key that
starts with `openbao.` or `store.` (in any case) is not copied under its own name, only under
`openbao.meta.`, so it can neither pose as a native key nor as one of the generic `store.*` labels
scrim adds for every secret. An entry
`openbao.mount = kv-dev` written by whoever may edit a secret's metadata shows up as
`openbao.meta.openbao.mount` and cannot make a secret look like it lives elsewhere. Custom metadata
is editable by anyone with `update` on the metadata path, so rules that grant access should prefer
native keys, which come from the store and from scrim's own configuration.

Custom metadata also appears under its own key, as it did before native labels existed, so the
catalog's `scrim.*` keys and rules on plain keys keep working. The one difference: keys starting with
`openbao.` or `store.` no longer appear under their own name.

### Example rules

A rule that reads a label the secret does not have fails, and a failing `ask` or `deny` rule counts
as matching ([policy.md](../policy.md#how-rules-combine)). Guard every label that can be missing
with `in` (or `has()`) before reading it, as below; `openbao.mount`, `openbao.engine` and the path
labels are always present on an OpenBao secret.

```yaml
rules:
  # Anything under mount kv-prod, with custom metadata team=payments, or below prod/ in any
  # mount must be approved, whatever the operation.
  - name: prod-asks
    decision: ask
    when: >-
      secret.store == "bao" && (
        secret.labels["openbao.mount"] == "kv-prod" ||
        ("openbao.meta.team" in secret.labels && secret.labels["openbao.meta.team"] == "payments") ||
        "openbao.ancestors.prod" in secret.labels)

  # The same with a glob on the path, for writes only.
  - name: prod-writes-ask
    decision: ask
    when: >-
      op == "store.write" && secret.store == "bao" &&
      secret.labels["openbao.path"].glob("prod/**")

  # Secrets in a mount described as production, or in team-a's namespace or below it.
  - name: described-prod
    decision: ask
    when: >-
      ("openbao.mount_description" in secret.labels &&
       secret.labels["openbao.mount_description"].contains("Production")) ||
      "openbao.namespaces.team-a" in secret.labels

  # Stale secrets: last written more than 90 days ago.
  - name: stale
    decision: deny
    when: >-
      "openbao.updated_time" in secret.labels &&
      timestamp(secret.labels["openbao.updated_time"]) < now - duration("2160h")

  # Secrets set to delete themselves, or whose writes need check-and-set.
  - name: self-deleting-or-cas
    decision: ask
    when: >-
      ("openbao.delete_version_after" in secret.labels &&
       secret.labels["openbao.delete_version_after"] != "0s") ||
      ("openbao.cas_required" in secret.labels && secret.labels["openbao.cas_required"] == "true")
```

Missing labels make a guarded rule not match, so do not grant access by absence: `allow` rules that
match on `!("openbao.meta.team" in secret.labels)` let through every secret whose metadata the
token could not read. `secret.labels` is not available to restore decisions in the data plane
([policy.md](../policy.md#rules-and-restore)). Which operations carry a secret's store labels into
`secret.labels` is decided by the policy gate, not by the adapter; for a `store.write` rule on a secret
that does not exist yet, the adapter reports the labels it can derive without asking the store
(`WriteLabels`, the `stores.WriteLabeler` interface): reference, namespace and cached mount labels.

## Configuration

```yaml
apiVersion: scrim.dev/v1
kind: Config
stores:
  bao:
    kind: openbao
    address: https://bao.example.com:8200
    auth: {method: approle}
    role-id: file:/run/secrets/bao-role-id
    secret-id: file:/run/secrets/bao-secret-id
    tls:
      ca-file: /etc/scrim/bao-ca.pem
    write-only-paths: [kv/agents/inbox]
    redact: ["bao://kv/agents/*"]
```

| Key | Env var (instance `bao`) | Default | Meaning |
| ----- | -------------------------- | --------- | --------- |
| `stores.bao.address` | `SCRIM_STORES_BAO_ADDRESS` | required | `http://` or `https://` URL of the API. |
| `stores.bao.namespace` | `SCRIM_STORES_BAO_NAMESPACE` | none | OpenBao namespace, sent as `X-Vault-Namespace`. |
| `stores.bao.mounts` | `SCRIM_STORES_BAO_MOUNTS` | none | KV v2 mounts that span more than one path segment. |
| `stores.bao.auth.method` | `SCRIM_STORES_BAO_AUTH_METHOD` | `token` | `token`, `approle` or `kubernetes`. |
| `stores.bao.token` | `SCRIM_STORES_BAO_TOKEN` | required for `token` | Token reference. |
| `stores.bao.role-id` | `SCRIM_STORES_BAO_ROLE_ID` | required for `approle` | AppRole role ID reference. |
| `stores.bao.secret-id` | `SCRIM_STORES_BAO_SECRET_ID` | required for `approle` | AppRole secret ID reference. |
| `stores.bao.auth.approle.mount` | `SCRIM_STORES_BAO_AUTH_APPROLE_MOUNT` | `approle` | Where the AppRole auth method is mounted. |
| `stores.bao.auth.kubernetes.role` | `SCRIM_STORES_BAO_AUTH_KUBERNETES_ROLE` | required for `kubernetes` | Kubernetes auth role to log in as. Not a secret. |
| `stores.bao.auth.kubernetes.mount` | `SCRIM_STORES_BAO_AUTH_KUBERNETES_MOUNT` | `kubernetes` | Where the Kubernetes auth method is mounted. |
| `stores.bao.auth.kubernetes.token-file` | `SCRIM_STORES_BAO_AUTH_KUBERNETES_TOKEN_FILE` | `/var/run/secrets/kubernetes.io/serviceaccount/token` | Service account token presented at login, read again at every login. Point it at a projected token with a dedicated audience. |
| `stores.bao.timeout` | `SCRIM_STORES_BAO_TIMEOUT` | `10s` | Per-request timeout. |
| `stores.bao.tls.ca-file` | `SCRIM_STORES_BAO_TLS_CA_FILE` | system roots | PEM bundle to verify the server with. |
| `stores.bao.tls.server-name` | `SCRIM_STORES_BAO_TLS_SERVER_NAME` | from address | TLS server name to verify. |
| `stores.bao.watch.interval` | `SCRIM_STORES_BAO_WATCH_INTERVAL` | `30s` | Metadata poll period for watch. |
| `stores.bao.watch.max-backoff` | `SCRIM_STORES_BAO_WATCH_MAX_BACKOFF` | `5m` | Longest wait between polls while the store fails. |
| `stores.bao.write-only-paths` | `SCRIM_STORES_BAO_WRITE_ONLY_PATHS` | none | Path prefixes (mount included) that scrim writes but never reads back. |
| `stores.bao.labels.lookups` | `SCRIM_STORES_BAO_LABELS_LOOKUPS` | `true` | Make the optional requests that fill [labels](#labels): a secret's metadata on read, and mount information. |

The common keys (`kind`, `aliases`, `redact`, `refresh.*`) are described in the
[stores overview](README.md). Unknown keys fail validation and name the closest known key. Lists
set from the environment are comma-separated.

With AppRole and Kubernetes auth, scrim logs in when it first needs a token. At two thirds of the
token's TTL it renews the token with `auth/token/renew-self` if the store issued it as renewable,
asking for the TTL of the login again. It logs in again instead when the token is not renewable,
when renewal fails or is refused, and when a renewal comes back shorter than asked for, which means
the token's `token_max_ttl` is close: scrim uses up what is left and then logs in. If the store
rejects a token it should have accepted (403), scrim logs in again once; a second refusal is
reported as a permission error. Use a role with a short `token_ttl` and a `token_max_ttl` of a few
hours. With a static token, use a periodic token or rotate it through its reference, because scrim
does not renew it. scrim refuses HTTP redirects, so a token is never sent to another host.

The session token a login issues is added to the redaction set with scrim's other store credentials.
No token, role ID, secret ID or service account token appears in an error.

## Kubernetes auth

When scrim runs in a Kubernetes cluster it logs in with its own pod's service account token, so the
cluster holds no OpenBao token, role ID or secret ID for scrim. OpenBao checks the token with the
Kubernetes TokenReview API and issues a token with the role's policies.

```yaml
stores:
  bao:
    kind: openbao
    address: https://bao.example.com:8200
    auth:
      method: kubernetes
      kubernetes:
        role: scrim
        token-file: /var/run/secrets/tokens/openbao
```

scrim reads `token-file` at every login, never only at start-up, because the kubelet rotates
projected tokens and an old one stops working. The token lives in wiped memory for the length of
the login request and is not kept. `token`, `role-id` and `secret-id` are refused with
`auth.method: kubernetes`, so a static credential left in the configuration is noticed.

Mount a projected token whose audience is meant for OpenBao alone, rather than the default
service account token, whose audience is the Kubernetes API server. A token leaked from OpenBao's
side is then useless against the API server, and the other way round:

```yaml
# scrim Deployment, pod spec
serviceAccountName: scrim
containers:
  - name: scrim
    volumeMounts:
      - {name: openbao-token, mountPath: /var/run/secrets/tokens, readOnly: true}
volumes:
  - name: openbao-token
    projected:
      sources:
        - serviceAccountToken:
            path: openbao
            audience: openbao
            expirationSeconds: 3600
```

On the OpenBao side, enable the method, point it at the cluster and bind a role to scrim's service
account name and namespace and to the audience:

```sh
bao auth enable kubernetes
# Run from a pod in the cluster, OpenBao can find the API server and its CA itself:
bao write auth/kubernetes/config kubernetes_host=https://kubernetes.default.svc:443
# Outside the cluster, also pass kubernetes_ca_cert=@ca.crt and a reviewer token
# (token_reviewer_jwt=...) of a service account allowed to create TokenReviews.
bao write auth/kubernetes/role/scrim \
  bound_service_account_names=scrim bound_service_account_namespaces=scrim \
  audience=openbao token_policies=scrim token_ttl=20m token_max_ttl=4h
```

OpenBao checks each login with a TokenReview, so the token it reviews with needs
`system:auth-delegator`:

- OpenBao in the cluster, no `token_reviewer_jwt`: OpenBao's own service account.
- `token_reviewer_jwt` set: the service account that token belongs to.
- OpenBao outside the cluster, no `token_reviewer_jwt`: OpenBao reviews with the client's own
  token, so scrim's service account needs the binding. The API server only accepts that token if
  its audience is the API server's, so this mode rules out a dedicated audience. Prefer a reviewer
  token.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: openbao-tokenreview
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: system:auth-delegator}
subjects:
  - {kind: ServiceAccount, name: openbao, namespace: openbao}
```

Outside that last mode, scrim's service account needs no Kubernetes RBAC. A wrong role, a token
outside the role's bound names, namespaces or audience, a missing mount, and an unreadable or empty
token file are all reported as permission errors naming the store; the token file error also names
the file and the option.

### Agents' own identity (passthrough)

scrim's own login loads the redaction set. To have OpenBao's policies decide what each agent pod may
use as well, set `identity.store-login` (see [Agent identity](../identity.md#store-identity-per-agent)):

```yaml
identity:
  kubernetes: {enabled: true}
  store-login:
    bao: "kubernetes role:{namespace}-{service_account}"
```

Every injection or restore of a `bao` secret then goes to the control plane. Once scrim's rules allow
it, scrim logs in at `auth/kubernetes/login` with the calling pod's own scrim-audience token and the
rendered role, and asks `sys/capabilities-self` whether that token may read the secret's
`<mount>/data/<path>`. It never reads the value with the agent's token. The login is cached for two
thirds of its lease, per pod token, and a rotated pod token is a new login. Each agent role binds one
service account and accepts scrim's audience:

```sh
bao write auth/kubernetes/role/agents-agent-a \
  bound_service_account_names=agent-a bound_service_account_namespaces=agents \
  audience=scrim token_policies=agent-a token_ttl=10m
```

Agents that are not pods can use a static token instead, `identity.store-credentials:
{bao/laptop: file:/run/secrets/bao-laptop}`, checked the same way. With either setting, an agent
that has neither is refused for this store. `scrim doctor` lists which one applies to each agent.

## Least privilege

scrim needs to read only what it redacts or injects, and to write only where agents capture or
generate secrets. Agents never read a value back whatever the policy allows. That rule is enforced
by scrim, so a policy is only an extra line of defence.

```hcl
# scrim.hcl: read and write the agents tree.
path "kv/data/agents/*"              { capabilities = ["create", "read", "update"] }
path "kv/metadata/agents/*"          { capabilities = ["list", "read", "update"] }
path "kv/detailed-metadata/agents/*" { capabilities = ["list"] }

# Write-only inbox: scrim stores what agents capture and can never read it back.
path "kv/data/agents/inbox/*"              { capabilities = ["create", "update"] }
path "kv/metadata/agents/inbox/*"          { capabilities = ["list"] }
path "kv/detailed-metadata/agents/inbox/*" { capabilities = ["list"] }
```

- `update` on `metadata/` is needed only for labels (custom metadata such as `scrim.hosts`). Drop
  it if you do not write labels.
- `list` on `detailed-metadata/` makes watch cheap. Without it the adapter falls back to listing
  `metadata/` and reading each secret's metadata, which needs `read` on `metadata/`.
- `read` on `metadata/` also fills the metadata [labels](#labels) of a read. Without it reads still
  work and those labels are missing.
- `read` on `metadata/` lets policy label an existing secret that is not in a redaction set (a
  write to it, `scrim catalog labels`) from its metadata alone, without reading its value. Without
  it scrim reads the secret's data and wipes the values at once, as for a store that has no
  metadata read. Paths in `write-only-paths` are refused either way.
- `token/lookup-self` (in the `default` policy) is used by the health check.
- Grant no `delete` or `destroy`. scrim never deletes from a store.

For a write-only path, use a policy like the inbox above and also list the prefix in
`write-only-paths`. scrim then marks those secrets as write-only, never tries to read them back,
and redacts only the value it wrote, which stays in memory for the retention period. Without
`write-only-paths` scrim would try the read and the store would refuse it. That is still safe, but
it is reported as a refresh error.

```sh
bao policy write scrim scrim.hcl
bao auth enable approle
bao write auth/approle/role/scrim token_policies=scrim token_ttl=20m token_max_ttl=1h \
  secret_id_ttl=720h secret_id_num_uses=0
bao read -field=role_id auth/approle/role/scrim/role-id > /run/secrets/bao-role-id
bao write -f -field=secret_id auth/approle/role/scrim/secret-id > /run/secrets/bao-secret-id
chmod 0400 /run/secrets/bao-role-id /run/secrets/bao-secret-id
```

## Errors

Errors name the store, the operation and the reference, never a value. If the store's own message
contains any value sent in the request, it is replaced by `(store message withheld)`.

| Store answer | Error kind |
| -------------- | ------------ |
| 403, failed AppRole or Kubernetes login, unreadable token file | permission denied by store |
| 404, deleted or destroyed version | not found |
| 400 check-and-set mismatch | conflict |
| other 400, 405 | invalid reference |
| unreachable, timeout, 429, 5xx, sealed | store unavailable (scrim keeps the last known values; see [outages](README.md#freshness-and-outages)) |

## Limitations

- KV version 2 only. KV v1, dynamic secrets and leases come with the `vault` adapter.
- Control groups are a Vault Enterprise feature and are not supported yet.
- Values are decoded straight into wiped memory, but the token header goes through Go's HTTP
  client as a string for the length of each request.
- A soft-deleted current version is reported as deleted. Undeleting it makes the secret reappear
  on the next poll. A version whose deletion time is still in the future (set by
  `delete_version_after`) is read and listed as usual until that time.

## Testing

`go test -race ./internal/stores/openbao/` runs unit tests against an in-process fake. With podman
available it also starts `quay.io/openbao/openbao:2.7.3` in dev mode, sets up a KV v2 mount, the
policy above and an AppRole role with a 30 second TTL, and then runs these checks. The first is
the conformance suite, with the outage simulated by pausing the container. The second covers
token auth and the write-only policy. The third stops the store mid-run under the refresher. The
fourth creates a described mount and a secret with version settings and custom metadata, then
checks its labels through a token with full access and one that may only read the data, and that
`ReadMetadata` reports the same labels without reading the value. A last test writes a name with
a space and a `%` and checks OpenBao stores it under that name, and that a secret stored under the
double-escaped name of 0.4.0 and earlier is still read. See the
[stores overview](README.md#conformance) for the switches.

Kubernetes auth is covered by the unit tests: an in-process OpenBao checks the login body,
renew-self, renewal refused then a fresh login, a rotated token file picked up at the next login,
refusals mapped to permission errors, and that no generated token or JWT appears in any error. The
end-to-end check runs in a kind cluster.
