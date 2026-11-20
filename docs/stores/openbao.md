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

## Capabilities

| read | list | watch | write | generate | dynamic |
|------|------|-------|-------|----------|---------|
| yes  | yes  | yes   | yes   | no       | no      |

- **List** walks a folder recursively and returns names and metadata only (version, times, custom
  metadata), never values. Soft-deleted and destroyed secrets are left out.
- **Watch** polls version metadata every `watch.interval` (with ±20% jitter) and reports changed
  and deleted secrets. On OpenBao one `LIST .../detailed-metadata/<folder>` per folder returns
  every key's version, so a poll costs a few requests however many secrets there are. On Vault,
  which lacks that endpoint, the adapter falls back to reading each secret's metadata. A failing
  poll backs off exponentially up to `watch.max-backoff` and the watch carries on.
- **Write** creates a new version with `POST <mount>/data/<path>`. It needs `create` (new secret)
  or `update` (new version), never `read`. Create-only writes use check-and-set version 0.
  Labels are written to the secret's custom metadata.

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
  on the next poll.

## Testing

`go test -race ./internal/stores/openbao/` runs unit tests against an in-process fake. With podman
available it also starts `quay.io/openbao/openbao:2.7.3` in dev mode, sets up a KV v2 mount, the
policy above and an AppRole role with a 30 second TTL, and then runs three things. The first is
the conformance suite, with the outage simulated by pausing the container. The second covers
token auth and the write-only policy. The third stops the store mid-run under the refresher. See
the [stores overview](README.md#conformance) for the switches.

Kubernetes auth is covered by the unit tests: an in-process OpenBao checks the login body,
renew-self, renewal refused then a fresh login, a rotated token file picked up at the next login,
refusals mapped to permission errors, and that no generated token or JWT appears in any error. The
end-to-end check runs in a kind cluster.
