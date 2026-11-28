# Infisical

The `infisical` adapter reads, lists, watches and writes secrets in Infisical, self-hosted or
Infisical Cloud. scrim logs in with a Universal Auth machine identity, or in a Kubernetes cluster with
a Kubernetes Auth identity and its own pod's service account ([Kubernetes Auth](#kubernetes-auth)),
and is the only holder of that identity's credentials. Agents never call Infisical: they ask scrim,
which enforces write-only toward agents itself. That works with the built-in project roles of the
free self-hosted edition, so no paid custom roles are needed.

## Capabilities

<!-- BEGIN GENERATED STORE CAPABILITIES kinds=infisical -->

| Kind | read | list | watch | write | glob | dynamic | per-agent check | `identity.store-login` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `infisical` | yes | yes | yes | yes | no | no | yes | `infisical-oidc` |

The columns are explained under [Capabilities](README.md#capabilities).

<!-- END GENERATED STORE CAPABILITIES -->

Watch polls; see [Watch and refresh](#watch-and-refresh).

## References

```text
<scheme>://<project>/<environment>/<folder>/.../<KEY>[?version=<n>][#value]
```

- `<scheme>` is the store instance name (or one of its aliases), for example `inf://`.
- `<project>` is the project slug (shown under Project Settings, for example `acme-k2x9`) or the
  project ID. A slug is resolved to the ID once and cached.
- `<environment>` is the environment slug: `dev`, `staging`, `prod` or your own.
- The segments between environment and key are the folder path. `inf://acme-k2x9/prod/API_KEY` is
  key `API_KEY` in folder `/`; `inf://acme-k2x9/prod/agents/github/TOKEN` is key `TOKEN` in folder
  `/agents/github`.
- An Infisical secret holds one value, exposed as the field `value`. `#value` is accepted; any
  other field reads as not found, and a write with any other field name is refused.
- `?version=<n>` reads an older version. Any other selector is refused rather than ignored.

A listing prefix stops at the environment or a folder: `inf://acme-k2x9/prod` lists the whole
environment, `inf://acme-k2x9/prod/agents` everything under `/agents`, recursively. A trailing `/*`
is accepted, so the catalog's bulk form `inf://acme-k2x9/prod/*` lists the same as
`inf://acme-k2x9/prod`. Listing never asks Infisical for values.

## Setup

1. In the organisation, open **Access Control > Identities** and create an identity, for example
   `scrim`, with organisation role **No Access**. scrim needs no organisation-level permission.
2. On the identity, add the **Universal Auth** method. Keep the default access token TTL (scrim
   logs in again before the token expires) and, where you can, set **Client Secret Trusted IPs** and
   **Access Token Trusted IPs** to the addresses scrim runs from.
3. Create a client secret and store it where scrim reads credentials from: a file readable only by
   scrim, a systemd credential, a Kubernetes secret or an environment variable. Note the client ID.
4. In each project scrim should serve, open **Access Control > Machine Identities**, add the identity
   and pick its role (see below).

### Least privilege

Infisical's built-in project roles are coarse: **Viewer** reads every environment of the project,
**Developer** and **Admin** can also write. Fine-grained per-environment and per-folder roles need
custom roles, which are a paid feature. Lay projects out so the built-in roles fit:

- A project scrim only reads from (secrets for redaction and injection): add the identity as
  **Viewer**. Writes are then refused by Infisical as well as by scrim.
- A project scrim writes captured and generated secrets into: add the identity as **Developer**.
  Point rules' default write target at a dedicated environment or folder of that project, for example
  `inf://agents-k2x9/dev/inbox/`.
- Do not give the identity **Admin**: scrim never manages members, environments, integrations or
  project settings.
- Keep secrets scrim must not see in projects the identity is not a member of. Membership, not
  scrim, decides what scrim's credentials can reach.

Whatever the role, agents only ever get references and metadata from scrim, never a value. If you
have custom roles, an identity with `create` and `edit` but not `read` on a folder works for writes;
scrim then keeps only the value it wrote in the redaction set.

## Configuration

Each instance is configured under `stores.<instance>`. The generic keys every store takes (`kind`,
`aliases`, `redact`, `refresh.*`) are shared by every store and handled by scrim; the keys below are
the adapter's own. Every key can also be set as an environment
variable: `SCRIM_` followed by the full key upper-cased, with dots and dashes as `_`. Nested and
dotted forms are equivalent in the file. Unknown keys fail validation and name the closest known key.

```yaml
stores:
  inf:
    kind: infisical
    address: https://infisical.example.com
    auth:
      method: universal-auth
    client-id: 74e8b22b-ac55-4cf6-8d9b-d6334d9e4e80
    client-secret: file:/run/credentials/scrim/infisical-client-secret
    watch:
      interval: 30s
```

| Key | Environment variable (instance `inf`) | Type | Default | Meaning |
| ----- | ---------------------------------------- | ------ | --------- | --------- |
| `stores.<name>.address` | `SCRIM_STORES_INF_ADDRESS` | URL | required | Base URL of the Infisical server. For Infisical Cloud use `https://app.infisical.com` (US) or `https://eu.infisical.com` (EU). There is no default, so scrim never contacts a server you did not name. |
| `stores.<name>.auth.method` | `SCRIM_STORES_INF_AUTH_METHOD` | string | `universal-auth` | `universal-auth` or `kubernetes-auth`. |
| `stores.<name>.client-id` | `SCRIM_STORES_INF_CLIENT_ID` | secret reference | required for `universal-auth` | The identity's client ID. Not secret on its own, but half of the credential, so it is taken as a reference (a literal is fine). |
| `stores.<name>.client-secret` | `SCRIM_STORES_INF_CLIENT_SECRET` | secret reference | required for `universal-auth` | `file:`, `env:`, a systemd credential or a store reference. A reference that does not resolve, or resolves to an empty value, stops start-up. A literal works but logs a warning. |
| `stores.<name>.auth.kubernetes.identity-id` | `SCRIM_STORES_INF_AUTH_KUBERNETES_IDENTITY_ID` | string | required for `kubernetes-auth` | ID of the machine identity with Kubernetes Auth. Not a secret. |
| `stores.<name>.auth.kubernetes.token-file` | `SCRIM_STORES_INF_AUTH_KUBERNETES_TOKEN_FILE` | path | `/var/run/secrets/kubernetes.io/serviceaccount/token` | Service account token presented at login, read again at every login. Point it at a projected token with a dedicated audience. |
| `stores.<name>.timeout` | `SCRIM_STORES_INF_TIMEOUT` | duration | `10s` | Per-request timeout. A timed-out request counts as the store being unavailable. |
| `stores.<name>.tls.ca-file` | `SCRIM_STORES_INF_TLS_CA_FILE` | path | system roots | PEM bundle to verify the server with, for a private CA. |
| `stores.<name>.watch.interval` | `SCRIM_STORES_INF_WATCH_INTERVAL` | duration | `30s` | How often the listing is polled for changes, with +-20% jitter. |
| `stores.<name>.watch.max-backoff` | `SCRIM_STORES_INF_WATCH_MAX_BACKOFF` | duration | `5m` | Longest wait between polls while Infisical keeps failing. |
| `stores.<name>.create-folders` | `SCRIM_STORES_INF_CREATE_FOLDERS` | bool | `true` | Create missing folders on write. With `false`, a write into a missing folder fails as not found. |
| `stores.<name>.expand-references` | `SCRIM_STORES_INF_EXPAND_REFERENCES` | bool | `true` | Expand Infisical secret references (`${KEY}`, `${env.folder.KEY}`) on read, as the Infisical CLI does when it injects secrets, so the value scrim redacts is the value your applications see. |

With either method scrim logs in when it first needs an access token and logs in again before the
token runs out: a tenth of `expiresIn` before it, at least 30 seconds, or halfway for very short
tokens. A fresh login rather than a renewal means the token's max TTL never cuts a session short. A
401, or a 403 about the token, drops it and logs in again once. The access token is added to the
redaction set; no client secret, access token or service account token appears in an error.

## Kubernetes Auth

When scrim runs in a Kubernetes cluster it can log in with its own pod's service account token, so
the cluster holds no client secret for scrim. Infisical checks the token with the Kubernetes
TokenReview API and issues an access token for the identity.

```yaml
stores:
  inf:
    kind: infisical
    address: https://infisical.example.com
    auth:
      method: kubernetes-auth
      kubernetes:
        identity-id: 2dd11664-68e3-471d-b366-907206ab1bff
        token-file: /var/run/secrets/tokens/infisical
```

The login is `POST /api/v1/auth/kubernetes-auth/login` with `identityId` and the token as `jwt`.
scrim reads `token-file` at every login, because the kubelet rotates projected tokens and an old one
stops working. The token lives in wiped memory for the length of the login request and is not kept.
`client-id` and `client-secret` are refused with `kubernetes-auth`, so a static credential left in
the configuration is noticed.

Mount a projected token with an audience meant for Infisical alone, so a token leaked on one side is
useless on the other:

```yaml
# scrim Deployment, pod spec
serviceAccountName: scrim
containers:
  - name: scrim
    volumeMounts:
      - {name: infisical-token, mountPath: /var/run/secrets/tokens, readOnly: true}
volumes:
  - name: infisical-token
    projected:
      sources:
        - serviceAccountToken:
            path: infisical
            audience: infisical
            expirationSeconds: 3600
```

In Infisical:

1. Create the identity as in [Setup](#setup), but add the **Kubernetes Auth** method instead of
   Universal Auth.
2. Set **Kubernetes Host / Base Kubernetes API URL** to the API server Infisical can reach, and the
   **CA Certificate** if it is private.
3. Set **Token Reviewer JWT** to the token of a dedicated reviewer service account (see below).
   Left empty, Infisical reviews with scrim's own token, which then needs the RBAC binding and an
   audience the API server accepts, so a dedicated audience is ruled out. Enterprise editions can
   use a gateway as the reviewer instead.
4. Set **Allowed Service Account Names** to `scrim`, **Allowed Namespaces** to the namespace scrim
   runs in (here `scrim`) and **Allowed Audience** to `infisical`.
5. Keep a short **Access Token TTL**, for example 20 minutes. scrim logs in again before it ends.
6. Note the identity ID for `auth.kubernetes.identity-id` and add the identity to projects as in
   [Least privilege](#least-privilege).

The reviewer service account needs `system:auth-delegator`. With a reviewer token, scrim's own
service account needs no Kubernetes RBAC:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata: {name: infisical-token-reviewer, namespace: scrim}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: infisical-token-reviewer}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: system:auth-delegator}
subjects:
  - {kind: ServiceAccount, name: infisical-token-reviewer, namespace: scrim}
---
# A long-lived token for the reviewer, to paste into Infisical.
apiVersion: v1
kind: Secret
metadata:
  name: infisical-token-reviewer
  namespace: scrim
  annotations: {kubernetes.io/service-account.name: infisical-token-reviewer}
type: kubernetes.io/service-account-token
```

A wrong identity ID, a token outside the allowed names, namespaces or audience, and an unreadable or
empty token file are all reported as permission errors naming the store; the token file error also
names the file and the option.

## Policy labels

Every secret the adapter reads or lists carries labels describing where it lives in Infisical and how
Infisical treats it, so [policy rules](../policy.md) can match on project, environment, folder, tags
and the rest through `secret.labels`. Labels are metadata: they never hold a secret value.

Infisical's own attributes are under `infisical.<attr>`. A multi-valued attribute has a comma-joined
key plus one presence key per value set to `"true"`, so `"infisical.tag.pci" in secret.labels` tests
for a tag without parsing a list. Secret metadata (the key/value pairs on a secret) is copied under
`infisical.meta.<key>`.

| Key | Example | Meaning |
| --- | --- | --- |
| `infisical.org.id` | `0b7c...` | Organisation ID of the project. The organisation's name is not read: the identity has no organisation permission. |
| `infisical.project` | `payments` | Project slug; the project ID when the project is addressed by ID and its details cannot be read. |
| `infisical.project.id` | `6a1b2c3d-...` | Project ID. |
| `infisical.project.slug` | `payments` | Project slug. |
| `infisical.project.name` | `Payments` | Project display name. |
| `infisical.environment` | `prod` | Environment slug from the reference. |
| `infisical.environment.name` | `Production` | Environment display name. |
| `infisical.environment.id` | `9f2e...` | Environment ID. |
| `infisical.folder` | `/db/Primary` | Folder path as Infisical spells it, `/` at the root. |
| `infisical.folder.<a>[.<b>...]` | `infisical.folder.db`, `infisical.folder.db.Primary` = `true` | One presence key per folder on the way down: the path below `/` with `/` written as `.`, folder names as spelt. Nothing for the root. |
| `infisical.key` | `PASSWORD` | Secret key name, case kept. |
| `infisical.path` | `/db/Primary/PASSWORD` | Folder and key together. |
| `infisical.type` | `shared` | Secret type. scrim reads shared secrets only, so this is `shared`. |
| `infisical.version` | `3` | Version number. |
| `infisical.created`, `infisical.updated` | `2026-03-04T05:06:07Z` | Creation and last update time, RFC 3339 in UTC; `timestamp(secret.labels["infisical.updated"])` turns one into a CEL timestamp. |
| `infisical.tag` | `pci,prod` | Tag slugs, comma-joined. Absent when the secret has no tags. |
| `infisical.tag.<slug>` | `infisical.tag.pci` = `true` | One presence key per tag. |
| `infisical.meta.<key>` | `infisical.meta.owner` = `payments-team` | Unencrypted secret metadata, key normalised as below, value as stored. |
| `infisical.encrypted-meta` | `card-pin` | Keys of encrypted metadata entries, comma-joined; their values are never read into labels. Absent when there are none. |
| `infisical.encrypted-meta.<key>` | `infisical.encrypted-meta.card-pin` = `true` | One presence key per encrypted metadata key. |
| `infisical.rotation` | `true` / `false` | The secret is managed by an Infisical secret rotation. |
| `infisical.rotation.id` | `1111...` | ID of that rotation. |
| `infisical.reminder` | `true` / `false` | A secret reminder is set. Listings only: Infisical leaves reminders out of a single read, so a read omits the key rather than say `false`. The reminder note is free text and is not exposed. |
| `infisical.reminder.days` | `30` | Reminder interval in days. |
| `infisical.imported` | `true` / `false` | The value was served through a secret import rather than stored in the folder itself. Only a read can tell; listings never include imported secrets, so they say `false`. |
| `infisical.import.environment`, `infisical.import.path` | `dev`, `/shared` | Where an imported secret really lives. |

Keys an attribute does not apply to are left out (`infisical.tag` on an untagged secret,
`infisical.rotation.id` without a rotation, names when the identity may not read the project), so
test them with `in`. Booleans are always written as `true` or `false` when Infisical reports the
attribute, so a rule can compare them without guarding against a missing key.

### Normalisation

The fixed part of a key is lower-case ASCII. The part that names a value is kept as Infisical spells
it: tag slugs (already lower-case letters, digits and `-`) and folder names (letters, digits, `-` and
`_`, case kept), so `/db/Primary` gives `infisical.folder.db.Primary` and a rule matches exactly the
folder it names. Metadata keys are free text, so they are folded: lower-cased, split on `.`, empty
segments dropped, and every character other than a letter, digit, `-` or `_` replaced by `_`.
Metadata key `Cost Center` is `infisical.meta.cost_center`; if two keys fold to the same name, the
first one Infisical returns wins. Tags are identified by slug, not by display name, because names are
free text that can be renamed.

### What metadata can and cannot do

Native keys are computed by scrim from what Infisical reports and set before `infisical.meta.*`,
which never overwrites a key, and every metadata key in the `infisical.` namespace (in any case,
with or without surrounding space) is left out of the top level. A metadata entry
`infisical.environment = dev` on a secret in `prod` therefore shows up as
`infisical.meta.infisical.environment` and cannot change `infisical.environment`. Anyone who can
edit metadata can set `infisical.meta.*` keys, so rules that grant access should match native keys;
use metadata for asks and denies, or for keys only trusted people edit.

Unencrypted metadata also keeps arriving under its own key, as it did before native labels existed:
`scrim.hosts`, `scrim.placeholder` and the other [catalog](../catalog.md) keys work unchanged. Two
things changed with native labels:

- Encrypted metadata entries are no longer copied. Infisical returns them decrypted, and they exist
  for sensitive text, so only their keys appear, in `infisical.encrypted-meta`.
- A write drops labels in the `infisical.` namespace instead of storing them as metadata, where they
  could only pose as native keys. Other labels are stored as before.

The secret comment and the reminder note are not exposed at all, not even behind an option: both are
free text that people do paste values into, and labels are shown to agents, logged and audited.
Put attributes a rule needs into metadata instead.

### Example rules

Anything in project `payments` that is in `prod`, under `/db` or tagged `pci` needs a human, for reads
and writes alike; a tag `agents-never` keeps agents away; everything else in the store is allowed:

<!-- policy-example -->
```yaml
default: deny
rules:
  - name: payments-sensitive
    decision: ask
    reason: prod, /db and PCI secrets of payments need a human
    when: >-
      op in ["store.read", "store.write", "inject"] && secret.store == "inf" &&
      secret.labels["infisical.project.slug"] == "payments" &&
      (secret.labels["infisical.environment"] == "prod" ||
       "infisical.folder.db" in secret.labels ||
       "infisical.tag.pci" in secret.labels)
  - name: agents-never
    decision: deny
    when: secret.store == "inf" && "infisical.tag.agents-never" in secret.labels
  - name: infisical-rest
    decision: allow
    when: op in ["store.read", "store.write"] && secret.store == "inf"
```

A rule that indexes a label the secret does not have fails, and a failing ask or deny rule counts as
matching, so a project whose details the identity cannot read is asked about rather than allowed.

More patterns:

```cel
secret.labels["infisical.path"].glob("/db/**")                      // anything below /db
secret.labels["infisical.project.slug"] in ["payments", "billing"]  // either project
secret.labels["infisical.imported"] == "true"                       // served through an import
"infisical.meta.owner" in secret.labels && secret.labels["infisical.meta.owner"] != agent.labels.team
timestamp(secret.labels["infisical.updated"]) < now - duration("2160h")  // not rotated in 90 days
```

For `store.write`, the adapter also tells scrim which labels a secret at the target reference would
get (`infisical.project*`, `infisical.environment*`, `infisical.folder*`, `infisical.key`,
`infisical.path` and `infisical.type`) without contacting Infisical, so a write rule matches on
environment and folder before the secret exists. Project and environment names appear there once an
earlier read or listing has fetched them.

### Cost

A project addressed by slug is described by the call that resolves the slug, which scrim already
made. A project addressed by ID costs one `GET /api/v1/projects/{id}` the first time. If that is
refused, labels carry the ID only and the lookup is retried after five minutes rather than at every
read. Everything else comes with the secret itself.

### Labels without the value

When a rule needs the labels of a secret that is not in a redaction set (a write to an existing
secret, or `scrim catalog labels`), scrim asks for the secret with `viewSecretValue=false` and
without expanding references. Infisical answers with its hidden-value mask in place of the value, and
scrim wipes whatever is in that field unread. The labels are the ones a read reports. A failure
(unreachable, refused, unknown project or environment) fails the lookup, and the rule is decided as
if the labels were unknown; a secret that does not exist gets the labels of a new one.

## Watch and refresh

Self-hosted Infisical has no change feed scrim can subscribe to, so the adapter polls the listing of
each watched prefix (names, versions and update times, never values) every `watch.interval` with
random jitter, so replicas and stores do not refresh in step. A new or rotated secret is reported as
changed and a removed one as deleted; scrim then reads only what changed. While Infisical is down
the poll backs off exponentially up to `watch.max-backoff` and the watch keeps running, so changes
made during or after an outage are picked up once the server answers again. Until then scrim keeps
redacting the last values it loaded and reports the store as degraded.

## Errors

Errors name the store, the operation and the reference, never a value. Infisical's own message is
included when it does not contain a value involved in the request, and is withheld otherwise.

| Infisical says | scrim reports |
| ---------------- | --------------- |
| 401, or 403 about the token | logs in again once, then permission denied |
| login refused (bad client secret, identity or service account token), unreadable token file | permission denied |
| 403 | permission denied |
| `secretValueHidden: true` on a read (the identity may describe the secret, not read its value) | permission denied; the mask is wiped, never used as the value |
| 404 (secret, version, folder, project or environment) | not found |
| 400 "already exists" on a create-only write | conflict |
| 429, 5xx, timeout, connection refused | store unavailable |
| other 400 | invalid reference |

## Values Infisical changes

Infisical trims leading and trailing whitespace from every value it stores, keeping one trailing
newline if the value ended with one. scrim refuses to write a value Infisical would change (for
example one ending in a space or in two newlines), with an error saying so and without the value,
rather than redact and inject something that differs from what is stored. Choose another store for
such values.

## Limitations

- The access token goes into an HTTP `Authorization` header, which Go's HTTP client takes as a
  string. That string lives only for the request but cannot be wiped like scrim's own value type.
  Values themselves never become strings: they move between the JSON body and scrim's secret type
  directly, and request and response bodies are zeroed after use.
- Personal secret overrides are ignored; scrim reads and writes shared secrets only.
- Secret imports are not followed when listing. Reference the source project directly. A read that
  Infisical answers from an import is labelled `infisical.imported`.
- Dynamic secrets are not read, so there are no labels for them.
- Per-agent store identity ([Agent identity](../identity.md#store-identity-per-agent)) works with a
  static Infisical access token per agent (`identity.store-credentials`) or with `infisical-oidc`,
  which logs in to a machine identity's OIDC Auth with an identity token scrim signs for the agent.
  Infisical has no call that reports a machine identity's permissions, so the per-agent check is the
  read itself, with the value wiped unread, and a write check is refused as unsupported. The only
  permissions endpoint (`GET /api/v1/projects/{id}/permissions`, undocumented) accepts user
  sessions, not machine identity tokens, and there is no dry run for a secret write. Infisical's
  audit log names the agent's machine identity for its reads. Kubernetes passthrough is not
  supported; use `infisical-oidc`.
- Infisical's own approval workflows are not used.

## Testing against a local Infisical

The integration test plays `internal/stores/infisical/testdata/pod.yaml` (Infisical, PostgreSQL and
Redis in one pod) with rootless podman, generates every key and password, bootstraps an
organisation, two projects and a machine identity through the API, runs the shared conformance
suite, pauses the backend container to check outage behaviour, and removes the pod:

```sh
go test -run TestConformanceInfisical -v ./internal/stores/infisical/
```

It skips when podman is not installed; `SCRIM_TEST_PODMAN=1` turns the skip into a failure.
`SCRIM_TEST_INFISICAL_VERSION` picks another image tag. To run it against an existing server
instead, set `SCRIM_TEST_INFISICAL_ADDR`, `SCRIM_TEST_INFISICAL_TOKEN` (an organisation admin
identity token) and `SCRIM_TEST_INFISICAL_ORG` (the organisation ID); the outage case is skipped then.
