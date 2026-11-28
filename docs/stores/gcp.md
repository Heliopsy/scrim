# Google Secret Manager

The `gcpsm` adapter reads, lists, watches and writes secrets in Google Secret Manager, global or
regional. scrim authenticates with Application Default Credentials, so on GKE with Workload Identity,
on Compute Engine or Cloud Run, or with workload identity federation from another platform it needs
no key at all. A service account key, an impersonated service account or a short-lived access token
work too, each taken by reference. Agents never call Google: they ask scrim, which enforces
write-only toward agents itself.

## Capabilities

<!-- BEGIN GENERATED STORE CAPABILITIES kinds=gcpsm -->

| Kind | read | list | watch | write | glob | dynamic | per-agent check | `identity.store-login` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `gcpsm` | yes | yes | yes | yes, not with `read-only: true` | yes | no | yes | `gcp-workload-identity` |

The columns are explained under [Capabilities](README.md#capabilities).

<!-- END GENERATED STORE CAPABILITIES -->

Write is dropped with `read-only: true`. Watch polls; see [Watch and refresh](#watch-and-refresh).

An agent's own Google identity, from `gcp-workload-identity` token exchange or a static access
token per agent, is checked before an injection or restore with `testIamPermissions` for
`secretmanager.versions.access`. No value is read with the agent's token
([Agent identity](../identity.md#store-identity-per-agent)).

## References

```text
<scheme>://<path>[?version=<n|latest|alias>][#<field>]
```

- `<scheme>` is the store instance name (or one of its aliases), for example `gsm://`.
- Secret Manager secret IDs are flat: letters, digits, `-` and `_`, up to 255 characters. scrim joins
  the path's segments with the path separator (`--` by default, option `path-separator`) to form the
  ID, so `gsm://agents/github` is the secret `agents--github` and a secret named `ci--deploy--token`
  lists as `gsm://ci/deploy/token`. A plain ID without the separator is a one-segment path:
  `gsm://GITHUB_TOKEN`.
- A path segment may not contain the separator or start or end with one of its characters (`a-/b`
  would read back as `a/-b`); such a write is refused instead of landing under a name that lists as
  another path. Secrets whose IDs do not map back to a path (`a---b`, `-x`) are left out of listings
  and cannot be addressed; rename them or pick another separator.
- Secrets live in the configured `project`, or in the project the credentials name. With `location`
  set, the instance addresses the regional secrets of that region instead of global ones. Use one
  instance per project or region.
- With `format: raw` (the default) a secret holds one value, the field `value`; `#value` is accepted
  and any other field reads as not found. With `format: json` the payload is a JSON object and each
  member is a field (`gsm://db/main#password`); strings are unquoted, other JSON values keep their
  JSON text, `null` members are skipped, and a payload that is not an object is refused.
- `?version=` reads a version by number (`3`), `latest` (the default) or a [version
  alias](https://cloud.google.com/secret-manager/docs/assign-alias-to-secret-version) (`stable`).
  Any other selector is refused rather than ignored.

A listing prefix selects a path and everything under it (`gsm://agents` lists `agents--github` and
`agents--ci--token`, not `agents-old`); a trailing `/*` is the same. Because IDs are flat the store
also takes globs: `gsm://GITHUB_*` lists every secret whose path starts with `GITHUB_`. Listing never
asks Google for payloads.

## Setup

1. Enable the Secret Manager API in the project.
2. Give scrim an identity. On GKE, enable Workload Identity Federation for GKE and either grant roles
   to the Kubernetes service account's principal
   (`principal://iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<project>.svc.id.goog/subject/ns/scrim/sa/scrim`)
   or bind it to a Google service account. Elsewhere, create a service account for scrim and attach
   it to the VM or Cloud Run service, or configure workload identity federation for the platform
   scrim runs on.
3. Grant the roles below on the project, or per secret where you can.

### Least privilege

| scrim does | Role | Permissions it uses |
| --- | --- | --- |
| Read and list secrets for redaction and injection | `roles/secretmanager.secretAccessor` plus `roles/secretmanager.viewer` | `secrets.list`, `secrets.get`, `versions.get`, `versions.access` |
| Also write captured and generated secrets | `roles/secretmanager.secretVersionAdder` on the target secrets, plus `secrets.create` (for example `roles/secretmanager.admin` on a dedicated project, or a custom role) | `versions.add`, `secrets.create`, `secrets.update` (annotations), `secrets.delete` (only to remove a secret it just created when the first version is refused) |

- Keep the secrets scrim writes in a project of their own, or grant creation through an IAM
  condition on the secret name prefix (`resource.name.startsWith("projects/<number>/secrets/inbox--")`),
  and point rules' default write target there.
- Accessor without viewer works for single secrets addressed by reference, but listing, redact
  prefixes, watch and the catalog need `secrets.list`, and labels need `secrets.get`.
- Grant on individual secrets for anything scrim must not touch beyond one value; IAM, not scrim,
  decides what scrim's credentials can reach.

Agents only ever get references and metadata from scrim, never a value.

## Configuration

Each instance is configured under `stores.<instance>`. The generic keys every store takes (`kind`,
`aliases`, `redact`, `refresh.*`, `labels`) are described in [the stores overview](README.md); the
keys below are the adapter's own. Every key can also be set as an environment variable: `SCRIM_`
followed by the full key upper-cased, with dots and dashes as `_`. Unknown keys fail validation and
name the closest known key.

```yaml
stores:
  gsm:
    kind: gcpsm
    project: acme-prod
    redact: ["gsm://agents/*"]
```

| Key | Environment variable (instance `gsm`) | Type | Default | Meaning |
| ----- | ---------------------------------------- | ------ | --------- | --------- |
| `stores.<name>.project` | `SCRIM_STORES_GSM_PROJECT` | string | from the credentials | Project ID or number the secrets live in. Required when the credentials name no project (workload identity federation, impersonation, the metadata server outside GCP). |
| `stores.<name>.location` | `SCRIM_STORES_GSM_LOCATION` | string | global | Region of [regional secrets](https://cloud.google.com/secret-manager/regional-secrets/regional-secrets-overview) (`europe-west4`). The instance then uses the regional endpoint `https://secretmanager.<location>.rep.googleapis.com` and only sees that region's secrets. |
| `stores.<name>.endpoint` | `SCRIM_STORES_GSM_ENDPOINT` | URL | the global or regional endpoint | API endpoint, for Private Service Connect or a test server. https, or http on a loopback address. |
| `stores.<name>.auth.method` | `SCRIM_STORES_GSM_AUTH_METHOD` | string | `adc` | `adc`, `credentials` or `access-token`; see [Authentication](#authentication). |
| `stores.<name>.credentials` | `SCRIM_STORES_GSM_CREDENTIALS` | secret reference | required for `credentials` | A credentials JSON file by reference (`file:/run/secrets/gsm.json`, `env:`, a systemd credential or a store reference): a service account key, a workload identity federation configuration, an impersonated service account or gcloud user credentials. |
| `stores.<name>.token` | `SCRIM_STORES_GSM_TOKEN` | secret reference | required for `access-token` | An OAuth access token by reference, for short runs (`gcloud auth print-access-token`). scrim cannot refresh it; once it expires every call fails as permission denied. |
| `stores.<name>.auth.impersonate-service-account` | `SCRIM_STORES_GSM_AUTH_IMPERSONATE_SERVICE_ACCOUNT` | email | none | Act as this service account: the credentials above mint its tokens through IAM Credentials `generateAccessToken`, which needs `roles/iam.serviceAccountTokenCreator` on it. |
| `stores.<name>.auth.delegates` | `SCRIM_STORES_GSM_AUTH_DELEGATES` | list of emails | none | Delegation chain for impersonation. |
| `stores.<name>.format` | `SCRIM_STORES_GSM_FORMAT` | string | `raw` | `raw` (one field, `value`) or `json` (a JSON object of fields). |
| `stores.<name>.path-separator` | `SCRIM_STORES_GSM_PATH_SEPARATOR` | string | `--` | What a `/` in a path becomes in the secret ID. Made of `-` and `_`. |
| `stores.<name>.replication.locations` | `SCRIM_STORES_GSM_REPLICATION_LOCATIONS` | list | automatic | Regions of a user-managed replication policy for secrets scrim creates. Unset means automatic replication. Not for regional instances. |
| `stores.<name>.read-only` | `SCRIM_STORES_GSM_READ_ONLY` | bool | `false` | Declare the store read-only: writes are refused before anything is sent. |
| `stores.<name>.write-only-paths` | `SCRIM_STORES_GSM_WRITE_ONLY_PATHS` | list | none | Path prefixes scrim writes but never reads back; listings report them write-only. |
| `stores.<name>.timeout` | `SCRIM_STORES_GSM_TIMEOUT` | duration | `10s` | Per-request timeout. A timed-out request counts as the store being unavailable. |
| `stores.<name>.watch.interval` | `SCRIM_STORES_GSM_WATCH_INTERVAL` | duration | `30s` | How often the listing is polled for changes, with +-20% jitter. |
| `stores.<name>.watch.max-backoff` | `SCRIM_STORES_GSM_WATCH_MAX_BACKOFF` | duration | `5m` | Longest wait between polls while Google keeps failing. |

## Authentication

`auth.method: adc` (the default) finds credentials the way Google's own libraries do, through
[`golang.org/x/oauth2/google`](https://pkg.go.dev/golang.org/x/oauth2/google):

1. the file `GOOGLE_APPLICATION_CREDENTIALS` names: a service account key, a [workload identity
   federation](https://cloud.google.com/iam/docs/workload-identity-federation) configuration
   (`external_account`, with a file, URL, AWS or executable credential source; executables need
   `GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1`), an impersonated service account or user
   credentials;
2. gcloud's application default credentials file (`gcloud auth application-default login`);
3. the metadata server, on GKE with Workload Identity, Compute Engine, Cloud Run and App Engine.

`auth.method: credentials` takes the same JSON by reference instead of from the environment, so the
file can come from a systemd credential or another store. Its `type` must be one of
`service_account`, `external_account`, `impersonated_service_account`, `authorized_user` or
`external_account_authorized_user`; anything else is refused.

On GKE with Workload Identity nothing is configured at all:

```yaml
stores:
  gsm:
    kind: gcpsm
    project: acme-prod
```

From a Kubernetes cluster outside Google Cloud, federate its service account tokens: create a
workload identity pool with an OIDC provider for the cluster's issuer, mount a projected token with
the provider's audience, and point `GOOGLE_APPLICATION_CREDENTIALS` (or `credentials`) at the
configuration `gcloud iam workload-identity-pools create-cred-config` writes, whose
`credential_source.file` is the token path. scrim reads the token file again at every exchange.

Tokens are fetched on first use and refreshed before they expire; building an adapter (`scrim config
validate`) resolves no reference and contacts nothing. scrim adds the access token it currently uses,
a static `token` and the private key of a `credentials` service account key to the redaction set.
x/oauth2 holds access tokens as Go strings, which cannot be wiped; values never are. Credentials
`GOOGLE_APPLICATION_CREDENTIALS` points to are read by the library, not by scrim, so scrim cannot add
their keys to the redaction set: prefer the metadata server or federation, which have no key, or
`credentials` by reference.

## Policy labels

Every secret the adapter reads or lists carries labels describing where it lives in Secret Manager,
so [policy rules](../policy.md) can match on them through `secret.labels`. Labels are metadata: they
never hold a payload.

| Key | Example | Meaning |
| --- | --- | --- |
| `gcpsm.project` | `acme-prod` | Project as configured (or as the credentials name it). |
| `gcpsm.project.number` | `123456789012` | Project number, from the resource name Google returns. |
| `gcpsm.location` | `global`, `europe-west4` | Region of a regional secret, `global` otherwise. |
| `gcpsm.secret` | `agents--github` | Secret ID. |
| `gcpsm.path` | `agents/github` | Reference path. |
| `gcpsm.replication` | `automatic`, `user-managed`, `regional` | Replication policy. |
| `gcpsm.replica`, `gcpsm.replica.<location>` | `europe-west1,europe-west4` | Replica locations of a user-managed policy, with one presence key each. |
| `gcpsm.kms-key`, `gcpsm.kms-key.<name>` | `projects/k/locations/.../cryptoKeys/a` | Customer-managed encryption keys. |
| `gcpsm.created`, `gcpsm.expires` | `2026-03-04T05:06:07Z` | Creation and expiry time, RFC 3339 in UTC. |
| `gcpsm.rotation.next`, `gcpsm.rotation.period` | `2026-06-01T00:00:00Z`, `2592000s` | Rotation schedule. |
| `gcpsm.topic`, `gcpsm.topic.<name>` | `projects/p/topics/rotations` | Pub/Sub topics notified of changes. |
| `gcpsm.alias`, `gcpsm.alias.<alias>` | `canary,stable` | Every version alias of the secret. |
| `gcpsm.version` | `3` | Version number of the payload described. |
| `gcpsm.version-alias`, `gcpsm.version-alias.<alias>` | `stable` | Aliases pointing at that version. |
| `gcpsm.version.state` | `enabled` | State of that version. |
| `gcpsm.meta.<key>` | `gcpsm.meta.env` = `prod` | Secret labels and annotations, key folded as for other stores; a label wins over an annotation with the same key. |

Keys an attribute does not apply to are left out, so test them with `in`.

Labels and annotations are editable by anyone with `secretmanager.secrets.update`, so they only
appear under `gcpsm.meta.`, which never overwrites a native key. Annotations are also copied under
their own key, so the [catalog](../catalog.md) keys (`scrim.hosts`, `scrim.placeholder`, ...) work
as annotations, which is where scrim stores the labels it writes (Secret Manager labels cannot hold
dots or upper-case letters). Annotation keys under `gcpsm.` are never copied, and a write drops labels
under `gcpsm.` instead of storing them. Rules that grant access should match native keys; use
`gcpsm.meta.*` for asks and denies.

### Example rules

Production secrets need a human, an annotation `agents-never` keeps agents away, everything else in
the store is allowed:

<!-- policy-example -->
```yaml
default: deny
rules:
  - name: gsm-prod
    decision: ask
    reason: production secrets need a human
    when: >-
      op in ["store.read", "store.write", "inject"] && secret.store == "gsm" &&
      (secret.labels["gcpsm.path"].startsWith("prod/") ||
       ("gcpsm.meta.env" in secret.labels && secret.labels["gcpsm.meta.env"] == "prod"))
  - name: gsm-agents-never
    decision: deny
    when: secret.store == "gsm" && "gcpsm.meta.agents-never" in secret.labels
  - name: gsm-rest
    decision: allow
    when: op in ["store.read", "store.write"] && secret.store == "gsm"
```

More patterns:

```cel
secret.labels["gcpsm.location"] == "europe-west4"                 // regional secrets of one region
"gcpsm.version-alias.stable" in secret.labels                      // the version aliased stable
"gcpsm.replica.us-central1" in secret.labels                       // replicated to us-central1
timestamp(secret.labels["gcpsm.created"]) < now - duration("2160h") // older than 90 days
```

For `store.write`, the adapter tells scrim the labels a secret at the target reference would get
(`gcpsm.project`, `gcpsm.location`, `gcpsm.secret`, `gcpsm.path`) without contacting Google.

### Labels without the payload

When policy needs the labels of a secret that is in no redaction set, scrim asks for the Secret and
SecretVersion resources (`secrets.get`, `versions.get`), which never carry the payload. The labels
equal those a read reports for an enabled version; a disabled or destroyed version fails as not
found, as a read does.

## Watch and refresh

Secret Manager can notify Pub/Sub of changes, but scrim does not consume Pub/Sub. The adapter polls:
each listing is `secrets.list` plus one `versions.get` of `latest` per secret under the prefix
(eight at a time), and reports a secret as changed when its latest version, labels or annotations
change, and as deleted when it disappears. The listing reports the version, so the refresher reads
only secrets whose version changed. Watch never reads payloads; with `watch.interval: 30s` and 100
secrets that is about 200 metadata calls a minute, well inside the default quota of 90,000 access
requests per minute per project. Secrets whose latest version is disabled or destroyed, or that have
no version, are left out of listings: there is nothing to read.

## Writes

A write adds a version to the secret, creating the secret first when it does not exist (with
automatic replication, or the `replication.locations` policy; regional instances create regional
secrets). Each version is sent with its CRC32C, so Google refuses a corrupted upload, and every
payload read is checked against the CRC32C Google returns. `WriteOptions` labels become the
secret's annotations, replacing the previous ones; a rotation without labels keeps them.
Create-only writes fail with a conflict when the secret exists. If scrim created a secret and Google
refuses its first version, scrim deletes the empty secret again. Secret Manager has no transaction
across the two calls, so a rotation that changes labels adds the version first and updates the
annotations after it. Payloads are at most 64 KiB; larger writes are refused before anything is sent.

## Errors

| Google says | scrim reports |
| --- | --- |
| 401 `UNAUTHENTICATED`, 403 `PERMISSION_DENIED`, a token endpoint refusing the credentials | permission denied |
| 404 `NOT_FOUND`, 400 `FAILED_PRECONDITION` (disabled or destroyed version) | not found |
| 409 `ALREADY_EXISTS` on a create-only write | conflict |
| 400 `INVALID_ARGUMENT` | invalid reference |
| 429, 5xx, timeouts, connection errors | unavailable |

Errors name the store, operation and reference with Google's own message, which is withheld when it
contains a value the request carried.

## Limitations

- One project and one location (global or a region) per instance.
- Pub/Sub notifications, TTL, expiry and rotation schedules are reported as labels but not managed:
  scrim never sets them on secrets it creates. Customer-managed encryption for created secrets comes
  from organisation policy, not from scrim.
- Version aliases are read, not written; `?version=<alias>` resolves an alias at Google.
- The REST API is used directly; there is no gRPC transport.

## Testing

There is no official Secret Manager emulator. The tests run the shared conformance suite (raw, JSON,
regional and a custom separator) against an in-process fake of the REST API in
`internal/stores/gcpsm/fake_test.go`, which also serves the OAuth token endpoint (service account key
JWTs, verified against the key), STS token exchange (workload identity federation from a token file),
IAM Credentials `generateAccessToken` (impersonation) and the metadata server (GKE workload
identity, through `GCE_METADATA_HOST`). The fake follows the documented resource shapes, names with
the project number, int64 fields as strings, `latest` and alias resolution, `FAILED_PRECONDITION` for
disabled versions, CRC32C checks, replication rules for global and regional secrets and Google's error
envelope. It does not model IAM beyond a token allow list and denied name prefixes, list filters,
ETag preconditions, TTLs, rotation schedules, Pub/Sub, version destruction delays or quotas, so a
behaviour change in the real service only shows up against Google.

```sh
go test -race ./internal/stores/gcpsm/...
```
