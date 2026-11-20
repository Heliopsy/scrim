# Infisical

The `infisical` adapter reads, lists, watches and writes secrets in Infisical, self-hosted or
Infisical Cloud. scrim logs in with a Universal Auth machine identity and is the only holder of that
identity's credentials. Agents never call Infisical: they ask scrim, which enforces write-only toward
agents itself. That works with the built-in project roles of the free self-hosted edition, so no paid
custom roles are needed.

## Capabilities

| Kind        | read | list | watch | write | generate | dynamic |
|-------------|------|------|-------|-------|----------|---------|
| `infisical` | yes  | yes  | yes   | yes   | no       | no      |

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
| `stores.<name>.auth.method` | `SCRIM_STORES_INF_AUTH_METHOD` | string | `universal-auth` | Only `universal-auth` for now; Kubernetes Auth follows. |
| `stores.<name>.client-id` | `SCRIM_STORES_INF_CLIENT_ID` | secret reference | required | The identity's client ID. Not secret on its own, but half of the credential, so it is taken as a reference (a literal is fine). |
| `stores.<name>.client-secret` | `SCRIM_STORES_INF_CLIENT_SECRET` | secret reference | required | `file:`, `env:`, a systemd credential or a store reference. A reference that does not resolve, or resolves to an empty value, stops start-up. A literal works but logs a warning. |
| `stores.<name>.timeout` | `SCRIM_STORES_INF_TIMEOUT` | duration | `10s` | Per-request timeout. A timed-out request counts as the store being unavailable. |
| `stores.<name>.tls.ca-file` | `SCRIM_STORES_INF_TLS_CA_FILE` | path | system roots | PEM bundle to verify the server with, for a private CA. |
| `stores.<name>.watch.interval` | `SCRIM_STORES_INF_WATCH_INTERVAL` | duration | `30s` | How often the listing is polled for changes, with +-20% jitter. |
| `stores.<name>.watch.max-backoff` | `SCRIM_STORES_INF_WATCH_MAX_BACKOFF` | duration | `5m` | Longest wait between polls while Infisical keeps failing. |
| `stores.<name>.create-folders` | `SCRIM_STORES_INF_CREATE_FOLDERS` | bool | `true` | Create missing folders on write. With `false`, a write into a missing folder fails as not found. |
| `stores.<name>.expand-references` | `SCRIM_STORES_INF_EXPAND_REFERENCES` | bool | `true` | Expand Infisical secret references (`${KEY}`, `${env.folder.KEY}`) on read, as the Infisical CLI does when it injects secrets, so the value scrim redacts is the value your applications see. |

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
| 403 | permission denied |
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
- Secret imports are not followed when listing. Reference the source project directly.
- Kubernetes Auth, OIDC token exchange for per-agent identities, and Infisical's own approval
  workflows are not used yet.

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
