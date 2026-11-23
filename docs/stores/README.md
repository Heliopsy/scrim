# Secret stores

scrim brokers the stores you already run. It reads the secrets your configuration marks for
redaction, keeps their values in memory only, and writes new secrets for agents, who never read a
value back.

| Store | Kind | Guide |
| ------- | ------ | ------- |
| OpenBao (and Vault-compatible KV v2) | `openbao` | [openbao.md](openbao.md) |
| Infisical | `infisical` | [infisical.md](infisical.md) |
| Bitwarden Secrets Manager | `bws` | [bws.md](bws.md) |
| Google Secret Manager | `gcpsm` | [gcp.md](gcp.md) |
| Azure Key Vault | `azkv` | [azure.md](azure.md) |
| Environment variables, files | `env`, `file` | [local.md](local.md) |
| SOPS-encrypted files | `sops` | [sops.md](sops.md) |
| Memory (tests, throwaway runs) | `memory` | none |

## Capabilities

`scrim doctor` prints this matrix for the stores you configure. An operation a store does not
support is refused before anything is attempted.

| Kind        | read | list | watch | write | generate | dynamic |
|-------------|------|------|-------|-------|----------|---------|
| `openbao`   | yes  | yes  | yes   | yes   | no       | no      |
| `infisical` | yes  | yes  | yes   | yes   | no       | no      |
| `bws`       | yes  | yes  | yes   | yes   | no       | no      |
| `gcpsm`     | yes  | yes  | yes   | yes   | no       | no      |
| `azkv`      | yes  | yes  | yes   | yes   | no       | no      |
| `env`       | yes  | yes  | no    | no    | no       | no      |
| `file`      | yes  | yes  | yes   | no    | no       | no      |
| `sops`      | yes  | yes  | yes   | no    | no       | no      |
| `memory`    | yes  | yes  | yes   | yes   | no       | no      |

Watch on OpenBao, Infisical, Bitwarden Secrets Manager, Google Secret Manager and Azure Key Vault
polls version metadata. It never fetches values, so it stays cheap even with a short interval.
Generated secrets are produced by scrim and then written, so generate needs write and no
store-side support.

## Configuring an instance

Each instance lives under `stores.<name>`. The name is the reference scheme: an instance named
`bao` answers `bao://...`. Several instances of one kind can sit side by side under different
names (`bao-prod`, `bao-dev`).

```yaml
apiVersion: scrim.dev/v1
kind: Config
stores:
  bao:
    kind: openbao
    aliases: [vault]
    address: https://bao.example.com:8200
    auth: {method: approle}
    role-id: file:/run/secrets/bao-role-id
    secret-id: file:/run/secrets/bao-secret-id
    redact:
      - bao://kv/agents/*
      - bao://kv/ci/deploy#token
    refresh:
      interval: 5m
      staleness: 15m
```

These fields are common to every kind. All other fields belong to the adapter and are listed in
its guide.

| Key | Default | Meaning |
| ----- | --------- | --------- |
| `stores.<name>.kind` | required | Adapter kind. |
| `stores.<name>.aliases` | none | Extra schemes that address this instance. |
| `stores.<name>.redact` | none | References loaded into the redaction set at start and kept fresh. A reference ending in `/*` loads every secret under that folder; one ending in `*` right after part of a name (`APP_*`, `dir/app-*`) is a glob that loads every secret whose path starts with the text before the `*` (env and file stores only); a `#field` limits a single secret to one field. A `*` anywhere else is refused. References must use the instance name as their scheme. |
| `stores.<name>.refresh.interval` | `5m` | Full refresh period, spread by ±20% jitter. |
| `stores.<name>.refresh.retention` | `24h` | How long a rotated, deleted or overwritten value stays in the redaction set. |
| `stores.<name>.refresh.staleness` | `15m` | How long a value confirmed by the store may still be injected without a newer confirmation, and how long the store may be unreachable before it is reported unhealthy. |
| `stores.<name>.refresh.max-backoff` | `5m` | Longest wait between retries after a failed load. |
| `stores.<name>.labels` | none | Labels of your own derived from the store's labels, for policy rules. See [labels](#labels). |

Every key can also be set from the environment: `SCRIM_` followed by the key upper-cased, with dots
and dashes turned into `_` (`stores.bao.secret-id` becomes `SCRIM_STORES_BAO_SECRET_ID`). The
instance has to be declared in a file, or the whole collection set as JSON in `SCRIM_STORES`.

Credential fields (`token`, `role-id`, `secret-id`, `client-id`, `client-secret`, `password`,
`credentials`, `certificate`) take a reference instead of a literal: `env:NAME`, `file:/path`,
`cred:NAME` (a systemd credential), or a reference into another configured store. They are
resolved at start; a reference that cannot be resolved stops start-up, and no store is contacted
with an empty credential. `scrim config show` masks them. A literal still works, but scrim logs a
warning naming the field. scrim also adds the credentials it holds, and the session tokens a store
issues at login, to the redaction set.

### Empty redact targets

Every redact target reports how many values it holds. A target that holds nothing after the first
load (a misspelt name, a glob that matches no variable, a prefix or allow list that hides it) stops
start-up with an error naming it:

```text
store local: redact target loaded no values: local://SCRIM_SECRET_NOTHING_* matched no secret; check the
name and the store's prefix or allow list, or set redaction.allow-empty-targets to start anyway
```

`redaction.allow-empty-targets: true` is a weakening setting: scrim starts, warns at start-up,
lists the setting under weakened protections, and reports the store as degraded with the empty
target at 0 values. `scrim status` shows the count of every target, and never reports redaction as
active while one is empty. An unreachable store is not an empty target: it stays not ready, as
below.

## Freshness and outages

Values load at start, refresh on `refresh.interval` and, on stores that watch, refresh again as
soon as the store reports a change. A secret whose version has not changed is not read again.

| Situation | Redaction | Injection | Reported state |
| ----------- | ----------- | ----------- | ---------------- |
| First load not done yet | Not ready. Requests that depend on the store are refused. | Refused | `loading`, not ready |
| First load failed | Not ready, as above | Refused, naming the reference | `unavailable`, not ready |
| Last refresh succeeded | Current values, plus rotated ones for `refresh.retention` | Allowed | `ready` |
| Store unreachable after a good load | The last known values are kept, so nothing is weakened | Allowed for values confirmed within `refresh.staleness`, refused after that | `degraded`; unhealthy past `refresh.staleness` |
| Store locked (Vaultwarden without its key) | Last known values kept | Refused | `locked`, unhealthy |

Injection never falls back to an empty string, a value past the staleness limit, or the
placeholder. A value that is not in memory is read from the store at the moment it is needed and
goes into the redaction set before it is used. If the store cannot answer, the request is refused
and the error names the reference.

A secret written through scrim (`secret_capture`, `secret_gen`, `scrim secret put`) goes into the
redaction set before the write is sent. If the store refuses the write, the value is dropped from
memory and the error gives the store's reason without the value.

The readiness endpoint (`/readyz`) has one check per store, named `store <name>`, and it stays
failing until that store's first load completes. The `scrim status` command reports the states
above.

## Labels

Every secret carries labels that describe where it lives, which policy rules match as
`secret.labels` (see [policy.md](../policy.md#labels-from-stores) for rules and examples). Each
backend's page lists the attributes it reports. List a secret's labels with
`scrim catalog labels <name|reference>`.

| Key | Set by | Meaning |
| --- | --- | --- |
| `store.name` | scrim | Instance name (not an alias). |
| `store.kind` | scrim | Adapter kind. |
| `store.path` | scrim | Reference path, without selectors or field. |
| `store.container` | scrim | Path before its last segment; empty at the top level. |
| `store.field` | scrim | Field, when the reference names one. |
| `<kind>.<attribute>` | adapter | A native attribute of the store (`vaultwarden.org`, `openbao.mount`, `infisical.environment`). |
| `<kind>.<attribute>.<value>` = `true` | adapter | One per value of a multi-valued attribute, next to the comma-joined `<kind>.<attribute>`. |
| `<kind>.meta.<key>` | adapter | Metadata store users can edit (custom fields, tags, custom metadata). |
| `scrim.*` | store metadata | Catalog bindings kept with the secret ([catalog](../catalog.md#sources-and-precedence)). |
| other names | `stores.<name>.labels` | Derived labels (below). |

Keys are lower-case ASCII letters, digits, `-` and `_` separated by dots; the value part of a
presence key keeps the value's spelling (`vaultwarden.collection.Prod`). Values are metadata, never
secret values. A native attribute always wins over user-editable metadata, which stays under
`<kind>.meta.`, so nobody who can edit an item can forge a native label. scrim replaces any
`store.*` key an adapter reports and drops keys under another kind's prefix.

The local stores report:

| Kind | Labels |
| --- | --- |
| `env` | `env.variable` (variable name), `env.prefix` (the `prefix` option, when set) |
| `file` | `file.root` (the `root` option), `file.path` (absolute path of the file), `file.format` (`raw`, `dotenv` or `json`) |
| `sops` | `sops.root`, `sops.path`, `sops.format`, `sops.version`, `sops.lastmodified`, `sops.key-type`, `sops.age-recipient` and more from the file's metadata ([sops.md](sops.md#labels)) |
| `memory` | `memory.top` (first path segment, when the path has more than one) |

`labels` derives names of your own from the labels above. Each entry is a label name and a source:
a label to copy, `{value}` for a constant, `{from, value}` for a constant set when a label exists, or
`{from, regex, value}` for a match (`$1` expands to a submatch):

```yaml
stores:
  ci-env:
    kind: env
    prefix: CI_
    labels:
      env: {value: ci}
      tier: {from: env.variable, regex: "^CI_PROD_", value: prod}
```

A derived label never replaces a native or `store.*` label, and a name under `store.`, `scrim.` or
any kind's prefix fails validation.

### Writing an adapter

Adapters put their attributes into `Metadata.Labels` with the helpers in `internal/stores`
(`labels.go`), never by writing keys by hand:

- `stores.SetNative(labels, kind, attr, values...)` sets `<kind>.<attr>`, replacing anything there.
  With several values, or any number for an attribute declared multi-valued, it sets the
  comma-joined key and a `<kind>.<attr>.<value>` = `true` presence key per value. Empty values are
  skipped; an attribute under `meta` is ignored.
- `stores.DeclareMulti(kind, attrs...)`, called from the adapter's `init`, declares multi-valued
  attributes, so one collection still gets its presence key.
- `stores.UserMeta(labels, kind, key, value)` records user-editable metadata as
  `<kind>.meta.<key>` and never overwrites a key already set.
- `stores.MetadataReader` (`ReadMetadata(ctx, ref) (Metadata, error)`) is optional: implement it
  when the store can return a secret's metadata, labels included, without its values, and return
  `ErrNotFound` for a missing secret. Policy uses it to label a request naming a secret that is not
  in a redaction set (a write to an existing item). Without it scrim reads the secret and wipes the
  values at once.
- `stores.WriteLabeler` (`WriteLabels(ref) map[string]string`) is optional: an adapter that can
  tell from a reference alone, without a store call, which labels a new item would get implements
  it, and `store.write` and `secret.gen` rules see them before the item exists.

Do not let a store user's input reach a native key: copy custom fields and tags with `UserMeta`. Do
not put a nested attribute under a multi-valued one (`vaultwarden.collection.id` would read as a
collection named `id`).

## Conformance

Every adapter passes the shared conformance suite in `internal/stores/storetest`, which covers
read, field and version selectors, value fidelity, list, write, create-only, rejected writes,
write-only paths, labels, watch (including deletes and recovery after an outage), health, outage
and concurrent use. It also checks that no value ever appears in an error, metadata or change
notification. The suite is itself tested against deliberately broken adapters.

The integration runs start each store in rootless podman, and docker is not supported:

```sh
SCRIM_TEST_PODMAN=1 go test -race ./internal/stores/...
```

| Variable | Effect |
| ---------- | -------- |
| `SCRIM_TEST_PODMAN=1` | Require podman: a missing podman fails the run instead of skipping it (CI). |
| `SCRIM_TEST_PODMAN=0` | Skip the container tests. |
| `SCRIM_TEST_OPENBAO_ADDR`, `SCRIM_TEST_OPENBAO_TOKEN` | Use an existing OpenBao (root token) instead of a container. The outage cases are skipped. |
| `SCRIM_TEST_OPENBAO_IMAGE` | OpenBao image (default `quay.io/openbao/openbao:2.7.3`). |
| `SCRIM_TEST_INFISICAL_VERSION` | Infisical image tag (default: `defaultInfisicalVersion` in `internal/stores/infisical/infisical_integration_test.go`). |
| `SCRIM_TEST_INFISICAL_ADDR`, `SCRIM_TEST_INFISICAL_TOKEN`, `SCRIM_TEST_INFISICAL_ORG` | Use an existing Infisical (an organisation admin identity token and the organisation ID) instead of a pod. The outage case is skipped. |

Containers and pods are named `scrim-stores-*` and are removed with their volumes when the tests
finish.
