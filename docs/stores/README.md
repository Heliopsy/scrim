# Secret stores

scrim brokers the stores you already run. It reads the secrets your configuration marks for
redaction, keeps their values in memory only, and writes new secrets for agents, who never read a
value back.

| Store | Kind | Guide |
|-------|------|-------|
| OpenBao (and Vault-compatible KV v2) | `openbao` | [openbao.md](openbao.md) |
| Infisical | `infisical` | [infisical.md](infisical.md) |
| Environment variables, files | `env`, `file` | [local.md](local.md) |
| Memory (tests, throwaway runs) | `memory` | none |

## Capabilities

`scrim doctor` prints this matrix for the stores you configure. An operation a store does not
support is refused before anything is attempted.

| Kind        | read | list | watch | write | generate | dynamic |
|-------------|------|------|-------|-------|----------|---------|
| `openbao`   | yes  | yes  | yes   | yes   | no       | no      |
| `infisical` | yes  | yes  | yes   | yes   | no       | no      |
| `env`       | yes  | yes  | no    | no    | no       | no      |
| `file`      | yes  | yes  | yes   | no    | no       | no      |
| `memory`    | yes  | yes  | yes   | yes   | no       | no      |

Watch on OpenBao and Infisical polls version metadata. It never fetches values, so it stays cheap
even with a short interval. Generated secrets are produced by scrim and then written, so generate
needs write and no store-side support.

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
|-----|---------|---------|
| `stores.<name>.kind` | required | Adapter kind. |
| `stores.<name>.aliases` | none | Extra schemes that address this instance. |
| `stores.<name>.redact` | none | References loaded into the redaction set at start and kept fresh. A reference ending in `/*` loads every secret under that prefix; a `#field` limits a single secret to one field. References must use the instance name as their scheme. |
| `stores.<name>.refresh.interval` | `5m` | Full refresh period, spread by ±20% jitter. |
| `stores.<name>.refresh.retention` | `24h` | How long a rotated, deleted or overwritten value stays in the redaction set. |
| `stores.<name>.refresh.staleness` | `15m` | How long a value confirmed by the store may still be injected without a newer confirmation, and how long the store may be unreachable before it is reported unhealthy. |
| `stores.<name>.refresh.max-backoff` | `5m` | Longest wait between retries after a failed load. |

Every key can also be set from the environment: `SCRIM_` followed by the key upper-cased, with dots
and dashes turned into `_` (`stores.bao.secret-id` becomes `SCRIM_STORES_BAO_SECRET_ID`). The
instance has to be declared in a file, or the whole collection set as JSON in `SCRIM_STORES`.

Credential fields (`token`, `role-id`, `secret-id`, `client-id`, `client-secret`, `password`) take
a reference instead of a literal: `env:NAME`, `file:/path`, `cred:NAME` (a systemd credential), or
a reference into another configured store. They are resolved at start; a reference that cannot be
resolved stops start-up, and no store is contacted with an empty credential. `scrim config show`
masks them. A literal still works, but scrim logs a warning naming the field. scrim also adds the
credentials it holds, and the session tokens a store issues at login, to the redaction set.

## Freshness and outages

Values load at start, refresh on `refresh.interval` and, on stores that watch, refresh again as
soon as the store reports a change. A secret whose version has not changed is not read again.

| Situation | Redaction | Injection | Reported state |
|-----------|-----------|-----------|----------------|
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
|----------|--------|
| `SCRIM_TEST_PODMAN=1` | Require podman: a missing podman fails the run instead of skipping it (CI). |
| `SCRIM_TEST_PODMAN=0` | Skip the container tests. |
| `SCRIM_TEST_OPENBAO_ADDR`, `SCRIM_TEST_OPENBAO_TOKEN` | Use an existing OpenBao (root token) instead of a container. The outage cases are skipped. |
| `SCRIM_TEST_OPENBAO_IMAGE` | OpenBao image (default `quay.io/openbao/openbao:2.7.3`). |
| `SCRIM_TEST_INFISICAL_VERSION` | Infisical image tag (default `v0.167.13`). |
| `SCRIM_TEST_INFISICAL_ADDR`, `SCRIM_TEST_INFISICAL_TOKEN`, `SCRIM_TEST_INFISICAL_ORG` | Use an existing Infisical (an organisation admin identity token and the organisation ID) instead of a pod. The outage case is skipped. |

Containers and pods are named `scrim-stores-*` and are removed with their volumes when the tests
finish.
