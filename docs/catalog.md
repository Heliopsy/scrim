# Secret catalog

The catalog is optional. Without it, store references work directly everywhere scrim takes a secret,
and a file can carry a reference placeholder such as `{{scrim:bao://kv/agents/github#token}}`. The
catalog adds three things on top:

- **logical names**: rules, tool profiles and MCP tools can say `github` instead of the reference;
- **bindings**: the hosts a credential may be injected toward, its value class, its injection
  locations and the tool profiles that use it;
- **declared placeholders**: readable strings such as `SCRIM_GITHUB_TOKEN` that hand-written config
  files can carry, substituted on the wire like generated placeholders.

A catalog never holds values. Every reference must parse as a store reference, unknown keys are
rejected, and a string that looks like a credential (a GitHub or GitLab token, an AWS key id, an
`sk-` key, a JWT, a private key, a long random path segment) fails validation in any field. A
catalog that fails validation is not loaded.

A bound entry whose value the store has not delivered yet (the store is still loading, or a read
failed) is still known to the tool proxy by its hosts and placeholders. A tool request toward one
of those hosts that carries its placeholder, or any other placeholder nothing resolves, is refused
with `503 credential_unavailable`; the placeholder is never forwarded as text.

## Entries

```yaml
apiVersion: scrim.dev/v1
kind: Catalog
entries:
  github:
    ref: bao://kv/agents/github#token
    hosts: [api.github.com, uploads.github.com]
    placeholder: SCRIM_GITHUB_TOKEN
    tools: [gh, git]
    inject: ["header:Authorization"]

  db:
    placeholder: SCRIM_DB_PASSWORD
    hosts: [db.internal]
    profiles:
      dev: bao://kv/dev/db#password
      prod: aws-sm://prod/db#password

  deploy-key:
    ref: bao://kv/shared/deploy          # default when no variant matches
    variants:
      - when: {profile: prod}
        ref: bao://kv/prod/deploy
      - when: {profile: prod, agent: ci}
        ref: bao://kv/prod/ci-deploy

  acme:
    prefix: inf://acme/prod/*
    template: SCRIM_ACME_{NAME}
    hosts: [api.acme.example]

  release-notes:
    ref: bao://kv/agents/notes#text
    class: display
```

| Key | Meaning |
| --- | --- |
| `ref` | Default store reference. |
| `profiles` | Reference per catalog profile; shorthand for `variants` on `profile` alone. |
| `variants` | References selected by `profile`, `environment`, `agent` and `namespace`. The matching variant with the most keys wins; two matching with the same number of keys is an error. |
| `prefix`, `template` | Bulk entry: every secret under the prefix, named by the template. `{NAME}` is the last path segment, upper-cased, other characters as `_`. |
| `hosts` | Hosts the credential may be sent to. `*.example.com` matches subdomains only. Without hosts a credential is never injected. |
| `placeholder` | Declared placeholder: `SCRIM_` followed by upper-case words joined by `_`. Unique across the catalog. |
| `class` | `credential` (default): injected at the network edge toward bound hosts only. `display`: data the agent may see, restored by the tool policy. |
| `inject` | Injection locations, for example `header:Authorization`, `query:key`, `env`. |
| `tools` | Tool profiles that use this secret. |

Entry names are lower-case words joined by dashes. Entries from a bulk prefix are named
`<entry>/<NAME>`, for example `acme/API_KEY`.

## Profiles and environments

The catalog resolves every entry for one selection: the catalog profile (`catalog.profile`,
`--catalog-profile`, `SCRIM_CATALOG_PROFILE`), the environment (`catalog.environment`), and the agent
and namespace of the session. The same placeholder in the same file then points at a development
secret in one session and a production secret in another.

An entry with no variant for the selection and no default `ref` is **unresolved** in that session.
It never falls back to another profile's reference, and naming the other profile's reference
directly does not pick up the entry's host binding either.

## Sources and precedence

From lowest to highest precedence:

1. **Store metadata.** With `catalog.metadata-from: [bao://kv/agents]`, secrets under those prefixes
   whose metadata carries `scrim.*` labels become entries: `scrim.hosts` (comma-separated),
   `scrim.placeholder`, `scrim.profiles` (the profiles the secret applies to), `scrim.name`,
   `scrim.class` and `scrim.field`. The prefix is `catalog.metadata-prefix`. OpenBao custom metadata,
   Infisical tags and Vaultwarden `scrim.*` custom fields all work this way.
2. **Catalog files** listed in `catalog.files`.
3. **Configuration**: `catalog.entries.<name>` in the config file, overridable per field from the
   environment (`SCRIM_CATALOG_ENTRIES_DB_HOSTS='["db2.internal"]'`) or replaced as a whole with
   `SCRIM_CATALOG_ENTRIES` holding a JSON object of entries.

A higher source overrides an entry of the same name, and the override is reported as a warning.
Store metadata for a secret the catalog already maps never changes the binding; where the labels
disagree (different hosts or placeholder) scrim reports it. The same name twice in one source kind,
or one placeholder declared twice anywhere, fails validation and names both.

If a store cannot be listed, its bulk entries and metadata are skipped with a warning and the rest of
the catalog still loads.

Kubernetes cluster resources as a catalog source are not implemented yet.

## Reload

The catalog reloads without a restart when the configuration changes (any `catalog.*` setting or
entry) or a catalog file changes; files are checked every `catalog.reload-interval` (default 5s). A
reload is all or nothing: an invalid catalog is rejected, logged, and the previous one stays in
effect.

## Commands

`scrim catalog show` prints every entry with the reference selected for the current selection and
where the entry came from. `--for-profile`, `--agent` and `--namespace` show another selection;
`--json` prints machine-readable output with every variant.

```text
selection: profile=dev
NAME    PLACEHOLDER        REFERENCE                     SELECTED     HOSTS           CLASS       SOURCE
db      SCRIM_DB_PASSWORD  bao://kv/dev/db#password      profile=dev  db.internal     credential  configuration catalog.entries.db
github  -                  bao://kv/agents/github#token  default      api.github.com  credential  catalog file catalog.yaml
```

`scrim catalog suggest` prints draft entries for what the catalog does not map yet, from the
project's `.env` files (`--dir`), configured tool profiles and the names of secrets under
`--prefix` store prefixes and `catalog.metadata-from`. Hosts come from store metadata, a URL
variable of the same provider in the project, a URL with credentials in it, or a table of known API
providers. Candidate references for secrets not found in a store go under `--store` (default
`bao://kv/agents/<project>/<name>`).

Suggestions are printed, never applied. The output is a valid catalog file to review, edit and save
yourself. Values in `.env` files are inspected in memory only (is it empty, is it already a
placeholder, which host does a URL name), wiped afterwards and never printed; store values are never
read.
