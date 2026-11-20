# Configuration

Every scrim setting has one dotted key, for example `approvals.timeout`. The same key names it in
the config file, as an environment variable and, for settings an operator changes per invocation,
as a flag. `scrim config show --effective` reports every setting under that key with the source
of its value.

| Source | Example |
|---|---|
| Config file | `approvals: {timeout: 60s}` or `approvals.timeout: 60s` |
| Environment | `SCRIM_APPROVALS_TIMEOUT=60s` |
| Flag | `--approvals-timeout 60s` |

The environment variable is `SCRIM_` followed by the key upper-cased, with `.` and `-` as `_`. The
flag is the key with `.` as `-`. The [reference](#settings-reference) at the end lists every
setting.

## Precedence

From lowest to highest:

1. built-in default
2. profile (`profile`, see [Profiles](#profiles))
3. config files, later files over earlier ones
4. environment variables
5. flags

`scrim config show --effective` names the winning source of each value: `default`,
`profile:<name>`, `file:<path>:<line>`, `env:<VARIABLE>` or `flag:--<name>`.

## Config files

A config file is YAML and declares its format version:

```yaml
apiVersion: scrim.dev/v1
kind: Config

approvals:
  timeout: 60s
log:
  level: info
proxy:
  upstream:
    anthropic: http://127.0.0.1:9000
```

A file without `apiVersion` and `kind`, or with an `apiVersion` this release does not read, is
rejected with an error naming the file and the supported versions. Nested and dotted keys mix
freely: `log.level: info` at the top level is the same setting as `log: {level: info}`. Setting
the same key twice in one file is an error.

### Where scrim looks

1. the file given with `--config`
2. otherwise `SCRIM_CONFIG`, which may hold several paths separated by `:`, applied in order
3. otherwise the first file that exists of `$XDG_CONFIG_HOME/scrim/config.yaml`,
   `~/.config/scrim/config.yaml` and `/etc/scrim/config.yaml`

A path given explicitly must exist. When no file is found, defaults, the environment and flags
apply.

### Includes

A file can pull in other files after its own settings:

```yaml
apiVersion: scrim.dev/v1
kind: Config
include:
  - conf.d                      # every *.yaml and *.yml file, in lexical order
  - local/*.yaml                # a glob, may match nothing
  - {path: site.yaml, optional: true}
```

Paths are relative to the including file. A plain path must exist unless marked `optional`. Each
file applies its own settings and then its includes, depth first, so a drop-in overrides the file
that includes it. Sections and map settings merge key by key; scalars and lists are replaced.
Include cycles, nesting deeper than 16 levels and more than 256 files are errors. Included files
declare `apiVersion` and `kind` too.

### Unknown keys

A key scrim does not know is an error naming the key and the closest known one:

```text
aprovals.timeout (file:/etc/scrim/config.yaml:4): unknown setting "aprovals.timeout" (did you mean "approvals.timeout"?)
```

With `config.strict: false` (or `SCRIM_CONFIG_STRICT=false`) unknown keys are warnings instead.

## Environment encoding

Scalars are written as they are in the file: `true`, `42`, `1.5`, `90s`. Durations use Go syntax
(`300ms`, `90s`, `1h30m`).

Lists take a JSON array, or comma-separated items with `\,` for a literal comma and `\\` for a
backslash:

```sh
SCRIM_PROXY_NO_PROXY='["127.0.0.1","localhost"]'
SCRIM_PROXY_NO_PROXY='127.0.0.1,localhost'
```

Maps take a JSON object or `key=value` pairs separated by commas. One entry of a map is set by
adding its name to the variable, lower-cased words with `_` for `-`; it merges into the map from
the lower layers, while the whole-map variable replaces it:

```sh
SCRIM_PROXY_UPSTREAM='{"anthropic":"http://127.0.0.1:9000"}'
SCRIM_PROXY_UPSTREAM_ANTHROPIC=http://127.0.0.1:9000
```

The JSON forms round-trip every value a file can hold.

## Collections

Some sections hold any number of named instances whose fields the owning component defines, such
as secret store instances:

```yaml
stores:
  bao-prod:
    kind: openbao
    address: https://bao.example.com
    token: file:/run/secrets/bao-token
```

Instance names are lower-case words separated by dashes. A field is addressed as
`stores.bao-prod.token`. From the environment:

- `SCRIM_STORES` holds a JSON object of instances and replaces the collection;
- `SCRIM_STORES_BAO_PROD_TOKEN` overrides a field already set by a file or by `SCRIM_STORES`, keeping
  its type;
- a variable that extends the name of a known instance adds a string field to it.

A variable under a collection's prefix that matches no known instance is reported as a warning,
since the instance name cannot be recovered from it.

## Secret-valued settings

Settings that hold credentials take a reference, which scrim resolves at start-up and on every
reload:

| Reference | Reads |
|---|---|
| `env:NAME` | the environment variable `NAME` |
| `file:/absolute/path` | the file, without one trailing newline |
| `cred:NAME` | the systemd credential `$CREDENTIALS_DIRECTORY/NAME` (`LoadCredential=`) |
| `<scheme>://<path>[#field]` | a secret store instance, for example `bao://kv/scrim#token` |

A reference that cannot be resolved (missing file, unset variable, empty value, store error) stops
start-up or rejects the reload, naming the setting and the reference. scrim never falls back to an
empty value.

A literal value is accepted with a warning naming the setting, except for settings marked
"literals rejected" in the reference, which refuse it. Outputs never contain a resolved value:
`scrim config show` prints `[scrim:redacted]` with the reference form, and a literal appears as
`<literal>`. User information in a store reference (`postgres://user:pass@host`) is masked as
`***@`.

`scrim config validate` resolves `env:`, `file:` and `cred:` references and checks store references
for syntax only; it does not contact stores.

## Profiles

A profile is a preset of defaults for a deployment shape: `local` (the default), `k8s` and `ci`.
Select one with `profile: ci`, `SCRIM_PROFILE=ci` or `--profile ci`. A profile sits just above the
built-in defaults, so any value it sets can be overridden by a file, the environment or a flag. The
reference lists the values each profile sets. A profile never enables a weakening setting.

## Validating and inspecting

```sh
scrim config validate                 # every problem with key and source, non-zero exit if invalid
scrim config validate -o json
scrim config show                     # settings not at their default, with sources
scrim config show --effective         # every setting
scrim config show --effective -o json
scrim config schema                   # JSON Schema of the config file
```

The JSON Schema is generated from the registry scrim validates against and committed as
[`schema/config-v1.json`](../schema/config-v1.json). It is at least as strict as scrim on keys,
types, enums and versions, and expects the nested form of keys. Checks the schema cannot express
(value ranges, cross-setting rules, references that resolve) happen in `scrim config validate`.

## Reloading

scrim reloads its configuration on `SIGHUP` and, while `config.watch` is true, when a config file,
an included file or directory, or a `file:` secret changes (Kubernetes ConfigMap and Secret volume
swaps included).

A reload is all or nothing. The new configuration is built completely, secrets included, before
anything changes. If any part is invalid, scrim keeps the running configuration, logs why and
reports the rejection in `scrim status`. Settings marked "restart required" keep their running value
when changed; the reload applies the rest and reports that a restart is needed for them.

## Weakening settings

A setting that weakens a security invariant is named for what it weakens (for example
`redaction.allow-unredacted-on-error`), defaults to the safe value, is logged as a warning at
start-up and after every reload while active, and is listed under weakened protections in
`scrim status`.

## Settings reference

This section is generated from the settings registry by `just config-docs`. A test fails when it
is out of date.

<!-- BEGIN GENERATED SETTINGS REFERENCE: edit the registry, then run `just config-docs` -->

| Key | Type | Default | Reload |
|---|---|---|---|
| [`config.strict`](#configstrict) | bool | `true` | hot |
| [`config.watch`](#configwatch) | bool | `true` | hot |
| [`log.format`](#logformat) | string | `text` | hot |
| [`log.level`](#loglevel) | string | `info` | hot |
| [`metrics.listen`](#metricslisten) | string | `""` | restart required |
| [`policy.default`](#policydefault) | string | `deny` | hot |
| [`profile`](#profile) | string | `local` | hot |
| [`state.backend`](#statebackend) | string | `memory` | restart required |
| [`stores.<name>.*`](#storesname) | collection | empty | restart required |

### `stores.<name>`

Secret store instances by name. The name is the instance's reference scheme (`bao://...` for an instance named bao); `kind` picks the adapter, `aliases` adds schemes, `redact` lists references and prefixes loaded into the redaction set, `refresh.*` tunes refresh and outage handling, and every other field is the adapter's own. See docs/stores.

| | |
|---|---|
| Type | collection of named instances (names: lower-case words with dashes) |
| Environment | `SCRIM_STORES` (JSON object of instances, replaces the collection); `SCRIM_STORES_<NAME>_<FIELD>` for one field |
| Required fields | `kind` |
| Secret fields | `token`, `role-id`, `secret-id`, `client-id`, `client-secret`, `password` (references; a literal is warned about) |
| Reload | restart required |

### config

#### `config.strict`

Reject config files containing keys scrim does not know. When false, unknown keys are reported as warnings instead.

| | |
|---|---|
| Type | bool |
| Default | `true` |
| Environment | `SCRIM_CONFIG_STRICT` |
| Flag | none |
| Reload | hot |

#### `config.watch`

Reload the configuration when a config file or an included file changes. SIGHUP always triggers a reload.

| | |
|---|---|
| Type | bool |
| Default | `true` |
| Environment | `SCRIM_CONFIG_WATCH` |
| Flag | none |
| Reload | hot |

### log

#### `log.format`

Log record format: text (logfmt) or json, one object per line.

| | |
|---|---|
| Type | string |
| Default | `text` |
| Environment | `SCRIM_LOG_FORMAT` |
| Flag | `--log-format` |
| Reload | hot |
| Values | `text`, `json` |

#### `log.level`

Minimum level of log records.

| | |
|---|---|
| Type | string |
| Default | `info` |
| Environment | `SCRIM_LOG_LEVEL` |
| Flag | `--log-level` |
| Reload | hot |
| Values | `debug`, `info`, `warn`, `error` |

### metrics

#### `metrics.listen`

Address of the metrics and health endpoint (Prometheus format at /metrics, /livez, /readyz). Empty disables it; bind to loopback unless scraped remotely.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_METRICS_LISTEN` |
| Flag | `--metrics-listen` |
| Reload | restart required |

### policy

#### `policy.default`

Decision applied when no rule matches. Anything other than deny is reported as a weakened protection.

| | |
|---|---|
| Type | string |
| Default | `deny` |
| Environment | `SCRIM_POLICY_DEFAULT` |
| Flag | none |
| Reload | hot |
| Weakening | **yes**: logged at start-up and on reload while active, listed in `scrim status` |
| Values | `deny`, `ask`, `allow` |

### profile

#### `profile`

Built-in preset of defaults for a deployment shape: `local` for a laptop or VM, `k8s` for Kubernetes, `ci` for throwaway runs. Any value a profile sets can be overridden.

| | |
|---|---|
| Type | string |
| Default | `local` |
| Environment | `SCRIM_PROFILE` |
| Flag | `--profile` |
| Reload | hot |
| Values | `local`, `k8s`, `ci` |

### state

#### `state.backend`

State backend for approvals, grants, sessions and audit metadata. memory writes nothing to disk.

| | |
|---|---|
| Type | string |
| Default | `memory` |
| Environment | `SCRIM_STATE_BACKEND` |
| Flag | `--state-backend` |
| Reload | restart required |
| Values | `memory`, `sqlite`, `postgres` |

<!-- END GENERATED SETTINGS REFERENCE -->
