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
| [`admin.url`](#adminurl) | string | `""` | hot |
| [`api.permissions`](#apipermissions) | string | `0600` | restart required |
| [`api.socket`](#apisocket) | string | `""` | restart required |
| [`approvals.poll-interval`](#approvalspoll-interval) | duration | `1s` | hot |
| [`approvals.public-url`](#approvalspublic-url) | string | `""` | hot |
| [`approvals.signing-key`](#approvalssigning-key) | secret-ref | empty | hot |
| [`approvals.timeout`](#approvalstimeout) | duration | `2m0s` | hot |
| [`catalog.environment`](#catalogenvironment) | string | `""` | hot |
| [`catalog.files`](#catalogfiles) | list | `[]` | hot |
| [`catalog.metadata-from`](#catalogmetadata-from) | list | `[]` | hot |
| [`catalog.metadata-prefix`](#catalogmetadata-prefix) | string | `scrim.` | hot |
| [`catalog.profile`](#catalogprofile) | string | `""` | hot |
| [`catalog.reload-interval`](#catalogreload-interval) | duration | `5s` | hot |
| [`config.strict`](#configstrict) | bool | `true` | hot |
| [`config.watch`](#configwatch) | bool | `true` | hot |
| [`dataplane.memory-lock`](#dataplanememory-lock) | string | `auto` | restart required |
| [`dataplane.path`](#dataplanepath) | string | `""` | restart required |
| [`dataplane.restart-max-backoff`](#dataplanerestart-max-backoff) | duration | `30s` | hot |
| [`dataplane.start-timeout`](#dataplanestart-timeout) | duration | `10s` | hot |
| [`entry.listen`](#entrylisten) | string | `127.0.0.1:0` | restart required |
| [`grants.default-ttl`](#grantsdefault-ttl) | duration | `30m0s` | hot |
| [`grants.max-ttl`](#grantsmax-ttl) | duration | `8h0m0s` | hot |
| [`identity.peers`](#identitypeers) | map | `{}` | restart required |
| [`log.format`](#logformat) | string | `text` | hot |
| [`log.level`](#loglevel) | string | `info` | hot |
| [`metrics.listen`](#metricslisten) | string | `""` | restart required |
| [`notify.ntfy.priority`](#notifyntfypriority) | int | `4` | hot |
| [`notify.ntfy.token`](#notifyntfytoken) | secret-ref | empty | hot |
| [`notify.ntfy.topic`](#notifyntfytopic) | string | `""` | hot |
| [`notify.ntfy.url`](#notifyntfyurl) | string | `""` | hot |
| [`notify.terminal.enabled`](#notifyterminalenabled) | bool | `true` | hot |
| [`notify.webhook.hold`](#notifywebhookhold) | duration | `30s` | hot |
| [`notify.webhook.poll-interval`](#notifywebhookpoll-interval) | duration | `2s` | hot |
| [`notify.webhook.secret`](#notifywebhooksecret) | secret-ref | empty | hot |
| [`notify.webhook.url`](#notifywebhookurl) | string | `""` | hot |
| [`policy.default`](#policydefault) | string | `deny` | hot |
| [`policy.deny-all`](#policydeny-all) | bool | `false` | hot |
| [`policy.deny-all-refresh`](#policydeny-all-refresh) | duration | `1s` | hot |
| [`policy.rules-file`](#policyrules-file) | string | `""` | hot |
| [`profile`](#profile) | string | `local` | hot |
| [`session.max-ttl`](#sessionmax-ttl) | duration | `168h0m0s` | restart required |
| [`session.ttl`](#sessionttl) | duration | `12h0m0s` | restart required |
| [`state.backend`](#statebackend) | string | `memory` | restart required |
| [`state.postgres.connect-timeout`](#statepostgresconnect-timeout) | duration | `15s` | restart required |
| [`state.postgres.dsn`](#statepostgresdsn) | secret-ref | empty | restart required |
| [`state.postgres.max-conns`](#statepostgresmax-conns) | int | `16` | restart required |
| [`state.sqlite.allow-network-filesystem`](#statesqliteallow-network-filesystem) | bool | `false` | restart required |
| [`state.sqlite.path`](#statesqlitepath) | string | `""` | restart required |
| [`tool-proxy.ca.cert-file`](#tool-proxycacert-file) | string | `""` | restart required |
| [`tool-proxy.ca.dir`](#tool-proxycadir) | string | `""` | restart required |
| [`tool-proxy.ca.key`](#tool-proxycakey) | secret-ref | empty | restart required |
| [`tool-proxy.ca.overlap`](#tool-proxycaoverlap) | duration | `168h0m0s` | restart required |
| [`tool-proxy.ca.rotate-before`](#tool-proxycarotate-before) | duration | `720h0m0s` | restart required |
| [`tool-proxy.ca.validity`](#tool-proxycavalidity) | duration | `17520h0m0s` | restart required |
| [`tools.approval-timeout`](#toolsapproval-timeout) | duration | `15m0s` | restart required |
| [`tools.grant-default-ttl`](#toolsgrant-default-ttl) | duration | `15m0s` | restart required |
| [`tools.grant-max-ttl`](#toolsgrant-max-ttl) | duration | `8h0m0s` | restart required |
| [`tracing.endpoint`](#tracingendpoint) | string | `""` | restart required |
| [`tracing.sample-ratio`](#tracingsample-ratio) | float | `1` | restart required |
| [`catalog.entries.<name>.*`](#catalogentriesname) | collection | empty | hot |
| [`stores.<name>.*`](#storesname) | collection | empty | restart required |

### `catalog.entries.<name>`

Catalog entries by logical name: ref, profiles, variants, prefix, template, hosts, placeholder, class, inject, tools. References only, never values.

| | |
|---|---|
| Type | collection of named instances (names: lower-case words with dashes) |
| Environment | `SCRIM_CATALOG_ENTRIES` (JSON object of instances, replaces the collection); `SCRIM_CATALOG_ENTRIES_<NAME>_<FIELD>` for one field |
| Reload | hot |

### `stores.<name>`

Secret store instances by name. The name is the instance's reference scheme (`bao://...` for an instance named bao); `kind` picks the adapter, `aliases` adds schemes, `redact` lists references and prefixes loaded into the redaction set, `refresh.*` tunes refresh and outage handling, and every other field is the adapter's own. See docs/stores.

| | |
|---|---|
| Type | collection of named instances (names: lower-case words with dashes) |
| Environment | `SCRIM_STORES` (JSON object of instances, replaces the collection); `SCRIM_STORES_<NAME>_<FIELD>` for one field |
| Required fields | `kind` |
| Secret fields | `token`, `role-id`, `secret-id`, `client-id`, `client-secret`, `password`, `unlock` (references; a literal is warned about) |
| Reload | restart required |

### admin

#### `admin.url`

Address of the scrim admin API for operator commands: unix:/path/to/socket or http(s)://host:port. Empty means unix:$XDG_RUNTIME_DIR/scrim/admin.sock.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_ADMIN_URL` |
| Flag | `--admin-url` |
| Reload | hot |

### api

#### `api.permissions`

Permission bits of the API socket, octal. Widen (for example 0660) only to let agents running as other local users connect; their identity still comes from peer credentials.

| | |
|---|---|
| Type | string |
| Default | `0600` |
| Environment | `SCRIM_API_PERMISSIONS` |
| Flag | none |
| Reload | restart required |

#### `api.socket`

Unix socket of the local agent API. Empty uses $XDG_RUNTIME_DIR/scrim/api.sock.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_API_SOCKET` |
| Flag | `--api-socket` |
| Reload | restart required |

### approvals

#### `approvals.poll-interval`

How often a waiting operation re-reads its approval from the state backend; bounds how long a decision recorded elsewhere takes to release it.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `1s` |
| Environment | `SCRIM_APPROVALS_POLL_INTERVAL` |
| Flag | none |
| Reload | hot |

#### `approvals.public-url`

Base URL under which the decision endpoint is reachable from approvers' devices, for example https://scrim.example.org. Empty means notifiers get no decision links and approvals are decided with scrim approve.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_APPROVALS_PUBLIC_URL` |
| Flag | none |
| Reload | hot |

#### `approvals.signing-key`

Reference to the key (at least 32 bytes) that signs decision links, shared by every replica. Empty means a random key per process: links stop working on restart and on other replicas.

| | |
|---|---|
| Type | secret reference (`env:`, `file:`, `cred:` or a store reference; a literal is warned about) |
| Default | empty |
| Environment | `SCRIM_APPROVALS_SIGNING_KEY` |
| Flag | none |
| Reload | hot |

#### `approvals.timeout`

How long an approval waits for a decision before it is denied. A rule's approval.timeout overrides it.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `2m0s` |
| Environment | `SCRIM_APPROVALS_TIMEOUT` |
| Flag | `--approvals-timeout` |
| Reload | hot |

### catalog

#### `catalog.environment`

Catalog environment that selects per-environment references.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_CATALOG_ENVIRONMENT` |
| Flag | `--catalog-environment` |
| Reload | hot |

#### `catalog.files`

Catalog files to load, in order. Each is a YAML document with `kind: Catalog` and an `entries` map. Reloaded when they change.

| | |
|---|---|
| Type | list of strings (env: JSON array or comma-separated, `\,` for a comma) |
| Default | `[]` |
| Environment | `SCRIM_CATALOG_FILES` |
| Flag | none |
| Reload | hot |

#### `catalog.metadata-from`

Store prefixes (for example bao://kv/agents) whose secrets' metadata labels are read as catalog entries.

| | |
|---|---|
| Type | list of strings (env: JSON array or comma-separated, `\,` for a comma) |
| Default | `[]` |
| Environment | `SCRIM_CATALOG_METADATA_FROM` |
| Flag | none |
| Reload | hot |

#### `catalog.metadata-prefix`

Prefix of the store metadata keys read as catalog bindings: <prefix>hosts, <prefix>placeholder, <prefix>profiles, <prefix>name, <prefix>class, <prefix>field.

| | |
|---|---|
| Type | string |
| Default | `scrim.` |
| Environment | `SCRIM_CATALOG_METADATA_PREFIX` |
| Flag | none |
| Reload | hot |

#### `catalog.profile`

Catalog profile (for example dev or prod) that selects per-profile references.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_CATALOG_PROFILE` |
| Flag | `--catalog-profile` |
| Reload | hot |

#### `catalog.reload-interval`

How often catalog files are checked for changes.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `5s` |
| Environment | `SCRIM_CATALOG_RELOAD_INTERVAL` |
| Flag | none |
| Reload | hot |

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

### dataplane

#### `dataplane.memory-lock`

Lock the data plane's memory so values are never swapped: auto locks when the memlock limit is unlimited and warns otherwise; require refuses to start without it.

| | |
|---|---|
| Type | string |
| Default | `auto` |
| Environment | `SCRIM_DATAPLANE_MEMORY_LOCK` |
| Flag | none |
| Reload | restart required |
| Values | `auto`, `require` |

#### `dataplane.path`

Path of a scrim-dataplane binary to run instead of the embedded one. For development builds; release builds embed it.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_DATAPLANE_PATH` |
| Flag | none |
| Reload | restart required |

#### `dataplane.restart-max-backoff`

Longest wait between data plane restarts after repeated crashes.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `30s` |
| Environment | `SCRIM_DATAPLANE_RESTART_MAX_BACKOFF` |
| Flag | none |
| Reload | hot |

#### `dataplane.start-timeout`

How long the data plane may take to start and answer the handshake.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `10s` |
| Environment | `SCRIM_DATAPLANE_START_TIMEOUT` |
| Flag | none |
| Reload | hot |

### entry

#### `entry.listen`

Loopback address of the page where a human enters a value for secret_ask_human. Port 0 picks a free port.

| | |
|---|---|
| Type | string |
| Default | `127.0.0.1:0` |
| Environment | `SCRIM_ENTRY_LISTEN` |
| Flag | none |
| Reload | restart required |

### grants

#### `grants.default-ttl`

Grant duration when neither the rule nor the approver chooses one.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `30m0s` |
| Environment | `SCRIM_GRANTS_DEFAULT_TTL` |
| Flag | none |
| Reload | hot |

#### `grants.max-ttl`

Longest grant any rule or approver can create. A rule's grant.max_ttl can only lower it.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `8h0m0s` |
| Environment | `SCRIM_GRANTS_MAX_TTL` |
| Flag | none |
| Reload | hot |

### identity

#### `identity.peers`

Agents by local user or group: agent name to space-separated selectors uid:N, user:NAME, gid:N, group:NAME, scope:SCOPE, label:K=V. Empty maps the user scrim runs as to one agent named after it.

| | |
|---|---|
| Type | map of strings (env: JSON object or `k=v,k2=v2`; one entry: variable plus `_ENTRY`) |
| Default | `{}` |
| Environment | `SCRIM_IDENTITY_PEERS` |
| Flag | none |
| Reload | restart required |

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

Address of the metrics and health endpoint (Prometheus format at /metrics, /healthz or /livez, /readyz). Empty disables it; bind to loopback unless scraped remotely.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_METRICS_LISTEN` |
| Flag | `--metrics-listen` |
| Reload | restart required |

### notify

#### `notify.ntfy.priority`

ntfy message priority, 1 (min) to 5 (max).

| | |
|---|---|
| Type | int |
| Default | `4` |
| Environment | `SCRIM_NOTIFY_NTFY_PRIORITY` |
| Flag | none |
| Reload | hot |

#### `notify.ntfy.token`

Reference to an ntfy access token for publishing. Empty publishes anonymously.

| | |
|---|---|
| Type | secret reference (`env:`, `file:`, `cred:` or a store reference; a literal is warned about) |
| Default | empty |
| Environment | `SCRIM_NOTIFY_NTFY_TOKEN` |
| Flag | none |
| Reload | hot |

#### `notify.ntfy.topic`

ntfy topic approval requests are published to. Anyone who can read the topic sees approval metadata, so use an access-controlled topic or a long random name.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_NOTIFY_NTFY_TOPIC` |
| Flag | none |
| Reload | hot |

#### `notify.ntfy.url`

Base URL of the ntfy server, for example https://ntfy.sh. Empty disables the ntfy notifier.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_NOTIFY_NTFY_URL` |
| Flag | none |
| Reload | hot |

#### `notify.terminal.enabled`

Print each approval request with its scrim approve and scrim deny commands to the control plane's terminal.

| | |
|---|---|
| Type | bool |
| Default | `true` |
| Environment | `SCRIM_NOTIFY_TERMINAL_ENABLED` |
| Flag | none |
| Reload | hot |

#### `notify.webhook.hold`

Longest time one submit or poll request is held open by the receiver (sent as X-Nono-Timeout-Secs, capped by the approval's remaining time).

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `30s` |
| Environment | `SCRIM_NOTIFY_WEBHOOK_HOLD` |
| Flag | none |
| Reload | hot |

#### `notify.webhook.poll-interval`

Pause between polls when the receiver answers pending without holding.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `2s` |
| Environment | `SCRIM_NOTIFY_WEBHOOK_POLL_INTERVAL` |
| Flag | none |
| Reload | hot |

#### `notify.webhook.secret`

Reference to the shared secret (at least 32 bytes) that signs webhook requests with HMAC-SHA256. Empty sends unsigned requests.

| | |
|---|---|
| Type | secret reference (`env:`, `file:`, `cred:` or a store reference; a literal is warned about) |
| Default | empty |
| Environment | `SCRIM_NOTIFY_WEBHOOK_SECRET` |
| Flag | none |
| Reload | hot |

#### `notify.webhook.url`

Approval service URL for the webhook notifier (nono approval webhook v1 compatible). https, or http to a loopback host. Empty disables it.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_NOTIFY_WEBHOOK_URL` |
| Flag | none |
| Reload | hot |

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

#### `policy.deny-all`

Break-glass: deny every injection, grant and approval while redaction continues. While set in configuration it cannot be released from the CLI.

| | |
|---|---|
| Type | bool |
| Default | `false` |
| Environment | `SCRIM_POLICY_DENY_ALL` |
| Flag | `--policy-deny-all` |
| Reload | hot |

#### `policy.deny-all-refresh`

How often each replica re-reads the deny-all state from the state backend; the bound on how long a change on one replica takes to reach the others.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `1s` |
| Environment | `SCRIM_POLICY_DENY_ALL_REFRESH` |
| Flag | none |
| Reload | hot |

#### `policy.rules-file`

Path of the policy rules file (YAML or JSON with default and rules). Empty means no rules: every request gets policy.default.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_POLICY_RULES_FILE` |
| Flag | `--policy-rules-file` |
| Reload | hot |

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

### session

#### `session.max-ttl`

Longest lifetime a session token can be minted with.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `168h0m0s` |
| Environment | `SCRIM_SESSION_MAX_TTL` |
| Flag | none |
| Reload | restart required |

#### `session.ttl`

Default lifetime of a session token minted by scrim run. The token is revoked earlier when scrim run exits.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `12h0m0s` |
| Environment | `SCRIM_SESSION_TTL` |
| Flag | none |
| Reload | restart required |

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

#### `state.postgres.connect-timeout`

How long start-up waits for PostgreSQL to answer before failing.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `15s` |
| Environment | `SCRIM_STATE_POSTGRES_CONNECT_TIMEOUT` |
| Flag | none |
| Reload | restart required |

#### `state.postgres.dsn`

Reference to the PostgreSQL connection string (postgres://user:pass@host/db?sslmode=verify-full), for example env:SCRIM_PG_DSN or file:/run/secrets/scrim-dsn. It holds a password, so it is a reference.

| | |
|---|---|
| Type | secret reference (`env:`, `file:`, `cred:` or a store reference; a literal is warned about) |
| Default | empty |
| Environment | `SCRIM_STATE_POSTGRES_DSN` |
| Flag | none |
| Reload | restart required |

#### `state.postgres.max-conns`

Maximum connections in the PostgreSQL pool.

| | |
|---|---|
| Type | int |
| Default | `16` |
| Environment | `SCRIM_STATE_POSTGRES_MAX_CONNS` |
| Flag | none |
| Reload | restart required |

#### `state.sqlite.allow-network-filesystem`

Allows the SQLite state file on a network or shared filesystem (NFS, SMB, sshfs), where file locking is unreliable and the database can be corrupted. Use the postgres backend instead.

| | |
|---|---|
| Type | bool |
| Default | `false` |
| Environment | `SCRIM_STATE_SQLITE_ALLOW_NETWORK_FILESYSTEM` |
| Flag | none |
| Reload | restart required |
| Weakening | **yes**: logged at start-up and on reload while active, listed in `scrim status` |

#### `state.sqlite.path`

SQLite state file. Empty means $XDG_STATE_HOME/scrim/state.db (~/.local/state/scrim/state.db).

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_STATE_SQLITE_PATH` |
| Flag | `--state-sqlite-path` |
| Reload | restart required |

### tool-proxy

#### `tool-proxy.ca.cert-file`

PEM certificate of an operator-supplied interception CA, used together with tool-proxy.ca.key. An operator-supplied CA is never rotated by scrim; a warning is logged once it is within tool-proxy.ca.rotate-before of expiry.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_TOOL_PROXY_CA_CERT_FILE` |
| Flag | none |
| Reload | restart required |

#### `tool-proxy.ca.dir`

Directory of the generated interception CA (certificates, private keys, rotation state, trust manifest). Empty means $XDG_STATE_HOME/scrim/ca (~/.local/state/scrim/ca). Created with mode 0700.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_TOOL_PROXY_CA_DIR` |
| Flag | none |
| Reload | restart required |

#### `tool-proxy.ca.key`

Reference to the PKCS#8 PEM private key of the operator-supplied CA in tool-proxy.ca.cert-file (env:, file:, cred: or a store reference). Empty means scrim generates and rotates its own CA.

| | |
|---|---|
| Type | secret reference (`env:`, `file:`, `cred:` or a store reference; literals rejected) |
| Default | empty |
| Environment | `SCRIM_TOOL_PROXY_CA_KEY` |
| Flag | none |
| Reload | restart required |

#### `tool-proxy.ca.overlap`

After a rotation, how long the previous CA stays trusted through a cross certificate and in the trust bundle. Capped at the previous certificate's expiry.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `168h0m0s` |
| Environment | `SCRIM_TOOL_PROXY_CA_OVERLAP` |
| Flag | none |
| Reload | restart required |

#### `tool-proxy.ca.rotate-before`

A generated CA is rotated when less than this much of its validity remains. For an operator-supplied CA it is how early the expiry warning starts.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `720h0m0s` |
| Environment | `SCRIM_TOOL_PROXY_CA_ROTATE_BEFORE` |
| Flag | none |
| Reload | restart required |

#### `tool-proxy.ca.validity`

Validity of each generated CA certificate.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `17520h0m0s` |
| Environment | `SCRIM_TOOL_PROXY_CA_VALIDITY` |
| Flag | none |
| Reload | restart required |

### tools

#### `tools.approval-timeout`

How long a pending approval waits for a decision before it expires as denied.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `15m0s` |
| Environment | `SCRIM_TOOLS_APPROVAL_TIMEOUT` |
| Flag | none |
| Reload | restart required |

#### `tools.grant-default-ttl`

Duration of a grant when secret_request names none.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `15m0s` |
| Environment | `SCRIM_TOOLS_GRANT_DEFAULT_TTL` |
| Flag | none |
| Reload | restart required |

#### `tools.grant-max-ttl`

Longest grant secret_request can produce. Longer requests are capped and the result says so.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `8h0m0s` |
| Environment | `SCRIM_TOOLS_GRANT_MAX_TTL` |
| Flag | none |
| Reload | restart required |

### tracing

#### `tracing.endpoint`

OTLP/HTTP collector URL for traces, for example http://127.0.0.1:4318. Empty disables export; incoming W3C trace context is still propagated.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_TRACING_ENDPOINT` |
| Flag | `--tracing-endpoint` |
| Reload | restart required |

#### `tracing.sample-ratio`

Fraction of new root traces sampled, 0 to 1. A sampled incoming parent is always followed.

| | |
|---|---|
| Type | float |
| Default | `1` |
| Environment | `SCRIM_TRACING_SAMPLE_RATIO` |
| Flag | none |
| Reload | restart required |

<!-- END GENERATED SETTINGS REFERENCE -->
