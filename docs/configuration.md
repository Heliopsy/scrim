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

```sh test env
SCRIM_PROXY_NO_PROXY='["127.0.0.1","localhost"]'
SCRIM_PROXY_NO_PROXY='127.0.0.1,localhost'
```

Maps take a JSON object or `key=value` pairs separated by commas. One entry of a map is set by
adding its name to the variable, lower-cased words with `_` for `-`; it merges into the map from
the lower layers, while the whole-map variable replaces it:

```sh test env
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

```sh test
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
| [`admin.token`](#admintoken) | secret-ref | empty | hot |
| [`admin.url`](#adminurl) | string | `""` | hot |
| [`api.group`](#apigroup) | string | `""` | restart required |
| [`api.permissions`](#apipermissions) | string | `0600` | restart required |
| [`api.socket`](#apisocket) | string | `""` | restart required |
| [`approvals.listen`](#approvalslisten) | string | `""` | restart required |
| [`approvals.poll-interval`](#approvalspoll-interval) | duration | `1s` | hot |
| [`approvals.public-url`](#approvalspublic-url) | string | `""` | hot |
| [`approvals.signing-key`](#approvalssigning-key) | secret-ref | empty | hot |
| [`approvals.timeout`](#approvalstimeout) | duration | `2m0s` | hot |
| [`audit.kafka.batch-size`](#auditkafkabatch-size) | int | `500` | restart required |
| [`audit.kafka.brokers`](#auditkafkabrokers) | list | `[]` | restart required |
| [`audit.kafka.password`](#auditkafkapassword) | secret-ref | empty | restart required |
| [`audit.kafka.policy`](#auditkafkapolicy) | string | `drop` | restart required |
| [`audit.kafka.queue-size`](#auditkafkaqueue-size) | int | `10000` | restart required |
| [`audit.kafka.sasl-mechanism`](#auditkafkasasl-mechanism) | string | `none` | restart required |
| [`audit.kafka.timeout`](#auditkafkatimeout) | duration | `5s` | restart required |
| [`audit.kafka.tls`](#auditkafkatls) | bool | `false` | restart required |
| [`audit.kafka.tls-ca-file`](#auditkafkatls-ca-file) | string | `""` | restart required |
| [`audit.kafka.topic`](#auditkafkatopic) | string | `scrim-audit` | restart required |
| [`audit.kafka.username`](#auditkafkausername) | string | `""` | restart required |
| [`audit.kafka.write-timeout`](#auditkafkawrite-timeout) | duration | `10s` | restart required |
| [`audit.loki.batch-size`](#auditlokibatch-size) | int | `500` | restart required |
| [`audit.loki.labels`](#auditlokilabels) | map | `{}` | restart required |
| [`audit.loki.password`](#auditlokipassword) | secret-ref | empty | restart required |
| [`audit.loki.policy`](#auditlokipolicy) | string | `drop` | restart required |
| [`audit.loki.queue-size`](#auditlokiqueue-size) | int | `10000` | restart required |
| [`audit.loki.tenant`](#auditlokitenant) | string | `""` | restart required |
| [`audit.loki.timeout`](#auditlokitimeout) | duration | `5s` | restart required |
| [`audit.loki.url`](#auditlokiurl) | string | `""` | restart required |
| [`audit.loki.username`](#auditlokiusername) | string | `""` | restart required |
| [`audit.loki.write-timeout`](#auditlokiwrite-timeout) | duration | `10s` | restart required |
| [`audit.otlp.batch-size`](#auditotlpbatch-size) | int | `500` | restart required |
| [`audit.otlp.endpoint`](#auditotlpendpoint) | string | `""` | restart required |
| [`audit.otlp.policy`](#auditotlppolicy) | string | `drop` | restart required |
| [`audit.otlp.queue-size`](#auditotlpqueue-size) | int | `10000` | restart required |
| [`audit.otlp.timeout`](#auditotlptimeout) | duration | `5s` | restart required |
| [`audit.otlp.token`](#auditotlptoken) | secret-ref | empty | restart required |
| [`audit.otlp.write-timeout`](#auditotlpwrite-timeout) | duration | `10s` | restart required |
| [`audit.sinks`](#auditsinks) | list | `["db"]` | restart required |
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
| [`dataplane.push-debounce`](#dataplanepush-debounce) | duration | `200ms` | hot |
| [`dataplane.restart-max-backoff`](#dataplanerestart-max-backoff) | duration | `30s` | hot |
| [`dataplane.start-timeout`](#dataplanestart-timeout) | duration | `10s` | hot |
| [`dataplane.upstream-ca-file`](#dataplaneupstream-ca-file) | string | `""` | restart required |
| [`deployment.replicas`](#deploymentreplicas) | int | `1` | restart required |
| [`entry.listen`](#entrylisten) | string | `127.0.0.1:0` | restart required |
| [`events.backend`](#eventsbackend) | string | `local` | restart required |
| [`events.nats.subject`](#eventsnatssubject) | string | `scrim.events` | restart required |
| [`events.poll-interval`](#eventspoll-interval) | duration | `1s` | restart required |
| [`events.valkey.channel`](#eventsvalkeychannel) | string | `scrim:events` | restart required |
| [`grants.default-ttl`](#grantsdefault-ttl) | duration | `30m0s` | hot |
| [`grants.max-ttl`](#grantsmax-ttl) | duration | `8h0m0s` | hot |
| [`identity.kubernetes.agents`](#identitykubernetesagents) | map | `{}` | restart required |
| [`identity.kubernetes.api-server`](#identitykubernetesapi-server) | string | `""` | restart required |
| [`identity.kubernetes.audience`](#identitykubernetesaudience) | string | `scrim` | restart required |
| [`identity.kubernetes.ca-file`](#identitykubernetesca-file) | string | `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt` | restart required |
| [`identity.kubernetes.cache-ttl`](#identitykubernetescache-ttl) | duration | `1m0s` | restart required |
| [`identity.kubernetes.enabled`](#identitykubernetesenabled) | bool | `false` | restart required |
| [`identity.kubernetes.token-file`](#identitykubernetestoken-file) | string | `/var/run/secrets/kubernetes.io/serviceaccount/token` | restart required |
| [`identity.kubernetes.unmapped`](#identitykubernetesunmapped) | string | `derive` | restart required |
| [`identity.peers`](#identitypeers) | map | `{}` | restart required |
| [`identity.store-credentials`](#identitystore-credentials) | map | `{}` | restart required |
| [`identity.store-login`](#identitystore-login) | map | `{}` | restart required |
| [`interception.ebpf.cgroups`](#interceptionebpfcgroups) | list | `[]` | hot |
| [`interception.ebpf.port`](#interceptionebpfport) | int | `9792` | hot |
| [`log.format`](#logformat) | string | `text` | hot |
| [`log.level`](#loglevel) | string | `info` | hot |
| [`metrics.allow-unauthenticated-remote`](#metricsallow-unauthenticated-remote) | bool | `false` | restart required |
| [`metrics.auth.token`](#metricsauthtoken) | secret-ref | empty | restart required |
| [`metrics.enabled`](#metricsenabled) | bool | `false` | restart required |
| [`metrics.listen`](#metricslisten) | string | `127.0.0.1:9792` | restart required |
| [`metrics.path`](#metricspath) | string | `/metrics` | restart required |
| [`nats.credentials-file`](#natscredentials-file) | string | `""` | restart required |
| [`nats.password`](#natspassword) | secret-ref | empty | restart required |
| [`nats.servers`](#natsservers) | list | `[]` | restart required |
| [`nats.timeout`](#natstimeout) | duration | `5s` | restart required |
| [`nats.tls-ca-file`](#natstls-ca-file) | string | `""` | restart required |
| [`nats.token`](#natstoken) | secret-ref | empty | restart required |
| [`nats.username`](#natsusername) | string | `""` | restart required |
| [`notify.ntfy.priority`](#notifyntfypriority) | int | `4` | hot |
| [`notify.ntfy.token`](#notifyntfytoken) | secret-ref | empty | hot |
| [`notify.ntfy.topic`](#notifyntfytopic) | string | `""` | hot |
| [`notify.ntfy.url`](#notifyntfyurl) | string | `""` | hot |
| [`notify.terminal.enabled`](#notifyterminalenabled) | bool | `true` | hot |
| [`notify.webhook.hold`](#notifywebhookhold) | duration | `30s` | hot |
| [`notify.webhook.poll-interval`](#notifywebhookpoll-interval) | duration | `2s` | hot |
| [`notify.webhook.secret`](#notifywebhooksecret) | secret-ref | empty | hot |
| [`notify.webhook.url`](#notifywebhookurl) | string | `""` | hot |
| [`policy.builtin.inject`](#policybuiltininject) | string | `allow` | hot |
| [`policy.default`](#policydefault) | string | `deny` | hot |
| [`policy.deny-all`](#policydeny-all) | bool | `false` | hot |
| [`policy.deny-all-refresh`](#policydeny-all-refresh) | duration | `1s` | hot |
| [`policy.rules-file`](#policyrules-file) | string | `""` | hot |
| [`profile`](#profile) | string | `local` | hot |
| [`proxy.capture.dir`](#proxycapturedir) | string | `""` | restart required |
| [`proxy.capture.retention`](#proxycaptureretention) | duration | `168h0m0s` | restart required |
| [`proxy.chain.on-unavailable`](#proxychainon-unavailable) | string | `fail` | hot |
| [`proxy.chain.url`](#proxychainurl) | string | `""` | hot |
| [`proxy.forward-listen`](#proxyforward-listen) | string | `127.0.0.1:9791` | restart required |
| [`proxy.listen`](#proxylisten) | string | `127.0.0.1:9790` | restart required |
| [`proxy.sni-listen`](#proxysni-listen) | string | `""` | restart required |
| [`proxy.socket`](#proxysocket) | string | `""` | restart required |
| [`proxy.transparent-listen`](#proxytransparent-listen) | list | `[]` | restart required |
| [`proxy.transparent-unrouted`](#proxytransparent-unrouted) | string | `pass` | restart required |
| [`proxy.upstream.anthropic`](#proxyupstreamanthropic) | string | `https://api.anthropic.com` | hot |
| [`proxy.upstream.chatgpt`](#proxyupstreamchatgpt) | string | `https://chatgpt.com` | hot |
| [`proxy.upstream.chatgpt-ab`](#proxyupstreamchatgpt-ab) | string | `https://ab.chatgpt.com` | hot |
| [`proxy.upstream.openai`](#proxyupstreamopenai) | string | `https://api.openai.com` | hot |
| [`ratelimit.agent-api.burst`](#ratelimitagent-apiburst) | int | `120` | hot |
| [`ratelimit.agent-api.interval`](#ratelimitagent-apiinterval) | duration | `1m0s` | hot |
| [`ratelimit.agent-api.rate`](#ratelimitagent-apirate) | int | `600` | hot |
| [`ratelimit.approvals.burst`](#ratelimitapprovalsburst) | int | `10` | hot |
| [`ratelimit.approvals.interval`](#ratelimitapprovalsinterval) | duration | `1h0m0s` | hot |
| [`ratelimit.approvals.rate`](#ratelimitapprovalsrate) | int | `60` | hot |
| [`ratelimit.asks.burst`](#ratelimitasksburst) | int | `5` | hot |
| [`ratelimit.asks.interval`](#ratelimitasksinterval) | duration | `1h0m0s` | hot |
| [`ratelimit.asks.rate`](#ratelimitasksrate) | int | `30` | hot |
| [`ratelimit.backend`](#ratelimitbackend) | string | `local` | restart required |
| [`ratelimit.valkey.prefix`](#ratelimitvalkeyprefix) | string | `scrim:rl:` | restart required |
| [`redaction.allow-empty-targets`](#redactionallow-empty-targets) | bool | `false` | restart required |
| [`redaction.min-value-length`](#redactionmin-value-length) | int | `8` | hot |
| [`redaction.placeholder-key-dir`](#redactionplaceholder-key-dir) | string | `""` | restart required |
| [`restore.allow-reveal-credentials`](#restoreallow-reveal-credentials) | list | `[]` | hot |
| [`restore.allow-shell-data-commands`](#restoreallow-shell-data-commands) | list | `[]` | hot |
| [`restore.builtin-tools`](#restorebuiltin-tools) | bool | `true` | hot |
| [`restore.display-mode`](#restoredisplay-mode) | string | `values` | hot |
| [`run.allow-unredacted-start`](#runallow-unredacted-start) | bool | `false` | hot |
| [`run.fs-view`](#runfs-view) | string | `auto` | hot |
| [`run.fs-view-hide`](#runfs-view-hide) | list | `[".ssh/id_*","!.ssh/id_*.pub"]` | hot |
| [`run.mcp`](#runmcp) | bool | `true` | hot |
| [`run.placeholder-env`](#runplaceholder-env) | bool | `true` | hot |
| [`run.profiles`](#runprofiles) | list | `["auto"]` | hot |
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
| [`tool-proxy.listen`](#tool-proxylisten) | string | `""` | restart required |
| [`tools.approval-timeout`](#toolsapproval-timeout) | duration | `15m0s` | restart required |
| [`tools.grant-default-ttl`](#toolsgrant-default-ttl) | duration | `15m0s` | restart required |
| [`tools.grant-max-ttl`](#toolsgrant-max-ttl) | duration | `8h0m0s` | restart required |
| [`tracing.endpoint`](#tracingendpoint) | string | `""` | restart required |
| [`tracing.sample-ratio`](#tracingsample-ratio) | float | `1` | restart required |
| [`valkey.addresses`](#valkeyaddresses) | list | `[]` | restart required |
| [`valkey.db`](#valkeydb) | int | `0` | restart required |
| [`valkey.password`](#valkeypassword) | secret-ref | empty | restart required |
| [`valkey.timeout`](#valkeytimeout) | duration | `5s` | restart required |
| [`valkey.tls`](#valkeytls) | bool | `false` | restart required |
| [`valkey.tls-ca-file`](#valkeytls-ca-file) | string | `""` | restart required |
| [`valkey.username`](#valkeyusername) | string | `""` | restart required |
| [`catalog.entries.<name>.*`](#catalogentriesname) | collection | empty | hot |
| [`redaction.placeholder-keys.<name>.*`](#redactionplaceholder-keysname) | collection | empty | hot |
| [`restore.tools.<name>.*`](#restoretoolsname) | collection | empty | hot |
| [`stores.<name>.*`](#storesname) | collection | empty | restart required |
| [`tool-profiles.<name>.*`](#tool-profilesname) | collection | empty | hot |
| [`tool-proxy.capture-rules.<name>.*`](#tool-proxycapture-rulesname) | collection | empty | hot |

### `catalog.entries.<name>`

Catalog entries by logical name: ref, profiles, variants, prefix, template, hosts, placeholder, class, inject, tools. References only, never values.

| | |
|---|---|
| Type | collection of named instances (names: lower-case words with dashes) |
| Environment | `SCRIM_CATALOG_ENTRIES` (JSON object of instances, replaces the collection); `SCRIM_CATALOG_ENTRIES_<NAME>_<FIELD>` for one field |
| Reload | hot |

### `redaction.placeholder-keys.<name>`

Placeholder keys by name, each with `version` (1 to 255) and `key` (a reference to at least 16 bytes). The highest version is current; lower ones keep resolving placeholders made before a rotation. Every replica sharing conversations needs the same keys. Empty means a key generated once and kept in redaction.placeholder-key-dir.

| | |
|---|---|
| Type | collection of named instances (names: lower-case words with dashes) |
| Environment | `SCRIM_REDACTION_PLACEHOLDER_KEYS` (JSON object of instances, replaces the collection); `SCRIM_REDACTION_PLACEHOLDER_KEYS_<NAME>_<FIELD>` for one field |
| Required fields | `version`, `key` |
| Secret fields | `key` (references; a literal is warned about) |
| Reload | hot |

### `restore.tools.<name>`

Tool aliases by name: `role` (none, read, search, shell, edit, write, network), optional `name` (the tool name exactly as the model calls it, default the instance name), `command-field` for shell, `old-fields` and `new-fields` for edit. An alias overrides the built-in table.

| | |
|---|---|
| Type | collection of named instances (names: lower-case words with dashes) |
| Environment | `SCRIM_RESTORE_TOOLS` (JSON object of instances, replaces the collection); `SCRIM_RESTORE_TOOLS_<NAME>_<FIELD>` for one field |
| Required fields | `role` |
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

### `tool-profiles.<name>`

Tool profiles by name: description, tools, requires, credentials (name, hosts, inject, required), params, env, unset, dirs, files (path, content), paths (home, generated), test (command, expect), notes. A name that matches a built-in profile overrides the fields it sets (params are merged key by key). Templates hold placeholders only, never values. See docs/cli-tools.md.

| | |
|---|---|
| Type | collection of named instances (names: lower-case words with dashes) |
| Environment | `SCRIM_TOOL_PROFILES` (JSON object of instances, replaces the collection); `SCRIM_TOOL_PROFILES_<NAME>_<FIELD>` for one field |
| Reload | hot |

### `tool-proxy.capture-rules.<name>`

Response capture rules by name: `hosts`, optional `methods`, `path` glob and `status` codes select the response; exactly one of `json-pointer` and `header` selects the field; `store-ref` is the store reference the value is written to. The agent receives the reference's placeholder instead.

| | |
|---|---|
| Type | collection of named instances (names: lower-case words with dashes) |
| Environment | `SCRIM_TOOL_PROXY_CAPTURE_RULES` (JSON object of instances, replaces the collection); `SCRIM_TOOL_PROXY_CAPTURE_RULES_<NAME>_<FIELD>` for one field |
| Required fields | `hosts`, `store-ref` |
| Reload | hot |

### admin

#### `admin.token`

Reference to the bearer token operators present on a TCP admin listener (admin.url http://host:port). Required for TCP; the Unix socket uses peer credentials instead. scrim approve and friends send it.

| | |
|---|---|
| Type | secret reference (`env:`, `file:`, `cred:` or a store reference; a literal is warned about) |
| Default | empty |
| Environment | `SCRIM_ADMIN_TOKEN` |
| Flag | none |
| Reload | hot |

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

#### `api.group`

Group (name or ID) the API socket belongs to, so members can connect with api.permissions 0660. scrim must be a member. Empty keeps the group of the process.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_API_GROUP` |
| Flag | none |
| Reload | restart required |

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

#### `approvals.listen`

TCP address that serves only the decision-link endpoint, for approvals.public-url to point at (usually through a TLS reverse proxy). Empty means decision links are served on the admin listener only.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_APPROVALS_LISTEN` |
| Flag | `--approvals-listen` |
| Reload | restart required |

#### `approvals.poll-interval`

How often a waiting operation re-reads its approval from the state backend; bounds how long a decision recorded on another replica takes to release it when no event announces it (events.backend).

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

### audit

#### `audit.kafka.batch-size`

How many audit entries one write to the kafka sink carries at most.

| | |
|---|---|
| Type | int |
| Default | `500` |
| Environment | `SCRIM_AUDIT_KAFKA_BATCH_SIZE` |
| Flag | none |
| Reload | restart required |

#### `audit.kafka.brokers`

Seed brokers (host:port) of the Kafka (or Redpanda) cluster of the kafka audit sink.

| | |
|---|---|
| Type | list of strings (env: JSON array or comma-separated, `\,` for a comma) |
| Default | `[]` |
| Environment | `SCRIM_AUDIT_KAFKA_BROKERS` |
| Flag | none |
| Reload | restart required |

#### `audit.kafka.password`

Reference to the SASL password of the kafka audit sink.

| | |
|---|---|
| Type | secret reference (`env:`, `file:`, `cred:` or a store reference; literals rejected) |
| Default | empty |
| Environment | `SCRIM_AUDIT_KAFKA_PASSWORD` |
| Flag | none |
| Reload | restart required |

#### `audit.kafka.policy`

What happens when the kafka sink's queue is full because the sink is slow or down: block makes the audited operation wait up to audit.kafka.timeout and then refuses it; drop lets it through and counts the entry in scrim_audit_sink_dropped_total (it stays in the database audit log). Never silent either way.

| | |
|---|---|
| Type | string |
| Default | `drop` |
| Environment | `SCRIM_AUDIT_KAFKA_POLICY` |
| Flag | none |
| Reload | restart required |
| Values | `block`, `drop` |

#### `audit.kafka.queue-size`

How many audit entries wait for the kafka sink at most.

| | |
|---|---|
| Type | int |
| Default | `10000` |
| Environment | `SCRIM_AUDIT_KAFKA_QUEUE_SIZE` |
| Flag | none |
| Reload | restart required |

#### `audit.kafka.sasl-mechanism`

SASL mechanism of the kafka audit sink; plain needs audit.kafka.tls.

| | |
|---|---|
| Type | string |
| Default | `none` |
| Environment | `SCRIM_AUDIT_KAFKA_SASL_MECHANISM` |
| Flag | none |
| Reload | restart required |
| Values | `none`, `plain`, `scram-sha-256`, `scram-sha-512` |

#### `audit.kafka.timeout`

With audit.kafka.policy block, how long an audited operation waits for room in the kafka queue before it is refused.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `5s` |
| Environment | `SCRIM_AUDIT_KAFKA_TIMEOUT` |
| Flag | none |
| Reload | restart required |

#### `audit.kafka.tls`

Connect to the Kafka brokers over TLS, verified against the system roots or audit.kafka.tls-ca-file.

| | |
|---|---|
| Type | bool |
| Default | `false` |
| Environment | `SCRIM_AUDIT_KAFKA_TLS` |
| Flag | none |
| Reload | restart required |

#### `audit.kafka.tls-ca-file`

PEM file of the certificate authorities that sign the Kafka broker certificates; empty uses the system roots.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_AUDIT_KAFKA_TLS_CA_FILE` |
| Flag | none |
| Reload | restart required |

#### `audit.kafka.topic`

Topic the kafka audit sink produces to. Records are keyed by agent, so one agent's entries stay in order on one partition.

| | |
|---|---|
| Type | string |
| Default | `scrim-audit` |
| Environment | `SCRIM_AUDIT_KAFKA_TOPIC` |
| Flag | none |
| Reload | restart required |

#### `audit.kafka.username`

SASL user of the kafka audit sink.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_AUDIT_KAFKA_USERNAME` |
| Flag | none |
| Reload | restart required |

#### `audit.kafka.write-timeout`

How long one write to the kafka sink may take before it counts as failed and is retried.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `10s` |
| Environment | `SCRIM_AUDIT_KAFKA_WRITE_TIMEOUT` |
| Flag | none |
| Reload | restart required |

#### `audit.loki.batch-size`

How many audit entries one write to the loki sink carries at most.

| | |
|---|---|
| Type | int |
| Default | `500` |
| Environment | `SCRIM_AUDIT_LOKI_BATCH_SIZE` |
| Flag | none |
| Reload | restart required |

#### `audit.loki.labels`

Extra static stream labels for audit entries in Loki, added to service_name=scrim and source=audit. Keep them low-cardinality; per-entry fields are in the JSON line.

| | |
|---|---|
| Type | map of strings (env: JSON object or `k=v,k2=v2`; one entry: variable plus `_ENTRY`) |
| Default | `{}` |
| Environment | `SCRIM_AUDIT_LOKI_LABELS` |
| Flag | none |
| Reload | restart required |

#### `audit.loki.password`

Reference to the basic auth password (or bearer token with an empty audit.loki.username) of the loki audit sink.

| | |
|---|---|
| Type | secret reference (`env:`, `file:`, `cred:` or a store reference; literals rejected) |
| Default | empty |
| Environment | `SCRIM_AUDIT_LOKI_PASSWORD` |
| Flag | none |
| Reload | restart required |

#### `audit.loki.policy`

What happens when the loki sink's queue is full because the sink is slow or down: block makes the audited operation wait up to audit.loki.timeout and then refuses it; drop lets it through and counts the entry in scrim_audit_sink_dropped_total (it stays in the database audit log). Never silent either way.

| | |
|---|---|
| Type | string |
| Default | `drop` |
| Environment | `SCRIM_AUDIT_LOKI_POLICY` |
| Flag | none |
| Reload | restart required |
| Values | `block`, `drop` |

#### `audit.loki.queue-size`

How many audit entries wait for the loki sink at most.

| | |
|---|---|
| Type | int |
| Default | `10000` |
| Environment | `SCRIM_AUDIT_LOKI_QUEUE_SIZE` |
| Flag | none |
| Reload | restart required |

#### `audit.loki.tenant`

Loki tenant (X-Scope-OrgID) for the loki audit sink; empty for a single-tenant Loki.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_AUDIT_LOKI_TENANT` |
| Flag | none |
| Reload | restart required |

#### `audit.loki.timeout`

With audit.loki.policy block, how long an audited operation waits for room in the loki queue before it is refused.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `5s` |
| Environment | `SCRIM_AUDIT_LOKI_TIMEOUT` |
| Flag | none |
| Reload | restart required |

#### `audit.loki.url`

Base URL of Loki (or a compatible push endpoint) for the loki audit sink; entries are pushed to <url>/loki/api/v1/push.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_AUDIT_LOKI_URL` |
| Flag | none |
| Reload | restart required |

#### `audit.loki.username`

Basic auth user for the loki audit sink; empty for none.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_AUDIT_LOKI_USERNAME` |
| Flag | none |
| Reload | restart required |

#### `audit.loki.write-timeout`

How long one write to the loki sink may take before it counts as failed and is retried.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `10s` |
| Environment | `SCRIM_AUDIT_LOKI_WRITE_TIMEOUT` |
| Flag | none |
| Reload | restart required |

#### `audit.otlp.batch-size`

How many audit entries one write to the otlp sink carries at most.

| | |
|---|---|
| Type | int |
| Default | `500` |
| Environment | `SCRIM_AUDIT_OTLP_BATCH_SIZE` |
| Flag | none |
| Reload | restart required |

#### `audit.otlp.endpoint`

OTLP/HTTP logs endpoint of the otlp audit sink, a collector or a backend that takes OTLP logs: http(s)://host:4318 (the /v1/logs path is added unless the URL has a path).

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_AUDIT_OTLP_ENDPOINT` |
| Flag | none |
| Reload | restart required |

#### `audit.otlp.policy`

What happens when the otlp sink's queue is full because the sink is slow or down: block makes the audited operation wait up to audit.otlp.timeout and then refuses it; drop lets it through and counts the entry in scrim_audit_sink_dropped_total (it stays in the database audit log). Never silent either way.

| | |
|---|---|
| Type | string |
| Default | `drop` |
| Environment | `SCRIM_AUDIT_OTLP_POLICY` |
| Flag | none |
| Reload | restart required |
| Values | `block`, `drop` |

#### `audit.otlp.queue-size`

How many audit entries wait for the otlp sink at most.

| | |
|---|---|
| Type | int |
| Default | `10000` |
| Environment | `SCRIM_AUDIT_OTLP_QUEUE_SIZE` |
| Flag | none |
| Reload | restart required |

#### `audit.otlp.timeout`

With audit.otlp.policy block, how long an audited operation waits for room in the otlp queue before it is refused.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `5s` |
| Environment | `SCRIM_AUDIT_OTLP_TIMEOUT` |
| Flag | none |
| Reload | restart required |

#### `audit.otlp.token`

Reference to a bearer token sent to the otlp audit sink; empty for none.

| | |
|---|---|
| Type | secret reference (`env:`, `file:`, `cred:` or a store reference; literals rejected) |
| Default | empty |
| Environment | `SCRIM_AUDIT_OTLP_TOKEN` |
| Flag | none |
| Reload | restart required |

#### `audit.otlp.write-timeout`

How long one write to the otlp sink may take before it counts as failed and is retried.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `10s` |
| Environment | `SCRIM_AUDIT_OTLP_WRITE_TIMEOUT` |
| Flag | none |
| Reload | restart required |

#### `audit.sinks`

Where audit entries go: db (the state backend's audit log, always written, in the transaction of the change it records) plus any of otlp, loki and kafka, each fed from its own bounded queue with the backpressure policy audit.<sink>.policy.

| | |
|---|---|
| Type | list of strings (env: JSON array or comma-separated, `\,` for a comma) |
| Default | `["db"]` |
| Environment | `SCRIM_AUDIT_SINKS` |
| Flag | none |
| Reload | restart required |

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

#### `dataplane.push-debounce`

How long the control plane waits after a store, catalog, configuration or policy change before it pushes a new snapshot, so bursts of changes become one push.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `200ms` |
| Environment | `SCRIM_DATAPLANE_PUSH_DEBOUNCE` |
| Flag | none |
| Reload | hot |

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

#### `dataplane.upstream-ca-file`

PEM bundle of extra root certificates the data plane trusts for upstream TLS, in the LLM proxy and the tool proxy (private API hosts, a corporate TLS-inspecting proxy). The system roots stay trusted. A file that is set but unreadable, or holds no certificate, stops the data plane from starting. Empty means the system roots only.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_DATAPLANE_UPSTREAM_CA_FILE` |
| Flag | none |
| Reload | restart required |

### deployment

#### `deployment.replicas`

How many control plane replicas share this configuration and state. More than 1 needs a shared state backend (state.backend postgres) and a shared events backend (events.backend postgres, valkey or nats); start-up fails otherwise.

| | |
|---|---|
| Type | int |
| Default | `1` |
| Environment | `SCRIM_DEPLOYMENT_REPLICAS` |
| Flag | none |
| Reload | restart required |

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

### events

#### `events.backend`

How replicas learn about state changes made elsewhere (approval decisions, grant and session changes, break-glass, configuration reloads). local reads the outbox every events.poll-interval and serves one process; postgres adds LISTEN/NOTIFY on the state database (needs state.backend postgres); valkey and nats publish a wake-up on a Valkey channel (valkey.*) or a NATS subject (nats.*). Every backend delivers from the outbox, so a lost wake-up costs latency, never an event. One of postgres, valkey or nats is required when deployment.replicas is more than 1.

| | |
|---|---|
| Type | string |
| Default | `local` |
| Environment | `SCRIM_EVENTS_BACKEND` |
| Flag | `--events-backend` |
| Reload | restart required |
| Values | `local`, `postgres`, `valkey`, `nats` |

#### `events.nats.subject`

NATS subject the nats events backend publishes and subscribes to. Replicas of one deployment share it; two deployments on one NATS account need different subjects.

| | |
|---|---|
| Type | string |
| Default | `scrim.events` |
| Environment | `SCRIM_EVENTS_NATS_SUBJECT` |
| Flag | none |
| Reload | restart required |

#### `events.poll-interval`

How often the outbox is read when nothing announces new events: always with events.backend local, and while the postgres listener or the valkey or nats subscription is disconnected. It bounds how long a change made on another replica takes to arrive then.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `1s` |
| Environment | `SCRIM_EVENTS_POLL_INTERVAL` |
| Flag | none |
| Reload | restart required |

#### `events.valkey.channel`

Valkey channel the valkey events backend publishes and subscribes to. Replicas of one deployment share it; two deployments on one Valkey need different channels.

| | |
|---|---|
| Type | string |
| Default | `scrim:events` |
| Environment | `SCRIM_EVENTS_VALKEY_CHANNEL` |
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

#### `identity.kubernetes.agents`

Agents by service account: agent name to space-separated selectors sa:NAMESPACE/NAME (globs allowed), scope:SCOPE, label:K=V. A service account no rule maps is the agent NAMESPACE/NAME, or unknown with identity.kubernetes.unmapped: unknown.

| | |
|---|---|
| Type | map of strings (env: JSON object or `k=v,k2=v2`; one entry: variable plus `_ENTRY`) |
| Default | `{}` |
| Environment | `SCRIM_IDENTITY_KUBERNETES_AGENTS` |
| Flag | none |
| Reload | restart required |

#### `identity.kubernetes.api-server`

Base URL of the Kubernetes API server for TokenReview. Empty uses the in-cluster address (KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT).

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_IDENTITY_KUBERNETES_API_SERVER` |
| Flag | none |
| Reload | restart required |

#### `identity.kubernetes.audience`

Audience an agent's projected service account token must carry. Tokens for any other audience, such as a pod's default API token, are refused.

| | |
|---|---|
| Type | string |
| Default | `scrim` |
| Environment | `SCRIM_IDENTITY_KUBERNETES_AUDIENCE` |
| Flag | none |
| Reload | restart required |

#### `identity.kubernetes.ca-file`

CA bundle that verifies the API server.

| | |
|---|---|
| Type | string |
| Default | `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt` |
| Environment | `SCRIM_IDENTITY_KUBERNETES_CA_FILE` |
| Flag | none |
| Reload | restart required |

#### `identity.kubernetes.cache-ttl`

How long a verified token is trusted before the cluster is asked again, capped at the token's expiry. A deleted pod or service account is refused within this bound.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `1m0s` |
| Environment | `SCRIM_IDENTITY_KUBERNETES_CACHE_TTL` |
| Flag | none |
| Reload | restart required |

#### `identity.kubernetes.enabled`

Identify in-cluster callers by projected service account tokens, verified with the TokenReview API. Pods send the token as the password of the proxy user k8s or as the value of x-scrim-session. On in the k8s profile.

| | |
|---|---|
| Type | bool |
| Default | `false` |
| Environment | `SCRIM_IDENTITY_KUBERNETES_ENABLED` |
| Flag | none |
| Reload | restart required |
| Profiles | k8s: `true` |

#### `identity.kubernetes.token-file`

scrim's own service account token, which authorises TokenReview calls (RBAC: create tokenreviews, for example by binding system:auth-delegator). Re-read on every call, since the kubelet rotates it.

| | |
|---|---|
| Type | string |
| Default | `/var/run/secrets/kubernetes.io/serviceaccount/token` |
| Environment | `SCRIM_IDENTITY_KUBERNETES_TOKEN_FILE` |
| Flag | none |
| Reload | restart required |

#### `identity.kubernetes.unmapped`

What a verified service account no identity.kubernetes.agents rule maps becomes: derive names the agent NAMESPACE/NAME, unknown treats it as an unknown caller.

| | |
|---|---|
| Type | string |
| Default | `derive` |
| Environment | `SCRIM_IDENTITY_KUBERNETES_UNMAPPED` |
| Flag | none |
| Reload | restart required |
| Values | `derive`, `unknown` |

#### `identity.peers`

Agents by local user or group: agent name to space-separated selectors uid:N, user:NAME, gid:N, group:NAME, scope:SCOPE, label:K=V. Empty maps the user scrim runs as to one agent named after it.

| | |
|---|---|
| Type | map of strings (env: JSON object or `k=v,k2=v2`; one entry: variable plus `_ENTRY`) |
| Default | `{}` |
| Environment | `SCRIM_IDENTITY_PEERS` |
| Flag | none |
| Reload | restart required |

#### `identity.store-credentials`

Static per-agent store credentials: `<store>/<agent>` to a reference (env:, file:, cred: or a store reference) of a store token held for that agent. The fallback for agents without Kubernetes passthrough; a store listed here refuses agents that have none.

| | |
|---|---|
| Type | map of strings (env: JSON object or `k=v,k2=v2`; one entry: variable plus `_ENTRY`) |
| Default | `{}` |
| Environment | `SCRIM_IDENTITY_STORE_CREDENTIALS` |
| Flag | none |
| Reload | restart required |

#### `identity.store-login`

Per-agent store login, by store instance: `kubernetes role:<template> [mount:<path>]` logs in to the store (OpenBao Kubernetes auth) with the calling pod's own service account token at the role the template names; {namespace}, {service_account} and {agent} are replaced. A store listed here refuses agents that have no usable identity of their own.

| | |
|---|---|
| Type | map of strings (env: JSON object or `k=v,k2=v2`; one entry: variable plus `_ENTRY`) |
| Default | `{}` |
| Environment | `SCRIM_IDENTITY_STORE_LOGIN` |
| Flag | none |
| Reload | restart required |

### interception

#### `interception.ebpf.cgroups`

Control groups (cgroup v2 paths below /sys/fs/cgroup, such as agents.slice) the eBPF transparent mode covers (Linux): `sudo scrim ebpf attach` redirects their TCP connections to ports 80 and 443 to the transparent listener and denies their direct and QUIC egress. Status and doctor report each one that is not attached. Empty: the mode is off.

| | |
|---|---|
| Type | list of strings (env: JSON array or comma-separated, `\,` for a comma) |
| Default | `[]` |
| Environment | `SCRIM_INTERCEPTION_EBPF_CGROUPS` |
| Flag | none |
| Reload | hot |

#### `interception.ebpf.port`

Port of the transparent listener on 127.0.0.1 and ::1 that the eBPF transparent mode redirects to. It must match the port of proxy.transparent-listen; nothing listening there means covered connections fail, never go direct.

| | |
|---|---|
| Type | int |
| Default | `9792` |
| Environment | `SCRIM_INTERCEPTION_EBPF_PORT` |
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

#### `metrics.allow-unauthenticated-remote`

Serve metrics.path on a non-loopback metrics.listen without metrics.auth.token, for a network policy or mesh that already restricts who connects. Anyone who can reach the port reads the metrics.

| | |
|---|---|
| Type | bool |
| Default | `false` |
| Environment | `SCRIM_METRICS_ALLOW_UNAUTHENTICATED_REMOTE` |
| Flag | none |
| Reload | restart required |
| Weakening | **yes**: logged at start-up and on reload while active, listed in `scrim status` |

#### `metrics.auth.token`

Reference to a bearer token (at least 16 bytes) a scraper must present on metrics.path. Required when metrics.listen is not a loopback address, unless metrics.allow-unauthenticated-remote is set. The health endpoints never need it.

| | |
|---|---|
| Type | secret reference (`env:`, `file:`, `cred:` or a store reference; a literal is warned about) |
| Default | empty |
| Environment | `SCRIM_METRICS_AUTH_TOKEN` |
| Flag | none |
| Reload | restart required |

#### `metrics.enabled`

Serve Prometheus metrics (control plane and data plane) at metrics.path on metrics.listen. Off: nothing is measured on the request path and no metrics listener is bound.

| | |
|---|---|
| Type | bool |
| Default | `false` |
| Environment | `SCRIM_METRICS_ENABLED` |
| Flag | `--metrics-enabled` |
| Reload | restart required |

#### `metrics.listen`

Address of the metrics and health endpoint (/healthz or /livez, /readyz, and metrics.path while metrics.enabled). Used when metrics.enabled is true; set explicitly with metrics.enabled false it serves the health endpoints only. Bind to loopback unless scraped remotely.

| | |
|---|---|
| Type | string |
| Default | `127.0.0.1:9792` |
| Environment | `SCRIM_METRICS_LISTEN` |
| Flag | `--metrics-listen` |
| Reload | restart required |

#### `metrics.path`

Path of the Prometheus endpoint on metrics.listen.

| | |
|---|---|
| Type | string |
| Default | `/metrics` |
| Environment | `SCRIM_METRICS_PATH` |
| Flag | none |
| Reload | restart required |

### nats

#### `nats.credentials-file`

Path to a NATS credentials file (JWT and NKey seed), for decentralised authentication; empty for none.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_NATS_CREDENTIALS_FILE` |
| Flag | none |
| Reload | restart required |

#### `nats.password`

Reference to the password of nats.username.

| | |
|---|---|
| Type | secret reference (`env:`, `file:`, `cred:` or a store reference; literals rejected) |
| Default | empty |
| Environment | `SCRIM_NATS_PASSWORD` |
| Flag | none |
| Reload | restart required |

#### `nats.servers`

NATS server URLs (nats://host:4222, tls://host:4222) used by events.backend nats.

| | |
|---|---|
| Type | list of strings (env: JSON array or comma-separated, `\,` for a comma) |
| Default | `[]` |
| Environment | `SCRIM_NATS_SERVERS` |
| Flag | none |
| Reload | restart required |

#### `nats.timeout`

Dial timeout, and the bound on the round trip that confirms a subscription after each reconnect. The client also pings the server at this interval and treats two missed answers as a lost connection.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `5s` |
| Environment | `SCRIM_NATS_TIMEOUT` |
| Flag | none |
| Reload | restart required |

#### `nats.tls-ca-file`

PEM file of the certificate authorities that sign the NATS server certificate; empty uses the system roots.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_NATS_TLS_CA_FILE` |
| Flag | none |
| Reload | restart required |

#### `nats.token`

Reference to a NATS authentication token; empty for none.

| | |
|---|---|
| Type | secret reference (`env:`, `file:`, `cred:` or a store reference; literals rejected) |
| Default | empty |
| Environment | `SCRIM_NATS_TOKEN` |
| Flag | none |
| Reload | restart required |

#### `nats.username`

NATS user for user and password authentication; empty for none.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_NATS_USERNAME` |
| Flag | none |
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

#### `policy.builtin.inject`

Built-in rule `builtin.inject-bound` for injecting a credential toward a host it is bound to, for an identified agent: allow, ask, or off (injection is then decided by your rules and policy.default). Deny rules in the rules file still win.

| | |
|---|---|
| Type | string |
| Default | `allow` |
| Environment | `SCRIM_POLICY_BUILTIN_INJECT` |
| Flag | none |
| Reload | hot |
| Values | `allow`, `ask`, `off` |

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

How often each replica re-reads the deny-all state from the state backend; the bound on how long a change on one replica takes to reach the others when no event announces it (events.backend).

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

### proxy

#### `proxy.capture.dir`

Capture mode: write every provider request exactly as it left, and the response as received, to this directory (mode 0700; refused if group or others can access it). Empty disables capture. `scrim proxy --capture=DIR` sets it.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_PROXY_CAPTURE_DIR` |
| Flag | `--proxy-capture-dir` |
| Reload | restart required |

#### `proxy.capture.retention`

Captured files older than this are deleted.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `168h0m0s` |
| Environment | `SCRIM_PROXY_CAPTURE_RETENTION` |
| Flag | none |
| Reload | restart required |

#### `proxy.chain.on-unavailable`

When the chained upstream cannot be reached: fail refuses the request, direct sends the already redacted request to the provider and audits the skip.

| | |
|---|---|
| Type | string |
| Default | `fail` |
| Environment | `SCRIM_PROXY_CHAIN_ON_UNAVAILABLE` |
| Flag | none |
| Reload | hot |
| Values | `fail`, `direct` |

#### `proxy.chain.url`

Base URL of a chained upstream (for example a context compression proxy) that receives every redacted provider request in place of the provider. Empty means no chain.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_PROXY_CHAIN_URL` |
| Flag | none |
| Reload | hot |

#### `proxy.forward-listen`

TCP address of the forward proxy for agents with HTTPS_PROXY set (scrim run sets it): provider hosts go to the LLM proxy, every other host to the tool proxy with credential injection. Empty disables it; keep it on loopback.

| | |
|---|---|
| Type | string |
| Default | `127.0.0.1:9791` |
| Environment | `SCRIM_PROXY_FORWARD_LISTEN` |
| Flag | `--proxy-forward-listen` |
| Reload | restart required |

#### `proxy.listen`

TCP address of the LLM proxy base URL (agents use http://<address>/anthropic and http://<address>/openai/v1). Empty disables it; keep it on loopback.

| | |
|---|---|
| Type | string |
| Default | `127.0.0.1:9790` |
| Environment | `SCRIM_PROXY_LISTEN` |
| Flag | `--proxy-listen` |
| Reload | restart required |

#### `proxy.sni-listen`

TCP address of the SNI listener for DNS override mode: provider names resolve to its address (scrim install --dns writes /etc/hosts entries and sets 127.0.83.1:443), it serves certificates for them from the scrim CA and routes by TLS server name. Connections made by address bypass it. Empty disables it.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_PROXY_SNI_LISTEN` |
| Flag | `--proxy-sni-listen` |
| Reload | restart required |

#### `proxy.socket`

Unix socket path for the LLM proxy base URL, for agents that can connect to one. Empty disables it.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_PROXY_SOCKET` |
| Flag | `--proxy-socket` |
| Reload | restart required |

#### `proxy.transparent-listen`

TCP addresses of the transparent listener (Linux): connections redirected to it by nftables are routed by TLS server name or Host header, provider hosts to the LLM proxy, bound tool hosts to the tool proxy. scrim install --transparent sets 127.0.0.1:9792 and [::1]:9792. Empty disables it.

| | |
|---|---|
| Type | list of strings (env: JSON array or comma-separated, `\,` for a comma) |
| Default | `[]` |
| Environment | `SCRIM_PROXY_TRANSPARENT_LISTEN` |
| Flag | `--proxy-transparent-listen` |
| Reload | restart required |

#### `proxy.transparent-unrouted`

What the transparent and SNI listeners do with a host that is neither a provider host nor bound to a credential or capture rule: pass relays the connection untouched to that host name (never to the address the client dialled), block closes it. TLS without a server name is always closed.

| | |
|---|---|
| Type | string |
| Default | `pass` |
| Environment | `SCRIM_PROXY_TRANSPARENT_UNROUTED` |
| Flag | none |
| Reload | restart required |
| Values | `pass`, `block` |

#### `proxy.upstream.anthropic`

Base URL Anthropic Messages requests are forwarded to after redaction.

| | |
|---|---|
| Type | string |
| Default | `https://api.anthropic.com` |
| Environment | `SCRIM_PROXY_UPSTREAM_ANTHROPIC` |
| Flag | none |
| Reload | hot |

#### `proxy.upstream.chatgpt`

Base URL requests to chatgpt.com (Codex signed in with ChatGPT, through the forward proxy) are forwarded to after redaction.

| | |
|---|---|
| Type | string |
| Default | `https://chatgpt.com` |
| Environment | `SCRIM_PROXY_UPSTREAM_CHATGPT` |
| Flag | none |
| Reload | hot |

#### `proxy.upstream.chatgpt-ab`

Base URL requests to ab.chatgpt.com (Codex signed in with ChatGPT, through the forward proxy) are forwarded to after redaction. Its API shape is not documented, so every request body is redacted as generic JSON.

| | |
|---|---|
| Type | string |
| Default | `https://ab.chatgpt.com` |
| Environment | `SCRIM_PROXY_UPSTREAM_CHATGPT_AB` |
| Flag | none |
| Reload | hot |

#### `proxy.upstream.openai`

Base URL OpenAI Chat Completions and Responses requests are forwarded to after redaction.

| | |
|---|---|
| Type | string |
| Default | `https://api.openai.com` |
| Environment | `SCRIM_PROXY_UPSTREAM_OPENAI` |
| Flag | none |
| Reload | hot |

### ratelimit

#### `ratelimit.agent-api.burst`

How many agent API calls (local API and MCP tools) one agent may make at once before ratelimit.agent-api.rate applies.

| | |
|---|---|
| Type | int |
| Default | `120` |
| Environment | `SCRIM_RATELIMIT_AGENT_API_BURST` |
| Flag | none |
| Reload | hot |

#### `ratelimit.agent-api.interval`

The interval ratelimit.agent-api.rate counts over.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `1m0s` |
| Environment | `SCRIM_RATELIMIT_AGENT_API_INTERVAL` |
| Flag | none |
| Reload | hot |

#### `ratelimit.agent-api.rate`

How many agent API calls (local API and MCP tools) one agent may make per ratelimit.agent-api.interval, after its burst; 0 turns the limit off.

| | |
|---|---|
| Type | int |
| Default | `600` |
| Environment | `SCRIM_RATELIMIT_AGENT_API_RATE` |
| Flag | none |
| Reload | hot |

#### `ratelimit.approvals.burst`

How many approval requests (tool calls and proxied requests held for a human) one agent may make at once before ratelimit.approvals.rate applies.

| | |
|---|---|
| Type | int |
| Default | `10` |
| Environment | `SCRIM_RATELIMIT_APPROVALS_BURST` |
| Flag | none |
| Reload | hot |

#### `ratelimit.approvals.interval`

The interval ratelimit.approvals.rate counts over.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `1h0m0s` |
| Environment | `SCRIM_RATELIMIT_APPROVALS_INTERVAL` |
| Flag | none |
| Reload | hot |

#### `ratelimit.approvals.rate`

How many approval requests (tool calls and proxied requests held for a human) one agent may make per ratelimit.approvals.interval, after its burst; 0 turns the limit off.

| | |
|---|---|
| Type | int |
| Default | `60` |
| Environment | `SCRIM_RATELIMIT_APPROVALS_RATE` |
| Flag | none |
| Reload | hot |

#### `ratelimit.asks.burst`

How many secret_ask_human asks one agent may make at once before ratelimit.asks.rate applies.

| | |
|---|---|
| Type | int |
| Default | `5` |
| Environment | `SCRIM_RATELIMIT_ASKS_BURST` |
| Flag | none |
| Reload | hot |

#### `ratelimit.asks.interval`

The interval ratelimit.asks.rate counts over.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `1h0m0s` |
| Environment | `SCRIM_RATELIMIT_ASKS_INTERVAL` |
| Flag | none |
| Reload | hot |

#### `ratelimit.asks.rate`

How many secret_ask_human asks one agent may make per ratelimit.asks.interval, after its burst; 0 turns the limit off.

| | |
|---|---|
| Type | int |
| Default | `30` |
| Environment | `SCRIM_RATELIMIT_ASKS_RATE` |
| Flag | none |
| Reload | hot |

#### `ratelimit.backend`

Where per-agent rate limits are counted. local counts in each replica's memory, so with several replicas an agent can get up to that many times each limit (approximate); valkey counts in Valkey (valkey.*), one exact limit shared by every replica. When the backend cannot answer, the request is refused.

| | |
|---|---|
| Type | string |
| Default | `local` |
| Environment | `SCRIM_RATELIMIT_BACKEND` |
| Flag | `--ratelimit-backend` |
| Reload | restart required |
| Values | `local`, `valkey` |

#### `ratelimit.valkey.prefix`

Prefix of the Valkey keys ratelimit.backend valkey keeps its counters in. Replicas of one deployment share it; two deployments on one Valkey need different prefixes.

| | |
|---|---|
| Type | string |
| Default | `scrim:rl:` |
| Environment | `SCRIM_RATELIMIT_VALKEY_PREFIX` |
| Flag | none |
| Reload | restart required |

### redaction

#### `redaction.allow-empty-targets`

Start even when a store's redact target matches no secret on the first load. Off, such a target stops start-up with an error naming it, since it usually means a misspelt name or pattern and redaction would protect nothing. On, the store starts and status reports the target as degraded with 0 values.

| | |
|---|---|
| Type | bool |
| Default | `false` |
| Environment | `SCRIM_REDACTION_ALLOW_EMPTY_TARGETS` |
| Flag | none |
| Reload | restart required |
| Weakening | **yes**: logged at start-up and on reload while active, listed in `scrim status` |

#### `redaction.min-value-length`

Shortest value matched in free text; shorter values are matched only in exact and encoded forms.

| | |
|---|---|
| Type | int |
| Default | `8` |
| Environment | `SCRIM_REDACTION_MIN_VALUE_LENGTH` |
| Flag | none |
| Reload | hot |

#### `redaction.placeholder-key-dir`

Directory of the generated placeholder key, used when redaction.placeholder-keys is empty. Empty means $XDG_STATE_HOME/scrim/keys (~/.local/state/scrim/keys).

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_REDACTION_PLACEHOLDER_KEY_DIR` |
| Flag | none |
| Reload | restart required |

### restore

#### `restore.allow-reveal-credentials`

Glob patterns over store references of credentials that scrim reveal may resolve locally. Empty means reveal never resolves a credential. Restore into responses never resolves credentials, whatever this holds.

| | |
|---|---|
| Type | list of strings (env: JSON array or comma-separated, `\,` for a comma) |
| Default | `[]` |
| Environment | `SCRIM_RESTORE_ALLOW_REVEAL_CREDENTIALS` |
| Flag | none |
| Reload | hot |
| Weakening | **yes**: logged at start-up and on reload while active, listed in `scrim status` |

#### `restore.allow-shell-data-commands`

Commands a shell-role restore may pass display values to, beyond the built-in list of commands that run no code. A listed command that interprets an argument as code turns a restored value into code.

| | |
|---|---|
| Type | list of strings (env: JSON array or comma-separated, `\,` for a comma) |
| Default | `[]` |
| Environment | `SCRIM_RESTORE_ALLOW_SHELL_DATA_COMMANDS` |
| Flag | none |
| Reload | hot |
| Weakening | **yes**: logged at start-up and on reload while active, listed in `scrim status` |

#### `restore.builtin-tools`

Use the built-in table of agent tool roles (Claude Code, Codex). When false only restore.tools have roles and every other tool is unknown, which restores nothing.

| | |
|---|---|
| Type | bool |
| Default | `true` |
| Environment | `SCRIM_RESTORE_BUILTIN_TOOLS` |
| Flag | none |
| Reload | hot |

#### `restore.display-mode`

What the agent displays for display-class values: values resolves them in assistant text, placeholders keeps placeholders (for example while screen sharing). Tool arguments follow the tool roles either way; credentials are never restored.

| | |
|---|---|
| Type | string |
| Default | `values` |
| Environment | `SCRIM_RESTORE_DISPLAY_MODE` |
| Flag | `--restore-display-mode` |
| Reload | hot |
| Values | `values`, `placeholders` |

### run

#### `run.allow-unredacted-start`

Start the agent anyway when scrim cannot start, its data plane is not ready or no session can be minted. The agent then reaches providers directly and unredacted; scrim run prints a warning.

| | |
|---|---|
| Type | bool |
| Default | `false` |
| Environment | `SCRIM_RUN_ALLOW_UNREDACTED_START` |
| Flag | `--run-allow-unredacted-start` |
| Reload | hot |
| Weakening | **yes**: logged at start-up and on reload while active, listed in `scrim status` |

#### `run.fs-view`

Session filesystem view for credential files at fixed home paths: auto (a user and mount namespace where the host allows it, the home mirror elsewhere), namespace (refuse to start the agent without one), home (HOME points at a mirror of the home directory without the real credential files) or off. See docs/run.md.

| | |
|---|---|
| Type | string |
| Default | `auto` |
| Environment | `SCRIM_RUN_FS_VIEW` |
| Flag | `--run-fs-view` |
| Reload | hot |
| Values | `auto`, `namespace`, `home`, `off` |

#### `run.fs-view-hide`

Home-relative paths or glob patterns hidden by the session filesystem view in addition to the fixed paths of the applied tool profiles; a leading ! takes matches out again.

| | |
|---|---|
| Type | list of strings (env: JSON array or comma-separated, `\,` for a comma) |
| Default | `[".ssh/id_*","!.ssh/id_*.pub"]` |
| Environment | `SCRIM_RUN_FS_VIEW_HIDE` |
| Flag | none |
| Reload | hot |

#### `run.mcp`

Register scrim mcp with the agent for this session (Claude Code --mcp-config, Codex -c mcp_servers.scrim). Nothing is written to the agent's own configuration.

| | |
|---|---|
| Type | bool |
| Default | `true` |
| Environment | `SCRIM_RUN_MCP` |
| Flag | `--run-mcp` |
| Reload | hot |

#### `run.placeholder-env`

Export each declared catalog placeholder that resolves for the session as an environment variable of the same name holding the placeholder, for example SCRIM_ACME_KEY=SCRIM_ACME_KEY.

| | |
|---|---|
| Type | bool |
| Default | `true` |
| Environment | `SCRIM_RUN_PLACEHOLDER_ENV` |
| Flag | `--run-placeholder-env` |
| Reload | hot |

#### `run.profiles`

Tool profiles scrim run applies: profile names, `auto` for every profile at least one catalog entry fills (an entry naming the profile in its tools list), or `none`. Profiles a selected one requires are added. See docs/cli-tools.md.

| | |
|---|---|
| Type | list of strings (env: JSON array or comma-separated, `\,` for a comma) |
| Default | `["auto"]` |
| Environment | `SCRIM_RUN_PROFILES` |
| Flag | `--run-profiles` |
| Reload | hot |

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

State backend for approvals, grants, sessions and audit metadata. The local profile uses sqlite ($XDG_STATE_HOME/scrim/state.db); ci and k8s use memory, which writes nothing to disk (set postgres for shared state).

| | |
|---|---|
| Type | string |
| Default | `memory` |
| Environment | `SCRIM_STATE_BACKEND` |
| Flag | `--state-backend` |
| Reload | restart required |
| Values | `memory`, `sqlite`, `postgres` |
| Profiles | local: `sqlite` |

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

#### `tool-proxy.listen`

TCP address of the HTTPS tool proxy (credential injection and response redaction) for tools pointed at it directly. Empty disables it.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_TOOL_PROXY_LISTEN` |
| Flag | `--tool-proxy-listen` |
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

### valkey

#### `valkey.addresses`

Valkey (or Redis-compatible) servers as host:port, used by events.backend valkey and ratelimit.backend valkey. Several addresses of one cluster are seeds; the client discovers the rest.

| | |
|---|---|
| Type | list of strings (env: JSON array or comma-separated, `\,` for a comma) |
| Default | `[]` |
| Environment | `SCRIM_VALKEY_ADDRESSES` |
| Flag | none |
| Reload | restart required |

#### `valkey.db`

Valkey logical database (standalone servers only).

| | |
|---|---|
| Type | int |
| Default | `0` |
| Environment | `SCRIM_VALKEY_DB` |
| Flag | none |
| Reload | restart required |

#### `valkey.password`

Reference to the Valkey password (env:, file:, cred: or a store reference); empty for none.

| | |
|---|---|
| Type | secret reference (`env:`, `file:`, `cred:` or a store reference; literals rejected) |
| Default | empty |
| Environment | `SCRIM_VALKEY_PASSWORD` |
| Flag | none |
| Reload | restart required |

#### `valkey.timeout`

Dial timeout and the bound on one Valkey round trip; a connection that does not answer a ping within it is considered dead and replaced.

| | |
|---|---|
| Type | duration (`90s`, `5m`, `1h30m`) |
| Default | `5s` |
| Environment | `SCRIM_VALKEY_TIMEOUT` |
| Flag | none |
| Reload | restart required |

#### `valkey.tls`

Connect to Valkey over TLS, verifying the server against the system roots or valkey.tls-ca-file.

| | |
|---|---|
| Type | bool |
| Default | `false` |
| Environment | `SCRIM_VALKEY_TLS` |
| Flag | none |
| Reload | restart required |

#### `valkey.tls-ca-file`

PEM file of the certificate authorities that sign the Valkey server certificate; empty uses the system roots.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_VALKEY_TLS_CA_FILE` |
| Flag | none |
| Reload | restart required |

#### `valkey.username`

Valkey ACL user; empty uses the default user.

| | |
|---|---|
| Type | string |
| Default | `""` |
| Environment | `SCRIM_VALKEY_USERNAME` |
| Flag | none |
| Reload | restart required |

<!-- END GENERATED SETTINGS REFERENCE -->
