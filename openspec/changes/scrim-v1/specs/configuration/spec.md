## Purpose

Defines how every scrim setting is named, supplied, validated, inspected and reloaded, so that any
behaviour can be tuned through a config file, environment variables or flags with predictable
precedence and without ever exposing a secret value.

## ADDED Requirements

### Requirement: Canonical setting keys

Every setting SHALL have exactly one canonical dotted key (for example `proxy.listen`,
`approvals.timeout`). The same key SHALL address the setting in the config file, the environment
variable name, the flag name and every diagnostic output.

#### Scenario: One key across all sources

- **WHEN** a user looks up the setting `approvals.timeout` in the documentation
- **THEN** the documentation names the file key `approvals.timeout`, the variable `SCRIM_APPROVALS_TIMEOUT` and the flag `--approvals-timeout`
- **AND** `scrim config show --effective` reports it under `approvals.timeout`

### Requirement: Versioned config file

scrim SHALL read configuration from YAML files that declare `apiVersion` and `kind`. A file without
them, or with an `apiVersion` this release does not support, SHALL be rejected with an error naming
the file and the supported versions.

#### Scenario: Unsupported apiVersion

- **WHEN** a config file declares `apiVersion: scrim.dev/v9`
- **THEN** scrim refuses to start
- **AND** the error names the file and lists the supported `apiVersion` values

### Requirement: Environment variable for every setting

Every setting SHALL be settable through an environment variable named `SCRIM_` followed by its key
upper-cased, with `.` and `-` replaced by `_`. List and map values SHALL use a documented encoding
(JSON or comma-separated with a documented escape) that round-trips every value the file can hold.

#### Scenario: Nested key from the environment

- **WHEN** `SCRIM_PROXY_UPSTREAM_ANTHROPIC=http://127.0.0.1:9000` is set
- **THEN** the effective value of `proxy.upstream.anthropic` is `http://127.0.0.1:9000`

#### Scenario: List value from the environment

- **WHEN** `SCRIM_PROXY_NO_PROXY='["127.0.0.1","localhost"]'` is set
- **THEN** the effective value of `proxy.no-proxy` is the two-element list

### Requirement: Collections of named instances

Sections that hold any number of named instances (for example secret store instances under
`stores`) SHALL address each field by the dotted key `<collection>.<name>.<field>`. The environment
SHALL be able to replace a whole collection with a JSON object and override any field already
present by its variable name; a variable under a collection's prefix that matches no known instance
SHALL be reported as a warning. Secret fields of an instance SHALL follow the secret-valued setting
rules.

#### Scenario: Store token from a file reference

- **WHEN** the file declares `stores.bao-prod` with `token: file:/run/secrets/bao` and that file exists
- **THEN** the token is resolved at start-up
- **AND** `scrim config show` lists `stores.bao-prod.token` with the reference and a masked value

#### Scenario: Field override from the environment

- **WHEN** the file declares `stores.bao-prod.address` and `SCRIM_STORES_BAO_PROD_ADDRESS` is set
- **THEN** the effective address is the variable's value and its source is the variable

### Requirement: Flags for operational settings

Settings an operator commonly changes per invocation (listen addresses, config path, log level,
state backend, interception mode, profile) SHALL also be available as command-line flags named from
their key.

#### Scenario: Flag sets the listen address

- **WHEN** scrim starts with `--proxy-listen 127.0.0.1:9790`
- **THEN** the LLM proxy listens on `127.0.0.1:9790`

### Requirement: Source precedence

When a setting is supplied by several sources, scrim SHALL apply flag over environment over config
file over profile over built-in default, and SHALL apply later files over earlier ones within the
file layer.

#### Scenario: Flag beats environment and file

- **WHEN** the file sets `log.level: info`, `SCRIM_LOG_LEVEL=warn` is set and `--log-level debug` is passed
- **THEN** the effective log level is `debug`
- **AND** its reported source is `flag`

### Requirement: Config file discovery

scrim SHALL load the file named by `--config` or `SCRIM_CONFIG` when given, and otherwise SHALL search
`$XDG_CONFIG_HOME/scrim/config.yaml`, then `~/.config/scrim/config.yaml`, then
`/etc/scrim/config.yaml`, using the first that exists. A path given explicitly that does not exist
SHALL be an error.

#### Scenario: Explicit path missing

- **WHEN** `SCRIM_CONFIG=/nonexistent.yaml` is set
- **THEN** scrim refuses to start with an error naming that path

#### Scenario: Fallback to system path

- **WHEN** no explicit path is given and only `/etc/scrim/config.yaml` exists
- **THEN** scrim loads `/etc/scrim/config.yaml`

### Requirement: Includes and overlays

A config file SHALL be able to include other files and directories of files (for example
`/etc/scrim/conf.d/*.yaml`), merged in a documented, deterministic order where maps merge by key and
scalars and lists are replaced. An include cycle or a missing required include SHALL be an error.

#### Scenario: Drop-in overrides base

- **WHEN** the base file sets `approvals.timeout: 120s` and an included drop-in sets `approvals.timeout: 60s`
- **THEN** the effective value is `60s`
- **AND** its reported source names the drop-in file

### Requirement: Profiles as overridable presets

scrim SHALL ship named profiles (at least `local`, `k8s` and `ci`) that set defaults for a deployment
shape. A profile SHALL sit below files, environment and flags in precedence, so any value it sets
can be overridden.

#### Scenario: Override a profile default

- **WHEN** profile `ci` sets `state.backend: memory` and the file sets `state.backend: sqlite`
- **THEN** the effective state backend is `sqlite`

### Requirement: Secret-valued settings by reference

Settings that hold credentials (store tokens, placeholder key, CA key, notifier tokens, database
passwords) SHALL accept references (`env:NAME`, `file:/path`, `cred:NAME` for a systemd credential,
or `<scheme>://<path>[#field]`) as well as literals, unless the setting requires a reference, in
which case a literal SHALL be rejected. A reference that cannot be resolved, or resolves to an
empty value, SHALL stop start-up or reload, never fall back to an empty value.

#### Scenario: Unresolvable reference

- **WHEN** `stores.openbao.token` is `file:/run/secrets/bao-token` and that file does not exist
- **THEN** scrim refuses to start and names the setting and the reference
- **AND** no store connection is attempted with an empty token

#### Scenario: Literal secret discouraged

- **WHEN** a secret-valued setting is given as a literal in a config file
- **THEN** scrim starts and logs a warning naming the setting, without its value

#### Scenario: Literal rejected where a reference is required

- **WHEN** a secret-valued setting that requires a reference is given as a literal, in a file or the environment
- **THEN** scrim refuses to start and names the setting and its source
- **AND** the error does not contain the literal

### Requirement: Published JSON Schema

Each release SHALL publish a JSON Schema for every supported `apiVersion`, generated from the same
definitions scrim validates against, and `scrim config schema` SHALL print it.

#### Scenario: Schema matches the binary

- **WHEN** a user runs `scrim config schema` and validates a file against it with an external tool
- **THEN** a file the external tool accepts is also accepted by `scrim config validate`, except for checks a schema cannot express (value ranges, cross-setting rules, references that must resolve), which `scrim config validate` reports by key

#### Scenario: Committed schema does not drift

- **WHEN** a setting is added or changed without regenerating the committed schema and reference
- **THEN** the test suite fails and names the stale file

### Requirement: Strict validation of unknown keys

scrim SHALL reject a config containing keys it does not know, naming each unknown key and the
closest known key, unless `config.strict` is set to `false`, in which case unknown keys SHALL be
reported as warnings.

#### Scenario: Typo in a key

- **WHEN** a file contains `aprovals.timeout: 60s`
- **THEN** validation fails and suggests `approvals.timeout`

### Requirement: Config validation command

`scrim config validate` SHALL check the full merged configuration (files, environment, flags,
references resolvable) without starting any listener, and SHALL exit non-zero with every error
listed when the configuration is invalid.

#### Scenario: Validate before deploy

- **WHEN** an operator runs `scrim config validate` against an invalid configuration
- **THEN** every problem is listed with its key and source
- **AND** the command exits non-zero

### Requirement: Effective configuration with provenance

`scrim config show --effective` SHALL print every setting's effective value and its source (default,
profile, file path, environment variable or flag). Secret-valued settings SHALL be shown as masked
with only their reference form, never their resolved value.

#### Scenario: Masked secret setting

- **WHEN** `stores.infisical.client-secret` is set from `env:INF_SECRET`
- **THEN** the output shows the reference `env:INF_SECRET` and a masked value
- **AND** the resolved secret does not appear anywhere in the output

### Requirement: Hot reload

scrim SHALL reload configuration on file change or on a reload signal. A reload SHALL either apply
completely and atomically or be rejected completely, keeping the previous configuration running and
reporting why.

#### Scenario: Invalid reload is rejected

- **WHEN** a running scrim's config file is edited into an invalid state
- **THEN** scrim keeps serving with the previous configuration
- **AND** logs and reports in status that the reload was rejected and why

#### Scenario: Valid reload applies

- **WHEN** the config file changes `approvals.timeout` to a valid value
- **THEN** new approval requests use the new timeout without a restart
- **AND** components subscribed to configuration changes are notified once with the new version

#### Scenario: Rotated secret file

- **WHEN** a file named by a `file:` reference changes and scrim reloads
- **THEN** the new value is used and the setting is reported as changed, without its value in any log

### Requirement: Settings that need a restart

Settings that cannot change at runtime (for example a listen address or the state backend) SHALL be
marked as such in the schema, and a reload that changes them SHALL report that a restart is needed
instead of applying them partially.

#### Scenario: Listen address change on reload

- **WHEN** a reload changes `proxy.listen`
- **THEN** scrim keeps the current listener and reports that `proxy.listen` requires a restart

### Requirement: Explicitly named weakening settings

Every setting that weakens a security invariant SHALL be named for what it weakens (for example
`redaction.allow-unredacted-on-error`), SHALL default to the safe value, SHALL log a warning at
start-up and on reload while active, and SHALL be listed in `scrim status`.

#### Scenario: Weakened setting is visible

- **WHEN** a setting that weakens an invariant is enabled
- **THEN** scrim logs a warning at start-up naming it
- **AND** `scrim status` lists it under weakened protections

### Requirement: Documentation generated from the schema

The reference documentation of every setting (key, type, default, environment variable, flag,
reloadable or not, weakening or not) SHALL be generated from the schema, and a release SHALL fail if
a setting lacks a description.

#### Scenario: Undocumented setting

- **WHEN** a setting is added without a description
- **THEN** the release check fails and names the setting
