# scrim config

<!-- Generated from the command tree by `just cli-docs`. Do not edit. -->

Global flags are listed in [the CLI reference](README.md#global-flags).

## scrim config

Inspect and validate configuration.

```text
scrim config [command]

Inspect and validate scrim's configuration: built-in defaults, the profile, config files with their includes, SCRIM_*
environment variables and flags, in rising precedence.
```

| Subcommand | Description |
| --- | --- |
| [`scrim config schema`](#scrim-config-schema) | Print the JSON Schema of the config file |
| [`scrim config show`](#scrim-config-show) | Print configuration values and where each came from |
| [`scrim config validate`](#scrim-config-validate) | Check the merged configuration without starting anything |

## scrim config schema

Print the JSON Schema of the config file.

```text
scrim config schema

Print the JSON Schema (draft 2020-12) of the config file for scrim.dev/v1, generated from the same registry scrim
validates against.
```

## scrim config show

Print configuration values and where each came from.

```text
scrim config show [flags]

Print the settings that are set (with --effective, every setting) with the value in effect and its source: default,
profile, file and line, environment variable or flag. Secret-valued settings show their reference form and a masked
value, never the value.
```

Flags:

```text
      --effective[=true|false]   show every setting, including those at their default
  -o, --output string            output format: text or json (default "text")
```

## scrim config validate

Check the merged configuration without starting anything.

```text
scrim config validate [flags]

Check the full merged configuration (files, environment, flags, secret references) without starting any listener. Every
problem is listed with its key and source, and the command exits non-zero when there is one. Store references are
checked for syntax only: validate does not contact secret stores.
```

Flags:

```text
  -o, --output string   output format: text or json (default "text")
```
