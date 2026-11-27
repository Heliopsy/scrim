# scrim project

<!-- Generated from the command tree by `just cli-docs`. Do not edit. -->

Global flags are listed in [the CLI reference](README.md#global-flags).

## scrim project

Find secret values in project files and move them into a store.

```text
scrim project [command]

scrim run scans the agent's working directory for secret values in project files (.env*, *.tfvars, application config,
compose files, .npmrc) and redacts them from the first request. These commands show what it finds and move values into a
store, replacing each in its file with a {{scrim:<ref>}} reference. Values are never printed.
```

| Subcommand | Description |
| --- | --- |
| [`scrim project move`](#scrim-project-move) | Move secret values from project files into a store, asking before each one |
| [`scrim project scan`](#scrim-project-scan) | List the secret values in project files, by file, line and key; values are never printed |

## scrim project move

Move secret values from project files into a store, asking before each one.

```text
scrim project move [flags]

For each secret value in the project files, asks whether to write it into the store under <store>/<name>#value (through
the agent API, so policy and audit apply) and replace it in the file with {{scrim:<ref>}}. Nothing is written or
rewritten without a yes; --yes answers yes to every value. Add a catalog entry for the reference so scrim injects it
where the file's value was sent.
```

Flags:

```text
      --dir string         project directory to scan (default ".")
      --key strings        only move values of these keys (repeatable)
      --store string       base reference the values are written under (default "bao://kv/agents")
  -y, --yes[=true|false]   move every value without asking
```

## scrim project scan

List the secret values in project files, by file, line and key; values are never printed.

```text
scrim project scan [flags]
```

Flags:

```text
      --dir string          project directory to scan (default ".")
      --json[=true|false]   shorthand for --output json
  -o, --output string       output format: text or json (default "text")
```
