# scrim status

<!-- Generated from the command tree by `just cli-docs`. Do not edit. -->

Global flags are listed in [the CLI reference](README.md#global-flags).

## scrim status

Report protections, interception, stores, state and weakened settings.

```text
scrim status [flags]

Report the version, active interception modes and protections, providers, stores with their health, the state backend,
audit sinks, the data plane, degraded components and every weakened setting in effect.

Exits 0 whenever the report could be produced; use `scrim doctor` for a pass or fail answer.
```

Flags:

```text
      --json[=true|false]   shorthand for --output json
  -o, --output string       output format: text or json (default "text")
```
