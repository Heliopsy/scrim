# scrim doctor

<!-- Generated from the command tree by `just cli-docs`. Do not edit. -->

Global flags are listed in [the CLI reference](README.md#global-flags).

## scrim doctor

Check the local setup and suggest a fix for each problem.

```text
scrim doctor [flags]

Check the state location and backend, store reachability, the data plane, audit sinks and weakened settings, print each
problem with a suggested fix, and exit non-zero when any check fails.
```

Flags:

```text
      --json[=true|false]   shorthand for --output json
  -o, --output string       output format: text or json (default "text")
      --timeout duration    time limit for each check (default 10s)
```
