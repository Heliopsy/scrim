# scrim api

<!-- Generated from the command tree by `just cli-docs`. Do not edit. -->

Global flags are listed in [the CLI reference](README.md#global-flags).

## scrim api

Run or inspect the local agent API.

```text
scrim api [command]
```

| Subcommand | Description |
| --- | --- |
| [`scrim api serve`](#scrim-api-serve) | Serve the local agent API and the human entry page until interrupted |
| [`scrim api whoami`](#scrim-api-whoami) | Show the identity the local agent API gives this process |

Flags:

```text
  -o, --output string   output format: text or json (default "text")
```

## scrim api serve

Serve the local agent API and the human entry page until interrupted.

```text
scrim api serve
```

Flags inherited from parent commands:

```text
  -o, --output string   output format: text or json (default "text")
```

## scrim api whoami

Show the identity the local agent API gives this process.

```text
scrim api whoami
```

Flags inherited from parent commands:

```text
  -o, --output string   output format: text or json (default "text")
```
