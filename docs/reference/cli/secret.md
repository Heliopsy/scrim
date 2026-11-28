# scrim secret

<!-- Generated from the command tree by `just cli-docs`. Do not edit. -->

Global flags are listed in [the CLI reference](README.md#global-flags).

## scrim secret

Work with secrets without seeing their values.

```text
scrim secret [command]

Agent-facing secret commands. Each one is the CLI form of an MCP tool and talks to the local scrim API on its Unix
socket. No command takes a value as an argument or prints one.

Exit codes: 0 success, 1 error, 3 denied, 4 pending, 5 declined or expired.
```

| Subcommand | Description |
| --- | --- |
| [`scrim secret ask`](#scrim-secret-ask) | Ask a human to enter a value on the local entry page (secret_ask_human) |
| [`scrim secret capture`](#scrim-secret-capture) | Store a value a command prints without showing it (secret_capture) |
| [`scrim secret gen`](#scrim-secret-gen) | Generate a random value inside scrim and store it (secret_gen) |
| [`scrim secret grants`](#scrim-secret-grants) | List your active grants (grants_list) |
| [`scrim secret ls`](#scrim-secret-ls) | List the secrets you may use (secrets_list) |
| [`scrim secret put`](#scrim-secret-put) | Store a value read from standard input, never echoing it |
| [`scrim secret request`](#scrim-secret-request) | Ask for time-limited use of a secret (secret_request) |
| [`scrim secret status`](#scrim-secret-status) | Check an approval or an ask (approval_status) |

Flags:

```text
  -o, --output string   output format: text or json (default "text")
```

## scrim secret ask

Ask a human to enter a value on the local entry page (secret_ask_human).

```text
scrim secret ask <ref> --prompt <text> [flags]
```

Flags:

```text
      --overwrite[=true|false]   replace an existing secret
      --prompt string            what to ask the human for (required)
      --store string             store to write to when the reference does not name one
      --timeout int              seconds the human has to answer (default 900)
      --wait int                 seconds to wait for the answer before returning pending (at most 600) (default 120)
```

Flags inherited from parent commands:

```text
  -o, --output string   output format: text or json (default "text")
```

## scrim secret capture

Store a value a command prints without showing it (secret_capture).

```text
scrim secret capture <ref> [--json-path P | --pattern RE] (--stdin | -- <command> [args...]) [flags]

Runs the command (no shell) or reads standard input, takes the value from the output (whole output, a JSON path or the
first group of a regular expression) and stores it. The output is never printed.
```

Flags:

```text
      --dir string               working directory for the command
      --json-path string         take the value at this JSON path, for example .token
      --overwrite[=true|false]   replace an existing secret
      --pattern string           take the first capture group of this regular expression
      --stdin[=true|false]       read the output from standard input instead of running a command
      --store string             store to write to when the reference does not name one
      --timeout int              command timeout in seconds (default 60)
```

Flags inherited from parent commands:

```text
  -o, --output string   output format: text or json (default "text")
```

## scrim secret gen

Generate a random value inside scrim and store it (secret_gen).

```text
scrim secret gen <ref> [flags]
```

Flags:

```text
      --charset string           for chars: alnum (default), alnum-symbols, alpha, lower, digits
      --format string            chars (default), hex, base64, base64url, uuid or passphrase
      --length int               number of characters (default 32)
      --overwrite[=true|false]   replace an existing secret
      --separator string         for passphrase: separator (default -)
      --store string             store to write to when the reference does not name one
      --words int                for passphrase: number of words (default 6)
```

Flags inherited from parent commands:

```text
  -o, --output string   output format: text or json (default "text")
```

## scrim secret grants

List your active grants (grants_list).

```text
scrim secret grants
```

Flags inherited from parent commands:

```text
  -o, --output string   output format: text or json (default "text")
```

## scrim secret ls

List the secrets you may use (secrets_list).

```text
scrim secret ls [flags]

Aliases: list
```

Flags:

```text
      --binding string   only secrets bound to this host
      --prefix string    only references starting with this prefix
      --store string     only secrets in this store
```

Flags inherited from parent commands:

```text
  -o, --output string   output format: text or json (default "text")
```

## scrim secret put

Store a value read from standard input, never echoing it.

```text
scrim secret put <ref> --stdin [flags]

Reads the value from standard input and stores it. On a terminal the value is read with echo off. One trailing newline
is removed unless --keep-newline is given. The value is never printed or logged; the output is the reference and the
result of the write.
```

Flags:

```text
      --keep-newline[=true|false]   keep a trailing newline as part of the value
      --overwrite[=true|false]      replace an existing secret
      --stdin[=true|false]          read the value from standard input (required)
      --store string                store to write to when the reference does not name one
```

Flags inherited from parent commands:

```text
  -o, --output string   output format: text or json (default "text")
```

## scrim secret request

Ask for time-limited use of a secret (secret_request).

```text
scrim secret request <ref> --reason <why> [flags]
```

Flags:

```text
      --duration string   how long the grant should last, for example 30m
      --reason string     why the secret is needed, shown to the approver (required)
```

Flags inherited from parent commands:

```text
  -o, --output string   output format: text or json (default "text")
```

## scrim secret status

Check an approval or an ask (approval_status).

```text
scrim secret status <approval-or-ask-id>
```

Flags inherited from parent commands:

```text
  -o, --output string   output format: text or json (default "text")
```
