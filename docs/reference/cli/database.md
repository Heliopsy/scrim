# scrim database

<!-- Generated from the command tree by `just cli-docs`. Do not edit. -->

Global flags are listed in [the CLI reference](README.md#global-flags).

## scrim database

List configured databases and run read-only queries by placeholder.

```text
scrim database [command]

The CLI form of the database_list and database_query tools. A placeholder inside a string literal or in --param is bound
as a query parameter carrying the real value; the result comes back redacted.

Exit codes: 0 success, 1 error, 3 refused or denied.
```

| Subcommand | Description |
| --- | --- |
| [`scrim database ls`](#scrim-database-ls) | List the configured databases and their local proxy endpoints (database_list) |
| [`scrim database query`](#scrim-database-query) | Run one read-only statement (database_query) |

Flags:

```text
  -o, --output string   output format: text or json (default "text")
```

## scrim database ls

List the configured databases and their local proxy endpoints (database_list).

```text
scrim database ls
```

Flags inherited from parent commands:

```text
  -o, --output string   output format: text or json (default "text")
```

## scrim database query

Run one read-only statement (database_query).

```text
scrim database query DATABASE SQL [flags]
```

Flags:

```text
      --max-rows int        return at most this many rows
      --param stringArray   parameter for $1, $2 or ?, in order; may contain placeholders (repeatable)
```

Flags inherited from parent commands:

```text
  -o, --output string   output format: text or json (default "text")
```
