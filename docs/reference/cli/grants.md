# scrim grants

<!-- Generated from the command tree by `just cli-docs`. Do not edit. -->

Global flags are listed in [the CLI reference](README.md#global-flags).

## scrim grants

List and revoke just-in-time grants.

```text
scrim grants [command]
```

| Subcommand | Description |
| --- | --- |
| [`scrim grants list`](#scrim-grants-list) | List active grants |
| [`scrim grants revoke`](#scrim-grants-revoke) | Revoke a grant at once |

## scrim grants list

List active grants.

```text
scrim grants list [flags]
```

Flags:

```text
      --agent string        only grants of this agent
      --all[=true|false]    include expired, revoked and used-up grants
      --json[=true|false]   print JSON
```

## scrim grants revoke

Revoke a grant at once.

```text
scrim grants revoke <grant-id> [flags]
```

Flags:

```text
      --reason string   reason recorded in the audit log
```
