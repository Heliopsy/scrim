# scrim approvals

<!-- Generated from the command tree by `just cli-docs`. Do not edit. -->

Global flags are listed in [the CLI reference](README.md#global-flags).

## scrim approvals

List and inspect approvals.

```text
scrim approvals [command]
```

| Subcommand | Description |
| --- | --- |
| [`scrim approvals list`](#scrim-approvals-list) | List approvals (pending by default) |
| [`scrim approvals show`](#scrim-approvals-show) | Show one approval |

## scrim approvals list

List approvals (pending by default).

```text
scrim approvals list [flags]
```

Flags:

```text
      --agent string        only approvals of this agent
      --json[=true|false]   print JSON
      --status string       pending, approved, denied, expired or all (default "pending")
```

## scrim approvals show

Show one approval.

```text
scrim approvals show <approval-id>
```
