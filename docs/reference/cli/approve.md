# scrim approve

<!-- Generated from the command tree by `just cli-docs`. Do not edit. -->

Global flags are listed in [the CLI reference](README.md#global-flags).

## scrim approve

Approve a pending approval and create its grant.

```text
scrim approve <approval-id> [flags]
```

Flags:

```text
      --json[=true|false]   print the result as JSON
      --reason string       reason recorded in the audit log
      --ttl duration        grant duration (default: the rule's grant ttl; capped at its maximum)
```
