# scrim policy

<!-- Generated from the command tree by `just cli-docs`. Do not edit. -->

Global flags are listed in [the CLI reference](README.md#global-flags).

## scrim policy

Check, evaluate and compile policy rules.

```text
scrim policy [command]
```

| Subcommand | Description |
| --- | --- |
| [`scrim policy check`](#scrim-policy-check) | Validate a rules file (default: policy.rules-file) |
| [`scrim policy eval`](#scrim-policy-eval) | Evaluate one request against the rules and explain the decision |
| [`scrim policy snapshot`](#scrim-policy-snapshot) | Print the decision table the data plane receives |

## scrim policy check

Validate a rules file (default: policy.rules-file).

```text
scrim policy check [rules-file]
```

## scrim policy eval

Evaluate one request against the rules and explain the decision.

```text
scrim policy eval [rules-file] [flags]

Evaluate one request against the rules and explain the decision. The request comes from flags or from --request, a JSON
file in the conformance vector format (op, agent, secret, provider, dest, tool).
```

Flags:

```text
      --agent string                  agent ID
      --agent-kind string             how the agent was identified (peer, session, k8s, mtls; empty for unknown)
                                      (default "session")
      --agent-label stringToString    agent labels, key=value (default [])
      --class string                  secret class
      --command string                command
      --host string                   destination host
      --label scrim catalog labels    one secret label, key=value (repeatable; a value may contain commas, as
                                      multi-valued store labels do); scrim catalog labels lists a secret's labels
      --method string                 HTTP method
      --name string                   catalog name
      --op string                     action (inject, store.write, ...)
      --path string                   request path
      --provider string               model provider
      --ref string                    secret reference
      --request string                JSON request file
      --secret-label stringToString   secret labels, key=value (default [])
      --tool string                   tool name
```

## scrim policy snapshot

Print the decision table the data plane receives.

```text
scrim policy snapshot [rules-file]
```
