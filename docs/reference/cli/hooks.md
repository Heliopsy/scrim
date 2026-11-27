# scrim hooks

<!-- Generated from the command tree by `just cli-docs`. Do not edit. -->

Global flags are listed in [the CLI reference](README.md#global-flags).

## scrim hooks

Agent hooks that redact tool results and check prompts (installed by scrim install --hooks).

```text
scrim hooks [command]

Hooks-only interception, the weakest method: scrim sees tool results and prompts, never the model traffic, and nothing
restores placeholders. Install with `scrim install --hooks`, remove with `scrim uninstall --hooks`; docs/interception.md
(method 6).
```

| Subcommand | Description |
| --- | --- |
| [`scrim hooks run`](#scrim-hooks-run) | Handle one hook call: the agent's hook JSON on standard input, the answer on standard output |

## scrim hooks run

Handle one hook call: the agent's hook JSON on standard input, the answer on standard output.

```text
scrim hooks run --agent claude|codex --event PostToolUse|UserPromptSubmit [flags]

Sends the tool result (PostToolUse) or the prompt (UserPromptSubmit) to scrim's local API, which runs it through the
data plane's redactor and guard. Claude Code gets the redacted tool result in place of the original; Codex gets the
result blocked, with the redacted result as the reason. A prompt holding a known value is blocked. When scrim cannot
redact, the tool result is withheld and the prompt blocked. Input that is not hook JSON exits 2.
```

Flags:

```text
      --agent string   the agent running the hook: claude or codex
      --event string   the hook event: PostToolUse or UserPromptSubmit
```
