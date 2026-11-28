# scrim run

<!-- Generated from the command tree by `just cli-docs`. Do not edit. -->

Global flags are listed in [the CLI reference](README.md#global-flags).

## scrim run

Run an agent with its traffic through scrim.

```text
scrim run [flags] -- <agent> [args...]

Starts the agent as a child process with its provider base URLs pointed at scrim's LLM proxy, its tool traffic through
scrim's forward proxy with scrim's CA trusted for that process only, a session token bound to this process tree, scrim
mcp registered and declared placeholders exported. Nothing outside the session changes, and the session ends when the
agent exits.

scrim run refuses to start the agent (exit 125) when scrim cannot serve it; run.allow-unredacted-start weakens that.
Otherwise it exits with the agent's status.

Presets: claude (Claude Code), codex (Codex CLI), opencode (OpenCode), generic. See docs/run.md.

Examples:
  scrim run -- claude
  scrim run -- codex exec 'fix the failing test'
  scrim run -- opencode run 'fix the failing test'
  scrim run --print-env -- claude
```

Flags:

```text
      --agent string             agent preset: claude, codex, opencode or generic (default: from the command name)
      --name string              session name shown in audit and whoami (default: the agent's command name)
  -o, --output string            --print-env format: text or json (default "text")
      --print-env[=true|false]   print what would be set for the agent and exit; the session token is never printed
      --ttl duration             session token lifetime (default session.ttl); the session ends earlier when the
                                 agent exits
```
