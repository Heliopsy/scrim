# scrim mcp

<!-- Generated from the command tree by `just cli-docs`. Do not edit. -->

Global flags are listed in [the CLI reference](README.md#global-flags).

## scrim mcp

Serve the agent tools over MCP (stdio).

```text
scrim mcp

Serves secrets_list, secret_request, secret_gen, secret_capture, secret_ask_human, approval_status and grants_list over
MCP on standard input and output. Each call goes to the local scrim API with this process's identity: its peer
credentials, and SCRIM_SESSION_TOKEN when it runs inside scrim run.

Register it with an agent, for example: claude mcp add scrim -- scrim mcp
```
