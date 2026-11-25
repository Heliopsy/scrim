## MODIFIED Requirements

### Requirement: Agent presets

`scrim run` SHALL add what each supported agent needs for the session only: for Claude Code an MCP
configuration on its command line, for Codex its base URL, MCP server and CA overrides as `-c`
options, for OpenCode inline configuration with its served providers' base URLs, the session header
and the MCP server, session variables passed by name. A preset SHALL refuse a setting that would send
the agent around scrim.

#### Scenario: Codex session

- **WHEN** a user runs `scrim run -- codex exec "fix the test"`
- **THEN** Codex sends its Responses requests to scrim's LLM proxy, starts `scrim mcp` with the session
  token, and `~/.codex/config.toml` is unchanged

#### Scenario: Cloud provider mode not served

- **WHEN** `CLAUDE_CODE_USE_BEDROCK` is set, scrim has no `bedrock` provider route and the user runs
  `scrim run -- claude`
- **THEN** `scrim run` refuses, because Claude Code would reach Bedrock directly

#### Scenario: Cloud provider mode served

- **WHEN** `CLAUDE_CODE_USE_BEDROCK` is set, scrim has a `bedrock` provider route and the user runs
  `scrim run -- claude`
- **THEN** Claude Code sends its Bedrock requests to scrim's route with its own AWS authentication
  turned off, inherited provider keys are removed from its environment, and scrim signs each
  redacted request with the credentials it holds

#### Scenario: OpenCode session

- **WHEN** a user runs `scrim run -- opencode run "fix the test"`
- **THEN** OpenCode sends its anthropic, openai and google requests to scrim's LLM proxy with the session
  header, its other providers are disabled, it starts `scrim mcp` with the session token, and no
  OpenCode configuration file changes

#### Scenario: OpenCode model of another provider

- **WHEN** a user runs `scrim run -- opencode run -m openrouter/some-model "fix the test"`
- **THEN** `scrim run` refuses, because OpenCode would reach that provider directly

#### Scenario: Codex with a custom model provider

- **WHEN** `~/.codex/config.toml` selects `model_provider = "azure"` and the user runs `scrim run -- codex`
- **THEN** `scrim run` warns that Codex's model requests go to that provider's base URL, not through scrim
