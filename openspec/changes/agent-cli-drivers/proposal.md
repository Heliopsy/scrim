## Why

`scrim audit run` drives only Claude Code among the real agents, although the audit harness
requirement names Codex too, and nothing in CI runs that driver. OpenCode (sst/opencode) does not
work under `scrim run`: it gets the common environment only, and its AI SDK providers expect base
URLs ending in the API version, so `ANTHROPIC_BASE_URL` without `/v1` misses scrim's Messages route,
its requests are not identified, and providers scrim does not serve stay enabled. The Codex preset
was written against Codex 0.17x and had not been checked against current releases.

## What Changes

- `scrim audit run --driver codex` and `--driver opencode`, next to `claude`: one driver for real
  agent CLIs (empty HOME, fake key, the agent's own shell tool), each checked against a pass-through
  proxy and gated against `scrim proxy` in CI (`test/leak/agents.sh`, `just leak-agents`).
- New `opencode` preset for `scrim run`: `OPENCODE_CONFIG_CONTENT` (merged over an inherited one)
  with scrim's routes for the anthropic, openai and google providers, `x-scrim-session` from
  `{env:SCRIM_SESSION_TOKEN}`, `enabled_providers` limited to those three, and `scrim mcp`. A
  `-m` of another provider is refused. `--print-env` hides an inherited configuration.
- Codex preset checked against Codex 0.171: `openai_base_url`, `CODEX_CA_CERTIFICATE` and the MCP
  options are current (`OPENAI_BASE_URL` is ignored). New: a warning when the configuration selects
  another `model_provider`.
- End-to-end: `TestOpenCodeSession` (anthropic, plus openai and google) under `scrim run`, with a
  policy rule that denies provider requests not made by the session. CI installs OpenCode at a pinned
  version next to Claude Code and Codex; the e2e harness routes Gemini to the fake model too.

## Impact

- Affected specs: leak-assurance (Audit harness), interception (Agent presets).
- Affected code: internal/leak/scenario, internal/leak/audit, internal/run, internal/cli/run.go,
  test/e2e/session, test/e2e/harness, test/leak/agents.sh, .github/workflows/ci.yaml, justfile.
- Docs: run.md, leak-assurance.md, limitations.md, interception.md, configuration.md (run.mcp).
