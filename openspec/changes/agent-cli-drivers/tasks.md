## 1. Leak suite agent drivers

- [x] 1.1 One driver for real agent CLIs: claude, codex (`codex exec`, Responses over WebSocket), opencode (`opencode run`, Anthropic)
- [x] 1.2 `scrim audit run --driver codex|opencode`; WebSocket sessions not measured for prompt cache
- [x] 1.3 `TestAgentDriversPassThrough`: each driver completes its sessions and leaks through a pass-through proxy; skipped without the agent unless `SCRIM_E2E_REQUIRE_TOOLS=1`
- [x] 1.4 `test/leak/agents.sh` (`just leak-agents`): the scenario gate per agent against `scrim proxy` in the sandbox

## 2. scrim run

- [x] 2.1 `opencode` preset: providers' base URLs, session header by `{env:}`, `enabled_providers`, `scrim mcp`, inherited `OPENCODE_CONFIG_CONTENT` merged and hidden from `--print-env`
- [x] 2.2 Refuse `-m` of a provider scrim does not serve
- [x] 2.3 Codex preset checked against Codex 0.171; warn about a custom `model_provider`
- [x] 2.4 Unit tests for the configuration, the merge, the refusal and the warning

## 3. End to end and CI

- [x] 3.1 `TestOpenCodeSession` and `TestOpenCodeSessionProviders` under `scrim run`, unidentified provider requests denied by policy
- [x] 3.2 e2e-agents job: OpenCode pinned, driver tests and the agent leak gate with `SCRIM_E2E_REQUIRE_TOOLS=1`

## 4. Docs

- [x] 4.1 run.md (OpenCode preset, Codex notes, tests, limitations), leak-assurance.md (agent drivers), limitations.md, interception.md (CA trust), configuration.md
