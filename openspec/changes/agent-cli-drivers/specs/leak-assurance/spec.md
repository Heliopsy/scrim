## MODIFIED Requirements

### Requirement: Audit harness

`scrim audit run` SHALL drive agents through scrim against a local fake model, seeded with generated
secrets, and SHALL report per request what the provider would have received, every leak found, and
the prompt-cache hit rate. It SHALL drive real agent CLIs (Claude Code, Codex and OpenCode) and a
built-in synthetic agent for every supported provider API. The report SHALL identify seeds by name,
kind, length and a short hash, never by value.

#### Scenario: Clean audit

- **WHEN** `scrim audit run --driver claude` runs a scripted session over files containing seeded secrets
- **THEN** the report shows zero leaks
- **AND** shows the cache hit rate across turns

#### Scenario: Leak fails the audit

- **WHEN** any seeded value reaches the fake model in any encoding
- **THEN** `scrim audit run` exits non-zero and names the request, field and encoding

#### Scenario: Restored value sent back

- **WHEN** the fake model calls a tool with a placeholder, the proxy restores it, and the agent sends that call back in its history
- **THEN** the next request carries the placeholder again, byte-identical to the first

#### Scenario: Cache measured

- **WHEN** a scenario runs twice through the proxy
- **THEN** the report shows, per turn, whether the previous turn's whole prompt was a cached prefix
- **AND** whether the replay produced byte-identical requests, failing the audit if either does not hold

#### Scenario: Report holds no value

- **WHEN** a run finds leaks
- **THEN** neither the JSON report nor the printed summary contains any seeded value

#### Scenario: Codex driver

- **WHEN** `scrim audit run --driver codex` runs the agent sessions through scrim
- **THEN** Codex runs every command over the Responses API (WebSocket or HTTPS) with an empty HOME and a fake key
- **AND** the report shows zero leaks, or fails naming the request

#### Scenario: OpenCode driver

- **WHEN** `scrim audit run --driver opencode` runs the agent sessions through scrim
- **THEN** OpenCode runs every command over the Anthropic Messages API with only that provider enabled, an empty HOME and a fake key
- **AND** the report shows zero leaks, or fails naming the request

#### Scenario: Driver checked against a pass-through proxy

- **WHEN** a driver's sessions run through a proxy that forwards everything
- **THEN** every session completes and reports leaks, so a driver that stopped running its commands fails
