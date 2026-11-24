## MODIFIED Requirements

### Requirement: Protocol upgrades are refused

The tool proxy SHALL refuse protocol upgrades (for example WebSocket) toward every host it serves
itself, because the upgraded stream cannot be scanned. A WebSocket handshake toward a provider host
the LLM proxy claims SHALL be handed to the LLM proxy with its connection still able to upgrade, and
served there (llm-proxy spec, "WebSocket connections").

#### Scenario: WebSocket handshake

- **WHEN** an agent sends a WebSocket upgrade request through the tool proxy to a host no provider route claims
- **THEN** the request is refused with `upgrade_unsupported`

#### Scenario: WebSocket handshake to a provider host

- **WHEN** an agent sends a WebSocket upgrade request through the forward proxy to `api.openai.com`
- **THEN** the LLM proxy serves it and redacts every message
