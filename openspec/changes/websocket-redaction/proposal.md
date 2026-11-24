## Why

The LLM proxy refuses every WebSocket upgrade, so the OpenAI Realtime API, the Responses API
WebSocket mode and any agent built on them do not work through scrim (docs/limitations.md). Codex
falls back to HTTPS; a client that cannot fall back fails. Refusing was the safe answer while
nothing could redact WebSocket messages, but it pushes users toward bypassing scrim for voice and
low-latency agents.

## What Changes

- The LLM proxy serves WebSocket handshakes on provider routes, by base URL and through the forward
  proxy and transparent listeners, by terminating the socket on both sides and relaying message by
  message. The handshake passes the same checks as an HTTP request head (values loaded, request
  gate, route credentials, redactor and guard over target and headers), and the provider handshake
  carries the agent's credentials or the route's own authentication.
- Every client message is reassembled (bounded by `proxy.limits.max-request-body`), planned per
  protocol, redacted and guarded like a request body. Binary messages are redacted whole when they
  are text and refused otherwise. A message that cannot be made safe is never forwarded: the agent
  gets an `error` event and close code 1008 (1009 for an oversized message).
- Provider messages get the placeholder restore of streamed responses: OpenAI Realtime events (new
  codec) and the Responses events of WebSocket mode (the existing Responses stream codec).
- Each message uses the snapshot in force; the request gate is asked again when it changed.
- Other upgrades are still refused with `501 upgrade_unsupported`. The tool proxy still refuses
  upgrades toward hosts it serves itself.
- The latency gate measures the latency added per WebSocket message against a budget.
- The leak suite gets a WebSocket protocol: the fake provider speaks Realtime (and Responses
  WebSocket mode), and the bypass matrix runs rows over it.

## Capabilities

### Modified Capabilities

- `llm-proxy`: WebSocket connections, client message redaction, refusal on an open connection,
  snapshot updates and provider message restore; "Protocol upgrades are refused" narrowed to other
  upgrades.
- `credential-injection`: the tool proxy hands WebSocket handshakes to provider hosts to the LLM
  proxy.
- `performance`: a per-message WebSocket budget.
- `leak-assurance`: the fake provider and the bypass matrix cover WebSocket.

## Impact

- `dataplane/crates/scrim-llm`: new `websocket` module and `codec::openai_realtime`, a second
  HTTP/1.1-only upstream client, `Refusal::ws_event` and `close_code`, the Responses stream codec
  resets on `response.created`, the fake WebSocket provider in `testing`, the latency gate.
- `dataplane/crates/scrim-toolproxy`: intercepted TLS connections and transparent HTTP connections
  are served with upgrades.
- New dependency: `tokio-tungstenite` (WebSocket framing, reassembly and size limits).
- Go: the fake provider, the bypass matrix runner and its stand-in proxies, a real data plane
  end-to-end test.
- Docs: limitations, run, interception, leak assurance, crate READMEs.
