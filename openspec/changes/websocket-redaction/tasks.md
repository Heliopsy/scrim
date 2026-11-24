# Tasks

## 1. Spec

- [x] 1.1 llm-proxy, credential-injection, performance and leak-assurance deltas; verify: `openspec validate --all --strict`

## 2. Data plane

- [x] 2.1 Serve WebSocket handshakes on routes (gate, route auth, head checks, provider handshake over an HTTP/1.1-only client, 101 after the provider, provider refusals passed back, chain behaviour); verify: `tests/websocket.rs` handshake tests, `tests/upgrade.rs` other upgrades still 501
- [x] 2.2 Client messages: reassembly with a size bound, per-protocol plan (Realtime codec, Responses WebSocket plan, generic), redactor and guard, binary messages, pings and close frames; verify: seeds never reach the fake provider, fragmented and oversized cases, watched fail with redaction removed from the relay
- [x] 2.3 Refusal on an open connection: error event, close code, provider closed, nothing forwarded; verify: guard refusal, redactor failure, malformed and unscannable cases, watched fail when a refused message is forwarded
- [x] 2.4 Snapshot changes re-run the gate; verify: a value added mid-session is redacted from the next message
- [x] 2.5 Provider message restore for Realtime and Responses WebSocket mode; verify: codec unit tests, restored deltas and done events end to end, watched fail with restore removed
- [x] 2.6 Tool proxy hands WebSocket handshakes to provider hosts to the LLM proxy; verify: `tests/forward_proxy.rs` WebSocket through CONNECT is redacted
- [x] 2.7 Latency gate: added p99 per WebSocket message against `websocket_message_p99_ms`; verify: `cargo bench -p scrim-llm --bench latency_gate`

## 3. Leak suite

- [x] 3.1 Fake provider speaks Realtime and Responses WebSocket mode and records each client message
- [x] 3.2 Bypass matrix rows over WebSocket, runner and stand-in proxies; verify: `just leak-selftest`, the gate against the real proxy
- [x] 3.3 Real data plane end-to-end test over WebSocket with the leak checker

## 4. Docs

- [x] 4.1 limitations, run, interception, leak assurance, crate READMEs
