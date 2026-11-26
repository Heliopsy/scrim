## 1. Research

- [x] 1.1 Current WebSocket protocols of OpenAI, Azure, Google, Anthropic, xAI, Mistral and AWS, and which scrim routes reach them (design.md)

## 2. Data plane

- [x] 2.1 Gemini Live codec: client plan and server restore with holdback per text; verify: codec unit tests, `tests/websocket.rs` Gemini Live tests, watched fail with the codec and the binary-frame restore removed
- [x] 2.2 Live connections: protocol from the Gemini and Vertex paths, binary JSON frames planned and restored in kind, refusal as a close frame alone; verify: watched fail with an error event sent and with binary messages redacted whole
- [x] 2.3 Realtime codec: transcripts of the user's audio and `input_audio` transcripts in user items; verify: codec unit test, Foundry route test, watched fail with the delta event unhandled
- [x] 2.4 Foundry route paths for Voice Live and Azure OpenAI Realtime; verify: `protocol_from_path`, Foundry route test, watched fail with the mapping removed
- [x] 2.5 `access_token` passes untouched on Gemini routes; verify: ephemeral token test, watched fail with the parameter removed

## 3. Docs

- [x] 3.1 limitations (restore coverage, audio, Nova Sonic), providers README, Vertex, Foundry, Bedrock
