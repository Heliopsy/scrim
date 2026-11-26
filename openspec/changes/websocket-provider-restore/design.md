## Context

`websocket-redaction` terminates provider WebSockets and redacts every client message, but restores
only OpenAI Realtime and the Responses WebSocket mode. This change covers the other protocols the
provider routes reach. It builds on that change's decisions W1 to W7.

## Research note (2026-11-25)

The official docs as of 2026-11-25. Dates are the doc's `updated_at`, `ms.date` or changelog entry
where one is shown. OpenAI pages show no date, so its dates come from the changelog.

| Provider | Protocol | Reached by a scrim route | What changed recently |
| --- | --- | --- | --- |
| OpenAI | Realtime, `wss://api.openai.com/v1/realtime` (also `?intent=transcription`, `/v1/realtime/translations`) | `openai` | GA 2025-08-28. The beta interface was removed on 2026-05-12, but the GA reference still lists `conversation.item.created`. New: `conversation.item.input_audio_transcription.segment` (diarized), `response.mcp_call_arguments.*`, models gpt-realtime-1.5 (2026-02-23), -2 (2026-05-07), -2.1 (2026-07-06) |
| OpenAI | Responses API WebSocket mode, `/v1/responses` | `openai`, `chatgpt` | Launched 2026-02-23. Server events are the Responses SSE events; `response.steer` added 2026-09-03 |
| OpenAI | GPT-Live, `wss://api.openai.com/v1/live/sessions` | `openai` (redacted only) | GA 2026-09-10, gpt-live-1.1 2026-11-19. A protocol of its own: `session.start`, `session.*_transcript.delta`, and `response.event` wrapping Responses events |
| Azure | OpenAI Realtime, `wss://<res>.openai.azure.com/openai/v1/realtime` | no route for that host | The `/openai/realtime?api-version=...&deployment=` preview was deprecated 2026-04-30. Uses the OpenAI GA event names (migration guide updated 2026-07-31) |
| Azure | Voice Live, `wss://<res>.services.ai.azure.com/voice-live/realtime?api-version=2026-04-10` | `foundry` | Reference updated 2026-11-17. Realtime protocol with the beta names (`response.text.delta`, `response.audio_transcript.delta`, `conversation.item.created`), plus Azure events (`response.foundry_agent_call_arguments.*`, avatar and animation events) |
| Google | Gemini Live, `wss://generativelanguage.googleapis.com/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent` (`?key=`), `...BidiGenerateContentConstrained?access_token=` for ephemeral tokens | `gemini` | Still "preview" in the reference. New fields: `interimInputTranscription`, `interactionStatus`, `waitingForInput`, transcription `languageCodes`/`diarization`/`sourceText` (2026-11-17). Models gemini-3.1-flash-live-preview (2026-03-26) and gemini-3.8-live (2026-09-15) |
| Google | Vertex AI Live, `wss://{location}-aiplatform.googleapis.com/ws/google.cloud.aiplatform.v1.LlmBidiService/BidiGenerateContent` | `vertex` | Reference updated 2026-11-24. Adds `contextUpdate` (new instructions and tools mid-session), `setupComplete.sessionId`, `Transcription.finished`, and lists transcriptions as top-level server messages |
| Anthropic | none | | No WebSocket or realtime API; Messages streaming is SSE |
| xAI | Voice Agent, `wss://api.x.ai/v1/realtime` | only through an `openai` route with its upstream changed | OpenAI Realtime compatible. Sends both `response.text.delta` and `response.output_text.delta`, a cumulative `conversation.item.input_audio_transcription.updated` and `conversation.item.truncated.transcript` |
| Mistral | Voxtral realtime transcription, `wss://api.mistral.ai/v1/audio/transcriptions/realtime` | no route | Transcription only (`transcription.text.delta`, `.segment`, `.done`); no conversational realtime API |
| AWS | Bedrock `InvokeModelWithBidirectionalStream` (Nova Sonic) | `bedrock`, but it does not work | An HTTP/2 event stream, not WebSocket: `textOutput.content`, `toolUse.content`, and `contentStart` with role and stage. Bedrock's only WebSocket is AgentCore Runtime, which carries the customer's own protocol |

Frames: no doc states the frame type. The Gemini API sends its server messages in binary frames,
and every Google client accepts both kinds: js-genai `live.ts` and the official
`gemini-live-api-examples` `geminilive.js` decode a `Blob` before `JSON.parse`, and python-genai
`live.py` calls `recv(decode=False)` then `json.loads`. The OpenAI protocols use text frames.

Sources:

- OpenAI: changelog <https://developers.openai.com/api/docs/changelog>, Realtime server events
  <https://developers.openai.com/api/reference/resources/realtime/server-events>, WebSocket mode
  <https://developers.openai.com/api/docs/guides/websocket-mode>, GPT-Live
  <https://developers.openai.com/api/reference/resources/live/primary-websocket>
- Azure: Realtime over WebSockets
  <https://learn.microsoft.com/en-us/azure/foundry/openai/how-to/realtime-audio-websockets>
  (updated 2026-11-24), migration guide
  <https://learn.microsoft.com/en-us/azure/foundry/openai/how-to/realtime-audio-preview-api-migration-guide>
  (2026-07-31), Voice Live reference
  <https://learn.microsoft.com/en-us/azure/ai-services/speech-service/voice-live-api-reference-2026-04-10>
  (2026-11-17)
- Google: Live API reference <https://ai.google.dev/api/live> (now served at
  <https://aistudio.google.com/api-reference/live>), WebSocket guide
  <https://aistudio.google.com/docs/live-api/get-started-websocket.md>, changelog
  <https://aistudio.google.com/docs/changelog.md>, Vertex AI
  <https://docs.cloud.google.com/vertex-ai/generative-ai/docs/model-reference/multimodal-live>
  (2026-11-24)
- Anthropic: <https://platform.claude.com/llms.txt>,
  <https://platform.claude.com/docs/en/build-with-claude/streaming.md>
- xAI: <https://docs.x.ai/docs/guides/voice/agent>; Mistral:
  <https://docs.mistral.ai/studio/audio/speech-to-text/transcribe-in-realtime>
- AWS: <https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_InvokeModelWithBidirectionalStream.html>,
  <https://docs.aws.amazon.com/nova/latest/nova2-userguide/sonic-output-events.md>

## Decisions

### P1. Protocol by route and path

`WsApi::for_path` picks the codec. On `gemini` and `vertex` routes, a last path segment ending in
`BidiGenerateContent` or `BidiGenerateContentConstrained` is Gemini Live. On a Foundry route (an
`anthropic` provider route that forwards every path), `/voice-live/realtime` and Realtime paths
under `/openai/` are Realtime. Anything else stays generic: redacted whole, not restored.

### P2. Gemini Live plan

The plan reuses the `generateContent` codec's pieces. `setup.model`, the plain `generationConfig`
settings, and the session settings that hold no prompt are kept: `realtimeInputConfig`,
`sessionResumption` (its handle is issued by the server; a detector must not rewrite it),
`contextWindowCompression`, and both transcription configs. `systemInstruction` (also in Vertex's
`contextUpdate`) and `clientContent.turns` are planned as contents. The `audio`, `video` and
`mediaChunks` blobs of `realtimeInput` are binary parts under the binary policy, with the media
type's parameters dropped (`audio/pcm;rate=16000` is reported as `audio/pcm`). Tools, `text` and
tool responses are redacted. Field names are accepted in both casings, and a field named both ways
is refused, as for `generateContent`.

### P3. Binary frames carry JSON on Live

A Live connection plans a UTF-8 binary client message like a text one, and restores the
provider's binary messages through the codec, sending the result in binary frames again, synthesised
releases included. Without this, every Gemini API server message would bypass restore. Other
protocols keep W3: binary client messages are redacted whole, and provider binary messages pass.

### P4. Live restore and holdback

There are three holdbacks: model text, output transcription and input transcription. Held text is
released into the message's last field of the same text when that is the last part, and as a
synthesised `serverContent` message before it otherwise. The synthesised message uses the
provider's casing. Model text is released before any other part and before a `toolCall`. Model
text and the output transcription are released at `generationComplete`, because the reference says
the turn's last output transcription comes before it. Everything is released at `turnComplete` and
`interrupted`. `interimInputTranscription` is rewritten while the user speaks, so each message is
restored alone, without a holdback. Tool call `args` are complete JSON objects and are restored
under the tool policy with the full arguments in view. Thoughts, audio, grounding and every other
message pass byte for byte.

### P5. Live refusal

The Live API has no error message: Google reports errors in the close frame. So a Live refusal is
the close frame alone, with the same code and reason as on the other protocols. An OpenAI `error`
event would reach a Live client as an empty server message.

### P6. Realtime transcripts of the user's audio

The provider's transcription model writes these, and it may be prompted with redacted text, so
they can carry placeholders. The deltas get a holdback keyed by item and content index.
`.completed`, the diarized `.segment`, and xAI's cumulative `.updated` and `conversation.item.truncated`
are restored whole. In a user item, only the `transcript` of `input_audio` parts is restored; the
agent's own text stays as echoed (W6). MCP and Foundry agent call arguments stay unrestored:
the provider runs those calls, so restoring them would show the agent values the tool never got.

### P7. No spoken-placeholder hint

Realtime `session.instructions` and Live `systemInstruction` could carry an added line asking the
model not to read placeholders aloud. scrim does not add one, for three reasons. Audio and its
transcript come from the same generation, so a model that avoids saying the placeholder also
leaves it out of the transcript, which is the one place it can be restored. On Realtime, setting
instructions where the agent sent none replaces the provider's default prompt. And the effect on
speech cannot be measured in tests. The limitation is documented instead: audio says the
placeholder, the transcript has the value.

### P8. Not covered

- GPT-Live (`/v1/live/sessions`) is redacted only. Its `response.event` envelope could reuse the
  Responses codec, but the protocol is new and large; it is a follow-up.
- Nova Sonic cannot work through the HTTP path, which reads a request body whole. Serving it would
  need a streaming event-stream relay; it is documented as unsupported.
- The leak suite's fake provider (Go) still speaks only the OpenAI protocols; the Live codec is
  covered by the data plane's fake provider.

## Risks / Trade-offs

- A placeholder split across a release point (for example a transcription chunk straddling
  `generationComplete`) is released unresolved. The agent then sees the placeholder, never a
  wrong value.
- Restoring binary Live messages parses every audio chunk's JSON, as Realtime already does for its
  audio events. Messages over the data plane's event size bound (16 MiB) pass unrestored.
