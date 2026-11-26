## Why

scrim redacts client WebSocket messages on every provider route but restores placeholders in
provider messages only for the OpenAI Realtime API and the Responses WebSocket mode. A Gemini Live
agent (Gemini API or Vertex AI) sees placeholders in model text, transcripts and tool call
arguments, and its audio and media blobs are redacted as text. Azure Voice Live on a Foundry route
is not recognised as Realtime. The Realtime codec misses the transcripts of the user's audio,
which the GA API sends as `conversation.item.input_audio_transcription.*`.

## What Changes

- New Gemini Live codec (`BidiGenerateContent`, `BidiGenerateContentConstrained`, Vertex AI's
  `LlmBidiService/BidiGenerateContent`): client messages planned (model and session settings kept,
  contents planned like `generateContent`, `realtimeInput` blobs as binary parts, JSON in binary
  frames planned too), and model text, output, input and interim transcriptions and tool call
  arguments restored, split-safe across messages, in the frame type the provider used.
- A refusal on a Live connection is the close frame alone: the Live API has no error message.
- Realtime: the transcripts of the user's audio (deltas, completed, diarized segments, xAI's
  cumulative updates and truncated items) and the `transcript` of `input_audio` parts in user items
  are restored.
- A Foundry route treats `/voice-live/realtime` and Realtime paths under `/openai/` as Realtime.
- The Gemini API's `access_token` query parameter (a Live ephemeral token) is the agent's own
  credential, like `key`.
- Docs: audio is not restored but its transcripts are; Nova Sonic's bidirectional stream does not
  work through scrim; GPT-Live sessions are redacted only.

## Capabilities

### Modified Capabilities

- `llm-proxy`: WebSocket message plans, binary frames, refusal framing, provider message restore,
  provider credentials exempt from head redaction; audio passes unchanged (added).

## Impact

- `dataplane/crates/scrim-llm`: new `codec::gemini_live`, `codec::openai_realtime`,
  `websocket` (protocol by route and path, binary-frame restore, refusal framing), `config`
  (`access_token`), the fake WebSocket provider (binary frames).
- Docs: limitations, providers (README, Vertex, Foundry, Bedrock).
- Depends on the `websocket-redaction` change, whose requirements it modifies.
