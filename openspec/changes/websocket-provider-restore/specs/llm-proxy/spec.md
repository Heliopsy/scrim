## MODIFIED Requirements

### Requirement: Provider credentials are exempt from head redaction

Only the agent's provider credentials SHALL be exempt from redaction and the guard in the request
head: the headers `authorization`, `x-api-key` and `x-goog-api-key`, and on a Gemini route the
`key` and `access_token` query parameters.

#### Scenario: Provider credential headers pass through

- **WHEN** an agent's request carries its provider API key in `x-api-key` or `authorization`
- **THEN** the provider receives those headers byte for byte as the agent sent them

#### Scenario: Gemini API key in the query

- **WHEN** an agent sends a Gemini request with its API key in the `key` query parameter or the `x-goog-api-key` header
- **THEN** the provider receives the key as sent while every other query parameter is redacted
- **AND** a capture of the request shows the key masked

#### Scenario: Live API ephemeral token

- **WHEN** an agent opens a Gemini Live WebSocket with an ephemeral token in the `access_token` query parameter
- **THEN** the provider receives the token as sent while every other query parameter is redacted

### Requirement: WebSocket message plans

A message SHALL be planned as one JSON event of the connection's protocol, every unknown field
redacted. Realtime (`.../realtime`, and on a Foundry route `/voice-live/realtime` and under
`/openai/`) keeps the event `type`, with audio and `data:` images as binary parts. Responses mode
plans `response.create` as a create body. Gemini Live keeps the model and session settings, plans
contents as `generateContent` and blobs as binary parts. Elsewhere the whole message is redacted.

#### Scenario: Audio append

- **WHEN** an agent sends `input_audio_buffer.append` under the `pass` binary policy
- **THEN** the audio is forwarded unchanged and the connection's audit entries mark unscanned `audio` content once

#### Scenario: Encrypted reasoning in Responses mode

- **WHEN** a `response.create` event carries a reasoning item with `encrypted_content`
- **THEN** the encrypted content leaves byte-identical and the rest of the input is redacted

#### Scenario: Gemini Live audio and turns

- **WHEN** a Live agent sends `realtimeInput.audio` and a `clientContent` turn with a known value
- **THEN** the audio leaves byte-identical even where a detector would match it, and the turn carries a placeholder

### Requirement: WebSocket binary and control frames

A binary client message SHALL be planned like a text message on a Gemini Live connection, whose
protocol carries JSON in binary frames, redacted whole elsewhere when it is valid UTF-8, and
refused as `unscannable_content` otherwise. Ping and pong frames SHALL be answered locally and
never forwarded; a close frame SHALL be forwarded with its code and without its reason.

#### Scenario: Binary frame that is not text

- **WHEN** an agent sends a binary message that is not valid UTF-8
- **THEN** nothing of it is forwarded and the connection is closed with code 1008 and reason `unscannable_content`

#### Scenario: Ping with a payload

- **WHEN** an agent sends a ping carrying a known value
- **THEN** scrim answers the pong itself and the provider receives no ping

### Requirement: Unsafe WebSocket message closes the connection

When a client message cannot be made safe, scrim SHALL NOT forward any part of it. It SHALL send
one `error` event carrying nothing from the message (none on Gemini Live, which has no error
message), close the agent's connection with 1008 and the reason code as close reason, close the
provider connection and audit the refusal. Over the size limit it closes with 1009, missing values
or credentials 1013, a provider failure 1014, a capture failure 1011.

#### Scenario: Guard refuses a message

- **WHEN** the guard refuses a client message
- **THEN** the provider receives nothing of that message, the agent receives an `error` event with code `guard_refused` and then a close frame with code 1008

#### Scenario: Redactor fails during a session

- **WHEN** the redactor returns an error for a client message
- **THEN** the agent receives an `error` event with code `redactor_failed` and a close frame with code 1008, and the provider receives nothing of it

#### Scenario: Guard refuses a Gemini Live message

- **WHEN** the guard refuses a message on a Gemini Live connection
- **THEN** the agent receives a close frame with code 1008 and reason `guard_refused` and no message before it

### Requirement: WebSocket provider messages are restored

Provider messages SHALL be restored as streamed responses are, with a holdback per text: Realtime
assistant text, transcripts of the model's and the user's audio and function call arguments with
their done events and items; the Responses events in WebSocket mode; Gemini Live model text,
transcriptions and tool call arguments. A restored message SHALL leave in the frame type it came
in; others byte for byte; held text before a provider close.

#### Scenario: Placeholder split across delta events

- **WHEN** the provider streams a placeholder split across two `response.output_text.delta` events
- **THEN** the agent receives the restored value once, in order, and the final `response.done` carries the same text

#### Scenario: Credential stays a placeholder

- **WHEN** a provider message contains the placeholder of a credential-class value
- **THEN** the agent receives the placeholder unchanged

#### Scenario: Echo of the agent's own item

- **WHEN** the provider echoes the agent's user item in `conversation.item.done`
- **THEN** the agent receives its text parts as the provider sent them and only the transcripts of its audio restored

#### Scenario: Gemini Live text split across binary messages

- **WHEN** the Gemini API sends a placeholder split across two `serverContent.modelTurn` messages in binary frames
- **THEN** the agent receives the restored value once, in binary frames, and the tool call's `args` restored

#### Scenario: Transcript of the user's audio

- **WHEN** a Realtime provider streams a placeholder split across two `conversation.item.input_audio_transcription.delta` events
- **THEN** the agent receives the restored value once and the `completed` event carries the same text

## ADDED Requirements

### Requirement: WebSocket audio passes unchanged

Audio in provider messages SHALL pass byte for byte, so a placeholder the model speaks stays in
the audio; its transcript is restored. scrim SHALL NOT add instructions to a session.

#### Scenario: Model reads a placeholder aloud

- **WHEN** a Realtime provider sends `response.output_audio.delta` events and a transcript containing a placeholder
- **THEN** the audio events reach the agent byte for byte and the transcript carries the restored value
