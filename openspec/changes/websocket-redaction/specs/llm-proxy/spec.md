## MODIFIED Requirements

### Requirement: Protocol upgrades are refused

The LLM proxy SHALL refuse a protocol upgrade other than a WebSocket handshake it serves (a `GET`
over HTTP/1.1 with `Upgrade: websocket`, version 13 and a key) with 501 and `upgrade_unsupported`,
before reading the body, loading values or asking the gate, and SHALL send nothing upstream.

#### Scenario: Other upgrade

- **WHEN** an agent asks a provider route for an upgrade to `h2c` or any protocol other than WebSocket
- **THEN** it receives status 501 with `x-scrim-error: upgrade_unsupported` within 100 ms and the provider receives nothing

#### Scenario: Upgrade before values load

- **WHEN** an upgrade other than a WebSocket handshake arrives before the known values have loaded
- **THEN** it is refused with `upgrade_unsupported`, not `not_ready`

#### Scenario: Codex opens a Responses WebSocket

- **WHEN** Codex sends a WebSocket handshake for the Responses API to a provider route, by base URL or through the forward proxy
- **THEN** it is not refused with `upgrade_unsupported`; it is served as the "WebSocket connections" requirement says

## ADDED Requirements

### Requirement: WebSocket connections

The LLM proxy SHALL serve a WebSocket handshake on a provider route, by base URL and through the
forward proxy and transparent listeners, by terminating the WebSocket on both sides: it accepts the
agent's handshake and opens its own WebSocket to the route's upstream, through the chained upstream
first when one is configured, with the `on-unavailable` behaviour of HTTP requests.

#### Scenario: Realtime session through the base URL

- **WHEN** an agent opens `ws://127.0.0.1:<port>/openai/v1/realtime?model=...`
- **THEN** scrim opens `<upstream>/v1/realtime?model=...` and relays messages between the two sockets

### Requirement: WebSocket handshake checks

Before anything is sent upstream, a WebSocket handshake SHALL pass the checks an HTTP request passes
before its body: values loaded (`not_ready`), the request gate (`policy_denied`), the route's own
credentials (`credential_unavailable`), and the redactor and the guard over the request target and
headers. A failure SHALL be answered over HTTP and nothing SHALL be sent upstream.

#### Scenario: Handshake before values load

- **WHEN** a WebSocket handshake arrives before the known values have loaded
- **THEN** it is answered 503 with `not_ready` and the provider receives nothing

#### Scenario: Secret in a handshake header

- **WHEN** a handshake header other than the agent's provider credential carries a known value
- **THEN** the provider receives the header with a placeholder in place of the value

### Requirement: Provider WebSocket handshake

The upstream handshake SHALL be HTTP/1.1 with a key scrim generates, SHALL offer no extension, and
SHALL carry the agent's provider credentials unchanged, or on a route that authenticates itself, the
route's authentication in place of the agent's. The agent SHALL get `101` only after the provider
answered `101` with a valid accept key and no extension; any other answer from the provider SHALL be
the answer to the agent's handshake.

#### Scenario: Agent credentials pass through

- **WHEN** an agent opens a Realtime session with its own `Authorization` header
- **THEN** the provider's handshake carries that header unchanged

#### Scenario: Provider refuses the handshake

- **WHEN** the provider answers scrim's handshake with 401
- **THEN** the agent receives 401 with the provider's body, and no WebSocket is opened

#### Scenario: Compression extension

- **WHEN** an agent offers `permessage-deflate`
- **THEN** scrim does not offer it to the provider and does not accept it from the agent

### Requirement: WebSocket client messages are redacted

Every message the agent sends on a WebSocket SHALL pass the redactor and then the independent guard
over the exact bytes that leave before scrim sends it, as a request body does. A message fragmented
across frames SHALL be reassembled first, and a message larger than
`proxy.limits.max-request-body` SHALL be refused without being forwarded.

#### Scenario: Seed in a conversation item

- **WHEN** an agent sends `conversation.item.create` with a known value in an `input_text` part or a `function_call_output`
- **THEN** the provider receives the event with a placeholder in place of the value

#### Scenario: Fragmented message

- **WHEN** an agent sends one text message in several continuation frames with a known value split across two of them
- **THEN** the provider receives one message with a placeholder in place of the value

#### Scenario: Oversized message

- **WHEN** an agent sends a message larger than the request body limit, in one frame or in fragments
- **THEN** the provider receives nothing of it and the agent's connection is closed with code 1009 and reason `body_too_large`

### Requirement: WebSocket message plans

A text message SHALL be planned as one JSON event of the connection's protocol, with every field
the codec does not know redacted: on an `OpenAI` Realtime route (`.../realtime`) the event `type`
stays byte-identical and base64 audio and `data:` image URLs are binary parts under the binary
policy; in the Responses WebSocket mode (`.../responses`) `response.create` is planned as a create
body; on any other path the whole message is redacted.

#### Scenario: Audio append

- **WHEN** an agent sends `input_audio_buffer.append` under the `pass` binary policy
- **THEN** the audio is forwarded unchanged and the connection's audit entries mark unscanned `audio` content once

#### Scenario: Encrypted reasoning in Responses mode

- **WHEN** a `response.create` event carries a reasoning item with `encrypted_content`
- **THEN** the encrypted content leaves byte-identical and the rest of the input is redacted

### Requirement: WebSocket binary and control frames

A binary client message SHALL be redacted whole when it is valid UTF-8 and refused as
`unscannable_content` otherwise. Ping and pong frames SHALL be answered locally and never
forwarded; a close frame SHALL be forwarded with its code and without its reason.

#### Scenario: Binary frame that is not text

- **WHEN** an agent sends a binary message that is not valid UTF-8
- **THEN** nothing of it is forwarded and the connection is closed with code 1008 and reason `unscannable_content`

#### Scenario: Ping with a payload

- **WHEN** an agent sends a ping carrying a known value
- **THEN** scrim answers the pong itself and the provider receives no ping

### Requirement: Unsafe WebSocket message closes the connection

When a client message cannot be made safe, scrim SHALL NOT forward any part of it. It SHALL send the
agent one `error` event carrying nothing from the refused message, close the agent's connection
with code 1008 (policy violation) and the reason code as close reason, close the provider
connection, and audit the refusal. A message over the size limit closes with 1009, missing values
or credentials with 1013, a provider failure with 1014 and a capture failure with 1011.

#### Scenario: Guard refuses a message

- **WHEN** the guard refuses a client message
- **THEN** the provider receives nothing of that message, the agent receives an `error` event with code `guard_refused` and then a close frame with code 1008

#### Scenario: Redactor fails during a session

- **WHEN** the redactor returns an error for a client message
- **THEN** the agent receives an `error` event with code `redactor_failed` and a close frame with code 1008, and the provider receives nothing of it

### Requirement: WebSocket connections follow snapshot updates

Each client message SHALL be redacted with the snapshot in force when it arrives. When the snapshot
changed since the connection's last message, scrim SHALL ask the request gate again with the
handshake it received and use its answer, so a value added while a connection is open is redacted
from its next message and a rule that now denies the caller closes the connection with
`policy_denied`.

#### Scenario: Value added during a session

- **WHEN** a value is added to the redaction set while a Realtime session is open and the agent then sends it
- **THEN** the provider receives a placeholder in place of the value

### Requirement: WebSocket provider messages are restored

Provider messages SHALL get the placeholder resolution of streamed HTTP responses, under the same
restore policy and holdback per content block: on a Realtime route assistant text, audio
transcripts and function call arguments with their done events, completed items and
`response.done`; in Responses WebSocket mode the events the Responses SSE stream restores. Other
messages SHALL leave byte for byte, and held text SHALL be released before a provider close.

#### Scenario: Placeholder split across delta events

- **WHEN** the provider streams a placeholder split across two `response.output_text.delta` events
- **THEN** the agent receives the restored value once, in order, and the final `response.done` carries the same text

#### Scenario: Credential stays a placeholder

- **WHEN** a provider message contains the placeholder of a credential-class value
- **THEN** the agent receives the placeholder unchanged

#### Scenario: Echo of the agent's own item

- **WHEN** the provider echoes the agent's user item in `conversation.item.done`
- **THEN** the agent receives it as the provider sent it
