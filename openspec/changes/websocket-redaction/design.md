## Context

WebSocket was refused because the upgraded stream is opaque to an HTTP proxy. The OpenAI Realtime
API (`/v1/realtime`) and the Responses API WebSocket mode (`GET /v1/responses` upgraded, used by
Codex first) send one JSON event per WebSocket message; the server events of Responses mode are
the events of the Responses SSE stream.

## Goals / Non-Goals

Goals: the two OpenAI protocols work through scrim with the same guarantees as HTTP (two
independent checks per outgoing message, fail closed, restore under the same policy); any other
WebSocket on a provider route is at least redacted. Non-goals: restoring audio, restoring the
Gemini Live API, WebSocket over HTTP/2 (RFC 8441), `permessage-deflate`.

## Decisions

### W1. Terminate on both sides, never splice

scrim accepts the agent's WebSocket and opens its own to the provider, with its own key and no
extension, and relays decoded messages. Splicing frames would forward control and continuation
frames scrim has not checked; terminating means every frame the provider receives is built by scrim
from a message that passed the redactor and the guard. `permessage-deflate` is never negotiated on
either side, so no message is compressed past the redactor. Pings are answered locally (a ping
payload can carry 125 bytes of anything); a close frame keeps its code and loses its reason.

The library is `tokio-tungstenite` with `tungstenite` doing framing, masking, reassembly of
fragmented messages and the size bound (`max_message_size` and `max_frame_size` set to
`proxy.limits.max-request-body` toward the agent, `max-response-body` toward the provider). A frame
header announcing more than the bound is refused before its payload is read.

### W2. The agent gets 101 only after the provider

The handshake runs the HTTP head path (gate, route auth, `head::prepare_with`), then scrim
dials the provider over a separate HTTP/1.1-only client (ALPN `http/1.1`; the pooled client may
negotiate h2, where the upgrade does not exist) with the same roots, resolver and timeouts. Only on
`101` with a valid `Sec-WebSocket-Accept` and no extension does the agent get `101`; any other
answer is the agent's answer (a 401 stays a 401). A chained upstream is tried first, with the HTTP
`on-unavailable` behaviour.

### W3. One message is one request body

A client text message goes through `outgoing::prepare_planned`, the body path with a protocol
planner: Realtime keeps `type` and marks base64 audio and `data:` images as binary parts (binary
policy applies); Responses mode plans `response.create` as a create body (allowlist, encrypted
content, reasoning, binary parts); any other path plans nothing, so everything is redacted. A
binary message is redacted whole when it is UTF-8 and refused otherwise: no OpenAI protocol uses
binary frames, and bytes the redactor cannot read as text could hide anything. Large messages go
to the blocking pool at the HTTP offload threshold.

### W4. Refusal on an open connection

There is no HTTP status left to answer with, so a refusal is one `error` event in the shape both
OpenAI protocols use (it carries nothing from the refused message, not even `event_id`) and a close
frame with a code from RFC 6455: 1008 for every redaction, guard, binary and gate failure, 1009
over the size bound, 1013 not ready, 1014 provider failure, 1011 capture failure. The provider
connection is closed (1001). The refused message is never forwarded, in part or whole.

### W5. Snapshots follow the connection

A Realtime session can last an hour. Each message loads the current snapshot; when it is a
different one, the gate is asked again with the stored handshake (headers and extensions, so peer
credentials and session tokens still identify the caller), and its answer (policy, narrowed
redaction, or a denial that closes with `policy_denied`) applies from that message on. Comparing
by pointer, not version, keeps tests with equal versions honest; the data plane swaps one `Arc` per
bundle, so an unchanged snapshot never re-runs the gate.

### W6. Provider messages go through the SSE codecs

Each provider text message is wrapped as one SSE event (`data: <message>`; JSON line breaks are
whitespace and become spaces) and handed to the API's existing `StreamCodec`; the events it emits
are split back into messages. An unchanged message leaves byte for byte. The Responses codec is
reused as is, except that it now releases held text and forgets output indexes on
`response.created`: on a socket, a response that ended with an `error` event and no
`response.completed` would otherwise leave held bytes in front of the next response's text. The new
Realtime codec keys holdback by item id and content index (out-of-band responses interleave by
item, and output indexes restart per response), restores assistant text and transcripts as text
and function call arguments as tool input, and leaves the echo of the agent's own items alone.

### W7. Audit volume

A voice session appends audio many times a second. Each message is counted in metrics, but an
audit `Forwarded` entry is written for the handshake and then only for messages where something
happened: a replacement, a detector, a guard repair, or a binary media type not yet reported on
that connection. Refusals are always audited; restore counters are audited once at close.

## Risks / Trade-offs

- A relay task outlives graceful shutdown's connection tracking (an upgraded connection leaves
  hyper's watch); it ends when either side closes or the process exits.
- A guard re-run of the gate on a new snapshot can wait on an approval, stalling that connection's
  messages until it is answered.
- The model can say a placeholder in Realtime audio; audio is not restored.
- Capture records the handshake and client messages, not provider messages.
