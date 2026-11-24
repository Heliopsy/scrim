## MODIFIED Requirements

### Requirement: Fake provider

The suite SHALL include a fake provider, usable in process and as a standalone binary, that speaks
the Anthropic Messages, OpenAI Chat Completions and OpenAI Responses APIs, streaming and not, with
tool-call round trips, and the OpenAI Realtime API and Responses API WebSocket mode over WebSocket,
that records every byte of every request and every client WebSocket message, splits streamed text
and tool arguments into small deltas, and reports prompt-cache usage by byte-identical prefix
blocks.

#### Scenario: Placeholder split across events

- **WHEN** the fake provider streams a reply containing a placeholder
- **THEN** the placeholder arrives split across several delta events

#### Scenario: Changed prefix

- **WHEN** a request changes one byte in an early message of an otherwise repeated conversation
- **THEN** the fake provider reports only the blocks before that message as cached

#### Scenario: WebSocket message recorded

- **WHEN** a client sends a message on a Realtime WebSocket
- **THEN** the fake provider records it as its own exchange with the handshake's path, query and headers

## ADDED Requirements

### Requirement: WebSocket rows in the bypass matrix

The bypass matrix SHALL run its placements over the WebSocket APIs (`openai-realtime`,
`openai-responses-ws`) with the expectations of the matching HTTP rows, the secret-bearing message
first, and SHALL count a connection the proxy closed before forwarding any client message as
`withheld`. A seed in a forwarded handshake SHALL count as a leak. The rows gate a release like the
HTTP rows.

#### Scenario: Refused message

- **WHEN** the proxy closes the socket with code 1008 instead of forwarding the secret-bearing message
- **THEN** the row's outcome is `withheld`

#### Scenario: Pass-through proxy

- **WHEN** the matrix runs through a proxy that relays WebSocket messages unchanged
- **THEN** every WebSocket row that is not a short-seed truncation leaks
