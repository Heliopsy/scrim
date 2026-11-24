## ADDED Requirements

### Requirement: WebSocket message budget

The latency scrim adds to one WebSocket message (redaction and guard of a client message, restore
of a provider message, and the relay between the two sockets) SHALL stay below a configured p99
target in the latency gate, initially 1 ms for a 4 KB client event, measured as the round trip
through the proxy minus the round trip to the same fake provider directly.

#### Scenario: Message budget met

- **WHEN** the latency gate sends 4 KB Realtime events through the proxy to a fake WebSocket provider that answers each with one event
- **THEN** the p99 latency added per message is below the configured target
