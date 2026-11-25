## ADDED Requirements

### Requirement: Boundary transport copies are zeroed

The control plane and the data plane SHALL zero the buffers their gRPC connection encodes a
message into, receives DATA frames into and decodes a message from, once each is used. The copies
the libraries make that scrim cannot reach SHALL be listed in docs/limitations.md.

#### Scenario: Snapshot and redact calls leave no copy in the client's transport

- **WHEN** the control plane sends a snapshot and redact calls holding generated values, larger
  and smaller than one HTTP/2 frame, and the calls return
- **THEN** no buffer its transport read into or wrote from, and none its buffer pool handed out,
  holds any part of the values

#### Scenario: Data plane frames are zeroed once consumed

- **WHEN** the data plane receives a request body in DATA frames and sends a response
- **THEN** each received payload is zeroed once tonic has copied it, each gRPC message header
  reaches tonic apart from its body, and each sent chunk is zeroed once h2 has dropped it

### Requirement: Credentials handed to libraries are built per use

Where an HTTP client or SDK takes a credential as a string, scrim SHALL build that string from
its secret type for one request, tunnel or signature, and SHALL NOT keep it in a proxy URL, a
header map, a credentials cache or an HTTP/2 header table of its own clients.

#### Scenario: Proxy password per CONNECT

- **WHEN** the control plane opens a tunnel to an https destination through an upstream proxy with
  a password
- **THEN** the proxy URL it uses has no user info and the CONNECT carries `Proxy-Authorization`
  built from the current password

#### Scenario: Bearer token not indexed over HTTP/2

- **WHEN** a store client sends the same bearer token on two requests over one HTTP/2 connection
- **THEN** the token is sent as a literal both times, so it is not in the connection's header table

#### Scenario: AWS static keys are not cached

- **WHEN** an AWS store is configured with a static access key
- **THEN** the SDK gets a credentials provider that builds the key strings for each signature and
  returns nothing once the key is wiped
