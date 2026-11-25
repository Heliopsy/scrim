## Context

Every value in the redaction set crosses the boundary in the snapshot. Before this change scrim
wiped its own copies (the snapshot message on the control plane, the decoded messages on the data
plane) but not the copies gRPC made on the way.

## Decisions

### Control plane (grpc-go)

- A `CodecV2` named `proto` marshals with `MarshalAppend` into a buffer sized by `proto.Size` and
  at least gRPC's pooling threshold, so gRPC releases it to the pool, which zeroes it. A message
  that outgrows the buffer (it changed between size and marshal) is refused.
- Unmarshal zeroes every received buffer after decoding. Frames below the pooling threshold are
  plain slices gRPC never releases, so the pool alone would miss them.
- `experimental.WithBufferPool` sets a pool that allocates fresh buffers and zeroes each one it
  gets back over its whole capacity.
- `WithReadBufferSize(0)` and `WithWriteBufferSize(0)`: grpc-go 1.85 then reads DATA payloads from
  the socket straight into pool buffers and writes the codec's buffers straight to the socket.
  Without them the bufio buffers hold whole frames. The boundary carries few messages, so the
  extra system calls do not matter.
- `TestBoundaryLeavesNoCopyInTransportBuffers` records every slice the transport reads into or
  writes from, and every pool buffer, and checks none holds part of the values after the calls.
  It fails with either buffer size option removed.

### Data plane (tonic, h2)

- `WipingCodec` (via `codec_path` in protogen) decodes from `DecodeBuf::copy_to_bytes`, which is
  `BytesMut::split_to` of tonic's receive buffer, and zeroes that range when dropped. Its encoder
  reserves the message's length before writing, and a yield threshold of one byte makes tonic hand
  each message to h2 alone, so the encode buffer never grows with a message in it.
- `WipeBodies` wraps the service. Request DATA payloads (split out of h2's read buffer) are wrapped
  in a `Bytes` whose owner zeroes the range after tonic copies it. The wrapper passes each gRPC
  message header to tonic on its own, so tonic reserves the message's length while its buffer holds
  none of the message. Response chunks (split out of tonic's encode buffer) are zeroed once h2 has
  written and dropped them.
- `Bytes` only hands out shared slices, so zeroing needs one `unsafe` write, in `wipe.rs`, under
  the condition that the `Bytes` is the only handle to a heap range split out of a `BytesMut`.
- The connection forwards vectored writes so h2 copies only DATA frames under 256 bytes into its
  write buffer.

### Not covered

h2's read buffer when it is reallocated with part of a frame in it, h2's write buffer for small
DATA frames, tokio's stdin and stdout buffers under `--stdio`, kernel buffers, and plugin
connections. A zeroing global allocator would cover the data plane's copies, but it would also
zero every free on the request path, which the latency budget does not have room for.

### Credentials as strings

Go strings cannot be wiped. The aim is fewer and shorter-lived copies: per-CONNECT proxy headers,
no HPACK indexing (Go's HTTP/2 client never marks a header sensitive, so a token stayed in the
encoder's table for the connection's life), AWS static keys without `aws.CredentialsCache`. What
libraries keep on their own is listed in docs/limitations.md.
