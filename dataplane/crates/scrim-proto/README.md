# scrim-proto

Generated Rust types for the gRPC boundary between the Go control plane and the Rust data plane
(design D12), from [`proto/scrim/dataplane/v1/dataplane.proto`](../../../proto/scrim/dataplane/v1/dataplane.proto).
`scrim-dataplane` serves the `DataPlane` service with them; `scrim-policy` and `scrim-toolproxy`
read their parts of the snapshot (`Policy`, `RestoreSettings`, credentials and capture rules) from
these types directly. The Go side's generated code is in `internal/dataplane/dataplanev1`.

The generated code under `src/gen` is committed, so building the data plane needs no `protoc`.
Regenerate the Go and Rust code together with `just proto` (`dataplane/tools/protogen` writes the
Rust side); CI's `proto` job fails when the committed output is stale. Changing the protocol
follows the rules in [AGENTS.md](../../../AGENTS.md#boundary-protocol).

## Public API

- `v1::*`: every message, enum, the `DataPlane` client and server, and `v1::PROTOCOL` (the
  protocol version this build speaks).
- Secret fields: `ValueEntry`, `PlaceholderKey`, `CaCertificate`, `CaptureRequest`, `AskCaller`,
  `ClientCertificateTrust`, `RedactRequest` and `UpstreamProxy` have a hand-written `Debug` that
  prints `REDACTED` (`[scrim:redacted]`) and the length in place of secret bytes, and zero those
  bytes on drop (`src/secret_fields.rs`).
- `wipe::WipingCodec`: the codec of the generated client and server. It zeroes each received
  message's bytes once decoded and encodes each message into its own buffer.
- `wipe::WipeBodies`: wraps the service so HTTP/2 DATA frames are zeroed once tonic or h2 is done
  with them. What still escapes (parts of h2's buffers, tokio's stdio buffers under `--stdio`) is
  listed in [docs/limitations.md](../../../docs/limitations.md).

A new secret field needs an entry in `src/secret_fields.rs` here and a wipe in
`internal/dataplane` on the Go side.

## Tests

```sh
cd dataplane
cargo test -p scrim-proto
```

Unit tests check that `Debug` never prints secret bytes, that messages round-trip, and that the
codec and body wrappers zero what they decoded or sent.
