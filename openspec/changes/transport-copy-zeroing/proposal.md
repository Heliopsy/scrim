## Why

docs/limitations.md listed two gaps in how scrim keeps secret bytes in memory. The gRPC transport
between the control plane and the data plane returned its encode, frame and decode buffers to the
allocator with the snapshot's values still in them. Credentials that libraries take as strings
(the upstream proxy password, store and notifier tokens, AWS keys) lived as strings for the life of
a connection, a credentials cache or an HTTP/2 header table.

## What Changes

- The control plane's boundary client marshals into buffers zeroed when gRPC releases them, reads
  DATA frames into a pool that zeroes what it gets back, zeroes received bytes after decoding, and
  runs without bufio read and write buffers.
- The data plane's generated server uses a codec that zeroes the range it decodes from and hands
  each encoded message to h2 on its own, and its service is wrapped so h2 DATA payloads are zeroed
  once tonic has copied them and once h2 has written them.
- The upstream proxy password reaches CONNECT through a per-tunnel `Proxy-Authorization` header
  instead of the proxy URL. The control plane's HTTP/2 clients no longer index headers. The OTLP
  audit sink sets its token per request and now uses the upstream proxy.
- AWS static keys are handed to the SDK without its credentials cache. GCP static tokens are read
  per call. Vaultwarden login tokens are decoded as bytes and wiped.
- docs/limitations.md lists exactly which copies remain.

## Impact

- Affected specs: secret-stores (Boundary transport copies are zeroed, Credentials handed to
  libraries are built per use; added).
- Affected code: internal/dataplane, dataplane/crates/scrim-proto (wipe module, generated code),
  dataplane/crates/scrim-dataplane/src/server.rs, dataplane/tools/protogen, internal/netproxy,
  internal/audit/sinks, internal/stores/{aws,gcpsm,vaultwarden}, docs/limitations.md,
  docs/plugins.md.
