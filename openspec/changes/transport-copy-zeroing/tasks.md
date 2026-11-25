## 1. Boundary

- [x] 1.1 Control plane: zeroing codec, buffer pool, no bufio buffers; test over a recording connection
- [x] 1.2 Data plane: zeroing codec through protogen `codec_path`; request and response body wrapper
- [x] 1.3 Round trip through the real data plane with messages spanning several frames

## 2. Credentials as strings

- [x] 2.1 Upstream proxy password per CONNECT; no HTTP/2 header indexing; OTLP token per request
- [x] 2.2 AWS static keys without the SDK's credentials cache; GCP static token per call; Vaultwarden tokens as bytes

## 3. Docs

- [x] 3.1 docs/limitations.md and docs/plugins.md list what remains
