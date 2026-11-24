## 1. Boundary

- [x] 1.1 `Snapshot.upstream_proxy` (`UpstreamProxy`: url, no_proxy, username, password); redacting
  `Debug` and zero on drop in `scrim-proto`; wipes in `internal/dataplane` and `internal/daemon`
- [x] 1.2 Regenerate Go and Rust code (`just proto`)

## 2. Data plane

- [x] 2.1 Crate `scrim-upstream-proxy`: `UpstreamProxy`, `NoProxy`, `ProxyHandle`, `connect`
  (CONNECT, Basic credentials, http and https proxies), `ProxyConnector`, test proxy
- [x] 2.2 LLM proxy and tool proxy clients through `ProxyConnector`; transparent pass-through
  through `connect`
- [x] 2.3 Snapshot apply parses the proxy and swaps the handle; an unusable proxy rejects the
  snapshot
- [x] 2.4 Tests: tunnel with and without credentials, 407, https proxy, intercepting proxy refused,
  connector bypass; e2e through the real binary (provider, tool host, NO_PROXY, refused password,
  bad URL)

## 3. Control plane

- [x] 3.1 `internal/netproxy`: settings, resolution from configuration and environment,
  `Func` on `http.DefaultTransport`, `Install`, snapshot message
- [x] 3.2 App installs the proxy at start and on reload; snapshot builder sends it
- [x] 3.3 Environment proxy password in the scrim-config redaction source
- [x] 3.4 Daemon info and agent API endpoints report the upstream proxy
- [x] 3.5 Tests: resolution, validation, shared NO_PROXY vectors, Go clients through a CONNECT
  proxy (with and without credentials, NO_PROXY, intercepting proxy), leak test through the chain
  with the real data plane

## 4. scrim run

- [x] 4.1 Inherited proxy becomes the upstream of a scrim `scrim run` starts; warning when the
  running scrim's upstream differs; credentials never shown
- [x] 4.2 Tests

## 5. Docs

- [x] 5.1 configuration.md (upstream proxy, corporate proxies), run.md, interception.md
- [x] 5.2 limitations.md entry reworded
