# scrim-upstream-proxy

Outbound connections of the data plane through an upstream HTTP `CONNECT` proxy, for networks that
only let traffic out through one (interception spec, "Outbound connections through an upstream
proxy"). The control plane sends the proxy in `Snapshot.upstream_proxy` (settings
`network.upstream-proxy.*`); `scrim-dataplane` puts it in a `ProxyHandle` on every snapshot, and
the connectors of `scrim-llm` (provider routes and chained upstreams) and `scrim-toolproxy` (tool
hosts and transparent pass-through) read the handle on each new connection. Every proxied
connection is a tunnel to the destination's `host:port`; TLS to the destination runs inside it and
is verified against the destination's name, so the proxy sees the `CONNECT` line and ciphertext
only. Redaction and the guard have already run before a request reaches a connection, so nothing
here sees request bytes.

Docs: [configuration, upstream proxy](../../../docs/configuration.md#upstream-proxy),
[limitations](../../../docs/limitations.md) (connections that do not use it).

## Public API

- `UpstreamProxy::new(url, no_proxy, username, password)`: an `http://` or `https://` proxy, its
  `NO_PROXY` list and optional Basic credentials (`ConfigError` when unusable). The password is
  held as the ready `Proxy-Authorization` value in a buffer zeroed on drop and never appears in
  `Debug`, an error or a log line.
- `ProxyHandle`: the proxy in force, swapped atomically (`set`, `current`, `route(host, port)`),
  so a reload that changes the proxy or rotates its password applies to the next connection.
- `ProxyConnector<C>`: wraps a hyper connector; destinations in `NO_PROXY` (`NoProxy`) go to the
  wrapped connector, the rest through the tunnel.
- `connect(...)`: opens one tunnel and returns the `Stream`, or a `TunnelError`.
- `testing::TestProxy` (feature `test-util`, never in a release build): a recording `CONNECT`
  proxy for tests.

## Tests

```sh
cd dataplane
cargo test -p scrim-upstream-proxy
```

`tests/tunnel.rs` runs tunnels through the test proxy with and without credentials, plain and TLS
proxies, `NO_PROXY` bypass through the connector, and TLS to the destination verified inside the
tunnel (a proxy presenting its own certificate is refused). `scrim-dataplane`'s `tests/e2e.rs`
covers the whole data plane behind a proxy.
