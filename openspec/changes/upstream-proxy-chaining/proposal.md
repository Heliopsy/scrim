## Why

`scrim run` replaces an inherited `HTTPS_PROXY` with scrim's forward proxy and nothing chains to
the proxy the user had (docs/limitations.md). The data plane connects to providers and tool hosts
directly, so on a network that only lets traffic out through a corporate proxy every provider
request fails, and the control plane's clients follow `HTTPS_PROXY` only by accident of Go's
default transport, with no way to configure a proxy, its credentials or its exceptions.

## What Changes

- New settings `network.upstream-proxy.url`, `.no-proxy`, `.username` and `.password` (a secret
  reference). An empty URL takes `HTTPS_PROXY`/`https_proxy`/`HTTP_PROXY`/`http_proxy` and
  `NO_PROXY` from scrim's own environment; `direct` turns the proxy off. Loopback is always
  direct.
- The data plane tunnels every outbound connection (provider routes, chained upstreams, tool
  hosts, transparent pass-through) through the proxy with HTTP `CONNECT`, after redaction and the
  guard, with TLS to the destination inside the tunnel and verified against the destination's
  name. The proxy reaches the data plane in the snapshot (`Snapshot.upstream_proxy`, a new field;
  the password is a new secret field with a redacting `Debug` and wipes on both sides).
- The control plane's HTTP clients (stores, notifiers, audit sinks, identity and token endpoints)
  use the same proxy and the same `NO_PROXY` matching.
- The proxy password, from the setting or from the user info of an environment proxy URL, is one
  of scrim's own credentials: redacted from provider traffic, never logged.
- `scrim run` keeps pointing the agent at scrim's forward proxy and no longer drops the inherited
  proxy: a scrim it starts takes it as its upstream; when the running scrim uses a different
  upstream (or none), `scrim run` says so before the agent starts. The agent never receives the
  corporate proxy's credentials.
- Daemon info and the agent API's endpoints report the upstream proxy without credentials.

## Impact

- Specs: interception (new requirements), secret-stores ("Scrim's own credentials are never
  exposed").
- Code: new crate `dataplane/crates/scrim-upstream-proxy`; `scrim-llm` and `scrim-toolproxy`
  clients; `scrim-dataplane` snapshot apply; `proto/scrim/dataplane/v1`; new Go package
  `internal/netproxy`; `internal/app`, `internal/daemon`, `internal/run`.
- Compatible boundary change: an older data plane ignores the field and connects directly, as
  before; an older control plane sends none.
- Docs: configuration, run, interception, limitations.
