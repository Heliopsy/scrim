## Context

Two planes make outbound connections. The Rust data plane has two hyper clients (LLM proxy, tool
proxy) plus raw TCP relays for transparent pass-through; the Go control plane has a dozen HTTP
clients, most cloned from `http.DefaultTransport`.

## Decisions

### One proxy, CONNECT for everything

Every proxied connection is an HTTP `CONNECT` tunnel to `host:port`, plain HTTP destinations
included. TLS to the destination runs inside the tunnel, set up exactly as on a direct
connection, so certificate verification against the destination's name is unchanged and the
proxy sees only the `CONNECT` line and ciphertext. Absolute-form proxying of plain HTTP would
need the proxy credential on every request and hand the proxy request bytes; nothing scrim talks
to needs it. One proxy URL serves all schemes: when the environment sets both, `HTTPS_PROXY`
wins.

Redaction and the guard run before a request reaches either client, so the order "redactor, guard,
upstream" is untouched: the proxy is below the client, not a new hop above it.

### Connector, not middleware

`scrim-upstream-proxy::ProxyConnector` wraps the existing `HttpConnector` (with scrim's
loop-safe resolver) under hyper-rustls. A tunnelled destination is never resolved locally, which
is what proxy-only networks without outside DNS need. Transparent pass-through calls the same
`connect` function.

### Configuration travels in the snapshot

The proxy, its `NO_PROXY` list and the credential go in `Snapshot.upstream_proxy`, swapped into a
`ProxyHandle` shared by both clients on every apply. A reload that changes the proxy or rotates
the password applies to new connections without a data plane restart, and the password uses the
existing secret channel (redacting `Debug`, zero on drop, wiped after send) instead of the data
plane's environment. Pooled connections keep the route they were opened with until they close.

A proxy the data plane cannot use rejects the snapshot. Connecting directly instead would go
around the operator's proxy without anyone noticing.

### One NO_PROXY grammar on both planes

Go uses `golang.org/x/net/http/httpproxy`; the Rust matcher mirrors its rules (host and
subdomains, `.domain` for subdomains only, IPs, CIDR, optional port, `*`). Shared vectors
(`internal/netproxy/testdata/no_proxy_vectors.json`) run in both test suites. Loopback is implicit
in Go and is sent explicitly to the data plane. Entries outside the grammar are rejected in the
setting and skipped (with a warning) from the environment, so a Windows-style `<local>` cannot
make the data plane reject every snapshot.

### Control plane clients through `http.DefaultTransport`

`internal/netproxy` sets `http.DefaultTransport.Proxy` to its `Func` at init, before any request,
so every clone and every client that uses the default transport follows the proxy the daemon
installs; before a daemon installs one, `Func` is `ProxyFromEnvironment`, what CLI commands always
used. Kubernetes TokenReview keeps its own transport and stays direct: it talks to the in-cluster
API server with the kubelet's CA. TCP clients (PostgreSQL, Valkey, NATS) and plugins over Unix
sockets are not HTTP and are not proxied.

### scrim run

A scrim that `scrim run` starts runs in its process and reads the same environment, so the
inherited proxy becomes its upstream with no extra plumbing. A running scrim (user or system
service) was started elsewhere; `scrim run` compares the inherited proxy, without credentials,
with the upstream the daemon reports and warns on a difference, since the upstream is shared by
every session and one session cannot change it.

## Risks

- Go's transport takes proxy credentials from the proxy URL's user info, so the password is
  copied into strings per connection: covered by the existing limitation on credentials that HTTP
  clients take as strings.
- Corporate TLS-inspecting proxies that re-sign `CONNECT` tunnels need their CA in
  `dataplane.upstream-ca-file` (data plane) and the system trust store (control plane); without
  it, connections fail closed.
