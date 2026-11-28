# scrim-dns

Upstream name resolution that never resolves to scrim itself. In DNS override mode
(`scrim install --system --dns`) provider names resolve to scrim's `SNI` listener through
`/etc/hosts` or a local resolver, so the system resolver would hand scrim its own address when it
connects to the real provider. `scrim-dataplane` registers each `SNI` listener's address
(`add_self_address`); `scrim-llm` resolves provider upstreams with `LoopSafeResolver` and
`scrim-toolproxy` resolves tool hosts with `resolve`. When the system answer contains one of
scrim's addresses, the crate queries the upstream name servers from
`/run/systemd/resolve/resolv.conf` or `/etc/resolv.conf` directly over UDP (A and AAAA, skipping
loopback stubs that may answer from `/etc/hosts`) and drops scrim's own addresses. A name that
only resolves to scrim is an error, never a connection back to scrim.

Docs: [interception, DNS override](../../../docs/interception.md#4-dns-override).

## Public API

- `add_self_address(ip)`, `is_self(ip)`: the process-wide set of scrim's own listener addresses.
  An unspecified address stands for every loopback address of its family.
- `resolve(host)`: system resolver first, direct queries when the answer points at scrim.
- `LoopSafeResolver`: the same as a resolver for hyper's `HttpConnector`.
- `parse_resolv_conf`, `encode_query`, `parse_answer`, `Answer`: the minimal DNS client, public
  for tests.

## Tests

```sh
cd dataplane
cargo test -p scrim-dns
```

Unit tests cover answer parsing (A and AAAA, CNAME records skipped, wrong ids, truncation, garbage), query
encoding, resolv.conf parsing, the self-address set, and a direct query against a fake name
server on loopback.
