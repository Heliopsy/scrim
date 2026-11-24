## Context

Callers reach the data plane over TCP on the base URL, forward proxy and tool proxy listeners, and
the control plane's agent API over TCP through the edge listener. On those, identity today is a
bearer credential: a session token or a Kubernetes service account token. A client certificate
proves possession of a private key that never leaves the client, which is what the spec's
"Optional mutual TLS identity" requirement asks for.

## Decisions

### C1. Separate TLS listeners, client certificate required

The plain listeners stay as they are. Client certificates come in on new listeners
(`proxy.tls-listen`, `proxy.forward-tls-listen`, `tool-proxy.tls-listen`) that accept TLS only and
refuse a handshake without a valid client certificate. One listener with optional client
certificates would make the identity of a request depend on what the client chose to send, and
turning TLS on for the existing listeners would break every agent configured for them.

The forward proxy over TLS is an HTTPS proxy (`HTTPS_PROXY=https://...`): the client authenticates
to the proxy itself, then sends CONNECT, and the tunnel's own TLS is intercepted as before. The
alternative, asking for a client certificate inside each intercepted handshake, would mix the
agent's identity certificate with the placeholder certificates of client-certificate credentials
and present it once per destination.

The listeners' own certificate is issued by scrim's CA (the interception CA agents already trust)
for `identity.client-certificates.server-names`.

### C2. Verified twice, mapped once

The data plane verifies the chain in the handshake with rustls' WebPKI client verifier against the
snapshot's trust anchors and CRLs: a certificate that is untrusted, expired, not for client
authentication or revoked never gets a connection, and the refusal is an event the control plane
audits (`dataplane.client_certificate_refused`). The handshake is also the only place possession of
the private key is proven; scrim never holds that key.

The verified chain (public) then travels with every request on the connection and in each ask
(`AskCaller.client_certificate_chain`). The control plane verifies it again with Go's x509 against
its own trust and CRLs before it maps the leaf, so a data plane bug cannot widen anything, and the
mapping (like every other identity mapping) lives in the control plane only. As with sessions, a
request with a certificate is an agent the data plane cannot place: a rule on the agent asks.

A request on a TLS listener has one identity, its certificate. An `x-scrim-session` header or proxy
credentials on such a connection are ignored (and still stripped).

### C3. Unmapped certificates are unknown by default

`identity.kubernetes.unmapped` defaults to `derive`, and docs/limitations.md lists that as a risk:
every pod that can mint a token for scrim's audience is an agent. A trust anchor for client
certificates is usually broader still (a SPIFFE trust domain, a company CA), so
`identity.client-certificates.unmapped` defaults to `unknown`: only certificates a rule maps are
agents. `derive` is available and names the agent after the SPIFFE ID without its scheme
(`example.org/agents/builder`); a certificate without a SPIFFE ID stays unknown, since a subject CN
has no structure scrim could trust as a name. The spec's SPIFFE scenario holds either way: the
SPIFFE ID is always `agent.labels.spiffe_id` and rules map on it.

### C4. Revocation: CRL files or short-lived certificates

- **CRL files** (`identity.client-certificates.crl-files`), re-read every
  `identity.client-certificates.refresh` (1 minute) and pushed to the data plane when they change.
  With any CRL configured, the end entity's issuer must have a current CRL signed by it: no CRL for
  the issuer, or one past its next update, refuses the certificate. That fails closed when the
  operator's CRL distribution stops. Only the end entity is checked (intermediates are expected to
  be under the operator's control and short-lived, and rustls and Go agree on this mode).
- **No CRL**: revocation is not checked, which is right for short-lived certificates (SPIFFE SVIDs
  live about an hour): a compromised certificate is useless once it expires.
- **No OCSP**: checking a responder during the handshake would put a network round trip, the
  responder's availability and a privacy leak (the responder learns which agent connected) on every
  new connection, and soft-fail OCSP is no check at all. Stapling would need the clients to staple,
  which client libraries do not do for client certificates.

### C5. Trust anchors as a reference, not a secret

The bundle is a reference (`file:`, `env:`, `cred:` or a store reference) resolved like a secret
reference but read as public data: it does not join the redaction set the way scrim's own
credentials do, since a CA certificate is public and redacting it would rewrite unrelated traffic.

### C6. Edge listener

The edge listener requests (but does not require) a client certificate and verifies it per request
with the same resolver, so a refusal is an audited 401 instead of a failed handshake. A certificate
wins over a bearer token. The forwarder reads its certificate and key files on every handshake, so
a rotated SVID is used at once; the key stays in the agent pod.

## Risks

- A trust anchor that issues to more workloads than intended, combined with `unmapped: derive`,
  makes each of them an agent. The default is `unknown`.
- A stale CRL refuses every certificate of its issuer until the file is replaced. That is the
  intended fail-closed direction; the reload warning and the audited refusals show it.
- The listeners' certificate comes from the interception CA, like the edge listener's (already a
  documented limitation).
