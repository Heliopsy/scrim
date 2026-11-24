## Why

The agent-identity spec describes client certificates, SPIFFE identities included, as an agent
identity source, but scrim 1.0 does not implement them (docs/limitations.md, "Client certificates
are not an agent identity in 1.0"). Workloads that already hold an X.509 identity (SPIFFE SVIDs,
an internal PKI for CI runners, agents on other machines) have no way to identify themselves to
scrim over TCP other than bearer tokens, which any process that reads them can replay.

## What Changes

- New TLS listeners for the data plane: the LLM proxy base URL (`proxy.tls-listen`), the forward
  proxy (`proxy.forward-tls-listen`) and the tool proxy (`tool-proxy.tls-listen`). Each requires a
  client certificate, verified in the handshake against configured trust anchors and CRLs; the
  verified chain travels with every request on the connection.
- The edge listener accepts a client certificate instead of a Kubernetes service account token,
  and the edge forwarder can present one (`edge-forwarder.client-cert-file`, `-key-file`).
- New settings `identity.client-certificates.*`: trust anchors as a reference (`file:`, `env:`,
  `cred:` or a store reference), CRL files re-read periodically, rules that map SPIFFE ID, subject
  CN, DNS, URI or email SANs to agents, `unmapped` (`unknown` by default, `derive` from the SPIFFE
  ID), and the server names of the listeners' certificate.
- The control plane verifies the chain again (trust anchors, validity, client-auth usage, CRL) on
  every ask, maps it, and the identity (kind `mtls`, principal `mtls:<agent>`) flows into policy,
  grants, approvals, store identity and audit like peer, session and Kubernetes identities.
- Refused certificates are audited: handshake refusals as `dataplane.client_certificate_refused`
  with the reason, ask-time refusals as decisions with `caller=refused`, unmapped certificates as
  `caller=unmapped`.
- Revocation is by CRL files or short-lived certificates. OCSP is not supported.
- docs/identity.md documents it; docs/limitations.md loses the entry this closes.

## Impact

- Specs: `agent-identity` (Optional mutual TLS identity, Data-plane identity from the transport,
  new requirements for mapping, revocation and the listeners).
- Code: `internal/identity` (certificate resolver and trust), `internal/agentapi` (settings),
  `internal/gate` (ask callers), `internal/daemon` (listeners, snapshot, reload), `internal/edge`,
  `internal/identity/issuer` (subject `mtls:<agent>`), the boundary proto, and the data plane
  listeners and identity (`scrim-dataplane`, `scrim-toolproxy`, `scrim-llm`).
- No change for deployments that do not enable it: the plain listeners and their identities are
  unchanged.
