## Why

Client certificates were checked against CRL files only, and only the end entity
(docs/limitations.md, "Client certificates are checked against CRL files only"). A CA that publishes
revocation through OCSP, or revokes an intermediate, had no way to stop a certificate before it
expired. The Helm chart also left out the TLS tool proxy listener, so tools pointed at the tool proxy
directly could not use a client certificate in a cluster.

## What Changes

- New: `identity.client-certificates.ocsp.enabled` (off by default). The control plane asks the
  responder named in each certificate's authority information access, or
  `identity.client-certificates.ocsp.responder`, through `network.upstream-proxy`. A response must be
  signed by the issuer or a responder it delegated to (OCSP signing usage) and be current. Answers are
  kept until their next update in a cache bounded by `ocsp.cache-size`; concurrent checks of one
  certificate share one request. Stapling is not used.
- New: `identity.client-certificates.ocsp.unreachable`: `fail-closed` (default) refuses a certificate
  when no valid answer can be had (`ocsp unavailable`), `soft-fail` accepts it. Revoked and unknown
  answers always refuse. `ocsp.timeout` bounds each request (at most 10s).
- New: `identity.client-certificates.revocation-scope`: `end-entity` (default) or `chain`, which
  checks every certificate below the trust anchor against CRLs and OCSP.
- A current CRL that does not list a certificate counts as an answer: with OCSP on, a certificate is
  accepted when a CRL or an OCSP answer covers it and neither revokes it.
- Where the check runs: the data plane still terminates TLS and checks CRLs in the handshake. With
  OCSP on it accepts certificates whose issuer has no CRL in the handshake, then sends every accepted
  chain to the control plane over a new `CertificateChecks` stream and serves the connection only
  once the control plane accepts it. The control plane applies CRLs and OCSP together, as it already
  does on asks and the edge listener. OCSP status is per certificate and unknown until a certificate
  connects, so it cannot be pushed in the snapshot the way CRLs are.
- Chart: `identity.clientCertificates.toolProxyPort` (9798, 0 for off) serves `tool-proxy.tls-listen`
  on the `<fullname>-mtls` Service with its NetworkPolicy; `revocationScope` and `ocsp.*` values map to
  the new settings, with `networkPolicy.ocspEgress` for the responders.

## Impact

- Affected specs: agent-identity, deployment.
- Affected code: proto/scrim/dataplane/v1 (`ClientCertificateTrust.revocation_chain`, `ocsp`, the
  `CertificateChecks` call), internal/identity, internal/agentapi, internal/daemon, internal/dataplane,
  internal/testing/certtest, dataplane/crates/scrim-dataplane (mtls, certchecks), scrim-proto,
  deploy/helm/scrim.
- Defaults are unchanged: OCSP off and end-entity scope behave as before. Adding a call is compatible:
  a data plane older than it answers UNIMPLEMENTED, which the control plane logs; the planes ship
  together in one binary.
