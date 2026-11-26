## 1. Spec and boundary

- [x] 1.1 OpenSpec change (agent-identity, deployment)
- [x] 1.2 Proto: `ClientCertificateTrust.revocation_chain`, `ocsp`, `CertificateChecks` call

## 2. Control plane

- [x] 2.1 Settings `revocation-scope`, `ocsp.enabled`, `ocsp.responder`, `ocsp.unreachable`, `ocsp.timeout`,
  `ocsp.cache-size`
- [x] 2.2 OCSP checker: request through the upstream proxy, response verification (issuer or delegated
  responder, serial, freshness), bounded cache until next update, shared in-flight requests
- [x] 2.3 CRLs and OCSP combined per certificate, chain scope, for asks, the edge listener and data plane
  checks
- [x] 2.4 Supervisor answers `CertificateChecks`; snapshot carries the new fields

## 3. Data plane

- [x] 3.1 Handshake: chain-scope CRLs, unknown CRL status allowed while OCSP is on
- [x] 3.2 Certificate check broker; a connection is served only after the control plane accepts it;
  refusals reported like handshake refusals

## 4. Chart

- [x] 4.1 `toolProxyPort` on the container, the mtls Service and the NetworkPolicy
- [x] 4.2 `revocationScope`, `ocsp.*` values, `networkPolicy.ocspEgress`, schema, goldens, tests

## 5. Tests and docs

- [x] 5.1 Go unit tests with a local OCSP responder (good, revoked, unknown, unreachable, delegated,
  stale, cache, chain scope), Rust integration tests, an end-to-end test with the real data plane
- [x] 5.2 docs/identity.md, docs/kubernetes.md, docs/limitations.md, generated configuration docs
