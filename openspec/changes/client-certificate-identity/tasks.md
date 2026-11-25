# Tasks

## 1. Spec and boundary

- [x] 1.1 Spec delta for agent-identity: mutual TLS identity, mapping, revocation, TLS listeners
- [x] 1.2 Proto: `Snapshot.client_certificates`, `Listener.tls`, `AskCaller.client_certificate_chain`, `EVENT_KIND_CLIENT_CERTIFICATE_REFUSED`

## 2. Control plane

- [x] 2.1 `identity.CertResolver`: chain verification (anchors, validity, client-auth usage), CRL check, rules, `unmapped`; verify: unit tests for mapped, unmapped, derive, untrusted, expired, not yet valid, server-only, revoked, stale CRL, CRL of another issuer, forged CRL
- [x] 2.2 Settings `identity.client-certificates.*`, trust source with periodic reload that pushes a snapshot on change
- [x] 2.3 Gate resolves `client_certificate_chain` asks and audits `caller=certificate`, `refused` or `unmapped` with `cert_sha256`; verify: gate test with two certificates and different decisions
- [x] 2.4 TLS listener settings and snapshot trust; refuse TLS listeners without client certificate identity
- [x] 2.5 Edge listener takes client certificates, the forwarder presents one from files; verify: edge test (mapped, untrusted, expired, revoked, unmapped, audited)
- [x] 2.6 Issuer subject `mtls:<agent>`

## 3. Data plane

- [x] 3.1 TLS listeners with a required client certificate, verified with the snapshot's anchors and CRLs; handshake refusals emitted as events with the reason
- [x] 3.2 The verified chain reaches every request on the connection (base URL, forward proxy, CONNECT tunnels, provider hosts handed to the LLM proxy) and the ask; it is the request's only identity

## 4. End to end and docs

- [x] 4.1 Daemon e2e with the real data plane: mapped certificate allowed and audited as its agent, policy per certificate, untrusted, expired, revoked and unmapped refused and audited, redaction applies with the leak check
- [x] 4.2 docs/identity.md, docs/limitations.md

## 5. Follow-ups (not in this change)

- [x] 5.1 Optional operator-supplied certificate and key for the TLS listeners (needs a secret field in the snapshot)
- [x] 5.2 Helm chart values for `identity.client-certificates.*` and the TLS listener settings
