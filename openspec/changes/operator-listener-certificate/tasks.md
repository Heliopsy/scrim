## 1. Settings and control plane

- [x] 1.1 `identity.client-certificates.listener-cert-file` and `listener-key` settings
- [x] 1.2 `identity.ListenerCert` checks: chain, key match, not a CA, server authentication, validity
- [x] 1.3 `ListenerCertSource` reload every refresh, keep the one in force on failure, wipe a replaced key
- [x] 1.4 Snapshot fields, `checkSnapshotTLS` pairing, wipe after send

## 2. Data plane

- [x] 2.1 Redacting `Debug` and zeroing `Drop` for `ClientCertificateTrust`
- [x] 2.2 Serve the operator's certificate on every TLS listener handshake; refuse a mismatched key

## 3. Chart

- [x] 3.1 `identity.clientCertificates.listenerCertificate.existingSecret`, mount, settings, refusal

## 4. Tests and docs

- [x] 4.1 Go unit tests, Rust integration tests, an end-to-end test with the real data plane and a
  renewal in place
- [x] 4.2 docs/identity.md, generated configuration docs, limitations.md
