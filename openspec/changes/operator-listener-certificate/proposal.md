## Why

The TLS listeners of client certificate identity present a certificate issued by scrim's
interception CA, so every agent that connects to them has to trust that CA. Agents on other
machines or in CI usually trust the organisation's PKI only, and trusting the interception CA
lets its key vouch for any host those agents reach (docs/limitations.md listed "no setting for a
certificate and key of your own").

## What Changes

- New: `identity.client-certificates.listener-cert-file` (PEM chain) and
  `identity.client-certificates.listener-key` (secret reference). When set, the TLS base URL, forward
  proxy and tool proxy listeners present that certificate instead of one from scrim's CA, and
  `server-names` is not used.
- scrim refuses to start when only one is set, when client certificate identity is off, when the
  key does not match the certificate, or when the certificate is a CA, does not allow server
  authentication or is outside its validity period.
- Both are read again every `identity.client-certificates.refresh`; a renewed pair is presented on
  new connections, and a pair that fails the checks is logged and the one in force kept.
- Chart: `identity.clientCertificates.listenerCertificate.existingSecret`, a `kubernetes.io/tls`
  Secret mounted into central scrim; the chart refuses a CA's Secret there.
- The key travels to the data plane in the snapshot (`ClientCertificateTrust.listener_chain_pem`
  and `listener_key_pem`), redacted in `Debug`, zeroed on drop and wiped after sending, and joins
  scrim's own credentials in the redaction set.

## Impact

- Affected specs: agent-identity, deployment.
- Affected code: proto/scrim/dataplane/v1, internal/identity, internal/agentapi, internal/daemon,
  internal/dataplane, dataplane/crates/scrim-proto, dataplane/crates/scrim-dataplane (mtls),
  deploy/helm/scrim.
- Configurations without the new settings behave as before. A data plane from before this change
  ignores the new fields and keeps presenting a certificate from scrim's CA; the control plane and
  data plane ship together in one binary.
