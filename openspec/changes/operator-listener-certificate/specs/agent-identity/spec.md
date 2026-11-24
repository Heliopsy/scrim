## ADDED Requirements

### Requirement: Operator certificate for the TLS listeners

When the operator configures a certificate and key for the TLS listeners of client certificate
identity, the system SHALL present that certificate instead of one issued by its interception CA,
SHALL refuse to start with a key that does not match it or a certificate that cannot serve TLS now,
and SHALL present a renewed pair on new connections without a restart.

#### Scenario: Agent that trusts only the organisation's PKI

- **WHEN** an agent that trusts the operator's CA and not scrim's connects to the TLS base URL
- **THEN** the handshake succeeds with the operator's certificate

#### Scenario: Renewal written halfway

- **WHEN** the certificate file is replaced but the key file still holds the old key
- **THEN** the certificate in force is kept and the mismatch is logged, and once the key is replaced
  too, new connections get the renewed certificate
