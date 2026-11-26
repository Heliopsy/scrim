## ADDED Requirements

### Requirement: OCSP checking of client certificates

When OCSP checking is on, the system SHALL ask the responder of each client certificate, from its
authority information access or a configured URL, before serving its connection, SHALL accept only
current responses signed by the issuer or a responder it delegated to, SHALL keep answers until their
next update in a bounded cache, and SHALL refuse a certificate the responder reports revoked or
unknown unless a current CRL covers the unknown one.

#### Scenario: Revoked by the responder

- **WHEN** the responder reports a client certificate revoked
- **THEN** its connection is closed before any request is served, and the refusal is audited as
  `revoked`

#### Scenario: Answer reused

- **WHEN** the same certificate connects again before the answer's next update
- **THEN** the responder is not asked again

#### Scenario: Forged response

- **WHEN** a response is signed by a responder certificate the issuer did not issue for OCSP signing
- **THEN** it counts as no answer

### Requirement: Unreachable OCSP responder

When OCSP checking is on and no valid answer can be had for a certificate that no current CRL
covers, the system SHALL refuse it as `ocsp unavailable` by default, and SHALL accept it only when
the operator chose soft-fail.

#### Scenario: Responder down, fail closed

- **WHEN** the responder cannot be reached and soft-fail is not set
- **THEN** the certificate is refused as `ocsp unavailable`

#### Scenario: Responder down, soft-fail

- **WHEN** the responder cannot be reached and soft-fail is set
- **THEN** the certificate is accepted and a warning is logged

### Requirement: Revocation scope

The system SHALL check only the end entity for revocation by default and, when the operator chooses
the chain scope, SHALL check every certificate below the trust anchor against CRLs and OCSP, so a
revoked intermediate refuses every certificate it issued.

#### Scenario: Revoked intermediate

- **WHEN** the chain scope is set and the root's CRL or responder reports the intermediate revoked
- **THEN** a client certificate issued by that intermediate is refused as `revoked`
