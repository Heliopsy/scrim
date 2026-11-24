## MODIFIED Requirements

### Requirement: Edge channel identifies the pod

The edge channel SHALL be TLS 1.3 to a listener whose certificate chains to the edge CA, verified
against that CA only: never the interception CA and never the system roots. Every connection and
agent API request SHALL carry the pod's projected service account token, read from its file each
time; the central instance SHALL verify it with TokenReview, accept nothing else, and treat the
verified agent as the caller for policy, approvals, grants and audit exactly as on the proxy.

#### Scenario: Signature policy per pod

- **WHEN** a pod's signature request is for a login no rule allows for its service account
- **THEN** the central instance refuses the signature, the push fails and the refusal is audited as
  that pod's agent

#### Scenario: Token refused

- **WHEN** the forwarder presents a token the cluster does not accept, a session token, or the token
  of a service account no rule maps
- **THEN** the central instance refuses the connection, audits the refusal without the token, and
  nothing is forwarded to a key, database or command

#### Scenario: Another certificate

- **WHEN** the edge listener's address answers with a certificate the edge CA did not sign, or one
  for another name
- **THEN** the forwarder does not send the token and refuses the local connection

#### Scenario: Certificate from the interception CA

- **WHEN** the edge listener's address answers with a certificate the interception CA signed
- **THEN** the forwarder does not send the token and refuses the local connection

## ADDED Requirements

### Requirement: Edge certificate authority

The edge listener's certificate SHALL be issued by an edge CA with its own key pair that issues
nothing else. scrim SHALL either generate it, rotating it with an overlap like the interception CA
and constraining it to the edge listener's names, to server certificates and to no further CA; or
use an operator-supplied edge CA by reference, never rotate it, and check that it can issue a
certificate for the edge listener's names.

#### Scenario: Generated edge CA

- **WHEN** scrim starts with the edge listener on and no edge CA configured
- **THEN** it generates an edge CA in its own directory whose name constraints permit only the
  configured edge names, and a certificate it issues for any other host or address does not verify

#### Scenario: Edge names change

- **WHEN** scrim starts with edge names the generated edge CA is not constrained to
- **THEN** it rotates the edge CA, keeping the previous one in the exported bundle until the overlap
  ends

#### Scenario: Operator edge CA that cannot issue for the names

- **WHEN** the operator-supplied edge CA's name constraints do not permit an edge name
- **THEN** scrim refuses to start and names the setting

### Requirement: Edge CA never shares the interception CA's key

scrim SHALL refuse to start when the edge CA has the interception CA's key or would be kept in the
interception CA's directory.

#### Scenario: Shared key refused

- **WHEN** the configured edge CA has the interception CA's key, or its directory is the
  interception CA's
- **THEN** scrim refuses to start and names the setting

### Requirement: Edge upgrade window

A weakening setting, off by default, SHALL let the edge listener serve a forwarder that does not
announce the edge CA a certificate from the interception CA, so pods started before the edge CA
keep working until they restart. scrim SHALL log a warning while it is on, and a forwarder that
announces the edge CA SHALL always get the edge CA's certificate.

#### Scenario: Upgrade window

- **WHEN** the upgrade-window setting is on and a forwarder from before the edge CA, which trusts
  the interception CA and does not announce the edge CA, connects
- **THEN** it gets a certificate from the interception CA, while a current forwarder still gets the
  edge CA's certificate and refuses the interception CA's

#### Scenario: Window closed

- **WHEN** the setting is off and a forwarder from before the edge CA connects
- **THEN** its handshake fails and it refuses every local connection
