## MODIFIED Requirements

### Requirement: Optional mutual TLS identity

The system SHALL accept client certificates, including SPIFFE identities, as an agent identity source
when configured (`identity.client-certificates`), on TLS listeners of the LLM proxy, the forward
proxy, the tool proxy and the edge listener, and SHALL never hold the client's private key. A request
on such a connection SHALL have the certificate as its only identity, with kind `mtls` and principal
`mtls:<agent>`.

#### Scenario: SPIFFE identity

- **WHEN** a workload presents a valid certificate for `spiffe://example.org/agents/builder` and a
  rule maps `spiffe:spiffe://example.org/agents/builder` to the agent `builder`
- **THEN** it is identified as `builder`, with `agent.kind == "mtls"` and
  `agent.labels.spiffe_id == "spiffe://example.org/agents/builder"`

#### Scenario: Two certificates, two outcomes

- **WHEN** a rule denies `llm.forward` for `agent.id == "reviewer"` and the agents `builder` and
  `reviewer` send the same provider request with their certificates
- **THEN** the request from `builder` is redacted and forwarded, the one from `reviewer` is refused,
  and each decision's audit entry names the caller as `certificate` with its agent

#### Scenario: Token on a certificate connection

- **WHEN** a request on a TLS listener also carries `x-scrim-session` with another agent's token
- **THEN** it is identified by its certificate and the header is not forwarded

### Requirement: Data-plane identity from the transport

The data plane SHALL take a request's caller only from its transport: Unix socket peer credentials,
`Proxy-Authorization: Basic` on the forward proxy, `x-scrim-session` on a base-URL listener (neither
header forwarded), or a client certificate verified on a TLS listener. A request with none SHALL be
an unknown caller. A rule on the agent of a request that carries one SHALL be decided by the control
plane, with what the transport said in the ask.

#### Scenario: Session header carries a token

- **WHEN** a request carries a session token or a service account token in `x-scrim-session` or
  `Proxy-Authorization`
- **THEN** the caller is taken from that token and the header is not forwarded

#### Scenario: Request without a session

- **WHEN** a request through the forward proxy names no session and a rule denies unknown callers
- **THEN** the data plane refuses it without asking the control plane

#### Scenario: Request naming a session

- **WHEN** a provider request carries `x-scrim-session` and a rule on `agent.session` could deny it
- **THEN** the data plane asks the control plane with the session id, and the provider never sees the header

#### Scenario: Request with a client certificate

- **WHEN** a provider request arrives on a TLS listener and a rule on `agent.id` could deny it
- **THEN** the data plane asks the control plane with the certificate chain, and the control plane
  maps it to the agent

## ADDED Requirements

### Requirement: Client certificate verification

The system SHALL refuse a client certificate that does not chain to a configured trust anchor, is
outside its validity period, is not for client authentication or is revoked, and SHALL audit every
refusal with its reason. The data plane SHALL verify the certificate in the TLS handshake, and the
control plane SHALL verify the chain again against its own trust anchors and revocation lists before
it maps it.

#### Scenario: Untrusted, expired or revoked certificate

- **WHEN** a client presents a certificate from another CA, an expired certificate or one a
  configured CRL revokes
- **THEN** the TLS handshake fails, nothing is forwarded, and an audit entry records the refusal
  with its reason

#### Scenario: Unusable trust is refused before the data plane

- **WHEN** the trust anchors do not parse, a CRL does not parse, no listener names are configured,
  or a listener kind that does not serve HTTP to agents has TLS set
- **THEN** the control plane refuses to build the snapshot with an error naming the setting, and
  the data plane keeps the snapshot in force

### Requirement: Client certificates map to agents

The system SHALL map a verified client certificate to an agent through configured rules on its
SPIFFE ID, subject common name, DNS, URI or email SANs (globs allowed), with optional scopes and
labels. A certificate no rule maps SHALL be an unknown caller unless
`identity.client-certificates.unmapped` is `derive`, which SHALL name the agent after the SPIFFE ID
without its scheme and leave a certificate without a SPIFFE ID unknown.

#### Scenario: Unmapped certificate

- **WHEN** a certificate that chains to the trust anchor matches no rule and `unmapped` is the
  default
- **THEN** the caller is unknown, its injection is refused, and the decision is audited as
  `caller=unmapped` with the certificate's fingerprint

#### Scenario: Derived name

- **WHEN** `unmapped` is `derive` and an unmapped certificate carries
  `spiffe://example.org/agents/x`
- **THEN** it is the agent `example.org/agents/x`

### Requirement: Client certificate labels

A client certificate identity SHALL carry the certificate's SPIFFE ID, subject common name, issuer
common name and SHA-256 fingerprint as labels policy can match, and configuration SHALL NOT be able
to set those labels.

#### Scenario: Rule on the SPIFFE ID

- **WHEN** a rule allows injection for `agent.labels.spiffe_id.startsWith("spiffe://example.org/agents/")`
- **THEN** a mapped certificate with such a SPIFFE ID is allowed, and a rule label `spiffe_id` in the
  mapping is a configuration error

### Requirement: Client certificate revocation

The system SHALL check client certificates against configured CRL files, read again periodically,
and SHALL refuse a certificate whose issuer has no current CRL among them, or whose issuer's CRL is
past its next update, once any CRL is configured. With no CRL configured it SHALL check no
revocation, for short-lived certificates. It SHALL NOT query OCSP responders.

#### Scenario: Revoked certificate

- **WHEN** the CRL of the client certificate's issuer lists its serial number
- **THEN** the certificate is refused as `revoked`

#### Scenario: Stale CRL

- **WHEN** the configured CRL of the issuer is past its next update
- **THEN** every certificate of that issuer is refused until a current CRL is in place

#### Scenario: New CRL picked up

- **WHEN** the CRL file is replaced with one that revokes a certificate
- **THEN** new connections with that certificate are refused within the refresh interval, without
  a restart
