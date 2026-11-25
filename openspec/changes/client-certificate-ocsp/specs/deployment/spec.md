## ADDED Requirements

### Requirement: TLS tool proxy listener in the chart

With client certificates on, the chart SHALL serve the tool proxy on a TLS listener that requires a
client certificate, on its own port of the `<fullname>-mtls` Service and NetworkPolicy, and SHALL
leave it off when its port is 0.

#### Scenario: Tool pointed at the tool proxy

- **WHEN** a tool outside the cluster connects to the tool proxy port of the mtls Service with a
  certificate issued by a CA in the bundle
- **THEN** scrim identifies it from the certificate

### Requirement: Revocation settings in the chart

The chart SHALL map its revocation scope and OCSP values to the client certificate settings, and
with OCSP on SHALL allow central scrim's egress to the responders unless the operator narrows it.

#### Scenario: OCSP on

- **WHEN** the chart is rendered with OCSP enabled
- **THEN** central scrim's configuration turns OCSP on and its NetworkPolicy allows egress to the
  responders
