## ADDED Requirements

### Requirement: Operator listener certificate in the chart

With client certificates on and an operator's TLS Secret given for the listener certificate, the
chart SHALL mount that Secret into central scrim only and have the TLS listeners present its
certificate, and SHALL refuse a CA's Secret in its place.

#### Scenario: Listener certificate from cert-manager

- **WHEN** the chart is rendered with a cert-manager Certificate's Secret for the listener certificate
- **THEN** central scrim mounts it and its TLS listeners present that certificate, read again on
  every refresh

#### Scenario: CA Secret refused

- **WHEN** the listener certificate Secret is the interception CA's or the edge CA's
- **THEN** rendering fails
