## MODIFIED Requirements

### Requirement: Edge forwarder mounts nothing secret

The injected forwarder SHALL mount only the edge CA's public certificate, the pod's identity token
and its socket volume, and the NetworkPolicies SHALL let central agent pods reach the edge port and
nothing else new.

#### Scenario: Forwarder volumes

- **WHEN** the central injection policy is rendered with `edge.enabled`
- **THEN** the forwarder container mounts no Secret, CA key or placeholder key, and verifies central
  scrim against the edge CA certificate, not the interception CA

## ADDED Requirements

### Requirement: Edge CA in the chart

With `edge.enabled` the chart SHALL give the edge listener its own CA, generated once and kept
across upgrades and uninstalls or supplied as a TLS Secret, mount its key only into central scrim,
and publish its certificate to every agent namespace under a CA ConfigMap key of its own that only
the forwarder mounts and that is in neither of the agents' trust files.

#### Scenario: Edge CA published to the forwarder only

- **WHEN** the chart is rendered with `edge.enabled`
- **THEN** the CA ConfigMap of every agent namespace carries the edge CA certificate as
  `scrim-edge-ca.pem`, the forwarder mounts only that key, and agent containers do not mount it

### Requirement: Edge CA values checked

The chart SHALL refuse the interception CA's Secret as the edge CA and an edge forwarder without an
edge CA, and SHALL offer the upgrade window for forwarders that trust the interception CA only as a
value that is off by default.

#### Scenario: Interception CA Secret as the edge CA

- **WHEN** `edge.ca.existingSecret` names the interception CA's Secret
- **THEN** the chart refuses to render and names the value
