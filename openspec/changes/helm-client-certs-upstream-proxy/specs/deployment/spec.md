## ADDED Requirements

### Requirement: Client certificates in the chart

With `identity.clientCertificates.enabled` the chart SHALL have central scrim serve the LLM base URL,
forward proxy and tool proxy on TLS listeners that require a client certificate, trust only the CA bundle and
CRLs it mounts from ConfigMaps, and expose those listeners on a Service of their own carrying no
plain listener.

#### Scenario: Agent outside the cluster

- **WHEN** an agent presents a certificate issued by a CA in the configured bundle to the TLS
  listener on the `<fullname>-mtls` Service
- **THEN** scrim identifies it from the certificate, and the central Service still carries only the
  plain listeners

#### Scenario: Missing trust anchors refused

- **WHEN** the chart is rendered with client certificates on and no CA ConfigMap
- **THEN** rendering fails and names the missing value

### Requirement: Upstream proxy in the chart

With `upstreamProxy.url` the chart SHALL write `network.upstream-proxy` for central scrim and every
sidecar, reach in-cluster Services directly unless told otherwise, and take the proxy password only
from a Secret, never from values or from credentials in the URL.

#### Scenario: Cluster behind a corporate proxy

- **WHEN** the chart is rendered with a proxy URL, a username and the Secret slot `upstream-proxy`
- **THEN** central scrim and the sidecars use the proxy with that user, read the password from the
  mounted Secret, and list `.svc` and the cluster domain as no-proxy entries

#### Scenario: Credentials in the proxy URL refused

- **WHEN** `upstreamProxy.url` carries a user name and password
- **THEN** rendering fails and points to `username` and the Secret slot
