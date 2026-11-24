## ADDED Requirements

### Requirement: Outbound connections through an upstream proxy

scrim SHALL send its own outbound connections through the upstream HTTP proxy that
`network.upstream-proxy.url` names, or when that is empty the proxy in the `HTTPS_PROXY`,
`https_proxy`, `HTTP_PROXY` or `http_proxy` it was started with. This covers the data plane's
connections to providers, chained upstreams and tool hosts and its transparent pass-through, and
the control plane's HTTP connections to stores, notifiers, audit sinks and identity endpoints.

#### Scenario: Provider request on a network that only reaches out through a proxy

- **WHEN** scrim runs with `HTTPS_PROXY=http://proxy.corp:3128` and an agent sends a model request
  carrying a secret
- **THEN** the request is redacted and checked by the guard, then sent to the provider through a
  `CONNECT` tunnel opened by that proxy
- **AND** the proxy relays only TLS ciphertext, and the provider's certificate is verified for the
  provider's name

#### Scenario: Proxy that presents its own certificate

- **WHEN** the upstream proxy terminates the tunnel with a certificate scrim does not trust for the
  destination's name
- **THEN** the connection fails and nothing of the request is sent

#### Scenario: Proxy credentials

- **WHEN** `network.upstream-proxy.username` is `scrim` and `network.upstream-proxy.password` is
  `file:/run/secrets/proxy`
- **THEN** every `CONNECT` carries those credentials
- **AND** when the proxy refuses them the request fails with an upstream error and is not retried
  directly

#### Scenario: Internal hosts skip the proxy

- **WHEN** `network.upstream-proxy.no-proxy` lists `corp.example` and a store lives at
  `vault.corp.example`
- **THEN** scrim connects to the store directly, and to providers through the proxy

#### Scenario: Proxy changed by a reload

- **WHEN** the upstream proxy or its password changes and the configuration is reloaded
- **THEN** new connections on both planes use the new proxy without a restart, and connections
  already open keep their route until they close

#### Scenario: Unsupported proxy

- **WHEN** scrim's environment sets `HTTPS_PROXY=socks5://proxy.corp:1080`
- **THEN** scrim refuses to start and names `network.upstream-proxy.url`

### Requirement: Upstream proxy keeps interception guarantees

Every proxied connection SHALL be an HTTP `CONNECT` tunnel opened only after the request passed
the redactor and the guard, with TLS to the destination inside the tunnel, verified against the
destination's name. A proxy scrim cannot use or that refuses a connection SHALL fail it, never
replace it with a direct connection.

#### Scenario: Refused tunnel

- **WHEN** the upstream proxy answers `CONNECT` with an error status
- **THEN** the request fails with an upstream error and nothing is sent directly

### Requirement: Upstream proxy exceptions

Destinations in `network.upstream-proxy.no-proxy`, in the environment's `NO_PROXY` when the proxy
came from the environment, and loopback SHALL be reached directly, with the same matching on both
planes. `network.upstream-proxy.url: direct` SHALL turn the proxy off.

#### Scenario: Direct overrides the environment

- **WHEN** scrim's environment sets `HTTPS_PROXY` and `network.upstream-proxy.url` is `direct`
- **THEN** scrim connects directly

### Requirement: Upstream proxy credentials

When the proxy needs credentials, scrim SHALL send `network.upstream-proxy.username` with the
password `network.upstream-proxy.password` references, or the user info of the environment's proxy
URL, as Basic `Proxy-Authorization` on every `CONNECT`. The password SHALL never reach a log,
error, status output or an agent's environment.

#### Scenario: Status without the password

- **WHEN** the upstream proxy has credentials and an operator runs `scrim status` or reads the daemon
  info on the admin API
- **THEN** the proxy is shown as `scheme://host:port` only

### Requirement: Wrapper chains an inherited proxy

`scrim run` SHALL set the agent's proxy variables to scrim's forward proxy whatever proxy the
user's environment names, and SHALL keep the inherited proxy as scrim's upstream proxy: a scrim
that `scrim run` starts SHALL take it from the same environment. When the scrim serving the session
already runs with a different upstream proxy, or none, `scrim run` SHALL say so before the agent
starts. The inherited proxy's credentials SHALL never reach the agent's environment or
`scrim run`'s output.

#### Scenario: Corporate HTTPS_PROXY

- **WHEN** a user with `HTTPS_PROXY=http://user:pw@proxy.corp:3128` runs `scrim run -- claude` and
  no scrim is running
- **THEN** the agent's `HTTPS_PROXY` is scrim's forward proxy, scrim's outbound connections go
  through `proxy.corp:3128` with those credentials, and no warning about the proxy is shown

#### Scenario: Running scrim without the proxy

- **WHEN** the scrim already running for the user connects directly and the user's environment
  sets `HTTPS_PROXY=http://proxy.corp:3128`
- **THEN** `scrim run` warns that the inherited proxy is not used and names
  `network.upstream-proxy.url`, without showing any credentials
