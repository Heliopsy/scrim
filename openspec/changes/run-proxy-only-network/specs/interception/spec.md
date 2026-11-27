## ADDED Requirements

### Requirement: Proxy-only agent network

With `run.network: proxy-only`, `scrim run` on Linux SHALL start the agent in a network namespace
with loopback only, inside an unprivileged user namespace, in which scrim's LLM base URL and forward
proxy are reachable at their usual addresses and no other host is. It SHALL cover Unix sockets
that act outside the session (buses, name resolvers, displays, container engines, tmux) for the
agent and SHALL refuse to start it when the namespace cannot be set up. The default SHALL be `open`.

#### Scenario: Command that ignores the proxy

- **WHEN** a command in a `proxy-only` session runs `env -i curl https://api.anthropic.com/` or dials a provider's address
- **THEN** its connection fails, while curl through `HTTPS_PROXY` and requests to the LLM base URL work and are redacted

#### Scenario: Name lookup through a host resolver

- **WHEN** a command in a `proxy-only` session looks up a name through the C library, the system bus or resolved's varlink socket
- **THEN** the lookup fails without reaching a resolver

#### Scenario: Host without user namespaces

- **WHEN** `run.network` is `proxy-only` and the host cannot create the namespace
- **THEN** `scrim run` exits with status 125 without starting the agent, and `scrim doctor` fails the `run-network` check

#### Scenario: scrim unavailable with weakened start

- **WHEN** `run.network` is `proxy-only`, `run.allow-unredacted-start` is set and scrim cannot be started
- **THEN** the agent is not started

#### Scenario: Default

- **WHEN** `run.network` is not set
- **THEN** the agent uses the host's network and `scrim doctor` notes whether `proxy-only` works on the host
