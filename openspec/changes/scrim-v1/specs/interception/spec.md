## Purpose

Interception covers every way an agent's traffic can reach scrim, so users can pick the mode that
suits them, and makes each mode fail closed wherever it can enforce that the agent cannot reach a
model provider directly.

## ADDED Requirements

### Requirement: Wrapper mode

`scrim run -- <agent> [args]` SHALL start the agent with every setting it needs (provider base URLs,
MCP registration, CA trust, identity) applied to that process only, and SHALL make no persistent
change to the user's configuration.

#### Scenario: One-off session

- **WHEN** a user runs `scrim run -- claude`
- **THEN** that session's traffic goes through scrim
- **AND** running `claude` afterwards without the wrapper leaves its configuration unchanged

### Requirement: Base URL mode

scrim SHALL accept provider traffic on a local base URL that agents can be pointed at through
their own configuration or environment variables, for every supported provider API.

#### Scenario: Agent configured by base URL

- **WHEN** an agent's provider base URL is set to scrim's local address
- **THEN** its requests are redacted and forwarded

### Requirement: Forward proxy mode

scrim SHALL act as an HTTP forward proxy with TLS interception, so agents that honour proxy
environment variables reach providers through scrim without a base URL change.

#### Scenario: HTTPS_PROXY set

- **WHEN** an agent with the proxy environment set connects to a provider host
- **THEN** scrim terminates TLS with its CA, redacts the request and forwards it

### Requirement: Transparent mode with packet filtering

scrim SHALL offer a transparent mode on Linux that redirects connections to provider hosts from
selected users or control groups to scrim, and blocks their direct connections, without any agent
configuration.

#### Scenario: Agent unaware of scrim

- **WHEN** transparent mode covers a user and an agent of that user connects to a provider directly
- **THEN** the connection is redirected to scrim and redacted

### Requirement: Transparent mode with eBPF

scrim SHALL offer a Linux transparent mode that attaches connection hooks to selected control
groups, redirecting provider connections to scrim and denying direct egress. Loading the hooks SHALL
require a privileged loader, and agents SHALL run unprivileged.

#### Scenario: Wrapped agent in its own control group

- **WHEN** an agent runs in a control group covered by the eBPF mode
- **THEN** its provider connections reach scrim and direct provider connections are denied

#### Scenario: Loader not available

- **WHEN** the eBPF mode is configured but the privileged loader is not installed or lacks rights
- **THEN** scrim refuses to report the mode as active and status names the missing privilege

### Requirement: DNS override mode

scrim SHALL offer a mode in which provider host names resolve to scrim, which serves certificates
for those names from its CA, and status SHALL report that this mode does not stop connections made
by address.

#### Scenario: Name-based connection

- **WHEN** an agent resolves a provider host name under the DNS override
- **THEN** it connects to scrim and its traffic is redacted

### Requirement: Kubernetes injection

In Kubernetes, pods carrying a configured label SHALL receive the provider settings, CA trust, MCP
registration and identity token automatically, and an egress policy SHALL limit them to scrim and
name resolution.

#### Scenario: Labelled agent pod

- **WHEN** a pod with the agent label starts
- **THEN** its provider traffic goes through scrim and its direct provider egress is blocked

### Requirement: Managed agent settings

scrim SHALL install managed settings for agents that support them (for example Claude Code's
managed settings with a pinned custom endpoint and allowed providers restricted to it), so the agent
can only use scrim's endpoint.

#### Scenario: Managed settings installed

- **WHEN** managed settings are installed and a user tries to point the agent at the provider directly
- **THEN** the agent refuses the direct endpoint

### Requirement: Hooks-only mode is reported as partial

scrim SHALL offer agent hooks that redact tool output before it enters the agent's context, and
SHALL report this mode as partial protection that does not resolve placeholders or stop direct
traffic.

#### Scenario: Status in hooks-only mode

- **WHEN** only hooks are installed
- **THEN** status reports protection as partial and lists what is not covered

### Requirement: CA trust installation

scrim SHALL install its public CA certificate for the system trust store and for runtimes that use
their own (Node.js, Python, OpenSSL-based tools, Java) when a mode needs TLS interception, and SHALL
remove it on uninstall.

#### Scenario: Node-based agent

- **WHEN** transparent mode is installed for a Node-based agent
- **THEN** the agent trusts scrim's certificate without manual configuration

### Requirement: Local chained proxies are not intercepted

When scrim is chained to a local upstream proxy, interception SHALL exclude that upstream's local
address from proxying and redirection, so traffic does not loop.

#### Scenario: Compression proxy on localhost

- **WHEN** a chained upstream listens on a loopback address
- **THEN** scrim reaches it directly and the agent's proxy exclusions include that address

### Requirement: Enforcement fails closed

Every mode that can enforce SHALL keep the agent from reaching providers when scrim is stopped or
failing; the agent SHALL see a connection error, not a direct connection.

#### Scenario: scrim stopped in transparent mode

- **WHEN** scrim is stopped while transparent mode is active
- **THEN** the agent's provider connections fail instead of going direct

### Requirement: Doctor and status report protections

`scrim doctor` and `scrim status` SHALL report, per agent or scope, the active interception mode,
whether direct egress is blocked, CA trust state, chained upstreams, and every known gap.

#### Scenario: Mixed setup

- **WHEN** a user runs `scrim doctor` with the wrapper active and no egress enforcement
- **THEN** the report shows redaction active and direct egress not blocked, with the fix
