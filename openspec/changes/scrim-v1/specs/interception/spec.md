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

### Requirement: Wrapper refuses to start an unprotected agent

`scrim run` SHALL start the agent only after scrim's data plane is ready to redact, its LLM base URL
listener and local agent API are reachable and the session token is minted, and SHALL otherwise exit
with a status of its own (125) naming the cause, without starting the agent. Only the weakening
setting `run.allow-unredacted-start` SHALL start the agent anyway, with its environment unchanged and
a warning.

#### Scenario: scrim cannot start

- **WHEN** a user runs `scrim run -- claude` and scrim cannot be started or its data plane is not ready
- **THEN** Claude Code is not started and `scrim run` exits with status 125 and the reason

#### Scenario: Weakened start

- **WHEN** `run.allow-unredacted-start` is set and scrim cannot be started
- **THEN** the agent starts without scrim's settings and `scrim run` warns that its traffic is unredacted

#### Scenario: Wrapper inside a session

- **WHEN** `scrim run` is started from inside another `scrim run` session
- **THEN** it refuses, because a session cannot mint sessions

### Requirement: Wrapper environment

`scrim run` SHALL point the provider SDKs at the LLM proxy (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`),
point the proxy variables at the forward proxy when it runs, trust scrim's CA for the child only
through a per-session bundle, and remove inherited proxy settings that would bypass the forward
proxy. The session token SHALL never appear on a command line or in `scrim run`'s output.

#### Scenario: Inherited NO_PROXY bypass

- **WHEN** the user's environment sets `NO_PROXY=*` and scrim's forward proxy runs
- **THEN** the agent's `NO_PROXY` lists only loopback and chained local upstreams, and `scrim run` warns

#### Scenario: Print the environment

- **WHEN** a user runs `scrim run --print-env -- claude`
- **THEN** every variable, argument and file is shown, the token as a secret marker, and no session is minted

### Requirement: Agent presets

`scrim run` SHALL add what each supported agent needs for the session only: for Claude Code an MCP
configuration on its command line, for Codex its base URL, MCP server and CA overrides as `-c`
options with the session variables passed to the MCP server by name. A preset SHALL refuse an
inherited setting that would send the agent around scrim.

#### Scenario: Codex session

- **WHEN** a user runs `scrim run -- codex exec "fix the test"`
- **THEN** Codex sends its Responses requests to scrim's LLM proxy, starts `scrim mcp` with the session
  token, and `~/.codex/config.toml` is unchanged

#### Scenario: Cloud provider mode not served

- **WHEN** `CLAUDE_CODE_USE_BEDROCK` is set and the user runs `scrim run -- claude`
- **THEN** `scrim run` refuses, because Claude Code would reach Bedrock directly

### Requirement: Wrapper exports declared placeholders

`scrim run` SHALL export each declared catalog placeholder that resolves for the session as an
environment variable of the same name whose value is the placeholder, except names scrim reads as its
own settings, so commands can reference the credential without holding it.

#### Scenario: Placeholder in a command

- **WHEN** the catalog declares `SCRIM_GITHUB_TOKEN` bound to `api.github.com` and the agent runs
  `curl -H "Authorization: Bearer $SCRIM_GITHUB_TOKEN" https://api.github.com/user`
- **THEN** curl sends the placeholder and the tool proxy injects the real token toward `api.github.com`

### Requirement: Wrapper passes signals and exit status

`scrim run` SHALL forward termination and user signals to the agent, SHALL not deliver a terminal's
interrupt twice to an agent in the terminal's foreground, SHALL exit with the agent's exit status (128
plus the signal number for an agent killed by a signal), and SHALL end the session and remove its
session files when the agent exits.

#### Scenario: Agent stopped by SIGTERM

- **WHEN** `scrim run` receives SIGTERM while the agent runs
- **THEN** the agent receives SIGTERM, `scrim run` exits with status 143 and the session is revoked

### Requirement: Wrapper keeps chained proxies behind scrim

`scrim run` SHALL refuse to start a context-compression wrapper (caveman) in front of the agent, since
it would receive requests before redaction, and SHALL warn when it replaces an inherited provider base
URL, pointing the user to chaining that proxy behind scrim.

#### Scenario: caveman as the wrapped command

- **WHEN** a user runs `scrim run -- caveman claude`
- **THEN** `scrim run` refuses and explains how to chain caveman behind scrim

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

#### Scenario: Tool traffic on the same listener

- **WHEN** an agent with the proxy environment set connects to a host that is not a model provider
- **THEN** scrim terminates TLS, handles the request in the tool proxy (credential injection and
  response redaction) and never passes the connection through uninspected

### Requirement: ChatGPT hosts are provider hosts

`chatgpt.com` and `ab.chatgpt.com` SHALL be provider hosts: a connection to either through the
forward proxy, or any other host-routed mode, SHALL go through the LLM proxy, never the tool proxy.
On `chatgpt.com`, `POST .../responses` SHALL use the OpenAI Responses codec. Every other path on
both hosts SHALL be redacted as generic JSON, since its shape is not documented.

#### Scenario: Codex signed in with ChatGPT

- **WHEN** Codex with a ChatGPT login, through the forward proxy, sends `POST /backend-api/codex/responses` to `chatgpt.com` and a request to `ab.chatgpt.com`, both holding a known value
- **THEN** both reach their upstream through the LLM proxy with placeholders only

### Requirement: One snapshot version per request

The data plane SHALL build every part of a control-plane snapshot (dictionary, LLM routes, tool
proxy credentials, policy) before any is used, publish them with one atomic swap and serve each
request with exactly one snapshot version. A snapshot that fails to build SHALL be rejected with
the previous one left in force, and before the first snapshot all traffic SHALL be refused.

#### Scenario: Snapshot replaced during traffic

- **WHEN** a snapshot is applied while requests are in flight
- **THEN** each request uses either the old or the new dictionary, routes, credentials and policy, never a mix

#### Scenario: Rejected snapshot

- **WHEN** a snapshot names a provider the data plane cannot serve
- **THEN** it is rejected with a message naming the route and the snapshot in force is unchanged

#### Scenario: Before the first snapshot

- **WHEN** a request reaches the data plane before any snapshot is applied
- **THEN** it is refused as not ready and nothing reaches a provider or a tool host

### Requirement: Data plane status

The data plane's status SHALL report each listener with its kind and whether it is bound, the
snapshot version, the value count, the redaction engine, the values that are not protected and the
decision engine, and SHALL report ready only when a snapshot is in force and every listener is
bound.

#### Scenario: Listener cannot be bound

- **WHEN** a snapshot names a listener whose address is in use or whose kind is not implemented
- **THEN** status lists that listener as unbound with the reason and reports the data plane not ready

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

scrim SHALL make its public CA certificate trusted wherever a mode needs TLS interception, scoped
to the processes that mode covers, and SHALL remove every trust change it made on uninstall.

#### Scenario: Wrapper trusts the CA for the agent only

- **WHEN** an agent is started with `scrim run`
- **THEN** the agent and the tools it starts trust scrim's CA through the session bundle
- **AND** no trust store outside the session directory is changed

#### Scenario: Modes that cover processes scrim does not start

- **WHEN** transparent or DNS mode is installed
- **THEN** the CA is also installed into the system trust store and the Java truststore

#### Scenario: Node-based agent

- **WHEN** transparent mode is installed for a Node-based agent
- **THEN** the agent trusts scrim's certificate without manual configuration

#### Scenario: Per-user trust installation

- **WHEN** a user runs `scrim ca install --user`
- **THEN** each change to a trust store or bundle file is shown before it is made and recorded in a manifest
- **AND** `scrim ca uninstall --user` reverts exactly the recorded changes and lists any it could not revert with the manual step

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
