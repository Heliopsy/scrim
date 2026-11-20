## Purpose

Credential injection lets an agent use a credential without holding it. The credential stays a
placeholder in the agent's commands and is swapped in only on outbound connections to the hosts it
is bound to.

## ADDED Requirements

### Requirement: Credentials are bound to destinations

Every credential SHALL declare the hosts it may be sent to, and MAY further restrict methods and
paths. A credential with no binding SHALL never be injected anywhere.

#### Scenario: Credential without binding

- **WHEN** a request carries the placeholder of a credential that has no destination binding
- **THEN** the request is refused and the audit log records the unbound credential

### Requirement: Injection only toward bound hosts

The HTTPS tool proxy SHALL replace a credential placeholder with the real value only on requests to
a host, method and path the credential is bound to, and SHALL refuse any request carrying that
placeholder to any other destination.

#### Scenario: Token sent to its own API

- **WHEN** an agent sends a request to `api.github.com` with the GitHub credential placeholder
- **THEN** the upstream receives the real token and the agent's command never contained it

#### Scenario: Token sent to another host

- **WHEN** an agent sends the GitHub credential placeholder to a host it is not bound to
- **THEN** the request is refused and nothing is sent to that host

### Requirement: Injection locations

Injection SHALL support placing the credential in a header, a query parameter or a body field, as
declared per credential, and SHALL refuse a request whose placeholder appears in a location the
credential does not declare.

#### Scenario: Placeholder in an undeclared location

- **WHEN** a placeholder for a header-only credential appears in the request body
- **THEN** the request is refused

### Requirement: Interception certificate authority

scrim SHALL generate its own certificate authority for TLS interception, keep its private key out
of agents' reach, support rotation with an overlap period, and export only the public certificate
for trust installation.

#### Scenario: CA rotation

- **WHEN** the CA is rotated
- **THEN** connections made with the previous CA keep working until the overlap period ends

#### Scenario: Client trusting only the previous CA

- **WHEN** a client that trusts only the previous CA connects during the overlap period
- **THEN** the handshake succeeds through a cross certificate, and fails once the overlap ends

#### Scenario: Restart during an overlap

- **WHEN** scrim restarts while a rotation's overlap period is running
- **THEN** it uses the same current CA and keeps the previous one until the recorded end of the overlap

#### Scenario: Operator-supplied CA

- **WHEN** `tool-proxy.ca.cert-file` and `tool-proxy.ca.key` name an operator's CA certificate and key reference
- **THEN** scrim uses that CA, never rotates it, and warns before it expires

#### Scenario: CA key readable by others

- **WHEN** the generated CA's key file is readable by group or others
- **THEN** scrim refuses to use it and names the file, without printing its content

### Requirement: Pinned certificates fail closed

When a client refuses the interception certificate, scrim SHALL not fall back to passing the
connection through uninspected, and SHALL report the refusing destination in status and the audit
log.

#### Scenario: Client with certificate pinning

- **WHEN** a client pins the upstream certificate and rejects the interception certificate
- **THEN** the connection fails and the destination is listed as unsupported in status

### Requirement: Response capture

Capture rules SHALL store a configured field of a matching response (for example a newly created
token) into a configured store reference and replace it with that reference's placeholder before
the agent receives the response. If storing fails, the field SHALL be withheld.

#### Scenario: Creating an API token

- **WHEN** an agent's request matches a capture rule and the response contains a new token
- **THEN** the token is written to the configured store and the agent receives its placeholder

#### Scenario: Store write fails during capture

- **WHEN** the store write for a captured field fails
- **THEN** the agent receives the response with the field withheld and an error marker

### Requirement: Destination is the connection

The tool proxy SHALL check bindings against the host and port it actually connects to (the CONNECT
target or the absolute-form URI), SHALL refuse a request whose `Host` header, `:authority` or TLS
server name names a different host, and SHALL match path bindings after removing dot segments.

#### Scenario: Host header pointing elsewhere

- **WHEN** an agent opens a tunnel to a bound host and sends a request whose `Host` header names
  another host
- **THEN** the request is refused as misdirected and nothing is sent upstream

#### Scenario: Dot segments in the path

- **WHEN** a credential is bound to `/v1/*` and the agent requests `/v1/../admin` with its placeholder
- **THEN** the request is refused because the effective path is `/admin`

### Requirement: Plain HTTP injection is opt-in

A credential SHALL only be injected into plain `http://` requests when its binding explicitly allows
plain HTTP, a setting named for what it weakens.

#### Scenario: Bound host over plain HTTP

- **WHEN** an agent sends a credential placeholder to its bound host over `http://` and the binding
  does not allow plain HTTP
- **THEN** the request is refused as an unbound destination

### Requirement: Documented refusals

Every refusal and withheld response from the tool proxy SHALL carry a stable error code in an
`x-scrim-error` header and a JSON body, SHALL name credentials only by alias, and SHALL be recorded
in the audit log without any value.

#### Scenario: Agent reads the refusal

- **WHEN** a request is refused because its placeholder is not bound to the destination
- **THEN** the agent receives status 403 with code `unbound_destination` and the credential alias,
  and the audit entry names the alias and destination

### Requirement: Bodies too large to rewrite

Request bodies above the configured buffering limit SHALL be streamed unmodified and cut off if a
placeholder appears in them, and an encoded oversized body toward a host with bound credentials
SHALL be refused. The upstream's answer to a cut-off request SHALL not reach the agent.

#### Scenario: Placeholder in a large upload

- **WHEN** an agent uploads a body larger than the buffering limit with a placeholder near its end
- **THEN** the upload is cut off before the placeholder leaves scrim and the agent receives
  `body_too_large`

### Requirement: Protocol upgrades are refused

The tool proxy SHALL refuse protocol upgrades (for example WebSocket) because the upgraded stream
cannot be scanned.

#### Scenario: WebSocket handshake

- **WHEN** an agent sends a WebSocket upgrade request through the tool proxy
- **THEN** the request is refused with `upgrade_unsupported`

### Requirement: Exec broker

The exec broker SHALL run commands on an agent's behalf under a separate operating-system identity,
with requested secrets in the command's environment. Only commands on the secret's allow list SHALL
run; others SHALL be refused or sent for approval per policy.

#### Scenario: Allowed command

- **WHEN** an agent asks the broker to run `psql` with the database credential and `psql` is allowed
- **THEN** the command runs with the credential in its environment and the agent's process never holds it

#### Scenario: Command not on the allow list

- **WHEN** an agent asks the broker to run a command not on the secret's allow list
- **THEN** the broker refuses it or asks for approval, as the policy decides

### Requirement: Exec broker output is redacted

The exec broker SHALL redact known values and their encoded variants from command output before
returning it, and SHALL refuse to run commands that transform secret-bearing output (byte dumps,
encoders, reversers, character splitting) when they are applied to a secret.

#### Scenario: Attempt to base64 the environment

- **WHEN** an agent asks the broker to run a command that encodes the environment
- **THEN** the broker refuses it and the audit log records the blocked transform

### Requirement: SSH agent

scrim SHALL act as an SSH agent offering keys from configured stores. Agents SHALL be able to sign
with a key but never read it, and policy MAY require approval for each signature.

#### Scenario: Git push over SSH with approval

- **WHEN** an agent's SSH client requests a signature with a key whose policy requires approval
- **THEN** the signature is produced only after a human approves, and refused on timeout

### Requirement: Database auth proxies

scrim SHALL offer local PostgreSQL and MySQL endpoints that accept the agent's connection without a
password and authenticate to the real database with the bound credential. A connection to an
unbound database SHALL be refused.

#### Scenario: Agent connects to a database

- **WHEN** an agent connects to the local database endpoint for a configured database
- **THEN** the session is authenticated upstream and the agent never receives the password

### Requirement: Read-only database tool

scrim SHALL offer a read-only database tool that turns placeholders inside string literals into
bound parameters carrying real values, rejects writes and multiple statements, enforces row and
time limits, and returns results redacted.

#### Scenario: Query by placeholder

- **WHEN** an agent queries with a placeholder inside a string literal
- **THEN** the database receives the real value as a bound parameter, never as SQL text

#### Scenario: Write attempt

- **WHEN** an agent submits a data-modifying statement to the database tool
- **THEN** the statement is refused and not executed

### Requirement: Placeholder credentials for command-line tools

`scrim run` and the Kubernetes injection SHALL provision, per configured tool profile, the
environment variables and generated config files a CLI reads its credentials from (for example
`GH_TOKEN`, an AWS config, a kubeconfig, `.npmrc`, `.netrc`, a container registry auth file). They
SHALL contain placeholders only, and SHALL be removed when the session ends.

#### Scenario: gh with a placeholder token

- **WHEN** an agent started with `scrim run` runs `gh pr list`
- **THEN** `GH_TOKEN` holds a placeholder, the request to `api.github.com` carries the real token
- **AND** no file or environment variable in the agent's session contains the real token

#### Scenario: Generated kubeconfig

- **WHEN** the `kubectl` profile is enabled for a cluster credential
- **THEN** `KUBECONFIG` points at a generated file whose token is a placeholder and whose server
  traffic is injected by scrim

### Requirement: Built-in tool profiles

The system SHALL ship tool profiles for at least git, gh, glab, aws, gcloud, az, kubectl, helm,
terraform and OpenTofu, docker and podman registries, npm, pnpm, pip and twine, cargo, hcloud,
doctl, psql, mysql and ssh, each declaring where the tool reads credentials, which hosts it talks
to and which injection or proxy mode it needs. Profiles SHALL be overridable and extendable in
configuration.

#### Scenario: Custom profile

- **WHEN** configuration adds a profile for an in-house CLI reading `ACME_TOKEN` and calling
  `api.acme.internal`
- **THEN** that CLI works through scrim like a built-in profile

### Requirement: Re-signing for signed request protocols

For protocols where the client signs requests with the secret (AWS SigV4 first), the tool proxy
SHALL discard the client's signature made with the placeholder and re-sign the request with the real
credential toward bound endpoints only. A request that cannot be re-signed SHALL be refused.

#### Scenario: aws CLI with placeholder keys

- **WHEN** the agent runs `aws s3 ls` with placeholder access keys
- **THEN** scrim re-signs the request with the real keys and S3 accepts it
- **AND** a request signed for an unbound account or region is refused

### Requirement: Format-preserving placeholders

A credential MAY be configured to use a placeholder that keeps the real secret's prefix, length and
alphabet, for clients that validate a token's shape before sending it. Format-preserving
placeholders SHALL still be unique, deterministic and recognised by the redactor and the guard.

#### Scenario: Client that checks the token prefix

- **WHEN** a CLI rejects tokens that do not start with `ghp_`
- **THEN** the format-preserving placeholder starts with `ghp_` and the CLI sends it

### Requirement: Client certificates toward upstreams

When an upstream authenticates clients with certificates (for example a Kubernetes API server or a
database requiring mTLS), scrim SHALL present the client certificate from the store on the upstream
connection. The private key SHALL never be written to the agent's filesystem.

#### Scenario: kubectl with certificate authentication

- **WHEN** a cluster credential is a client certificate and key stored in a store
- **THEN** kubectl reaches the API server through scrim, which presents the certificate upstream

### Requirement: Edge forwarder for local sockets

Where scrim runs centrally, an edge component in the agent's pod or host SHALL expose the local
endpoints tools expect (the ssh-agent socket, database ports on localhost, the exec broker) and
forward them to the central instance over an authenticated, encrypted channel. The edge SHALL hold
no secret values.

#### Scenario: ssh in a pod with central scrim

- **WHEN** an agent pod runs `git push` over SSH and scrim runs as a central deployment
- **THEN** the edge forwarder provides `SSH_AUTH_SOCK` in the pod and signatures are made by the
  central instance

### Requirement: Environment overrides before file tricks

A tool profile SHALL point the tool at its generated placeholder config through the tool's own
override variable when one exists (for example `AWS_SHARED_CREDENTIALS_FILE`, `KUBECONFIG`,
`DOCKER_CONFIG`, `GH_CONFIG_DIR`, `NPM_CONFIG_USERCONFIG`, `PGPASSFILE`, `TF_CLI_CONFIG_FILE`,
`CLOUDSDK_CONFIG`, `AZURE_CONFIG_DIR`), and SHALL use a filesystem view only for tools without one.

#### Scenario: Tool with an override variable

- **WHEN** the docker profile is enabled
- **THEN** `DOCKER_CONFIG` points at a generated directory whose auth entries are placeholders

### Requirement: Session filesystem view for fixed paths

On Linux, `scrim run` SHALL be able to start the agent in an unprivileged mount namespace where
configured credential paths (for example `~/.aws/credentials`, `~/.kube/config`, `~/.netrc`,
`~/.ssh/id_*`, `~/.config/gh/hosts.yml`) show generated placeholder versions or are hidden, while the
rest of the home directory stays as it is. The real files SHALL not be readable from the session.

#### Scenario: Tool that ignores environment overrides

- **WHEN** a tool reads `~/.aws/credentials` directly from the home directory in the password
  database
- **THEN** inside the session it reads the placeholder version and its requests are injected

#### Scenario: Real file hidden

- **WHEN** the agent runs `cat ~/.ssh/id_ed25519` inside the session
- **THEN** the file is absent or empty and the agent is pointed at `SSH_AUTH_SOCK`

### Requirement: Filesystem view fallback without namespaces

Where mount namespaces are unavailable (macOS, restricted containers), scrim SHALL fall back to a
session home directory that mirrors the real one except configured credential paths, and SHALL
report in status which tools may still read the real files because they bypass `HOME`.

#### Scenario: macOS session

- **WHEN** `scrim run` starts an agent on macOS
- **THEN** `HOME` points at the session directory and `scrim status` lists the fallback and its gaps

### Requirement: Credential helpers

The system SHALL provide credential helpers for tools that support them (git credential helper,
docker credential helper, AWS `credential_process`, kubectl exec plugin) returning placeholders by
default, or short-lived scoped credentials only where policy allows it and with the grant recorded.

#### Scenario: git asks its credential helper

- **WHEN** git pushes over HTTPS and calls the scrim credential helper
- **THEN** the helper returns a placeholder and the push succeeds through the tool proxy

### Requirement: Tools that print their own credentials

Commands that print stored credentials (for example `aws configure get`, `gh auth token`,
`kubectl config view --raw`, docker credential helpers called directly) SHALL only ever print
placeholders inside a session, and any real value they emit SHALL be redacted from tool output.

#### Scenario: Agent asks gh for its token

- **WHEN** the agent runs `gh auth token`
- **THEN** the output is a placeholder

### Requirement: Secrets in project files

The system SHALL scan the session's working directory for secret values in files such as `.env*`,
`*.tfvars` and application config, register what it finds as known values for redaction, watch those
files for changes, and offer to move each value into a configured store and replace it in the file
with a reference. Nothing is moved or rewritten without confirmation.

#### Scenario: Unregistered secret in .env

- **WHEN** a project's `.env` contains an API key that no store holds
- **THEN** scrim redacts it from LLM traffic from the start of the session
- **AND** `scrim doctor` lists it with an offer to move it into a store

### Requirement: User-declared placeholders

Users SHALL be able to declare their own placeholder strings (for example `SCRIM_GITHUB_TOKEN` or
`{{scrim:bao://kv/agents/github#token}}`) and map each to a secret reference and its bound hosts, so
hand-written config files can carry readable placeholders. Declared placeholders SHALL be substituted
on the wire exactly like generated ones and SHALL be unique across the configuration.

#### Scenario: Placeholder written into a config file

- **WHEN** `config/app.yaml` contains `api_key: SCRIM_ACME_KEY` and a tool sends it to the bound host
- **THEN** the request leaves scrim with the real key in place of `SCRIM_ACME_KEY`
- **AND** the tool and the agent behave as if the real key were configured

#### Scenario: Duplicate declaration

- **WHEN** two secrets declare the same placeholder string
- **THEN** configuration validation fails and names both

### Requirement: Substitution in any declared part of the request

For a credential whose configuration allows it, the tool proxy SHALL substitute its placeholder
anywhere in the request (URL, headers, cookies, form, JSON or multipart body), decompressing and
recompressing bodies, recomputing lengths and content digests, and re-signing where the protocol
requires. A body it cannot rewrite safely SHALL be refused, never sent with the placeholder replaced
partially.

#### Scenario: Gzip-compressed JSON body

- **WHEN** a tool uploads a gzip-compressed JSON document containing a placeholder to its bound host
- **THEN** the upstream receives a valid gzip body with the real value and a correct length

#### Scenario: Unsupported body encoding

- **WHEN** the placeholder sits inside a body encoding scrim cannot rewrite
- **THEN** the request is refused with an error naming the encoding

### Requirement: Tool proxy responses are redacted

Every response returned through the tool proxy SHALL be scanned for known values in headers and
bodies, including streamed and compressed bodies, and each value SHALL be replaced with its
placeholder before the agent receives it, so an API that echoes a credential back shows the agent
the same placeholder it sent. A response that cannot be scanned SHALL be withheld.

#### Scenario: API echoes the credential

- **WHEN** an API's error message repeats the Authorization header it received
- **THEN** the agent sees the placeholder in the error, not the real token

#### Scenario: Created resource returns its secret

- **WHEN** a tool creates a webhook whose response includes the signing secret already held in a store
- **THEN** the agent receives the placeholder for that secret

#### Scenario: Echo of a declared placeholder

- **WHEN** an agent sends `SCRIM_ACME_KEY` and the API echoes the injected key back
- **THEN** the agent sees `SCRIM_ACME_KEY`, the placeholder it sent

#### Scenario: Captured token returned again

- **WHEN** a capture rule stored a token and a later response from any host contains the same token
- **THEN** the agent receives its placeholder, even before the next snapshot includes the value
