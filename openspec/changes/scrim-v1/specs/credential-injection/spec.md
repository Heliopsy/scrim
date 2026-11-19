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
