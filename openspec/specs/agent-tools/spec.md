# agent-tools Specification

## Purpose
Gives agents tools, over MCP and the CLI, to discover, request, generate, capture and ask a human for
secrets, without any tool ever accepting or returning a secret value.

## Requirements

### Requirement: MCP server over stdio and HTTP

The system SHALL serve its agent tools as an MCP server over stdio and over HTTP, with the same tool
set, inputs, outputs and policy on both transports. Every call SHALL be attributed to the calling
agent's identity.

#### Scenario: Same tools on both transports

- **WHEN** an agent lists tools over stdio and another over HTTP
- **THEN** both receive the same tool names and input schemas

#### Scenario: Unauthenticated HTTP call

- **WHEN** an MCP request over HTTP carries no valid agent credential
- **THEN** it is refused and no tool runs

### Requirement: Local agent API

The system SHALL serve a versioned local API on a Unix socket that the MCP server and the CLI use for
every tool call. Each request SHALL be attributed from the socket's peer credentials and, when
present, a session token; callers that are not mapped to an agent SHALL be refused. Request bodies
with unknown fields SHALL be refused. Exactly one route SHALL store a value, taken as a raw request
body, and no route SHALL return one.

#### Scenario: Unmapped local user

- **WHEN** a process running as a local user with no agent mapping calls a tool route
- **THEN** it is refused as unauthenticated and the refusal is audited with its user ID

#### Scenario: Value smuggled into a tool body

- **WHEN** a client sends a `value` field in the body of a generate request
- **THEN** the request is refused and nothing is generated or stored

### Requirement: Redaction route for agent hooks

The local API SHALL offer a route that takes text that may hold values, for agent hooks, and SHALL
answer only with that text as the data plane's redactor and guard left it, or with an error that
carries none of it.

#### Scenario: Hook text redacted

- **WHEN** an agent hook sends a tool result holding a known value to the redact route
- **THEN** the answer holds the value's placeholder and not the value
- **AND** when the data plane cannot redact it, the answer is an error that holds no part of the text

### Requirement: Every tool has an equivalent CLI command

The system SHALL offer each agent tool as a CLI command with the same inputs, outputs, policy and
audit behaviour, with machine-readable output on request and meaningful exit codes.

#### Scenario: CLI request with JSON output

- **WHEN** a script runs the CLI equivalent of `secret_request` with JSON output
- **THEN** it receives the same fields the MCP tool returns
- **AND** the exit code distinguishes granted, denied, pending and error

#### Scenario: Documented exit codes

- **WHEN** a CLI tool command finishes
- **THEN** it exits 0 on success, 1 on error, 3 when denied, 4 while pending and 5 when declined or
  expired

### Requirement: No tool accepts or returns a secret value

The system SHALL NOT define any tool input that carries a secret value, and SHALL NOT return a secret
value in any tool result, error or progress message. Where a result refers to a secret, it SHALL use
the reference or the placeholder.

#### Scenario: Result mentions a secret

- **WHEN** a tool result describes a stored secret
- **THEN** it contains the reference and placeholder only

#### Scenario: Error while handling a secret

- **WHEN** a tool fails after it has read or written a value
- **THEN** the error message contains no part of the value

### Requirement: secrets_list

The system SHALL provide `secrets_list`, returning the references, names and non-secret metadata of
secrets the calling agent may see under policy, filterable by store, prefix and binding.

#### Scenario: Agent sees only what policy allows

- **WHEN** an agent's policy covers only `bao://kv/agents/*`
- **THEN** `secrets_list` returns only references under that path

### Requirement: secret_request

The system SHALL provide `secret_request` taking a reference, a requested duration and a reason. It
SHALL evaluate policy and return granted, denied or pending with an approval identifier; a pending
request SHALL become a grant only on approval, and SHALL be denied when the approval times out.

#### Scenario: Request needing approval

- **WHEN** an agent requests `bao://kv/agents/hetzner` for 30 minutes and policy says ask
- **THEN** the tool returns pending with an approval identifier
- **AND** a grant exists only after a human approves

#### Scenario: Requested duration above the maximum

- **WHEN** the requested duration exceeds the configured maximum for that secret
- **THEN** the grant, if approved, is capped at the maximum and the result says so

### Requirement: secret_gen

The system SHALL provide `secret_gen`, which generates a value inside scrim from a specification
(length, character set or format such as hex, base64, UUID or passphrase), stores it at a reference
in the chosen or default store, and returns only the reference and placeholder.

#### Scenario: Generate a database password

- **WHEN** an agent calls `secret_gen` for `bao://kv/agents/app-db#password` with length 32
- **THEN** a 32-character value is stored there and the agent receives the reference

#### Scenario: Store write fails

- **WHEN** the generated value cannot be stored
- **THEN** the tool fails, the value is discarded, and nothing about the value is returned

### Requirement: secret_capture

The system SHALL provide `secret_capture`, which runs a command or reads standard input, extracts a
value (whole output, a JSON path, or a line pattern), stores it at a reference, and returns only the
reference. The command's output SHALL NOT be returned to the agent.

#### Scenario: Capture a token created by an API

- **WHEN** an agent captures `.token` from the output of a command that creates a token
- **THEN** the token is stored, added to the redaction set, and the agent receives only the reference

#### Scenario: Capture refused by policy

- **WHEN** policy denies storing at the capture's reference
- **THEN** the command is not run at all

#### Scenario: Extraction finds nothing

- **WHEN** the JSON path matches no value
- **THEN** nothing is stored and the error contains no part of the command's output

### Requirement: Piped values never echo

The system SHALL accept values for storage on standard input in the CLI (`scrim secret put --stdin`)
and SHALL NOT print, echo or log any part of the value. Output SHALL be limited to the reference and
the result of the write.

#### Scenario: Piping a response into a store

- **WHEN** a command's output is piped into `scrim secret put new-token --stdin`
- **THEN** the terminal and the agent's tool result show only the reference and success

#### Scenario: Typing a value at a terminal

- **WHEN** `scrim secret put --stdin` reads from a terminal
- **THEN** terminal echo is off while the value is typed and restored afterwards

### Requirement: secret_ask_human

The system SHALL provide `secret_ask_human`, which sends a prompt to a human through the configured
notifiers with a link to a local, authenticated entry page. The value entered there SHALL be stored
directly, and the agent SHALL learn only whether it was stored, declined or timed out.

#### Scenario: Human enters a value

- **WHEN** the agent asks for an API key and the human submits it on the entry page
- **THEN** the key is stored and redacted from then on, and the agent receives "stored" with the
  reference

#### Scenario: Entry link reused or opened from elsewhere

- **WHEN** an entry link is submitted a second time, or a submission comes from another origin or
  Host name
- **THEN** it is refused and the stored value, if any, is unchanged

#### Scenario: Agent does not wait

- **WHEN** the human has not answered within the call's wait time
- **THEN** the agent receives pending with an ask identifier it can poll with `approval_status`,
  and never the entry link

#### Scenario: Human declines

- **WHEN** the human declines or does not answer before the timeout
- **THEN** the agent receives "declined" or "timed out" and nothing is stored

### Requirement: approval_status and grants_list

The system SHALL provide `approval_status` for a given approval identifier, and `grants_list` for the
calling agent's active grants with reference, scope, expiry and remaining uses.

#### Scenario: Checking a pending approval

- **WHEN** an agent polls `approval_status` for a pending request
- **THEN** it receives pending, approved, denied or expired

### Requirement: Tools obey policy and identity

The system SHALL evaluate policy for every tool call with the caller's identity, and SHALL deny calls
whose identity is unknown or whose policy decision is deny. One agent SHALL NOT see another agent's
approvals or grants.

#### Scenario: Another agent's approval

- **WHEN** agent A calls `approval_status` with agent B's approval identifier
- **THEN** the call is refused as not found

### Requirement: Tool calls are audited

The system SHALL write an audit entry for every tool call with the agent identity, tool, reference,
decision and outcome, and no value.

#### Scenario: Generation is audited

- **WHEN** an agent generates a secret
- **THEN** the audit log records who, which reference, which store and when, without the value
