## Purpose

Establishes which agent is behind every request scrim handles, on a single machine and in a cluster,
so that policy, grants and audit apply to the right agent and one agent cannot act as another.

## ADDED Requirements

### Requirement: Identity on every request

The system SHALL resolve an agent identity for every provider request, tool call, injection and
admin call before policy is evaluated, and SHALL attach that identity to the decision and the audit
entry.

#### Scenario: Audit shows the caller

- **WHEN** an agent's provider request is redacted and forwarded
- **THEN** the audit entry names the agent identity that sent it

### Requirement: Unknown identity is denied by default

The system SHALL treat a caller whose identity cannot be established as unknown and SHALL apply the
configured default for unknown callers, which SHALL be deny unless an operator configures otherwise.
Redaction SHALL still apply to any traffic it does forward.

#### Scenario: Process without a session

- **WHEN** a process with no session token connects to the injection proxy
- **THEN** credential injection is refused for it

#### Scenario: Operator allows unknown callers for redaction only

- **WHEN** the default for unknown callers is set to redact-only
- **THEN** their provider requests are redacted and forwarded, but they receive no injection, tools or
  grants

### Requirement: Unix socket peer credentials

The system SHALL identify local callers on its Unix socket by the operating system's peer
credentials (user, group and process) and SHALL map them to agent identities through configuration.

#### Scenario: Agent running as a mapped user

- **WHEN** a process running as user `agent1` connects over the socket
- **THEN** it is identified as the agent mapped to `agent1`

### Requirement: Session tokens from scrim run

The system SHALL mint a session token for each `scrim run` invocation, bound to the launched process
tree and the caller's peer credentials, and SHALL pass it to the agent through its environment and MCP
configuration.

#### Scenario: Two wrapped agents

- **WHEN** a user starts two agents with `scrim run`
- **THEN** each gets its own session token and identity, and their grants are separate

### Requirement: Tokens expire and can be revoked

The system SHALL give every agent token an expiry and SHALL let an operator revoke a token or all
tokens of an agent at once. A revoked or expired token SHALL be refused on every path.

#### Scenario: Session ends

- **WHEN** the process started by `scrim run` exits
- **THEN** its session token is revoked

#### Scenario: Revoked token reused

- **WHEN** a revoked token is presented
- **THEN** the call is refused and audited as a revoked credential

### Requirement: Kubernetes service account identity

The system SHALL identify in-cluster callers by projected service account tokens with a scrim-specific
audience, verified through the cluster, and SHALL derive the identity from namespace, service account
and pod. Tokens with another audience SHALL be refused.

#### Scenario: Pod with a projected token

- **WHEN** a pod in namespace `agents` with service account `agent-a` calls scrim with its projected
  token
- **THEN** it is identified as `agents/agent-a` with its pod name attached

#### Scenario: Token with the wrong audience

- **WHEN** a pod presents its default API token instead of the scrim-audience token
- **THEN** the call is refused

### Requirement: Optional mutual TLS identity

The system SHALL accept client certificates, including SPIFFE identities, as an agent identity source
when configured, and SHALL refuse certificates that do not chain to a configured trust root or are
expired.

#### Scenario: SPIFFE identity

- **WHEN** a workload presents a valid certificate for `spiffe://example.org/agents/builder`
- **THEN** it is identified by that SPIFFE ID

### Requirement: Grants belong to one identity

The system SHALL bind every grant and approval to the identity that requested it, and SHALL NOT let
any other identity use, see or settle it.

#### Scenario: Grant used from another agent

- **WHEN** agent B sends a request that would match agent A's grant
- **THEN** the grant does not apply to agent B

### Requirement: Per-agent policy scoping

The system SHALL let policy be scoped by identity attributes (agent name, user, namespace, service
account, labels, SPIFFE ID), so each agent can be limited to its own secrets, destinations and tools.

#### Scenario: Two agents with different scopes

- **WHEN** agent A may use GitHub and agent B only read-only Hetzner
- **THEN** agent B's request to use the GitHub credential is denied

### Requirement: Identity is not taken from request content

The system SHALL derive identity only from the transport (socket peer, token, certificate) and SHALL
ignore any identity claimed in a provider request body, header added by the agent, or tool argument.

#### Scenario: Agent claims another identity in a header

- **WHEN** a request carries a header naming another agent
- **THEN** scrim uses the transport identity and ignores the header
