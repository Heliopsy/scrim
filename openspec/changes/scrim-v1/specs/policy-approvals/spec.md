## Purpose

Decides whether each use, request or creation of a secret is allowed, denied or needs a human, runs
the approval flow and just-in-time grants, and records every decision in an audit log without values.

## ADDED Requirements

### Requirement: Rules over request attributes

The system SHALL evaluate expression-based rules over the agent identity, secret reference, store,
provider, destination host, method and path, tool or command, and time. Each rule SHALL yield allow,
deny or ask. Rules SHALL be evaluated before anything is forwarded, injected, stored or granted.

#### Scenario: Writes to an API need approval

- **WHEN** a rule says ask for non-GET requests to `api.github.com` using `bao://kv/agents/github`
- **THEN** a GET is injected immediately and a POST waits for approval

#### Scenario: Rule refers to the agent

- **WHEN** a rule allows `bao://kv/prod/*` only for agents in namespace `deploy`
- **THEN** an agent in namespace `agents` is denied

### Requirement: Rule evaluation order and default decision

The system SHALL apply a documented, deterministic order to rules (deny over ask over allow when
several match) and SHALL apply a configurable default decision when no rule matches. The shipped
default SHALL be deny.

#### Scenario: No rule matches

- **WHEN** a request matches no rule and no default is configured
- **THEN** it is denied

#### Scenario: Deny and allow both match

- **WHEN** one rule allows and another denies the same request
- **THEN** the request is denied

### Requirement: Invalid rules fail closed

The system SHALL validate rules when configuration loads. A configuration with an invalid rule SHALL
be rejected; on reload, scrim SHALL keep the previous valid rules and report the error.

#### Scenario: Typo in a rule on reload

- **WHEN** a reloaded configuration contains a rule that does not compile
- **THEN** the previous rules stay in force and the error is logged and exposed in health status

### Requirement: Ask creates a pending approval

The system SHALL turn an ask decision into a pending approval holding the agent identity, reference,
destination or tool, and reason, and SHALL hold the operation until a decision arrives. When the
approval timeout elapses without a decision, the operation SHALL be denied.

#### Scenario: Nobody answers

- **WHEN** an approval is not answered within its timeout
- **THEN** the held operation fails as denied and the approval is marked expired

### Requirement: Notifiers

The system SHALL deliver approval requests through one or more configured notifiers: ntfy with action
buttons, Telegram, Slack, a generic signed webhook using submit-then-poll, the terminal
(`scrim approve` / `scrim deny`) and optionally tix. A notifier failure SHALL NOT approve anything.

#### Scenario: Two notifiers configured

- **WHEN** ntfy and Telegram are both configured
- **THEN** the request appears on both, and the first decision received settles it

#### Scenario: Notifier unreachable

- **WHEN** every configured notifier fails to deliver
- **THEN** the approval stays pending until timeout and is then denied

### Requirement: Approval messages contain no values

The system SHALL include in an approval request the agent identity, reference, destination, method,
tool, reason and a request summary, and SHALL NOT include any secret value or unredacted request body.

#### Scenario: Approval for a request with a secret in its body

- **WHEN** an approval is raised for a request whose body contains a secret
- **THEN** the notification shows the placeholder, not the value

### Requirement: Single-use, signed decisions

The system SHALL bind each approve or deny action to one pending approval through a signed,
single-use token with an expiry. A replayed, forged, expired or mismatched token SHALL be rejected.

#### Scenario: Button tapped twice

- **WHEN** an approve button is used a second time
- **THEN** the second use is rejected and changes nothing

#### Scenario: Token for another approval

- **WHEN** a decision token issued for approval A is submitted for approval B
- **THEN** it is rejected

### Requirement: Generic webhook protocol

The system SHALL offer a webhook notifier that posts a signed approval request to a configured URL and
accepts the decision either in the response or later through a signed callback or poll, within the
approval timeout.

#### Scenario: External approver decides later

- **WHEN** the webhook receiver acknowledges and posts a signed decision a minute later
- **THEN** the pending approval is settled by that decision

### Requirement: Just-in-time grants

The system SHALL create a grant when an approval is approved or a request is allowed with a duration.
A grant SHALL carry the agent identity, reference, scope (destinations, tools), expiry and an optional
use count, and SHALL let matching operations through without a new approval until it ends.

#### Scenario: Grant covers repeated calls

- **WHEN** an agent holds a 30-minute grant for `bao://kv/agents/hetzner` toward `api.hetzner.cloud`
- **THEN** calls within 30 minutes proceed without asking

#### Scenario: Use count exhausted

- **WHEN** a grant with one use has been used
- **THEN** the next matching operation is evaluated as if no grant existed

### Requirement: Grant limits and revocation

The system SHALL enforce a configurable maximum grant duration per rule, SHALL let an operator revoke
a grant at once, and SHALL stop honouring an expired or revoked grant on every replica within a
bounded, documented delay.

#### Scenario: Revoked grant on another replica

- **WHEN** an operator revokes a grant on one replica
- **THEN** requests reaching any other replica stop using it within the documented delay

### Requirement: Durability of approvals and grants

The system SHALL persist pending approvals and grants in the configured state backend so they survive
a restart. With the memory backend, a restart SHALL drop them, denying held operations rather than
approving them.

#### Scenario: Restart with SQLite

- **WHEN** scrim restarts while a grant is active and the state backend is SQLite
- **THEN** the grant is still honoured until its expiry

#### Scenario: Restart with memory state

- **WHEN** scrim restarts with the memory backend
- **THEN** previous grants are gone and pending operations end as denied

### Requirement: Audit log

The system SHALL record an audit entry for every decision, approval, grant, revocation, store write,
generation, capture and credential injection, holding identity, reference, destination, decision,
outcome and time, and never a value.

#### Scenario: Injection is audited

- **WHEN** a credential is injected toward its bound host
- **THEN** the audit log records the agent, reference, host, method and decision

### Requirement: Querying the audit log

The system SHALL let operators query the audit log by agent, reference, decision, time range and
outcome through the CLI and the admin API, with machine-readable output.

#### Scenario: Last hour of asks for one agent

- **WHEN** an operator queries asks for agent `claude-laptop` in the last hour
- **THEN** only matching entries are returned, newest first

### Requirement: Break-glass deny-all

The system SHALL provide a switch, available through the CLI, the admin API and configuration, that
denies every injection, grant and approval at once while redaction continues. Turning it off SHALL
need an explicit operator action.

#### Scenario: Deny-all engaged

- **WHEN** an operator engages deny-all
- **THEN** all pending approvals are denied, grants stop being honoured, and provider redaction keeps
  working
