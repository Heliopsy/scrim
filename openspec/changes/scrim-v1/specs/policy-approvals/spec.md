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

### Requirement: Rule errors only tighten decisions

When a rule cannot be evaluated for a request (for example it reads an agent label the agent does
not have), the system SHALL treat a deny or ask rule as matching and an allow rule as not matching,
and SHALL record the error with the decision.

#### Scenario: Allow rule reads a missing label

- **WHEN** the only rule allows agents whose label `team` is `infra` and an agent without a `team`
  label makes a request
- **THEN** the default decision applies and the decision records the rule error

#### Scenario: Deny rule reads a missing label

- **WHEN** a rule denies agents whose label `team` is not `infra` and an agent without a `team`
  label makes a request
- **THEN** the request is denied

### Requirement: Data-plane decisions equal control-plane decisions

The data plane SHALL decide a request locally only when its decision and deciding rule are certain
to equal the control plane's full evaluation, and SHALL send every other request to the control
plane. A rule part the data plane cannot evaluate SHALL cause a control-plane call only when it could
change the outcome. While break-glass deny-all is engaged the data plane SHALL deny without
evaluating rules.

#### Scenario: Time-based rule does not slow unrelated requests

- **WHEN** a deny rule applies only to `store.write` at night and an agent sends an injection that a
  simple allow rule covers
- **THEN** the data plane allows it without calling the control plane

#### Scenario: Time-based rule could decide

- **WHEN** the same night-time deny rule exists and an agent makes a `store.write`
- **THEN** the data plane asks the control plane, which evaluates the time and decides

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

#### Scenario: Opening a link does not decide

- **WHEN** a decision link is opened with GET, for example by a link preview
- **THEN** a confirmation page is shown and the approval stays pending until the page is submitted

#### Scenario: Expired link

- **WHEN** a decision link is used after its approval's timeout
- **THEN** it is rejected and the approval is expired

### Requirement: Generic webhook protocol

The system SHALL offer a webhook notifier that posts a signed approval request to a configured URL and
accepts the decision either in the response or later through a signed callback or poll, within the
approval timeout. The request and response format SHALL be compatible with nono's approval webhook
protocol v1 (submit-then-poll). A decision received through the webhook SHALL settle the approval
through the same single-use token check as any other decision link.

#### Scenario: External approver decides later

- **WHEN** the webhook receiver acknowledges and posts a signed decision a minute later
- **THEN** the pending approval is settled by that decision

#### Scenario: Receiver answers with an error

- **WHEN** the webhook receiver answers a poll with an error status or a redirect
- **THEN** the approval is not settled by it and stays pending until another notifier decides or it
  expires as denied

#### Scenario: Approval service shared with nono

- **WHEN** the webhook URL points at an approval service implementing nono's approval webhook
  protocol v1
- **THEN** it receives the request as an `endpoint` approval with the destination host, method and
  path, and its granted or denied answer settles the approval

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
bounded, documented delay. With a shared state backend that delay SHALL be zero: grants are read on
every use, so expiry and revocation take effect on the next request.

#### Scenario: Revoked grant on another replica

- **WHEN** an operator revokes a grant on one replica
- **THEN** requests reaching any other replica stop using it within the documented delay

#### Scenario: Approver asks for too long

- **WHEN** an approver approves with a duration longer than the rule's maximum
- **THEN** the grant is created with the maximum and the result says it was capped

#### Scenario: Grant expires between two requests

- **WHEN** a grant expires after one request and before the next
- **THEN** the next request is evaluated as if no grant existed

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

#### Scenario: Paging through a long log

- **WHEN** a query matches more entries than its limit
- **THEN** the result names a cursor, and the same query with that cursor returns the next older entries without repeating any

### Requirement: Audit entry written with its change

An audit entry recorded through the state backend SHALL be written in the same transaction as the
state change it records. A failure between the two writes SHALL leave neither, and a change that
comes without an audit entry SHALL be refused.

#### Scenario: Connection lost before the audit write

- **WHEN** the database connection is lost after a grant is written and before its audit entry is
- **THEN** neither the grant nor the entry exists afterwards and the operation reports an error

### Requirement: Break-glass deny-all

The system SHALL provide a switch, available through the CLI, the admin API and configuration, that
denies every injection, grant and approval at once while redaction continues. Turning it off SHALL
need an explicit operator action.

#### Scenario: Deny-all engaged

- **WHEN** an operator engages deny-all
- **THEN** all pending approvals are denied, grants stop being honoured, and provider redaction keeps
  working

#### Scenario: Restart while engaged

- **WHEN** scrim restarts with a durable state backend while deny-all is engaged
- **THEN** deny-all is still engaged until an operator releases it

#### Scenario: Engaged in configuration

- **WHEN** `policy.deny-all` is set in configuration and an operator runs `scrim deny-all off`
- **THEN** the command is refused and names the setting
