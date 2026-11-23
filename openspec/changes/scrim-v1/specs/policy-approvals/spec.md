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

#### Scenario: Conformance vectors

- **WHEN** the data plane evaluates every vector in `internal/policy/testdata/conformance.json`
- **THEN** each outcome, deciding rule and reason to ask equals the Go reference evaluator's

### Requirement: Provider requests are not stopped by the default

A provider request (`op` `llm.forward`) SHALL be refused only by a deny rule that matches it, or by
an ask rule or a rule the data plane cannot evaluate whose control-plane answer is not an allow. The
default decision SHALL NOT refuse provider requests, and break-glass deny-all SHALL NOT stop them,
since redaction applies to them whatever the rules say.

#### Scenario: Default deny and no forward rule

- **WHEN** the policy default is deny and no rule mentions `llm.forward`
- **THEN** provider requests are redacted and forwarded

#### Scenario: Break-glass during a session

- **WHEN** break-glass deny-all is engaged
- **THEN** provider requests are still redacted and forwarded, and no placeholder is restored or credential injected

#### Scenario: Control plane answers a provider ask

- **WHEN** the data plane asks about a provider request because a residual deny rule could match, and the control plane's full evaluation finds no rule matches
- **THEN** the control plane answers allow, since the default does not refuse provider requests

### Requirement: Asks are bounded

An operation the data plane sends to the control plane SHALL be held at most for the approval
timeout the snapshot carries, and SHALL be denied when no allow answer arrives in time or the
control plane's ask stream is not connected. The snapshot SHALL carry `approvals.timeout`, or the
longest per-rule approval timeout when a rule sets a longer one; each approval SHALL still expire
at its own rule's timeout.

#### Scenario: Rule with a longer approval timeout

- **WHEN** `approvals.timeout` is 2m and an ask rule sets `approval.timeout: 10m`
- **THEN** the snapshot's ask timeout is 10m, and an approval raised by another rule still expires after 2m

#### Scenario: Ask stream down

- **WHEN** the control plane's ask stream is closed and a request needs an ask
- **THEN** the request is denied at once

### Requirement: Rules only restrict restore

Restoring a placeholder into a response (`op` `restore`) SHALL be decided by the tool policy, and a
deny or ask rule that matches, could match or errors on the restore SHALL keep the placeholder. Allow
rules and the default decision SHALL NOT grant a restore the tool policy does not, and an ask SHALL
keep the placeholder rather than hold the response.

#### Scenario: Deny rule on restore

- **WHEN** a rule denies `op == "restore"` for references under `bao://kv/prod/` and a read tool call carries a placeholder of such a value
- **THEN** the tool receives the placeholder unresolved

#### Scenario: Default deny

- **WHEN** the policy default is deny and no rule matches a restore of a display value into a read tool
- **THEN** the value is restored

### Requirement: Restore request attributes

A restore request SHALL carry the tool name, the value's reference, catalog name, store, class and
labels, and the agent identity where the listener knows it. A rule condition on a field the data
plane does not have, including the labels of a value the snapshot carries none for, SHALL keep the
placeholder.

#### Scenario: Rule on an unknown agent

- **WHEN** a rule denies unknown callers and the listener cannot establish the agent's identity for a restore
- **THEN** the placeholder stays

#### Scenario: Rule on a store label

- **WHEN** a rule denies `op == "restore"` for values whose `secret.labels` hold `vaultwarden.collection.Prod`,
  and a model reply carries placeholders of two display values, one in that collection and one not
- **THEN** the data plane restores the value outside the collection and keeps the other's placeholder

#### Scenario: Value without labels

- **WHEN** a rule on `secret.labels` exists and the snapshot carries no labels for a value (an older control plane)
- **THEN** the data plane treats the labels as unknown and keeps the placeholder

### Requirement: Store labels in rules

Every request that names a secret (`store.write`, `secret.gen`, `store.read`, grants, `inject` and
`restore`) SHALL carry the secret's labels as `secret.labels` (secret-stores "Store-native metadata
labels"). A write or generate to an item that does not exist yet SHALL see the labels it would get.
`scrim policy eval` SHALL accept secret labels (`--label key=value`).

#### Scenario: Writes into a collection need approval

- **WHEN** a rule asks for `op in ["store.write", "secret.gen"]` when `"vaultwarden.collection.Prod" in secret.labels`
- **THEN** an agent's write to a Vaultwarden item in collection Prod waits for approval and a write elsewhere does not

#### Scenario: Write to an existing item scrim never loaded

- **WHEN** a rule asks for writes when `"vaultwarden.collection.Prod" in secret.labels`, and an agent overwrites an item in Prod that is in no redaction set
- **THEN** scrim looks the item's labels up in the store without keeping a value and the write waits for approval

#### Scenario: New item in a governed place

- **WHEN** a rule asks for writes whose `secret.labels["store.container"]` is `prod`, and an agent creates `bao://prod/new-token`, which does not exist yet
- **THEN** the write waits for approval

### Requirement: Unknown labels fail closed

When the store cannot answer a label lookup for a secret a request names, the system SHALL treat
`secret.labels` as unknown: a rule whose outcome depends on them SHALL count as erroring (deny and
ask match, allow does not), and the decision's audit entry SHALL name the failure. A lookup that
finds no such secret SHALL label the request as a new item instead.

#### Scenario: Store down during a governed write

- **WHEN** a rule asks for writes into collection Prod and the store fails the label lookup for the target
- **THEN** the write waits for approval and the audit entry records that the labels were unknown

### Requirement: Data plane decides on the same labels

The control plane SHALL send each value's labels that a policy condition reads to the data plane in
the snapshot, so `inject` and `restore` are decided on the labels the control plane would use, and
SHALL evaluate a data plane ask on its own labels for the secret, not on labels the ask carries.
A snapshot whose policy reads no labels SHALL carry none.

#### Scenario: Only the labels rules read

- **WHEN** the only label condition is `"vaultwarden.collection.Prod" in secret.labels`
- **THEN** each value in the snapshot carries at most that one label, and with no label condition none

#### Scenario: Injection governed by an organisation

- **WHEN** a rule denies `inject` of credentials whose `secret.labels["vaultwarden.org"]` is `Acme` toward hosts outside `*.acme.example`
- **THEN** the data plane refuses such an injection without asking the control plane

#### Scenario: Ask carries forged labels

- **WHEN** the data plane asks about an injection and the ask's request carries labels that differ from the control plane's for that secret
- **THEN** the control plane decides on its own labels

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

### Requirement: Notifier plugins

The system SHALL deliver approval requests through notifier plugins configured in `notify.plugins`
under the plugin contract (docs/plugins.md, design D15), with the request summary and decision links
and no value. A plugin failure SHALL fail that delivery with an error naming the plugin and holding
no decision link, and SHALL NOT approve anything.

#### Scenario: Notifier plugin delivers

- **WHEN** a notifier plugin is configured and an approval is raised
- **THEN** the plugin receives the agent, action, reference, rule, reason, expiry and both decision
  links

#### Scenario: Notifier plugin fails

- **WHEN** a notifier plugin exits or does not answer within its timeout
- **THEN** that delivery fails with an error naming the plugin, the other notifiers still deliver,
  and the plugin is started again for the next request

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

#### Scenario: Approval for one operation only

- **WHEN** an ask rule with grant scope `once` is approved
- **THEN** the held operation proceeds, no grant is created, and the next matching operation asks
  again

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
