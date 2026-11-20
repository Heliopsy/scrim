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

#### Scenario: Many session tokens in one snapshot

- **WHEN** several session tokens are live at once, from concurrent or earlier `scrim run` sessions
- **THEN** every token is in the redaction set and the data plane accepts the snapshot that carries them

#### Scenario: Token used from outside the session's process tree

- **WHEN** a process of the same user that did not descend from the `scrim run` that minted a token
  presents that token
- **THEN** the call is refused and audited as a token used outside its process tree

#### Scenario: Refused token is not retried as the peer

- **WHEN** a caller presents a token that is refused
- **THEN** the call fails, even though the caller's peer credentials alone would map to an agent

#### Scenario: Session cannot mint sessions

- **WHEN** a process holding a session token asks for a new session token
- **THEN** the request is refused

### Requirement: Tokens expire and can be revoked

The system SHALL give every agent token an expiry and SHALL let an operator revoke a token or all
tokens of an agent at once. A revoked or expired token SHALL be refused on every path.

#### Scenario: Session ends

- **WHEN** the process started by `scrim run` exits
- **THEN** its session token is revoked

#### Scenario: scrim run killed

- **WHEN** the `scrim run` process that minted a token dies without revoking it
- **THEN** scrim revokes the token once it sees the process is gone

#### Scenario: Revoked token reused

- **WHEN** a revoked token is presented
- **THEN** the call is refused and audited as a revoked credential

### Requirement: Sessions are kept in the state backend

The system SHALL store session tokens in the configured state backend, keeping only a hash of each
token, and SHALL record creating and revoking a session in the audit log without the token or its
hash. With a durable backend a session and its revocation SHALL survive a control plane restart;
with the `memory` backend a restart SHALL end every session.

#### Scenario: Restart with a durable backend

- **WHEN** scrim with `state.backend: sqlite` restarts while a `scrim run` session is active
- **THEN** the session's token is still accepted from its process tree after the restart

#### Scenario: Revocation survives a restart

- **WHEN** a session is revoked and scrim then restarts with a durable backend
- **THEN** the token is refused as revoked

#### Scenario: Restart with the memory backend

- **WHEN** scrim with `state.backend: memory` restarts while a `scrim run` session is active
- **THEN** the session's token is refused

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

### Requirement: Data-plane identity from the transport

The data plane SHALL take a request's caller only from its transport: Unix socket peer credentials,
`Proxy-Authorization: Basic <session id>:<token>` on the forward proxy, or the `x-scrim-session`
header on a base-URL listener, neither of which SHALL be forwarded. A request with none of these
SHALL be an unknown caller. A rule on the agent of a request that carries one SHALL be decided by
the control plane, with what the transport said in the ask.

#### Scenario: Request without a session

- **WHEN** a request through the forward proxy names no session and a rule denies unknown callers
- **THEN** the data plane refuses it without asking the control plane

#### Scenario: Request naming a session

- **WHEN** a provider request carries `x-scrim-session` and a rule on `agent.session` could deny it
- **THEN** the data plane asks the control plane with the session id, and the provider never sees the header

### Requirement: Session tokens stay out of the data plane

The data plane SHALL NOT log, keep or forward a session token. It SHALL reduce a token to its
stored verifier on arrival and send the control plane only a proof bound to the one ask (design
D14).

#### Scenario: Token on the proxy connection

- **WHEN** a client with `HTTPS_PROXY=http://<session id>:<token>@host:port` sends a request through the tool proxy
- **THEN** the ask carries the session id and a proof of the token, and neither the token nor the proxy credentials reach the tool API

### Requirement: Data-plane callers are verified by the control plane

The control plane SHALL resolve the caller of every ask before it evaluates the rules, ignoring
agent fields in the asked request. A named session SHALL be its agent only with a valid proof of
its token for that ask, while active, and for a Unix peer only from its user and process tree. Any
other caller SHALL be evaluated as unknown without falling back to its peer mapping, and the audit
entry SHALL record how the caller was identified and why a session was refused.

#### Scenario: Ask rule on the agent

- **WHEN** an agent started by `scrim run` sends a provider request and an ask rule matches its session's agent
- **THEN** the approval names that agent and session

#### Scenario: Bare session id

- **WHEN** a request names a valid session id without its token
- **THEN** the control plane evaluates it as an unknown caller and audits it as refused for lack of proof

#### Scenario: Proof replayed for another ask

- **WHEN** an ask carries a proof computed for a different ask id or deadline
- **THEN** the caller is refused and evaluated as unknown

### Requirement: Unix peers inside a session's tree

A Unix socket peer without a session SHALL be the innermost active session of its user whose
process tree it is in, else its configured peer mapping, else unknown.

#### Scenario: Agent's own child over the Unix socket

- **WHEN** a process descended from a `scrim run` session connects to the Unix socket listener without a token
- **THEN** it is evaluated as that session's agent

### Requirement: scrim run identifies the session to the data plane

`scrim run` SHALL point the agent's proxy variables at the forward proxy with the session id and
token as proxy credentials, and SHALL make agents whose presets support custom headers send
`x-scrim-session` with the token on base-URL requests (Claude Code through
`ANTHROPIC_CUSTOM_HEADERS`). It SHALL NOT print the token: `--print-env` SHALL show a marker in its
place. Where an agent cannot send the header, its base-URL requests SHALL be documented as unknown
callers.

#### Scenario: Claude Code under scrim run

- **WHEN** Claude Code runs under `scrim run`
- **THEN** its provider requests carry `x-scrim-session` and its tool traffic carries the session as proxy credentials, and `--print-env` shows neither token

### Requirement: Identity is not taken from request content

The system SHALL derive identity only from the transport (socket peer, token, certificate) and SHALL
ignore any identity claimed in a provider request body, header added by the agent, or tool argument.

#### Scenario: Agent claims another identity in a header

- **WHEN** a request carries a header naming another agent
- **THEN** scrim uses the transport identity and ignores the header

### Requirement: Agents act on stores with their own identity

When configured, scrim SHALL perform every store operation on an agent's behalf (inject, generate,
capture, write) with a store identity belonging to that agent, not with scrim's own identity, so the
store's own permissions and audit apply per agent. An agent without a usable store identity SHALL be
refused for that store.

#### Scenario: Store policy narrower than scrim policy

- **WHEN** scrim's rules allow agent `claude-laptop` to use `bao://kv/prod/db` but the OpenBao policy
  for that agent's identity does not
- **THEN** the operation is refused with the store's denial and audited in both places

### Requirement: Effective permission is the intersection

An operation SHALL succeed only when both scrim's policy and the store's permissions for the agent's
identity allow it. Neither side SHALL be able to widen what the other denies.

#### Scenario: Store allows more than scrim

- **WHEN** the store would let the agent read `kv/prod/*` but scrim's rules deny `kv/prod/payments`
- **THEN** scrim refuses `kv/prod/payments` without contacting the store

### Requirement: scrim as an identity provider for agents

scrim SHALL be able to issue short-lived signed identity tokens for each agent session, with claims
for agent name, session, host or namespace, profile and audience, and SHALL publish standard
discovery and signing keys so stores and clouds can trust it as an identity provider. Signing keys
SHALL rotate without breaking live sessions.

#### Scenario: OpenBao trusts scrim's tokens

- **WHEN** OpenBao's JWT auth is configured with scrim's discovery URL and a role bound to
  `agent=claude-laptop`
- **THEN** scrim logs in to OpenBao for that agent with a scrim-issued token and gets only that role's policy

### Requirement: Token exchange per store

Each adapter that supports federated login SHALL exchange the agent's identity token for a
short-lived store credential: Vault and OpenBao JWT/OIDC auth, AWS AssumeRoleWithWebIdentity, Google
Workload Identity Federation, Azure federated credentials, Infisical OIDC machine identities. Store
credentials SHALL be cached per agent session and dropped when it ends.

#### Scenario: AWS role per agent

- **WHEN** the IAM role `agent-claude-laptop` trusts scrim's identity provider for that agent's claims
- **THEN** scrim assumes that role for the agent and AWS CloudTrail shows the agent's session name

### Requirement: Kubernetes identity passed through

In Kubernetes, scrim SHALL be able to use the agent pod's own service account identity toward stores
that trust the cluster (for example Vault or OpenBao Kubernetes auth), so the store's role for that
service account applies, instead of a scrim-issued token.

#### Scenario: Pod service account role

- **WHEN** an agent pod runs as service account `agents/reviewer` and OpenBao has a role for it
- **THEN** scrim's operations for that pod run under that role

### Requirement: Static per-agent store credentials as fallback

For stores without federated login, the system SHALL support a separate store credential per agent,
held by scrim and referenced in configuration, and SHALL report in `scrim doctor` which stores fall
back to shared identity because no per-agent credential exists.

#### Scenario: Vaultwarden per agent

- **WHEN** each agent has its own Vaultwarden account or organisation member configured
- **THEN** scrim decrypts and writes for that agent only with that agent's account

### Requirement: Redaction coverage is separate from use

The redaction set SHALL be loaded with scrim's own read identity and SHALL cover secrets the agent
cannot use, so a value an agent sees by accident is still redacted. Per-agent identities SHALL govern
use and writes only. A stricter option SHALL limit the redaction set to what the agent's identity can
read, and SHALL be reported as weakening.

#### Scenario: Agent reads a file with someone else's secret

- **WHEN** an agent without access to `prod/payments` reads a log containing its value
- **THEN** the value is still redacted before reaching the provider
