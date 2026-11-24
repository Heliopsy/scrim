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
audience, verified through the cluster (TokenReview), and SHALL derive the identity from namespace,
service account and pod: a configured agent name, else `<namespace>/<service account>`, kind `k8s`,
with those as labels. Tokens with another audience SHALL be refused, and the caller SHALL be unknown.

#### Scenario: Pod with a projected token

- **WHEN** a pod in namespace `agents` with service account `agent-a` calls scrim with its projected
  token
- **THEN** it is identified as `agents/agent-a` with its pod name attached

#### Scenario: Token with the wrong audience

- **WHEN** a pod presents its default API token instead of the scrim-audience token
- **THEN** the call is refused

#### Scenario: Two service accounts, two outcomes

- **WHEN** a rule denies injection for `agent.labels.service_account == "agent-b"` and pods running as
  `agent-a` and `agent-b` send the same request through the forward proxy
- **THEN** the request from `agent-a` is injected and the one from `agent-b` is refused, and each
  decision's audit entry names the caller as `kubernetes` with its namespace and service account

#### Scenario: Token never forwarded

- **WHEN** a pod sends its token in `x-scrim-session` to the base URL and as proxy credentials to a tool API
- **THEN** neither the provider nor the tool API receives the token, and it appears in no log or audit entry

### Requirement: Where pods send their service account token

Pods SHALL send the token as the password of the proxy user `k8s` on the forward proxy, as the value
of `x-scrim-session` on a base-URL listener, or as a bearer token on the agent API. The data plane SHALL
hand it to the control plane only inside the ask, SHALL NOT log or forward it, and the control plane
SHALL wipe it once the ask is answered.

#### Scenario: Proxy user k8s

- **WHEN** a pod sets `HTTPS_PROXY=http://k8s:<token>@scrim:3128` and calls a bound tool API
- **THEN** the ask carries the token, the decision names the pod's service account, and the tool API
  receives no proxy credentials

### Requirement: Verified Kubernetes tokens are redacted

Every service account token the cluster accepts for scrim's audience SHALL enter the redaction set
as soon as scrim verifies it, for redaction only (never injectable), and SHALL leave it when the
token expires (a token without an expiry 24 hours after its last verification). The copy SHALL live
in memory only and be wiped when it leaves. A token scrim never verified relies on the fallback JWT
detector.

#### Scenario: Agent reads its own token file

- **WHEN** a pod's verified token appears in a tool result the agent sends to a provider
- **THEN** the provider receives scrim's placeholder for it, never the token

#### Scenario: Token expires

- **WHEN** a verified token's expiry passes
- **THEN** it is removed from the redaction set and its copy is wiped

### Requirement: Verified Kubernetes tokens are cached briefly

The system SHALL reuse a verified token's identity for at most `identity.kubernetes.cache-ttl` and never
past the token's expiry, SHALL NOT cache refusals, and SHALL keep only a hash of the token as the cache
key.

#### Scenario: Pod deleted

- **WHEN** a pod's service account is deleted after its token was verified
- **THEN** the token is refused once the cache lifetime has passed

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
`Proxy-Authorization: Basic` on the forward proxy, or the `x-scrim-session` header on a base-URL
listener, each carrying a session or a service account token, neither of which SHALL be forwarded. A request with none of these
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

scrim SHALL be able to issue short-lived signed identity tokens (RS256 JWTs) for an agent identity
it established from the transport, one audience per token, and SHALL publish an OpenID Connect
discovery document and a JWKS under the issuer URL so stores and clouds can trust it as an identity
provider. Tokens SHALL be presented by scrim to stores on the agent's behalf and SHALL NOT be handed
to agents. An unknown caller SHALL get no token.

#### Scenario: OpenBao trusts scrim's tokens

- **WHEN** OpenBao's JWT auth is configured with scrim's discovery URL and a role bound to
  `agent=claude-laptop`
- **THEN** scrim logs in to OpenBao for that agent with a scrim-issued token and gets only that role's policy

#### Scenario: Another agent's token

- **WHEN** a token scrim signed for agent `intruder` is presented at the role bound to
  `agent=claude-laptop`
- **THEN** OpenBao refuses the login

#### Scenario: Wrong audience

- **WHEN** a token scrim signed for another audience is presented to OpenBao
- **THEN** OpenBao refuses the login

#### Scenario: Expired token

- **WHEN** a token scrim signed has expired
- **THEN** OpenBao refuses the login

#### Scenario: Unknown caller

- **WHEN** a token is requested for a caller scrim could not identify
- **THEN** no token is minted

### Requirement: Identity token claims

A token SHALL carry the agent name, how the agent was identified (`agent_kind`), the session, the
host for a local agent or the namespace, service account and pod for a Kubernetes agent, scrim's
profile and the audience. Its subject SHALL name the agent the same way in every session:
`agent:<name>`, or `k8s:<name>` for a Kubernetes agent.

#### Scenario: Two sessions of one agent

- **WHEN** tokens are minted for two `scrim run` sessions of agent `claude-laptop`
- **THEN** both have the subject `agent:claude-laptop` and each names its own session

### Requirement: The issuer listener serves discovery only

`identity.issuer.listen` SHALL serve the discovery document and the JWKS under the issuer URL's path
and nothing else. Both SHALL hold public keys only.

#### Scenario: Another path

- **WHEN** a client requests any other path on the issuer listener
- **THEN** it gets 404

### Requirement: Identity tokens are short-lived and redacted

An identity token SHALL expire after `identity.issuer.token-ttl` (between one minute and one hour,
ten minutes by default) and never after the session it names. Every token scrim mints SHALL enter
the redaction set when it is minted, for redaction only (never injectable), and SHALL leave it when
it expires. A token minted for the same claims and audience SHALL be reused while two thirds of its
lifetime remain, and tokens held for a session SHALL be dropped when the session ends.

#### Scenario: Token in a tool result

- **WHEN** a token scrim minted appears in text an agent sends to a provider
- **THEN** the provider receives scrim's placeholder for it

#### Scenario: Session ends first

- **WHEN** a token is minted for a session that ends in five minutes
- **THEN** the token expires when the session does

#### Scenario: Session ended

- **WHEN** a session ends while a token minted for it is cached
- **THEN** the cached token is never handed out again

### Requirement: Signing keys rotate without breaking tokens

scrim SHALL generate its signing keys in a private directory (mode 0700, key files 0600) and rotate
them every `identity.issuer.rotate-every`, and at start-up when overdue. The key that signs next
SHALL be published one rotation period before it signs. A replaced key SHALL stay published until
the last token it signed has expired plus five minutes, and then be deleted.

#### Scenario: Rotation with a live token

- **WHEN** the signing key rotates while a token it signed is still valid
- **THEN** the JWKS still holds the old key, OpenBao accepts both that token and a token from the new
  key, and the old key leaves the JWKS once the token has expired

### Requirement: Operator-managed signing keys

With `identity.issuer.signing-keys` set, scrim SHALL sign with the first of the operator's keys,
publish all of them and never rotate them, so replicas that share the reference agree on the JWKS.

#### Scenario: Replicas with operator keys

- **WHEN** two replicas share the same `identity.issuer.signing-keys` reference
- **THEN** both publish the same JWKS and sign with the same key

### Requirement: Signing keys are never disclosed

A signing key's private part SHALL NOT appear in any log line, error, metric, snapshot, API response
or the JWKS; logs and errors SHALL name keys only by their key ID (the RFC 7638 thumbprint). The
issuer URL SHALL be https, or http on a loopback host; plain http elsewhere SHALL require
`identity.issuer.insecure-http`, a weakening setting, since a verifier fetching keys over plain
http can be handed someone else's keys.

#### Scenario: Keys formatted for a log

- **WHEN** the issuer or one of its keys is formatted, logged or marshalled
- **THEN** the output holds the key ID and no private key material

#### Scenario: Plain http issuer

- **WHEN** `identity.issuer.url` is `http://scrim.example.test` without `identity.issuer.insecure-http`
- **THEN** scrim refuses to start and names both settings

### Requirement: Token exchange per store

Each adapter that supports federated login SHALL exchange an identity token scrim signs for the
agent for a short-lived store credential, as `identity.store-login` configures per store: `jwt`
(Vault and OpenBao JWT auth), `aws-web-identity` (AssumeRoleWithWebIdentity),
`gcp-workload-identity` (Google STS, optionally impersonating a service account), `azure-federated`
(Entra ID client assertion) or `infisical-oidc` (Infisical OIDC machine identities).

#### Scenario: AWS role per agent

- **WHEN** the IAM role `agent-claude-laptop` trusts scrim's identity provider for that agent's claims
- **THEN** scrim assumes that role for the agent with the session name `claude-laptop.<session>` and
  AWS CloudTrail shows the agent's session name

#### Scenario: OpenBao role per agent

- **WHEN** OpenBao's JWT auth trusts scrim's issuer, the role for `claude-laptop` may read
  `kv/agents/shared/*` and the role for `intruder` may not, and scrim's rules allow both to use
  `bao://kv/agents/shared/db`
- **THEN** the use by `claude-laptop` passes and the use by `intruder` is refused with OpenBao's denial

### Requirement: Exchanged store credentials are cached per agent

Store credentials obtained by token exchange SHALL be cached per agent identity, and per pod for a
Kubernetes agent, until two thirds of their lifetime has passed, and SHALL be wiped when the agent's
`scrim run` session ends.

#### Scenario: Session ends

- **WHEN** a `scrim run` session whose agent logged in to a store ends
- **THEN** the store credential cached for it is wiped and a later session of that agent logs in again

### Requirement: Store checks as the agent

After scrim's rules allow a use of a governed store's secret, the control plane SHALL check it with
the agent's own store identity, so the store's policy and audit apply to the agent. Where the store
can say what an identity may do (Vault and OpenBao `sys/capabilities-self`, Google Secret Manager
`testIamPermissions`) the value SHALL NOT be read with the agent's identity; elsewhere (AWS, Azure
Key Vault, Infisical) the check SHALL read it as the agent and wipe it unused.

#### Scenario: AWS role without access

- **WHEN** the role an agent assumes may not read the secret
- **THEN** the use is refused with the store's denial, although scrim's rules allow it

#### Scenario: Google principal without access

- **WHEN** the federated principal of an agent lacks `secretmanager.versions.access` on the secret
- **THEN** the use is refused without the value being read

### Requirement: Token exchange is configured safely

scrim SHALL refuse to start when `identity.store-login` names a store that does not exist or does
not take the method, or a token exchange method while `identity.issuer.url` is empty, naming the
setting. Options outside a method's list, a placeholder outside a templated option and malformed
values SHALL be refused the same way. `scrim doctor` SHALL report each agent of such a store as
`federated` with the method and options, which hold no credential.

#### Scenario: Method the store does not take

- **WHEN** `identity.store-login.bao` is `aws-web-identity role-arn:...` for an OpenBao store
- **THEN** scrim refuses to start and says the store takes `jwt`

#### Scenario: Issuer off

- **WHEN** a store logs agents in with `jwt` and `identity.issuer.url` is empty
- **THEN** scrim refuses to start and `scrim doctor` fails the store with a fix naming
  `identity.issuer.url`

### Requirement: Kubernetes identity passed through

In Kubernetes, scrim SHALL be able to use the agent pod's own service account identity toward stores
that trust the cluster (OpenBao Kubernetes auth), so the store's role for that service account applies.
After scrim's rules allow a use, scrim SHALL log in with the pod's token at the configured role and
SHALL refuse the use when that identity may not read the secret.

#### Scenario: Pod service account role

- **WHEN** an agent pod runs as service account `agents/reviewer` and OpenBao has a role for it
- **THEN** scrim's operations for that pod run under that role

#### Scenario: Two pods, two OpenBao roles

- **WHEN** OpenBao's role for `agents/agent-a` may read `kv/agents/a/*` only and the role for
  `agents/agent-b` may read `kv/agents/b/*` only, and both pods ask scrim to inject the credential at
  `bao://kv/agents/a/token`
- **THEN** the injection for `agent-a` succeeds and the one for `agent-b` is refused with the store's
  denial, although scrim's own rules allow both

### Requirement: Uses of governed stores are decided by the control plane

For a store with per-agent identity configured, every injection or restore of its secrets SHALL be
sent to the control plane, whatever the rules say, so the agent's store identity is always checked.

#### Scenario: Built-in injection rule

- **WHEN** an identified agent injects a credential from a store with `identity.store-login` and the
  only rule that applies is the built-in injection rule
- **THEN** the data plane asks the control plane, which checks the agent's store identity

### Requirement: Static per-agent store credentials as fallback

For stores without federated login, the system SHALL support a separate store credential per agent,
held by scrim and given by reference in `identity.store-credentials`, and SHALL report in `scrim doctor`,
per store and agent, which identity applies: passthrough, federated (token exchange), static,
shared (a store without per-agent identity) or none. An agent with no usable identity for a store that has per-agent identity SHALL be
refused for it.

#### Scenario: Vaultwarden per agent

- **WHEN** each agent has its own Vaultwarden account or organisation member configured
- **THEN** scrim decrypts and writes for that agent only with that agent's account

#### Scenario: Doctor lists the identity sources

- **WHEN** store `bao` has Kubernetes passthrough, store `vw` a static credential for agent `laptop`
  only, and store `env` neither
- **THEN** `scrim doctor` reports `bao` as passthrough for service accounts, `vw` as static for
  `laptop` and refused for other agents, and `env` as using scrim's own identity

### Requirement: Redaction coverage is separate from use

The redaction set SHALL be loaded with scrim's own read identity, the credentials of each store
instance, and SHALL cover secrets the agent cannot use, so a value an agent sees by accident is still
redacted. Per-agent identities SHALL govern use and writes only and SHALL never load the redaction
set. A stricter option SHALL limit the redaction set to what the agent's identity can read, and
SHALL be reported as weakening.

#### Scenario: Agent reads a file with someone else's secret

- **WHEN** an agent without access to `prod/payments` reads a log containing its value
- **THEN** the value is still redacted before reaching the provider

#### Scenario: Redaction never uses the agent's identity

- **WHEN** store `bao` has a static credential for agent `agent-a` whose policy reads only
  `kv/agents/a`, scrim's own `bao` credential reads `kv/prod/payments` and `kv/agents/a`, and both
  are redact targets
- **THEN** both values are loaded with scrim's credential and redacted from `agent-a`'s provider
  requests

### Requirement: Stricter per-agent redaction is weakening

The stricter option, `redaction.limit-to-agent-identity`, SHALL be off by default and reported as
weakening in logs, `scrim status` and `scrim doctor`. It SHALL leave out only values the store
refused that agent's identity, and only for provider requests carrying a token of that agent's
session; every other caller and path SHALL keep the whole redaction set.

#### Scenario: Stricter option narrows only proven sessions

- **WHEN** `redaction.limit-to-agent-identity` is on and OpenBao refuses `agent-a`'s credential
  for `kv/prod/payments`
- **THEN** a provider request from a session of `agent-a` that carries its token is not redacted
  for the payments value and is still redacted for `kv/agents/a`
- **AND** the same request with no session, a bare session id or a token of that session id with
  another secret is redacted for both
- **AND** start-up logs a warning naming the setting, and `scrim status` and `scrim doctor` report
  it as weakened

#### Scenario: Unknown answers stay redacted

- **WHEN** `redaction.limit-to-agent-identity` is on and the check of a value as `agent-a` fails or
  has not run yet
- **THEN** the value is redacted from `agent-a`'s sessions
