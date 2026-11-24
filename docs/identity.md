# Agent identity

Every call to scrim's local agent API is attributed to an agent before policy runs, and the
decision and audit entry name that agent. Identity comes only from the transport: the Unix socket's
peer credentials, plus a session token when the caller has one. Nothing in a request body, header
or tool argument can change it.

This page covers local identity, Kubernetes service accounts and scrim as an identity provider for
stores. scrim 1.0 does not accept client certificates as an agent identity, although the
agent-identity spec describes them.

## Peer credentials

When a process connects to the API socket, the kernel records who it is. scrim reads that record:

| Platform | Mechanism | What it reports |
| --- | --- | --- |
| Linux | `SO_PEERCRED` | user, group, process |
| macOS | `LOCAL_PEERCRED`, `LOCAL_PEERPID` | user, primary group, process |
| Windows | `SIO_AF_UNIX_GETPEERPID`, the process token's user | process, and whether it runs as scrim's account |
| others | none | the caller is unknown and refused |

Windows has no user IDs: a caller running as the account scrim runs as is that account's agent,
any other account is unknown, and `identity.peers` can name only scrim's own account
([limitations.md](limitations.md#platforms)).

The caller cannot forge these values. scrim maps them to an agent with `identity.peers`:

```yaml
identity:
  peers:
    claude: "user:agent1"
    ci: "group:ci-agents scope:secrets:list label:team=infra"
```

Each key is an agent name (lower case, digits, `.`, `_`, `-`). Each value lists selectors separated
by spaces:

| Selector | Matches |
| --- | --- |
| `uid:N`, `user:NAME` | the peer's user |
| `gid:N`, `group:NAME` | the peer's primary group |
| `scope:S` | limits the agent to scope S (repeatable; default all) |
| `label:K=V` | an attribute policy rules can match |

A user match wins over a group match. Mapping one user or group to two agents is a configuration
error. With no `identity.peers`, the user scrim runs as is one agent named after that user, and
every other local user is unknown. Unknown callers get no tools.

The socket is created with mode `0600` (`api.permissions`), so by default only scrim's own user
can connect. To serve agents running as other users, widen it (for example `0660` with a shared
group) and map those users; the mode only decides who may connect, never who they are.

Check the result from inside an agent's environment:

```sh
scrim api whoami
```

### Scopes

| Scope | Allows |
| --- | --- |
| `secrets:list` | `secrets_list` |
| `secrets:request` | `secret_request`, `approval_status`, `grants_list` |
| `secrets:write` | `secret_gen`, `secret_capture`, `secret_ask_human`, `scrim secret put` |
| `sessions:mint` | minting session tokens; never held by a session |

## Session tokens

On a single-user machine every agent runs as the same Unix user, so peer credentials alone cannot
tell two agents apart. `scrim run` therefore mints a session token for each agent it starts
(`POST /v1/sessions`) and passes it in `SCRIM_SESSION_TOKEN`; `scrim mcp` and `scrim secret`
present it as `Authorization: Bearer`.

A token is:

- **opaque**: `scrim_st_<id>_<secret>`, 256 random bits in the secret part
- **hashed at rest**: only a SHA-256 of the secret part is stored, keyed by the public ID; the
  token is returned once, to the minting process
- **bound to a user**: it is accepted only from a peer with the minting user's ID
- **bound to a process tree**: it is accepted only from the minting process (`scrim run`) or one
  of its descendants. scrim walks the caller's parents (`/proc/<pid>/stat` on Linux,
  `kern.proc.pid` on macOS) and compares PID and start time, so a later process that reuses the PID
  does not count. Where the process tree cannot be read, the token is refused.
- **scoped**: it carries the minter's agent scopes or a subset, never `sessions:mint`
- **expiring**: `session.ttl` (default 12h), at most `session.max-ttl` (default 7 days)

The tree binding is what keeps agents apart on one machine. A second agent of the same user can
read the first agent's environment from `/proc`, but a token presented from outside the tree it was
minted for is refused and audited as `outside the session's process tree`.

### Principals

Grants, approvals and asks belong to a principal:

| Caller | Principal |
| --- | --- |
| peer credentials only | `<agent>` |
| session | `<agent>/<session id>` |

Two `scrim run` sessions of the same agent, and the agent's plain peer identity, are three
principals. None can see or use another's grants, approvals or asks: another principal's approval
is reported as not found. Policy rules still match on the agent name, with the session ID and
labels available as attributes.

### Refusals

A presented token that fails is an error, never a fall-back to the caller's peer identity, so a
stolen or stale token cannot be retried as something else. The caller is only told the token was
refused; the audit entry (action `tool.auth`) records why:

| Reason | Meaning |
| --- | --- |
| `malformed` | not shaped like a token |
| `unknown` | no such session, or the secret part does not match |
| `revoked` | the session was ended or revoked |
| `expired` | past its expiry |
| `wrong user` | presented by another Unix user |
| `outside the session's process tree` | presented by a process that did not descend from `scrim run` |

### Ending a session

- `scrim run` ends its own session when the agent exits (`DELETE /v1/sessions/self`).
- If `scrim run` is killed first, the control plane notices within 15 seconds that the session's
  root process is gone and revokes the token (`root exited`).
- A process of the same user with `sessions:mint` can revoke any session of that user
  (`DELETE /v1/sessions/{id}`).

### Where sessions are kept

Sessions are rows in the [state backend](state-and-observability.md#state-backends), next to
grants and approvals. A row holds the session ID, agent, name, user, the root process (PID, parent
and start time), scopes, labels, times and why it ended; of the token it holds only the hash.
Creating and revoking a session each write an audit entry and an event, `session.created` and
`session.revoked`, with the session ID, agent, user, name and reason, never the hash.

- With `sqlite` or `postgres`, sessions survive a control plane restart: a `scrim run` started
  before the restart keeps working after it, and a revoked session stays revoked. With
  `postgres`, every replica sees the same sessions.
- With `memory`, a restart ends every session, which is the safe direction.

The token is bound to the root process's PID and start time, so after a reboot (new start times) no
old session matches any process and every old token is refused as `outside the session's process
tree`.

## Provider and tool traffic

The data plane serves the agent's provider requests and tool traffic, and holds no session
verifiers and no `identity.peers` mapping. It reads what the transport carries and leaves the
rest to the control plane:

| Listener | What the data plane reads |
| --- | --- |
| Unix socket base URL | the kernel's peer credentials (user, group, process) |
| forward proxy | `Proxy-Authorization: Basic <session id>:<token>`, which clients send for `HTTPS_PROXY=http://<session id>:<token>@127.0.0.1:<port>` |
| TCP base URL | the `x-scrim-session: <token>` header (Claude Code sends it through `ANTHROPIC_CUSTOM_HEADERS`) |

Neither the proxy credentials nor the header are forwarded: `Proxy-Authorization` ends at the
proxy, and the base-URL listener strips `x-scrim-session`. The token is in the redaction set as
well, so it cannot reach a provider in a request body either.

A request that carries none of these is an unknown caller (`agent.known` is false), and rules on
it are decided in the data plane. A request that carries any of them is an agent the data plane
cannot place: a rule that depends on the agent goes to the control plane, and the ask carries what
the transport said (`AskCaller` in `proto/scrim/dataplane/v1`). A restore cannot wait for an
answer, so a restore rule on the agent keeps the placeholder for such a request.

### How the control plane verifies an ask's caller

The data plane cannot verify a session, and it must not hold or log tokens. When a request carries
a token, the data plane reduces it on arrival to its verifier, the SHA-256 the control plane
stores for the session, and forgets the token. An ask about that request carries only a proof:
an HMAC keyed with the verifier over the session id, the ask id and the ask deadline
(`AskCaller.session_proof`; design D14). The control plane recomputes it from the stored hash.
The proof is good for one ask only and reveals neither the token nor the hash.

| What the ask carries | Who the rules see |
| --- | --- |
| a session and a valid proof | that session's agent (`agent.kind == "session"`, `agent.session`), if the session is active; over a Unix socket the peer must also be the session's user and inside its process tree |
| a session without a proof (a bare session id), or a wrong proof | an unknown caller; the decision is audited with `caller=refused` and the reason |
| a revoked or expired session, or a Unix peer outside the session's tree | an unknown caller, audited with the reason (`revoked`, `expired`, `outside the session's process tree`) |
| a Unix peer and no session | the innermost active session of that user whose process tree it is in, else its `identity.peers` mapping, else unknown |
| nothing | an unknown caller |

A refused session is never retried as the peer's mapping, and agent fields in the request itself
are ignored. Each decision's audit entry records how the caller was identified in the `caller`
attribute (`session`, `peer`, `unmapped`, `refused`, `none`).

A session id alone is public (it appears in audit entries and status), so it proves nothing. Over
TCP the control plane checks possession of the token but cannot see the client's process, so a
process of the same user that read the token from an agent's environment can act as that session
on the forward proxy and the base URL (on the agent API and Unix sockets the process tree is
checked). See [What this does not protect against](#what-this-does-not-protect-against).

### Cost

A rule that depends on the agent of a request carrying a session always costs one round trip to
the control plane (a local gRPC call and a state read), since the data plane cannot place the
caller. That includes the built-in injection rule (`agent.known`), so every injection for a
`scrim run` session is asked about once per credential and request. Rules that do not mention
`agent` are decided in the data plane. The data plane does not receive a peer-to-agent map, so
agent rules on Unix-socket requests also ask.

## Kubernetes service accounts

In a cluster, agent pods identify themselves with a projected service account token minted for
scrim's audience. scrim verifies it with the cluster's TokenReview API and maps the namespace,
service account and pod to an agent.

```yaml
identity:
  kubernetes:
    enabled: true            # on in the k8s profile
    audience: scrim          # tokens for any other audience are refused
    agents:                  # optional; unmapped accounts are <namespace>/<name>
      reviewer: "sa:agents/reviewer label:team=platform"
      ci: "sa:ci/* scope:secrets:list"
```

The agent pod mounts a token for that audience. The kubelet rotates the file, so clients read it
on every request:

```yaml
volumes:
  - name: scrim-token
    projected:
      sources:
        - serviceAccountToken: {audience: scrim, expirationSeconds: 3600, path: scrim}
```

The token goes where a session token would (design D14):

| Listener | How the pod sends the token |
| --- | --- |
| forward proxy | the password of the proxy user `k8s`: `HTTPS_PROXY=http://k8s:<token>@scrim.scrim.svc:3128` |
| base URL | the value of `x-scrim-session` (Claude Code: `ANTHROPIC_CUSTOM_HEADERS="x-scrim-session: <token>"`) |
| agent API | `Authorization: Bearer <token>` |

The forward proxy credentials end at the proxy and the base-URL listener strips `x-scrim-session`,
so the token never reaches a provider or a tool API.

Unlike a session token, the control plane has to see a service account token to verify it, so a
proof cannot stand in for it. The data plane keeps the token in a zeroed type for the request (for
a forward-proxy tunnel, for the life of the tunnel), sends it in the ask
(`AskCaller.kubernetes_token`, a secret field with a redacting `Debug`), and the control plane
wipes the ask's copy once the ask is answered. The token is never logged, audited or forwarded.

The agent can read its own token file, so a token could end up in a tool result sent to a
provider. Every token the cluster accepts is added to the redaction set when scrim verifies it,
redaction only (it is never injected), and removed when it expires (24 hours after its last
verification for a token without an expiry). scrim verifies a token whenever a decision needs the
caller (an injection, an approval, a rule on `agent.*` for provider requests). A token scrim has not
verified yet is still caught by the fallback JWT detector, as `⟦scrim:det-jwt:...⟧`; once verified
it shows as `⟦scrim:scrim-kubernetes-credential:...⟧`.

What the rules see:

| Field | Value |
| --- | --- |
| `agent.id` | the `identity.kubernetes.agents` name, else `<namespace>/<service account>` |
| `agent.kind` | `k8s` |
| `agent.labels.namespace`, `agent.labels.service_account` | from the token |
| `agent.labels.pod`, `agent.labels.pod_uid` | the pod the token is bound to |
| other `agent.labels` | `label:` selectors of the matching rule |

Grants and approvals belong to the agent (principal `k8s:<agent>`), so pods of one Deployment
share them. A token the cluster does not accept for scrim's audience, including the pod's default
API token, is an unknown caller audited with `caller=refused` and the reason, never its Unix peer.
`identity.kubernetes.unmapped: unknown` makes every account no rule names unknown too.

A verified token is cached by its hash for `identity.kubernetes.cache-ttl` (one minute by
default), and never past the token's expiry, so a deleted pod or service account is refused within
that bound. Refusals are not cached.

### RBAC

scrim's own service account must be allowed to create TokenReviews:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: scrim-auth-delegator}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: system:auth-delegator}
subjects: [{kind: ServiceAccount, name: scrim, namespace: scrim}]
```

scrim reads its own token from `identity.kubernetes.token-file` and the API server's CA from
`identity.kubernetes.ca-file` (the pod's mounted service account by default), and finds the API
server through `KUBERNETES_SERVICE_HOST` unless `identity.kubernetes.api-server` is set. Agent
pods need no RBAC: any pod can get a projected token for its own service account.

### Store identity for pods

A pod can also act on OpenBao with its own service account (`kubernetes` in
`identity.store-login`); see [Store identity per agent](#store-identity-per-agent).

### Redaction identity

Redaction reads with its own identity: each store's refresher loads the `redact` targets with the
credentials configured on the store instance (`stores.<name>.auth`, `token`, `role-id`, ...),
never with an agent's login or static credential. Give that identity read access to everything in
the redaction set. Because the per-agent identities above only govern use and writes, a value an
agent cannot use is still redacted when the agent sends it by accident, for example when it reads
a log file that holds another team's secret.

The opposite is available as a weakening setting, `redaction.limit-to-agent-identity`. With it on,
scrim asks the store, as each agent with a static credential in `identity.store-credentials`,
whether that agent can read each value of the redaction set (OpenBao `sys/capabilities-self`,
never a read), and the provider requests of that agent's `scrim run` sessions are no longer
redacted for the values its store refused it:

```yaml
redaction:
  limit-to-agent-identity: true   # weakening: listed by scrim status and scrim doctor
```

It narrows as little as it can:

- Only provider requests on the LLM proxy, and only from a session that sent its own token
  (`x-scrim-session` or the forward proxy's `Proxy-Authorization`). A bare session id, a peer
  without a session, a Kubernetes caller, the tool proxy and every other path keep the whole
  redaction set. The data plane checks the token against the session tokens it already holds for
  redaction. It does not check the process tree the token was minted for, so a process that stole
  a session's token gets that session's narrower redaction.
- Only stores with a static per-agent credential. Kubernetes passthrough is not checked: scrim
  holds a pod's token only while one of its requests is in flight.
- Only values the store refused. A value not checked yet, a check that failed and an answer older
  than five minutes stay redacted until the next check.

scrim logs a warning at start-up and each time an agent's set of unredacted values changes (agent
and references, never values), `scrim status` lists the setting under weakened protections, and
`scrim doctor` warns per store which agents' sessions it affects.

### Testing in a cluster

`test/k8s/identity/run.sh` runs all of this in a kind cluster on rootless podman: OpenBao with
Kubernetes auth, two scrim replicas on one PostgreSQL logging in to OpenBao with their own service
account, and two agent pods whose service accounts get different outcomes from scrim's rules and
from their OpenBao roles. It removes the cluster and its images when it ends.

## scrim as an identity provider

Stores and clouds that federate trust a JWT from an issuer they know through its OpenID Connect
discovery document. scrim can be that issuer for its agents: it signs a short-lived token for an
agent it has identified, presents it to the store on the agent's behalf, and the store applies its
own role for that agent. The agent never sees the token.

```yaml
identity:
  issuer:
    url: https://scrim.example.com/idp   # the iss claim; stores fetch discovery from here
    listen: 127.0.0.1:9795               # serves discovery and JWKS only; put TLS in front
    token-ttl: 10m                       # 1m to 1h, never past the session's end
    rotate-every: 24h
```

The listener answers two paths under the URL's path and nothing else, both public:

| Path | Content |
| --- | --- |
| `<url>/.well-known/openid-configuration` | discovery document: `issuer`, `jwks_uri`, `RS256` |
| `<url>/.well-known/jwks.json` | the published public keys |

The URL must be https, or http on a loopback host. `identity.issuer.insecure-http` allows plain
http elsewhere and is reported as weakening: a store fetching keys over plain http can be handed
an attacker's keys and would then trust tokens the attacker signs.

### Tokens

Each token is an RS256 JWT for one audience (the store's), minted only for an identity scrim
resolved from the transport. An unknown caller gets none.

| Claim | Value |
| --- | --- |
| `iss` | `identity.issuer.url` |
| `sub` | `agent:<name>`, or `k8s:<name>` for a Kubernetes agent; the same for every session of the agent |
| `aud` | the store's audience |
| `iat`, `nbf`, `exp`, `jti` | issue time, expiry (`token-ttl`, capped at the session's end), random ID |
| `agent`, `agent_kind` | the agent name and how scrim identified it (`peer`, `session`, `k8s`) |
| `session`, `session_name` | the `scrim run` session, when there is one |
| `host` | the machine scrim runs on, for local agents |
| `namespace`, `service_account`, `pod` | for Kubernetes agents |
| `profile` | scrim's configuration profile |

A store role binds on these, for example OpenBao JWT auth:

```sh
bao auth enable jwt
bao write auth/jwt/config oidc_discovery_url=https://scrim.example.com/idp \
  bound_issuer=https://scrim.example.com/idp
bao write auth/jwt/role/claude-laptop role_type=jwt user_claim=sub bound_audiences=openbao \
  bound_claims=agent=claude-laptop token_policies=claude-laptop token_ttl=5m
```

Every token scrim mints is added to the redaction set until it expires, redaction only (store
`scrim-issuer`), so one that turned up in a store's error message or a log an agent reads reaches a
provider as `⟦scrim:scrim-issuer-credential:...⟧`. A token for the same claims and audience is
reused while two thirds of its life remain; tokens held for a session are dropped when it ends.

### Signing keys

By default scrim generates its keys in `identity.issuer.key-dir` (`~/.local/state/scrim/issuer`,
mode 0700, one 0600 PKCS#8 file per key) and rotates them every `rotate-every`:

- the next key is published one full period before it starts to sign, so a store that cached the
  JWKS at any point since the last rotation already has it;
- a replaced key stays published until the last token it signed has expired, plus five minutes for
  verifiers' clock leeway, then its file is deleted;
- a key set that is overdue (scrim was stopped for longer than a period) rotates at start-up.

Keys are named by their RFC 7638 thumbprint (`kid`). Logs name keys by `kid` only; no log line,
error, metric or response carries a private key.

Replicas behind one URL must publish the same JWKS, so they cannot each generate keys. Give them
operator-managed keys instead:

```yaml
identity:
  issuer:
    signing-keys: file:/run/secrets/scrim-issuer/keys.pem   # one or more PKCS#8 RSA keys
```

The first key signs and all are published; scrim does not rotate them. To rotate, put a new key
first and keep the old one second, roll the replicas, wait one token lifetime plus the stores' JWKS
cache time, then remove the old key.

In Kubernetes the Helm chart sets all of this from its `identity.issuer` values and puts the
listener on its own Service ([kubernetes.md](kubernetes.md#identity-issuer)).

## Store identity per agent

scrim loads the redaction set with its own store identity, so a value an agent may not use is
still redacted. Using a value can also be checked against the agent's own store identity, so an
operation succeeds only when both scrim's rules and the store's policy for that agent allow it.
Neither side can widen what the other denies: scrim refuses what its rules deny without asking the
store, and the store refuses what its policy denies for that agent although scrim's rules allow it.

```yaml
identity:
  store-login:
    # Kubernetes passthrough: the calling pod's own service account token, at the role the
    # template names (OpenBao and Vault Kubernetes auth).
    bao-cluster: "kubernetes role:{namespace}-{service_account} mount:kubernetes"
    # Token exchange: a token scrim's issuer signs for the agent (see above).
    bao: "jwt role:agent-{agent_slug} audience:openbao mount:jwt"
    aws: "aws-web-identity role-arn:arn:aws:iam::123456789012:role/agent-{agent_slug}"
    gsm: "gcp-workload-identity provider://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/scrim/providers/scrim service-account:{agent_slug}@proj.iam.gserviceaccount.com"
    akv: "azure-federated tenant:00000000-0000-0000-0000-000000000000 client-id:11111111-1111-1111-1111-111111111111"
    inf: "infisical-oidc identity-id:22222222-2222-2222-2222-222222222222 audience:infisical"
  # Static fallback: a store token per agent, by reference (store/agent).
  store-credentials:
    bao/laptop: file:/run/secrets/bao-laptop-token
```

Static credentials work with the store kinds in the table below; any other store configured for a
per-agent identity refuses every use as unsupported.

In templates `{agent}`, `{agent_slug}` (the agent name with anything outside `[A-Za-z0-9_.-]`
replaced by `-`, so `agents/reviewer` becomes `agents-reviewer`), `{namespace}` and
`{service_account}` are replaced per agent.

| Method | Store kinds | Options (defaults) | How the agent's permission is checked |
| --- | --- | --- | --- |
| `kubernetes` | `openbao`, `vault` | `role`, `mount` (`kubernetes`) | `sys/capabilities-self` on the secret's API path |
| `jwt` | `openbao`, `vault` | `role`, `audience`, `mount` (`jwt`) | `sys/capabilities-self` on the secret's API path |
| `aws-web-identity` | `awssm`, `ssm` | `role-arn`, `audience` (`sts.amazonaws.com`), `duration` (`15m`, up to `12h`) | the read itself with the assumed role, value wiped; CloudTrail shows `assumed-role/<role>/<agent>.<session>` |
| `gcp-workload-identity` | `gcpsm` | `provider` (`//iam.googleapis.com/...`), `service-account`, `audience` (`https:` + provider) | `testIamPermissions` for `secretmanager.versions.access` |
| `azure-federated` | `azkv` | `tenant`, `client-id`, `audience` (`api://AzureADTokenExchange`), `authority` (`https://login.microsoftonline.com`) | the read itself with the agent's token, value wiped |
| `infisical-oidc` | `infisical` | `identity-id`, `audience` | the read itself with the agent's token, value wiped |

For a store listed in either setting, every injection or restore of its secrets goes to the control
plane. After scrim's rules allow it, the control plane checks with the store, as the agent, and
refuses the request when the agent's identity may not read the secret. An agent with no usable
identity for the store (a local agent under `kubernetes`, any agent without a static credential) is
refused for it. A store in neither setting is used with scrim's own identity.

Store credentials obtained for an agent are cached per agent identity (per pod for Kubernetes
agents) until two thirds of their lifetime has passed, and a `scrim run` session's are dropped when
the session ends. scrim refuses to start when a store does not take the method its login names, or
when a token exchange method is configured without `identity.issuer.url`.

`scrim doctor` lists, per store and agent, which identity applies (`kubernetes`, `federated`,
`static`, `shared`, or `none` for refused), and fails a token exchange login while the issuer is
off.

## What this does not protect against

- Processes running as the same user that are not agents (your shell, an editor) are that user's
  peer identity. scrim trusts the local user; the design treats the user's machine as trusted.
- An agent that runs as root, or can `ptrace` another agent, can act as it. Run agents as separate
  users or in containers when they must not be able to impersonate each other.
- A session token in an agent's environment can reach the model if the agent prints its
  environment; it is in the redaction set for that reason. It is useless off the machine. On the
  agent API and Unix sockets it is useless outside the session's process tree; on the TCP forward
  proxy and base URL, which cannot see the client's process, a same-user process that holds the
  token is that session.
- A Kubernetes service account token for scrim's audience is a bearer credential toward scrim.
  Any process in the pod that can read the projected token file is that agent. Keep one agent per
  service account, and do not mount the token into pods that are not agents.
