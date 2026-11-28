# Agent identity

Every call to scrim's local agent API is attributed to an agent before policy runs, and the
decision and audit entry name that agent. Identity comes only from the transport: the Unix socket's
peer credentials, plus a session token when the caller has one, a Kubernetes service account token,
or a client certificate on a TLS listener. Nothing in a request body, header or tool argument can
change it.

This page covers local identity, Kubernetes service accounts, client certificates and scrim as an
identity provider for stores.

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
| `secrets:request` | `secret_request`, `approval_status`, `grants_list`, `secret_exec` (the [exec broker](exec-broker.md)), and listing keys and signing through scrim's [ssh-agent](ssh-agent.md) |
| `secrets:write` | `secret_gen`, `secret_capture`, `secret_ask_human`, `scrim secret put` |
| `sessions:mint` | minting session tokens, revoking another session of the same user, and asking for scrim's own files (`scrim run` does, to [hide them](run.md#scrims-own-files) from the agent); never held by a session |

`database_list`, `database_query` and the hooks' `POST /v1/redact` need a known agent but no scope;
policy decides the database tools.

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
| Kubernetes service account | `k8s:<agent>` |
| client certificate | `mtls:<agent>` |

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
| TLS base URL, forward proxy and tool proxy | the client certificate verified in the TLS handshake ([Client certificates](#client-certificates)) |

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
attribute (`session`, `peer`, `kubernetes`, `certificate`, `unmapped`, `refused`, `none`).

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

The agent pod mounts a token for that audience. The kubelet rotates the file, so a client should
read it again rather than keep it. The edge forwarder reads it for every connection. The chart's
`scrim-exec` launcher reads it once, when the agent starts, so an agent process that runs longer
than `expirationSeconds` loses its identity until it is restarted
([kubernetes.md](kubernetes.md#identity)):

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
| forward proxy | the password of the proxy user `k8s`: `HTTPS_PROXY=http://k8s:<token>@scrim.scrim.svc:9791` |
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

scrim's own service account must be allowed to create TokenReviews, and needs nothing else. The
Helm chart creates such a ClusterRole and binds it to scrim's service account
(`identity.kubernetes.tokenReviewRBAC`, [kubernetes.md](kubernetes.md#identity)). Without the chart:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: scrim-tokenreview}
rules: [{apiGroups: [authentication.k8s.io], resources: [tokenreviews], verbs: [create]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: scrim-tokenreview}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: scrim-tokenreview}
subjects: [{kind: ServiceAccount, name: scrim, namespace: scrim}]
```

`system:auth-delegator` works too, but also allows SubjectAccessReviews, which scrim does not use.

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
the redaction set. Because the per-agent identities above only govern use, a value an
agent cannot use is still redacted when the agent sends it by accident, for example when it reads
a log file that holds another team's secret.

The opposite is available as a weakening setting, `redaction.limit-to-agent-identity`. With it on,
scrim asks the store, as each agent with a static credential in `identity.store-credentials`,
whether that agent can read each value of the redaction set (the store's check from
[the table below](#store-identity-per-agent), for example OpenBao `sys/capabilities-self`, never a
read), and the provider requests of that agent's `scrim run` sessions are no longer
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

## Client certificates

Agents that hold an X.509 identity (a SPIFFE SVID, a certificate from an internal CA for CI runners
or agents on other machines) can identify themselves with it instead of a bearer token. A client
certificate proves that the caller holds the private key in the TLS handshake; scrim sees only the
certificate, never the key, so a process that copies the certificate alone cannot use it.

```yaml
identity:
  client-certificates:
    enabled: true
    ca: file:/etc/scrim/agents-ca.pem          # or env:NAME, cred:NAME, bao://kv/pki#ca
    crl-files: [/etc/scrim/agents-ca.crl]      # optional, see Revocation
    ocsp: {enabled: true}                      # optional, see Revocation
    agents:
      builder: "spiffe:spiffe://example.org/agents/builder label:team=platform"
      ci: "cn:ci-runner-* scope:secrets:list"
    unmapped: unknown                          # the default
    server-names: [scrim.internal, 10.0.0.5]   # names in the listeners' certificate
proxy:
  tls-listen: 0.0.0.0:9796                     # LLM proxy base URL over TLS
  forward-tls-listen: 0.0.0.0:9797             # forward proxy over TLS (HTTPS proxy)
tool-proxy:
  tls-listen: 0.0.0.0:9798                     # tool proxy over TLS
```

### Listeners

The TLS listeners are separate from the plain ones and require a client certificate: a client that
presents none, or one that fails the checks below, does not get a connection.

| Listener | Setting | How the agent uses it |
| --- | --- | --- |
| LLM proxy base URL | `proxy.tls-listen` | `ANTHROPIC_BASE_URL=https://scrim.internal:9796/anthropic` with the certificate configured in the client |
| forward proxy | `proxy.forward-tls-listen` | `HTTPS_PROXY=https://scrim.internal:9797`; the client authenticates to the proxy (`curl --proxy-cert`, Go's `TLSClientConfig`), then CONNECTs as usual |
| tool proxy | `tool-proxy.tls-listen` | tools pointed at the tool proxy directly |
| edge listener | `edge.listen` | the forwarder presents `edge-forwarder.client-cert-file` and `edge-forwarder.client-key-file` instead of the pod's token |

Their certificate is issued by scrim's CA (the one agents already trust for TLS interception, see
[ca.md](ca.md)) for the name the client asked for when it is in `server-names`, else for the address
the client connected to when that is listed, else for the first name. Starting scrim with a TLS
listener but without `identity.client-certificates.enabled` is an error.

To present a certificate of your own instead, from your PKI, cert-manager or an ACME client, so
agents verify the listeners against a CA they already trust and need not trust scrim's:

```yaml
identity:
  client-certificates:
    listener-cert-file: /etc/scrim/listener/tls.crt   # end entity first, then intermediates
    listener-key: file:/etc/scrim/listener/tls.key     # or env:, cred: or a store reference
```

scrim refuses to start when the key does not match the certificate, or the certificate is a CA,
does not allow server authentication or is outside its validity period. `server-names` is not used
then: the certificate names what it names. Both files are read again every
`identity.client-certificates.refresh`, so a certificate renewed in place is presented on new
connections without a restart; a pair that fails the same checks (a renewal written halfway, a
certificate that expired) is logged and the one in force stays. The key is one of scrim's own
credentials: redacted from provider traffic and never logged. The edge listener keeps its own CA
(`edge.ca.*`).

On a TLS listener the certificate is the request's only identity. An `x-scrim-session` header or
proxy credentials on such a connection are ignored (and still stripped before forwarding).

The edge listener requests a client certificate but does not require one, so forwarders that send
the pod's token keep working; when a forwarder presents a certificate, it wins over a token. The
forwarder reads its certificate and key files for every connection, so a certificate a SPIFFE
helper rotates in the pod is used at once. The key stays in the pod.

### Checks

Each certificate is checked twice. The data plane checks it in the handshake; the control plane
checks the chain again with its own copy of the trust anchors and CRLs (and OCSP, when it is on)
before it maps it, so a data plane fault cannot let a certificate through.

| Refusal reason | Meaning |
| --- | --- |
| `untrusted` | does not chain to `identity.client-certificates.ca` (no system roots are used) |
| `expired`, `not yet valid` | outside its validity period |
| `not a client certificate` | its extended key usage does not allow client authentication |
| `revoked` | the issuer's CRL lists it, or its OCSP responder says it is revoked |
| `revocation status unknown` | CRLs or OCSP are configured but neither covers it: no CRL from its issuer and no OCSP answer, or the responder answered "unknown" |
| `crl expired` | the issuer's CRL is past its next update |
| `ocsp unavailable` | OCSP is on, no current CRL covers it, and no valid OCSP answer could be had (`unreachable: fail-closed`) |
| `no certificate` | the client presented none (TLS listeners only) |
| `invalid` | refused in the handshake for any other reason, such as a malformed certificate (TLS listeners) |
| `malformed certificate` | the chain carried to the control plane does not parse (edge listener, asks) |

A certificate refused in the handshake is audited as `dataplane.client_certificate_refused` with
the reason, the listener, the client's address and, when the certificate could be parsed, its
SHA-256 fingerprint, subject CN and SPIFFE ID. A certificate refused by the control plane is
evaluated as an unknown caller and its decision is audited with `caller=refused`, the reason in
`caller_reason` and the fingerprint in `cert_sha256`. On the edge listener a refusal is a 401 and an
audit entry for the tool `edge`.

### Mapping

`identity.client-certificates.agents` maps certificates to agents. Each value lists selectors
separated by spaces:

| Selector | Matches |
| --- | --- |
| `spiffe:ID` | the SPIFFE ID (the certificate's one URI SAN with the `spiffe` scheme) |
| `cn:NAME` | the subject common name |
| `dns:NAME`, `uri:URI`, `email:ADDRESS` | a DNS, URI or email SAN |
| `scope:S` | limits the agent to scope S (repeatable; default all agent scopes) |
| `label:K=V` | an attribute policy rules can match |

Patterns are globs in which `*` does not cross a `/`: `spiffe:spiffe://example.org/agents/*`
matches `.../agents/builder` but not `.../agents/team/builder`. Rules are tried in agent name order
and the first match wins.

A certificate that chains to the trust anchor but matches no rule is an unknown caller
(`caller=unmapped`): it gets no injection, tools or grants, and its provider requests follow your
rules for unknown callers. A trust anchor usually covers more than your agents (a whole SPIFFE trust
domain, a company CA), which is why this is the default, unlike `identity.kubernetes.unmapped`. With
`unmapped: derive`, an unmapped certificate with a SPIFFE ID becomes the agent named after it
without the scheme (`spiffe://example.org/agents/x` is `example.org/agents/x`); one without a SPIFFE
ID stays unknown.

What the rules see:

| Field | Value |
| --- | --- |
| `agent.id` | the rule's agent name, or the derived name |
| `agent.kind` | `mtls` |
| `agent.labels.spiffe_id` | the SPIFFE ID, when the certificate has one |
| `agent.labels.cert_cn`, `agent.labels.cert_issuer_cn` | subject and issuer common names |
| `agent.labels.cert_sha256` | the certificate's SHA-256 fingerprint |
| other `agent.labels` | `label:` selectors of the matching rule |

The certificate labels come from the certificate and cannot be set with `label:`. Grants and
approvals belong to the agent (principal `mtls:<agent>`), so every certificate a rule maps to one
agent shares them. Tokens scrim's identity provider mints for such an agent have the subject
`mtls:<agent>` and expire no later than the certificate. Static per-agent store credentials and
token exchange work for these agents; Kubernetes passthrough does not.

### Revocation

- **CRL files.** List them in `identity.client-certificates.crl-files` (PEM or DER). scrim reads
  them, and the trust anchors, again every `identity.client-certificates.refresh` (one minute) and
  applies a change to new connections without a restart; connections already open keep the
  identity they were accepted with. Once any CRL is configured, a certificate whose issuer has no
  CRL among them is refused unless OCSP answers for it, and a CRL past its next update refuses every
  certificate of its issuer until a current one is in place, so a broken CRL distribution fails
  closed. A file that cannot be read on a refresh keeps the lists in force and logs a warning.
- **OCSP.** With `identity.client-certificates.ocsp.enabled`, scrim asks the issuer's OCSP responder
  about each certificate before its connection is served. The responder is the one in the
  certificate's authority information access extension, or `ocsp.responder` for every certificate.
  Requests go from the control plane, through `network.upstream-proxy` when one is set. A response
  counts only when it is signed by the issuer or by a responder certificate the issuer issued for OCSP
  signing, names the certificate's serial number and is current; it is kept until its next update (an
  hour after it was produced when it has none), in a cache of `ocsp.cache-size` answers (10000).
  Stapled responses are not used.
- **Revocation scope.** `identity.client-certificates.revocation-scope: end-entity` (the default)
  checks the client certificate only. `chain` checks every certificate below the trust anchor as
  well, each against its own issuer's CRL or responder, so revoking an intermediate CA refuses every
  certificate it issued. With CRLs and no OCSP, `chain` needs a CRL from every issuer in the chain,
  the root's included.
- **Short-lived certificates.** With no CRL and OCSP off, revocation is not checked. Use
  certificates that live for hours, not years (SPIFFE SVIDs default to one hour): a stolen
  certificate and key are useless once they expire.

With CRLs and OCSP both configured, a certificate is accepted when a current CRL or an OCSP answer
covers it and neither says it is revoked:

| CRL of its issuer | OCSP answer | Result |
| --- | --- | --- |
| lists it | any | `revoked` |
| past its next update | any | `crl expired` |
| any | revoked | `revoked` |
| current, does not list it | good, unknown or none | accepted |
| none | good | accepted |
| none | unknown, or no responder | `revocation status unknown` |
| none | no valid answer | `ocsp unavailable`, or accepted with `soft-fail` |

`identity.client-certificates.ocsp.unreachable` decides the last row. `fail-closed` (the default)
refuses: a check that passes whenever the responder is down checks nothing against an attacker who
can block it. `soft-fail` accepts and logs a warning, for responders you do not trust to stay up.
Revoked and unknown answers refuse either way. `ocsp.timeout` (5s, at most 10s) bounds each request;
the requests for one chain run in parallel.

Where the check runs: the data plane terminates TLS and checks CRLs in the handshake as before. With
OCSP on it lets a certificate whose issuer has no CRL through the handshake, then hands the verified
chain to the control plane, which fetches and verifies the OCSP responses and applies the CRLs, and
serves the connection only once the control plane accepts it. A refusal closes the connection before
any request is read and is audited like a handshake refusal. The first connection of a certificate
waits for its responder; later ones use the cached answer.

OCSP has costs. A new certificate's first connection waits for a network round trip, the responder
learns which certificates connect and when, and a responder outage refuses agents under
`fail-closed`. Short-lived certificates avoid all three.

In Kubernetes the Helm chart sets these settings and the TLS listeners from its
`identity.clientCertificates` values ([kubernetes.md](kubernetes.md#client-certificates)).

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
| `sub` | `agent:<name>`, `k8s:<name>` for a Kubernetes agent, or `mtls:<name>` for a client certificate; the same for every session of the agent |
| `aud` | the store's audience |
| `iat`, `nbf`, `exp`, `jti` | issue time, expiry (`token-ttl`, capped at the session's end), random ID |
| `agent`, `agent_kind` | the agent name and how scrim identified it (`peer`, `session`, `k8s`, `mtls`) |
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
    dop: "doppler-oidc identity:33333333-3333-3333-3333-333333333333 audience:https://api.doppler.com"
  # Static fallback: a store credential per agent, by reference (store/agent).
  store-credentials:
    bao/laptop: file:/run/secrets/bao-laptop-token
    bws/laptop: file:/run/secrets/bws-laptop-access-token
    vw/laptop: file:/run/secrets/vw-laptop-api-key.json
    op/laptop: file:/run/secrets/op-connect-laptop-token
    dop/laptop: file:/run/secrets/doppler-laptop-service-token
```

Any store configured for a per-agent identity that cannot check one refuses every use as
unsupported (the `env`, `file`, `sops`, `keyring`, `kubernetes` and `plugin` stores, and AWS with a
static credential: AWS checks agents only by token exchange).

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
| `doppler-oidc` | `doppler` | `identity` (a service account identity ID), `audience` | the read itself with the agent's token, value wiped |

Static credentials (`identity.store-credentials`) and how each store checks them:

| Store kind | The agent's credential | Read checked by | Write checked by |
| --- | --- | --- | --- |
| `openbao`, `vault` | a token | `sys/capabilities-self` | `sys/capabilities-self` |
| `gcpsm` | an access token | `testIamPermissions` | `testIamPermissions` (`versions.add`) |
| `azkv` | an access token | the read itself, value wiped | not checkable |
| `infisical` | an access token of the agent's machine identity | the read itself, value wiped | not checkable |
| `doppler` | a service token or service account token | the read itself, value wiped | not checkable |
| `onepassword` | a Connect access token from the same Connect server | the vault's item list (summaries, no value) | not checkable |
| `bws` | a machine account access token of the same organisation | `GET /secrets/{id}` as that machine account, never decrypted | the `write` flag Bitwarden returns for the secret or its project |
| `vaultwarden` | the agent account's personal API key, as JSON | the item's `viewPassword` flag for that account | the item's `edit` flag, or the collection's `readOnly` |

"Not checkable" means the store has no way to say whether an identity may write without writing:
such a check is refused as unsupported. The read checks run before scrim uses a value (injection and
restore), the write checks before an agent's write; see [What is checked](#what-is-checked).

For a store listed in either setting, every injection or restore of its secrets goes to the control
plane. After scrim's rules allow it, the control plane checks with the store, as the agent, and
refuses the request when the agent's identity may not read the secret. An agent with no usable
identity for the store (a local agent under `kubernetes`, any agent without a static credential) is
refused for it. A store in neither setting is used with scrim's own identity.

Store credentials obtained for an agent are cached per agent identity (per pod for Kubernetes
agents) until two thirds of their lifetime has passed, and a `scrim run` session's are dropped when
the session ends. scrim refuses to start when a store does not take the method its login names, or
when a token exchange method is configured without `identity.issuer.url`.

### What is checked

The control plane asks the store as the agent before every injection or restore of a governed
store's secret, and `redaction.limit-to-agent-identity` asks it before it narrows a session's
redaction.

Agent writes (`secret_gen`, `secret_capture`, `secret_ask_human` and `scrim secret put`, over MCP,
the local API or the edge listener) are decided by scrim's rules first. For a governed store, the
control plane then asks the agent's own store identity whether it may write there, using the write
check in the table above, and refuses the write when the store says no. An agent with no usable
identity for such a store is refused, as it is for a read. The value itself is still written with
scrim's own store identity once both agree, so the store's audit records scrim's write after the
agent's check. `secret_capture` and `secret_ask_human` are checked before the command runs or a
human is asked, so a refused write costs nothing.

| Store kinds | Agents' writes |
| --- | --- |
| `openbao`, `vault`, `gcpsm`, `bws`, `vaultwarden` | checked with the agent's own identity; refused when it may not write |
| `awssm`, `ssm`, `azkv`, `infisical`, `doppler`, `onepassword` | not checkable: written with scrim's own identity once scrim's rules allow them, or refused when `identity.refuse-unchecked-writes` names the store |
| stores in neither identity setting | scrim's own identity, as before |

```yaml
identity:
  # Refuse agents' writes to governed stores that cannot check them (or "*" for all of them).
  refuse-unchecked-writes: [aws, dop]
  # Weakening: write without asking the agent's identity on stores that could check.
  # skip-agent-write-checks: true
```

`identity.skip-agent-write-checks` is a weakening setting, logged at start-up and listed in
`scrim status`. Every write audit entry records how it was checked: `store_identity` (`static`,
`federated`, `kubernetes`, `shared` or `none`) and `store_write_check` (`checked`, `unchecked`,
`skipped` or `shared`). A refusal's message names the store, the reference and the store's reason,
never a value or the agent's credential.

### Stores without a token exchange

- **Bitwarden Secrets Manager**: create a machine account per agent, give it **Can read** or **Can
  read, write** on the agent's projects, and hold its access token for the agent. scrim logs in as
  that machine account (the token is cached per agent until two thirds of its life) and asks for
  the secret: Bitwarden answers "not found" for a secret the machine account may not read and
  returns a `write` flag with one it may read. The secret's ciphertext is never decrypted. Bitwarden
  records `Secret_Retrieved` (or `Project_Retrieved`, for a new secret) under the agent's machine
  account. Secrets Manager has no OIDC login, so there is no token exchange.
- **Vaultwarden and Bitwarden password manager**: give each agent its own account, make it a member
  of the organisation that holds the shared items and set its collection access (can view, can view
  except passwords, can edit). Hold its personal API key for the agent as
  `{"client_id": "user.<uuid>", "client_secret": "<secret>"}`; the agent's master password is not
  needed, because the check decrypts nothing. scrim logs in with the API key and fetches the item as
  that account: an item the account cannot see is refused, and one in a collection that hides
  passwords is refused for every field. Items in scrim's personal vault are never an agent's. On
  bitwarden.com each agent account takes a seat.
- **1Password**: issue a Connect access token per agent from the same Connect server, scoped to the
  agent's vaults (`op connect token create <agent> --server <server> --vault <vault>,r`). Connect
  grants access per vault, so scrim checks that the agent's token lists the item in its vault.
  1Password service account tokens cannot be used: the adapter only speaks Connect
  ([onepassword.md](stores/onepassword.md#why-connect-and-not-service-accounts)).
- **Doppler**: hold a service token for the agent's config, or a service account token, or log the
  agent in with `doppler-oidc`: add a service account identity with OIDC authentication to a
  service account, trust scrim's issuer URL, require the audience you configure and the subject
  `agent:<name>`, and name the identity's ID. Doppler returns a short-lived token, cached per agent.

`scrim doctor` lists, per store and agent, which identity applies (`kubernetes`, `federated`,
`static`, `shared`, or `none` for refused), fails a token exchange login while the issuer is off,
and says per governed store whether agents' writes are checked with the agent's identity, warning
where they are not.

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
- A client certificate is only as private as its key. Any process that can read the key file is
  that agent, and a certificate keeps working until it expires unless a CRL or OCSP revokes it. Keep keys
  readable by the agent only and certificates short-lived, and map certificates explicitly rather
  than with `unmapped: derive` when the CA issues to more than your agents.
