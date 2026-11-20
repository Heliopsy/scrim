# Agent identity

Every call to scrim's local agent API is attributed to an agent before policy runs, and the
decision and audit entry name that agent. Identity comes only from the transport: the Unix socket's
peer credentials, plus a session token when the caller has one. Nothing in a request body, header
or tool argument can change it.

This page covers local identity. Kubernetes service accounts, client certificates and scrim as an
identity provider for stores are specified in `openspec/changes/scrim-v1/specs/agent-identity` and
arrive later.

## Peer credentials

When a process connects to the API socket, the kernel records who it is. scrim reads that record:

| Platform | Mechanism | What it reports |
|---|---|---|
| Linux | `SO_PEERCRED` | user, group, process |
| macOS | `LOCAL_PEERCRED`, `LOCAL_PEERPID` | user, primary group, process |
| others | none | the caller is unknown and refused |

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
|---|---|
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
|---|---|
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
|---|---|
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
|---|---|
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

Sessions are kept in memory: restarting the control plane ends every session, which is the safe
direction. Persisting them in the state backend for multi-replica deployments is later work.

## What this does not protect against

- Processes running as the same user that are not agents (your shell, an editor) are that user's
  peer identity. scrim trusts the local user; the design treats the user's machine as trusted.
- An agent that runs as root, or can `ptrace` another agent, can act as it. Run agents as separate
  users or in containers when they must not be able to impersonate each other.
- A session token in an agent's environment can reach the model if the agent prints its
  environment. It is useless off the machine and outside the process tree, but should still be
  redacted like any other credential.
