# Edge forwarder

With scrim as a central deployment, HTTP traffic already reaches it over the network: the base URL and
the forward proxy are Service ports. Some tools expect a local endpoint instead: ssh and git look for
an agent at `SSH_AUTH_SOCK`, `psql` and database drivers connect to a port on localhost, and `scrim
exec`, `scrim mcp` and the database tool talk to the agent API on a Unix socket. The edge forwarder
provides those endpoints inside the agent pod and carries every connection to the central scrim.

Spec: `openspec/changes/scrim-v1/specs/credential-injection` ("Edge forwarder for local sockets") and
`specs/deployment` ("Edge forwarder in the chart"). Code: `internal/edge` (both ends), `scrim edge`
(`internal/cli/edge.go`), the edge listener in `internal/daemon/edge.go`.

## How it fits together

```text
agent pod                                         central scrim

git, ssh ───▶ SSH_AUTH_SOCK ────┐                  ┌──▶ ssh-agent keyring (keys from stores)
psql ───────▶ 127.0.0.1:5432 ───┼─▶ scrim edge ════╪══▶ database auth proxy (password from the store)
scrim exec ─▶ SCRIM_API_SOCKET ─┘   no secrets     └──▶ agent API, exec broker (runs centrally)
                                    TLS 1.3, the pod's token per connection, edge listener :9794
```

- `scrim edge` runs as a native sidecar in the agent pod. It listens on `SSH_AUTH_SOCK`, on one
  loopback port per forwarded database and on `SCRIM_API_SOCKET`, all inside the pod.
- Each local connection becomes one TLS 1.3 connection to the central scrim's edge listener
  (`edge.listen`). The forwarder verifies the certificate against scrim's CA only (the `scrim-ca`
  ConfigMap every agent pod already mounts), never the system roots.
- The forwarder presents the pod's projected service account token for scrim's audience, read from
  its file for every connection, so the kubelet's rotation is picked up and the agent keeps its
  identity however long it runs.
- The central scrim verifies the token with TokenReview through the same resolver as the proxy's
  Kubernetes callers ([kubernetes.md](kubernetes.md#identity)). The agent is `<namespace>/<service
  account>` or what `identity.kubernetes.agents` maps it to; policy, approvals, grants and audit see
  it exactly as they see that pod's proxy traffic.
- Then the connection carries the tool's own protocol: the ssh-agent protocol to scrim's keyring,
  the PostgreSQL or MySQL protocol to the database auth proxy, HTTP to the agent API.

## What never reaches the pod

| Endpoint | The pod gets | Stays in central scrim |
| --- | --- | --- |
| ssh-agent | public keys and signatures, each a policy decision with an audit entry | the private keys ([ssh-agent.md](ssh-agent.md)) |
| database port | the session scrim logged in for it | the database password ([databases.md](databases.md)) |
| agent API | tool results, redacted command output | exec secrets: the command runs in the central scrim ([exec-broker.md](exec-broker.md)) |

The forwarder holds no secret value. Its container mounts the CA's public certificate and the pod's
identity token, which every agent container mounts anyway; it gets no store credential, no CA key
and no placeholder key. Compromising it gives what compromising the agent gives: the pod's identity,
which policy already governs.

## Failing closed

There is nothing in the pod to fall back to:

- A local connection whose tunnel cannot be opened (central scrim unreachable, its certificate does
  not verify, the token is refused or the caller is unmapped) is closed at once. ssh reports
  `Permission denied (publickey)`, psql `server closed the connection unexpectedly`.
- An agent API request in that state is answered `503` with `{"error": {"code": "unavailable"}}`
  and never runs.
- While the cluster's TokenReview cannot be reached the central scrim refuses the connection
  (`unavailable`) instead of serving it unidentified.
- The sidecar's startup probe is `scrim edge check`, which asks the central scrim who the pod is.
  The agent containers start only once it passes. After that, losing the central scrim refuses
  connections until it is back; the forwarder needs no restart.

Identity is checked once per connection, like a database login: a long `psql` session keeps the
identity it was opened with. Every agent API request is checked on its own.

## With the Helm chart

```yaml
edge:
  enabled: true
  databases:
    app: 5432                    # config.databases.app, at 127.0.0.1:5432 in the pod
identity:
  kubernetes:
    enabled: true                # the default; the edge needs it
kyverno:
  enabled: true
config:
  catalog:
    entries:
      deploy:
        ref: bao://kv/agents/deploy#private_key
        ssh_key: true
  databases:
    app:
      kind: postgres
      address: db.internal:5432
      user: app_agent
      password: file:/run/secrets/scrim/db/password   # secretMounts: [{name: db, secretName: app-db}]
```

`edge.enabled` turns on `edge.listen` in the central scrim (port `edge.port`, 9794, on the container
and the Service), with the Service's names in its certificate, and has the central MutatingPolicy add
to every pod labelled `scrim.dev/inject: central`:

| What | Value |
| --- | --- |
| native sidecar `scrim-edge` | `scrim edge` from the scrim image, UID 65532, read-only root, no capabilities |
| volume `scrim-edge` | an in-memory `emptyDir` at `edge.socketDir` (`/run/scrim-edge`) in every container |
| `SSH_AUTH_SOCK` | `/run/scrim-edge/ssh-agent.sock` (with `edge.sshAgent`, on by default) |
| `SCRIM_API_SOCKET` | `/run/scrim-edge/api.sock` (with `edge.api`, on by default) |
| database ports | `127.0.0.1:<port>` for each `edge.databases` entry |

The NetworkPolicies let central agent pods reach the edge port and nothing else new. Only the
agent's signatures go through scrim, not the SSH session: ssh connects to the git server itself, so
`git push` over SSH needs an egress rule for it in `networkPolicy.agentEgress`:

```yaml
networkPolicy:
  enabled: true
  agentEgress:
    - to:
        - ipBlock: {cidr: 140.82.112.0/20}     # github.com
      ports:
        - {port: 22, protocol: TCP}
```

Database ports and the agent API need nothing: those connections end at the forwarder. The chart refuses
`edge.enabled` without central mode, without `identity.kubernetes.enabled`, with nothing to forward,
on a port another listener uses, and with an `edge.databases` name `config.databases` does not have.
Without Kyverno, the agent env ConfigMap has the two variables, and `helm template --set
kyverno.enabled=true --show-only templates/kyverno.yaml` prints the sidecar to copy into the pod
spec.

Policy rules decide as for any other caller. For example, git over SSH and the database for every
agent in the `agents` namespace:

```yaml
policyRules:
  rules:
    - name: git-over-ssh
      decision: allow
      when: >-
        op == "ssh.sign" && agent.labels.namespace == "agents" &&
        ssh.user == "git" && dest.host == "github.com"
    - name: app-database
      decision: allow
      when: op == "database.auth" && agent.labels.namespace == "agents" && dest.path == "/app"
```

`dest.host` for SSH comes from `ssh-agent.known-hosts` in the central scrim's configuration, a file
you mount there ([ssh-agent.md](ssh-agent.md#which-host-a-login-is-for)).

In the agent container:

<!-- docs-test: skip: needs a cluster with a central scrim -->

```sh
git push git@github.com:acme/app.git main        # signed by the central scrim
psql "host=127.0.0.1 port=5432 dbname=app user=anything"
curl --unix-socket "$SCRIM_API_SOCKET" http://scrim/v1/whoami
```

The agent image needs no scrim binary: the agent API is plain HTTP on the socket. `scrim exec` and
`scrim mcp` work as on a laptop when the image has the scrim binary.

## Settings

The central scrim (`scrim proxy`):

| Setting | Meaning |
| --- | --- |
| `edge.listen` | Address of the edge listener; empty turns it off. Needs `identity.kubernetes.enabled` |
| `edge.server-names` | Names and addresses in its certificate, which scrim issues from its CA for 24 hours and renews |

The forwarder (`scrim edge`, environment `SCRIM_EDGE_FORWARDER_*`):

| Setting | Meaning |
| --- | --- |
| `edge-forwarder.central` | `host:port` of the edge listener |
| `edge-forwarder.server-name` | Name to verify its certificate for; default the host of `central` |
| `edge-forwarder.ca-file` | scrim's CA certificate (default `/etc/scrim/trust/scrim-ca.pem`) |
| `edge-forwarder.token-file` | The pod's projected token (default `/var/run/secrets/scrim/token`) |
| `edge-forwarder.ssh-agent-socket` | Where to serve the ssh-agent; empty serves none |
| `edge-forwarder.api-socket` | Where to serve the agent API; empty serves none |
| `edge-forwarder.databases` | Database name to loopback address, `app=127.0.0.1:5432`; non-loopback addresses are refused |
| `edge-forwarder.socket-permissions` | Mode of the Unix sockets, `0666`: agent containers run as other users |
| `edge-forwarder.connect-timeout` | How long to wait for the central scrim before refusing (10s) |

`scrim edge check` prints the agent the central scrim verified the pod as, and exits non-zero when
it cannot.

## The channel

The edge listener speaks HTTP/1.1 over TLS 1.3 (no HTTP/2). The agent API is served on its own
paths, `/v1/...`, each request with `Authorization: Bearer <token>`; only the agent routes are
served (`whoami`, `secrets`, `asks`, `status`, `grants`, `redact`, `ssh`, `exec`, `databases`),
never session minting or the daemon's endpoint list. A tunnel is an HTTP Upgrade:

```text
GET /edge/v1/ssh-agent HTTP/1.1          (or /edge/v1/database/<name>)
Connection: Upgrade
Upgrade: scrim-edge.v1
Authorization: Bearer <projected token>

HTTP/1.1 101 Switching Protocols         (or 401, 404, 503 with a JSON error)
```

Only Kubernetes service account tokens are accepted: a `scrim run` session token is bound to a local
process tree and means nothing here, and there are no peer credentials to fall back to. A refused
token is audited with tool `edge`, outcome `refused` and the reason, never the token. Every token
the cluster verifies joins the redaction set, as on the proxy.

## Tests

- `internal/edge`: ssh-agent list and sign through the forwarder as the pod's agent, a signature
  the keyring denies, a database tunnel that carries the caller, agent API requests with the
  client's own `Authorization` replaced, refused tokens (unknown, a session token) audited without
  the token, an unknown database, a central certificate from another CA or for another name,
  failing closed with the central scrim down or TokenReview unreachable, and recovery without a
  restart.
- `internal/ca`: the listener certificate chains to scrim's CA, carries the names, and never
  outlives the CA.
- `internal/daemon` (`TestEdgeForwarder`): a daemon with Kubernetes identity against a fake
  TokenReview, its edge listener and an in-process forwarder: ssh login signed for one service
  account and denied for another, `psql`-protocol login through the forwarded port, an exec call,
  each audited as the pod's agent.
- `just edge-e2e` (`test/k8s/edge-e2e.sh`): kind on rootless podman with the chart, Kyverno and a
  central scrim. From an agent pod, `git push` over SSH to a throwaway sshd and git server succeeds
  with a key only the central scrim's store holds, and a push whose signature policy denies fails;
  `psql` through the forwarded port reaches PostgreSQL with only a placeholder in the pod; an exec
  call runs centrally with the real value and returns redacted output; the pod cannot reach the
  database or the git server directly; with the central scrim scaled to zero every endpoint refuses,
  and works again when it is back; no secret value is in any log. CI runs it in the `edge-e2e` job.
