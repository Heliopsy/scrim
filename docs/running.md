# Running the daemon

`scrim proxy` is the long-running scrim process. It runs the control plane (configuration, stores,
catalog, policy, approvals, audit) and supervises the data plane (the Rust LLM proxy, redactor,
guard and tool proxy) as a child process. Everything else talks to it: agents through the base URL
or the forward proxy, `scrim mcp` and `scrim secret` through the agent API socket, `scrim approve`
and friends through the admin API.

```sh
scrim proxy                        # until SIGINT or SIGTERM
scrim proxy --capture              # capture mode into $XDG_STATE_HOME/scrim/capture
scrim proxy --capture ~/scrim-cap  # or into a directory of your choice
ANTHROPIC_BASE_URL=http://127.0.0.1:9790/anthropic claude
```

The release binary has the data plane embedded. A development build without it needs
`SCRIM_DATAPLANE_PATH` (`just build-dev`, then
`SCRIM_DATAPLANE_PATH=dataplane/target/debug/scrim-dataplane bin/scrim proxy`).

## What starts

1. The configuration is loaded and the weakened settings are logged.
2. The state backend opens (SQLite at `$XDG_STATE_HOME/scrim/state.db` in the local profile; a
   second scrim process on the same file is refused).
3. The placeholder keys load, or one is generated (see below).
4. The catalog loads; the tool-proxy CA loads or is created ([ca.md](ca.md)).
5. The agent API socket, the entry page, the admin listener and, when configured, the decision and
   metrics listeners are bound. `Start` fails if any cannot be bound.
6. Store refreshers, the policy loops, the catalog watcher and the data plane start.
7. The data plane gets its first snapshot. Until it holds one and every data plane listener is
   bound, the daemon is not ready and the data plane refuses traffic: nothing is forwarded
   unredacted.

A failing component (a listener that stops, the data plane refusing to run because of a protocol
mismatch) stops the daemon with an error. A data plane crash is not a failure: the supervisor
restarts it with backoff and traffic is refused until it is back.

## Listeners and sockets

| What | Setting | Default | Notes |
| --- | --- | --- | --- |
| LLM proxy base URL | `proxy.listen` | `127.0.0.1:9790` | `http://<addr>/anthropic` and `http://<addr>/openai/v1`. Keep it on loopback. |
| LLM proxy on a Unix socket | `proxy.socket` | off | Same routes, for clients that can use a socket. |
| Forward proxy | `proxy.forward-listen` | `127.0.0.1:9791` | `HTTPS_PROXY=http://<addr>` (`scrim run` sets it with the CA for the child): provider hosts, including `chatgpt.com` and `ab.chatgpt.com` for Codex, go to the LLM proxy; other hosts to the tool proxy with credential injection. |
| Tool proxy | `tool-proxy.listen` | off | HTTPS tool proxy alone. |
| Agent API | `api.socket` | `$XDG_RUNTIME_DIR/scrim/api.sock` | Mode `api.permissions` (0600), group `api.group` (the system service: 0660, `scrim-agents`). Callers are identified by peer credentials and session tokens ([identity.md](identity.md)). |
| Entry page | `entry.listen` | `127.0.0.1:0` | Where a human types a value for `secret_ask_human`. |
| Admin API | `admin.url` | `unix:$XDG_RUNTIME_DIR/scrim/admin.sock` | Operator commands ([approvals.md](approvals.md)). |
| Decision links | `approvals.listen` | off | Only the decision endpoint, for `approvals.public-url` to point at through a TLS proxy. |
| Metrics and health | `metrics.listen` | off | `/metrics`, `/livez`, `/readyz`. |

Listener addresses need a restart; a reload that changes one keeps the running listener and lists the
setting under pending restart in `scrim status`.

### Admin API authentication

On the Unix socket (the default) the operator is the peer: only the user scrim runs as, or root,
is accepted, and approvals record `user:<name>` as the approver. The socket is mode 0600.

A TCP admin listener (`admin.url: http://127.0.0.1:9792`) requires `admin.token`, a reference to a
token of at least 16 bytes; the daemon refuses to start without one. Clients send it as a bearer
token (`scrim approve` reads the same setting). The daemon serves plain HTTP: put TLS in front of it
if it leaves the host.

Besides the endpoints in [approvals.md](approvals.md) the admin API serves:

| Method and path | Result |
| --- | --- |
| `GET /v1/daemon` | Process ID, version, readiness with failing checks, every address, the capture directory, the data plane's status and the runtime report (interception modes from bound listeners and open `scrim run` sessions, protections, providers) that `scrim status` and `scrim doctor` print |
| `GET /v1/ca` | The tool-proxy CA certificates clients must trust, PEM (public, no operator needed) |

The same information is written to `daemon.json` next to the admin socket (mode 0600) and removed on
shutdown.

## Snapshots

The data plane decides from a snapshot the control plane pushes: every value in the stores'
redaction sets with its catalog binding (bound hosts, inject locations, declared placeholder, value
class), the placeholder keys, the compiled policy table, the provider routes and chain, the
listeners, the capture rules and capture mode, and the tool-proxy CA.

A new snapshot is pushed after any store value change (load, refresh, write, capture, expiry), any
catalog reload, any configuration reload, any policy reload and any break-glass change. Changes
within `dataplane.push-debounce` (200ms) become one push. Pushes never block requests: the data plane
swaps the snapshot atomically. A rotated or deleted value stays in the snapshot for redaction during
the store's retention, but only the current value is injectable.

The restore settings travel in every snapshot too: `restore.display-mode` (`values`, or
`placeholders` while screen sharing), `restore.builtin-tools`, the `restore.tools` aliases and the
weakening `restore.allow-shell-data-commands` and `restore.allow-reveal-credentials`. Changing one
and reloading takes effect with the next push.

Catalog entries whose secret no store's `redact` list loads are read once in the background so they
are redacted and injectable too.

### Placeholder keys

Placeholders are an HMAC of the value under a versioned key. Without configuration the daemon
generates a 32-byte key once and keeps it in `$XDG_STATE_HOME/scrim/keys/placeholder-01.key` (mode
0600, directory 0700; a key readable by others is refused). Several replicas, or a key you want to
manage yourself, use references:

```yaml
redaction:
  placeholder-keys:
    k2: {version: 2, key: file:/run/secrets/scrim-placeholder-k2}
    k1: {version: 1, key: file:/run/secrets/scrim-placeholder-k1}
```

The highest version is current; lower ones keep resolving placeholders made before a rotation. A
changed key collection is picked up on reload. Key material is never logged.

## Callbacks from the data plane

- **Asks** (a rule says ask, a residual rule could decide, or an allow rule leaves a grant) go to the
  gate: break-glass, the full rule set, grants, then an approval that waits for a human. No answer
  by the data plane's deadline denies.
- **Captures** (a tool-proxy capture rule took a token from a response) go through the gate as
  `store.write` on the rule's `store-ref`, then into the store through its refresher, so the value is
  redacted before the agent gets the placeholder. A policy rule must allow the write; without one
  the field is withheld from the agent.
- **Events** are written to the audit log (metadata only, action `dataplane.<kind>`) in one
  transaction per batch and counted in metrics.

## Capture mode

`scrim proxy --capture DIR` (or `proxy.capture.dir`; `--capture` alone uses
`$XDG_STATE_HOME/scrim/capture`) writes every provider request exactly as it
left, and the response as received, to `DIR`, so you can check what the provider saw. The directory
is created with mode 0700 and the daemon refuses to start if group or others can access it. The
agent's own `authorization` and `x-api-key` headers are masked in captures; bodies are byte for byte
what the provider received. Files older than `proxy.capture.retention` (7 days) are deleted.

Captures hold only post-redaction bytes, but they are still your prompts: turn capture off when you
are done.

## Chained upstream

`proxy.chain.url` sends every redacted provider request to another proxy (for example a context
compression proxy) instead of the provider. Redaction happens before the chain and placeholder
resolution after it. `proxy.chain.on-unavailable: direct` sends the redacted request to the provider
when the chain is down, and audits the skip; the default `fail` refuses the request.

## Shutdown and reload

SIGINT or SIGTERM: the HTTP listeners stop accepting and finish in-flight requests (up to 15s), the
data plane is stopped (held asks are denied), the sockets and `daemon.json` are removed, state is
closed and every value and key in memory is wiped.

SIGHUP, or a change to a config file while `config.watch` is on, reloads the configuration. An
invalid reload is rejected and the previous configuration stays in force.

## Running it as a service

`scrim install` sets the daemon up as a service and `scrim uninstall` removes it again
([service.md](service.md)):

```sh
scrim install --user            # systemd user unit, sockets in $XDG_RUNTIME_DIR/scrim/
sudo scrim install --system     # dedicated user scrim, hardened unit, sockets in /run/scrim/
scrim install --quadlet         # the container image under rootless podman
```

`scrim run` finds a running service on its own: this user's daemon first, then the system
service's agent API at `/run/scrim/api.sock`, and starts a private daemon only when neither runs.

## From Go: `scrim run` and tests

Package `internal/daemon` exposes the daemon to other commands:

```go
d, err := daemon.Start(ctx, daemon.Options{Config: opts})   // binds everything, starts the data plane
err = d.WaitReady(ctx)                                     // data plane holds a snapshot, listeners bound
a := d.Addrs()                                             // BaseURL, ForwardProxy, AgentAPI, Admin, ...
err = d.Shutdown(ctx)

info, d, err := daemon.Ensure(ctx, daemon.Options{Config: opts}) // reuse a running daemon or start one here
info, err := daemon.Connect(ctx, cfg)                            // ask the running daemon, ErrNotRunning if none
l, err := daemon.Acquire(ctx, daemon.Options{Config: opts})       // what scrim run uses: Ensure, or the system service
```

`Ensure` returns `d == nil` when it found a running daemon; otherwise the caller owns `d`.
`Acquire` with nothing configured tries this user's admin socket, then the system service through
its agent API (`GET /v1/endpoints`), then starts a daemon in the process.
