# Approvals, grants and break-glass

When a rule decides `ask` (see [policy.md](policy.md)), scrim holds the operation, records a pending
approval in the state backend and sends it to every configured notifier. The first decision that
arrives settles it. Nobody answering within the timeout is a denial.

```text
pending ──approve──▶ approved, and a grant is created
   │ ────deny──────▶ denied
   └────timeout────▶ expired (denied)
```

An approval moves out of pending exactly once. A second button tap, a replayed link, or a decision
from a second notifier is refused and changes nothing. Every transition, every notification and
every refused link is written to the audit log in the same transaction as the change.

Notifications carry names and metadata: agent, action, secret reference, destination host, method
and path (without its query string), tool, rule and reason. They never carry a secret value or a
request body.

## Settings

| Key | Default | Meaning |
| --- | --- | --- |
| `approvals.timeout` | `2m` | How long an approval waits before it is denied. A rule's `approval.timeout` overrides it. |
| `approvals.public-url` | empty | Base URL where approvers' devices reach the decision endpoint, e.g. `https://scrim.example.org`. Without it notifiers get no buttons and you decide with `scrim approve`. |
| `approvals.signing-key` | empty | Reference (`env:NAME`, `file:/path`) to a key of at least 32 bytes that signs decision links. Set it whenever the state backend is not memory or there is more than one replica; without it each process uses a random key and its links die with it. |
| `approvals.poll-interval` | `1s` | How often a held operation re-reads its approval, which bounds how long a decision recorded on another replica takes to release it. |
| `grants.default-ttl` | `30m` | Grant duration when neither rule nor approver chooses one. |
| `grants.max-ttl` | `8h` | Longest grant anything can create. A rule's `grant.max_ttl` can only lower it. |
| `policy.deny-all` | `false` | Break-glass from configuration. |
| `policy.deny-all-refresh` | `1s` | How often each replica re-reads the break-glass state. |
| `admin.url` | empty | Where `scrim approve` and friends reach the admin API: `unix:/path` or `http(s)://host:port`. Empty means `unix:$XDG_RUNTIME_DIR/scrim/admin.sock`, or `unix:$TMPDIR/scrim-<uid>/admin.sock` without `$XDG_RUNTIME_DIR` ([running.md](running.md#runtime-directory)). |

The full list is in [configuration.md](configuration.md). Each key is also an environment variable
(`SCRIM_APPROVALS_TIMEOUT`) and, where marked in
`scrim config show`, a flag (`--approvals-timeout`).

## Decision links

Each notifier gets its own pair of links:

```text
https://scrim.example.org/v1/approvals/<id>/decide?t=<token>
```

The token is `v1.<key id>.<payload>.<HMAC-SHA256>`, where the payload names the approval, the
action (approve or deny), the expiry (the approval's) and the notifier. A link is refused if it
was forged, signed with a key scrim no longer has, issued for another approval, or expired.

Opening a link with GET shows the request and a confirm button and decides nothing, so chat link
previews and mail scanners cannot approve anything. POST decides; that is what the ntfy buttons do.

Rotate the signing key by adding the new key next to the old one; links signed with the old key
keep working until it is removed. Approvals are short-lived, so one timeout after the switch the old
key can go.

## Notifiers

### ntfy

[ntfy](https://ntfy.sh) pushes to a phone with **Approve** and **Deny** buttons. The buttons POST
straight to scrim's decision links, so ntfy never carries a decision and the phone needs to reach
`approvals.public-url`.

| Key | Meaning |
| --- | --- |
| `notify.ntfy.url` | ntfy server, e.g. `https://ntfy.sh` or your own. Setting it enables the notifier. |
| `notify.ntfy.topic` | Topic to publish to. Anyone who can read it sees approval metadata: use an access-controlled topic, or at least a long random name. |
| `notify.ntfy.token` | Reference to an ntfy access token, sent as `Authorization: Bearer`. |
| `notify.ntfy.priority` | 1 to 5, default 4. |

```yaml
approvals.public-url: https://scrim.example.org
approvals.signing-key: file:/run/credentials/scrim/approval-key
notify.ntfy.url: https://ntfy.example.org
notify.ntfy.topic: scrim-approvals-7f3a9c
notify.ntfy.token: env:SCRIM_NTFY_TOKEN
```

Subscribe to the topic in the ntfy app. Without `approvals.public-url` the message says which
`scrim approve` command to run instead.

`just e2e-ntfy` runs an approve and a deny round trip against a local ntfy in rootless podman; CI
runs the same test.

### Webhook

The webhook notifier sends each approval to an HTTP approval service and accepts its decision in
the response, by polling, or by a callback to the decision link. Its format is
[nono's approval webhook protocol v1](https://github.com/nolabs-ai/nono/blob/main/docs/protocols/approval-webhook-v1.md),
so one approval service can serve both tools.

| Key | Meaning |
| --- | --- |
| `notify.webhook.url` | Submit URL, e.g. `https://approvals.example.org/api/v1/approvals`. https, or http to a loopback host. Setting it enables the notifier. |
| `notify.webhook.secret` | Reference to a shared secret (at least 32 bytes) for request signatures. |
| `notify.webhook.hold` | Longest time one request may be held open, default `30s`; sent as `X-Nono-Timeout-Secs`, capped by the approval's remaining time. |
| `notify.webhook.poll-interval` | Pause between polls when the receiver does not hold, default `2s`. |

**Submit.** `POST <url>`:

```json
{
  "backend": "webhook",
  "request": {
    "capability_type": "endpoint",
    "request_id": "<approval id>",
    "session_id": "<agent session, or agent id>",
    "reason": "Writes to GitHub need a human",
    "child_pid": 0,
    "route_id": "github-write",
    "credential_route": "bao://kv/agents/github",
    "upstream": "api.github.com",
    "method": "POST",
    "path": "/repos/acme/app/issues",
    "rule_label": "github-write[POST /repos/acme/app/issues]",
    "scrim": {
      "agent": "claude-laptop",
      "agent_kind": "session",
      "action": "inject",
      "ref": "bao://kv/agents/github",
      "rule": "github-write",
      "expires_at": "2026-11-20T12:02:00Z",
      "approve_url": "https://scrim.example.org/v1/approvals/<id>/decide?t=...",
      "deny_url": "https://scrim.example.org/v1/approvals/<id>/decide?t=...",
      "summary": "claude-laptop: inject bao://kv/agents/github toward api.github.com"
    }
  }
}
```

`capability_type` is `endpoint` when there is a destination host, `command` (with `command`,
`caller`, `intercept_rule`) for a tool or command, and `secret` for store writes, generation and
capture, which have no nono equivalent. Receivers must ignore fields they do not know.

**Answer.** `200` with a final status, or `202` with `{"state": "pending"}` after holding the
request:

```json
{ "request_id": "<id>", "state": "granted", "decision": "granted" }
{ "request_id": "<id>", "state": "denied", "decision": "denied", "reason": "not today" }
{ "request_id": "<id>", "state": "pending" }
```

nono's spellings are accepted (`approve`, `allow`, `reject`, `block`, the `_session` variants, which
scrim treats as plain grant and deny). Session-wide answers have no meaning for scrim: grants are
created by scrim from the rule's grant settings.

**Poll.** `GET <url>/<request_id>` with the same hold semantics, repeated until a final state or the
approval expires.

**Callback.** Instead of answering, the receiver can POST to `request.scrim.approve_url` or
`deny_url` whenever its human decides. The token in the link is the authority.

**What settles.** A grant or denial settles the approval through the same single-use token check as
a phone button. A `timeout` answer, any non-2xx status, a redirect (never followed), or a body
without a recognised decision settles nothing; the approval stays pending for other notifiers and is
denied when it expires. This is where scrim differs from nono, which denies on the spot: here a
broken webhook cannot deny on behalf of a human who answers on the phone.

**Signatures.** With `notify.webhook.secret` set, every request carries:

```text
X-Scrim-Timestamp: <Unix milliseconds>
X-Scrim-Request-Id: <random nonce, fresh per HTTP request>
X-Scrim-Content-SHA256: sha256:<hex digest of the exact body bytes>
X-Scrim-Signature: hmac-sha256=<base64url HMAC-SHA256(secret, canonical)>
```

with `canonical` being these lines joined by `\n`:

```text
scrim-webhook-v1
<METHOD>
<path and query as sent>
<timestamp>
<request id>
<digest>
```

A receiver must check the signature, reject timestamps outside a short skew window and reject a
reused request ID. `webhook.Verify` in `internal/notify/webhook` is a reference implementation.
nono's signed variant (ECDSA keys from platform enrollment) is not supported; responses are
trusted on the strength of TLS to the configured URL.

### Plugins

Any other channel can be added as a notifier plugin, a separate executable configured under
`notify.plugins.<name>`. It gets the same summary and decision links as the built-in notifiers and,
like them, only delivers. See [plugins.md](plugins.md).

### Terminal

With `notify.terminal.enabled` (default on) the control plane prints each approval to its terminal:

```text
scrim: approval 3f9c... pending (claude-laptop: inject bao://kv/agents/github toward api.github.com, rule github-write, expires in 2m0s)
  scrim approve 3f9c...
  scrim deny 3f9c...
```

From any shell that can reach the admin API:

```sh
scrim approvals list                      # pending; --status all|approved|denied|expired, --agent, --json
scrim approvals show <id>
scrim approve <id> --ttl 1h --reason "release window"
scrim deny <id> --reason "not during the freeze"
```

`--ttl` is capped at the rule's `grant.max_ttl` and `grants.max-ttl`; the output says when it was.
The operator's name comes from the admin connection and is recorded as the approver.

## Just-in-time grants

Approving an ask creates a grant. So does an allow rule with `grant.ttl` ("allow with a duration").
A grant belongs to one agent identity and one secret reference, and covers:

| `grant.scope` | Later requests it covers |
| --- | --- |
| `request` (default) | same destination host and same tool |
| `host` | same destination host, any tool |
| `secret` | anything on that reference that policy would send to ask |
| `once` | nothing: the approval releases the one operation, and the next one asks again |

A grant only ever turns an ask into an allow. A deny rule still denies, break-glass still denies,
and another agent never matches it. `grant.uses` limits how many operations it lets through; the
operation the approval released does not count against it.

```sh
scrim grants list                 # active grants; --all for expired, revoked and used up; --agent
scrim grants revoke <id> --reason "done"
```

Grants are read from the state backend on every use, never cached, so expiry, revocation and an
exhausted use count take effect on the next request, on every replica that shares the backend.
With the memory backend a restart drops every grant and approval, and held operations end denied.

## Break-glass deny-all

```sh
scrim deny-all on --reason "token pasted into a transcript"
scrim deny-all status
scrim deny-all off --reason "rotated"
```

While it is on, every injection, restore, grant and approval is refused: policy decisions are deny,
grants are not honoured, no approval can be created or approved, every pending approval is denied
on the spot, and the data plane snapshot carries `break_glass` so the data plane denies without
asking. Provider redaction keeps working.

The state is the newest `breakglass.engaged` or `breakglass.released` audit entry, so it survives a
restart with a durable backend, reaches every replica within `policy.deny-all-refresh`, and nobody
can change it without leaving an audit entry. Turning it off always takes an explicit `scrim
deny-all off`. When `policy.deny-all: true` is set in configuration, `off` is refused until the
setting is changed.

## Admin API

The CLI commands above call these endpoints. They belong on the authenticated admin listener only;
the handler refuses any request the listener has not attributed to an operator.

| Method and path | Body | Result |
| --- | --- | --- |
| `GET /v1/approvals?status=&agent=&limit=` | | approvals |
| `GET /v1/approvals/{id}` | | approval |
| `POST /v1/approvals/{id}/approve` | `{"ttl": "1h", "reason": "..."}` | approval, grant ID and ttl, `ttl_capped` |
| `POST /v1/approvals/{id}/deny` | `{"reason": "..."}` | approval |
| `GET /v1/grants?agent=&active=false` | | grants |
| `POST /v1/grants/{id}/revoke` | `{"reason": "..."}` | grant |
| `GET /v1/deny-all` | | status |
| `POST /v1/deny-all` | `{"active": true, "reason": "..."}` | status |

Errors are `{"error": "...", "code": "..."}` with codes `already_decided` (409), `expired` (410),
`token_invalid` (403), `token_expired` (410), `deny_all` (403), `deny_all_configured` (409),
`not_found` (404), `bad_request` (400) and `unauthenticated` (401).

The decision link endpoint, `GET` and `POST /v1/approvals/{id}/decide`, is the only part meant to be
reachable from outside, at `approvals.public-url`.
