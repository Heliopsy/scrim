# scrim-dataplane

The scrim data plane binary (design D1, D8, D11, D12). The control plane starts it as a child,
hands it one end of a socketpair (`--fd <n>` or `SCRIM_DP_FD`) and talks gRPC over it
(`proto/scrim/dataplane/v1`). It exits when the control plane's end closes.

## What it wires together

One `ApplySnapshot` builds, off the request path:

| Part | From | Used by |
| --- | --- | --- |
| Redaction core (`scrim_redact::Snapshot`) | `values`, `placeholder_keys`, `redaction` | everything below |
| Decisions (`policy::Decisions`: `scrim_policy::Table`, `RestoreEngine`) | `policy`, `restore`, values' metadata | request gate, injection policy, restore policy |
| LLM engine snapshot (`scrim_llm::core::CoreEngine`) | core, decisions as gate and restore policy, `routes` | base-URL listeners, provider hosts on the forward proxy |
| Tool proxy snapshot (compiled) | values with bindings, generated placeholders, `capture_rules`, core as response redactor, decisions as injection policy | forward-proxy and tool-proxy listeners |

These go into one immutable bundle, published with a single atomic swap. The LLM proxy and the
tool proxy read the bundle through snapshot sources, once per request, so a request never mixes
versions. Listeners are reconciled after the swap. A snapshot that fails any step is rejected and
the bundle in force stays. Before the first snapshot there are no listeners and both engines
refuse with 503 `not_ready`.

Entry `i` of `values` is entry id `i` in the core. A slug that is not a valid placeholder slug is
derived from the slug, name or reference. Without keys and values an ephemeral random key stands
in. Routes: the snapshot's (`anthropic` and `openai` providers; an empty `path_prefix` becomes
`/<name>`; `chain` sends the redacted request to a chained proxy), or the built-in
`/anthropic` and `/openai` routes when the snapshot has none.

## Listeners

| Kind | Address | Served by |
| --- | --- | --- |
| `BASE_URL` | `host:port` | LLM proxy |
| `UNIX` | socket path, mode 0600, removed when the listener stops | LLM proxy |
| `FORWARD_PROXY`, `TOOL_PROXY` | `host:port` | tool proxy; hosts of the LLM routes go to the LLM proxy (`LlmIntercept`) |
| `TRANSPARENT` | | not implemented, reported unbound |

## Decisions

`scrim-policy` decides (`StatusResponse.policy_engine` `table/v1`). A snapshot whose `policy` or
`restore` does not validate is rejected; a `policy` with nothing but `default_effect` and
`break_glass` (`table_format` 0) is an empty table.

| Operation | Where | Request | Outcome |
| --- | --- | --- | --- |
| `inject` | tool proxy, once per credential, after the binding checks | `secret.ref`, `.name`, `.store`, `.class`, `dest.host`, `.method`, `.path`, agent | the table: allow, deny (`403 policy_denied`), or ask |
| `llm.forward` | LLM proxy request gate, before the body is read | `provider`, agent | deny and ask rules only; the default and break-glass do not stop forwarding |
| `restore` | LLM proxy, per placeholder | `tool.name`, `secret.*`, agent, `provider` | the tool policy; deny or ask rules (or break-glass) keep the placeholder |

An ask goes over the `Asks` stream with the request (`PolicyRequest`), the rule and its reason, a
deadline, and the caller (`AskCaller`). The operation waits at most `Policy.ask_timeout_millis`
(default 120 s); a timeout, a closed stream or anything but an allow answer denies. Grants are never
cached: the next request asks again and the control plane reads its grants. Every decision is an
`EVENT_KIND_DECISION` event (rule, effect, `op`, `decided` = `data_plane` or `control_plane`,
`grant_id`, session).

Restore: text follows `Snapshot.restore.display_mode` (absent `restore` restores nothing). Shell
and edit tool calls are buffered and restored through `RestoreEngine::restore_tool_input`, each
value escaped for its shell, heredoc or interpreter context, or kept where it would become code.
Credentials are never restored, and scrim-llm hands the policy display values only. Thinking and
signatures stay byte-identical.

Break-glass also strips every credential's binding from the tool proxy snapshot, so nothing is
injected even before the table is consulted.

## Identity

The data plane holds no session tokens and no peer-to-agent mapping (`identity.rs`). It reads the
Unix socket peer (base-URL Unix listener), the session named as the user of
`Proxy-Authorization: Basic` (forward proxy, `HTTPS_PROXY=http://<session>:<token>@host:port`; the
password is never read) or the `x-scrim-session` header (base URL; stripped before forwarding). A
request with none is an unknown caller (`agent.known` false), decided locally. A request with any
is one the data plane cannot place: its agent fields are unknown to the table, so a rule on them
goes to the control plane with `AskCaller` (session id, peer uid, gid, pid) to resolve and verify,
and a restore rule on them keeps the placeholder.

## Events and status

Both proxies' audit events reach the Events stream as metadata only: one redaction event per
forwarded LLM request (with its count), guard repairs, detector hits, restores, injections and
every refusal with its code. Tool-proxy captures go over the Captures stream. Status reports
readiness (bundle in force, tool proxy ready, every listener bound), each listener with its kind,
the snapshot version, value count, the redaction engine and pattern count, short values, values
below the floor (not protected) and the decision engine.

## Environment

| Variable | Meaning |
| --- | --- |
| `SCRIM_DP_FD` | inherited socket, if `--fd` is not given |
| `SCRIM_DP_MLOCK` | `auto` (default), `require` or `off` |
| `SCRIM_DP_LOG` | log filter, default `info`; JSON lines on stderr |
| `SCRIM_DP_EXTRA_CA_FILE` | extra PEM roots for upstream TLS, both proxies |

## Tests

`tests/boundary.rs` drives the gRPC service in process. `tests/e2e.rs` starts the real binary
with a socketpair, pushes a snapshot with generated secrets, a decision table and restore settings,
and sends traffic through every listener kind:

- Anthropic Messages over TCP, the Unix socket and `CONNECT` to `api.anthropic.com`: the provider
  gets placeholders only; the display value comes back restored in text, the credential never, and
  a `curl` tool call keeps both placeholders.
- A display value with spaces and both kinds of quotes restored into a Bash `echo` as one
  single-quoted word; the credential kept in another Bash call and in text.
- Injection toward the credential's bound host (injected, the echo redacted back), toward another
  host (`unbound_destination`), and on a path a deny rule covers (`policy_denied`, nothing sent).
- An ask rule round-tripping over the `Asks` stream: answered allow (injected, the ask carries the
  request, rule, deadline and the session named on the proxy connection), then deny (asked again,
  no grant cached), then no answer (denied after the ask timeout), then the stream closed (denied
  at once). A provider request naming a session a deny rule could match is asked about and refused.
- Break-glass: redaction continues, nothing is restored or injected.
- Refusal before the first snapshot, and a race of applies against readers checking every engine
  sees one version.

Events, asks, refusal bodies and the binary's stderr are checked for the values (raw, JSON-escaped
and base64). Socket files live in a short temporary directory, so long worktree paths stay under
the Unix socket path limit.
