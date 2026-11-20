# scrim-dataplane

The scrim data plane binary (design D1, D8, D11, D12). The control plane starts it as a child,
hands it one end of a socketpair (`--fd <n>` or `SCRIM_DP_FD`) and talks gRPC over it
(`proto/scrim/dataplane/v1`). It exits when the control plane's end closes.

## What it wires together

One `ApplySnapshot` builds, off the request path:

| Part | From | Used by |
| --- | --- | --- |
| Redaction core (`scrim_redact::Snapshot`) | `values`, `placeholder_keys`, `redaction` | everything below |
| LLM engine snapshot (`scrim_llm::core::CoreEngine`) | core, restore policy, `routes` | base-URL listeners, provider hosts on the forward proxy |
| Tool proxy snapshot (compiled) | values with bindings, generated placeholders, `capture_rules`, core as response redactor | forward-proxy and tool-proxy listeners |
| Decisions (`policy`) | `policy` | restore policy, break-glass |

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

The decision-table evaluator is not in this build. The stand-in (`StatusResponse.policy_engine`
`standin/v1`) restores display values in assistant text only, keeps every placeholder in tool
arguments, never restores credentials, sends no asks, and under break-glass restores and injects
nothing. Credential injection follows each credential's host, method, path and location binding.
The ask broker never caches grants: the control plane reads them on every use.

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
with a socketpair, pushes a snapshot with generated secrets and sends traffic through every
listener kind: Anthropic Messages over TCP and the Unix socket and through `CONNECT` to
`api.anthropic.com` (the provider gets placeholders only, the stream comes back with the display
value restored in text and placeholders kept in tool arguments); a placeholder toward the
credential's bound host (injected, the echo redacted back) and toward another host (refused,
nothing sent); break-glass; refusal before the first snapshot; and a race of applies against
readers checking every engine sees one version. Events, refusal bodies and the binary's stderr
are checked for the values.
