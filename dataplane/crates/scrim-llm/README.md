# scrim-llm

The LLM proxy of the scrim data plane (design D2 to D5, D8, D12). Agents point their provider base
URL at it, or reach it through the forward proxy. Every request body is redacted on its raw bytes
and checked by an independent guard before it leaves; responses, streamed or not, get their
placeholders resolved only where the restore policy allows. Anything that cannot be made safe is
refused with a documented error and nothing reaches the provider.

Spec: `openspec/changes/scrim-v1/specs/llm-proxy`, plus the base-URL and forward-proxy parts of
`specs/interception`, `specs/redaction` (restore side) and `specs/performance`.

## What it does

- **Listeners.** TCP and Unix socket (mode 0600), HTTP/1.1 and HTTP/2 prior knowledge on the same
  port, graceful shutdown. `LlmIntercept` (feature `intercept`) plugs into `scrim-toolproxy` so
  provider hosts reached through `HTTPS_PROXY` take the same path.
- **Routing.** By path prefix on whole segments (`/anthropic`, `/openai` by default) or by provider
  host (`api.anthropic.com`, `api.openai.com`) for forward-proxy traffic. The API follows from the
  path: Anthropic Messages (and `count_tokens`), OpenAI Chat Completions, OpenAI Responses (and
  `/responses/compact`). Other paths are forwarded with the whole body redacted.
- **Upstream.** Pooled hyper client, rustls with webpki and/or native roots plus an optional extra
  CA bundle, ALPN `h2` and `http/1.1`. The agent's own `authorization`, `x-api-key` and other
  headers pass through untouched; hop-by-hop headers are dropped and `accept-encoding` is set to
  `identity` so responses can be restored.
- **Request side.** The codec parses the body with a strict span scanner (no re-serialisation) and
  lists byte-stable spans: allowlisted configuration (`model`, `max_tokens`, `stream`, ...),
  thinking text and signatures, redacted thinking, `encrypted_content`, reasoning items, and base64
  or `data:` binary parts. The redactor runs over every other byte, so unknown fields are redacted
  by default. The guard then scans the complete outgoing bytes, spans included.
- **Response side.** SSE events are framed without copying, and each content block keeps at most
  `max_len - 1` held bytes for a placeholder split across events. Text resolves under the display
  policy, tool arguments under the per-tool policy (`ToolMode::Buffered` hands the policy complete
  arguments). Thinking, reasoning, signatures and encrypted content pass byte-identical.
  Credential-class values are never restored, whatever the policy says. `*.done` events and final
  snapshots get the same resolution as their deltas.
- **Capture mode.** `<ms>-<seq>-<route>.request.{json,body}` and `.response.{json,body}` in a
  directory that must be mode 0700. Bodies are post-redaction and byte-identical to what left;
  header values outside a short allowlist are `[masked]`. Retention sweep included.
- **Chaining.** A route can send the redacted request to a chained upstream (a context-compression
  proxy such as caveman) with `on-unavailable: fail` (default) or `direct`.

## Contracts

The redaction engine sits behind traits in `engine`, delivered in a `Snapshot` that is swapped
atomically (`SnapshotCell`); a request uses one snapshot from start to end.

| Trait | Provided by | Job |
| --- | --- | --- |
| `Redactor` | `scrim-redact` | known values and variants to placeholders, on raw bytes |
| `Guard` | `scrim-redact` | independent check of the exact outgoing bytes, repair or refuse |
| `Placeholders` | `scrim-redact` | placeholder syntax (find, partial prefix) and resolution |
| `RestorePolicy` | control-plane snapshot | per site and tool: resolve or keep |
| `AuditSink` | data plane binary | metadata-only events, non-blocking |

Feature `redact` provides the production engine: `core::CoreEngine` wraps a built
`scrim_redact::Snapshot` and hands out the `Redactor`, `Guard` and `Placeholders` adapters (the
data plane binary uses it). A `Snapshot` may carry its own `routes`, so a request takes its route
and its dictionary from one version; `SnapshotCell::from_source` lets an embedder publish one
bundle for several engines. The `test-util` feature provides fakes (`testing::Fixture`) with fault
injection, a stand-in fallback detector and a recording fake upstream.

## Errors

Generated responses carry `x-scrim-error: <code>` and a provider-shaped error body (Anthropic or
OpenAI). 422 is the redaction-failed status.

| Code | Status |
| --- | --- |
| `malformed_body`, `redactor_failed`, `guard_failed`, `guard_refused`, `unscannable_content` | 422 |
| `not_ready` (with `Retry-After: 1`) | 503 |
| `no_route` | 404 |
| `body_too_large` | 413 |
| `unsupported_encoding` (compressed request body) | 415 |
| `chain_unavailable`, `upstream_unavailable` | 502 |
| `capture_failed` | 500 |

## Use

```rust,ignore
let snapshots = Arc::new(SnapshotCell::new());       // filled from the control plane
let proxy = Arc::new(Proxy::new(ProxyConfig::default(), snapshots.clone(), audit)?);
let listener = tokio::net::TcpListener::bind("127.0.0.1:9790").await?;
scrim_llm::server::serve_tcp(listener, proxy.clone(), shutdown).await;
```

Agents then use `ANTHROPIC_BASE_URL=http://127.0.0.1:9790/anthropic` or
`OPENAI_BASE_URL=http://127.0.0.1:9790/openai/v1`.

Configuration (`ProxyConfig`, kebab-case keys under `proxy.`): `routes` (name, prefix, upstream,
provider, strip-prefix, chain, hosts), `limits` (max-request-body 32 MiB, max-response-body
32 MiB, max-event 16 MiB, max-buffered-tool-input 1 MiB, offload-threshold 1 MiB), `capture`
(dir, retention-secs), `tls` (roots, extra-ca-file), `connect-timeout-ms`,
`pool-max-idle-per-host`.

Memory per stream is bounded by `max-event + open blocks x (max placeholder length - 1) +
max-buffered-tool-input`, independent of stream length.

## Tests and the latency gate

`cargo test -p scrim-llm`: unit and property tests per module (span scanner against serde_json,
SSE framing at every split, holdback at every cut), and integration tests against a recording
fake upstream: recorded Claude Code, Chat Completions and Codex-style Responses fixtures
(`tests/fixtures`, secrets generated at run time), every fail-closed path, capture, chaining
through a compression stand-in, h2c, Unix socket, upstream TLS with a private CA and connection
reuse, and the forward proxy with `curl` and `HTTPS_PROXY`.

`cargo bench -p scrim-llm --bench latency_gate` measures proxy overhead, engine-inclusive request
latency for 10, 1,000 and 10,000 secrets and per-chunk restore time on a 20,000-event stream, and
exits non-zero when a p99 exceeds `benches/budget.json`. Engine budgets are reported but enforced
only once `scrim-redact` is wired in (`engine.enforce`).

## Limitations

- Compressed request bodies are refused, not decompressed.
- A placeholder written with JSON `\u` escapes inside streamed tool arguments is left unresolved.
- Synthesised flush events in Responses streams reuse the template's `sequence_number`.
- WebSocket transports (Responses over WebSocket) are not supported.
- Gemini, Bedrock, Vertex and Foundry routes are later tasks (11.3, 11.4).
