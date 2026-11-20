# scrim-toolproxy

The HTTPS tool proxy of the scrim data plane (design D5, D8). Agents keep placeholders in their
commands, files and configuration; this proxy swaps in the real credential only on requests toward
the hosts that credential is bound to, and redacts known values out of every response, so the agent
sees placeholders back.

Spec: `openspec/changes/scrim-v1/specs/credential-injection` and the forward-proxy requirement in
`specs/interception`.

## What it does

- **Forward proxy.** HTTP `CONNECT` (TLS intercepted with scrim's CA) and plain `http://` proxying in
  absolute form. HTTP/1.1 and HTTP/2 toward the agent and the upstream. Destinations another engine
  owns (model providers) are handed to an `InterceptHandler`.
- **CA.** P-256 CA generated with rcgen, leaf certificates per host cached and re-issued before
  expiry. Rotation keeps the previous CA working through a cross certificate until the overlap
  ends. Only the public trust bundle is exported; installing it is the control plane's job.
- **Placeholders.** Generated (`⟦scrim:acme:…⟧`), user-declared (`SCRIM_ACME_KEY`) and reference
  placeholders (`{{scrim:bao://kv/agents/acme#key}}`), found as written, percent-encoded and
  JSON `\u`-escaped. Declared word-like placeholders only match as whole words.
- **Binding.** Hosts (`api.example.com`, `*.example.com`, optional `:port` or `:*`), methods and
  path globs (matched after removing dot segments). Plain HTTP only with `allow_plaintext_http`.
  The Host header or `:authority` and the TLS server name must name the connection's destination.
- **Locations.** `header`, `header:<name>`, `cookie`, `query`, `path`, `body`, `anywhere`;
  default `header`. A placeholder elsewhere is refused.
- **Substitution.** URL path and query (percent-encoded), headers, Basic credentials (decoded and
  re-encoded), cookies, JSON (string-escaped), form, XML and multipart bodies (encoded per part).
  Bodies are decoded and re-encoded through gzip, deflate, br and zstd; `Content-Length`,
  `Content-Digest`, `Repr-Digest`, `Digest` and `Content-MD5` are recomputed.
- **Responses.** Headers, trailers and bodies are redacted, buffered (known small length, digests,
  capture rules) or streamed chunk by chunk through decoder, redactor and encoder. An injected
  value echoed back shows the exact placeholder the agent sent.
- **Capture.** A rule names a JSON pointer or response header; the value goes to the
  `CaptureSink` (the control plane stores it) and the agent gets the returned placeholder. If
  storing fails the field becomes `⟦scrim:withheld:capture-failed⟧`.

Everything fails closed: a refused request sends nothing upstream, a response that cannot be scanned
is withheld, a stream that fails midway is cut off.

## Errors

Refusals are HTTP responses with `x-scrim-error: <code>` and a JSON body
`{"error":{"type":"scrim_tool_proxy_error","code":…,"message":…}}`. Messages name credentials by
alias and never contain a value.

| Code | Status | Meaning |
| --- | --- | --- |
| `not_ready` | 503 | no snapshot applied yet |
| `unbound_credential` | 403 | the credential has no binding |
| `unbound_destination` | 403 | host, port, scheme, method or path not bound |
| `undeclared_location` | 403 | placeholder in a location the credential does not declare |
| `credential_unavailable` | 503 | the store has not delivered the value |
| `unrepresentable_value` | 422 | the value cannot be written there (line break in a header) |
| `unsupported_encoding` | 415 | body coding scrim cannot rewrite, toward a bound host |
| `malformed_body` | 400 | body could not be decoded or parsed |
| `body_too_large` | 413 | body over the buffering limit needs rewriting |
| `resigning_unsupported` | 422 | signed request (SigV4, HTTP signatures, OAuth 1) or unknown digest |
| `upgrade_unsupported` | 501 | WebSocket and other upgrades |
| `misdirected_request` | 421 | Host or SNI differs from the CONNECT target |
| `upstream_unavailable` | 502 | upstream unreachable or failed TLS verification |
| `response_withheld` | 502 | response could not be scanned |
| `redaction_failed` | 502 | the redactor failed |

## Use

```rust,ignore
let proxy = ToolProxy::builder()
    .audit(audit_sink)            // AuditSink: events to the control plane
    .capture_sink(capture_sink)   // CaptureSink: stores captured values
    .intercept(llm_engine)        // InterceptHandler: provider hosts
    .build()?;
proxy.apply(Snapshot::from_proto(&snapshot, |entry| redact_core.placeholders(entry))?)?;
std::fs::write(ca_path, proxy.ca().trust_bundle_pem())?;
proxy.serve(listener, shutdown).await?;
```

Seams for other work: `Redactor` (the `scrim-redact` matcher; `ValueRedactor` is a small exact
stand-in), `RequestSigner` (AWS SigV4, task 10a.2), `ToolProxy::handle` (transparent listeners).

Settings (`ToolProxySettings`): `toolproxy.max_buffered_body_bytes` (32 MiB),
`toolproxy.max_decoded_body_bytes` (128 MiB), `toolproxy.captured_values_capacity` (1024).

## Limitations

- Request bodies above the buffering limit are streamed unmodified; a placeholder in one cuts the
  request off (`body_too_large`). Encoded oversized bodies toward bound hosts are refused.
- Streamed responses hold back up to one value length minus one byte, so the last bytes of a chunk
  can wait for the next one.
- Buffered responses drop trailers; streamed ones keep them, redacted.
- A captured JSON field is re-serialised, so that response's formatting changes.
- Certificate-pinning clients fail closed and are listed in `ProxyStatus::unsupported_destinations`.

## Tests

`cargo test -p scrim-toolproxy`: unit tests per module, `tests/proxy.rs` against in-process fake
upstreams (HTTP/1.1, HTTP/2, every coding, capture, rotation, pinning), and `tests/clients.rs`
with curl, git clone and push over HTTPS (`git http-backend`), Python `requests` and Node `fetch`,
each skipped when the tool is missing.
