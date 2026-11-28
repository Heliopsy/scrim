# scrim-toolproxy

The HTTPS tool proxy of the scrim data plane (design D5, D8). Agents keep placeholders in their
commands, files and configuration; this proxy swaps in the real credential only on requests toward
the hosts that credential is bound to, and redacts known values out of every response, so the agent
sees placeholders back.

`scrim-dataplane` builds one `ToolProxy`, feeds it the credentials of each snapshot and serves it
on the `FORWARD_PROXY`, `TOOL_PROXY`, `TRANSPARENT` and `SNI` listeners. Provider hosts are handed
to `scrim-llm` through the `InterceptHandler`; known values are redacted with the `scrim-redact`
core; injection decisions come from `scrim-policy` through `InjectionPolicy`. Upstream connections
go through `scrim-upstream-proxy` when a corporate proxy is configured and resolve names with
`scrim-dns`, so a DNS override never points scrim back at itself.

Spec: `openspec/specs/credential-injection` and the forward-proxy requirement in
`specs/interception`. Docs: [CLI tools and credentials](../../../docs/cli-tools.md),
[interception](../../../docs/interception.md), [CA](../../../docs/ca.md).

## What it does

- **Forward proxy.** HTTP `CONNECT` (TLS intercepted with scrim's CA) and plain `http://` proxying in
  absolute form. HTTP/1.1 and HTTP/2 toward the agent and the upstream. Destinations another engine
  owns (model providers) are handed to an `InterceptHandler`.
- **CA.** P-256 CA generated with rcgen, leaf certificates per host cached and re-issued before
  expiry. Rotation keeps the previous CA working through a cross certificate until the overlap
  ends. Only the public trust bundle is exported; installing it is the control plane's job.
- **Placeholders.** Generated (`⟦scrim:acme:…⟧`), user-declared (`SCRIM_ACME_KEY`) and reference
  placeholders (`{{scrim:bao://kv/agents/acme#key}}`), found as written, percent-encoded and
  JSON `\u`-escaped. Declared word-like placeholders only match as whole words. Toward a host
  with bound credentials, a token in exact placeholder grammar that nothing resolves (a value not
  loaded yet, a credential listed in the snapshot's `unavailable`, an unknown reference) is
  refused with `credential_unavailable` instead of being sent as text.
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
- **AWS SigV4 re-signing.** A credential with `aws_sigv4` holds a secret access key and names the
  credential holding its access key id. A request whose SigV4 access key id is a placeholder of
  that credential must be signed with a placeholder of the secret (`signature_invalid`
  otherwise); its credential scope's region and service must be allowed (`unbound_destination`
  otherwise); then the session token placeholder is substituted as usual and the request is
  signed again with the real keys. Header and presigned (query) forms, body hashes,
  `UNSIGNED-PAYLOAD`, chunk-signed bodies (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`, with or without
  a signed trailer, buffered or streamed) and `aws-chunked` uploads. Signed headers the proxy
  drops (hop-by-hop, `Expect`) leave the signed header list. The secret is never sent as text.
  Checked against AWS's signing test suite (`testdata/aws-sigv4-test-suite`, Apache-2.0).
- **Client certificates.** A credential with `client_certificate` holds a PEM chain and key.
  Toward its bound hosts the proxy asks the agent for a client certificate; when the agent
  presents the credential's placeholder certificate (Ed25519, key seeded by
  `SHA-256("scrim-placeholder-cert-v1\0" || placeholder)`, see `placeholder_certificate`), the
  request goes through the binding and policy checks like any injection and the real certificate
  is presented in the upstream handshake, on a connection pool of its own. The certificate is
  never sent as text, and no other host is asked for a certificate.
- **Format-preserving placeholders.** Generated placeholders can also be shaped like the token
  (`placeholder_format: shape`, from `scrim-redact`); they are matched exactly like any other.
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
| `credential_unavailable` | 503 | the store has not delivered the value, or a placeholder toward a bound host matches no credential with a value |
| `unrepresentable_value` | 422 | the value cannot be written there (line break in a header) |
| `unsupported_encoding` | 415 | body coding scrim cannot rewrite, toward a bound host |
| `malformed_body` | 400 | body could not be decoded or parsed |
| `body_too_large` | 413 | body over the buffering limit needs rewriting |
| `resigning_unsupported` | 422 | signed request scrim cannot re-sign (SigV4 not signed with a scrim access key id placeholder, HTTP signatures, OAuth 1) or unknown digest |
| `upgrade_unsupported` | 501 | WebSocket and other upgrades toward hosts the LLM proxy does not claim |
| `bad_request` | 400 | not a proxy request scrim can handle |
| `misdirected_request` | 421 | Host or SNI differs from the CONNECT target |
| `upstream_unavailable` | 502 | upstream unreachable or failed TLS verification |
| `response_withheld` | 502 | response could not be scanned |
| `redaction_failed` | 502 | the redactor failed |
| `policy_denied` | 403 | the injection policy refused a credential (a rule, a denied or expired approval) |
| `signature_invalid` | 403 | a SigV4 request names a placeholder access key id but is not signed with the placeholder secret, or a chunk or trailer signature does not chain |

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

Other entry points: `ToolProxy::serve_connection` and `serve_connection_with_certificate` (one
accepted connection, the latter from a TLS listener that verified a client certificate),
`ToolProxy::serve_transparent` (one connection of a `TRANSPARENT` or `SNI` listener, routed by
server name or `Host`), `ToolProxy::handle` (one request toward a known destination, after the
connection layer).

Seams for other work: `Redactor` (the `scrim-redact` matcher; `ValueRedactor` is a small exact
stand-in), `RequestSigner` (signature schemes other than AWS SigV4, which is built in),
`InjectionPolicy` (`Snapshot::injection`): once per credential a request uses, after every binding
and location check and before anything is substituted, it decides allow or deny and may wait for
an approval. Every request carries a `ClientInfo` extension: the client's address and the session
it named as the user of `Proxy-Authorization: Basic` on the proxy connection (the password is
never read).

Limits (`ToolProxySettings`): `max_buffered_body_bytes` (32 MiB), `max_decoded_body_bytes`
(128 MiB), `captured_values_capacity` (1024). These are builder fields, not scrim settings: the
data plane builds the proxy with the defaults and no configuration key changes them.

## Limitations

- Request bodies above the buffering limit are streamed unmodified; a placeholder in one cuts the
  request off (`body_too_large`). Encoded oversized bodies toward bound hosts are refused.
- Streamed responses hold back up to one value length minus one byte, so the last bytes of a chunk
  can wait for the next one.
- Buffered responses drop trailers; streamed ones keep them, redacted.
- A captured JSON field is re-serialised, so that response's formatting changes.
- Certificate-pinning clients fail closed and are listed in `ProxyStatus::unsupported_destinations`.

## Tests

`cargo test -p scrim-toolproxy` (in `dataplane/`) runs:

- unit tests per module;
- `tests/proxy.rs` against in-process fake upstreams (HTTP/1.1, HTTP/2, every coding, capture,
  rotation, pinning);
- `tests/transparent.rs`: transparent and SNI connections, routed by server name or `Host`;
- `tests/sigv4.rs`: an upstream that checks every SigV4 signature with the real secret;
- `tests/clientcert.rs`: an upstream that requires a client certificate;
- `tests/clients.rs` with curl, git clone and push over HTTPS (`git http-backend`), Python
  `requests` and Node `fetch`, each skipped when the tool is missing;
- `tests/fuzz_seeds.rs`: the committed `sigv4` fuzz seeds match what AWS's test suite gives.

End to end, ignored by default: `tests/e2e_aws.rs`, run by `test/e2e/toolproxy-aws.sh` (the aws
CLI against LocalStack in rootless podman: `sts get-caller-identity`, `s3 cp`, `s3 ls`, a
presigned URL, an unbound region), and `tests/e2e_kube.rs`, run by `test/e2e/toolproxy-kube.sh`
(kubectl with certificate authentication against a kind cluster).

Fuzzing (`fuzz/`, nightly): `cargo +nightly fuzz run sigv4` (parsers, chunk re-signer, and the
sign, verify, re-sign round trip on arbitrary requests).
