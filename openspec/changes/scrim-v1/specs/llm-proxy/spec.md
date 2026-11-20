## Purpose

The LLM proxy sits between agents and model providers. It accepts each supported provider API,
redacts every request before it leaves, resolves placeholders in responses, and refuses to forward
anything it cannot make safe.

## ADDED Requirements

### Requirement: Supported provider APIs

The proxy SHALL accept and forward the Anthropic Messages API, the OpenAI Chat Completions API, the
OpenAI Responses API and the Gemini generateContent API, in both non-streaming and streaming form,
with request and response semantics unchanged apart from redaction and placeholder resolution.

#### Scenario: Anthropic streaming request

- **WHEN** an agent sends a streaming Anthropic Messages request through the proxy
- **THEN** the agent receives the provider's event stream with the same event types and order
- **AND** the provider receives the request with known secret values replaced by placeholders

#### Scenario: OpenAI Responses request

- **WHEN** an agent sends an OpenAI Responses API request through the proxy
- **THEN** the request is redacted and forwarded and the response is returned to the agent

### Requirement: Cloud provider routes

The proxy SHALL support Claude on Amazon Bedrock (including its binary event stream), Google Vertex,
Microsoft Foundry and Claude Platform on AWS. Where a route's authentication signs the request body,
the proxy SHALL sign the request after redaction and SHALL refuse the request when it cannot sign.

#### Scenario: Bedrock request re-signed after redaction

- **WHEN** an agent sends a Bedrock InvokeModel request containing a known secret
- **THEN** the proxy redacts the body and signs the redacted body before forwarding
- **AND** the provider accepts the signature

#### Scenario: Signing credentials missing

- **WHEN** a route requires signing and no signing credentials are configured
- **THEN** the proxy refuses the request with an error naming the missing credentials
- **AND** nothing is sent to the provider

### Requirement: Routing by path

The proxy SHALL route each incoming request to a provider by the request path prefix and SHALL
reject a request whose path matches no configured route, without forwarding it anywhere.

#### Scenario: Unknown route

- **WHEN** a request arrives on a path that matches no configured provider route
- **THEN** the proxy answers with a not-found error and forwards nothing

### Requirement: Routing by provider host

Each route SHALL be able to name provider host names. A request for one of those hosts that
reaches scrim through the forward proxy or a transparent listener SHALL be handled by the LLM
proxy with its whole path, with the same redaction, guard, capture, chaining and restore as a
base-URL request. Two routes SHALL NOT claim the same host.

#### Scenario: Agent with HTTPS_PROXY set

- **WHEN** an agent whose `HTTPS_PROXY` points at scrim sends a Messages request to `api.anthropic.com`
- **THEN** the provider receives the request with known values replaced by placeholders
- **AND** the agent receives the response with placeholders resolved under the tool policy

### Requirement: Agent provider credentials pass through

The proxy SHALL forward the agent's own provider authentication (API key, OAuth token or session
credential) to the provider unchanged and SHALL never write it to logs, captures, metrics or the
audit log.

#### Scenario: Subscription login

- **WHEN** an agent authenticated with its own OAuth login sends a request through the proxy
- **THEN** the provider receives the same authorization header the agent sent
- **AND** the header value appears in no log line or capture file

### Requirement: Upstream chaining

The proxy SHALL support forwarding to a configured chained upstream (for example a
context-compression proxy) instead of the provider, and SHALL apply redaction before the request
reaches the chained upstream and placeholder resolution after its response returns.

#### Scenario: Chained compression proxy sees only placeholders

- **WHEN** a chained upstream is configured and an agent sends a request containing a known secret
- **THEN** the chained upstream receives the request with the secret replaced by a placeholder
- **AND** the agent receives the response with placeholders resolved under the tool policy

### Requirement: Chained upstream unavailable

The proxy SHALL apply the configured `on_unavailable` behaviour when a chained upstream cannot be
reached: `fail` refuses the request, `direct` forwards the already-redacted request to the provider.
The default SHALL be `fail`.

#### Scenario: Chained upstream down with fail

- **WHEN** the chained upstream is unreachable and `on_unavailable` is `fail`
- **THEN** the agent receives an error stating the chained upstream is unavailable
- **AND** nothing is sent to the provider

#### Scenario: Chained upstream down with direct

- **WHEN** the chained upstream is unreachable and `on_unavailable` is `direct`
- **THEN** the redacted request is sent to the provider directly
- **AND** the audit log records that the chained upstream was skipped

### Requirement: Unknown request fields are redacted

The proxy SHALL treat every request field it does not positively know to be configuration as
content and redact it. Only fields on a per-API allowlist of known configuration fields SHALL be
forwarded without redaction.

#### Scenario: Undocumented field carrying a path

- **WHEN** a request contains a field not on the allowlist whose value includes a known secret
- **THEN** the forwarded request carries that field with the secret replaced by a placeholder

### Requirement: Request target and headers are redacted

The redactor SHALL run over every path segment, query key and value, and request header value the
proxy forwards, known header or not, on the raw bytes and on their percent-decoded form (in the
query also with `+` read as a space). A component changed in its decoded form SHALL be forwarded
percent-encoded. Only the agent's provider credential headers, `authorization` and `x-api-key`,
SHALL be exempt. Response headers SHALL reach the agent as sent, with no placeholder restored.

#### Scenario: Secret in a custom header

- **WHEN** an agent's request carries a known secret in a custom header such as `X-Debug-Context`, raw, quoted or base64-encoded
- **THEN** the provider receives that header with the secret replaced by a placeholder

#### Scenario: Percent-encoded secret in the query string

- **WHEN** an agent's request URL carries a known secret in a query parameter, percent-encoded or form-encoded
- **THEN** the provider receives the query with the secret replaced by a percent-encoded placeholder and the other parameters unchanged

#### Scenario: Provider credential headers pass through

- **WHEN** an agent's request carries its provider API key in `x-api-key` or `authorization`
- **THEN** the provider receives those headers byte for byte as the agent sent them

#### Scenario: Placeholder in a response header

- **WHEN** the provider's response carries a placeholder in a response header
- **THEN** the agent receives that header with the placeholder unresolved

### Requirement: Request target and headers are guarded

The guard SHALL check the exact outgoing request line and header block, credential headers
excepted, and the decoded form of every target component. It SHALL repair a component or
withhold the request, and SHALL refuse a request with a known value it cannot repair in place (in
a header name, or split across headers or components).

#### Scenario: Redactor misses a header

- **WHEN** the redactor misses a known secret in a header value or query parameter
- **THEN** the guard replaces it before the request leaves, or refuses the request with nothing forwarded

#### Scenario: Secret in a header name

- **WHEN** a known secret appears in a request header name
- **THEN** the proxy refuses the request and nothing reaches the provider

### Requirement: Raw-byte request redaction

The proxy SHALL redact the raw request bytes without re-serialising the body, parsing the body
only to locate the byte-stable spans of the next requirement. Every byte outside those spans,
including every field the proxy does not know, SHALL go through the redactor.

#### Scenario: Unchanged bytes outside secrets

- **WHEN** a recorded request containing known values is forwarded
- **THEN** the provider receives the same bytes with only the values replaced by placeholders

### Requirement: Byte-stable request spans

Values of allowlisted configuration fields, the text and signature of thinking blocks, the data of
redacted thinking blocks, encrypted reasoning and compaction content, and unscannable binary data
SHALL NOT be changed by the redactor or its fallback detectors. The guard SHALL still scan them as
part of the outgoing bytes and repair or refuse a known value found there.

#### Scenario: Detector match inside a signature

- **WHEN** a fallback detector would match bytes inside a thinking block signature that the agent sends back
- **THEN** the provider receives the signature byte-identical to what it emitted

#### Scenario: Known value inside an allowlisted field

- **WHEN** an allowlisted configuration field contains a known value
- **THEN** the redactor leaves the field alone and the guard repairs it or refuses the request

### Requirement: Ambiguous request structure is refused

A body that is not strictly valid JSON, or whose structure is ambiguous where the proxy needs to
read it (such as a duplicate `type` key in a content block), SHALL be refused as malformed, so the
proxy and the provider never disagree about which bytes are content.

#### Scenario: Ambiguous content block

- **WHEN** a content block carries two `type` members
- **THEN** the request is refused with the redaction-failed status and nothing is forwarded

### Requirement: Compressed request bodies

The proxy SHALL refuse a request body with a content encoding other than `identity`, because it
cannot redact bytes it does not see, and SHALL ask the provider for identity-encoded responses so
it can resolve placeholders in them. A response that still arrives encoded SHALL be forwarded with
its placeholders unresolved.

#### Scenario: Gzip request body

- **WHEN** an agent sends a request with `Content-Encoding: gzip`
- **THEN** the agent receives an unsupported-media-type error and nothing is forwarded

### Requirement: Fail closed on redaction error

The proxy SHALL refuse a request with a distinct error status when redaction or the guard fails for
any reason, including malformed input, an unknown schema shape or an internal error, and SHALL
never forward the original bytes as a fallback.

#### Scenario: Malformed request body

- **WHEN** a request body cannot be parsed well enough to redact it
- **THEN** the agent receives an error with the redaction-failed status
- **AND** the provider receives nothing

#### Scenario: Guard finds an unrepairable leak

- **WHEN** the guard detects a known value in the outgoing bytes and cannot repair it
- **THEN** the request is refused and the audit log records which secret reference was involved

### Requirement: Proxy error responses

Every response the proxy generates itself SHALL carry an `x-scrim-error` header naming the reason
and a body in the error shape of the provider API the request used. Its message SHALL name secret
references at most and SHALL never contain a value or request content.

#### Scenario: Redaction failure seen by an OpenAI client

- **WHEN** redaction fails for an OpenAI Responses request
- **THEN** the agent receives `x-scrim-error: redactor_failed` and an OpenAI-shaped error body

### Requirement: Proxy error statuses

The proxy SHALL answer 422 (the redaction-failed status) for malformed bodies, redactor errors,
guard errors, guard refusals and unscannable content under `block`; 503 with `Retry-After` while
redaction is not ready; 404 for an unknown route; 413 for an oversized body; 415 for a compressed
body; 502 for an unreachable provider or chained upstream; 500 when capture cannot record.

#### Scenario: Guard refusal status

- **WHEN** the guard refuses a request
- **THEN** the agent receives status 422 and the provider receives nothing

### Requirement: Streaming without whole buffering

The proxy SHALL relay streamed responses incrementally. It SHALL hold back no more bytes than needed
to resolve a placeholder split across chunks and SHALL flush held bytes when the content block or
stream ends.

#### Scenario: Long streamed answer

- **WHEN** a provider streams a response over many seconds
- **THEN** the agent receives events as they arrive, delayed only by the bounded hold-back

### Requirement: Response restore sites

The proxy SHALL resolve placeholders only in assistant text and refusals (under the display
policy) and in tool-call arguments (under the tool policy for that tool), and SHALL forward
thinking, reasoning summaries, signatures and encrypted content byte-identical. In JSON tool
arguments a value SHALL be resolved only inside a string literal, JSON-escaped.

#### Scenario: Thinking stream with a placeholder

- **WHEN** a provider streams a thinking block containing a placeholder
- **THEN** the agent receives the thinking text and its signature byte-identical

### Requirement: Held text released in order

Text held back in a stream SHALL be released before the event that ends its content block, so no
text follows a block stop, a `finish_reason` or a `*.done` event. Where a stream repeats the full
text (done events, final response snapshots), it SHALL carry the same resolution as the deltas.

#### Scenario: Placeholder split before finish

- **WHEN** a chat completion stream ends a choice while a placeholder prefix is held back
- **THEN** the held text reaches the agent before the chunk carrying `finish_reason`

### Requirement: Capture mode

The proxy SHALL offer a capture mode that writes every request exactly as it left for the provider,
and the response as received, to a configured directory, so users can verify what the provider saw.

#### Scenario: Verifying what the provider saw

- **WHEN** capture mode is on and an agent sends a request containing a known secret
- **THEN** the capture directory contains the outgoing request with only placeholders in place of the secret

#### Scenario: Agent credentials in captures

- **WHEN** capture mode records a request carrying the agent's `authorization` or `x-api-key` header
- **THEN** the captured headers show those values as masked and the body is byte-identical to what the provider received

### Requirement: Images and binary content

The proxy SHALL apply a configurable policy to images, documents and other binary content parts it
cannot scan: `pass` forwards them unscanned and records that in the audit log, `block` refuses the
request. The default SHALL be `pass`, and the limitation SHALL be reported by the status command.

#### Scenario: Screenshot with block policy

- **WHEN** a request contains an image part and the binary policy is `block`
- **THEN** the request is refused with an error naming the unscannable content type

#### Scenario: Screenshot with pass policy

- **WHEN** a request contains an image part and the binary policy is `pass`
- **THEN** the request is forwarded and the audit entry marks it as containing unscanned content

### Requirement: Provider connection reuse

The proxy SHALL reuse upstream connections across requests and SHALL forward provider rate-limit
and error responses to the agent unchanged apart from placeholder resolution.

#### Scenario: Provider rate limit

- **WHEN** the provider answers with a rate-limit error
- **THEN** the agent receives the same status and retry headers
