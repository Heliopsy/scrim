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

### Requirement: Streaming without whole buffering

The proxy SHALL relay streamed responses incrementally. It SHALL hold back no more bytes than needed
to resolve a placeholder split across chunks and SHALL flush held bytes when the content block or
stream ends.

#### Scenario: Long streamed answer

- **WHEN** a provider streams a response over many seconds
- **THEN** the agent receives events as they arrive, delayed only by the bounded hold-back

### Requirement: Capture mode

The proxy SHALL offer a capture mode that writes every request exactly as it left for the provider,
and the response as received, to a configured directory, so users can verify what the provider saw.

#### Scenario: Verifying what the provider saw

- **WHEN** capture mode is on and an agent sends a request containing a known secret
- **THEN** the capture directory contains the outgoing request with only placeholders in place of the secret

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
