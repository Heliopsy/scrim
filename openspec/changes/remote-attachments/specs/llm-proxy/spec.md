## MODIFIED Requirements

### Requirement: Images and binary content

The proxy SHALL apply `redaction.binary` to the binary parts of a request (images, documents,
audio): `scan` (the default), `block` or `pass`. Under `block` it SHALL refuse every request with a
binary part, naming the content types. Under `pass`, a weakening value, it SHALL forward them
unscanned and record their media types in the audit entry. Parts only referenced follow
`redaction.remote-attachments`.

#### Scenario: Screenshot with block policy

- **WHEN** a request contains an image part and the binary policy is `block`
- **THEN** the request is refused with an error naming the unscannable content type

#### Scenario: Screenshot with pass policy

- **WHEN** a request contains an image part and the binary policy is `pass`
- **THEN** the request is forwarded and the audit entry marks it as containing unscanned content

#### Scenario: Image by URL

- **WHEN** a request contains an image part that references an `https:` URL and the remote attachment policy is `inline`
- **THEN** the proxy fetches the image, applies the binary policy to it and forwards it inline in place of the URL

## ADDED Requirements

### Requirement: Attachments referenced by URL or file ID

The proxy SHALL apply `redaction.remote-attachments` to references: `inline` (default) fetches each
URL, scans the content under the binary policy and sends it in the provider's inline form in place
of the reference; `refuse` refuses a request with a URL; `pass`, weakening, forwards references and
audits them as unscanned. Under `inline` and `refuse`, references scrim cannot fetch SHALL refuse the
request.

#### Scenario: Image URL with a secret in its metadata

- **WHEN** an Anthropic image block references a URL whose PNG carries a known value in a text chunk and the policy is `inline`
- **THEN** the request is refused with `secret_in_binary` and nothing reaches the provider

#### Scenario: Document URL inlined

- **WHEN** an OpenAI Responses `input_file` has a `file_url` to a clean PDF and the policy is `inline`
- **THEN** the provider receives the part with `file_data` holding the PDF as a base64 `data:` URL and no `file_url`

#### Scenario: Refuse policy

- **WHEN** a request references an image URL and the policy is `refuse`
- **THEN** the request is refused with `remote_attachment` and the error does not contain the URL

#### Scenario: Pass policy

- **WHEN** a request references an image URL and the policy is `pass`
- **THEN** the request is forwarded with the URL and the audit entry lists `remote:url` as unscanned

#### Scenario: Storage location

- **WHEN** a Gemini part references a `gs://` URI or a Bedrock block an `s3Location` under `inline` or `refuse`
- **THEN** the request is refused with `remote_attachment`

#### Scenario: WebSocket message with a URL

- **WHEN** a Realtime or Responses WebSocket message references an image URL under `inline`
- **THEN** the message is refused, since the relay cannot fetch

### Requirement: Fetching remote attachments

A fetch SHALL go through the upstream proxy in force, carry no header of the agent's request, and
connect only to public addresses unless `redaction.remote-attachments-allowed-networks` names the
network, resolving the host once and connecting to the checked addresses. Each redirect SHALL be
checked the same way, at most 5. All fetches of a request share 64 MiB and 18 s.

#### Scenario: Loopback and metadata addresses

- **WHEN** a request references `http://127.0.0.1/...`, `http://169.254.169.254/...` or a name that resolves to a private address, and no allowed network covers it
- **THEN** nothing is fetched and the request is refused with `remote_attachment`

#### Scenario: Redirect to a refused address

- **WHEN** an allowed server answers with a redirect to `127.0.0.1` that no allowed network covers
- **THEN** the redirect is not followed and the request is refused

#### Scenario: URL carrying a secret

- **WHEN** a referenced URL contains a known secret value
- **THEN** it is not fetched and the request is refused with `remote_attachment`, naming the reference

#### Scenario: Through the upstream proxy

- **WHEN** an upstream proxy applies to the attachment's host
- **THEN** the fetch goes through a `CONNECT` tunnel to it

#### Scenario: Unavailable or oversized

- **WHEN** the server answers an error status, or the content exceeds the bound
- **THEN** the request is refused with `attachment_unavailable` or `unscannable_content` and nothing reaches the provider

### Requirement: File IDs of scanned uploads

Under `inline` and `refuse` a provider file ID SHALL pass only when scrim scanned its upload on the
same route: the file part of an Anthropic or OpenAI `POST .../files`, or of a Gemini upload sent in
one request, is scanned under the binary policy, and the ID in a successful answer is remembered in
memory, bounded per route. Any other file ID SHALL refuse the request.

#### Scenario: Upload then reference

- **WHEN** an agent uploads a clean PDF through scrim on the OpenAI route and then references the returned `file_id`
- **THEN** the request is forwarded with the file ID

#### Scenario: Unknown file ID

- **WHEN** a request references a file ID that was not uploaded through scrim on that route
- **THEN** the request is refused with `remote_attachment`

#### Scenario: Upload with a secret

- **WHEN** an uploaded PDF carries a known value
- **THEN** the upload is refused with `secret_in_binary` and its ID is never remembered
