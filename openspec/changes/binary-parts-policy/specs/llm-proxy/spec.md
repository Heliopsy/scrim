## MODIFIED Requirements

### Requirement: Images and binary content

The proxy SHALL apply `redaction.binary` to the binary parts of a request (images, documents,
audio): `scan` (the default), `block` or `pass`. Under `block` it SHALL refuse every request with a
binary part, naming the content types. Under `pass`, a weakening value, it SHALL forward them
unscanned and record their media types in the audit entry. Parts only referenced (an image URL, a
file ID) are not fetched or scanned.

#### Scenario: Screenshot with block policy

- **WHEN** a request contains an image part and the binary policy is `block`
- **THEN** the request is refused with an error naming the unscannable content type

#### Scenario: Screenshot with pass policy

- **WHEN** a request contains an image part and the binary policy is `pass`
- **THEN** the request is forwarded and the audit entry marks it as containing unscanned content

#### Scenario: Image by URL

- **WHEN** a request contains an image part that references an `https:` URL
- **THEN** the proxy does not fetch the image and the URL is redacted as text

### Requirement: Byte-stable request spans

Values of allowlisted configuration fields, the text and signature of thinking blocks, the data of
redacted thinking blocks, encrypted reasoning and compaction content, and binary data SHALL NOT be
changed by the redactor or its fallback detectors, except a text document the `scan` binary policy
redacts and encodes again. The guard SHALL still scan them as part of the outgoing bytes and repair
or refuse a known value found there.

#### Scenario: Detector match inside a signature

- **WHEN** a fallback detector would match bytes inside a thinking block signature that the agent sends back
- **THEN** the provider receives the signature byte-identical to what it emitted

#### Scenario: Known value inside an allowlisted field

- **WHEN** an allowlisted configuration field contains a known value
- **THEN** the redactor leaves the field alone and the guard repairs it or refuses the request

## ADDED Requirements

### Requirement: Binary scan

Under `scan` the proxy SHALL decode each binary part (base64, or a `data:` URL), detect its format by
its bytes, never by the declared media type, and run the redactor and the guard over the decoded
bytes, their UTF-16 text and the text the format carries: PNG text chunks and ICC profiles, JPEG
comment and APP segments, GIF extensions, SVG and XML text, PDF streams and strings, and gzip and
ZIP entries. Pixels, audio and video samples are not interpreted.

#### Scenario: Clean screenshot under scan

- **WHEN** a request under the default policy contains a PNG image with no known value in its bytes or metadata
- **THEN** the request is forwarded with the image byte-identical and the audit entry lists no unscanned content

#### Scenario: Secret in a PDF

- **WHEN** a request under `scan` contains a PDF whose Flate-compressed content stream shows a known value split over a `TJ` array
- **THEN** the request is refused with `secret_in_binary`

### Requirement: Binary scan refusals

When a known value or a fallback detector matches in a part under `scan`, the proxy SHALL refuse the
request with `secret_in_binary`, naming the part and the references, never the value. When a part
cannot be decoded, or decoding it would exceed the bounds on size, inflated bytes, objects, nesting
depth or time, the proxy SHALL refuse with `unscannable_content` and the reason. Nothing SHALL be
forwarded unscanned under `scan`.

#### Scenario: Secret in image metadata

- **WHEN** a request under `scan` contains a PNG whose compressed zTXt chunk holds a known value
- **THEN** the request is refused with `secret_in_binary`, the error names the part and the value's reference, and neither the error nor the audit entry contains the value

#### Scenario: Guard catches what the redactor misses in a part

- **WHEN** the redactor misses a known value in the metadata of an image part under `scan`
- **THEN** the guard finds it in the same view and the request is refused with `secret_in_binary`

#### Scenario: Part that cannot be decoded

- **WHEN** a request under `scan` contains an encrypted PDF, a part that is not valid base64, or a compressed stream that inflates past the bound
- **THEN** the request is refused with `unscannable_content` naming the part and the reason, and nothing is forwarded

### Requirement: Text documents under scan

Under `scan`, a part declared as text (`text/*`, JSON, XML, YAML and similar) whose bytes are UTF-8
text SHALL be redacted like any other text and encoded again in its original form instead of
refused.

#### Scenario: Text document

- **WHEN** a request under `scan` attaches a `text/plain` file part holding a known value
- **THEN** the provider receives the file with the value replaced by its placeholder, still base64 encoded with its `data:` URL prefix
