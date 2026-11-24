## Why

Images, PDFs and other binary parts of provider requests pass unscanned in scrim 1.0. The llm-proxy
spec describes a `block` policy, but there is no setting for it and the data plane always passes
them (docs/limitations.md, "Images, PDFs and other binary parts pass unscanned"). A secret in a
screenshot's metadata, in a PDF the agent attaches or in a text file sent as a file part reaches the
provider. Where the guard happened to see an uncompressed value inside the base64, it repaired the
base64 text in place, which forwards a corrupted image instead of refusing.

## What Changes

- New setting `redaction.binary` (`scan`, `block`, `pass`; default `scan`), sent to the data plane in
  the snapshot (`RedactionSettings.binary`). `pass` is weakening: logged while active and listed in
  `scrim status` and `scrim doctor`. `block` is stricter than the default and is not weakening.
- `scan`: the data plane decodes each binary part (base64 or a `data:` URL) and runs the redactor and
  the guard over the decoded bytes and over the text the part carries: PNG text chunks (tEXt, zTXt,
  iTXt) and ICC profiles, JPEG comment and APP segments (EXIF, XMP, joined across segments), GIF
  comment and application extensions, SVG and other XML as text with entities decoded, PDF streams
  (Flate, LZW, ASCIIHex, ASCII85, RunLength, PNG predictors) and their strings, gzip and ZIP
  containers (deflate), UTF-16 text in any of them. A match refuses the request with
  `secret_in_binary`, naming the part and the secret references, never the value: a binary part
  cannot be redacted in place without corrupting it. A part that cannot be decoded within the bounds
  (size, inflated bytes, object count, nesting depth, time) is refused with `unscannable_content`.
- Text documents (a part declared `text/*`, JSON, XML, YAML or similar whose bytes are UTF-8 text)
  are redacted like any text and encoded again instead of refused.
- Parts referenced by URL (an `image_url` with an `https:` URL, file IDs) are not fetched and not
  scanned; the provider fetches them. Documented.
- New config registry feature: a weakening setting can name the values that weaken it
  (`WeakeningValues`), so `redaction.binary: block` is not reported as weakened.
- Leak suite: the `image-metadata` row is gated (`withheld`), with new gated rows for compressed PNG
  text, a JPEG comment, SVG text and PDF text. A new `image-pixels` row keeps text rendered into
  pixels (no OCR) as a documented limitation. The leak checker inflates PNG chunks and PDF streams
  so it sees values there.

## Impact

- Specs: llm-proxy (images and binary content, byte-stable spans), configuration (weakening values),
  leak-assurance (matrix expectations, documented limitations).
- Code: `internal/config` (weakening values), `internal/daemon` (setting, snapshot),
  `proto/scrim/dataplane/v1` (`BinaryPolicy`), `dataplane/crates/scrim-llm` (`binary` module,
  `outgoing`, `secret_in_binary` refusal), `dataplane/crates/scrim-dataplane` (snapshot),
  `internal/leak` (checker, matrix rows).
- Behaviour change for users: requests whose attachments carry a secret value, or attachments scrim
  cannot decode (encrypted PDFs, unsupported compression), are now refused by default. Set
  `redaction.binary: pass` to restore the 1.0 behaviour; it is reported as weakened.
- Latency: decoding and scanning a part costs roughly one redactor and one guard pass over its
  decoded bytes and extracted text, bounded per part; measured in design.md.
