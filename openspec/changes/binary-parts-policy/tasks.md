# Tasks

## 1. Setting and snapshot

- [x] 1.1 Registry: `WeakeningValues` on a weakening setting; `Weakened()`, the schema
  (`x-scrim-weakening-values`) and the settings reference use it, and a profile cannot set one;
  verify: `TestWeakeningValues` and `TestEveryWeakeningSettingIsReported` (`internal/cli`), which
  now picks the setting's own weakening value
- [x] 1.2 `redaction.binary` (`scan`, `block`, `pass`; default `scan`; `pass` weakening) sent in
  `RedactionSettings.binary`; unset and `UNSPECIFIED` mean `scan`; verify: `TestBinaryPolicySetting`,
  the snapshot fields in `TestSnapshotBuilderBindsCurrentValuesOnly`, `binary_policy_from_snapshot` in the data plane
- [x] 1.3 `pass` is listed by `scrim status` and `scrim doctor`, `block` is not; verify:
  `TestBinaryPassIsWeakened`

## 2. Decoder (`scrim-llm/src/binary.rs`)

- [x] 2.1 Base64 and `data:` URL decoding, sized before allocating; verify: unit tests and a
  round-trip proptest over both alphabets, padding, whitespace and data URLs
- [x] 2.2 Views: raw, UTF-16 runs, PNG text chunks and ICC profile (and data after `IEND`), JPEG
  segments joined per marker and identifier, GIF extensions, XML entities, gzip, ZIP, PDF streams,
  filters, predictors and strings; verify: one test per format with a generated value that only
  the expected view holds
- [x] 2.3 Fail closed: encryption, unsupported compression or filters, indirect filters and
  parameters, malformed structure; verify: a table of refusal cases per format
- [x] 2.4 Bounds: decoded size, decompressed bytes, object count, nesting depth, view bytes, time;
  verify: bombs per decoder, a zero budget always `OverBudget`
- [x] 2.5 LZW `EarlyChange`; verify: Ghostscript `LZWEncode` vectors for 0 and 1 across two width
  changes decode only with the right setting, the PDF reference example, clear codes at 12 bits
- [x] 2.6 Robustness; verify: proptests over random bytes behind each magic prefix and over
  mutated fixtures; each guarded behaviour broken in turn (EarlyChange, `Crypt`, ExtendedXMP
  order, PDF strings) fails its test

## 3. Proxy

- [x] 3.1 `scan` in `outgoing::prepare`: refuse with `secret_in_binary` naming the part and the
  references, or `unscannable_content` with the reason; the guard alone catches a value the
  redactor misses; verify: `outgoing` unit tests, `binary_scan_refuses_secret_in_image_metadata`
  in `tests/fail_closed.rs`
- [x] 3.2 Text documents redacted and encoded again with their `data:` prefix; verify:
  `scan_redacts_a_text_document_and_encodes_it_again`
- [x] 3.3 Latency of `scan` measured (`benches/binary_scan.rs`); verify: numbers in design.md

## 4. Leak suite and docs

- [x] 4.1 Matrix rows: `image-metadata`, `image-metadata-compressed`, `jpeg-comment`, `svg-text`,
  `pdf-text` withheld; `image-pixels` a limitation; Gemini `document-text`; the checker inflates
  PNG chunks and PDF streams; the runner counts a placeholder inside base64 as redacted; verify:
  the gate against `scrim proxy` with the real data plane passes with 0 unexpected outcomes
- [x] 4.2 docs/limitations.md, docs/configuration.md, docs/leak-assurance.md (matrix table), the
  scrim-llm README
