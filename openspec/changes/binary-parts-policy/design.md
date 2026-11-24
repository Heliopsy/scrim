## Context

scrim 1.0 forwards images, PDFs and other binary parts of provider requests without looking inside
them (proposal.md). The redactor and the guard work on the request bytes. A value inside a base64
part is only visible to them when it happens to sit uncompressed and aligned, and when the guard did
see one it repaired the base64 text in place, so the provider got a corrupted image instead of a
refusal.

This change adds the `redaction.binary` setting and a decoder for the formats agents attach in
practice. The decoder hands the redactor and the guard byte views to scan. It does not judge what is
a secret itself.

## Goals / Non-Goals

**Goals:**

- A secret in the metadata or document text of an attachment never reaches the provider under the
  default policy.
- Fail closed: a part scrim must read but cannot (encryption, an unknown filter, a broken structure,
  a bound exceeded) refuses the request. It is never passed.
- Error messages, audit entries and logs name the part, its media type and the references, never
  part content.
- Bounded cost per part, whatever the input.

**Non-Goals:**

- OCR, speech recognition or reading video frames. Text drawn into pixels stays a documented
  limitation (`image-pixels` row).
- Redacting a binary part in place. Rewriting a JPEG segment or a PDF stream would mean
  re-encoding formats the provider then has to accept. A refusal is honest and simpler.
- Fetching parts the request only references by URL or file ID.

## Decisions

### B1. Scan views, refuse on a match

`binary::scan_views` calls back with every view of a decoded part: the raw bytes, UTF-16 runs at
both alignments and endiannesses, and per format the extracted text (PNG text chunks and ICC
profile, JPEG COM and APPn segments joined per marker and identifier, GIF extensions with their
sub-blocks joined, XML with entities decoded, gzip and ZIP entries, PDF streams with their filters
undone and the strings in and outside them). `outgoing::scan_parts` runs the redactor and then the
guard over each view. The first match stops the scan and refuses with `secret_in_binary`.

Two independent checks still apply: the guard sees every view the redactor saw, so a value the
redactor misses is still refused (tested with `redactor_misses`).

Alternative considered: scanning only the raw base64 text with more base64 alignments. That cannot
see compressed chunks, joined segments or PDF text split across `TJ` elements, so it was rejected.

### B2. The format comes from magic bytes, never from the declared media type

An agent can declare a PDF as `image/png`. The dispatcher checks PNG, JPEG, GIF, gzip, ZIP, the
archives it refuses (bzip2, xz, zstd, 7z, RAR), `%PDF-` in the first KiB, then markup. A buffer
that comes out of a format (an inflated chunk, a ZIP entry, a decoded stream, a DCT image inside a
PDF) goes through the same dispatcher, so formats nest. Nesting depth is bounded. WebP, audio, video
and unknown data get the raw and UTF-16 views only.

### B3. Text documents are redacted, not refused

A part declared as text (`text/*`, JSON, XML, YAML, TOML, CSV, Markdown, or Bedrock's
`application/txt` and similar), whose decoded bytes are UTF-8 with no NUL, is a file the agent
attached, such as a `.env` or a log. It is redacted like any other text, checked by the guard and
encoded again as standard base64, keeping its `data:` URL prefix. The body is then planned again,
so the rest of the request goes through the normal path. A part declared as text whose bytes are
not text is scanned as binary.

### B4. Bounds are errors

`Limits`: 64 MiB decoded, 64 MiB decompressed or filter-decoded in total, 100,000 objects (chunks,
segments, blocks, entries, streams), nesting depth 4, 256 MiB across all views, and a wall clock of
2 s plus 250 ms per decoded MiB. The redactor and the guard run over every view inside that budget,
so the time a valid part needs grows with its size. A flat budget refused the 20 MiB images of the
latency bench at p99.
The base64 decoder checks the output size before it allocates. Inflaters read 64 KiB at a time
against the shared meter, so a bomb stops after one read past the bound. Long loops check the
clock every 64 KiB, and every dispatch checks it first, so a zero budget always reports
`OverBudget`. Exceeding any bound is `unscannable_content`.

### B5. PDF without a full parser

Streams are found by their `stream` keyword. The dictionary in front of a stream is matched
backwards and confirmed by a forward parse. A direct `/Length` is used only when `endstream`
follows it, otherwise the stream ends at `endstream`. Filters: Flate and LZW with PNG predictors
(10 to 15) and the TIFF predictor (2, 8 bits per component), ASCIIHex, ASCII85 and RunLength. A DCT
stream goes to the JPEG reader for its metadata. JPX, JBIG2 and CCITT data are opaque. These cases
refuse the request:

- `Crypt`, or `/Encrypt` in a trailer or a stream dictionary: encrypted.
- An unknown filter, an indirect filter or indirect decode parameters, or one parameter dictionary
  for a chain of filters: unsupported.
- A broken stream or dictionary: malformed.

Image streams other than DCT hold pixels and are skipped.

LZW follows pdf.js for `EarlyChange`. The tests decode vectors written by Ghostscript's
`LZWEncode` with `EarlyChange` 0 and 1, which cross the 9-to-10 and 10-to-11 bit widths
(`crates/scrim-llm/testdata/lzw`). Each vector fails to decode with the other setting.

Not covered: text shown through fonts with custom encodings, or CID fonts whose codes need a
`ToUnicode` CMap.

### B6. `pass` is weakening, `block` is not

`scan` and `block` are both safe, so the registry gains `WeakeningValues`. A weakening setting can
name the values that weaken it, and `Weakened()`, `scrim status`, `scrim doctor`, the schema
(`x-scrim-weakening-values`) and the settings reference all use it. A profile cannot set a
weakening value. Unset, or `BINARY_POLICY_UNSPECIFIED` in the snapshot, means `scan`.

## Risks / Trade-offs

- Requests that 1.0 forwarded are now refused: an encrypted PDF, an archive other than gzip or
  deflate ZIP, an attachment with a secret in it. The refusal message says what to do, and
  `redaction.binary: pass` restores 1.0 behaviour, reported as weakened.
- A decoder over untrusted input is attack surface. It has no `unsafe` and no indexing that can
  panic, and it is checked by proptests over random bytes behind each magic prefix and over
  mutated fixtures.
- Latency grows with the attachment, measured below.

## Latency

`benches/binary_scan.rs`: `outgoing::prepare` on an Anthropic Messages body with one attachment,
using the production engine with 1,000 values. Release build, 21 runs per row, Xeon W-2295. `pass`
is the 1.0 cost: the redactor and the guard over the request text, the base64 included. The
attachments are a PNG of noise pixels with a text chunk, a JPEG with EXIF and XMP segments and
noise scan data, and a PDF of Flate-compressed text pages (every stream inflated and its strings
extracted, the expensive case).

| part | MiB | pass p50 | pass p99 | scan p50 | scan p99 | added p50 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| png | 1 | 26.2 ms | 26.9 ms | 79.6 ms | 117.4 ms | 53.4 ms |
| jpeg | 1 | 26.3 ms | 27.8 ms | 79.1 ms | 83.7 ms | 52.8 ms |
| pdf | 1 | 26.4 ms | 29.4 ms | 268.6 ms | 296.6 ms | 242.2 ms |
| png | 5 | 130.0 ms | 134.3 ms | 401.4 ms | 442.9 ms | 271.4 ms |
| jpeg | 5 | 131.8 ms | 180.6 ms | 395.6 ms | 464.2 ms | 263.8 ms |
| pdf | 5 | 130.8 ms | 159.1 ms | 1423.0 ms | 1466.5 ms | 1292.3 ms |
| png | 20 | 522.7 ms | 633.5 ms | 1567.2 ms | 1700.2 ms | 1044.5 ms |
| jpeg | 20 | 524.6 ms | 568.1 ms | 1563.4 ms | 1750.6 ms | 1038.9 ms |
| pdf | 20 | 526.8 ms | 606.4 ms | refused | refused | 3996.3 ms to refuse |

The 20 MiB PDF inflates past the 64 MiB decompression bound and is refused
(`unscannable_content`).

The cost is about one redactor pass and one guard pass per byte of every view. An image costs
about twice its pass time: the decoded bytes, plus the base64 text the request already paid for.
A text PDF costs about ten times: its streams inflate three to four times, and each stream is
scanned both as decoded and as extracted text.

The first version called the redactor and the guard once per view. On the 1 MiB PDF that added
770 ms, and the 5 MiB PDF ran out of its 2 s budget. Views under 1 MiB are now scanned in batches
of up to 1 MiB, joined with a NUL separator that no value contains. A batch that matches is scanned
again view by view, so the refusal still names the view. Batching made the PDF three times faster.

The hot path for requests without attachments is unchanged. `latency_gate` does not exercise
binary parts, and `codec::plan` only records their spans.
