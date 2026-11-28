## Context

The guard (design D4) shares no matching code with the redactor and decodes the outgoing bytes
into views. `guard_tx.rs` already hosts transform decoders that write decoded bytes with a raw span
per byte (`TxScratch`) and a fragment index. The guard is being optimised in parallel, so the new
decoders live in `guard_extra.rs`, a child module of `guard_tx.rs`, and `guard.rs` only gains the
config parameter and three view names.

## Decisions

### D1 Confusables: a skeleton, not a normal form

Matching needs one canonical form on both sides. The view folds each character that maps to ASCII
(NFKC compatibility decomposition with combining marks dropped, then a table of look-alikes from
Unicode's `confusables.txt`) and maps every byte to a skeleton: lower case, `0` as `o`, `1`, `I`
and `|` as `l`. Values that hold `0`, `1`, `I` or `|` get their skeleton indexed next to them, in
the guard's index and the fragment index, so a line of a PEM key in look-alikes is still a
fragment. Only runs around a foldable character are decoded (bounded to 4 KiB, starting at most
512 bytes before it), so ASCII text costs one high-bit test per eight bytes and CJK or emoji one
range test per character. Tag characters (U+E0020 to U+E007E) are read as the ASCII they spell,
since they are the usual way to hide text from a reader.

### D2 Spelled-out values from an automaton

Probing every sixteen bytes for a word cost 4.8 ms per MB. An Aho-Corasick automaton over NATO
words and the digit words prose rarely uses (`zero`, `three`, `seven`, `eight`, `niner`), in three
cases, finds anchors; a run then extends over units separated by spaces, tabs, line breaks or
commas, at most three in a row. A unit is a spelled word or any single printable character, and
case words are skipped. At least half the units must be words so ordinary single-letter sequences
stay with the separated view. Cost: 1.1 to 1.6 ms per MB.

### D3 Split fragments: coverage, not count

The fragment rule already finds runs of a value's bytes of at least the minimum length; it keeps
only those of at least half the value. Shorter ones are now collected (at most 512 per request)
with their offset in the value. A value counts as found when its pieces come from at least two
places and cover it all but its last `min(7, len / 4)` bytes, and each piece is repaired. Pieces
shorter than the minimum length are invisible to the index and stay a limitation. Requests chained
by server-side state are checked one at a time and cannot be assembled without state shared across
requests (a value's pieces would have to be remembered per conversation), which scrim does not
keep; this is documented.

### D4 base85 as indexed forms, off by default

The base85 alphabets cover nearly all printable ASCII, so runs cannot be delimited in text. As for
base64 inside longer streams, the characters that encode only a value's whole four-byte groups are
the same wherever it sits at a given alignment; four alignments times three alphabets are twelve
indexed forms. Nothing is decoded per request, but the index grows: +4% guard time with 1,000
values, +32% with 10,000. Off by default.

### D5 Compressed documents, off by default

Base64 runs of at least 32 characters (continuing over line breaks after full lines of at least 60)
are sniffed: gzip, zlib and zstd by header; anything else that is no known file format (PNG, JPEG,
GIF, PDF, ZIP, RIFF, Ogg, ...) or text is tried as raw deflate, then brotli, each giving up past
1 MiB or on an error. Output that starts as text is scanned like a base64 text document, and a
value found replaces the whole run. All runs of a request share a 64 MiB budget, the binary scan's
bound. On the benchmark body, whose base64 blobs are random data, the headerless attempts cost
7 to 9 ms per MB. Off by default.

## Risks

- A wider run around a look-alike or a spelled word only costs decoding; matches still need a whole
  value or the fragment rules. `transforms_stay_quiet_on_ordinary_text` checks prose with accents,
  emoji, Cyrillic, Greek and NATO words, code and agent bodies.
