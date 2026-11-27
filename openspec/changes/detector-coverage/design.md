## Context

Fallback detectors run in the redactor over the bytes between exact matches (design D13 of
`known-format-detectors`): anchor automata, then an anchored regular expression per rule. The
guard does not know detector matches; they have no value behind them.

## Decisions

### D1 Encoded forms are decoded, not compiled

Compiling the base64 forms of every anchor at three alignments, plus hex and percent forms, would
multiply the anchors several times over and the automata with them. Instead the scan finds
candidate runs cheaply and decodes only those that look like text:

- base64 runs of at least 24 characters (either alphabet): a run that long holds two consecutive
  aligned eight-byte chunks of base64 characters, one at an offset divisible by sixteen, so one
  SWAR test per sixteen bytes finds every candidate. The first 48 characters are decoded and the
  run is dropped when they hold a control byte (images, archives, random data). Runs longer than
  16 KiB are data and skipped.
- hex runs of at least 40 digits (optionally after `0x`), with the same text check.
- percent-encoded spans: each `%XX` escape and the URL-ish run around it, at most 4 KiB.

The decoded bytes go through the same rules (not entropy). A match is reported as the characters
that encode it (for base64, from the character holding its first bit to the one holding its last,
padding included at the end), so the text around it survives. Decoding uses a per-thread buffer,
wiped after use, so the warm path does not allocate.

Rejected: decoding every base64 run fully (images cost megabytes of decoding per request);
recursion into encodings of encodings (unbounded; documented).

### D2 Encoded forms are off by default

On the 1 MB agent body of the redaction benchmark the scan adds 0.5 to 0.65 ms on one core
(redactor throughput 810 to 530 MB/s on the measuring machine), below the 600 MB/s floor of the
latency gate. It finds nothing in the repository corpus or the generated bodies.

### D3 Entropy needs a key name by default

The entropy detector over every token fires 892 times per MB on agent bodies (hex ids, base64
data) and 8 per MB on the repository. With the key-name context (a value assigned to `token`,
`secret`, `password`, `api_key`, a name ending in `key` or `auth`, after `Bearer`, or a flag such
as `--password`) it fires 0 times on the generated bodies and synthetic corpus and 0.39 per MB on
the repository, all on documented example credentials. It stays off by default all the same: page
tokens, cursors and nonces under such names would become placeholders that never resolve, and the
agent could not send them back. Key names with `page`, `next`, `cursor`, `continuation`, `sync`,
`csrf`, `xsrf` or `nonce` are skipped, as are values that are paths (start with `/` or hold three
or more), calls, indexes and templates. Symbols count as a fourth character class here, so
passwords qualify.

### D4 Anchor grouping by fingerprint

Teddy checks nibbles of the first three bytes; a bucket admits crossings of its fingerprints.
Grouping anchors by first byte, the 28 new formats raised the rule scan from 0.70 to 1.12 ms per
MB of agent body. Grouping fingerprints of three letters by case and those holding a digit or
punctuation separately, and anchoring new prefixes on a punctuated suffix with the match starting
before it (`sk_` for `gsk_`, `lx-` for `pplx-`), brings it to 0.82 ms. Two low-value rules whose
fingerprints are common words (`pul-`, `rubygems_`) were left out.
