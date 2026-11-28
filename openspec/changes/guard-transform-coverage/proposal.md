## Why

The guard reads a value through JSON escapes, percent-encoding, base64, hex, base32, dumps and
separated characters, but not through look-alike Unicode, words that spell it out, compression or
the base85 family, and it catches a value split within one request only when one piece is at least
half of it. `docs/limitations.md` lists these as open gaps; the bypass matrix runs them as
limitations.

## What Changes

- Five guard transforms, switched by name with `redaction.guard.disable` (weakening) and
  `redaction.guard.enable`:
  - `confusables` (on): runs around a look-alike character are read as their ASCII skeleton
    (NFKC, Unicode's confusables for Cyrillic, Greek, Armenian and Latin, tag characters as the
    ASCII they spell, invisible characters dropped); each value's skeleton is indexed.
  - `spelled-out` (on): NATO, digit and symbol words, single characters among them.
  - `split-fragments` (on): pieces of at least the minimum length that together cover a value,
    from at least two places of one request.
  - `base85` (off): Ascii85, Z85 and RFC 1924 forms of each value indexed at every alignment.
  - `compressed` (off): gzip, zlib, zstd, brotli and raw deflate streams in base64 runs inflated
    within 64 MiB per request and checked like a base64 text document.
- `RedactionSettings.guard_disabled` and `guard_enabled` (additive). The data plane refuses a
  snapshot naming an unknown transform.
- `scrim status` lists a `guard transforms` protection; `scrim doctor` warns when one that is on
  by default is off.
- New guard views `confusable`, `spelled` and `compressed` in findings.
- Bypass matrix: `homoglyphs`, `fullwidth`, `nato-spelling` and the new `zero-width-scattered`
  and `unicode-tags` rows become gated `guard` rows; `ascii85`, `base85` and `gzip-base64` stay
  limitations by default with notes naming the setting.

## Capabilities

### Modified Capabilities

- `redaction`: guard transforms and their settings.
- `leak-assurance`: matrix rows for the transforms.

## Impact

- `scrim-redact` (`guard_extra.rs`, small hooks in `guard_tx.rs`, `guard.rs`, `guard_oracle.rs`,
  `redactor.rs`), new dependencies `unicode-normalization`, `flate2`, `zstd`,
  `brotli-decompressor`; `scrim-dataplane` (`snapshot.rs`); proto (two additive fields);
  `internal/daemon`, `internal/cli`, `internal/leak/matrix`; docs.
- Cost on the guard, one thread, 1 MB agent request: the three default transforms +2.3 ms with
  1,000 values, +3.3 ms with 10,000; `base85` +0.8 / +7.7 ms; `compressed` +7 to 9 ms.
