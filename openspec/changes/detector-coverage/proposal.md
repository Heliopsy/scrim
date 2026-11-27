## Why

The fallback detectors match a known format only as written. A token base64-encoded in a
Kubernetes secret, hex-dumped or percent-encoded in a query string reaches the provider when no
store holds it. A random password or a key without a vendor prefix is caught only by the generic
assignment rule; the entropy detector exists in the redaction core but no setting reaches it. The
rule list also predates several token formats in common use in November 2026 (Groq, xAI,
OpenRouter, Amazon Bedrock API keys, LangSmith, Tailscale, Notion, Heroku and others).

## What Changes

- 28 more pattern rules (66 in all, the generic rule and private keys included), each with generated test
  cases and a check on the repository corpus.
- `redaction.detectors.encoded` (off by default) runs the pattern rules over the decoded form of
  base64 runs, hex runs and percent-encoded text, and replaces the characters that encode a match.
- `redaction.detectors.entropy.*` reaches the entropy detector: `enabled` (off by default),
  `context` (`key-name`, the default, or `any`), `threshold`, `min-length`, `min-classes`. The
  key-name context only looks at values assigned to a key name that says secret, and skips
  pagination, sync and anti-forgery tokens, paths and references.
- `scrim status` lists a `fallback detectors` protection (rules in force, encoded forms, entropy),
  and `scrim doctor` reports it.
- Anchor automata are grouped by their three-byte fingerprint (all letters by case, or with a
  digit or punctuation), which keeps the larger rule set at about the old cost.
- Leak matrix: `unknown-secret` rows for five of the new formats (gated); the encoded-token and
  random-password rows stay limitations by default, their notes naming the opt-in settings.

## Capabilities

### Modified Capabilities

- `redaction`: encoded forms of known formats, entropy context and settings, detector status.

## Impact

- `scrim-redact` (`detect.rs`), `scrim-dataplane` (`snapshot.rs`),
  `proto/scrim/dataplane/v1/dataplane.proto` (two additive fields and one message, protocol
  unchanged), `internal/daemon` (settings, status), `internal/cli` (doctor),
  `internal/leak/matrix`, docs.
- Cost, measured with the `detect` bench group and single-thread `Redactor::redact` on the
  1 MB agent body: the new rules +0.12 ms/MB; encoded forms +0.5 to 0.65 ms/MB (redactor
  throughput 810 to 530 MB/s, under the 600 MB/s floor, hence off); entropy +2 to 2.5 ms/MB in
  either context.
