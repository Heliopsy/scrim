## Why

The performance spec's 5 ms p99 target for an agent's next turn (1 MB, 1,000 secrets) was not met
reliably on the reference runner: 6.8 ms at p99 after the guard verdict cache. Of the next turn,
the guard took about 1 ms; the rest was the codec plan (a strict parse of the whole 1 MB body) and
the redactor over every byte, both done again for bytes the previous request already went through.
Within the redactor the fallback detectors take more than half the time.

## What Changes

- New: a redactor segment cache. The redactor cuts bodies at `X},{Y` where no compiled pattern and
  no detector match can cross (per-rule windows around cuts for rules whose pattern can match `,`
  or `{`, AWS key ids and private key headers), copies segments it replaced nothing in before and
  redacts the rest. For segments with replacements the detector scan is skipped when the hash of
  the matched output and its placeholder positions is known clean. Hashes and 64-bit probes only;
  never kept for a segment's input bytes when it holds a replacement. Off for sets that cannot
  segment (entropy or encoded detectors, format-preserving placeholders, nested values, a pattern
  with `,{`).
- New: a codec plan cache. The LLM proxy remembers runs of elements of the `messages`, `system` and
  `tools` arrays of Anthropic Messages requests by hash, with their verbatim spans as offsets, and
  the parser steps over a remembered run. Plans and errors are unchanged.
- The guard's verdict cache hashes runs of segments first (content-defined, about eight segments),
  then the segments of unknown runs, which halves its hashing cost on a next turn.
- New setting `redaction.redactor-cache` (default true), `redactor_cache_off` in
  `RedactionSettings`; it turns both new caches off.
- Next-turn budgets set to the spec's targets (5 ms for 10 and 1,000 secrets, 7 ms for 10,000).
  The latency gate clears every cache for first-sight measurements and measures redaction
  throughput without the segment cache.

## Impact

- Affected specs: performance (Redactor segment cache, Codec plan cache: added). The redaction and
  llm-proxy requirements are unchanged: output, plans and verdicts are the same with the caches on
  or off.
- Affected code: dataplane/crates/scrim-redact (redactor.rs, redact_cache.rs, detect.rs, guard.rs,
  guard_cache.rs), dataplane/crates/scrim-llm (json.rs, codec/plan_cache.rs, codec/anthropic.rs,
  core.rs, engine.rs, outgoing.rs, benches), dataplane/crates/scrim-dataplane/src/snapshot.rs,
  proto/scrim/dataplane/v1/dataplane.proto, internal/daemon, docs.
