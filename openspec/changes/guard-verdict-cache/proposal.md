## Why

The guard took about 25 ms per 1 MB at the median and 40 ms at p99 on the reference runner, five
to eight times the performance spec's targets, while redaction takes about 1 ms. Profiling one
1 MB request on one thread put about 22 of its 28 ms in the transform decoders (separated units
12 ms, byte dumps 6 ms, base32 3 ms, fragments 1 to 4 ms), which scanned every byte and ran on the
calling thread while the rest of the guard was split over workers.

LLM APIs are stateless: an agent's next request resends the whole conversation, so nearly all of a
1 MB body is bytes the guard checked one request earlier.

## What Changes

- The transform decoders look only at positions their per-byte class bitmaps allow (necessary
  conditions for a run to start there); the result is byte for byte what the byte-by-byte scan
  gives. The fragment index uses a blocked Bloom filter and open addressing instead of a 64-bit
  per key bitmap and a SipHash map. On large bodies the decoders and the fragment search run on
  threads of their own.
- New: a guard verdict cache. The guard splits the outgoing bytes at `X},{Y` boundaries no
  occurrence can cross, remembers the BLAKE3 hash of every segment of a body it found clean, and on
  a later body checks only the segments it has not seen, as one piece per run of new segments. Any
  finding falls back to the whole check, so verdicts, repairs and findings are unchanged. Hashes
  only, at most 65,536 per redaction set, dropped with the snapshot. Off for a set with a value
  containing `,{`.
- New setting `redaction.guard-cache` (default true); `guard_cache_off` in `RedactionSettings`.
- The latency gate measures first-sight requests with the cache cleared, and a new next-turn
  measurement (`turn/<secrets>/1MB`). On the reference runner the next turn takes 8 to 12 ms at
  p99, above the 5 ms target, mostly the codec plan and the redactor; its budgets are 10 and 12 ms.
  First-sight budgets tighten from 60 ms to 40 ms (request) and 30 ms (protect).

## Impact

- Affected specs: performance (Guard verdict cache, added; Added request latency budget,
  modified). The guard's own requirements (redaction spec) are unchanged: it reaches the same
  verdicts.
- Affected code: dataplane/crates/scrim-redact (guard.rs, guard_tx.rs, guard_cache.rs),
  dataplane/crates/scrim-dataplane/src/snapshot.rs, proto/scrim/dataplane/v1/dataplane.proto,
  internal/daemon (settings.go, snapshot.go), dataplane/crates/scrim-llm/benches, docs.
