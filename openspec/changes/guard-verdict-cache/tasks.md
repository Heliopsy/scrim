## 1. Decoders

- [x] 1.1 Profile the guard per view on a 1 MB body
- [x] 1.2 Class bitmap prefilters for separated units, dumps and base32, checked against the byte-by-byte decoders
- [x] 1.3 Fragment index: blocked Bloom filter, open addressing
- [x] 1.4 Transform decoders and fragment search on their own threads for large bodies

## 2. Verdict cache

- [x] 2.1 Segment cuts no occurrence can cross; cache off for values containing `,{`
- [x] 2.2 BLAKE3 per segment, bounded LRU of clean segments per guard
- [x] 2.3 Check only runs of new segments; any finding falls back to the whole check
- [x] 2.4 Tests: cached and whole checks agree on next turns; new value, value across a cached and new boundary, dump column across a boundary
- [x] 2.5 Setting `redaction.guard-cache`, proto field, data plane wiring

## 3. Measurement and docs

- [x] 3.1 Next-turn measurement in the latency gate and its budgets
- [x] 3.2 docs/performance.md, docs/limitations.md, README, configuration docs
