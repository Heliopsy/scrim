## 1. Profile

- [x] 1.1 Split the next turn into plan, redactor (patterns and detectors) and guard on the gate's fixture

## 2. Redactor segment cache

- [x] 2.1 Cuts no pattern or detector match can cross; per-rule windows from the patterns' byte sets
- [x] 2.2 Probe-first lookup, BLAKE3 confirmation, bounded LRU per redactor
- [x] 2.3 Detector scan skipped for segments whose matched output is known clean
- [x] 2.4 Tests: segments, cold and warm cache agree with the whole body; windows; sets that cannot segment

## 3. Codec plan cache

- [x] 3.1 Parser steps over known objects in root member arrays; UTF-8 checked around them
- [x] 3.2 Runs of elements keyed by hash, verbatim spans as offsets; Anthropic Messages
- [x] 3.3 Tests: plans and errors agree with and without the cache over edited turns
- [x] 3.4 Elements with binary parts or attachment references are never remembered

## 4. Guard, setting, measurement, docs

- [x] 4.1 Guard hashes runs of segments, then the segments of unknown runs
- [x] 4.2 Setting `redaction.redactor-cache`, proto field, data plane wiring
- [x] 4.3 Gate clears every cache on first sight; next-turn budgets at the spec's targets
- [x] 4.4 docs/performance.md, docs/limitations.md, README, crate README, configuration docs
