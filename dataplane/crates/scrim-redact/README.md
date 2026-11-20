# scrim-redact

The redaction core of scrim: every known secret value in a request bound for a model provider is
replaced by a deterministic placeholder, an independent guard re-checks the exact outgoing bytes,
and placeholders in streamed responses are restored where the tool policy allows. No HTTP, no
provider codecs, no policy files: the LLM proxy and the HTTPS tool proxy build on this crate.

Specs: `openspec/changes/scrim-v1/specs/redaction/spec.md` (the contract), design D2, D3, D4 and
D13.

## Public API

```text
Snapshot::build(Vec<Entry>, Arc<Keyring>, &Config) -> Result<Snapshot, BuildError>
  .protect(&[u8], &mut Workspace) -> Result<Protected, Error>   redact + guard, the outbound check
  .redactor() -> &Redactor    redact / redact_with / find_matches / max_match_len / engine
  .guard()    -> &Guard       check(&[u8], &mut GuardScratch) -> Verdict
  .resolver() -> &Resolver    resolve / meta / covering / substitute_into
  .report()   -> &BuildReport values, duplicates, short, rejected ids, patterns, engine
SnapshotHandle  new / store(Arc<Snapshot>) / load() -> Result<Arc<Snapshot>, Error::NotReady>
BlockRestorer   new / push(&Resolver, &dyn RestorePolicy, &str, &mut String) / finish / held_len
RestorePolicy   trait: allow(&EntryMeta) -> bool   (KeepAll, RestoreDisplay, any Fn(&EntryMeta) -> bool)
restore_text, placeholder_for, find_placeholders, next_placeholder, json_escape_into
Entry, EntryMeta, EntryId, RefSlug, ValueClass, SecretValue, PlaceholderKey, Keyring
Config, DetectorConfig, EntropyConfig, EngineChoice, EngineKind, builtin_rule_names
Stats, Hit, Variant, Protected, GuardOutcome, GuardFinding, GuardView, Verdict, RestoreStats
Error { NotReady, InputTooLarge, Withheld(WithholdReason) }, BuildError
```

Thread safety: `Snapshot`, `Redactor`, `Guard`, `Resolver` and `SnapshotHandle` are `Send + Sync`
and used through `&self`. `Workspace`, `GuardScratch` and `BlockRestorer` belong to one request or
one content block. Build snapshots off the request path; a request loads one snapshot and keeps the
`Arc` to the end.

```rust
let handle = SnapshotHandle::new();
handle.store(Arc::new(Snapshot::build(entries, keyring, &Config::default())?));

let snap = handle.load()?;                 // Err(NotReady) until the first store: refuse
let sent = snap.protect(body, &mut ws)?;   // Err(_) means refuse; there is no fallback
forward(sent.bytes);
for f in sent.findings { audit_guard_intervention(f.entry, f.view) }
```

## How it works

**Variants (`variants.rs`).** Each value is compiled with the forms agents and their tools produce:
raw; JSON-escaped (minimal, `\/`, `\uXXXX` lower and upper case, PHP, Go and Gson HTML-safe, and
double-escaped); the stable inner base64 substring at byte offsets 0, 1 and 2, standard and
URL-safe; hex lower and upper; percent-encoding (`%2F`, `%2f`, form encoding, Python `quote`,
JavaScript `encodeURIComponent`). Duplicates are removed. Values below `min_len` (default 8) are
short: matched verbatim and in whole encodings only (the full base64 of the value alone, padded and
unpadded, instead of inner fragments). Values below `short_floor` (4) are rejected and reported.

**Matching (`matcher.rs`).** Non-overlapping leftmost-longest over the raw bytes; the request is
never decoded or re-serialised. Two engines, byte-identical output, chosen by pattern count
(`engine_threshold`, default 256):

* Aho-Corasick. Its SIMD prefilter only applies up to 64 patterns, and throughput falls about
  tenfold past that, so sets of up to 256 patterns are split into automata of 64 whose matches are
  merged.
* Hash-window (D13). Every pattern of eight bytes or more is keyed by its first eight bytes. Each
  eight-byte window of the input is hashed and tested against a blocked Bloom filter (one word, two
  bits). A hit is looked up in a prefix table pointing at the lexicographically sorted patterns
  with that prefix; the longest pattern that is a prefix of the input is the predecessor found by
  binary search, or one of its precomputed longest-proper-prefix ancestors. Patterns shorter than
  eight bytes go to a small Aho-Corasick tier merged by the same rule.

A genuine placeholder already in the input (one that resolves) is copied byte for byte, so an
unchanged conversation prefix redacts to identical bytes and prompt caching keeps working.

**Placeholders (`placeholder.rs`).** `⟦scrim:<slug>:<vv><tag>⟧`, slug `[a-z0-9-]{1,48}`, `vv` the
key version in two hex digits, `tag` the first 8 bytes of
`HMAC-SHA256(key, "scrim-placeholder-v1\0" || value)` in hex. At most 79 bytes. Inert in JSON,
shell words, YAML and Markdown. The resolver indexes the tags of every retained key, so
placeholders from before a rotation keep resolving; acceptance compares tag and slug in constant
time.

**Guard (`guard.rs`).** Shares no matching code with the redactor and works the other way round:
it decodes the bytes into views and searches the raw values there, ASCII case-insensitively. Views:
raw, JSON-unescaped once and twice, percent-decoded, every base64 run (both alphabets, joined
across line breaks) at all four alignments, every hex run (any case) at both alignments. Values are
indexed by five-byte grams at offsets 0 to 3, so only every fourth position of a view is probed.
Exact necessary conditions keep the cost down: 64-byte blocks without an eleven-character base64
run are skipped, runs whose character classes cannot hold any value's encoding are not decoded,
and the second JSON view and the URL view are only scanned near decoded units, within the longest
value containing a byte those units produced. Findings are mapped back to the outgoing bytes and
replaced with the value's placeholder; the repaired body is checked again. A value still present,
or more findings than `guard_max_repairs`, withholds the request.

**Detectors (`detect.rs`).** Pattern rules for AWS access keys, GitHub (classic and fine-grained),
Anthropic, OpenAI, GitLab, Slack, Stripe, Google API keys, npm tokens, JWTs and private key blocks
(including JSON-escaped and truncated), found by literal anchors and validated by anchored regexes
with token boundaries. An entropy detector is available and off by default. Detector placeholders
use the slug `det-<rule>` and never resolve.

**Restorer (`restore.rs`).** One `BlockRestorer` per content block. It emits everything that can no
longer be part of a placeholder at once and holds back at most `MAX_PLACEHOLDER_LEN - 1` bytes.
Credentials are never offered to the policy and never restored; `Resolver::substitute_into` is the
explicit primitive for injection at the network edge.

## Limitations

* Values shorter than 4 bytes are not protected; values shorter than `min_len` are not found
  inside longer base64 streams.
* The guard folds ASCII case only. Transforms other than the listed encodings (reversal, rot13,
  spacing, compression) are out of scope here; the leak checker and the bypass matrix cover them.
* `aho-corasick` keeps its own copy of patterns that this crate cannot wipe. Pattern bytes owned by
  this crate and all values are zeroed on drop.

## Benchmarks

`cargo bench -p scrim-redact` (criterion). Conditions mirror `bench/redact-bench`: sets of 10,
1,000 and 10,000 secrets with all variants, bodies of 100 KB, 1 MB and 4 MB with one hit per 4 KiB
or none. `SCRIM_REDACT_GOFIX=<dir>` runs on the Go generator's fixtures instead. The bench also
prints p50/p99 of `protect` per 1 MB request and of restoration per chunk.

Reference run: Intel Xeon W-2295 (18 cores, 3.0 GHz), one pinned core, rustc 1.100.0, on a shared
machine with other load (load average around 10), so numbers carry some noise. Throughput in
MiB/s (criterion median, 1 MB bodies, hits / clean); redact-bench numbers are from
`bench/redact-bench/results/summary.md` (MB/s, same conditions).

| set | redact, auto engine | redact, one AC automaton | redact-bench ac-auto | protect (redact + guard) |
| --- | --- | --- | --- | --- |
| 10 | 1,429 / 1,481 (split AC) | n/a (split applies) | 3,259 / 3,863 | 208 / 207 |
| 1,000 | 508 / 503 (hash-window) | 98 / 99 | 119 / 119 (ac-dfa 301 / 378) | 141 / 146 |
| 10,000 | 471 / 458 (hash-window) | n/a | 97 / 97 | 105 / 101 |

Latency per 1 MB request, `protect` (p50 / p99): 10 secrets 4.9 / 7.9 ms, 1,000 secrets
6.5 / 9.7 ms, 10,000 secrets 9.0 / 15.0 ms. Redact alone p99: 1.0, 3.5 and 3.6 ms. Restore per
chunk p99: 0.27 to 0.36 µs. Snapshot build: 20 ms (10), 24 ms (1,000), 212 ms (10,000).

Against the performance spec: restore per chunk is far inside its 50 µs budget. The redact + guard
p99 budget (5 ms per 1 MB at 1,000 secrets, 10 ms at 10,000) is **not met**: the guard costs about
4 to 6 ms per MB, more than the redactor. Task 2.0's 500 MB/s at 10,000 secrets is met on some
bodies and missed by up to 15 % on others.

## Fuzzing

```sh
cd dataplane/crates/scrim-redact/fuzz
cargo +nightly fuzz run engines  -- -max_total_time=300   # AC and hash-window agree
cargo +nightly fuzz run variants -- -max_total_time=300   # encoded values never leave protect()
cargo +nightly fuzz run guard    -- -max_total_time=300   # repairs leave nothing, no panics
cargo +nightly fuzz run restore  -- -max_total_time=300   # chunked restore equals whole, no credential
```
