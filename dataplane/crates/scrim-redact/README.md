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
nested, see below); the stable inner base64 substring at byte offsets 0, 1 and 2, standard and
URL-safe; hex lower and upper; percent-encoding (`%2F`, `%2f`, form encoding, Python `quote`,
JavaScript `encodeURIComponent`). Duplicates are removed. Values below `min_len` (default 8) are
short: matched verbatim and in whole encodings only (the full base64 of the value alone, padded and
unpadded, instead of inner fragments). Values below `short_floor` (4) are rejected and reported.

JSON text inside a JSON string (tool-call `arguments`, a tool result holding `JSON.stringify`
output, an MCP text block wrapping JSON) escapes a value once per level. Each value is compiled
escaped two to `json_depth` (default 3, at most 4) times: `inner^k outer^(d-k)`, the inner levels
in any single-level style above, the outer levels in minimal, Go or Python escaping (one program,
the agent, writes the outer levels). A value with nothing JSON escapes adds no pattern; one with
only `"` and `\` adds one per level; the leak suite's password (all the symbols, ASCII) adds 15 at
depth 3, and with a non-ASCII letter 43. Other mixes, and every character as `\uXXXX`, are the
guard's: it unescapes to the same depth. Depth 3 covers `arguments` holding JSON that itself holds
a JSON string (Codex code mode `text(JSON.stringify(result))` of a tool result); 4 is allowed for
deeper tool chains at about 5 % more patterns. Measured on the bench sets (10, 1,000 and 10,000
secrets): 73, 6,641 and 65,832 patterns before, 87, 7,044 and 69,963 at depth 3 (+19 %, +6 %,
+6 %; the 10-value set was already split into two Teddy automata and still is). Redact throughput
on the 1 MB bench bodies, best of 40, moved within 0 to 13 % (machine noise is about as large);
on a body made only of nested tool turns, the third JSON view costs the guard about 15 %.

**Matching (`matcher.rs`).** Non-overlapping leftmost-longest over the raw bytes; the request is
never decoded or re-serialised. Two engines, byte-identical output, chosen by pattern count
(`engine_threshold`, default 256):

* Aho-Corasick. Its SIMD (Teddy) prefilter only applies up to 64 patterns, and throughput falls
  about tenfold past that. Sets of up to 128 patterns use the crate's packed Teddy searcher
  directly, with its heuristic 64-pattern limit lifted (one pass); larger sets of up to 256
  patterns, or CPUs without SSSE3, are split into automata of 64 whose matches are merged.
* Hash-window (D13). Every pattern of eight bytes or more is keyed by its first eight bytes. A
  first filter holds the five-byte grams at offsets 0 to 3 of every such pattern and is probed at
  every fourth input position only; a hit there checks the (up to four) eight-byte windows that
  can start a pattern containing that gram, each hashed and tested against a blocked Bloom filter
  (one word, two bits). A window hit is looked up in a prefix table pointing at the
  lexicographically sorted patterns with that prefix; the longest pattern that is a prefix of the
  input is the predecessor found by binary search, or one of its precomputed longest-proper-prefix
  ancestors. Patterns shorter than
  eight bytes go to a small Aho-Corasick tier merged by the same rule.

A genuine placeholder already in the input (one that resolves) is copied byte for byte, so an
unchanged conversation prefix redacts to identical bytes and prompt caching keeps working.

**Values inside other values.** A value can lie inside a longer one: LocalStack's `test`
credentials inside an API key `sk-test-...`. In the forms the redactor compiles the longer value
wins (leftmost-longest), but in a form only the guard decodes (hex wrapped at 60 columns, `xxd`,
`hexdump -C`, a truncation) the redactor finds just the shorter one, and replacing it cuts the
longer value apart: no whole value, and no half of one, is left for the guard, and the rest of the
key goes out. At build, `enclosures` finds every value that lies inside another (raw with ASCII
case ignored, raw inside another's hex form, or in hex form inside another) and the bytes that can
border it there: the longer value's neighbouring bytes, in both cases, rot13 and rot47, and line
breaks and escape ends or starts. Around a match of such a value, unless both bytes next to a raw
or JSON-form match are outside those sets (prose, identifiers), the redactor runs the guard's
decoders (`Guard::spans`) over its input, 24 bytes per byte of the longer value plus 256 to each
side, windows joined where they meet. A value found there that overlaps the match and reaches past
it is replaced whole with its own placeholder (`Variant::Enclosing`, the whole pass is redone with
those spans). Sets without nested values never take this path. With `test` nested in a key,
single-threaded `protect` on the 1 MB reference bodies (805 matches of `test`) takes 13 % (1,000
values) and 19 % (10,000) longer than with `test` alone, and 1.8 and 2.1 times as long when every
match borders bytes of a possible encoding.

In `protect`, bodies of at least `parallel_min_bytes` (512 KiB) are matched on up to
`parallel_threads` (4) scoped threads: each region runs its own cursor, the region lists are
stitched (a cursor from the last match's end runs until it meets a match the next region also
found), and seeks past genuine placeholders resync the same way. The output is byte for byte what
one thread produces; `redact` and `redact_with` stay on the calling thread.

**Placeholders (`placeholder.rs`).** `⟦scrim:<slug>:<vv><tag>⟧`, slug `[a-z0-9-]{1,48}`, `vv` the
key version in two hex digits, `tag` the first 8 bytes of
`HMAC-SHA256(key, "scrim-placeholder-v1\0" || value)` in hex. At most 79 bytes. Inert in JSON,
shell words, YAML and Markdown. The percent form `%E2%9F%A6scrim:<slug>:<vv><tag>%E2%9F%A7` (at
most 91 bytes) is the ASCII spelling for header values and URLs; parsing, resolution, the
restorer and `next_placeholder` accept both, and a value restored for a percent-form placeholder
is percent-encoded. The resolver indexes the tags of every retained key, so
placeholders from before a rotation keep resolving; acceptance compares tag and slug in constant
time.

**Guard (`guard.rs`).** Shares no matching code with the redactor and works the other way round:
it decodes the bytes into views and searches the raw values there, ASCII case-insensitively. Views:
raw, JSON-unescaped once, twice and up to `json_depth` times, percent-decoded, every base64 run
(both alphabets, joined across line breaks) at all four alignments, every hex run (any case) at
both alignments. Values are indexed by five-byte grams at offsets 0 to 3, so only every fourth position of a view is probed;
a probe folds bit 5 of every byte and tests a blocked Bloom filter (one word, two bits, about 16
bits per gram) before the exact, case-insensitive check. Exact necessary conditions keep the cost
down: one pass builds bitmaps of base64 and hex characters, from which runs of eleven base64
characters and sixteen hex digits are found by shift-and, so other text is never walked byte by
byte; runs whose character classes cannot hold any value's encoding are not decoded; each run is
decoded once into its bit stream and the other alignments are read from it at a bit offset; values
containing a backslash (which only the raw bytes show) are found from the backslash positions the
JSON pass records; and the second JSON view and the URL view are only scanned near decoded units,
within the longest value containing a byte those units produced. Bodies of at least
`parallel_min_bytes` (512 KiB) are split into up to `parallel_threads` (4) regions checked on scoped
threads, with region ends where no base64 run can cross; the verdict is the same as on one
thread. Findings are mapped back to the outgoing bytes and replaced with the value's placeholder;
the repaired body is checked again. A value still present, or more findings than
`guard_max_repairs`, withholds the request. The guard as it was before these optimisations is kept
as a test oracle (`guard_oracle.rs`, feature `oracle`): property tests and the `guard` fuzz target
check that both reach the same verdict, repaired bytes and findings.

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
* Base64 or hex of a JSON-escaped form (a base64-encoded JSON file holding the value with a
  quote) is not compiled, and the guard does not JSON-unescape decoded base64.
* The guard folds ASCII case only. Transforms other than the listed encodings (reversal, rot13,
  spacing, compression) are out of scope here; the leak checker and the bypass matrix cover them.
* `aho-corasick` keeps its own copy of patterns that this crate cannot wipe. Pattern bytes owned by
  this crate and all values are zeroed on drop.

## Benchmarks

`cargo bench -p scrim-redact` (criterion). Conditions mirror `bench/redact-bench`: sets of 10,
1,000 and 10,000 secrets with all variants, bodies of 100 KB, 1 MB and 4 MB with one hit per 4 KiB
or none. `SCRIM_REDACT_GOFIX=<dir>` runs on the Go generator's fixtures instead. The bench also
prints p50/p99 of redact, guard and `protect` per request (1 MB bodies;
`SCRIM_REDACT_LATENCY_SIZES=100k,1m,4m` for all sizes) and of restoration per chunk.
`SCRIM_REDACT_THREADS` overrides `parallel_threads`.

Reference run: Intel Xeon W-2295 (18 cores, 3.0 GHz), rustc 1.100.0, `json_depth` 3 (87, 7,044 and
69,963 patterns), on a shared machine with other load (load average about 5 during the runs), so
numbers carry noise, p99 most of all. Single-thread runs are pinned to one core whose hyperthread
sibling was the least busy; four-thread runs to four such cores. Redact throughput (criterion
median, auto engine, hits / clean):

| set | 100 KB | 1 MB | 4 MB |
| --- | --- | --- | --- |
| 10 (packed Teddy) | 1.91 / 2.05 GiB/s | 1.79 / 1.80 GiB/s | 1.77 / 1.71 GiB/s |
| 1,000 (hash-window) | 1.07 / 1.05 GiB/s | 1,016 / 1,015 MiB/s | 1,011 / 1,020 MiB/s |
| 10,000 (hash-window) | 1,024 / 1,042 MiB/s | 932 / 955 MiB/s | 923 / 884 MiB/s |

`protect` per 1 MB request, p50 / p99 in ms, 300 requests per cell (hits / clean):

| set | one thread | four threads (default) |
| --- | --- | --- |
| 10 | 3.11 / 3.56, 3.16 / 3.62 | 1.87 / 3.71, 1.63 / 2.43 |
| 1,000 | 4.20 / 4.85, 4.03 / 4.60 | 2.38 / 4.43, 2.19 / 3.75 |
| 10,000 | 4.43 / 5.06, 4.53 / 5.20 | 2.37 / 4.85, 2.26 / 4.20 |

Of a single-thread `protect` on 1 MB, the redactor takes about 1 ms and the guard 3.1 to 3.5 ms.
Restore per chunk p99: 0.25 to 0.36 µs.

Against the performance spec: restore per chunk is far inside its 50 µs budget. With the default
four threads, the redact + guard budget is met: at 1,000 secrets p99 3.8 to 4.4 ms against 5 ms,
at 10,000 secrets 4.2 to 4.9 ms against 10 ms. On one thread it is met at 10,000 and just met at
1,000 (4.6 to 4.9 ms). Under heavier machine load (15 and more) p99 at 1,000 secrets can go past
5 ms, mostly from thread wake-up latency. Task 2.0's 500 MB/s at 10,000 secrets is met on every
body size (880 MiB/s and up).

## Fuzzing

```sh
cd dataplane/crates/scrim-redact/fuzz
cargo +nightly fuzz run engines  -- -max_total_time=300   # AC and hash-window agree
cargo +nightly fuzz run variants -- -max_total_time=300   # encoded values never leave protect()
cargo +nightly fuzz run guard    -- -max_total_time=300   # repairs leave nothing, no panics
cargo +nightly fuzz run restore  -- -max_total_time=300   # chunked restore equals whole, no credential
```
