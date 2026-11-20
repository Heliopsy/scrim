# redact-bench

Benchmark for one decision: should the data plane of a secret-redacting LLM proxy be
written in Go or Rust? The same algorithm is implemented in both languages, run over the
same fixtures and measured the same way. A third arm ("combo") measures a Rust data plane
behind a separate Go control plane, so the cost of the process boundary is visible.

Everything is synthetic. No real secrets, no calls to real LLM providers.

```
just bench-quick   # ~6 min
just bench-full    # ~30 min, produced the numbers below
just crosscheck    # correctness only
```

<!-- RESULTS -->

## Method

### Algorithm (identical in both languages)

**Redact (request body).** The JSON body is never decoded. One Aho-Corasick automaton
(leftmost-longest, non-overlapping) is built over every variant of every secret and run
over the raw bytes; each match is replaced by `⟦kss:<first 12 hex of HMAC-SHA256(key, value)>⟧`
(22 bytes). Variants per secret, in this order: raw; JSON-escaped (minimal: `"` `\` and
control characters); JSON-escaped with `/` as `\/`; JSON-escaped with non-ASCII as
`\uXXXX` (UTF-16 surrogates above U+FFFF); both of the last two; base64 std at the 3
alignment offsets (only the characters fully determined by the secret, so the substring is
stable whatever precedes it); the same for base64url; lowercase hex; URL-encoding
(everything but `A-Za-z0-9-._~`, uppercase hex). Variants shorter than 8 bytes are
dropped; duplicates are removed globally, first occurrence wins. With no match, the input
buffer is returned without a copy.

**Restore (SSE response).** The stream is split into events on `\n\n`. Only
`content_block_delta` and `content_block_stop` are decoded (Go `encoding/json` into a
struct, Rust `serde_json` with borrowed `Cow<str>`). For `text_delta`, `thinking_delta` and
`input_json_delta`, the decoded string is prefixed with the block's held-back bytes,
known placeholders are replaced (raw value in text/thinking, JSON-escaped value inside
`partial_json`), and a trailing suffix that is a proper prefix of the placeholder shape is
held back (at most 21 bytes, per content block). An event that needs no change is
passed through byte-for-byte; a changed one is re-emitted in canonical form; held bytes
are flushed as one synthetic delta right before `content_block_stop`. `signature_delta`
and every other event pass through untouched. Unknown placeholders stay literal.

### Fixtures (`fixtures/gen`, deterministic seed 20261120)

- Secret sets of 10, 1,000 and 10,000: `ghp_`+36, `github_pat_`+82, `sk-ant-api03-`+93,
  `AKIA`+16, 40-char AWS secret, base62 32/48/64, JWT-ish, ~1.7 KB PEM private key, 8-char
  passwords (some with `"`, `\`, `/`, non-ASCII). 56 / 5,306 / 53,094 patterns
  (21 KB / 0.77 MB / 7.3 MB of pattern bytes).
- Anthropic Messages request bodies of ~100 KB, ~1 MB, ~4 MB (system prompt, tools,
  user/assistant turns, `tool_use` with commands, `tool_result` with code, logs and
  `.env` dumps). About one hit per 4 KB, embedded raw/JSON-escaped (45%), with `\/` or
  `\u` escaping, inside base64/base64url blobs of a `.env`, as hex, and URL-encoded.
  Plus a clean body of each size with zero hits, and a 256 KB round-trip body.
- SSE streams of ~2k and ~20k events (260 KB / 2.6 MB), chunked at uniform random
  boundaries of 1-4096 bytes, with placeholders in `text_delta`, `input_json_delta`
  (curl `Authorization` headers) and `thinking_delta`, split across events and chunks,
  unknown placeholders, trailing incomplete prefixes, and a placeholder inside a
  `signature_delta` that must survive untouched. A 300-event stream (21 chunks) is
  the proxy-level response, in a 1k-set and a 10k-set version.
- Generated data is gitignored; `fixtures/manifest.sha256.json` holds the hashes and
  `just fixtures` regenerates and verifies them.

### Implementations

- Go (`go/redact`): engines `petar-dambovaliev/aho-corasick` (NFA and DFA modes),
  `pgavlin/aho-corasick` (fork of the former), `coregx/ahocorasick` (DFA). Also tried:
  `cloudflare/ahocorasick` reports only which patterns occur, not positions, so it cannot
  replace; `BobuSumisu/aho-corasick` stores a `[256]int64` row per trie state
  (~2 KB/state, several GB at 10k secrets) and reports overlapping matches only. Neither
  was benchmarked. Output buffers come from `sync.Pool`.
- Rust (`rust/src/lib.rs`): `aho-corasick` 1.1.5 (`MatchKind::LeftmostLongest`, kind
  auto or forced DFA), `memchr`, `serde_json`, `hmac`/`sha2`.
- Builds: Go `CGO_ENABLED=0 GOAMD64=v3`; Rust release with `lto="fat"`,
  `codegen-units=1`, `panic="abort"`, `-C target-cpu=x86-64-v3`. An x86-64-v2 subset is
  run for both.
- Proxies: Go `net/http` (`go/cmd/proxy`); Rust hyper 1.x + tokio + hyper-util client
  (`rust/src/bin/proxy.rs`). Both read the whole request, redact, POST to the upstream,
  and stream the response through the restorer, flushing each chunk.
- Fake upstream (`harness/upstream`, Go): discards the body and replays the fixture SSE in
  its recorded chunks, with 15 ms between chunks (paced) or no pause (unpaced).
- Combo arm: the Rust proxy started with `-cp <socket>` gets its dictionary (secret values
  plus all 13 variants per secret) and a policy snapshot from `go/cmd/controlplane` over
  a Unix domain socket. Wire format: `u32 BE length | u8 type | JSON payload`. Policy is
  evaluated locally from the snapshot. Per request the data plane emits one ~330-byte JSON
  audit event (agent id, provider, secret refs, decision, timings). Variants:
  `combo-async` (audit through a bounded channel, batched every 5 ms or 256 events,
  `try_send` so a full channel drops rather than blocks; diff of 100 secrets pushed every
  2 s), `combo-nodiff` (same, no diffs), `combo-syncaudit` (the response does not finish
  until the control plane acks the event), `combo-grant` (async audit plus one
  synchronous "check grant" round trip before forwarding each request). A diff triggers a
  full automaton rebuild on a blocking thread and an atomic snapshot swap.

### Measurement

- Micro: Go `go test -bench` (`-count 10`, benchstat), Rust criterion (20 samples,
  2-3 s). Both pinned to one logical CPU (`taskset -c 4`). Allocation counts: Go
  `-benchmem`; Rust a counting global allocator in `rbcli allocs`. Build time and
  retained heap: `rbcli buildmem` in each language (Go: `HeapAlloc` delta after GC;
  Rust: live bytes from the counting allocator).
- Proxy: load from `oha` 1.17.0 in a rootless podman container (`--network host`,
  `--cpuset-cpus 14-17,32-35`); proxy on CPUs 2-5 (4 logical CPUs, distinct physical
  cores; Go GOMAXPROCS and tokio workers follow the affinity mask), upstream on 8-13,
  control plane on 6-7. Every run starts fresh processes, so peak RSS (`VmHWM`) is per
  run. CPU = utime+stime of the proxy (and control plane) during the load window, divided
  by request+response bytes of successful requests. Added latency = target minus
  direct-to-upstream at the same scenario and concurrency.
- Correctness (`just crosscheck`, `harness/check.py`, same checks for both languages): the
  pattern list of each language must equal the generator's oracle list; re-scanning every
  redacted body finds zero variants; the redacted body still parses as JSON; clean bodies
  are unchanged; restore(redact(x)) == x on the round-trip body; every restored stream
  reproduces the original block contents, tool inputs parse as JSON, `signature_delta`
  and all non-delta events are byte-identical, no known placeholder remains; and every
  Go output is byte-identical to the Rust output.
