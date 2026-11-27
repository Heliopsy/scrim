## Why

The guard joins short pieces of a value only within one request (`split-fragments`). An agent
that sends one piece per request, or a provider that keeps earlier turns itself (OpenAI's
`previous_response_id` and conversations, a WebSocket session), never puts the pieces in one body,
so each is checked alone. `docs/limitations.md` lists this as an open gap and the bypass matrix
cannot gate it.

## What Changes

- A guard transform `cross-request`, on by default: per session, the guard remembers which short
  pieces of which value left (the fragment index's form, offset and length, never bytes) and
  joins a request's pieces with them under the split-fragments coverage rule. The request whose
  pieces complete a value has them repaired; deciding and remembering happen under one lock.
- Only pieces that read as random count: a lower-case letter followed by a capital, a letter
  next to a digit, two letters or digits next to punctuation that does not join words, or four
  consonants in a row.
- Bounded: 256 pieces per session, 1,024 sessions, 30 minutes after a piece was last seen. Pieces
  name their value by a keyed fingerprint (a per-process random key), and the data plane gives
  every snapshot one memory, so pieces join across changes to the redaction set; a check drops
  pieces of values that left the set. Per replica.
- The session is what the transport says (`Identity::guard_session`): the client certificate's
  leaf, else the session id, else the Kubernetes token, else the Unix user; unknown callers share
  one. The LLM gate returns it in `Admission::Forward`, and the proxy binds the request's guard to
  it (`Guard::check_in`).
- New guard view `CrossRequest` in findings.
- Bypass matrix: gated rows `split-requests-2` and `split-requests-3` (raw and reversed, every
  API with a tool turn but Realtime) that name their pieces, so the runner reports a leak when
  every piece arrives.
- This supersedes the sentence "Pieces that arrive in separate requests SHALL each be checked
  alone" of the `guard-transform-coverage` change's "Split value within one request".

## Capabilities

### Modified Capabilities

- `redaction`: the `cross-request` transform.
- `leak-assurance`: rows for values split over requests.

## Impact

- `scrim-redact` (`guard_cross.rs`, hooks in `guard_tx.rs`, `guard_extra.rs`, `guard.rs`),
  `scrim-llm` (`Guard::check_in`, `SessionKey`, `Admission::Forward.session`), `scrim-dataplane`
  (`identity.rs`, `policy.rs`); `internal/daemon/guard_transforms.json`, `internal/leak/matrix`;
  proto comment only; docs.
- Cost: none measurable on the guard (0.74 ms per 66 KB request with a session, 0.73 ms without,
  1,200 values). False positives over a 9 MB session of the repository's docs and sources: none
  for 1,000 random tokens; for 200 weak values made of three distinct words of that text, 16 of 141
  requests (`split-fragments` alone flags 85); for 200 made of its most frequent words, none
  (`split-fragments`: 128).
