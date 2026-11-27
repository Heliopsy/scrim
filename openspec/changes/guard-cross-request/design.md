## Context

`split-fragments` (`guard-transform-coverage`, D3) collects fragments of a value that are at least
the minimum length but too short to count alone, with their offset in one of the fragment index's
forms (the value, its reversal, its skeleton), and counts a form found when its pieces from at
least two places cover all of it but `min(7, len / 4)` bytes. The guard is immutable and per
snapshot; the data plane binds a request to a caller only in the request gate.

## Decisions

### D1 Memory of offsets, per guard

Each guard built with `cross-request` holds a `CrossMemory`: a map from session key to the pieces
seen, each `(form, offset, length, last seen)` as four `u32`, 16 bytes. The form index is only
meaningful within one guard, so the memory belongs to it and a new snapshot starts empty. That
also clears it when the redaction set changes, including when a session's token is added or
revoked. Bytes and values are never stored.

### D2 Join and remember under one lock

After a whole check, the request's short pieces (minus forms the within-request rule already
joined) are grouped by form; a form with remembered pieces whose union with the request's covers
it has the request's pieces emitted as `CrossRequest` hits and repaired. Every piece is remembered,
the repaired ones too: once the older pieces have expired, the next piece may need them (the leak
gate found this). Both steps run under the memory's lock, so two requests of a
session checked at once are seen in some order and the second sees the first; the completing piece
is therefore always in the request being checked, and refusing an earlier request after the fact
never arises. The check of the repaired body does not join, so pieces are not counted twice. The
verdict cache needs no change: a segment holding a short piece is never cached, so a body the
cache shows clean has nothing to join.

### D3 Pieces that read as random

Over a session of 140 requests (9 MB of the repository's docs and sources), 200 values made of
three distinct words of that text were joined in 100 requests when every piece counted, and in 16
of 141 (the corpus had grown by this change) when only pieces that read as random count (`looks_random`: a lower-case letter followed by a capital, a
letter next to a digit, two letters or digits next to punctuation that does not join words, or
four consonants in a row). Values of the text's most frequent words: 53 requests, then none. Random tokens were never
joined either way. Judging each piece rather than the value matters: a value with one digit word
(`sha256`) would otherwise let its plain-word pieces count (97 requests). The cost is that an agent can choose cuts that read as words; an AWS
access key ID's letters between digits often do. Pieces below the minimum length were already
invisible, so the transform raises the bar against splitting rather than closing it.

### D4 Session key

`Identity::guard_session` hashes, in order of preference, the client certificate's leaf, the
session id (claimed or proven), the Kubernetes token, or the Unix user; unknown callers share one
key. SHA-256 with a domain prefix, so no token is kept. An agent that can change its session id or
certificate gets a fresh memory; one Unix user, or all unknown callers, share theirs, which only
joins more.

### D5 Bounds

256 pieces per session (the oldest replaced), 1,024 sessions (the one seen longest ago evicted),
30 minutes after a piece was last seen; expired sessions are swept every 256 joins. At most 4 MiB.
Per replica: the shared state backend is not used, since a lookup per request would add a round
trip to the guard's path; deployments that care pin sessions to a replica.

## Risks

- Default on: a weak value made of random-looking pieces that occur in a session's ordinary text
  gets those occurrences repaired. Measured above; the within-request rule has the same exposure.
