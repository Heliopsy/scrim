## Why

With several replicas, each scrim keeps only the tokens it minted or verified in its redaction set:
`scrim run` session tokens, the Kubernetes service account tokens it verified and the identity tokens
its issuer signed. The shared state holds only hashes of session tokens. A session minted through
replica A is accepted by replica B, but if the agent prints its token and the request goes through
B, B forwards it to the provider unredacted. `redaction.limit-to-agent-identity` has the same
gap the other way round: B does not hold the session's token, so it cannot check that a request
proves the session, and the session gets the whole redaction set on B. 1.0 documents both under
"Several replicas" in docs/limitations.md and asks for session affinity.

## What Changes

- Each replica writes every token it mints or verifies to the shared state, sealed with AES-256-GCM
  under a key derived from the placeholder key ring, and announces it through the event outbox. Every
  replica opens the sealed tokens it reads and adds them to its own redaction set, so every replica
  redacts every live token whichever replica minted it. A replica starting later loads every live
  sealed token before it serves.
- Token values never reach the state backend, the events backend, Valkey or NATS in plaintext. The
  state holds the ciphertext, the key version and the expiry; the outbox carries only the row ID.
- A revoked session leaves the narrowed redaction scopes on every replica at the `session.revoked`
  event and stays in every replica's redaction set until its token expires. Expired tokens leave
  every replica's set at their expiry and their rows are deleted.
- Narrowed redaction (`redaction.limit-to-agent-identity`) works on every replica: the session's
  token and agent are known everywhere, so a request that proves the session gets its narrower
  redaction whichever replica it reaches, and a revoked session loses it on every replica.
- With `deployment.replicas` above 1, start-up refuses an empty `redaction.placeholder-keys`: each
  replica would generate its own key, so placeholders would not match and no replica could open
  another's tokens. The Helm chart already requires shared placeholder keys.
- State schema 3 adds the `redaction_tokens` table to the SQLite and PostgreSQL backends.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `state-and-scaling`: the no-secret rule allows sealed scrim tokens; every replica redacts every
  live scrim token; replicas need shared placeholder keys.
- `agent-identity`: narrowed redaction applies on every replica and ends when the session is
  revoked.

## Impact

- `internal/state` (new `RedactionToken` row and four `Tx` methods, schema 3 for SQLite and
  PostgreSQL, the memory backend, the contract suite), new package `internal/tokenseal`,
  `internal/daemon` (the token sets, sharing, revocation), `internal/app` (replica check).
- docs/limitations.md loses the two token entries under "Several replicas";
  docs/state-and-observability.md describes the shared tokens.
- No boundary protocol change: the data plane sees the shared tokens as ordinary entries of the
  stores `scrim-sessions`, `scrim-kubernetes` and `scrim-issuer`.
