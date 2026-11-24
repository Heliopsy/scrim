## Context

Three token sets in the daemon feed the redaction set with scrim's own bearer credentials:
`scrim-sessions` (session tokens minted by `scrim run`), `scrim-kubernetes` (service account tokens
scrim verified) and `scrim-issuer` (identity tokens scrim's issuer signed). Each lives in one
process. The state backend holds only a SHA-256 of each session token, which is enough to verify a
token on any replica but not to redact it: the redactor matches the value itself and its encoded
forms (JSON escapes, base64 at three alignments, hex, percent encoding) in streaming text.

With `deployment.replicas` above 1 the state backend is PostgreSQL and the events backend is
`postgres`, `valkey` or `nats` (start-up refuses anything else). Every events backend delivers from
the outbox in PostgreSQL; Valkey and NATS carry empty wake-ups only.

## Goals / Non-Goals

**Goals:**

- Every replica redacts every live token of all three sets, whichever replica minted or verified it.
- No token value in plaintext in the state backend, the outbox, Valkey or NATS.
- Revocation and expiry reach every replica.
- Narrowed redaction behaves the same on every replica.
- No change to the data plane or the boundary protocol, no new setting.

**Non-Goals:**

- Protecting tokens from someone who holds both the database and the placeholder key. That person
  can already derive every placeholder and, with the key, read every sealed token; the key is
  documented as as sensitive as the CA key.
- Sharing anything with single-process backends (`memory`, `sqlite`).
- Decision links across replicas (`approvals.signing-key`); unchanged.

## Decisions

### S1. Seal the value; do not share a keyed hash

The redaction set needs the value: the data plane builds its matcher from the bytes and their
encodings, and the guard decodes outgoing text and compares values. A keyed hash would need a
second matcher that finds token-shaped candidates and hashes them, which covers session tokens
(they have a fixed prefix) but not service account or issuer JWTs, loses every encoded form, and
moves work into the hot path (design D13). So each replica needs the plaintext, and the shared
state carries it sealed.

Each row holds `nonce || AES-256-GCM(key, nonce, token, aad)` with a random 96-bit nonce and
`aad = "scrim-redaction-token/v1" 0x00 kind 0x00 id`. Binding kind and ID stops a database writer
moving a ciphertext to another row: a session token can only open as the session it was sealed for,
so it cannot be attached to another session's narrowed redaction. Expiry is not bound: anyone who can
write the table can delete rows, which costs more than shortening one.

### S2. The key comes from the placeholder key ring

Every replica already must hold the same placeholder keys (placeholders are an HMAC of the value
under them, so replicas agree on placeholders without shared state). They are secret, loaded through
references, rotated by version and protected like the CA key. A second shared key would add a
setting, a chart secret and a rotation procedure that protects the same thing.

The sealing key for a placeholder key version is `HKDF-SHA256(ikm = placeholder key, salt = none,
info = "scrim/redaction-token-seal/v1")`, the row ID key (S4) the same with
`info = "scrim/redaction-token-id/v1"`. HKDF with distinct labels makes the derived keys independent
of each other and of the HMAC placeholders made with the raw key. New rows are sealed with the
current version; a row records its version and opens with that version while the ring holds it. A
row whose version left the ring is skipped and logged by row ID and version: tokens live at most
`session.max-ttl` (seven days by default) and placeholder keys are kept far longer after a rotation.

Random nonces under one key are safe to about 2^32 messages; one row per minted or verified token
stays many orders of magnitude below that.

### S3. Distribute through the state and its outbox, not on the events channel

The minting replica writes the sealed row and an outbox event `redaction.token` (subject: the row ID)
in one transaction; every replica's events bus delivers the event and the replica reads the row,
opens it and adds the token. The state is durable, so a replica that starts later loads every live
row before it serves, and the outbox makes delivery ordered and exactly-once per replica under all
three events backends. Nothing secret, sealed or not, crosses Valkey or NATS: they still carry empty
wake-ups. Publishing the sealed token on a channel instead would lose it for any replica that was
down or not yet started.

The write runs after the mint returns, on a background goroutine that retries with backoff until it
succeeds or the token expires; the mint is not refused when the write fails, because the minting
replica redacts the token at once either way. The gap before another replica redacts a new token is
the write plus the event delivery bound (milliseconds with a connected listener). `scrim run` mints
the token before it starts the agent, so the agent cannot print the token before that.

The start-up load is synchronous: a replica that cannot read the shared tokens refuses to start,
since it would otherwise serve requests without other replicas' tokens. The events bus fixes its
start position in `app.New`, before the load, so a row committed between the two is delivered by the
bus as well as loaded; adding a token twice is a no-op.

### S4. Row IDs

A session token's row ID is its session ID, which is not secret and is what the data plane's
redaction scopes key on. A service account or issuer token has no ID of its own; its row ID is the
hex HMAC-SHA256 of the token under the derived ID key. A plain SHA-256 would also be safe for JWTs
with a signature in them, but the keyed form gives a database reader no check value at all. After a
key rotation the same token gets a second row; replicas deduplicate in memory by the SHA-256 they
already key the sets on.

### S5. Session metadata stays in the sessions table

The agent of a session token and whether the session ended come from the sessions table, not from
the token row: it is the record every replica already trusts to verify the token. On a
`session.revoked` event every replica marks the session ended, which removes it from the narrowed
redaction scopes in the next snapshot. The token itself stays in the redaction set until it expires,
as it did on the minting replica in 1.0: a revoked token is useless toward scrim but still a
credential-shaped string, and keeping it costs nothing. The minting replica follows the same event
for its own revocations, so a revoked session loses narrowed redaction on one replica as on
several.

### S6. When sharing is on

Sharing is on when `state.backend` is `postgres` and `redaction.placeholder-keys` is set. Without
configured keys each process generates its own key, so no other process could open its rows; with
`deployment.replicas` above 1 start-up refuses that combination, naming `redaction.placeholder-keys`
(1.0 only warned, and placeholders did not match across replicas either). PostgreSQL with one
declared replica and no keys keeps 1.0's warning and shares nothing.

Expired rows are deleted by each replica's session sweep (every 30 seconds); the deletes are
idempotent, so several replicas sweeping at once is harmless.

## Risks / Trade-offs

- [The database plus the placeholder key yields every live token] -> both are already required to be
  protected as root secrets; tokens expire; documented in docs/limitations.md.
- [A database writer deletes rows] -> the token is then redacted only by the replica that holds it,
  as in 1.0. The writer can also revoke sessions or rewrite grants, so this adds no new power.
- [Sidecar mode gives every agent pod the placeholder keys] -> sidecars do not use the PostgreSQL
  state, and they already hold the whole redaction set.
- [Rows sealed under a retired key version are unreadable] -> skipped and logged; only a token minted
  before a rotation and still live after the old version is removed from the ring is affected.
