# Tasks

## 1. State

- [x] 1.1 `state.RedactionToken` and the `Tx` methods `PutRedactionToken`, `GetRedactionToken`, `ListRedactionTokens`, `DeleteRedactionTokens` in the memory, SQLite and PostgreSQL backends, schema 3; verify: the contract suite case `RedactionTokens` passes on all three, PostgreSQL in podman
- [x] 1.2 The type walk and the leak dump cover the new row; verify: `TestTypesHoldNoValues` lists it

## 2. Sealing

- [x] 2.1 `internal/tokenseal`: keys derived from the placeholder ring with HKDF, AES-256-GCM with kind and row ID as associated data, keyed row IDs; verify: round trip, every mismatch (kind, ID, version, one flipped bit) refused, no plaintext in the sealed bytes, IDs stable across processes and different per key

## 3. Daemon

- [x] 3.1 Share every new token of the three sets (write and event, retried in the background) and add every delivered or loaded one; verify: with the fake data plane, a session minted, a service account token verified and an identity token signed on replica A reach replica B's snapshot, for `events.backend` `postgres`, `valkey` and `nats`
- [x] 3.2 Load live shared tokens before the first snapshot; verify: a replica started after the mint has the token in its first snapshot
- [x] 3.3 Expiry and revocation: expired tokens leave every replica and their rows are deleted; a revoked session leaves the redaction scopes on every replica and its token stays until expiry; verify: daemon tests
- [x] 3.4 Refuse more than one replica without `redaction.placeholder-keys`; verify: start-up error names the setting
- [x] 3.5 No token value in the state dump; verify: the multi-replica test dumps every table and runs the leak checker over it

## 4. End to end

- [x] 4.1 Real data plane, two replicas on PostgreSQL: a session minted on A, its token sent through B's base URL, the fake provider receives a placeholder, for each events backend; verify: watched failing with sharing disabled
- [x] 4.2 Narrowed redaction across replicas against OpenBao; verify: the session minted on A gets its narrower redaction through B, and the whole set after it is revoked

## 5. Docs

- [x] 5.1 docs/limitations.md: remove the two token entries under "Several replicas", state what the database plus the placeholder key reveal
- [x] 5.2 docs/state-and-observability.md: shared tokens, the event, the placeholder key requirement
