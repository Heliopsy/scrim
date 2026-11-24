-- SPDX-License-Identifier: AGPL-3.0-only
-- scrim state schema 3. scrim's own tokens (session, Kubernetes service
-- account and issued identity tokens) shared between replicas so every
-- replica redacts them. sealed is AES-256-GCM ciphertext under a key derived
-- from the placeholder keys, which never reach the database; no column holds
-- a token in plaintext. Times are UTC Unix nanoseconds.

CREATE TABLE redaction_tokens (
  id          TEXT    PRIMARY KEY,
  kind        TEXT    NOT NULL CHECK (kind IN ('session', 'kubernetes', 'issuer')),
  key_version INTEGER NOT NULL CHECK (key_version BETWEEN 1 AND 255),
  sealed      BLOB    NOT NULL,
  created_at  INTEGER,
  expires_at  INTEGER NOT NULL
);
CREATE INDEX redaction_tokens_expires ON redaction_tokens (expires_at);
