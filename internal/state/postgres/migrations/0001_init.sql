-- SPDX-License-Identifier: AGPL-3.0-only
-- scrim state schema 1. Metadata only: no column holds a secret value or a
-- placeholder-to-value mapping. Times are UTC Unix nanoseconds, NULL when
-- unset, the same encoding as the SQLite backend. JSON columns hold agent
-- identities, grant scopes and requests.

CREATE TABLE approvals (
  id           TEXT   PRIMARY KEY,
  status       TEXT   NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
  agent_id     TEXT   NOT NULL,
  request      TEXT   NOT NULL,
  rule         TEXT   NOT NULL DEFAULT '',
  reason       TEXT   NOT NULL DEFAULT '',
  grant_ttl_ns BIGINT NOT NULL DEFAULT 0,
  created_at   BIGINT,
  expires_at   BIGINT,
  decided_at   BIGINT,
  decided_by   TEXT   NOT NULL DEFAULT ''
);
CREATE INDEX approvals_status ON approvals (status, created_at, id);
CREATE INDEX approvals_agent ON approvals (agent_id, created_at, id);

CREATE TABLE grants (
  id          TEXT    PRIMARY KEY,
  agent_id    TEXT    NOT NULL,
  agent       TEXT    NOT NULL,
  ref         TEXT    NOT NULL DEFAULT '',
  scope       TEXT    NOT NULL,
  max_uses    INTEGER NOT NULL DEFAULT 0 CHECK (max_uses >= 0),
  uses        INTEGER NOT NULL DEFAULT 0 CHECK (uses >= 0),
  approval_id TEXT    NOT NULL DEFAULT '',
  rule        TEXT    NOT NULL DEFAULT '',
  created_at  BIGINT,
  expires_at  BIGINT,
  revoked_at  BIGINT,
  revoked_by  TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX grants_agent ON grants (agent_id, created_at, id);
CREATE INDEX grants_ref ON grants (ref, created_at, id);

CREATE TABLE sessions (
  id         TEXT PRIMARY KEY,
  agent_id   TEXT NOT NULL,
  agent      TEXT NOT NULL,
  token_hash TEXT UNIQUE,
  created_at BIGINT,
  expires_at BIGINT,
  ended_at   BIGINT,
  labels     TEXT NOT NULL
);

CREATE TABLE audit_log (
  id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  time       BIGINT,
  action     TEXT NOT NULL,
  actor      TEXT NOT NULL DEFAULT '',
  agent_id   TEXT NOT NULL DEFAULT '',
  agent      TEXT NOT NULL,
  ref        TEXT NOT NULL DEFAULT '',
  effect     TEXT NOT NULL DEFAULT '',
  outcome    TEXT NOT NULL DEFAULT '',
  rule       TEXT NOT NULL DEFAULT '',
  target     TEXT NOT NULL DEFAULT '',
  subject    TEXT NOT NULL DEFAULT '',
  request_id TEXT NOT NULL DEFAULT '',
  reason     TEXT NOT NULL DEFAULT '',
  attrs      TEXT NOT NULL
);
CREATE INDEX audit_agent ON audit_log (agent_id, id);
CREATE INDEX audit_ref ON audit_log (ref, id);
CREATE INDEX audit_action ON audit_log (action, id);
CREATE INDEX audit_outcome ON audit_log (outcome, id);
CREATE INDEX audit_time ON audit_log (time);

CREATE TABLE events (
  id      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  kind    TEXT NOT NULL,
  subject TEXT NOT NULL DEFAULT '',
  time    BIGINT
);
