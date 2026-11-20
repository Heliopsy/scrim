-- SPDX-License-Identifier: AGPL-3.0-only
-- scrim state schema 2. What a `scrim run` session is bound to, so sessions
-- survive a restart: the user, the root of the process tree (PID, parent PID
-- and the platform's opaque start time, stored bit for bit as a signed 64-bit
-- integer), the scopes as a JSON array of names, the optional name and why
-- it ended. Additive: existing rows take the defaults, and a session with
-- root_pid 0 matches no process, so it can never be used.

ALTER TABLE sessions ADD COLUMN name TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN uid INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN root_pid INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN root_ppid INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN root_start INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN scopes TEXT NOT NULL DEFAULT '[]';
ALTER TABLE sessions ADD COLUMN end_reason TEXT NOT NULL DEFAULT '';
CREATE INDEX sessions_agent ON sessions (agent_id, created_at, id);
