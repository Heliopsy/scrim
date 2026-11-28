## Why

On Unix without `$XDG_RUNTIME_DIR` (plain ssh sessions, cron, some containers) the default admin
socket was `$TMPDIR/scrim/admin.sock`, a directory every local user shares, while the agent API
already used the per-user `$TMPDIR/scrim-<uid>`. Another local user could create `/tmp/scrim`
first and either squat the path or serve a fake admin API to this user's `scrim approve`,
`scrim status` and `scrim run` daemon discovery. A pre-created `/tmp/scrim-<uid>` is the same
attack, and nothing refused a runtime directory owned by someone else.

## What Changes

- Changed: one per-user runtime directory (`internal/runtimedir`): `$XDG_RUNTIME_DIR/scrim`, or
  `$TMPDIR/scrim-<uid>` without it (`%TEMP%\scrim` on Windows, unchanged). The admin socket, the
  agent API socket, `daemon.json`, the database proxy sockets and the `scrim run` session
  directories all default to it.
- New: on Unix, scrim refuses a runtime directory (or a directory under it) that is owned by
  another user, writable by group or others, or a symbolic link. The daemon does not listen there,
  and the admin and agent API clients do not dial a socket there. The error names the directory.
- Paths set explicitly (`api.socket`, `admin.url`, `databases.<name>.listen`) and the system
  service's `/run/scrim` keep their current rules.

## Impact

- Specs: deployment (new requirement "Per-user runtime directory").
- Code: `internal/runtimedir`, `internal/approval`, `internal/localapi`, `internal/daemon`,
  `internal/dbproxy`, `internal/run`.
- Docs: running.md (runtime directory section), approvals.md, run.md, databases.md, generated
  configuration and CLI references.
