## ADDED Requirements

### Requirement: Per-user runtime directory

scrim SHALL keep its default sockets, daemon info file, database proxy sockets and session
directories in one per-user runtime directory: `$XDG_RUNTIME_DIR/scrim`, else on Unix
`$TMPDIR/scrim-<uid>`, else on Windows `%TEMP%\scrim`. On Unix it SHALL refuse, naming it, a
runtime directory or one below it that another user owns, that group or others can write, or that
is a symbolic link: the daemon SHALL NOT listen there and clients SHALL NOT connect there.

#### Scenario: No XDG_RUNTIME_DIR

- **WHEN** `$XDG_RUNTIME_DIR` is unset on Unix and `admin.url` is empty
- **THEN** the daemon listens on, and `scrim status` dials, `$TMPDIR/scrim-<uid>/admin.sock`, never
  a directory shared by every user

#### Scenario: Directory planted by another user

- **WHEN** the runtime directory exists but another user owns it, or its mode lets group or others
  write it
- **THEN** the daemon refuses to start, `scrim status` and `scrim approve` refuse to connect, and
  each error names the directory

#### Scenario: Explicit paths

- **WHEN** `api.socket` or `admin.url` names a path outside the runtime directory, such as the
  system service's `/run/scrim`
- **THEN** that path is used under its existing rules
