## ADDED Requirements

### Requirement: Readable own files reported

`scrim status` SHALL list scrim's own secret files (`file:` reference targets, key-material settings
and store fields, the state directory of a user-level install) that the current user can read, and
`scrim doctor` SHALL warn about them, recommending a system install with `--agent-user` or systemd
credentials.

#### Scenario: User-level install with a file reference

- **WHEN** scrim's configuration has `approvals.signing-key: file:<path>` and the current user can
  read that file
- **THEN** `scrim status` lists the path and `scrim doctor` prints an `own-files` warning with the fix
