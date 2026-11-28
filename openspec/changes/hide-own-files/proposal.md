## Why

On a single-user machine the agent runs as the same Unix user as a user-level scrim (`scrim install
--user`). The session filesystem view of `scrim run` hides tool credential files, but not scrim's
own: the files behind `file:` references in scrim's configuration (a Vaultwarden `unlock:` master
password, a `client-secret:`, notifier tokens, signing keys), its config files, its CA keys, its
state database and its file and sops stores. An agent can `cat` the Vaultwarden master password.

## What Changes

- New: settings and store fields declare that their value is the path of key material
  (`config.Spec.KeyMaterial`, `CollectionSpec.KeyMaterialFields`). `Config.OwnPaths` lists every
  such path with the targets of `file:` references, the config files and the state directory.
- New: `GET /v1/own-paths` on the local agent API returns those paths (never content) to a mapped
  local user that may mint sessions; sessions are refused.
- Changed: `scrim run` asks the daemon for its own files and hides each one the agent's user can
  read. The namespace view bind-mounts the empty 0000 file or directory over it wherever it is,
  outside `$HOME` too. The home mirror leaves out those under `$HOME` and refuses to start the agent
  for a readable one outside it; so does either view for one that holds a path the session needs.
  When a config file is hidden, `SCRIM_CONFIG` points at an empty config in the session directory so
  `scrim mcp` and `scrim secret` still start.
- New: `run.fs-view-allow-readable-own-files`, a weakening setting that starts the agent anyway and
  reports the files it does not hide.
- New: `scrim status` lists scrim's own secret files the current user can read, and `scrim doctor`
  warns about them (`own-files`), recommending the system install or systemd credentials.

## Impact

- Specs: credential-injection (new requirement "Session filesystem view hides scrim's own files"),
  observability (doctor and status report readable own files).
- Code: `internal/config` (`own.go`, registry and collection fields), settings marked as key
  material in `internal/ca`, `internal/state/sqlite`, `internal/placeholder`,
  `internal/identity/issuer`, `internal/daemon`, `internal/edge`, `internal/agentapi`,
  `internal/natsconn`, `internal/stores/storeconfig`; `internal/localapi` (route and client),
  `internal/agentapi` (wiring), `internal/fsview` (absolute entries), `internal/run`,
  `internal/cli`, `internal/status`.
- Upgrades: a `scrim run` talking to an older daemon warns that its own files are not hidden.
  A user-level install with readable secret files outside `$HOME` on a host without user namespaces
  now refuses to start agents until scrim runs as another user or the weakening setting is set.
