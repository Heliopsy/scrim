# Tasks

## 1. Collect the paths

- [x] 1.1 `internal/config`: `KeyMaterial` and `Companions` on settings, `KeyMaterialFields` on collections, `Config.OwnPaths` (file: targets, key-material settings and fields, state directory, config files); mark the key directories, the SQLite file, token and credential files and the store `root`, kubeconfig and token-file options; verify: `TestOwnPaths`, `TestKeyMaterialOnlyForStrings`
- [x] 1.2 `GET /v1/own-paths` for a mapped local user with `sessions:mint`, refused to sessions and unknown callers; wired to the daemon's live configuration; verify: `internal/localapi` `TestOwnPaths`, `TestUnknownCallersAreRefused`, `internal/agentapi` `TestRuntimeEndToEnd`

## 2. Hide them in the session view

- [x] 2.1 `internal/fsview`: absolute own entries, readable ones only, merged with profile entries; home mirror hides those under `$HOME`; refusal for one it cannot hide, or one holding a path the session needs, unless `run.fs-view-allow-readable-own-files`; verify: `TestBuildNamespaceOwnFiles`, `TestBuildOwnFilesUnreadableSkipped`, `TestBuildOwnFilesKeepWhatTheSessionNeeds`, `TestHomeMirrorOwnFiles`
- [x] 2.2 `internal/run`: ask the daemon, keep the session directory, API socket and scrim executable, empty `SCRIM_CONFIG` when a config file is hidden, warn for an older daemon; verify: `TestFSViewOwnFiles` (namespace, cannot read a `file:` unlock reference), `TestFSViewHomeMirrorOwnFiles`, watched failing with the paths not passed to the view

## 3. Report

- [x] 3.1 `scrim status` lists readable own secret files, `scrim doctor` warns (`own-files`); verify: `TestDoctorWarnsReadableOwnFiles`

## 4. Docs

- [x] 4.1 docs/run.md, docs/limitations.md, docs/stores/vaultwarden.md, generated configuration reference
