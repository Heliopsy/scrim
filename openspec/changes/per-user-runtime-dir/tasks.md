# Tasks

## 1. Runtime directory

- [x] 1.1 `internal/runtimedir`: `Dir`, `UserTemp`, `Mkdir`/`MkdirUnder` (create private, then refuse a foreign, group/other writable or symlinked directory from the top down), `CheckSocket` for clients; verify: `TestDirWithoutXDGRuntimeDirCarriesTheUID`, `TestMkdirRefusesALooseDirectory`, `TestMkdirRefusesALooseSubdirectory`, `TestMkdirRefusesADirectoryOwnedBySomeoneElse`, `TestMkdirRefusesASymlink`, `TestOutsideTheRuntimeDirIsNotChecked`, each watched failing with its check removed

## 2. Use it everywhere

- [x] 2.1 Admin socket and `admin.url` description; admin client checks the directory before dialing; verify: `internal/approval` `TestDefaultAdminSocketWithoutXDGRuntimeDir`, `TestClientRefusesALooseRuntimeDir`, watched failing before the change
- [x] 2.2 Agent API socket, `localapi.Listen` and the agent API client; `api.socket` description
- [x] 2.3 Daemon info file and admin discovery (`Connect` refuses rather than reporting no daemon); verify: `internal/daemon` `TestInfoPathWithoutXDGRuntimeDir`, `TestConnectRefusesALooseRuntimeDir`, watched failing before the change
- [x] 2.4 Database proxy socket directory; verify: `internal/dbproxy` `TestDefaultSocketDirWithoutXDGRuntimeDir`
- [x] 2.5 `scrim run` session directories; verify: `internal/run` `TestSessionDirWithoutXDGRuntimeDir`, `TestSessionDirRefusesALooseRuntimeDir`, watched failing before the change

## 3. Docs

- [x] 3.1 docs/running.md runtime directory section, docs/approvals.md, docs/run.md, docs/databases.md, `just config-docs`, `just cli-docs`
