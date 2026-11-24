## 1. Windows control plane

- [x] 1.1 Data plane boundary over stdin/stdout on Windows (`internal/dataplane`), socketpair kept on Unix
- [x] 1.2 Data plane binary cached under %LOCALAPPDATA%\scrim with a protected DACL and `.exe` name
- [x] 1.3 Peer credentials (`SIO_AF_UNIX_GETPEERPID`, token SID) and process lookup on Windows
- [x] 1.4 `identity.peers` on Windows limited to scrim's own account
- [x] 1.5 `internal/fsperm`: DACL-based private-file checks, adopted by ca, placeholder, issuer, capture, status, vaultwarden
- [x] 1.6 Start-up refusal of settings Windows cannot honour, each named
- [x] 1.7 Exec broker refused, ssh-agent and filesystem view skipped in `scrim run` on Windows
- [x] 1.8 HOME from USERPROFILE when unset; per-user socket directory under %TEMP%\scrim

## 2. Windows data plane

- [x] 2.1 `--stdio` transport, generic server over any stream
- [x] 2.2 Hardening and listeners on Windows (no Unix listener, `require` refused)
- [x] 2.3 Unix-only tests gated with a reason

## 3. Release and CI

- [x] 3.1 windows-amd64 and windows-arm64 data plane jobs, control plane cross-build, archives, SBOMs, checksums
- [x] 3.2 macOS signing and notarisation jobs gated on the Apple secrets, pass-through and release-note line without them
- [x] 3.3 CI job running Go and Rust unit tests on Windows and the real data plane over stdio

## 4. Docs

- [x] 4.1 docs/install.md: Windows install and verification, maintainer signing setup
- [x] 4.2 docs/limitations.md: Platforms
