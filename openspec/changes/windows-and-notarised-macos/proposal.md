## Why

scrim 1.0 ships Linux and macOS binaries only, and the macOS binaries are not notarised, so a
browser download is blocked by Gatekeeper until the user clears the quarantine attribute
(docs/limitations.md, Platforms). Windows users have no release at all, although most of the
control plane and the data plane need nothing Unix-specific.

## What Changes

- New: Windows amd64 and arm64 builds of `scrim` and `scrim-dataplane` in every release, built on
  GitHub-hosted Windows runners in jobs without secrets or OIDC, covered by the same signed checksums,
  SBOMs and provenance as the other platforms.
- New: a defined Windows support level. The daemon, the LLM proxy's base URL and forward proxy
  listeners, the tool proxy, stores, MCP, the agent API and `scrim run` work; settings that need Unix
  (Unix socket LLM listeners, transparent and eBPF interception, the exec broker, the database
  proxies, socket modes and groups, numeric peer rules, required memory locking) are refused at
  start-up, each named with the reason.
- New: the data plane talks to the control plane over its stdin and stdout on Windows, where a child
  cannot inherit a socket by descriptor number (`scrim-dataplane --stdio`).
- New: peer identity on Windows from `SIO_AF_UNIX_GETPEERPID` and the peer process's token, and
  session tokens bound to a process tree through the process snapshot and creation times.
- New: private-file checks that read the owner and DACL on Windows instead of mode bits, and
  directories scrim creates get a protected DACL.
- New: the release workflow signs (Developer ID Application, hardened runtime, secure timestamp)
  and notarises the darwin binaries when the Apple signing secrets are set, in jobs that build
  nothing. Without them the release still publishes, with a notice and a line in the release notes
  saying the darwin binaries are not notarised.
- New: a CI job that runs the Go and Rust unit tests on Windows, and the real data plane over the
  stdio boundary.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `deployment`: release platforms, Windows support level and refusals, the stdio boundary,
  private files on Windows, macOS signing and notarisation.
- `agent-identity`: peer credentials and process trees on Windows.

## Impact

- `internal/dataplane`, `internal/identity`, `internal/localapi`, `internal/fsperm` (new),
  `internal/daemon`, `internal/run`, `internal/fsview`, `internal/execbroker`, the private-file checks
  in `ca`, `placeholder`, `identity/issuer`, `status` and `stores/vaultwarden`.
- `dataplane/crates/scrim-dataplane` (stdio transport, Windows hardening and listeners), tests gated
  to Unix where they use Unix sockets or POSIX tools.
- `.github/workflows/release.yaml`, `.github/workflows/ci.yaml`, `scripts/release/*`,
  `scripts/ci-setup-rust.sh`, `scripts/test-windows.sh`.
- Docs: install.md (Windows, maintainer signing setup), limitations.md (Platforms).
