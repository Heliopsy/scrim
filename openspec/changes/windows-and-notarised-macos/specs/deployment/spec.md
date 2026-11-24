## MODIFIED Requirements

### Requirement: Single static binary per platform

Each release SHALL ship one self-contained `scrim` binary per supported platform: Linux amd64 and
arm64, macOS amd64 and arm64, and Windows amd64 and arm64, with no runtime dependencies beyond the
operating system.

#### Scenario: Run on a minimal host

- **WHEN** the Linux amd64 binary is copied to a minimal host with no extra libraries
- **THEN** `scrim version` runs and prints the version

#### Scenario: Windows binaries need no runtime

- **WHEN** a Windows release binary is checked by the release scripts
- **THEN** it is a PE file for its architecture and imports no DLL outside the operating system (the C runtime is linked statically)

## ADDED Requirements

### Requirement: Windows support level

On Windows, scrim SHALL run the daemon with its data plane, the TCP listeners, the stores, the
agent API, MCP and `scrim run`, and SHALL refuse to start, naming each setting and why, when the
configuration asks for a feature Windows cannot provide (docs/limitations.md, Platforms).

#### Scenario: Unsupported settings are named

- **WHEN** scrim starts on Windows with `proxy.socket` and `exec.commands` set
- **THEN** it refuses to start, and the error names both settings with the reason

#### Scenario: Defaults start

- **WHEN** scrim starts on Windows with the default configuration
- **THEN** it starts and serves the base URL and forward proxy listeners

#### Scenario: scrim run skips what Windows lacks

- **WHEN** `scrim run` starts an agent on Windows
- **THEN** it leaves `SSH_AUTH_SOCK` as it is and uses no filesystem view, and says so in its warnings

### Requirement: Data plane boundary on Windows

On Windows, the control plane SHALL run the data plane with its stdin and stdout as the boundary
connection (`scrim-dataplane --stdio`), anonymous pipes that only the two processes hold, and the
data plane SHALL exit when its stdin reaches end of file.

#### Scenario: Handshake over stdio

- **WHEN** the control plane starts the data plane on Windows
- **THEN** the handshake, snapshot and status calls run over the child's stdin and stdout, and the data plane exits when the control plane closes its end

### Requirement: Private files on Windows

Where scrim refuses a key, state or capture file or directory that other users can reach, it SHALL
on Windows decide from the owner and DACL: the owner SHALL be the user scrim runs as, SYSTEM or
Administrators, and no ACE SHALL grant access to any other account. Directories scrim creates for
such files SHALL get a protected DACL granting only the user, SYSTEM and Administrators.

#### Scenario: Directory readable by Everyone is refused

- **WHEN** the CA directory's DACL grants Everyone read access
- **THEN** scrim refuses to use it and names the account the DACL grants

### Requirement: Notarised macOS binaries

When the repository's Apple signing secrets are set, the release SHALL sign every darwin binary with
a Developer ID Application certificate (hardened runtime, secure timestamp) and have Apple notarise
it, in jobs that build no code, signing the data plane before it is embedded. When none is set, the
release SHALL publish unsigned darwin binaries with a notice, and the release notes SHALL say they are
not notarised. When only some are set, the release SHALL fail.

#### Scenario: Release without the secrets

- **WHEN** a release runs and no Apple signing secret is set
- **THEN** it publishes, and the release notes say the darwin binaries are not signed or notarised

#### Scenario: Embedded copy stays the shipped one

- **WHEN** a release with the secrets signs the darwin binaries
- **THEN** the data plane embedded in each darwin `scrim` is byte for byte the signed `scrim-dataplane` of the same release

### Requirement: Windows tested in CI

CI SHALL build scrim and run the Go and Rust unit tests on Windows for every change, and launch the
real data plane from Go over the stdio boundary. A package or test that cannot run on Windows SHALL
be excluded with the reason stated next to the exclusion.

#### Scenario: Windows job on a pull request

- **WHEN** a pull request runs CI
- **THEN** the Windows job runs both test suites and the real data plane test, and lists each excluded package with its reason
