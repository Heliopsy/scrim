## Context

The control plane launches the data plane with one end of a socketpair as fd 3 and identifies
local callers by Unix peer credentials. Neither exists on Windows. Private files are checked by mode
bits, which Go reports on Windows without any relation to who can read the file. The release builds
every platform's data plane on a native runner and cross-compiles the Go control plane on Linux.

## Goals / Non-Goals

**Goals:** a Windows release that keeps every security invariant where it runs and refuses what it
cannot do; notarised macOS binaries once the owner adds the Apple credentials, without breaking
releases before that.

**Non-Goals:** Authenticode signing of the Windows binaries; transparent interception, the exec
broker, plugins, the ssh-agent, the filesystem view, service installation and the database proxies
on Windows; separating Windows accounts other than the one scrim runs as.

## Decisions

### D1. Boundary over stdin and stdout on Windows

The data plane runs with `--stdio` and the gRPC connection is its stdin and stdout, two anonymous
pipes. Go hands a Windows child exactly the handles it is given, so only the two processes hold the
ends, and nothing has a name another process could open. Named pipes or an AF_UNIX path would need
a name, an ACL and a race-free handshake for no gain. EOF on stdin is the shutdown signal, as the
socket closing is on Unix. The data plane already never writes to stdout.

Alternatives: loopback TCP with a token (any local process can connect and probe); a named pipe
with a random name (needs a security descriptor and still has a name).

### D2. One identity per Windows account

Windows has no UIDs. `SIO_AF_UNIX_GETPEERPID` gives the peer's PID; the user SID of that process's
token is compared with scrim's. A peer running as scrim's account gets the UID `os.Getuid` reports
on Windows (-1), so the default peer rule and the admin socket's same-user check work unchanged;
any other account gets a distinct UID no rule can name. `identity.peers` may name only scrim's own
account there. Agents are separated by `scrim run` session tokens, bound to the process tree through
the Toolhelp snapshot (parent PID) and process creation times; a parent created after its child is a
reused PID and ends the walk.

### D3. DACL checks behind one package

`internal/fsperm` answers "can anyone but the owner reach this?" per platform: mode bits on Unix;
on Windows the owner must be the user, SYSTEM or Administrators and no allow ACE may grant another
account. Directories scrim creates get a protected DACL (user, SYSTEM, Administrators, inherited by
children). Callers keep their Unix messages; the detail string and fix hint come from the package.

### D4. Refuse at start-up, by name

`internal/daemon` checks the configuration against the platform before anything listens and lists
every setting Windows cannot honour, so a protection is never silently missing. Defaults always pass.

### D5. Signing in separate jobs

Apple's secrets are only in two macOS jobs that build nothing: one signs the darwin data planes
before the Linux job embeds them (so the embedded copy stays byte-identical to the shipped data
plane), one signs the darwin `scrim` binaries and notarises all four with `notarytool` (App Store
Connect API key). Packaging moves to its own job after them. On pull requests, and when no secret is
set, both jobs pass the binaries through unchanged with a notice, and the publish job adds a line to
the release notes. A partly configured set fails the release.

## Risks / Trade-offs

- Signed macOS binaries carry Apple's timestamp and are not byte-reproducible; the reproducibility
  gate covers linux-amd64 only, as before.
- PID reuse between a peer's connect and the token lookup could misattribute a Windows peer to
  another account; the socket directory's DACL already limits who can connect to scrim's account,
  SYSTEM and Administrators.
- Windows has no memory locking or core dump suppression in the data plane; `require` is refused.
