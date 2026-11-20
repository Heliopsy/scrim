## Purpose

Defines how scrim is packaged and installed on a laptop, VM, container host or Kubernetes cluster,
with one binary and one configuration contract everywhere, and how every installation change can be
reverted.

## ADDED Requirements

### Requirement: Single static binary per platform

Each release SHALL ship one self-contained `scrim` binary per supported platform, at least Linux
amd64, Linux arm64 and macOS arm64, with no runtime dependencies beyond the operating system.

#### Scenario: Run on a minimal host

- **WHEN** the Linux amd64 binary is copied to a minimal host with no extra libraries
- **THEN** `scrim version` runs and prints the version

### Requirement: Hardened container image

Each release SHALL publish a container image that runs as a non-root user, works with a read-only
root filesystem, contains only what scrim needs, and supports amd64 and arm64.

#### Scenario: Read-only root filesystem

- **WHEN** the image runs with a read-only root filesystem and a writable state volume
- **THEN** scrim starts and serves normally

### Requirement: Same configuration in every target

The binary, container image, systemd/Quadlet units and Helm chart SHALL accept the same configuration
file format, environment variables and flags, so a configuration validated in one target is valid in
every other.

#### Scenario: Reuse a config in Kubernetes

- **WHEN** a config file validated locally is mounted into the Helm deployment
- **THEN** the deployment starts with the same effective settings, apart from those the chart sets explicitly

### Requirement: Signed releases with SBOM and provenance

Every release artifact (binaries, image, chart) SHALL be signed, SHALL have a software bill of
materials and build provenance attestation, and the verification steps SHALL be documented.

#### Scenario: Verify a binary

- **WHEN** a user follows the documented verification steps for a downloaded binary
- **THEN** the signature and provenance verify against the release

#### Scenario: Verify an image

- **WHEN** a user follows the documented verification steps for a published image tag
- **THEN** the image signature, the SBOM attestation for the user's architecture and the build provenance verify against the release workflow's identity

#### Scenario: Pre-release does not move latest

- **WHEN** a pre-release tag such as `v0.2.0-rc.1` is released
- **THEN** its image is tagged `0.2.0-rc.1` only and `latest` still names the previous release

### Requirement: Reproducible release builds

Release binaries, archives and images SHALL be byte-for-byte reproducible from the tagged source,
the locked dependencies and the pinned toolchains, and the release SHALL fail if a rebuild differs.

#### Scenario: Rebuild matches the release

- **WHEN** the linux amd64 binaries are rebuilt from the release tag on a different machine and checkout path
- **THEN** their SHA-256 digests equal those in the signed checksums of the release

### Requirement: Standalone data plane artifacts

Each release SHALL publish the data plane on its own, as `scrim-dataplane` binaries for the same
platforms and a `scrim-dataplane` image, built from the same source and toolchain as the copy
embedded in `scrim`, with the same signatures, SBOMs and provenance.

#### Scenario: Sidecar uses the same data plane

- **WHEN** the `scrim-dataplane` binary of a release is compared with the data plane embedded in that release's `scrim` binary for the same platform
- **THEN** they are byte-identical

### Requirement: Local service installation

`scrim install` SHALL set scrim up as a local service (systemd unit or Quadlet on Linux, launch
agent on macOS), SHALL show every change before making it, SHALL list the changes without making
them with `--dry-run`, and SHALL wait until the started service reports ready.

#### Scenario: Install as a systemd service

- **WHEN** a user runs `scrim install --system` on Linux with systemd
- **THEN** scrim runs as a service under its own user
- **AND** the user was shown each file, unit and rule before it was created

#### Scenario: Dry run

- **WHEN** a user runs `scrim install --system --dry-run`
- **THEN** every change is listed and the file system, accounts and units are unchanged

### Requirement: Service install modes

`scrim install` SHALL offer three modes: `--user`, a systemd user unit for the current user;
`--system`, a hardened system unit running as the dedicated user `scrim` with its configuration in
`/etc/scrim`, state in `/var/lib/scrim` and sockets in `/run/scrim`, the agent API socket given to
the group `scrim-agents`; and `--quadlet`, the release image as a podman Quadlet container,
rootless or with `--system` as the dedicated user.

#### Scenario: Hardened system unit

- **WHEN** the system unit is installed
- **THEN** it runs without capabilities and with no new privileges, a read-only system
  (`ProtectSystem=strict`), a private `/tmp`, `MemoryDenyWriteExecute`, `LockPersonality`, restricted
  address families, the `@system-service` system call filter, unlimited memlock and no core dumps
- **AND** the data plane still starts from memory

#### Scenario: Agents of another user find the system service

- **WHEN** a user in `scrim-agents` who is mapped in `identity.peers` runs `scrim run` with no scrim
  configured and no daemon of their own
- **THEN** the agent is served by the system service through `/run/scrim/api.sock`
- **AND** no private daemon is started

#### Scenario: User outside the agent group

- **WHEN** a user who is not in `scrim-agents` runs `scrim run` against the system service
- **THEN** the agent is not started

### Requirement: Install upgrades in place

Running `scrim install` again in the mode already installed SHALL keep the recorded changes,
replace the files whose content changed and restart the service.

#### Scenario: Upgrade in place

- **WHEN** `scrim install` is run again in the same mode with a new binary
- **THEN** the installed binary is replaced, the service is restarted and the manifest lists the
  binary once

### Requirement: Status reports the installed service

`scrim status` SHALL report the service `scrim install` set up and its state.

#### Scenario: Status reports the service

- **WHEN** `scrim status` runs on a host with an installed service
- **THEN** it reports the mode, the unit, its state and the manifest, and lists an inactive
  service as degraded

### Requirement: Complete uninstall

`scrim install` SHALL record every change it makes (units, users, groups and memberships, files and
directories it created, CA trust entries, nftables or eBPF rules, managed agent settings,
environment drop-ins), and `scrim uninstall` SHALL revert each of them, newest first, and report
anything it could not revert with the manual step.

#### Scenario: Uninstall leaves no trace

- **WHEN** scrim is installed in system or user mode, used by an agent, and uninstalled with `--purge`
- **THEN** the file system outside runtime and log directories is identical to a snapshot taken before install

#### Scenario: Uninstall reverts trust and rules

- **WHEN** a user runs `scrim uninstall` after a transparent-mode install
- **THEN** the CA is removed from every trust store it was added to and the interception rules are gone
- **AND** any item that could not be reverted is listed with the manual step to do it

### Requirement: Uninstall keeps what install did not create

`scrim uninstall` SHALL NOT remove accounts or files that existed before install, SHALL leave in
place and report a file install wrote that was changed since, and SHALL keep the state directory,
a Quadlet volume and a pulled image unless `--purge` is given.

#### Scenario: State kept without purge

- **WHEN** `scrim uninstall` runs without `--purge`
- **THEN** the state directory stays, is listed with the command to remove it, and stays in the manifest

#### Scenario: Edited file

- **WHEN** a file install wrote was edited before uninstall
- **THEN** the file stays, is listed with the manual step, and the command exits non-zero

### Requirement: Helm chart

scrim SHALL ship a Helm chart that deploys a Deployment, Service, PodDisruptionBudget and optional
HorizontalPodAutoscaler, with every scrim setting exposed through values or a config file.

#### Scenario: Install the chart

- **WHEN** an operator installs the chart with default values
- **THEN** scrim runs with readiness and liveness probes and a PodDisruptionBudget

### Requirement: Autoscaling on concurrent streams

The chart SHALL allow autoscaling on the number of concurrent proxied streams per replica, not only on
CPU.

#### Scenario: Scale on streams

- **WHEN** concurrent streams per replica exceed the configured target
- **THEN** the autoscaler adds replicas

### Requirement: Network policy

The chart SHALL optionally create network policies that let agent pods reach only scrim (and DNS) for
model provider traffic, and let scrim reach providers, stores and notifiers.

#### Scenario: Agent bypass blocked

- **WHEN** network policies are enabled and an agent pod connects to a provider directly
- **THEN** the connection is refused

### Requirement: Sidecar mode

The chart SHALL optionally run the full `scrim proxy` inside each agent pod on loopback instead of a
central Deployment, with an egress guard that lets only the sidecar's user open outbound
connections, and SHALL refuse sidecar mode without the guard unless it is turned off explicitly.

#### Scenario: Sidecar agent cannot bypass

- **WHEN** a pod labelled for sidecar mode starts with the egress guard
- **THEN** its agent reaches providers and tool hosts only through the in-pod scrim
- **AND** a direct connection from the agent to the provider is refused

#### Scenario: Sidecar without a guard image

- **WHEN** sidecar mode is enabled without a guard image and the guard is not turned off
- **THEN** the chart refuses to render and names the setting

### Requirement: One CA and placeholder key set per installation

Every scrim pod of an installation (replicas and sidecars) SHALL use the same interception CA and
the same placeholder keys, held in Kubernetes Secrets the chart creates once and keeps across
upgrades, or supplied by the operator. The CA's public certificate SHALL be published to every agent
namespace; its private key SHALL be mounted only into scrim containers.

#### Scenario: Upgrade keeps the CA

- **WHEN** the chart is upgraded
- **THEN** the CA certificate agents trust is unchanged

#### Scenario: Agent pods get the certificate only

- **WHEN** an agent pod is configured by the injection policy
- **THEN** it mounts the CA certificate and no container but scrim's mounts the CA key

### Requirement: Chart values hold no secrets

The chart SHALL take credentials only as references to Secrets (mounted files or environment from
Secret keys), and SHALL refuse to render when a credential field of the scrim configuration in the
values holds a literal.

#### Scenario: Literal store token

- **WHEN** the values set a store token to a literal instead of a reference
- **THEN** the chart refuses to render and names the field

### Requirement: Private upstream roots

scrim SHALL accept a PEM bundle of extra roots for upstream TLS (`proxy.upstream-ca-file`), trusted
by the LLM proxy and the tool proxy in addition to the system and Mozilla roots, and SHALL refuse to
start the data plane when the file cannot be read or holds no certificate.

#### Scenario: Tool host with a private CA

- **WHEN** a credential is bound to a host whose certificate is signed by a private CA listed in
  `proxy.upstream-ca-file`
- **THEN** the tool proxy connects to it and injects the credential

### Requirement: Agent pod injection policy

The chart SHALL optionally install an admission policy that configures pods carrying a documented
label to use scrim (environment, CA, MCP config, identity token), without changing agent images.

#### Scenario: Labelled pod is configured

- **WHEN** a pod with the scrim agent label is created
- **THEN** it starts with scrim's base URLs, CA bundle and identity token in place

#### Scenario: Labelled pod in an unprepared namespace

- **WHEN** a pod with the scrim agent label is created in a namespace the chart did not prepare
- **THEN** it is refused, rather than started without its CA, environment or network policy

#### Scenario: Configuration without the admission policy

- **WHEN** the admission policy is not installed
- **THEN** the chart provides the same environment as a ConfigMap in each agent namespace for the
  pod to reference

### Requirement: Long-running daemon

`scrim proxy` SHALL run the control plane and the supervised data plane as one service with every
configured listener, SHALL push a new data plane snapshot after every store, catalog,
configuration, policy or break-glass change, SHALL report ready only while the data plane holds a
snapshot and every listener is bound, and SHALL stop gracefully on SIGINT or SIGTERM.

#### Scenario: Value added while running

- **WHEN** a value is written to a store while the daemon runs
- **THEN** the data plane receives a snapshot containing it without a restart

#### Scenario: Not ready before the first snapshot

- **WHEN** the data plane has not yet applied a snapshot or a listener is not bound
- **THEN** the readiness endpoint fails and names the reason

#### Scenario: Repeated store credentials and retained values

- **WHEN** a store's own credential appears twice (a static token that is also the current token) or
  a rotated value is retained next to the current one
- **THEN** the data plane accepts the snapshot, the repeated value is sent once and the current
  value keeps its catalog name

#### Scenario: Graceful stop

- **WHEN** the daemon receives SIGTERM
- **THEN** it removes its sockets and info file and exits without error

### Requirement: Operator authentication on the admin API

The admin API SHALL attribute every request to an operator from the connection: on its Unix socket
only the user scrim runs as or root, by peer credentials; on a TCP listener only a request
presenting the configured `admin.token`. The daemon SHALL refuse to start a TCP admin listener
without a token.

#### Scenario: Another local user

- **WHEN** a different local user connects to the admin socket
- **THEN** every operator call is refused as unauthenticated

#### Scenario: TCP without a token

- **WHEN** `admin.url` is a TCP address and `admin.token` is not set
- **THEN** the daemon refuses to start and names `admin.token`
