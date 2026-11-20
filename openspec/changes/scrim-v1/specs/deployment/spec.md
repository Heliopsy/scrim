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

`scrim install` SHALL set scrim up as a local service running as a dedicated user (systemd unit or
Quadlet on Linux, launch agent on macOS), and SHALL show every change it will make before making it.

#### Scenario: Install as a systemd service

- **WHEN** a user runs `scrim install` on Linux with systemd
- **THEN** scrim runs as a service under its own user
- **AND** the user was shown each file, unit and rule before it was created

### Requirement: Complete uninstall

`scrim install` SHALL record every change it makes (units, users, CA trust entries, nftables or eBPF
rules, managed agent settings, environment drop-ins), and `scrim uninstall` SHALL revert each of them
and report anything it could not revert.

#### Scenario: Uninstall reverts trust and rules

- **WHEN** a user runs `scrim uninstall` after a transparent-mode install
- **THEN** the CA is removed from every trust store it was added to and the interception rules are gone
- **AND** any item that could not be reverted is listed with the manual step to do it

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

### Requirement: Agent pod injection policy

The chart SHALL optionally install an admission policy that configures pods carrying a documented
label to use scrim (environment, CA, MCP config, identity token), without changing agent images.

#### Scenario: Labelled pod is configured

- **WHEN** a pod with the scrim agent label is created
- **THEN** it starts with scrim's base URLs, CA bundle and identity token in place

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

### Requirement: Tested deployment examples

The repository SHALL document every supported way to deploy scrim (workstation, systemd, cloud-init,
Ansible, podman, Kubernetes manifests, Kustomize, Helm, Flux, Argo CD) with complete example files,
and CI SHALL check each file: configs with `scrim config validate` in the release image, Kubernetes
objects against pinned schemas, units with `systemd-analyze verify`, and the container examples by
running them and sending a canary request.

#### Scenario: Example config drifts from the release

- **WHEN** an example config uses a setting the pinned release does not know
- **THEN** the deployment example check fails and names the example and the setting

#### Scenario: Container example leaks

- **WHEN** a container example is run by the smoke check and sent a canary value
- **THEN** the capture holds the placeholder and not the value, or the check fails
