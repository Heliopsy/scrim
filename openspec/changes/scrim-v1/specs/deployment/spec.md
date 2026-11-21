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

#### Scenario: Image signature checked at admission

- **WHEN** the documented Kyverno ImageValidatingPolicy (`deploy/examples/kyverno`) is installed and
  a pod names a scrim image
- **THEN** a release image signed by the release workflow is admitted with its tag pinned to the
  verified digest, and an unsigned image of the same repository is refused

#### Scenario: Pre-release does not move latest

- **WHEN** a pre-release tag such as `v0.2.0-rc.1` is released
- **THEN** its image is tagged `0.2.0-rc.1` only and `latest` still names the previous release

### Requirement: Reproducible release builds

Release binaries, archives and images SHALL be byte-for-byte reproducible from the tagged source,
the locked dependencies and the pinned toolchains, and the release SHALL fail if a rebuild differs.

#### Scenario: Rebuild matches the release

- **WHEN** the linux amd64 binaries are rebuilt from the release tag on a different machine and checkout path
- **THEN** their SHA-256 digests equal those in the signed checksums of the release

### Requirement: Direct dependencies on their latest major

CI SHALL fail, on every change and on a weekly schedule, when a direct dependency is behind its
latest stable major release: a non-indirect or tool require in `go.mod`, or a registry entry of a
dependency table or `[workspace.dependencies]` in a Cargo manifest under `dataplane/`. A 0.x crate
is behind when a newer 0.x minor exists; a Go module is behind when a newer major module path has a
stable release, and fails when its module is deprecated.

#### Scenario: Crate a 0.x minor behind

- **WHEN** a Cargo manifest requires `rcgen = "0.13"` and crates.io has a stable `0.14` release
- **THEN** `just deps-fresh` and the CI job fail and name rcgen, the requirement and the latest version

#### Scenario: New Go major module path

- **WHEN** `go.mod` requires `example.com/m v1.9.0` and the module proxy has a stable release of `example.com/m/v2`
- **THEN** the check fails and names the `/v2` path and its latest version

#### Scenario: Minor lag after 1.0

- **WHEN** a manifest requires `tokio = "1.40"` and the latest release is `1.54.1`
- **THEN** the check passes, and the bump is left to Dependabot

### Requirement: Dated exceptions to the freshness check

A dependency MAY stay behind its latest major only through an entry in `.deps-fresh-ignore` that
names it and gives a reason and an expiry date; an expired entry SHALL fail the check.

#### Scenario: Expired exception

- **WHEN** `.deps-fresh-ignore` holds an entry whose expiry date has passed
- **THEN** the check fails and names the entry, whether or not the dependency is still behind

### Requirement: Freshness check fails closed

The dependency freshness check SHALL query no host but the Go module proxy and the crates.io index,
and a lookup that fails SHALL fail the check, never pass it. The pin check SHALL fail the same way
on a lookup that fails.

#### Scenario: Registry unreachable

- **WHEN** the crates.io index or the module proxy cannot be reached after retries
- **THEN** the check fails with an error for each dependency it could not look up

### Requirement: Every pin is visible to an update bot

Every tool, container image, toolchain and Kubernetes version the repository pins outside `go.mod`
and the Cargo manifests SHALL be described to Renovate (an annotation above the pin or a pattern in
`renovate.json`), and every workflow action SHALL be pinned by commit SHA with its version in a
comment. No file SHALL be managed by both Renovate and Dependabot.

#### Scenario: Annotation Renovate cannot see

- **WHEN** a pin carries a `renovate:` annotation that no custom manager in `renovate.json` matches
- **THEN** the depsfresh tests fail and name the file and line

### Requirement: Pinned tools and actions on their latest release

A weekly check SHALL fail when a pin or action is behind a stable release that has been published
for longer than the grace period (14 days), or when an action's SHA is not the commit of the
version its comment names. A pin MAY stay behind only through a dated, explained entry in
`.deps-fresh-ignore`.

#### Scenario: Tool behind an old release

- **WHEN** a script pins a tool at `v1.1.0` and its `v1.2.0` release is 30 days old
- **THEN** `just pins-fresh` and the weekly run fail and name the tool, the pin and the latest release

#### Scenario: Release inside the grace period

- **WHEN** the only newer release of a pinned tool is 3 days old
- **THEN** the check reports the pin as pending and passes

#### Scenario: Action SHA that is not its tag

- **WHEN** a workflow uses an action at a SHA whose comment names `v1.0.0` and that tag points at another commit
- **THEN** the check fails and names the action, the pinned SHA and the tag's commit

### Requirement: Pinned checksums follow their versions

A release asset that is downloaded by version SHALL be verified against a pinned SHA-256, and the
asset's URL SHALL be written next to that checksum, so the checksum can be recomputed when the
version moves. CI SHALL fail on a changed file whose pinned checksum does not match the asset its
version names, and name the checksum and the asset.

#### Scenario: Version bumped without its checksum

- **WHEN** a pull request moves `HELM_VERSION` and leaves its checksum unchanged
- **THEN** the pinned checksums job fails, names the file and line, and `just pin-sums` rewrites the checksum

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

### Requirement: Host-level interception install

`scrim install --system` SHALL install the transparent mode with `--transparent` (nftables rules for
the users and control groups given with `--cover-user` and `--cover-cgroup`, loaded by a unit
independent of the scrim service, and a drop-in that turns on the transparent listener) and the DNS
override with `--dns` (a block in `/etc/hosts` and a drop-in that turns on the SNI listener on port
443), recording each change in the install manifest. It SHALL refuse to cover scrim's own user.

#### Scenario: Transparent install and uninstall

- **WHEN** a user runs `scrim install --system --transparent --cover-user agent1`, then `scrim uninstall --system --purge`
- **THEN** agent1's provider connections were redirected while installed
- **AND** after uninstall the file system and `nft list ruleset` are identical to before the install

#### Scenario: Rules outlive the service

- **WHEN** scrim.service stops while the transparent mode is installed
- **THEN** the nftables rules stay loaded and the covered users' provider connections fail

#### Scenario: Edited hosts block

- **WHEN** the scrim block in `/etc/hosts` was edited before uninstall
- **THEN** the block stays, is listed with the manual step, and the command exits non-zero

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

The chart SHALL allow autoscaling on the load of proxied streams per replica, not only on CPU, using
a metric scrim exports: the open data plane connections (`scrim_dataplane_connections_active`), each
of which carries at most one stream at a time.

#### Scenario: Scale on streams

- **WHEN** open connections per replica exceed the configured target
- **THEN** the autoscaler adds replicas

#### Scenario: Connections metric without metrics

- **WHEN** the connections metric is enabled while scrim's metrics are off
- **THEN** the chart refuses to render and names `metrics.enabled`

### Requirement: Several replicas share state and events

The chart SHALL render `state.backend` and `events.backend` together from one PostgreSQL setting and
set `deployment.replicas`, and SHALL refuse more than one replica, or the autoscaler, without
PostgreSQL.

#### Scenario: Replicas on memory state

- **WHEN** the values ask for two replicas without PostgreSQL
- **THEN** the chart refuses to render and names the PostgreSQL setting

#### Scenario: Replicas on PostgreSQL

- **WHEN** the values enable PostgreSQL and the autoscaler
- **THEN** scrim's configuration has `state.backend` and `events.backend` set to postgres and
  `deployment.replicas` set to the autoscaler's maximum

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

### Requirement: Private upstream roots in the chart

The chart SHALL mount an operator's PEM bundle of extra upstream roots and set
`dataplane.upstream-ca-file` to it, in central and sidecar mode.

#### Scenario: Tool host with a private CA in the cluster

- **WHEN** a credential is bound to a tool host whose certificate is signed by a private CA given to
  the chart
- **THEN** the tool proxy connects to it and injects the credential

### Requirement: Agent pod identity in the chart

With Kubernetes identity on (the chart's default), the chart SHALL give every labelled agent
container a projected service account token for scrim's audience and a launcher that sends it where
scrim expects a caller's token (the password of the proxy user `k8s` and `x-scrim-session`), SHALL
let scrim create TokenReviews and nothing else, and SHALL install no policy rule that injects for
unknown callers.

#### Scenario: Agent started through the launcher

- **WHEN** an agent command in a labelled pod runs through the launcher and sends a placeholder
  toward the credential's bound host
- **THEN** scrim identifies the pod's service account with TokenReview and the built-in rule injects
  the credential

#### Scenario: Agent started without the launcher

- **WHEN** the same request comes from a process started without the launcher
- **THEN** the caller is unknown and nothing is injected

#### Scenario: Token never forwarded

- **WHEN** an identified agent calls a provider through the base URL
- **THEN** neither the provider nor scrim's logs see the agent's token

### Requirement: Store login with the pod's service account

The chart SHALL mount a projected token with the store's audience into central scrim and every
sidecar for store Kubernetes authentication, so an installation can run with no static store
credential.

#### Scenario: No static store credential

- **WHEN** the store is configured with Kubernetes auth and the token mount is enabled
- **THEN** scrim loads its redaction set and injects credentials with no store credential in any
  Secret

### Requirement: Metrics from the chart

The chart SHALL render scrim's `metrics.*` settings from its values, SHALL refuse metrics on the pod
IP without a bearer token unless the operator sets the weakening that allows it, and SHALL ship the
alert rules and dashboard of `deploy/monitoring` unchanged.

#### Scenario: Metrics without a token

- **WHEN** metrics are enabled without a token Secret or the weakening
- **THEN** the chart refuses to render and names the token setting

#### Scenario: Bundled rules drift

- **WHEN** the chart's copy of the alert rules or dashboard differs from `deploy/monitoring`
- **THEN** the chart test fails

### Requirement: Published, signed chart

Each release SHALL publish the chart at the release version to `oci://ghcr.io/heliopsy/charts/scrim`,
signed keyless with the same workflow identity as the images, with an SPDX SBOM and SLSA provenance
attached to its digest, and SHALL verify all three from the registry before the release completes.

#### Scenario: Verify a published chart

- **WHEN** a user runs `cosign verify` on the chart digest with the release workflow identity
- **THEN** the signature verifies, and the SBOM and provenance attestations verify on the same digest

### Requirement: Closed chart values and one chart gate

The chart's values schema SHALL be generated from values.yaml and closed, so an unknown key is
refused, and one script SHALL check the chart the same way locally and in CI: generated files,
lint, schema validation with CRDs, Pod Security "restricted" for every pod the chart renders or
injects (the egress guard as the one listed exception), unit tests, the upgrade from the previous
chart, and packaging.

#### Scenario: Misspelt value

- **WHEN** the values name a key the chart does not declare
- **THEN** the chart refuses to render and names the key

#### Scenario: High availability preset

- **WHEN** `global.ha` is on without PostgreSQL
- **THEN** the chart refuses to render; with PostgreSQL it renders two replicas, a PDB keeping one,
  anti-affinity and a zone spread

#### Scenario: helm test

- **WHEN** an operator runs `helm test` on an installed release
- **THEN** test pods reach the LLM listener and the forward proxy through the Service

### Requirement: Agent pod injection policy

The chart SHALL optionally install an admission policy that configures pods carrying a documented
label to use scrim (environment, CA, MCP config, identity token), without changing agent images.
The policy SHALL use Kyverno's `policies.kyverno.io/v1` API (MutatingPolicy and ValidatingPolicy),
SHALL mutate Pods only, never the controllers that create them, and the chart SHALL document the
Kyverno versions it supports and the upgrade order from the `kyverno.io/v1` ClusterPolicy of earlier
charts.

#### Scenario: Labelled pod is configured

- **WHEN** a pod with the scrim agent label is created
- **THEN** it starts with scrim's base URLs, CA bundle and identity token in place

#### Scenario: Labelled controller left as written

- **WHEN** a Deployment whose pod template carries the scrim agent label is created
- **THEN** the Deployment is stored as written and only the pods it creates are configured

#### Scenario: Current Kyverno

- **WHEN** the chart is installed with the policy on the latest Kyverno release, which no longer
  creates or runs `kyverno.io/v1` ClusterPolicies
- **THEN** labelled pods are configured and labelled pods in unprepared namespaces are refused

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

### Requirement: Tested deployment examples

The repository SHALL document every supported way to deploy scrim (workstation, systemd, cloud-init,
Ansible, podman, Kubernetes manifests, Kustomize, Helm, Flux, Argo CD) with complete example files,
and CI SHALL check each file against the scrim image built from the same commit: configs with
`scrim config validate`, Kubernetes objects against pinned schemas, units with `systemd-analyze
verify`, and the container examples by running them and sending a canary request.

#### Scenario: Example config drifts from the code

- **WHEN** an example config uses a setting the scrim of the same commit does not know
- **THEN** the deployment example check fails and names the example and the setting

#### Scenario: Container example leaks

- **WHEN** a container example is run by the smoke check and sent a canary value
- **THEN** the capture holds the placeholder and not the value, or the check fails

### Requirement: Example versions follow the release

Every scrim release version an example pins SHALL be the current release, and the release pull
request SHALL move all of them to the version it releases.

#### Scenario: Example version left behind

- **WHEN** an example names a scrim version other than the current release on a line the release
  pull request updates
- **THEN** the deployment example check fails and names the file
