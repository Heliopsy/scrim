# AGENTS.md

Rules for anyone, human or agent, changing scrim. Terse by design. Read before writing code.

## Security invariants

- No API, MCP tool, CLI command, error message, log line, metric, trace attribute or audit entry
  ever contains a secret value. Secret values live in memory only, in a type that redacts itself
  when printed or serialised.
- Redaction failure refuses the request. Nothing is ever forwarded unredacted as a fallback.
- Every outbound provider request passes two independent checks: the redactor, then a separate
  guard over the exact outgoing bytes. The guard's check of the outgoing bytes never uses the
  redactor's matching code. The one exception runs the other way: around a value nested inside a
  longer one, the redactor asks the guard's decoders about its own input, so it can replace the
  longer value whole (design D4).
- Fields of a provider request that are not known configuration are redacted by default.
- A credential is injected only on connections to the hosts it is bound to. It is never restored
  into an agent's command, file edit or tool argument unless the tool policy names that tool and
  that destination.
- A restored value is escaped for every language layer it lands in (shell, heredoc, interpreter
  `-c` strings, SQL, JSON, YAML). Where its output would itself become code, it is not restored.
- Placeholders are deterministic (HMAC of the value), so prompt caching and multiple replicas work
  without shared lookup state.
- Agents can create and update secrets but never read them back.

## Specs and tests

- Behaviour changes update `openspec/` first. Requirements use SHALL; every requirement has a
  scenario.
- New behaviour ships with its tests in the same change.
- The leak suite (fixtures, bypass matrix, recorded provider streams) and the latency budget are
  release gates, not reports.
- A test you have not watched fail is not evidence. Break the behaviour, watch the guard fail,
  restore against git.

## Layout

- Go control plane at the root: `main.go`, `internal/<package>`. Rust data plane in `dataplane/`,
  a Cargo workspace whose members are `dataplane/crates/*`. The boundary schema is
  `proto/scrim/dataplane/v1/dataplane.proto`.
- Shared contracts, each with an in-memory implementation and a contract suite:
  `internal/secret` (the only type a value may live in), `internal/config` (settings registry),
  `internal/stores` (+ `storetest`, `memstore`), `internal/state` (+ `statetest`, `memstate`),
  `internal/policy`, `internal/audit`, `internal/notify`, `internal/obs`. `internal/app` wires
  them; `internal/cli` is the command line; `internal/dataplane` launches and supervises the data
  plane.

## Go

- Go version from `go.mod` (`.tool-versions` for asdf). `gofmt`, `go vet` and `golangci-lint`
  (`.golangci.yml`) are clean; tests run with `-race`.
- A secret value is a `secret.Value` from the moment it is read until it is wiped. Never convert
  it to a `string`, never put one in an error, log attribute, metric label, audit entry, state row
  or API response. Use `Expose` in the narrowest scope that needs the bytes.
- Log through the `*slog.Logger` from `internal/obs` (it scrubs), never `fmt.Print` or `log`.
- Errors that may reach a user name the setting, reference, store or operation, not the data.
- Tests generate values at runtime. A test that checks for leaks seeds a generated value and
  greps every output for it.

### Adding a setting

Declare it once in the package that reads it, as a package-level key:

```go
var Timeout = config.Register(config.Spec[time.Duration]{
    Key: "approvals.timeout", Default: 2 * time.Minute, Flag: true,
    Description: "How long an approval waits before it is denied.",
})
```

Read it with `Timeout.Get(cfg)`. The environment variable and flag are derived from the key. A
setting that weakens an invariant sets `Weakening: true` and is named for what it weakens; one
that holds a credential has type `config.SecretRef`.

### Adding a CLI command

Create `internal/cli/<area>.go` with one method on `cli.Commands`:

```go
func (Commands) Secret(e *Env) *cobra.Command { ... }
```

The root picks it up by reflection; there is no list to edit. Use `e.Config()` and
`e.App(ctx)` for configuration and components, and write to `cmd.OutOrStdout()`.

### Adding a store adapter

Create `internal/stores/<kind>`, implement `stores.Adapter`, declare capabilities honestly, wrap
every error with `stores.NewError` and one of the error kinds, and register the factory in
`init` with `stores.Register(kind, factory)`. Report where a secret lives in the store as labels
with `stores.SetNative` and user-editable metadata with `stores.UserMeta`, never by hand
(docs/stores/README.md, "Writing an adapter"). Link it in with a one-line
`internal/app/store_<kind>.go` blank import. Its tests call `storetest.Run` against the store or
an emulator in podman. State backends follow the same shape with `state.RegisterBackend`,
`statetest.Run` and `internal/app/backend_<name>.go`.

## Rust

- Toolchain pinned in `dataplane/rust-toolchain.toml`, edition 2024. `cargo fmt`, `cargo clippy
  --all-targets -- -D warnings` (lints in `[workspace.lints]`) and `cargo test` are clean.
- `unsafe` is denied workspace-wide. A module that needs it allows it at the top with a comment
  saying why, and every block has a `SAFETY:` comment. Prefer `rustix` to raw `libc`.
- Secret bytes live in `SecretBytes` (zeroed on drop, redacted `Debug`). Never derive `Debug`,
  `Display` or `Serialize` on a type that holds them, and never put them in a `tracing` field.
- The data plane never prints to stdout; logs are JSON on stderr, relayed by the control plane.
- New listeners go in `listeners`, request handling in `engine`; both read the snapshot through
  `engine::Engine` and never wait on the control plane except `Engine::ask`.

## Dependencies

- Before adding or bumping a Go module or Rust crate, check the registry (module proxy or
  pkg.go.dev, probing `/v2`, `/v3`, ... for Go; crates.io for Rust) for the latest stable release
  and use it. Never pick a version from memory, and never copy an older requirement from another
  crate in the tree.
- `just deps-fresh` (`scripts/deps-fresh.sh`, CI job `deps-fresh`, weekly as well) enforces it: it
  fails when a direct dependency is behind its latest stable major, or its latest 0.x minor before
  1.0, or when its module is deprecated. Minor and patch lag on a 1.x line is Dependabot's.
- A new major that cannot be adopted yet gets an entry in `.deps-fresh-ignore` with an expiry date
  and a reason; expired entries fail the gate.
- Every other pin (release binaries in scripts, env files and workflows, container images, the
  Kubernetes target, npm and Python tools, the Go and Rust toolchains) carries a
  `# renovate: datasource=<ds> depName=<name>` comment on the line above, or matches one of the
  inline patterns in `renovate.json` (images, `npx`, `go run`, `pip install`). Look the latest
  stable release up in its registry before bumping it, never from memory.
- Updates are split by ecosystem, never two bots on one file: Dependabot keeps `go.mod`, the
  Cargo manifests and the workflow actions (`.github/dependabot.yml`); Renovate keeps everything
  else (`renovate.json`): the regex managers above, Containerfiles, `.tool-versions`, the Argo CD
  examples and `deploy/examples/ansible/requirements-lint.txt`. release-please owns every scrim
  version with an `x-release-please-version` marker.
- A release asset pinned by sha256 has its URL on the line above the sum
  (`# sha256: https://.../{version}/...`). Renovate moves only the version: run `just pin-sums` on
  its branch to rewrite the sums, and review the diff. The `pin-sums` CI job fails on a sum that
  does not match its asset, naming it.
- `just pins-fresh` (weekly in `deps-fresh.yaml`) fails when a pin or action is behind a release
  that has been out for more than 14 days, the time Renovate and Dependabot get to land it. A pin
  that has to stay behind gets a `pin <depName>` (or `action <owner/repo>`) entry in
  `.deps-fresh-ignore`, with an expiry date and a reason.

## Boundary protocol

- `proto/scrim/dataplane/v1` is the contract. `just proto` regenerates the committed Go and Rust
  code; CI fails when it is stale.
- Adding a field is compatible. Removing, renumbering or changing the meaning of a field, or
  adding a call an older peer would get wrong, bumps `PROTOCOL_VERSION_CURRENT`, and both sides
  and their tests change in the same commit.
- `ValueEntry.value`, `PlaceholderKey.key`, `CaptureRequest.value`, `CaCertificate.key_pem`,
  `AskCaller.kubernetes_token`, `RedactRequest.text` and `UpstreamProxy.password` are the only
  secret fields. Keep it that way: a new secret field needs a redacting `Debug` in `scrim-proto`
  and a wipe in `internal/dataplane` (the control plane wipes `kubernetes_token` in
  `gate.Answer`, and `Supervisor.Redact` wipes `RedactRequest.text`).

## Configuration

- Every setting has one canonical key, settable in the config file, as an environment variable
  (`SCRIM_` plus the key, upper-cased, dots as `_`), and where it makes sense as a flag.
  Precedence: flag, environment, config file, default.
- A setting that weakens a security invariant is named for what it weakens and logs a warning at
  start-up.

## Commits

- Conventional Commits. No `Co-Authored-By` trailers.
- Pin every GitHub Action to a full commit SHA with the version as a comment.

## Release pipeline

- `.github/workflows/release.yaml` builds every release; `scripts/release/` holds the steps, so a
  laptop and CI run the same commands. `docs/install.md` is the user's side of it.
- Plain scripts and a GitHub Actions matrix, not GoReleaser. GoReleaser builds Go targets in
  parallel from one tree, and each needs a different data plane at the one embed path; a prebuild
  hook per target would race or force serial builds through a tool that no longer does the build.
  Its archive, checksum and signing steps are a few lines of shell here.
- No cross linker, no cargo-zigbuild. Each Linux data plane is built on a native runner of its
  architecture (GitHub's `ubuntu-24.04` for amd64 and `ubuntu-24.04-arm` for arm64) against musl,
  both darwin targets on GitHub's `macos-15` with Apple's toolchain. The Go
  control plane is `CGO_ENABLED=0` and cross-compiles from one Linux runner, embedding the data
  plane built for the same target. Zig would add a third toolchain whose libc and linker nobody else
  tests.
- Reproducible: `--locked` and `-mod=readonly`, `-trimpath`, Rust paths remapped, symbols stripped,
  `SOURCE_DATE_EPOCH` from the commit, deterministic tar and gzip, images with `--timestamp` and
  the base pinned by digest in the Containerfile. The `reproduce` job rebuilds linux-amd64 on a
  second `ubuntu-24.04` runner from a different path and fails the release on any byte difference.
  The C parts of the build (ring, zstd) use the image's compiler and musl, so the bytes only match
  on the same image; release builds move to `ho-z10` once it has a pinned toolchain image. No caches
  in the release workflow.
- Images are assembled from the release binaries (`COPY`, no `RUN`), so the image holds the bytes
  the archives hold and a multi-arch build needs no emulation. Rootless podman, distroless static
  base, UID 65532, read-only root filesystem tested on every build.
- Signing is keyless (GitHub OIDC, Sigstore), on GitHub-hosted runners only: cosign over
  `checksums.txt` and each image (`--recursive`), SPDX SBOMs per archive and per image architecture,
  SLSA provenance through `actions/attest-build-provenance`. Build jobs have a read-only token and
  no OIDC token; only the sign, image and publish jobs get `id-token`, `attestations` or `contents:
  write`.
- Release tools are pinned in `scripts/release/release.env`, downloads checked by sha256. Bump a
  tool by changing its version and checksum together.
- The Helm chart is packaged at the release version (`scripts/release/chart.sh`), pushed to
  `oci://ghcr.io/heliopsy/charts/scrim` after the images, signed keyless with the same identity,
  SBOM and provenance attested; its job gets `packages`, `id-token` and `attestations` and builds no
  code. The chart's own gate is `deploy/helm/scrim/ci/verify.sh` (`just helm-test`).
- release-please creates the tag with `GITHUB_TOKEN`, which starts no workflow, so its workflow
  must dispatch the release: `gh workflow run release.yaml -f tag=vX.Y.Z`. A hand-pushed `v*` tag
  builds on its own.
- The release pull request needs no hand commit. release-please bumps every
  `x-release-please-version` marker, `docs/helm-values.md` included (its helm-docs template keeps
  one version per line inside `x-release-please-start-version` blocks, followed by a character that
  cannot continue a semver), and `test/k8s/golden.sh` renders a copy of the chart pinned to version
  1.2.3, so no golden moves with a release. A new generated file that depends on the version gets a
  marker or a pin the same way. After it opens or updates the pull request, the workflow runs
  `verify.sh --generate-only` on the release branch and pushes anything that changed.
- That pull request and that push come from `GITHUB_TOKEN` and start no workflow, so the
  release-please workflow dispatches `ci.yaml`, `leak.yaml`, `openspec.yaml` and
  `deploy-examples.yaml` (each has `workflow_dispatch`) on the release branch; their checks show on
  the pull request. It uses the `actions: write` the job already has, no App key or PAT.
- The layout the scripts depend on (embed path, Go main package, version package, crate name) is
  the top block of `release.env`. Move a path there in the same change that moves it in the tree.
