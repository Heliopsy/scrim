# AGENTS.md

Rules for anyone, human or agent, changing scrim. Terse by design. Read before writing code.
Language-specific standards are added once the implementation language is decided.

## Security invariants

- No API, MCP tool, CLI command, error message, log line, metric, trace attribute or audit entry
  ever contains a secret value. Secret values live in memory only, in a type that redacts itself
  when printed or serialised.
- Redaction failure refuses the request. Nothing is ever forwarded unredacted as a fallback.
- Every outbound provider request passes two independent checks: the redactor, then a separate
  guard over the exact outgoing bytes. The two never share matching code.
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
  architecture (`ubuntu-24.04`, `ubuntu-24.04-arm`) against musl, both darwin targets on one macOS
  runner with Apple's toolchain. The Go control plane is `CGO_ENABLED=0` and cross-compiles from
  one Linux runner, embedding the data plane built for the same target. Zig would add a third
  toolchain whose libc and linker nobody else tests.
- Reproducible: `--locked` and `-mod=readonly`, `-trimpath`, Rust paths remapped, symbols stripped,
  `SOURCE_DATE_EPOCH` from the commit, deterministic tar and gzip, images with `--timestamp` and
  the base pinned by digest in the Containerfile. The `reproduce` job rebuilds linux-amd64 on a
  second runner from a different path and fails the release on any byte difference. No caches in
  the release workflow.
- Images are assembled from the release binaries (`COPY`, no `RUN`), so the image holds the bytes
  the archives hold and a multi-arch build needs no emulation. Rootless podman, distroless static
  base, UID 65532, read-only root filesystem tested on every build.
- Signing is keyless (GitHub OIDC, Sigstore): cosign over `checksums.txt` and each image
  (`--recursive`), SPDX SBOMs per archive and per image architecture, SLSA provenance through
  `actions/attest-build-provenance`. Build jobs have a read-only token and no OIDC token; only the
  sign, image and publish jobs get `id-token`, `attestations` or `contents: write`.
- Release tools are pinned in `scripts/release/release.env`, downloads checked by sha256. Bump a
  tool by changing its version and checksum together.
- release-please creates the tag with `GITHUB_TOKEN`, which starts no workflow, so its workflow
  must dispatch the release: `gh workflow run release.yaml -f tag=vX.Y.Z`. A hand-pushed `v*` tag
  builds on its own.
- The layout the scripts depend on (embed path, Go main package, version package, crate name) is
  the top block of `release.env`. Move a path there in the same change that moves it in the tree.
