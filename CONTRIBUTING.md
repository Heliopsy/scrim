# Contributing to scrim

See "Building from source" in the README for toolchains. `just check` runs every gate CI runs
except CodeQL and Scorecard; run it before pushing. Coding rules are in [AGENTS.md](AGENTS.md).

## Specs come first

[OpenSpec](https://openspec.dev) is the normative contract. A change to behaviour updates
`openspec/` before the code, and a pull request that changes behaviour without a spec change is not
merged.

```sh
openspec validate --all --strict
```

## Documented commands

Shell blocks in the README and the user docs listed in `test/e2e/docs` run in CI as written. Mark a
runnable block with `test` after the language (and a mode where it needs one, see the package
comment of `test/e2e/docs/docs_test.go`):

````markdown
```sh test
scrim config validate
```
````

A command that cannot run in the sandbox (it needs the network, a published release or root) says
why on the line above the block, `<!-- docs-test: skip: downloads a release from GitHub -->`. A
shell block with neither fails the test. Run it with `just docs-test`.

## Fuzzing

`scripts/fuzz.sh targets` lists every fuzz target, cargo-fuzz and Go; `scripts/fuzz.sh run KIND UNIT
TARGET SECONDS` runs one as CI does (cargo-fuzz needs `scripts/fuzz.sh tools DIR` first). A pull
request fuzzes the targets it touches for 5 minutes, the nightly run every target for an hour. When
a target finds something, the job uploads the input; [docs/leak-assurance.md](docs/leak-assurance.md#fuzzing)
says how it becomes a regression test. Fuzz seeds are built from the fixtures: after changing a
fixture, rewrite them with `SCRIM_FUZZ_SEEDS=update cargo test -p scrim-redact -p scrim-toolproxy
--test fuzz_seeds` in `dataplane/`.

## Dependencies

Before you add or bump a dependency, Go module or Rust crate, look up its latest stable release in
the registry ([pkg.go.dev](https://pkg.go.dev) or the module proxy for Go, including newer major
paths such as `/v2`; [crates.io](https://crates.io) for Rust) and use that version. Never write a
version from memory or copy one from an older crate in the tree. CI enforces it: `just deps-fresh`
fails when a direct dependency is behind its latest major (its latest 0.x minor before 1.0), and
runs weekly as well. When a new major cannot be adopted yet, add a line to `.deps-fresh-ignore`
with an expiry date and the reason.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/):

```text
<type>[optional scope]: <description>

Types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert
```

Types map to semver: `fix:` is a patch, `feat:` a minor, `feat!:` or `BREAKING CHANGE:` a major.
Release notes and version bumps are generated from them, so the type matters. The pull request
title must be a conventional commit too, because squash merges use it.

Do not add `Co-Authored-By` trailers.

## Secrets in contributions

Never commit, paste or attach a real secret, not even an expired one. Test fixtures use generated
values. Bug reports use placeholders.

## Contributor License Agreement

scrim is released under the AGPL-3.0. Contributions are accepted under the [CLA](CLA.md). The CLA
assistant comments on your first pull request with a link; signing is one comment and covers all
your future contributions.
