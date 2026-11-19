# Contributing to scrim

scrim is in its design phase. Build, test and toolchain instructions arrive with the first code,
once the implementation language is settled.

## Specs come first

[OpenSpec](https://openspec.dev) is the normative contract. A change to behaviour updates
`openspec/` before the code, and a pull request that changes behaviour without a spec change is not
merged.

```sh
openspec validate --all --strict
```

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
