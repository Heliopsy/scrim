## What changed

## Why

## Spec

- [ ] Behaviour change is reflected in `openspec/` (or this PR changes no behaviour)
- [ ] `openspec validate --all --strict` passes
- [ ] Relevant tasks ticked in `tasks.md`

## Checks

- [ ] New behaviour has tests in the same change
- [ ] PR title is a conventional commit

## Security invariants

- [ ] No secret value can reach a log, metric, trace, error, audit entry, API or MCP response
- [ ] Redaction failure still refuses the request
- [ ] Credentials are injected only toward their bound hosts
- [ ] No real secret in code, fixtures or this description

## Notes for reviewers
