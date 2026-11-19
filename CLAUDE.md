# scrim

Coding standards, security invariants and test conventions live in @AGENTS.md. Read that first.

## GitHub Actions

Always pin actions to a full commit SHA, never use a tag or branch reference alone.
Include the version as a comment for readability:

```yaml
uses: actions/checkout@<full-sha>  # v7.0.1
```
