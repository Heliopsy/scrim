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
