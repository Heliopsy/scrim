# scrim-policy

Data-plane policy for scrim: the decision-table evaluator (design D7), the per-tool restore policy
and context-aware escaping of restored values (design D5). It decides what reaches agents' tools,
so it fails closed: anything it does not understand keeps the placeholder or goes to the control
plane.

Spec: `openspec/changes/scrim-v1/specs/policy-approvals` ("Data-plane decisions equal control-plane
decisions", "Rules only restrict restore", "Restore request attributes") and `specs/redaction`
("Resolution follows tool policy" through "Share and reveal").

The crate holds no secret values. The restore engine keeps metadata and a few bits per value
(`ValueTraits`: which character classes it contains); values pass through a `ValueSource` for the
length of one call and are never logged, printed or stored.

## Public API

```rust
// Decision table (Snapshot.policy, table_format 1).
Table::from_proto(&pb::Policy) -> Result<Table, TableError>
Table::evaluate(&Request) -> Decision            // { outcome, ask, by }
Table::restricts(&Request) -> Option<DecidedBy>  // deny/ask rule matches or could match
Table::rule_name(DecidedBy) / Table::reason(DecidedBy)
Request { op, agent, secret, provider, dest, tool, unknown: FieldSet }
Request::{from_proto, to_proto}                  // PolicyRequest, for AskRequest

// Restore policy (Snapshot.restore + Snapshot.policy + Snapshot.values metadata).
RestoreEngine::from_snapshot(&pb::Snapshot) -> Result<RestoreEngine, RestoreError>
RestoreEngine::keep_all()                        // before the first snapshot
RestoreEngine::decide(&Caller, At, reference, ValueClass) -> Verdict
RestoreEngine::needs_arguments(tool) -> bool     // buffer shell and edit tool calls
RestoreEngine::restore_tool_input(&Caller, tool, arguments, &dyn ValueSource) -> Restored
RestoreEngine::restore_text(&Caller, text, &dyn ValueSource) -> Restored
RestoreEngine::reveal(text, &dyn ValueSource) -> Restored   // data-plane side of `scrim reveal`
RestoreEngine::block_policy(&Caller, At) -> BlockPolicy     // scrim_redact::RestorePolicy
RedactValues { resolver: &scrim_redact::Resolver, index: &ValueIndex }  // a ValueSource
LlmRestorePolicy::new(Arc<RestoreEngine>, Caller)           // scrim_llm::RestorePolicy (feature `llm`)
impl scrim_llm::RestorePolicy for RestoreEngine             // unknown caller (feature `llm`)

// Escaping.
escape::shell::{analyze_script, analyze_argv}   // placeholder -> Site (layers) or Refusal
escape::code::analyze                            // python -c, node -e, sqlite3 programs
escape::escape(&Site, value) -> Result<String, Refusal>
escape::ValueTraits::{of, raw_is_safe}
```

Wiring notes for the data plane binary:

- Build one `RestoreEngine` per applied snapshot (`from_snapshot`) and swap it with the snapshot.
  A snapshot whose `policy` or `restore` fails validation should be rejected like any other.
- scrim-llm: use `LlmRestorePolicy::new(engine, caller)` as `Snapshot.policy` (the data plane
  binds one per request through its request gate). It returns `ToolMode::Buffered` for shell and
  edit tools. `SecretRef` must carry the value's `ValueEntry.ref` (or its slug, when unique).
  Streamed placeholders are decided with `decide`, which keeps a value that would need shell
  escaping (`KeepReason::NeedsEscaping`) because scrim-llm inserts raw values there; complete
  tool calls come through scrim-llm's `RestorePolicy::restore_tool_input`, which this crate
  implements with `restore_tool_input`, so those values are restored escaped.
- scrim-redact: build entries with `EntryId(i)` for the `i`-th `ValueEntry` so `RedactValues` and
  `BlockPolicy` map entries to references by position (they fall back to a unique slug).
- `Caller` carries the agent identity and provider when the listener knows them. With
  `Caller::default()` the agent is unknown to the decision table, and any deny or ask rule that
  depends on it (`!agent.known` is common) keeps every placeholder.

## Decision table

`Table::evaluate` is a port of `policy.Snapshot.Evaluate` (`internal/policy/snapshot_eval.go`):
three-valued clause and rule logic, errors that only tighten (a failing deny or ask rule matches, a
failing allow rule does not), residual clauses, deny then ask then allow, the first rule at a
level that is not a no-match decides, side-effect allows and an ask default go to the control
plane, and break-glass denies without evaluating. `Table::from_proto` rejects what
`policy.SnapshotFromProto` rejects (format, operator, field, key, arity, glob), plus the legacy
`rules`, `engine` and `compiled` forms, which this data plane does not implement.

`Request::unknown` marks fields the caller cannot fill in; a condition on one is unknown, so a rule
that depends on it never decides locally. Ordinary requests leave it empty and behave exactly as in
Go.

Globs (`*` within a segment, `**` across, `?`, `\x`) match on Unicode scalar values with a linear
dynamic programme, as in Go.

## Restore policy

For each placeholder in a response, in order:

1. Credentials are kept, whatever the caller or settings say. Everything is kept under break-glass.
2. Displayed text (assistant text, refusals) follows `display_mode`. A snapshot without restore
   settings restores nothing.
3. Tool calls follow the tool's role, from an alias (`Snapshot.restore.tools`) or the built-in
   table (`BUILTIN_TOOLS`: Claude Code, Codex CLI, Gemini CLI):

   | Role | Restored |
   | --- | --- |
   | read, search | display values |
   | shell | display values where the escaping analysis keeps them data |
   | edit | values the call shows are already in the file: the replaced text, or context and removed lines of the same file in an `apply_patch` patch |
   | write, network, none (unknown tools) | nothing |

   Shell and edit decisions need the complete arguments; while streamed, the placeholder stays.
4. The decision table can only take a restore away: a deny or ask rule that matches, could match
   or errors on `op == "restore"` (with `tool.name`, `secret.ref`, `secret.name`, `secret.store`,
   `secret.class`, and the caller's identity) keeps the placeholder. Allow rules and the default are
   not consulted. `secret.labels` is always unknown here.

`reveal` resolves display values, and credentials only when `reveal_credential_refs` names them;
display mode and tool roles do not apply, break-glass does.

## Escaping

`escape::shell` lexes the command (quotes, backslashes, `$var`, `$(...)`, `<(...)`, pipelines,
lists, redirections, heredocs, here-strings, comments; `sh -c` scripts recursively; `python3 -c`,
`node -e` and `sqlite3` programs through `escape::code`) and gives each placeholder a stack of
layers, innermost first, or a refusal. A value is restored only when:

- every command on the line is a data-only command (`DATA_COMMANDS`: `cat`, `echo`, `grep`, `ls`,
  `head`, `wc`, ... that take no code and run nothing whatever their arguments; `sort`, `rg`,
  `find`, `xargs`, `sed`, `awk`, `jq`, `printf`, `test`, `git`, `env` and network clients are
  deliberately absent; `extra_shell_data_commands` adds more), a nested shell whose script passes
  the same test, or an interpreter whose program the code analyser vouches for (Python and
  JavaScript: an identifier allowlist, no f-strings, template literals, regex literals or computed
  property access; SQLite: no dot-commands, `ATTACH`, `PRAGMA`, `VACUUM`, `load_extension`,
  `edit`, `writefile`, ...);
- no command writes to a code file (`escape::files::is_code_path`: shell rc files, scripts, git
  and ssh configuration, CI workflows, cron, systemd units, `/dev/tcp`) or to a target with an
  expansion;
- the placeholder is an argument, here-string, heredoc body or interpreter string literal; not a
  command name, assignment, redirection target, comment, or inside backticks, `$((...))`, `${...}`
  beyond a plain name, `$'...'`, `case`, `for`, `[[` or a function definition;
- it does not follow a backslash or `$`, and the value does not start a word with `-`.

Layers and their encodings (each returns the value unchanged when nothing needs escaping):

| Layer | Encoding |
| --- | --- |
| unquoted shell word | single-quoted when not all `[A-Za-z0-9_@%+=:,./-]` |
| single quotes | `'` becomes `'\''` |
| double quotes | close, single-quote, reopen when it holds a backslash, `$`, a backtick, `"` or `!` |
| quoted heredoc body | as is; refused with a line break, or where it would complete the delimiter line |
| start of a `<<-` line | refused when it starts with a tab (the shell strips it) |
| unquoted heredoc body | backslash, `$` and backtick escaped with a backslash; refused with a line break, or where it would complete the delimiter line |
| argv element | as is; refused with NUL |
| Python, JavaScript string | backslash escapes for `\`, the quote, line breaks and control characters (JS also U+2028/9) |
| SQL string | `'` doubled |
| JSON string (heredoc into `.json`) | RFC 8259 escapes |
| YAML (heredoc into `.yaml`) | whole plain scalar quoted when needed, or double-quoted scalar escapes |

NUL bytes and non-UTF-8 values are never restored into a shell.

### Limitations

- Command names are taken at their standard meaning. Aliases and functions defined in the agent's
  own shell start-up files (which some agents snapshot into their shell tool) are not visible.
- `is_code_path` is a heuristic; the allowlist is the primary guard.
- The analyser assumes a non-interactive POSIX shell or bash; double-quote escaping avoids `!` so
  history expansion does not matter.
- YAML and JSON layers apply only to heredoc bodies redirected to `.json`, `.yaml` or `.yml`.

## Tests

- `tests/conformance.rs`: every vector of `internal/policy/testdata/conformance.json` (145), plus
  break-glass and the Go rejection cases.
- `tests/differential.rs`: property tests of the evaluator against an independent port of the Go
  reference on random tables and requests, and of the glob matcher against Go's regex oracle.
- `tests/escape_props.rs`: `ValueTraits::raw_is_safe` holds exactly when `escape` is the identity;
  the analysers are total; escaped shell words never leave a quote open.
- `tests/escape_exec.rs`: the escaping fuzzer. Hostile values (command substitution, quotes,
  heredoc terminators, Python, JavaScript and SQLite payloads, control characters) are restored
  into generated commands and each restored command runs under `unshare -rn` (no network) in a
  fresh temporary directory with an empty environment and a timeout. A marker file created by any
  payload fails the test, as does a data-only command printing anything but the value, or a
  streaming decision that would insert a value raw where escaping changes it. Without unprivileged
  user namespaces the commands run without network isolation (set
  `SCRIM_ESCAPE_FUZZ_REQUIRE_SANDBOX=1` to fail instead). `SCRIM_ESCAPE_FUZZ_CASES` sets the
  number of cases (default 1500).

```sh
cd dataplane
cargo test -p scrim-policy
SCRIM_ESCAPE_FUZZ_CASES=50000 cargo test -p scrim-policy --release --test escape_exec
```
