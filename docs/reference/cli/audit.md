# scrim audit

<!-- Generated from the command tree by `just cli-docs`. Do not edit. -->

Global flags are listed in [the CLI reference](README.md#global-flags).

## scrim audit

Query the audit log of decisions, approvals, grants, store writes and injections.

```text
scrim audit [command]
```

| Subcommand | Description |
| --- | --- |
| [`scrim audit log`](#scrim-audit-log) | List audit entries, newest first |
| [`scrim audit run`](#scrim-audit-run) | Run the leak suite against a proxy and report every seeded value that reached the fake provider |

## scrim audit log

List audit entries, newest first.

```text
scrim audit log [flags]

Examples:
  scrim audit log --agent claude-laptop --decision ask --since 1h
  scrim audit log --ref bao://kv/gh#token --outcome refused -o json
```

Flags:

```text
      --action string       only this action, for example decision or grant.revoked
      --agent string        only entries about this agent ID
      --before int          page cursor: entries with an ID below this
      --decision string     only this decision: allow, deny or ask
      --json[=true|false]   shorthand for --output json
      --limit int           maximum entries (default 50)
      --outcome string      only this outcome: ok, refused, failed or pending
  -o, --output string       output format: text or json (default "text")
      --ref string          only entries about this secret reference
      --since string        entries at or after this RFC 3339 time or duration ago (1h)
      --until string        entries before this RFC 3339 time or duration ago
```

## scrim audit run

Run the leak suite against a proxy and report every seeded value that reached the fake provider.

```text
scrim audit run [flags]

Run the bypass matrix and the scenario corpus through a proxy to a local fake
model provider, seeded with generated fake secrets, and report every leak,
every row whose outcome differs from its expectation, and the prompt-cache
hit rate. Exits non-zero when the gate fails.

The proxy must know the seeds: write them with --seeds-out and load that file
into the store the proxy uses, or let --proxy-cmd start the proxy with
SCRIM_LEAK_SEEDS, SCRIM_LEAK_UPSTREAM and SCRIM_LEAK_LISTEN set. Point the
proxy's provider routes at the fake provider (--upstream-listen).

--proxy builtin:passthrough and builtin:naive run the suite against stand-ins
that forward everything or redact only verbatim values; use them to check the
suite itself.
```

Flags:

```text
      --agent-bin string               agent CLI binary for --driver claude, codex or opencode (default: the
                                       driver's name on PATH)
      --api strings                    APIs to run: anthropic, openai-chat, openai-responses, gemini,
                                       openai-realtime, openai-responses-ws (default all; the scenarios run on the
                                       HTTP ones)
      --driver string                  agent for the scenarios: synthetic (every API), or a real agent CLI with an
                                       empty HOME: claude (Claude Code), codex (Codex CLI) or opencode (OpenCode)
                                       (default "synthetic")
      --header stringArray             header sent with every request, as 'Name: value' (the agent's provider
                                       auth; never a seed)
      --list-matrix[=true|false]       print the bypass matrix catalogue as Markdown and exit
      --max-partial int                fragment length that always counts, for long seeds (default 24)
      --min-partial int                shortest fragment of a seed that counts as a leak (default 8)
      --partial-fraction float         fraction of a seed's length a fragment must reach (default 0.5)
      --placeholder string             regular expression matching the proxy's placeholders (default the
                                       ⟦scrim:...⟧ format)
      --proxy string                   base URL of the proxy under test, or builtin:passthrough / builtin:naive
      --proxy-cmd string               command that starts the proxy (split on spaces); it must listen on --proxy
      --proxy-start-timeout duration   how long to wait for --proxy-cmd to listen (default 30s)
  -q, --quiet[=true|false]             do not print failures as they happen
      --report string                  write the JSON report to this file (mode 0600), or - for stdout
      --route strings                  route prefix of an API on the proxy, as api=prefix (for example
                                       anthropic=/anthropic); the WebSocket APIs default to the openai-responses prefix
      --rows strings                   run only matrix rows whose ID starts with one of these prefixes
      --seeds string                   read seeds (fake values) from this file instead of generating them
      --seeds-out string               write the seeds (fake values) to this file, mode 0600
      --suite strings                  suites to run: matrix, scenarios (default both)
      --upstream-listen string         address of the fake provider (default "127.0.0.1:0")
```
