# Agent tools

scrim gives agents tools to find, request, create and capture secrets, and to ask a person for one,
without the agent or the model ever seeing a value. The tools are offered twice, with the same
inputs, outputs, policy and audit:

- as an MCP server on standard input and output, `scrim mcp`
- as CLI commands, `scrim secret ...`

Both are thin clients of the control plane's [local agent API](#local-agent-api). Who the caller
is comes from the transport, never from a tool argument; see [identity.md](identity.md).

No tool takes a value as an argument, and no result, error or progress message contains one. A
result that refers to a secret carries its reference (`bao://kv/agents/github#token`) and, once the
redaction core is wired in, its placeholder. Values move around the model instead of through it:

| Tool | How the value moves |
| --- | --- |
| `secret_gen` | made inside scrim, written to the store, wiped |
| `secret_capture` | the command runs in the tool process; only the extracted value goes to scrim |
| `secret_ask_human` | a person types it into a local entry page, which writes it to the store |
| `scrim secret put --stdin` | read from standard input (echo off on a terminal) and sent to scrim |
| `secret_exec` | used, not moved: scrim runs an allowed command as another user with the value and returns redacted output |

## Running the agent API

The tools need the control plane's local API. Start it with:

```sh test daemon
scrim api serve
```

It listens on `$XDG_RUNTIME_DIR/scrim/api.sock` (setting `api.socket`) and serves the human entry
page on a free loopback port (setting `entry.listen`). Check what identity a process gets:

```sh test proxied
scrim api whoami
```

## MCP setup

`scrim mcp` reads `SCRIM_API_SOCKET` (or `--api-socket`) to find the API and
`SCRIM_SESSION_TOKEN` when it runs inside `scrim run`. Both are optional for a single user on one
machine: without a token the caller is identified by its Unix user alone.

### Claude Code

<!-- docs-test: skip: changes Claude Code's own configuration -->

```sh
claude mcp add scrim -- scrim mcp
```

or, shared with a project, in `.mcp.json`:

```json
{
  "mcpServers": {
    "scrim": { "command": "scrim", "args": ["mcp"] }
  }
}
```

Claude Code starts MCP servers with its own environment, so a session token set by `scrim run`
reaches `scrim mcp` without further configuration.

### Codex

In `~/.codex/config.toml`:

```toml
[mcp_servers.scrim]
command = "scrim"
args = ["mcp"]
```

Codex starts MCP servers with a reduced environment, so the session variables have to be passed
through by name with `env_vars = ["SCRIM_API_SOCKET", "SCRIM_SESSION_TOKEN", "SCRIM_SESSION_ID"]`
(not an `env` table, which would put the token in the file). `scrim run -- codex` does this for the
session with `-c` options; see [run.md](run.md).

### OpenCode

In `opencode.json`:

```json
{
  "mcp": {
    "scrim": {
      "type": "local",
      "command": ["scrim", "mcp"],
      "environment": {
        "SCRIM_API_SOCKET": "{env:SCRIM_API_SOCKET}",
        "SCRIM_SESSION_TOKEN": "{env:SCRIM_SESSION_TOKEN}",
        "SCRIM_SESSION_ID": "{env:SCRIM_SESSION_ID}"
      }
    }
  }
}
```

OpenCode substitutes `{env:...}` when it loads the configuration, so the token stays out of the
file. Its tools appear to the model as `scrim_secrets_list` and so on. `scrim run -- opencode` adds
the same server for the session through `OPENCODE_CONFIG_CONTENT`; see [run.md](run.md).

## Tools

Each section shows the MCP call, the CLI equivalent and a result. Errors have the same shape on
every path:

```json
{"error": {"code": "denied", "message": "denied by policy: no rule matches"}}
```

Codes: `invalid`, `unauthenticated`, `forbidden`, `denied`, `needs_approval`, `not_found`,
`conflict`, `unavailable`, `internal`. Messages never quote a value or a dependency's error text.

### secrets_list

Lists the secrets the caller may see under policy: reference, name, store, placeholder, bound hosts
and non-secret metadata. Filters: `store`, `prefix`, `binding`.

```json
{"name": "secrets_list", "arguments": {"prefix": "bao://kv/agents/"}}
```

```sh test session
scrim secret ls --prefix bao://kv/agents/
```

```json
{"secrets": [{"ref": "bao://kv/agents/github", "name": "agents/github", "store": "bao",
  "bindings": ["api.github.com"]}]}
```

A secret whose policy decision is deny for the caller is not listed.

### secret_request

Asks for time-limited use of a secret. Takes `ref`, `duration` (Go duration, such as `30m`) and
`reason`, which the approver sees. Returns `granted`, `denied`, or `pending` with an `approval_id`.
A duration above the maximum is capped and `capped` is true.

```json
{"name": "secret_request", "arguments": {"ref": "bao://kv/agents/hetzner", "duration": "30m",
  "reason": "deploy the web project"}}
```

```sh test session exit=4
scrim secret request bao://kv/agents/hetzner --duration 30m --reason "deploy the web project"
```

```json
{"status": "pending", "ref": "bao://kv/agents/hetzner", "approval_id": "3f2a9c0d...", "duration": "30m0s"}
```

A grant lets scrim use the secret for the agent (for example inject it toward its bound host). It
never shows the agent the value.

### secret_gen

Generates a value inside scrim and stores it. `format` is `chars` (default), `hex`, `base64`,
`base64url`, `uuid` or `passphrase`; `length` (8 to 4096, default 32) applies to the character
formats; `charset` (`alnum`, `alnum-symbols`, `alpha`, `lower`, `digits`) to `chars`; `words` and
`separator` to `passphrase` (EFF large wordlist). Every character is drawn uniformly from
`crypto/rand`. Without `overwrite`, an existing secret is not replaced.

```json
{"name": "secret_gen", "arguments": {"ref": "bao://kv/agents/app-db#password", "length": 32}}
```

```sh test session
scrim secret gen bao://kv/agents/app-db#password --length 32
```

```json
{"status": "stored", "ref": "bao://kv/agents/app-db#password", "store": "bao", "length": 32}
```

A reference without `#field` writes the field `value`.

### secret_capture

Runs a command without a shell, takes a value from its standard output and stores it. Extraction:
the whole output (trimmed), `json_path` (`.token`, `.data[0].key`, `["odd key"]`) or `pattern`
(first capture group of a regular expression). Policy is checked before the command runs, so a
token-creating command is not run only to have its output refused.

The command runs in the tool process, as the agent. Standard input is empty, standard error is
discarded, and the output is never returned: a failure reports the exit status only.

```json
{"name": "secret_capture", "arguments": {"ref": "bao://kv/agents/ci-token",
  "command": ["gh", "api", "-X", "POST", "/repos/acme/web/actions/runners/registration-token"],
  "json_path": ".token"}}
```

<!-- docs-test: skip: calls the GitHub API with gh, and some-command stands for any command printing JSON -->

```sh
scrim secret capture bao://kv/agents/ci-token --json-path .token -- \
  gh api -X POST /repos/acme/web/actions/runners/registration-token
# or, from a pipe:
some-command | scrim secret capture bao://kv/agents/ci-token --json-path .token --stdin
```

```json
{"status": "stored", "ref": "bao://kv/agents/ci-token#value", "store": "bao", "length": 29, "exit_code": 0}
```

Output is read up to 1 MiB; values are at most 64 KiB.

### secret_ask_human

Asks a person for a value the agent cannot get itself. scrim opens an ask, sends the person a
one-time link to the local entry page through the configured notifiers (by default, printed on the
terminal running `scrim api serve`), and waits up to `wait_seconds` (default 120 for MCP) for the
answer. The agent gets `stored`, `declined`, `timed_out`, or `pending` with an `id` to poll with
`approval_status`. It never gets the link.

```json
{"name": "secret_ask_human", "arguments": {"ref": "bao://kv/agents/hcloud",
  "prompt": "Hetzner Cloud API token for project web"}}
```

<!-- docs-test: skip: waits for a person to answer on the entry page -->

```sh
scrim secret ask bao://kv/agents/hcloud --prompt "Hetzner Cloud API token for project web"
```

```json
{"id": "ask_9c1e...", "status": "stored", "ref": "bao://kv/agents/hcloud#value"}
```

The person has `timeout_seconds` (default 900) to answer.

#### The entry page

- served on loopback only (`entry.listen`, default `127.0.0.1:0`), plain HTTP: the link carries a
  256-bit one-time token, and nothing leaves the machine
- the token is burned on the first submission or decline; a reused or expired link shows a page
  saying so and changes nothing
- requests for any `Host` other than the page's own address are refused, which stops DNS
  rebinding; submissions need a same-origin `Origin` (and `Sec-Fetch-Site` when sent)
- no scripts, no external assets; `Content-Security-Policy: default-src 'none'` with the inline
  stylesheet allowed by hash, `frame-ancestors 'none'`, `form-action 'self'`, `no-referrer`,
  `no-store`
- the page shows the asking agent, the target reference and the agent's prompt as untrusted text,
  so the person can tell an unexpected request from a real one
- policy is checked again when the value is submitted, so a deny-all engaged while the person types
  still applies
- single-line values only; use `scrim secret put --stdin` for certificates and other multi-line
  values

Asks live in the control plane's memory: a restart drops open asks, the agent sees `not_found`, and
nothing is stored.

### approval_status

Checks an approval from `secret_request` (`pending`, `approved`, `denied`, `expired`) or an ask
from `secret_ask_human` (`pending`, `stored`, `declined`, `timed_out`).

```json
{"name": "approval_status", "arguments": {"id": "3f2a9c0d..."}}
```

<!-- docs-test: skip: takes the id that secret request or secret ask returned -->

```sh
scrim secret status 3f2a9c0d...
```

```json
{"id": "3f2a9c0d...", "kind": "approval", "status": "approved", "ref": "bao://kv/agents/hetzner",
  "grant_id": "grt_77b0..."}
```

Another agent's (or another session's) approval or ask is reported as `not_found`.

### grants_list

Lists the caller's active grants with reference, scope, expiry and remaining uses.

```json
{"name": "grants_list", "arguments": {}}
```

```sh test session
scrim secret grants
```

```json
{"grants": [{"id": "grt_77b0...", "ref": "bao://kv/agents/hetzner", "expires_at": "2026-11-20T12:30:00Z"}]}
```

### database_list and database_query

`database_query` runs one read-only statement on a database configured under `databases`, with
placeholders bound as query parameters and the result redacted; `database_list` names the databases
and their local proxy endpoints. The CLI forms are `scrim database ls` and
`scrim database query DATABASE SQL [--param ...]`. Details, policy and limits:
[databases.md](databases.md).

```json
{"name": "database_query", "arguments": {"database": "app",
  "sql": "SELECT id FROM api_keys WHERE key = '⟦scrim:stripe:01a1b2c3d4e5f60718⟧'"}}
```

```json
{"database": "app", "columns": ["id"], "rows": [["42"]]}
```

### scrim secret put --stdin

The CLI-only way to store a value that is already in a pipe. It has no MCP tool, because an MCP
tool cannot take a value.

<!-- docs-test: skip: api.example.com stands for the service that issues the token -->

```sh
curl -s -X POST https://api.example.com/tokens | jq -r .token | scrim secret put bao://kv/agents/new-token --stdin
```

```text
stored bao://kv/agents/new-token#value in bao
```

On a terminal it prompts on standard error and reads with echo off. One trailing newline is
removed unless `--keep-newline` is given. Without `--stdin` the command refuses to run: values never
come from arguments, where shell history and process listings would keep them.

### secret_exec

Runs a command scrim allows with a secret the agent never holds: the agent puts the secret's
placeholder where the value belongs, scrim runs the command outside the agent's process as another
user, and the exit status and redacted output come back. The CLI form is `scrim exec`. Which
commands may run, what is always refused and the security argument are in
[exec-broker.md](exec-broker.md).

```json
{"name": "secret_exec", "arguments": {"command": ["psql", "-h", "db.internal", "-c", "select 1"],
  "env": {"PGPASSWORD": "SCRIM_DB_PASSWORD"}}}
```

<!-- docs-test: skip: needs a configured exec.commands entry and a database -->

```sh
scrim exec --env PGPASSWORD=SCRIM_DB_PASSWORD -- psql -h db.internal -c 'select 1'
```

```json
{"exit_code": 0, "stdout": " ?column? \n----------\n        1\n", "stderr": "", "refs": ["bao://kv/app/db#password"]}
```

## CLI output and exit codes

Every `scrim secret` command takes `-o json` for the same fields the MCP tool returns. Errors with
`-o json` are the error envelope on standard output.

| Exit | Meaning |
| --- | --- |
| 0 | success: granted, stored, approved |
| 1 | error |
| 3 | denied by policy, or the caller is not allowed |
| 4 | pending: an approval or ask is still open |
| 5 | declined, timed out or expired |

## Local agent API

HTTP/1.1 with JSON on the Unix socket, every route under `/v1`, every response carrying
`Scrim-Api-Version: v1`. A client of another version is refused rather than misread.

| Route | Tool |
| --- | --- |
| `GET /v1/version` | (open) API and server version |
| `GET /v1/whoami` | the caller's identity |
| `POST /v1/sessions` | mint a session token (`scrim run`) |
| `DELETE /v1/sessions/self` | end the caller's session |
| `DELETE /v1/sessions/{id}` | revoke a session of the same user |
| `PUT /v1/sessions/self/values` | add the values found in the session's project files to the redaction set (`scrim run`) |
| `GET /v1/own-paths` | the files and directories scrim reads secrets or key material from, paths only, for a local user with `sessions:mint` (`scrim run`'s [filesystem view](run.md#scrims-own-files)); sessions are refused |
| `GET /v1/secrets` | `secrets_list` |
| `POST /v1/secrets/request` | `secret_request` |
| `POST /v1/secrets/generate` | `secret_gen` |
| `POST /v1/secrets/check` | policy pre-check for a write |
| `PUT /v1/secrets/value` | store a value: raw body, reference in the query |
| `POST /v1/asks` | `secret_ask_human` |
| `GET /v1/status/{id}` | `approval_status` |
| `GET /v1/grants` | `grants_list` |
| `POST /v1/redact` | redact text for an agent hook: raw body in, `{"text", "replacements"}` out |
| `POST /v1/exec` | `secret_exec`, the [exec broker](exec-broker.md) |
| `GET /v1/databases` | `database_list` |
| `POST /v1/databases/query` | `database_query` |

The caller is identified from the socket's peer credentials and, when present, the
`Authorization: Bearer` session token. Unmapped users are refused. JSON bodies with unknown fields
are refused, so a `value` field cannot be smuggled into a tool call. `PUT /v1/secrets/value` is the
only route that stores a value and no route returns one; the session token from
`POST /v1/sessions` is the one credential the API returns, once, to the process that will start the
agent.

`PUT /v1/sessions/self/values` is what `scrim run` calls with the secret values it found in project
files ([run.md](run.md#secrets-in-project-files)). Only a session may call it. The body is the values
and their names (`<file>#<key>`), each a uvarint length and the bytes, up to 1000 values and 4 MiB;
the call replaces the session's set and returns once the data plane applied it. The values are
redacted, never injected or stored, and wiped when the session ends. Each call is audited as
`tool.session_values` with the count, never a value or name.

`POST /v1/redact` is what `scrim hooks run` calls (hooks-only interception,
[interception.md](interception.md#6-hooks-only)). Its body is raw bytes, up to 3 MiB, such as a tool
result; the data plane runs them through the same redactor and guard as a provider request and only
the redacted copy comes back. With no snapshot applied, a redactor error or a guard that withholds,
the call fails with `unavailable` and nothing of the text is returned. A call that replaced values
or failed is audited as `tool.redact` with the references found, never the text. Like sending text
through the LLM proxy, the route tells the caller whether a string is a known value; it is no
oracle beyond that.

## Audit

Every tool call writes an audit entry (action `tool.<name>`) with the agent, principal, user and
process ID, reference, store, decision, rule and outcome. Refused credentials and unmapped callers
are audited as action `tool.auth`. No entry holds a value. If the audit entry cannot be written, the
call fails.

## Current limits

- MCP over HTTP is not served yet; only stdio.
- Placeholders are empty in results until the redaction core provides them, and values stored
  through the tools join the redaction set through the store watch, not directly.
- The interim approval adapter creates grants for allowed requests and pending approvals for asks;
  deciding approvals (`scrim approve`, signed links) comes with the approvals service.
- Writing one field of a multi-field secret replaces the secret's fields in stores that do not
  merge fields.
