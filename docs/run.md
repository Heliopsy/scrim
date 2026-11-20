# scrim run

`scrim run` starts an agent with its traffic going through scrim. It is the wrapper interception
mode: everything it sets applies to the agent's process and its children only, and nothing in your
shell, your agent's configuration or the system changes.

```sh
scrim run -- claude
scrim run -- codex exec "fix the failing test"
scrim run --print-env -- claude      # show what would be set, start nothing
```

Spec: `openspec/changes/scrim-v1/specs/interception` ("Wrapper mode") and
`specs/agent-identity` ("Session tokens from scrim run").

## What happens

1. **scrim is found or started.** `scrim run` reuses the scrim already running for your user, or
   starts one, and waits until its data plane is ready to redact.
2. **A session is minted.** `scrim run` asks the local agent API for a session token
   (`POST /v1/sessions`). The token is bound to your Unix user and to this `scrim run` process and
   its descendants; see [identity.md](identity.md).
3. **A session directory is created** under `$XDG_RUNTIME_DIR/scrim/run/` (mode 0700) for the CA
   files and the MCP configuration.
4. **The agent starts as a child** with the environment and arguments below.
5. **When the agent exits**, `scrim run` ends the session (`DELETE /v1/sessions/self`), removes the
   session directory and exits with the agent's status. If `scrim run` itself is killed, scrim
   revokes the session once it sees the process is gone.

Everything after the agent's name belongs to the agent, so `--` is only needed when the agent's
name could be read as a flag. `scrim run` flags go before it:

| Flag | Meaning |
| --- | --- |
| `--agent claude\|codex\|generic` | Pick the preset instead of deriving it from the command name. |
| `--print-env` | Print what would be set and exit. Mints no session and writes no files. `-o json` for JSON. |
| `--name NAME` | Session name shown in `scrim api whoami` and audit (default: the command name). |
| `--ttl 2h` | Session token lifetime (default `session.ttl`). The session ends earlier when the agent exits. |
| `--run-mcp=false` | Do not register `scrim mcp` with the agent (setting `run.mcp`). |
| `--run-placeholder-env=false` | Do not export declared placeholders (setting `run.placeholder-env`). |
| `--run-allow-unredacted-start` | Weakening: start the agent even when scrim cannot serve it. See [Failing closed](#failing-closed). |

## Environment contract

### Every agent

| Variable | Value | Why |
| --- | --- | --- |
| `ANTHROPIC_BASE_URL` | `http://127.0.0.1:<port>/anthropic` | Anthropic SDKs and Claude Code send Messages requests to scrim's LLM proxy. |
| `OPENAI_BASE_URL` | `http://127.0.0.1:<port>/openai/v1` | OpenAI SDKs (and older Codex releases) send requests to scrim's LLM proxy. |
| `HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY`, `http_proxy` | `http://<session id>:<token>@127.0.0.1:<port>`, scrim's forward proxy | Tool traffic (curl, git, SDKs) goes through scrim for credential injection and response redaction. The user info identifies the session: clients send it as `Proxy-Authorization`, which ends at the proxy, so policy and grants apply to this agent. `--print-env` shows `<session-token>` in its place. |
| `NO_PROXY`, `no_proxy` | `localhost,127.0.0.1,::1` plus chained local upstreams | Loopback, including the LLM base URL, is reached directly. |
| `NODE_EXTRA_CA_CERTS` | `<session>/scrim-ca.pem` | Node.js adds scrim's CA to its bundled roots. |
| `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `AWS_CA_BUNDLE`, `PIP_CERT`, `NPM_CONFIG_CAFILE`, `CARGO_HTTP_CAINFO`, `DENO_CERT` | `<session>/ca-bundle.pem` | Runtimes that replace their trust store get the system roots plus scrim's CA. |
| `SCRIM_API_SOCKET` | the local agent API socket | Read by `scrim mcp` and `scrim secret`. |
| `SCRIM_SESSION_TOKEN` | the session token | Presented by `scrim mcp` and `scrim secret`. Never printed by `scrim run`. |
| `SCRIM_SESSION_ID` | the session's public ID | For logs and scripts. |
| declared placeholders | for example `SCRIM_GITHUB_TOKEN=SCRIM_GITHUB_TOKEN` | See [Declared placeholders](#declared-placeholders). |

`ALL_PROXY` and `all_proxy` are removed, so nothing skips the forward proxy through them.

When scrim runs without its forward proxy, the proxy and CA variables are not set; your own
`HTTPS_PROXY` stays in place for tool traffic, and `NO_PROXY` keeps your entries with loopback
added so the LLM base URL is never sent to that proxy.

The session bundle starts from the file your `SSL_CERT_FILE` names, if set, otherwise from the
system trust store (`/etc/ssl/certs/ca-certificates.crt` and the other usual locations). The
contents of an inherited `NODE_EXTRA_CA_CERTS` file are kept in `scrim-ca.pem`. A file holding a
private key is never copied.

When a variable scrim sets was already set to something else in your environment (a base URL
pointing at a local proxy, a corporate `HTTPS_PROXY`, `NO_PROXY=*`), `scrim run` replaces it for
the session and says so before the agent starts.

### Claude Code (`claude`)

| Addition | Why |
| --- | --- |
| `--mcp-config=<session>/mcp.json` inserted after `claude` | Registers `scrim mcp` for this session. The `=` form keeps the option from taking the prompt as a second value. Claude Code starts MCP servers with its own environment, so the session token reaches them. |
| `ANTHROPIC_CUSTOM_HEADERS` gets `x-scrim-session: <token>` | Claude Code adds these headers to every API request, so the base-URL listener can identify the session. The listener strips the header before the provider. Headers you set there yourself are kept (an inherited `x-scrim-session` line is dropped); `--print-env` shows them as `<inherited headers>`. |

`scrim run` refuses to start Claude Code when `CLAUDE_CODE_USE_BEDROCK`, `CLAUDE_CODE_USE_VERTEX` or
`CLAUDE_CODE_USE_FOUNDRY` is set: those route Claude Code to cloud endpoints scrim does not serve
yet, and the agent would reach them directly.

Claude Code honours `ANTHROPIC_BASE_URL`, `HTTPS_PROXY`, `NO_PROXY` and `NODE_EXTRA_CA_CERTS`, and
sends its own authentication (API key or subscription login) to the base URL; scrim passes it
through to the provider.

### Codex (`codex`)

| Addition | Why |
| --- | --- |
| `-c openai_base_url="<llm>/openai/v1"` after `codex` | Current Codex reads the OpenAI base URL from its configuration, not the environment. `-c` sets it for this run only; `~/.codex/config.toml` is untouched. |
| `-c mcp_servers.scrim.command=...`, `.args=["mcp"]`, `.env_vars=[...]` | Registers `scrim mcp`. Codex starts MCP servers with a reduced environment; `env_vars` passes `SCRIM_API_SOCKET`, `SCRIM_SESSION_TOKEN` and `SCRIM_SESSION_ID` through by name, so the token never appears on a command line. |
| `CODEX_CA_CERTIFICATE` | Codex's own CA override, set to the session bundle. |

Codex's base-URL requests are not identified: its built-in `openai` provider takes no extra
headers and the id is reserved, and a provider defined by `scrim run` would change where a ChatGPT
sign-in sends its requests. They reach scrim as an unknown caller (rules on `agent` see
`agent.known == false`). Codex's tool traffic, and with a ChatGPT sign-in its model traffic too,
goes through the forward proxy and carries the session. With an API key you can identify the base
URL requests yourself with a provider of your own:

```toml
model_provider = "scrim"
[model_providers.scrim]
name = "scrim"
base_url = "http://127.0.0.1:<port>/openai/v1"
env_key = "OPENAI_API_KEY"
env_http_headers = { "x-scrim-session" = "SCRIM_SESSION_TOKEN" }
```

Codex options given at the top level apply to every subcommand, so `scrim run -- codex exec ...`
works. Codex first tries the Responses API over WebSocket; scrim serves HTTP only, so Codex retries
and falls back to HTTPS after a few seconds. Both attempts go to scrim's loopback listener, never to
the provider. Tested with Codex CLI 0.171.

### Other agents (`generic`)

Any other command gets the common environment only. Agents built on the Anthropic or OpenAI SDKs
pick up the base URLs; anything that honours the proxy variables sends its tool traffic through
scrim. Proxy traffic carries the session; requests to the base URL are identified only when
the agent sends `x-scrim-session: $SCRIM_SESSION_TOKEN` with them (most SDKs take default
headers, for example `default_headers` in the Anthropic and OpenAI Python SDKs). Without it they
reach scrim as an unknown caller.

## Declared placeholders

Each declared catalog placeholder that resolves for the session (see [catalog.md](catalog.md)) is
exported as a variable of the same name holding the placeholder itself:

```sh
SCRIM_GITHUB_TOKEN=SCRIM_GITHUB_TOKEN
```

So `curl -H "Authorization: Bearer $SCRIM_GITHUB_TOKEN" https://api.github.com/user` inside the
session sends the placeholder, and the tool proxy swaps in the real token on the way to
`api.github.com` only. The agent and the model never see the value.

The catalog is resolved for the session's agent, `catalog.profile` and `catalog.environment`.
Placeholders whose name is one of scrim's own settings or variables (`SCRIM_LOG_LEVEL`,
`SCRIM_API_SOCKET`, `SCRIM_STORES_...`) are not exported, with a warning. Turn the export off with
`run.placeholder-env: false`.

## Failing closed

`scrim run` does not start the agent, and exits with status 125, when:

- scrim is not running and cannot be started;
- its data plane is not ready (no snapshot, a listener not bound, a store still loading);
- it has no LLM base URL listener or no local agent API;
- the session cannot be minted;
- `scrim run` is already inside a session (`SCRIM_SESSION_TOKEN` is set);
- the preset refuses the environment (Claude Code with Bedrock, Vertex or Foundry);
- the command is `caveman` (see below) or cannot be found.

Status 125 is the wrapper's own failure, as with `env` and `timeout`; any other status is the
agent's. An agent killed by a signal gives 128 plus the signal number.

If scrim stops while the agent runs, the agent's requests to the loopback base URL and proxy fail
with a connection error. They do not go direct.

The weakening setting `run.allow-unredacted-start` (flag `--run-allow-unredacted-start`, variable
`SCRIM_RUN_ALLOW_UNREDACTED_START`) starts the agent anyway, with your environment unchanged, after
a warning. Its traffic then reaches providers unredacted. Like every weakening setting it is listed
in `scrim status`.

## Signals

`SIGTERM`, `SIGHUP`, `SIGUSR1` and `SIGUSR2` sent to `scrim run` are passed to the agent.
`SIGINT` and `SIGQUIT` are passed on too, except when the agent runs in the foreground of your
terminal: the terminal already delivers Ctrl-C and Ctrl-\ to the agent, and a second copy would make
Claude Code treat one Ctrl-C as two. `scrim run` itself never exits before the agent.

## Chained proxies

A context-compression proxy such as caveman belongs behind scrim: agent, then scrim, then caveman,
then the provider. Configure it as the chained upstream of scrim's LLM route (llm-proxy spec,
"Upstream chaining"); caveman then receives redacted requests only. Chained upstreams on loopback
are added to the agent's `NO_PROXY`, so the forward proxy never loops through them.

Running `scrim run -- caveman claude` is refused: caveman would set the agent's base URL to itself
and see every request before scrim redacts it. If your shell exports `ANTHROPIC_BASE_URL` pointing
at caveman, `scrim run` replaces it for the session and warns.

## Checking a session

Inside the agent (or a shell started with `scrim run -- bash`):

```sh
scrim api whoami        # agent dev via session (uid 1000, pid ...), session ..., expires ...
```

`scrim run --print-env -- claude` shows every variable, argument and file without starting
anything:

```text
preset   claude
command  claude --mcp-config=<session-dir>/mcp.json

set
  ANTHROPIC_BASE_URL=http://127.0.0.1:9790/anthropic   # Anthropic API through scrim's LLM proxy
  OPENAI_BASE_URL=http://127.0.0.1:9790/openai/v1      # OpenAI API through scrim's LLM proxy
  SCRIM_API_SOCKET=/run/user/1000/scrim/api.sock       # local agent API for scrim mcp and scrim secret
  SCRIM_SESSION_TOKEN=<secret>                         # session token, bound to this process tree
  ...
```

## Tests

- `internal/run` unit tests cover the environment and arguments per preset, inherited variables
  being replaced or removed, placeholders, trust inputs and every refusal.
- An integration test runs a small agent under `scrim run` against the fake provider behind a
  stand-in redactor and a CONNECT proxy with its own CA: the provider sees placeholders only, the
  tool call is tunnelled and trusts the session CA, the agent is identified by its session, the exit
  code comes back and the session ends.
- `TestClaudeCodeThroughScrimRun` runs the real Claude Code CLI with an empty `HOME`, a fake key and
  the fake model: it reads a file of seeded secrets with its Bash tool and calls `secrets_list`
  over the MCP server `scrim run` registered. The test asserts zero leaks under the leak checker,
  that the call was made as the session and that the task completes. It is skipped when `claude`
  is not installed. `TestCodexThroughScrimRun` does the same with the Codex CLI, whose tools sit
  behind one code-mode `exec` tool, so it has its own small Responses model: the script runs
  `exec_command` on the file, then `tools.mcp__scrim__secrets_list`.
- These tests stand a verbatim redactor in for scrim's data plane: they test the wrapper, not the
  redactor. `TestRunPrintEnvWithRealDaemon` (in `internal/cli`, with `SCRIM_TEST_DATAPLANE`) runs
  `scrim run --print-env` against a daemon started in process with the real data plane, and
  `TestEndToEndRealDataPlane` (in `internal/daemon`) checks what the provider receives through it.

## Which scrim serves the run

`scrim run` asks the daemon behind `admin.url` first ([running.md](running.md)). When one runs,
the agent uses it and it keeps running after the agent exits. When none does, `scrim run` starts
one in its own process for the session, waits until its data plane is ready, logs it to
`$XDG_STATE_HOME/scrim/run-daemon.log` and stops it when the agent exits. With the SQLite state
backend only one of them can hold the state file, so a second concurrent `scrim run` without a
`scrim proxy` reuses the first run's daemon while it lives.

## Limitations

- The wrapper relies on the agent honouring the variables and arguments it is given. It does not
  stop an agent that ignores them; the transparent, managed-settings and Kubernetes modes enforce.
- Claude Code on Bedrock, Vertex or Foundry is refused until scrim serves those APIs (tasks.md 11.4).
- Codex with a custom `model_provider` in its configuration talks to that provider's own base URL,
  which `scrim run` does not change. Codex signed in with a ChatGPT account calls the Responses
  API on `chatgpt.com` through the forward proxy, which routes it to the LLM proxy
  (`proxy.upstream.chatgpt`); other ChatGPT backend paths are forwarded with the whole body redacted.
- `scrim run` replaces an inherited corporate `HTTPS_PROXY` instead of chaining scrim's forward
  proxy to it.
- Bulk catalog entries (`prefix` with `template`) need a store listing and are not exported as
  placeholders by `scrim run` yet; entries from configuration and catalog files are.
- The session token is added to the redaction set when it is minted, so an agent that prints its
  environment does not send it to the model. Tokens of the `scrim_st_` shape minted by another scrim
  are not matched by a pattern rule yet.
- Codex's update checks and plugin downloads (`github.com`) go through the forward proxy as tool
  traffic.
- Runtimes with their own trust stores that read none of the variables above (Java, for one) do not
  trust scrim's CA inside the session.
