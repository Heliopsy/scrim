# scrim run

`scrim run` starts an agent with its traffic going through scrim. It is the wrapper interception
mode: everything it sets applies to the agent's process and its children only, and nothing in your
shell, your agent's configuration or the system changes.

```sh test
scrim run -- claude
scrim run -- codex exec "fix the failing test"
scrim run -- opencode run "fix the failing test"
scrim run --print-env -- claude      # show what would be set, start nothing
```

Spec: `openspec/specs/interception` ("Wrapper mode") and
`specs/agent-identity` ("Session tokens from scrim run").

## What happens

1. **scrim is found or started.** `scrim run` reuses the scrim already running for your user or the
   system service, or starts one in its own process, and waits until its data plane is ready to
   redact. See [Which scrim serves the run](#which-scrim-serves-the-run).
2. **A session is minted.** `scrim run` asks the local agent API for a session token
   (`POST /v1/sessions`). The token is bound to your Unix user and to this `scrim run` process and
   its descendants; see [identity.md](identity.md).
3. **A session directory is created** under `$XDG_RUNTIME_DIR/scrim/run/` (mode 0700;
   `$TMPDIR/scrim-<uid>/run/` without `$XDG_RUNTIME_DIR`, see
   [running.md](running.md#runtime-directory)) for the CA files, the MCP configuration and the
   [ssh-agent](ssh-agent.md) socket.
4. **Project files are scanned.** Secret values in the working directory's `.env*`, `*.tfvars`,
   application config and similar files are registered with scrim for this session and applied to the
   data plane before the agent starts, so they are redacted from its first request. See
   [Secrets in project files](#secrets-in-project-files).
5. **The agent starts as a child** with the environment and arguments below.
6. **When the agent exits**, `scrim run` ends the session (`DELETE /v1/sessions/self`), removes the
   session directory and exits with the agent's status. If `scrim run` itself is killed, scrim
   revokes the session once it sees the process is gone.

Everything after the agent's name belongs to the agent, so `--` is only needed when the agent's
name could be read as a flag. `scrim run` flags go before it:

| Flag | Meaning |
| --- | --- |
| `--agent claude\|codex\|opencode\|generic` | Pick the preset instead of deriving it from the command name. |
| `--print-env` | Print what would be set and exit. Mints no session and writes no files. `-o json` for JSON. |
| `--name NAME` | Session name shown in `scrim api whoami` and audit (default: the command name). |
| `--ttl 2h` | Session token lifetime (default `session.ttl`). The session ends earlier when the agent exits. |
| `--run-mcp=false` | Do not register `scrim mcp` with the agent (setting `run.mcp`). |
| `--run-placeholder-env=false` | Do not export declared placeholders (setting `run.placeholder-env`). |
| `--run-scan-project=false` | Do not scan the working directory for secret values (setting `run.scan-project`). |
| `--run-scan-interval 30s` | How often project files are rescanned while the agent runs; `0` scans once (setting `run.scan-interval`, default 10s). |
| `--run-ssh-agent=false` | Do not serve scrim's ssh-agent to the session (setting `run.ssh-agent`). See [ssh-agent.md](ssh-agent.md). |
| `--run-profiles auto` | Tool profiles to apply: names, `auto` or `none` (setting `run.profiles`). See [Tool profiles](#tool-profiles). |
| `--run-fs-view auto\|namespace\|home\|off` | Session filesystem view (setting `run.fs-view`). See [Filesystem view](#filesystem-view). |
| `--run-fs-view-allow-readable-own-files` | Weakening: start the agent even when the view cannot hide some of [scrim's own files](#scrims-own-files). |
| `--run-network open\|proxy-only` | The agent's network (setting `run.network`). See [Agent network](#agent-network). |
| `--run-allow-unredacted-start` | Weakening: start the agent even when scrim cannot serve it. See [Failing closed](#failing-closed). |

## Environment contract

### Every agent

| Variable | Value | Why |
| --- | --- | --- |
| `ANTHROPIC_BASE_URL` | `http://127.0.0.1:<port>/anthropic` | Anthropic SDKs and Claude Code send Messages requests to scrim's LLM proxy. |
| `OPENAI_BASE_URL` | `http://127.0.0.1:<port>/openai/v1` | OpenAI SDKs send requests to scrim's LLM proxy. Codex ignores it (see below). |
| `GOOGLE_GEMINI_BASE_URL` | `http://127.0.0.1:<port>/gemini` | Gemini CLI and the Google Gen AI SDKs send Gemini API requests to scrim's LLM proxy. Their own `x-goog-api-key` (or `key=`) is forwarded untouched. |
| `HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY`, `http_proxy` | `http://<session id>:<token>@127.0.0.1:<port>`, scrim's forward proxy | Tool traffic (curl, git, SDKs) goes through scrim for credential injection and response redaction. The user info identifies the session: clients send it as `Proxy-Authorization`, which ends at the proxy, so policy and grants apply to this agent. `--print-env` shows `<session-token>` in its place. |
| `GIT_HTTP_PROXY_AUTHMETHOD` | `basic` | git otherwise sends proxy credentials only after a `407` challenge, which scrim's forward proxy never sends, so its tunnels would carry no session and injection toward bound hosts would be refused. Set only when the proxy URL carries the session. |
| `NO_PROXY`, `no_proxy` | `localhost,127.0.0.1,::1` plus chained local upstreams | Loopback, including the LLM base URL, is reached directly. |
| `NODE_EXTRA_CA_CERTS` | `<session>/scrim-ca.pem` | Node.js adds scrim's CA to its bundled roots. |
| `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `AWS_CA_BUNDLE`, `PIP_CERT`, `NPM_CONFIG_CAFILE`, `CARGO_HTTP_CAINFO`, `DENO_CERT` | `<session>/ca-bundle.pem` | Runtimes that replace their trust store get the system roots plus scrim's CA. |
| `SCRIM_API_SOCKET` | the local agent API socket | Read by `scrim mcp` and `scrim secret`. |
| `SCRIM_SESSION_TOKEN` | the session token | Presented by `scrim mcp` and `scrim secret`. Never printed by `scrim run`. |
| `SCRIM_SESSION_ID` | the session's public ID | For logs and scripts. |
| declared placeholders | for example `SCRIM_GITHUB_TOKEN=SCRIM_GITHUB_TOKEN` | See [Declared placeholders](#declared-placeholders). |
| `SSH_AUTH_SOCK` | `<session>/ssh-agent.sock` | ssh and git over SSH sign through scrim's ssh-agent, with keys from scrim's stores, a policy decision per signature and an audit entry each ([ssh-agent.md](ssh-agent.md)). An inherited agent is replaced and `SSH_AGENT_PID` removed. Not set with `run.ssh-agent: false`, nor on Windows, where your own `SSH_AUTH_SOCK` is left as it is. |

`ALL_PROXY` and `all_proxy` are removed, so nothing skips the forward proxy through them.

When scrim runs without its forward proxy, the proxy and CA variables are not set; your own
`HTTPS_PROXY` stays in place for tool traffic, and `NO_PROXY` keeps your entries with loopback
added so the LLM base URL is never sent to that proxy.

The session bundle starts from the file your `SSL_CERT_FILE` names, if set, otherwise from the
system trust store (`/etc/ssl/certs/ca-certificates.crt` and the other usual locations). The
contents of an inherited `NODE_EXTRA_CA_CERTS` file are kept in `scrim-ca.pem`. A file holding a
private key is never copied.

When a variable scrim sets was already set to something else in your environment (a base URL
pointing at a local proxy, `NO_PROXY=*`), `scrim run` replaces it for the session and says so
before the agent starts. A corporate `HTTPS_PROXY` is replaced for the agent too, and becomes
scrim's upstream proxy ([Corporate proxies](#corporate-proxies)).

### Claude Code (`claude`)

| Addition | Why |
| --- | --- |
| `--mcp-config=<session>/mcp.json` inserted after `claude` | Registers `scrim mcp` for this session. The `=` form keeps the option from taking the prompt as a second value. Claude Code starts MCP servers with its own environment, so the session token reaches them. |
| `ANTHROPIC_CUSTOM_HEADERS` gets `x-scrim-session: <token>` | Claude Code adds these headers to every API request, so the base-URL listener can identify the session. The listener strips the header before the provider. Headers you set there yourself are kept (an inherited `x-scrim-session` line is dropped); `--print-env` shows them as `<inherited headers>`. |

Claude Code's cloud provider modes (`CLAUDE_CODE_USE_BEDROCK`, `CLAUDE_CODE_USE_MANTLE`,
`CLAUDE_CODE_USE_ANTHROPIC_AWS`, `CLAUDE_CODE_USE_FOUNDRY`, `CLAUDE_CODE_USE_VERTEX`) are kept: when
one is on and scrim has a [provider route](providers/README.md#claude-code-under-scrim-run) of the
matching kind, `scrim run` points Claude Code's base URL variable for the mode at that route and
turns Claude Code's own authentication off, since scrim signs the redacted request. Without such a
route, or with `CLAUDE_CODE_USE_ANTHROPIC_GOOGLE_CLOUD`, which scrim does not serve, it refuses to
start the agent, because Claude Code would reach the provider directly.

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
works. Codex first tries the Responses API over WebSocket. scrim serves the WebSocket and redacts
every message like a request body; if the provider refuses the handshake, Codex falls back to HTTPS.
Both go to scrim's loopback listener, never to the provider. Codex ignores `OPENAI_BASE_URL`, and a
project's `.codex/config.toml` cannot set `openai_base_url` or `model_provider`, so a repository
cannot point it elsewhere. Codex's HTTP clients (rustls) trust `CODEX_CA_CERTIFICATE`, then
`SSL_CERT_FILE`; both name the session bundle. When `~/.codex/config.toml` (or `$CODEX_HOME`) selects
a `model_provider` other than `openai` at its top level, or `-c model_provider=...` does, `scrim run`
warns before the agent starts: that provider's `base_url` is used, not scrim's. Tested with Codex CLI
0.171 over WebSocket, against a fake model.

### OpenCode (`opencode`)

| Addition | Why |
| --- | --- |
| `OPENCODE_CONFIG_CONTENT` | OpenCode's inline configuration, which it merges over its global, `OPENCODE_CONFIG` and project files. It sets `provider.anthropic`, `provider.openai` and `provider.google` `options.baseURL` to scrim's routes (`<llm>/anthropic/v1`, `<llm>/openai/v1`, `<llm>/gemini/v1beta`), `enabled_providers` to those three, and `options.headers` with `x-scrim-session: {env:SCRIM_SESSION_TOKEN}` on each. OpenCode substitutes `{env:...}` when it loads the configuration, so the token is never written into it. |
| `mcp.scrim` in the same configuration | Registers `scrim mcp` as a local MCP server, with `SCRIM_API_SOCKET`, `SCRIM_SESSION_TOKEN` and `SCRIM_SESSION_ID` passed through `environment` by `{env:...}` reference. Not set with `run.mcp: false`. |

OpenCode builds its providers on the AI SDK, whose base URLs end in the API version
(`ANTHROPIC_BASE_URL` without `/v1` would miss scrim's Messages route), so the preset sets them in
OpenCode's configuration instead of relying on the common variables. Its model requests are
identified by the session header; the base-URL listener strips it before the provider.

`enabled_providers` keeps OpenCode to the providers scrim serves: any other (OpenCode Zen, GitHub
Copilot, OpenRouter, Bedrock, a custom OpenAI-compatible endpoint) would send its requests to its own
endpoint, which the LLM proxy never sees. A list you set yourself is narrowed, never widened: when
your global configuration (`~/.config/opencode/config.json`, `opencode.json` or `opencode.jsonc`),
the file `OPENCODE_CONFIG` names or your `OPENCODE_CONFIG_CONTENT` sets `enabled_providers` (the last
of them that does, as OpenCode ranks them), the session enables only the providers in both that list
and scrim's three, and `scrim run` refuses to start OpenCode when none is left. A configuration file
that cannot be parsed is refused too, since its list could not be kept. `disabled_providers` is left
as you set it. `scrim run` refuses a `-m`/`--model` of another provider before the agent starts.
Your own `OPENCODE_CONFIG_CONTENT` is kept with scrim's settings merged over it (objects key by
key, other values replaced); it must be plain JSON, and `--print-env` shows it as
`<inherited OPENCODE_CONFIG_CONTENT>` because it may hold your keys. Keys come from
`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_GENERATIVE_AI_API_KEY` or `opencode auth login` as
usual, and are passed through to the provider.

OpenCode is a Bun binary. Its own HTTPS (its `webfetch` tool, for one) goes through `HTTPS_PROXY`
with the session in the proxy URL and trusts scrim's CA through `NODE_EXTRA_CA_CERTS`. Nobody can
answer a permission prompt of `opencode run`, so allow the tools it may use unattended with
`permission` in your configuration or `OPENCODE_PERMISSION`. Tested with OpenCode 1.19.6 on the
Anthropic, OpenAI (Responses API) and Gemini routes, against a fake model.

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

```sh test env
SCRIM_GITHUB_TOKEN=SCRIM_GITHUB_TOKEN
```

So `curl -H "Authorization: Bearer $SCRIM_GITHUB_TOKEN" https://api.github.com/user` inside the
session sends the placeholder, and the tool proxy swaps in the real token on the way to
`api.github.com` only. The agent and the model never see the value.

The catalog is resolved for the session's agent, `catalog.profile` and `catalog.environment`.
Placeholders whose name is one of scrim's own settings or variables (`SCRIM_LOG_LEVEL`,
`SCRIM_API_SOCKET`, `SCRIM_STORES_...`) are not exported, with a warning. Turn the export off with
`run.placeholder-env: false`.

## Tool profiles

CLIs such as `gh`, `git`, `kubectl`, `aws` and `terraform` get their configuration generated with
placeholders under `<session-dir>/profiles` and are pointed at it with their own override variables
(`GH_TOKEN`, `KUBECONFIG`, `AWS_SHARED_CREDENTIALS_FILE`, ...). Inherited variables that could hold a
real credential (`GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, ...) are removed. Which profiles apply is
`run.profiles` (`auto`: every profile a catalog entry names in its tools list). See
[cli-tools.md](cli-tools.md).

## Secrets in project files

Before the agent starts, `scrim run` walks the working directory (four levels deep, skipping `.git`,
`node_modules`, `vendor`, `.terraform`, build output and virtualenvs) for the files secrets are
usually written into: `.env` and `.env.*` (not `.env.example`, `.sample`, `.template`), `*.env`,
`*.tfvars` and `*.tfvars.json`, `application*.properties|yml`, `appsettings*.json`, compose files,
`secrets.*`, `credentials.*`, `.npmrc`, `.pypirc`, `.netrc` and YAML, JSON, TOML or INI files under a
`config/` or `conf/` directory. In them it takes the value of every key whose name says it holds a
secret (`TOKEN`, `KEY`, `SECRET`, `PASSWORD`, `DSN`, `AUTH`, ...) and the password of every URL with
credentials, skipping empty values, references (`{{scrim:...}}`, `SCRIM_*`, `${...}`), booleans,
numbers, paths and sample words.

The values are sent to scrim over the local agent API (`PUT /v1/sessions/self/values`, the body is
the values and nothing else) and added to the redaction set as `project://<file>#<key>`, redacted and
never injected. The call returns only after the data plane applied them, so the agent's first request
is already redacted. `scrim run` rescans every `run.scan-interval` and registers the new set when a
value or file changed. The values leave the redaction set when the session ends.

`scrim project scan` lists what the scan finds (file, line, key; never the value), `scrim doctor`
lists each finding with the offer to move it, and `scrim project move` writes each value into a store
through the agent API (policy and audit apply) and replaces it in the file with a `{{scrim:<ref>}}`
reference, asking before each one. Nothing is written or rewritten without a yes (`--yes` answers yes
to all). Add a catalog entry for the reference so its placeholder is injected where the file's value
was sent.

If the values cannot be registered, `scrim run` refuses to start the agent (exit 125);
`run.scan-project=false` skips the scan. A working directory that is the home directory or `/` is not
scanned.

## Filesystem view

Profiles point tools at their generated files through override variables. Some tools have none
(doctl's `config.yaml`), and some find the home directory through the password database instead of
`HOME`. For those, `scrim run` gives the agent a view of the home directory in which the credential
paths show the generated placeholder file or are hidden. Which paths: every `paths` entry of the
applied tool profiles (`~/.aws/credentials`, `~/.kube/config`, `~/.docker/config.json`, `~/.netrc`,
`~/.config/gh/hosts.yml`, ...; see [cli-tools.md](cli-tools.md)) and the patterns in
`run.fs-view-hide` (default `.ssh/id_*` without `.ssh/id_*.pub`: ssh private keys, not their public
halves). Only paths that exist are covered, and a session with none starts without any of this.
The view also hides [scrim's own files](#scrims-own-files).

Spec: `specs/credential-injection` ("Session filesystem view for fixed paths", "Filesystem view
integrity", "Filesystem view selection", "Filesystem view fallback without namespaces", "Session home
mirror", "Session filesystem view hides scrim's own files"). Code: `internal/fsview`.

| `run.fs-view` | What the agent gets |
| --- | --- |
| `auto` (default) | The namespace view where the host allows unprivileged user namespaces, the home mirror elsewhere. |
| `namespace` | The namespace view, or no agent: `scrim run` exits 125 on a host without user namespaces. |
| `home` | The home mirror. |
| `off` | The home directory as it is. |

Windows has no filesystem view: `auto` gives `off` and says so, and `namespace` or `home` refuses to
start the agent (Windows tools find the profile directory through `USERPROFILE`, not `HOME`).
Credential files in your profile stay readable from the session.

### Namespace view (Linux)

`scrim run` starts its own executable again as a small helper in a new user and mount namespace that
maps only your uid and gid, so the agent keeps your identity and file ownership. The helper makes the
mount tree private (nothing propagates to the host), then for each covered path that exists, in
`$HOME` and in the password-database home:

- bind-mounts the profile's generated file from the session directory over it, or
- bind-mounts an empty file or directory with mode 0000, read-only, over it, so `cat` fails with
  "Permission denied".

It then drops every capability, sets `no_new_privs` and executes the agent in place (same process ID,
so the session stays bound to it). The agent cannot unmount the view, and the kernel locks the mounts
together against a user namespace the agent creates itself. Nothing on disk changes; the mounts go
away with the agent's process tree, and the real files are untouched.

If a mount fails, or the helper does not run, the agent is not started (exit 125): it never starts
with half a view.

Not covered by the namespace view:

- setuid programs (`sudo`, `newuidmap` and so rootless `podman`) gain no privileges inside the user
  namespace. Use `run.fs-view: home` for sessions that need them.
- Services outside the session (`systemd --user`, D-Bus, ssh to localhost, a container engine's
  daemon) run outside the view and can read the real files on the agent's behalf.
- A covered path created after the session started is not covered.

The session directory, with the generated profile files, the credential helper links in
`<session-dir>/bin` and their target (the scrim executable), stays reachable in both views: it lives
under `$XDG_RUNTIME_DIR`, outside the covered paths. `just e2e-profiles` (TestCredentialHelpers,
TestProjectFileValues) runs git, skopeo, kubectl and aws through scrim's helpers, and the project
scan, inside the namespace view.

### Home mirror (fallback)

On macOS, and on Linux hosts that forbid unprivileged user namespaces (Ubuntu 24.04's default
AppArmor policy, `kernel.apparmor_restrict_unprivileged_userns=1`; `user.max_user_namespaces=0`;
many containers), `HOME` points at `<session-dir>/fsview/home`: every entry of your home directory is
a symbolic link to the real one, except along the way to a covered path, where the directory is
recreated with links to its other entries, the covered path links to the generated file, and a hidden
path is left out. `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME` and `XDG_CACHE_HOME` move with
`HOME` when they pointed into it. `scrim run` prints the fallback, its reason and its gaps before the
agent starts.

Not covered by the home mirror:

- Tools that find the home directory through the password database instead of `HOME` (ssh, scp,
  sftp, git over ssh) read the real files.
- The real files stay readable at their absolute paths: the mirror changes where `HOME` leads, it
  does not hide anything from a process that opens `/home/you/.aws/credentials`.
- New files at the top of the home directory or inside a mirrored credential directory stay in the
  session home and are removed with it.
- On macOS, credentials kept in the Keychain (git-credential-osxkeychain,
  docker-credential-osxkeychain, gh's keyring) are not files and are not covered.

### scrim's own files

When scrim runs as the same user as the agent (a user-level install, `scrim install --user`, or the
daemon `scrim run` starts itself), that user can read scrim's own secrets: the file behind a
Vaultwarden `unlock: file:...`, a `client-secret:`, notifier tokens, signing keys. `scrim run` asks
the daemon which files it reads secrets or key material from (`GET /v1/own-paths` on the agent API,
answered only to a local user that may mint sessions, never to a session) and hides each one the
agent's user can read:

- the target of every `file:` reference in scrim's configuration, settings and store fields alike;
- scrim's config files;
- the state directory (`$XDG_STATE_HOME/scrim`: CA keys, placeholder key, issuer keys, the SQLite
  database), and those directories or files wherever their settings move them (`tool-proxy.ca.dir`,
  `edge.ca.dir`, `redaction.placeholder-key-dir`, `identity.issuer.key-dir`, `state.sqlite.path`
  with its `-wal`, `-shm` and `-journal` files, `proxy.capture.dir`);
- token and credential files (`identity.kubernetes.token-file`, `nats.credentials-file`,
  `edge-forwarder.client-key-file`, `edge-forwarder.token-file`);
- store files: the file and sops stores' `root`, a Kubernetes store's `auth.kubeconfig`, and
  `auth.*token-file` options.

A path counts only while the configuration makes scrim read it. A setting whose feature is off is not
one of scrim's own files, even at a non-empty default: `identity.kubernetes.token-file` only with
`identity.kubernetes.enabled`, the `edge-forwarder.*` files only with `edge-forwarder.central` set
(the token file only without a client certificate), `state.sqlite.path` only with the sqlite backend,
`identity.issuer.key-dir` only with `identity.issuer.url` set and no `identity.issuer.signing-keys`,
and `redaction.placeholder-key-dir` only without `redaction.placeholder-keys`. So a pod's own service
account token is not hidden, and does not make `scrim run` refuse, unless scrim uses it.

A file the agent's user cannot read, such as a system service's files under its own user, needs no
cover and is skipped. The namespace view mounts the empty 0000 file or directory over each one,
inside or outside the home. The home mirror can only leave out paths under `$HOME`; it does not hide
them from a process that opens the absolute path (see its gaps below).

`scrim run` refuses to start the agent (exit 125), naming the files, when the agent's user can read
one of scrim's own files and the view cannot hide it: outside `$HOME` with the home mirror, or a
directory that holds the session directory, the agent API socket or the scrim executable. The
weakening setting `run.fs-view-allow-readable-own-files` starts the agent anyway and prints each
file it leaves readable. The session directory, the CA bundle and the sockets stay reachable in every
case.

When a config file is hidden, `SCRIM_CONFIG` in the session points at an empty config file in the
session directory, so `scrim mcp`, `scrim secret` and the credential helpers start; they reach the
daemon through `SCRIM_API_SOCKET`. A daemon older than `scrim run` does not report its files: `scrim
run` warns and starts the agent without hiding them.

The view keeps a session away from these files; any other process of the same user can still read
them. The fix is to run scrim as its own user: `sudo scrim install --system --agent-user $USER`
([service.md](service.md)), whose files are mode 0600 under the `scrim` user, or to give secrets as
systemd credentials (`cred:`). `scrim status` lists the readable files under "Filesystem view (scrim
run)" and `scrim doctor` warns about them (`own-files`).

### Checking the view

`scrim run --print-env` lists the view and every covered path:

```text
filesystem view: namespace (user and mount namespace)
  /home/you/.aws/credentials  shows <session-dir>/profiles/aws/credentials  (aws)
  /home/you/.config/doctl/config.yaml  hidden  (doctl)
  /home/you/.ssh/id_ed25519  hidden  (run.fs-view-hide)
  /home/you/.config/scrim/vw-master  hidden  (scrim's own: stores.vw.unlock)
```

`scrim status` shows the view sessions get on this host under "Filesystem view (scrim run)", with
the fallback reason and its gaps, and `scrim doctor` checks it (`run-fs-view`): a warning for the
fallback, `home` or `off`, a failure when `run.fs-view` is `namespace` and the host has none. To get
the namespace view on Ubuntu, either `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`
or give the scrim binary an AppArmor profile with `userns,`.

## Agent network

By default (`run.network: open`) the agent shares your network. The base URLs and proxy variables
steer every client that honours them through scrim, but a command that ignores them, clears its
environment or dials a provider's address itself goes straight out. `run.network: proxy-only`
(flag `--run-network proxy-only`, variable `SCRIM_RUN_NETWORK`) closes that on Linux, without root:
the agent and every process it starts run in a network namespace of their own in which scrim's
listeners are the only reachable addresses.

Spec: `specs/interception` ("Proxy-only agent network"). Code: `internal/run/network.go`,
`internal/fsview/helper_linux.go`.

| `run.network` | What the agent gets |
| --- | --- |
| `open` (default) | Your network. Clients that honour the base URLs and `HTTPS_PROXY` go through scrim; others go direct. |
| `proxy-only` | A network namespace with loopback only. The LLM base URL and the forward proxy answer at their usual addresses; nothing else is reachable. |

How it works: the [namespace helper](#namespace-view-linux) is started in a new network namespace
as well as the user and mount namespaces. It brings loopback up, binds a listening socket at the
address of scrim's LLM base URL and at the address of the forward proxy (the same `127.0.0.1:port`
as outside, so the environment `scrim run` sets does not change), and hands those sockets to
`scrim run` over a Unix socket before it executes the agent. `scrim run` accepts on them from
outside the namespace and splices each connection to scrim's real listener. The agent never holds
the sockets, and no process in the namespace can reach the host's network: there is no route, and
the resolver in `/etc/resolv.conf` is unreachable from it, so names do not resolve either. The
forward proxy resolves names itself, from the hostname in each `CONNECT`, so `curl`, git over HTTPS,
package managers and SDKs that honour `HTTPS_PROXY` work as before and scrim's tool proxy sees
every request they make. This is the approach rootless podman uses, without pasta or
slirp4netns: the namespace needs no virtual interface or user-space TCP stack, because the only
destinations are scrim's own listeners. Nothing new has to be installed.

The local agent API, `scrim mcp` and scrim's ssh-agent use Unix sockets in the filesystem, which a
network namespace does not separate, so they keep working. The same is true of other programs'
Unix sockets, and some of those would act outside the namespace for the agent. `scrim run` covers
these for the agent:

- sockets that run commands: the D-Bus session bus and the systemd user manager
  (`$XDG_RUNTIME_DIR/bus`, `$XDG_RUNTIME_DIR/systemd/private`, also under `/run/user/<uid>`),
  rootless podman and docker (`$XDG_RUNTIME_DIR/podman`, `$XDG_RUNTIME_DIR/docker.sock`), the
  docker daemon (`/run/docker.sock`) and tmux (`/tmp/tmux-<uid>`);
- name resolvers, since a looked-up name carries data out in its labels: the system bus
  (`/run/dbus/system_bus_socket`, through which systemd-resolved and NetworkManager answer),
  systemd-resolved's directory (`/run/systemd/resolve`, its varlink sockets and the stub
  `resolv.conf`), nscd (`/run/nscd`) and avahi (`/run/avahi-daemon`, mDNS). A lookup through the C
  library then fails at once instead of reaching a resolver. systemd's user database
  (`/run/systemd/userdb`) is left alone, so user lookups keep working;
- display servers, through which a process could type into a terminal outside: X11
  (`/tmp/.X11-unix`) and every `$XDG_RUNTIME_DIR/wayland-*` present when the session starts.
  `DISPLAY` and `WAYLAND_DISPLAY` are removed from the agent's environment.

A socket is covered by `/dev/null`, a directory by an empty read-only tmpfs, in the agent's mount
namespace only, after the [filesystem view](#filesystem-view) is mounted; a path inside a
directory the view hides (for example one of [scrim's own files](#scrims-own-files)) is unreachable
already and left as it is. Abstract Unix sockets belong to the network namespace and are
unreachable already.

What fails under `proxy-only`, by design:

- A command that ignores `HTTPS_PROXY` (`curl --noproxy '*'`, `env -i curl ...`, a client that
  hard-codes an address): its connection fails with "connection refused" or "network unreachable",
  or its name does not resolve.
- ssh, and so git over ssh: there is no route to port 22 and no `ProxyCommand` is set up. Use HTTPS
  remotes; their credentials come from [tool profiles](#tool-profiles) and go through the forward
  proxy.
- scrim's database proxies and chained local upstreams such as caveman are not reachable from the
  session. A chained upstream is scrim's upstream, not the agent's.
- Anything that needs a display or a bus: GUI programs, the clipboard, desktop notifications, the
  Secret Service keyring, NetworkManager's CLI (`nmcli`), `resolvectl`, and tmux, podman or docker
  commands, inside the session.
- Rootless podman inside the session, for the reasons in [Namespace view](#namespace-view-linux).

`scrim run` refuses to start the agent (status 125) in `proxy-only` mode when:

- the host cannot create the namespace (no unprivileged user namespaces, see
  [Checking the view](#checking-the-view) for the Ubuntu setting), or the helper does not run;
- a listener cannot be bound inside the namespace or a socket cannot be covered;
- scrim's LLM base URL or forward proxy listens on an address that is not loopback;
- the platform is not Linux. macOS has no unprivileged network namespaces: `proxy-only` is not
  supported there, and `open` with [managed agent settings](interception.md#managed-agent-settings-enforcement-add-on)
  is the closest thing;
- scrim is unavailable, even with `run.allow-unredacted-start`: that setting would start the agent
  with no way out, or an open one, and `proxy-only` promises neither.

Not covered by `proxy-only`:

- Unix sockets of other programs running outside the session that accept commands or connections
  (screen, an IDE or editor server, an ssh `ControlMaster` socket, a container engine at a path
  not listed above). Hide such paths with [`run.fs-view-hide`](#filesystem-view) or run the agent
  as its own user.
- What the forward proxy itself allows: a tunnel to a host scrim does not intercept still leaves
  through scrim, and tool policy decides what it may carry.

`scrim run --print-env` lists the network:

```text
network: proxy-only (network namespace with loopback only; 2 of scrim's listeners reachable)
  reachable  127.0.0.1:9790  (LLM base URL)
  reachable  127.0.0.1:9791  (forward proxy)
  masked     /run/user/1000/bus
  ...
```

`scrim status` shows it under "Agent network (scrim run)", and `scrim doctor` checks it
(`run-network`): a failure when `run.network` is `proxy-only` and the host cannot create the
namespace, and a passing note when it is `open` that says whether `proxy-only` would work here. The
default is `open` for compatibility; it may change to `proxy-only` in a later release.

## Failing closed

`scrim run` does not start the agent, and exits with status 125, when:

- scrim is not running and cannot be started;
- its data plane is not ready (no snapshot, a listener not bound, a store still loading);
- it has no LLM base URL listener or no local agent API;
- the session cannot be minted;
- the secret values found in project files cannot be registered for redaction;
- `scrim run` is already inside a session (`SCRIM_SESSION_TOKEN` is set);
- the preset refuses the environment (Claude Code in a cloud provider mode scrim has no route for,
  see [providers](providers/README.md#claude-code-under-scrim-run));
- the command is `caveman` (see below) or cannot be found;
- the [filesystem view](#filesystem-view) cannot be set up, or `run.fs-view` is `namespace` and the
  host has no unprivileged user namespaces;
- the agent's user can read one of [scrim's own files](#scrims-own-files) that the view cannot hide,
  unless `run.fs-view-allow-readable-own-files` is set;
- `run.network` is `proxy-only` and the [agent network](#agent-network) cannot be set up.

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
Claude Code treat one Ctrl-C as two. `scrim run` itself never exits before the agent. On Windows no
signal is passed on.

## Chained proxies

A context-compression proxy such as caveman belongs behind scrim: agent, then scrim, then caveman,
then the provider. Configure it as the chained upstream of scrim's LLM route (llm-proxy spec,
"Upstream chaining"); caveman then receives redacted requests only. Chained upstreams on loopback
are added to the agent's `NO_PROXY`, so the forward proxy never loops through them.

Running `scrim run -- caveman claude` is refused: caveman would set the agent's base URL to itself
and see every request before scrim redacts it. If your shell exports `ANTHROPIC_BASE_URL` pointing
at caveman, `scrim run` replaces it for the session and warns.

## Corporate proxies

An inherited `HTTPS_PROXY` (or `HTTP_PROXY`, lowercase forms included) is not passed to the agent:
the agent's proxy variables point at scrim's forward proxy, as always. It becomes scrim's own
upstream proxy instead. A scrim that `scrim run` starts takes it, credentials and `NO_PROXY`
included, from the same environment, so provider and tool traffic leaves through your proxy after
redaction ([configuration.md](configuration.md#upstream-proxy)). The agent never sees the proxy's
credentials.

A scrim that already runs (a user or system service) was started with its own environment and
serves every session the same way. When its upstream differs from your `HTTPS_PROXY`, or it has
none, `scrim run` says so before the agent starts, showing the proxy without credentials. Set
`network.upstream-proxy.url` in that scrim's configuration, or the proxy variables in its service
environment.

## Checking a session

Inside the agent (or a shell started with `scrim run -- bash`):

```sh test session
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
  GOOGLE_GEMINI_BASE_URL=http://127.0.0.1:9790/gemini  # Gemini API through scrim's LLM proxy
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
- `internal/run/fsview_test.go` and `fsview_linux_test.go` plant decoys at `~/.aws/credentials`,
  `~/.ssh/id_ed25519` and doctl's config in a temporary home and run an agent that reads them under
  `scrim run`. With the namespace view it reads the placeholder file, `cat` of the key fails, the
  public key and other files are unchanged, unmounting fails (also from a namespace of its own), and
  the session still identifies it. `TestFSViewPasswdHome` starts the test again in a namespace with a
  temporary directory mounted over the password-database home, so a tool that ignores `HOME` is
  checked without reading the real home. The home mirror, the refusals (namespace required, helper
  that does not run) and `run.fs-view: off` as a control are covered too. The namespace tests skip
  without user namespaces unless `SCRIM_TEST_REQUIRE_USERNS=1`, which the `e2e-profiles` CI job sets.
  `TestStatusRunFSViewOnThisHost` runs on macOS in CI and checks that status lists the fallback.
- `internal/run/network_linux_test.go` (`TestRunNetworkProxyOnly`) runs the small agent under
  `run.network: proxy-only`: its provider requests through the base URL and its tool call through
  the forward proxy work and reach the provider redacted, while dialling the tool server's address
  itself and fetching with the proxy switched off, by address or by name, fail. The same agent with
  `open` reaches them, so the failures come from the namespace. `TestRunNetworkRefusals` covers the
  refusals, and `TestRunNetworkMasksResolversAndDisplays` dials a Wayland socket planted in the
  runtime directory and the host's system bus, resolved, nscd, avahi and X11 sockets where they
  exist (they answer with `open` and fail with `proxy-only`), checks that a `getent hosts` lookup
  fails at once and that `DISPLAY` and `WAYLAND_DISPLAY` are removed. `internal/fsview`
  (`TestNetworkNamespace`) covers the helper: the handed-over listener
  answers inside the namespace, another loopback listener of the host and the masked sockets do
  not. `SCRIM_TEST_RUN_NETWORK=proxy-only` runs `TestClaudeCodeThroughScrimRun` and
  `TestCodexThroughScrimRun` in the namespace. These skip without user namespaces unless
  `SCRIM_TEST_REQUIRE_USERNS=1`, which CI sets.
- These tests stand a verbatim redactor in for scrim's data plane: they test the wrapper, not the
  redactor. `TestRunPrintEnvWithRealDaemon` (in `internal/cli`, with `SCRIM_TEST_DATAPLANE`) runs
  `scrim run --print-env` against a daemon started in process with the real data plane, and
  `TestEndToEndRealDataPlane` (in `internal/daemon`) checks what the provider receives through it.
- `just e2e-tools`, `just e2e-chain` and `just e2e-session` (`test/e2e/`) run the real `scrim`
  binary and data plane, started as `scrim proxy` with temporary directories, memory state and a
  file store of generated values. They run inside `test/e2e/sandbox.sh`: unprivileged user,
  network and mount namespaces with loopback only (no request can reach a real provider or any
  other host) and their own `/etc/hosts`, so the test hosts `api.scrim.test`, `git.scrim.test`
  and `other.scrim.test` resolve to loopback addresses and are bound by name, on port 443.
  - `e2e-tools`: curl (a placeholder in a header and in a JSON body), `git clone` and `git push`
    with placeholder credentials in `~/.git-credentials` against `git http-backend` behind TLS and
    Basic authentication, Node.js `fetch` with `NODE_USE_ENV_PROXY=1` and Python `requests`, each
    under `scrim run` against TLS test APIs with a private CA (`dataplane.upstream-ca-file`). The
    APIs receive the real values, echoed values come back as placeholders, an unbound host gets
    `403 unbound_destination`, and after `scrim ca rotate` clients trusting only the previous CA,
    only the new CA, or a new session's bundle all keep working. CI runs it on GitHub-hosted
    Ubuntu with `SCRIM_E2E_REQUIRE_TOOLS=1`, so a missing client fails instead of skipping.
  - `e2e-chain`: scrim with caveman as its chained upstream (`proxy.chain.url`), caveman with its
    own HOME, data directory and port, pointed at the fake provider. caveman's stores hold
    placeholders only, placeholders survive its compression and are restored in the response, and
    every request reached the fake provider through caveman. Skipped without `caveman-proxy`
    (`SCRIM_E2E_CAVEMAN` names it).
  - `e2e-profiles` (see [cli-tools.md](cli-tools.md)) ends with the filesystem view: the real `aws`
    CLI, with `AWS_SHARED_CREDENTIALS_FILE` removed, reads the placeholder at `~/.aws/credentials`
    where a decoy sits, and `cat` of a decoy ssh key and doctl config fails.
  - `e2e-session`: Claude Code under `scrim run` with an empty `HOME` and a fake key reads a `.env`
    of seeded secrets, cats a config, runs `git diff` on a file with a key in it, calls a bound tool
    API through `HTTPS_PROXY` with `SCRIM_API_TOKEN`, and calls `secrets_list`. Every provider
    request and scrim's capture of it are checked with the leak suite's checker. Skipped without
    `claude`. `TestCodexSession` runs the same session with `codex exec` over the Responses API:
    the fake model calls whichever shell tool Codex offers (`exec_command`, `shell_command` or
    `shell`), then `secrets_list` in the `mcp__scrim` namespace tool. `SCRIM_E2E_CODEX` names the
    native `codex` binary (from the `@openai/codex` npm package, installed into a temporary
    directory), otherwise it is looked up on `PATH` and skipped when missing.
    `TestOpenCodeSession` runs it with `opencode run` on the anthropic provider: the same `bash`
    steps, `scrim_secrets_list` over MCP, and a `webfetch` of the tool API (OpenCode's own HTTPS
    through the forward proxy, trusting the session CA). A policy rule denies every provider request
    that does not come from the session, so the run only completes when OpenCode sends the session
    header. `TestOpenCodeSessionProviders` runs it on the openai (Responses API) and google
    (Gemini) providers too. `SCRIM_E2E_OPENCODE` names the native `opencode` binary (from the `opencode-ai` npm
    package). CI installs the three agents at pinned versions into the runner's temporary
    directory and runs it with `SCRIM_E2E_REQUIRE_TOOLS=1`, then runs the three agent sessions
    again with `SCRIM_E2E_RUN_NETWORK=proxy-only`, which sets `run.network: proxy-only` for every
    `scrim run` of the suite.
  - `e2e-tools` also runs `TestProxyOnlyNetwork`: real curl under `scrim run --run-network
    proxy-only` calls the tool API through `HTTPS_PROXY` (the API gets the real token, the session
    sees the placeholder) and the fake provider through the base URL (it gets the secret as a
    placeholder), while curl with `--noproxy '*'` by hostname, by the provider's address, and
    `env -i curl` all fail. The same script with `--run-network open` reaches both hosts directly. CI also runs
    the whole `TestTools` suite (curl, git over HTTPS, Node.js, Python) with
    `SCRIM_E2E_RUN_NETWORK=proxy-only`.

  Each needs unprivileged user namespaces; on Ubuntu 24.04 with AppArmor's restriction on, run
  `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` first.

## Which scrim serves the run

With neither `admin.url` nor `api.socket` set, `scrim run` looks for this user's daemon (its admin
socket, `$XDG_RUNTIME_DIR/scrim/admin.sock`), then for the system service's agent API at
`/run/scrim/api.sock` ([service.md](service.md#how-agents-find-the-service)). With either setting
given it skips the system service and asks only the daemon behind `admin.url` (by default this
user's admin socket). When one runs, the agent uses it and it keeps running after the
agent exits; a system service that does not answer or is not ready is an error. When none runs,
`scrim run` starts one in its own process for the session, waits until its data plane is ready, logs
it to `$XDG_STATE_HOME/scrim/run-daemon.log` and stops it when the agent exits. With the SQLite state
backend only one of them can hold the state file, so a second concurrent `scrim run` without a
`scrim proxy` reuses the first run's daemon while it lives.

## Limitations

- With `run.network: open` (the default) the wrapper relies on the agent honouring the variables
  and arguments it is given. It does not stop an agent that ignores them; `run.network: proxy-only`
  (Linux), the transparent, managed-settings and Kubernetes modes enforce. See
  [Agent network](#agent-network) for what `proxy-only` leaves open.
- Claude Code on Bedrock, Mantle, Claude Platform on AWS, Foundry and Vertex needs a
  [provider route](providers/README.md); Claude on Google Cloud operated by Anthropic is refused.
- Codex with a custom `model_provider` in its configuration talks to that provider's own base URL,
  which `scrim run` does not change; it warns when the top level of the configuration or a `-c`
  option selects one, not when a `--profile` does. Codex signed in with a ChatGPT account calls the Responses
  API on `chatgpt.com` through the forward proxy, which routes it to the LLM proxy
  (`proxy.upstream.chatgpt`); other ChatGPT backend paths, and everything on `ab.chatgpt.com`
  (`proxy.upstream.chatgpt-ab`), are forwarded with the whole body redacted as generic JSON.
- Codex tries the Responses API over WebSocket first. The LLM proxy serves it and redacts every
  message ([limitations](limitations.md#how-traffic-reaches-scrim)); when the provider refuses the
  handshake, its answer reaches Codex, which falls back to HTTPS requests.
- Bulk catalog entries (`prefix` with `template`) need a store listing and are not exported as
  placeholders by `scrim run` yet; entries from configuration and catalog files are.
- The session token is added to the redaction set when it is minted, so an agent that prints its
  environment does not send it to the model. Tokens of the `scrim_st_` shape minted by another scrim
  are not matched by a pattern rule yet.
- Codex's update checks and plugin downloads (`github.com`) go through the forward proxy as tool
  traffic.
- OpenCode's managed configuration (`/etc/opencode` on Linux, `/Library/Application Support/opencode`
  and managed preferences on macOS) ranks above `OPENCODE_CONFIG_CONTENT`. A provider base URL or
  `enabled_providers` set there is not changed by `scrim run`.
- OpenCode is limited to its `anthropic`, `openai` and `google` providers in the session.
  `enabled_providers` in a project's `opencode.json` or `.opencode/opencode.json` is not read, so the
  session's narrowed list replaces it. scrim's
  cloud provider routes (Bedrock, Vertex, Foundry) are not wired to OpenCode's providers for them.
- Runtimes with their own trust stores that read none of the variables above (Java, for one) do not
  trust scrim's CA inside the session.
