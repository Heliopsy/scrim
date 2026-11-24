# Workstation

One developer, one machine, agents started by hand. `scrim run` starts scrim when it is not
running, wraps the agent and stops scrim again when the agent exits, so nothing runs in the
background unless you want it to.

Use this when you run Claude Code, Codex or another agent on your own laptop or desktop. If several
people or unattended jobs share the machine, see [vm.md](vm.md) instead.

Files: [`deploy/examples/workstation/`](../../deploy/examples/workstation/).

## Prerequisites

- Linux or macOS, amd64 or arm64.
- `curl`, `tar`, `sha256sum` (or `shasum` on macOS) and
  [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) 2.4 or later.
- `~/.local/bin` on your `PATH`.

## Install

[`install.sh`](../../deploy/examples/workstation/install.sh) downloads a release, checks the
signature over `checksums.txt` against the release workflow's identity, checks the archive against
the signed checksums and installs the binary into `~/.local/bin`. Nothing is installed when either
check fails.

```sh
curl -fsSLO https://raw.githubusercontent.com/Heliopsy/scrim/main/deploy/examples/workstation/install.sh
less install.sh                      # read it before you run it
VERSION=1.0.0 bash install.sh
```

The last lines it prints:

```text
Verified OK
scrim_1.0.0_linux_amd64.tar.gz: OK
scrim 1.0.0 (commit: <commit>, built: <date>, linux/amd64)
```

`PREFIX=/usr/local` installs into `/usr/local/bin` instead (run it with `sudo`). The steps are the
same as in [install.md](../install.md), which also covers the provenance check.

## Configure

Put [`config.yaml`](../../deploy/examples/workstation/config.yaml) at `~/.config/scrim/config.yaml`:

```yaml
apiVersion: scrim.dev/v1
kind: Config

stores:
  local:
    kind: env
    prefix: SCRIM_SECRET_
    redact:
      - local://SCRIM_SECRET_GITHUB_TOKEN

catalog:
  entries:
    github:
      ref: local://SCRIM_SECRET_GITHUB_TOKEN
      hosts: [api.github.com]
      placeholder: SCRIM_GITHUB_TOKEN
      inject: ["header:Authorization"]
```

The env store reads secrets from scrim's own environment, so the example works without a secret
store. The target names the variable; from 0.2.0 on, `local://SCRIM_SECRET_*` also works and
redacts every variable with that prefix (0.1.0 read it as one variable named `SCRIM_SECRET_*`).
A redact target that loads nothing stops `scrim proxy` at start-up with an error naming it, so
export the variable before starting scrim. For daily use, point a store at OpenBao, Infisical or
Vaultwarden ([stores](../stores/README.md)) and redact a folder of it.

```sh
mkdir -p ~/.config/scrim
cp config.yaml ~/.config/scrim/config.yaml
scrim config validate
```

## Trust scrim's CA

The forward proxy terminates TLS toward the hosts a credential is bound to. `scrim run` gives each
agent a CA bundle of its own, so this step is only needed for tools you start outside `scrim run`
with `HTTPS_PROXY` pointing at scrim, and for browsers:

```sh
scrim ca install --user --dry-run   # what it would change
scrim ca install --user
```

It writes `~/.local/share/scrim/scrim-ca.pem` and `ca-bundle.pem`, adds the CA to the login
keychain on macOS and to `~/.pki/nssdb` on Linux when that exists, and prints the variables to
export. [ca.md](../ca.md) has the details and rotation.

## Run an agent

```sh
export SCRIM_SECRET_GITHUB_TOKEN=...   # from your password manager
scrim run -- claude
scrim run -- codex
```

`scrim run` sets the base URLs, the forward proxy, the CA bundle, the MCP registration and a
session token for that one process. `scrim run --print-env -- claude` shows all of it without
starting anything; [run.md](../run.md) has the full list per agent.

To keep scrim running between agents, run it as a user service ([vm.md](vm.md#user-service)). Then
`scrim run` uses that daemon and leaves it running when the agent exits.

## Verify

Start the daemon by hand in one terminal, with capture mode on:

```sh
SCRIM_SECRET_GITHUB_TOKEN=example-a71c90e2fb3d44c8 scrim proxy --capture=$HOME/scrim-capture
```

Write `--capture=DIR` with the `=`: the flag's value is optional, so `--capture DIR` reads `DIR`
as a second argument and fails.

In another terminal:

```sh
scrim status      # Interception lists base-url and forward-proxy; Data plane shows "1 values"
scrim doctor      # every check passes, exit status 0
```

`scrim status` reports `DEGRADED` while break-glass, capture mode or direct-egress blocking are
inactive. On a workstation direct egress is never blocked, so that line stays.

Send a canary request: the fake value in a message, an invalid API key, straight to the base URL.
Anthropic refuses the key with 401, and the capture shows what it received:

```sh
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9790/anthropic/v1/messages \
  -H 'x-api-key: not-a-real-key' -H 'anthropic-version: 2023-06-01' \
  -H 'content-type: application/json' \
  -d '{"model":"claude-sonnet-4-5","max_tokens":16,"messages":[{"role":"user","content":"my token is example-a71c90e2fb3d44c8"}]}'
grep -c example-a71c90e2fb3d44c8 ~/scrim-capture/*.request.body    # 0
grep -o '⟦scrim:github:[0-9a-f]*⟧' ~/scrim-capture/*.request.body  # the placeholder
```

Then check that an agent's tool traffic is identified and the credential is injected. With a real
token in `SCRIM_SECRET_GITHUB_TOKEN` this prints `200`; the command only ever holds the placeholder:

```sh
scrim run -- sh -c 'curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer $SCRIM_GITHUB_TOKEN" https://api.github.com/user'
```

The same request through the forward proxy without `scrim run` comes from an unknown caller and is
refused with `403 policy_denied`, which shows the proxy is in the path and the built-in injection
rule only serves identified agents. Stop the daemon with Ctrl-C and delete `~/scrim-capture` when
you are done.

## Upgrade and roll back

```sh
VERSION=1.0.1 bash install.sh        # keeps the old binary as ~/.local/bin/scrim.prev
mv ~/.local/bin/scrim.prev ~/.local/bin/scrim   # roll back
```

State in `~/.local/state/scrim` (SQLite, placeholder key, CA) carries over. A newer scrim migrates
the SQLite schema forward and an older one refuses a newer schema, so after a rollback across a
schema change move `~/.local/state/scrim/state.db` aside. Restart the user service if you run one.

## Uninstall

```sh
scrim ca uninstall --user            # reverts exactly what ca install recorded
rm ~/.local/bin/scrim ~/.local/bin/scrim.prev
rm -r ~/.config/scrim ~/.local/state/scrim ~/.local/share/scrim
```
