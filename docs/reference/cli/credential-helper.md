# scrim credential-helper

<!-- Generated from the command tree by `just cli-docs`. Do not edit. -->

Global flags are listed in [the CLI reference](README.md#global-flags).

## scrim credential-helper

Credential helper for git, docker, AWS credential_process and kubectl exec; returns placeholders only.

```text
scrim credential-helper <git|docker|aws|kubectl> [args...]

Tool profiles configure tools to call this helper inside scrim run (docs/cli-tools.md): `git` speaks the git credential
helper protocol over the session's generated credential file, `docker` the docker credential helper protocol over
$DOCKER_CONFIG/config.json (also run as docker-credential-scrim), `aws` prints credential_process JSON and `kubectl` an
ExecCredential. It never reads a store or the home directory's credential files, and never stores a credential.

Examples:
  printf 'protocol=https\nhost=github.com\n\n' | scrim credential-helper git --file creds get
```
