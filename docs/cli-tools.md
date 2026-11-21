# Command-line tools

Agents run `gh`, `git`, `kubectl`, `aws`, `terraform` and other CLIs that read credentials from
environment variables and fixed config files. Under `scrim run` those tools see placeholders only and
still work: a tool profile generates each tool's configuration with placeholders in the session
directory, points the tool at it with the tool's own override variables, and the tool proxy swaps the
placeholder for the real value on connections to the hosts the credential is bound to (design D5).
Nothing is written outside the session directory, and it is removed when the agent exits.

Spec: `openspec/changes/scrim-v1/specs/credential-injection` ("Placeholder credentials for
command-line tools", "Built-in tool profiles", "Tool profile selection", "Catalog entries take their
tool profile's binding", "Environment overrides before file tricks", "Tools that print their own
credentials", "Testing tool profiles", "Credential helpers").

## Quick start

Name the profile in the catalog entry's `tools` list:

```yaml
catalog:
  entries:
    github:
      ref: bao://kv/agents/github#token
      tools: [gh, git]
    prod-cluster:
      ref: bao://kv/agents/k8s-prod#token
      hosts: [k8s.example.com:6443]
      tools: [kubectl]
```

```sh
scrim profiles list            # which profiles apply, filled by which entries
scrim profiles show gh         # what the session gets (placeholders only)
scrim run -- claude            # gh, git and kubectl now work inside the agent
```

Inside the session `GH_TOKEN=SCRIM_GITHUB`, `KUBECONFIG` points at a generated kubeconfig whose
token is `SCRIM_PROD_CLUSTER`, and `gh auth token` or `kubectl config view --raw` print those
placeholders. `gh pr list` reaches `api.github.com` with the real token, injected by scrim.

An entry that names a profile and gives no `hosts` is bound to the hosts the profile declares for
that credential (`api.github.com`, `github.com`, `uploads.github.com` for gh), and one without a
`placeholder` gets `SCRIM_<NAME>`. `scrim catalog show` marks both as derived. Entries for cluster
APIs, registries and private package indexes name their hosts themselves.

## Built-in profiles

| Profile | Catalog `tools` | Default hosts | What the session gets |
| --- | --- | --- | --- |
| `gh` | `gh` | api.github.com, github.com, uploads.github.com | `GH_TOKEN`, an empty `GH_CONFIG_DIR`; `GITHUB_TOKEN` removed |
| `git` | `git` | github.com | scrim's git credential helper over a generated credential file, via `GIT_CONFIG_COUNT`; other credential helpers reset |
| `glab` | `glab` | gitlab.com | `GITLAB_TOKEN`, an empty `GLAB_CONFIG_DIR` |
| `kubectl` | `kubectl` | none (the entry's first host is the API server) | `KUBECONFIG`, one context per entry, trusting the session CA bundle |
| `helm` | `helm` | none | `HELM_REGISTRY_CONFIG` for OCI registries; cluster access from the kubectl profile |
| `docker` | `docker` | none | `DOCKER_CONFIG` with one auth entry per bound host and `credHelpers` naming `docker-credential-scrim` |
| `podman` | `podman` | none | `REGISTRY_AUTH_FILE` (podman, buildah, skopeo) |
| `npm` | `npm` | registry.npmjs.org | `NPM_CONFIG_USERCONFIG`, `NPM_TOKEN`, `NODE_AUTH_TOKEN` (npm and pnpm) |
| `aws` | `aws`, `aws.secret-access-key`, `aws.session-token` | *.amazonaws.com | `AWS_SHARED_CREDENTIALS_FILE`, `AWS_CONFIG_FILE`; inherited `AWS_*` credentials removed, IMDS off |
| `terraform` | `terraform` | app.terraform.io | `TF_CLI_CONFIG_FILE` with a credentials block per host (Terraform and OpenTofu); `TF_TOKEN_*` removed |
| `gcloud` | `gcloud` | *.googleapis.com | `CLOUDSDK_CONFIG`, `CLOUDSDK_AUTH_ACCESS_TOKEN_FILE`, `GOOGLE_OAUTH_ACCESS_TOKEN` |
| `az` | `az` | login.microsoftonline.com (body) | `AZURE_CONFIG_DIR`, `AZURE_CLIENT_SECRET` for `az login --service-principal` |
| `pip` | `pip` | none (a private index) | `PIP_INDEX_URL` and `UV_INDEX_URL` with the placeholder as password |
| `twine` | `twine` | upload.pypi.org | `TWINE_USERNAME=__token__`, `TWINE_PASSWORD` |
| `cargo` | `cargo` | crates.io | `CARGO_REGISTRY_TOKEN` |
| `hcloud` | `hcloud` | api.hetzner.cloud | `HCLOUD_TOKEN`, `HCLOUD_CONFIG` |
| `doctl` | `doctl` | api.digitalocean.com | `DIGITALOCEAN_ACCESS_TOKEN` |

`scrim profiles show <name>` prints the profile's notes. The ones that matter most:

- **docker**: `docker login` and `docker pull` are performed by dockerd, outside the session, so
  their registry traffic is not injected. podman, buildah, skopeo, crane and BuildKit run in the
  session and are.
- **aws**: the access keys sign requests, so the tool proxy re-signs them with the real keys
  (tasks 10a.2). The profile places the keys and removes inherited credentials.
- **gcloud**: access tokens live an hour; keep the store value fresh.
- **az**: the access token Entra ID returns is a live credential and lands in the session's
  `AZURE_CONFIG_DIR` until the session ends. A capture rule keeps it a placeholder.
- **psql, mysql, ssh** use the database proxy and the ssh agent, not profiles.

## Credential helpers

`scrim credential-helper` answers the tools that ask a helper for credentials, with the session's
placeholders only. It reads no store, no credential file in the home directory and no network, and
never stores what a tool hands it.

| Tool | Helper | Profile | Default |
| --- | --- | --- | --- |
| git | `scrim credential-helper git --file <generated git-credentials> get` (git credential protocol) | `git`, `GIT_CONFIG_VALUE_1` | on |
| docker, skopeo, podman with `DOCKER_CONFIG` | `docker-credential-scrim get\|list\|store\|erase` (docker credential helper protocol over `$DOCKER_CONFIG/config.json`) | `docker`, `credHelpers` per bound registry | on |
| aws CLI and SDKs | `credential_process = scrim credential-helper aws --access-key-id ... --secret-access-key ...` | `aws`, generated config | off |
| kubectl and client-go tools | kubeconfig `user.exec` running `scrim credential-helper kubectl --token ...` (ExecCredential) | `kubectl` | off |

Each profile has a `helper` param: `scrim` uses the helper, `""` writes the placeholder into the
generated file instead. Turn the aws and kubectl helpers on with

```yaml
tool-profiles:
  aws: {params: {helper: scrim}}
  kubectl: {params: {helper: scrim}}
```

With the helper on, the credentials file and kubeconfig hold no credential at all, and
`aws configure export-credentials` or the exec plugin print the placeholders. `aws configure get` then
prints nothing, since no key is in a file.

The docker profile links `docker-credential-scrim` to scrim in `<session-dir>/bin`, which `scrim run`
puts first on `PATH`; a profile may only link scrim's own helper names there. `store` succeeds only
for the placeholder the helper already returns, so `docker login` or `skopeo login` with a typed
password fails with an error telling you to put the credential in a store instead of keeping it in
the session. `erase` changes nothing. git's `store` and `erase` calls change nothing either.

Short-lived scoped credentials from a helper (instead of placeholders) are not implemented.

## Selecting profiles

`run.profiles` (`SCRIM_RUN_PROFILES`, `--run-profiles`) lists the profiles `scrim run` applies:

- `auto` (default): every profile a resolved catalog credential fills.
- profile names: those, whether or not the catalog fills them (unfilled ones are reported).
- `none`: no profiles.

A profile whose required credential is missing is left out with a warning naming the catalog tools
entry to add. Profiles only apply when scrim's forward proxy runs, since that is where their
placeholders are injected. A profile never changes a variable `scrim run` sets itself (proxies,
trust, `SCRIM_*`, `HOME`, `PATH`, `XDG_RUNTIME_DIR`).

`scrim run --print-env` lists the profile variables and files with the rest of the session.

## Custom and overridden profiles

Profiles live in the configuration collection `tool-profiles.<name>`, in the same format as the
built-in ones (`internal/profiles/builtin/*.yaml`). A new name adds a profile:

```yaml
tool-profiles:
  acme:
    description: In-house acme CLI
    credentials:
      - name: token
        hosts: [api.acme.internal]
        required: true
    env:
      ACME_TOKEN: '{{ placeholder "token" }}'
      ACME_CONFIG: '{{ path "acme.toml" }}'
    files:
      - path: acme.toml
        content: |
          token = "{{ placeholder "token" }}"
    paths:
      - home: .config/acme/acme.toml
        generated: acme.toml
    test:
      command: [acme, auth, print-token]
      expect: '{{ placeholder "token" }}'
catalog:
  entries:
    acme: {ref: bao://kv/agents/acme#token, tools: [acme]}
```

A built-in name overrides only the fields it sets; `params` merge key by key:

```yaml
tool-profiles:
  docker:
    params: {username: robot}
```

Fields: `description`, `tools` (executables), `requires` (profiles applied with this one),
`credentials` (`name`, `hosts`, `inject`, `required`; the first is filled by `tools: [<profile>]`,
others by `tools: [<profile>.<name>]`), `params`, `env`, `unset` (a trailing `*` removes a prefix),
`dirs` (created empty), `files` (`path`, `content`), `bin` (credential helper names linked to scrim
in the session's `PATH`: `docker-credential-scrim`), `paths` (fixed home paths and the generated file
shown there, for the session filesystem view), `test` (`command`, `stdin`, `expect`), `notes`.

Templates are Go `text/template` and only ever see placeholders: `placeholder SLOT`, `creds SLOT`
(each filling entry with `.Name`, `.Placeholder`, `.Hosts`, `.Host`), `host SLOT`, `param NAME`,
`path REL`, `dir`, `cabundle`, `home`, `scrim` (the scrim executable), `authsjson SLOT USER [HELPER]`
(a registry auth file, with `credHelpers` naming HELPER), `b64`, `basic USER PASS`, `json`, `shquote`,
`envname`, `stripport`. A variable whose template renders empty is not set.

## Testing profiles

```sh
scrim profiles test            # every profile with a test command whose tool is installed
scrim profiles test kubectl
```

Each test runs the tool's credential-printing command (`gh auth token`, `aws configure get`,
`kubectl config view --raw`, `gcloud auth print-access-token`, `git credential fill`, ...) with an
empty home directory and the profile applied with sample placeholders. Decoys sit at the tool's fixed
credential paths (`~/.kube/config`, `~/.aws/credentials`, ...) and in the variables the profile
removes (`GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, ...). The test fails if the tool prints a decoy or
not the generated placeholder. No real credential is read or sent.

`just e2e-profiles` runs the real CLIs under `scrim run` against fakes of their APIs on their default
hosts inside the end-to-end sandbox; CI installs the versions pinned in `scripts/cli-tools/tools.env`.

## Secrets in project files

Secrets that live in the project rather than a store (`.env`, `*.tfvars`, `config/*.yaml`) are
redacted from the session's first request: `scrim run` scans the working directory and registers
them. `scrim project scan` lists them and `scrim project move` moves each into a store after
confirmation, leaving a `{{scrim:<ref>}}` reference in the file. See
[run.md](run.md#secrets-in-project-files).

## What profiles do not cover

- A tool that reads a fixed path and has no override variable (doctl's config file, a hand-written
  `~/.netrc`) still sees the real file unless the session filesystem view hides it (tasks 10a.7,
  10a.8). Profiles list those paths for it.
- OAuth flows that return a new token (az, gcloud login) put a live token in the session until a
  capture rule turns it into a placeholder.
- Profiles replace the tool's user configuration for the session (`~/.npmrc`, `~/.terraformrc`,
  `GIT_CONFIG_COUNT`); non-credential settings belong in the project's own files.
