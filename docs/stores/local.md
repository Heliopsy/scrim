# Local sources: env and file

Two read-only store adapters for secrets that already live on the machine scrim runs on: variables
in scrim's own environment, and files under a directory. Use them for a laptop setup, a CI job that
receives secrets as variables, or Kubernetes and systemd secrets mounted as files. Values are loaded
into the redaction set and can be injected toward bound hosts like any other store's; scrim cannot
write to either source.

## Capabilities

<!-- BEGIN GENERATED STORE CAPABILITIES kinds=env,file -->

| Kind | read | list | watch | write | glob | dynamic | per-agent check | `identity.store-login` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `env` | yes | yes | no | no | yes | no | no | none |
| `file` | yes | yes | yes | no | yes | no | no | none |

The columns are explained under [Capabilities](README.md#capabilities).

<!-- END GENERATED STORE CAPABILITIES -->

A write or generate targeting either source is refused before anything happens, with an error such
as `store env: write env://NEW_TOKEN: operation not supported by this store: store env is
read-only`. Pick a writable store (OpenBao, Infisical, Vaultwarden) as the default target of any rule
that captures or generates secrets.

The env source does not watch: a process environment does not change from outside, so a value set
after scrim started is only seen after a restart. The file source polls (see `watch.interval`).

## Configuration

Each store instance is configured under `stores.<instance>`, where `<instance>` is the name you pick
and also the reference scheme. Every key below can be set in the config file, or as an environment
variable: `SCRIM_` followed by the full key upper-cased, with dots and dashes as `_` (for example
`stores.local-env.prefix` is `SCRIM_STORES_LOCAL_ENV_PREFIX`). Nested and dotted forms are
equivalent in the file. Unknown keys fail validation and name the closest known key.

### env

```yaml
stores:
  ci-env:
    kind: env
    prefix: SCRIM_SECRET_
    allow:
      - SCRIM_SECRET_GITHUB_TOKEN
      - SCRIM_SECRET_NPM_*
```

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `stores.<name>.kind` | string | | `env` |
| `stores.<name>.prefix` | string | `""` | Only variables whose names start with this are visible. References still use the full name. |
| `stores.<name>.allow` | list of strings | empty | When set, only variables matching one of these exact names or glob patterns (`*`, `?`, `[a-z]`) are visible. As an environment variable, separate entries with commas. |

Set a `prefix` or an `allow` list. Without either, every variable in scrim's environment, including
`PATH` and `HOME`, can be referenced. An invisible variable reads as not found, the same as an unset
one.

References: `ci-env://SCRIM_SECRET_GITHUB_TOKEN`. An env secret has one field, `value`, so
`#value` is accepted and any other field is not found. Version selectors (`?version=`) are refused.

Listing matches path segments like every other store, so `ci-env://APP` lists `APP` and `APP/...`.
End the prefix with `*` to match by plain name prefix instead: `ci-env://SCRIM_SECRET_*` lists every
visible variable starting with `SCRIM_SECRET_`.

Globs in `redact`: only a trailing `*` is special, and it matches any characters, so
`ci-env://SCRIM_SECRET_*` loads `SCRIM_SECRET_GITHUB_TOKEN` and `SCRIM_SECRET_NPM_TOKEN`. `prefix`
and `allow` still decide what is visible: with `prefix: SCRIM_SECRET_`, `ci-env://SCRIM_*` loads the
same variables and never `SCRIM_OTHER`. A `*` elsewhere in a target is refused. A target that
matches no variable stops start-up (see [empty redact targets](README.md#empty-redact-targets)).

### file

```yaml
stores:
  mounted:
    kind: file
    root: /run/secrets
    format: auto
    trim-newline: true
    max-size: 1MiB
    watch:
      interval: 10s
```

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `stores.<name>.kind` | string | | `file` |
| `stores.<name>.root` | path | required | Absolute directory every reference resolves under. Opened at start-up; a missing root stops start-up. |
| `stores.<name>.format` | string | `auto` | `auto`, `raw`, `dotenv` or `json`. |
| `stores.<name>.trim-newline` | bool | `true` | Raw files only: remove one trailing `\n` or `\r\n`, as most editors and `echo` add one. |
| `stores.<name>.max-size` | size | `1MiB` | Larger files are refused. Accepts bytes or `KiB`, `MiB`, `GiB`, `KB`, `MB`, `GB`. |
| `stores.<name>.watch.interval` | duration | `10s` | How often watched files are checked. Each poll is offset by up to 10% of random jitter. |

References: `mounted://<path under root>[#field]`, for example `mounted://github/token` or
`mounted://app/.env#DATABASE_PASSWORD`. Paths are always relative to `root`. A reference with a
`..` segment or an absolute path is rejected as invalid, and a symlink that resolves outside `root`
is refused as a permission error; symlinks that stay inside `root` (as Kubernetes uses for mounted
secrets) work. Version selectors are refused.

Formats:

- `raw`: the whole file is one field, `value`. Use it for files holding a single token, such as
  Kubernetes secret mounts and systemd credentials.
- `dotenv`: one field per `KEY=VALUE` line. Blank lines and `#` comments are skipped, an `export` prefix before
  a key is allowed, unquoted values lose surrounding spaces and a trailing comment (space, then `#`),
  single-quoted values are literal, and double-quoted values decode `\n`, `\r`, `\t`, `\"`, `\\`,
  `\$` and `` \` ``. Quoted values may span lines. Variables are not expanded. A repeated key keeps
  its last value.
- `json`: a top-level object, one field per member. String members are unquoted; numbers, booleans,
  objects and arrays keep their JSON text; `null` members are skipped.
- `auto`: `dotenv` for names ending in `.env` or starting with `.env` (`.env.local`), `json` for
  names ending in `.json`, `raw` for everything else.

A file that does not parse is refused with an error that names the line or byte offset, never the
content.

Listing walks the prefix directory recursively and returns regular files, including symlinks to
files inside `root`. Field names are not listed, since that would mean reading every file. A
listed secret's version is its modification time and size.

A trailing `*` right after part of a name is a glob over paths under `root`: `mounted://app-*`
covers `app-db` and `app-cache/token` but not `apple`, and `mounted://github/ci-*` covers the files
in `github/` (and below) whose path starts with `github/ci-`. `mounted://github/*` stays the whole
folder. Globs work in `redact`, listing and watch; a `*` elsewhere in a target is refused.

Watch reports a file as changed when its size, modification time or content changes, and as deleted
when it disappears. Content is compared through a keyed digest held only in memory, with a random
key per process, so a rewrite of the same length within one filesystem timestamp tick is still
noticed. The digest is never shown or stored. A poll that fails reports nothing and keeps the
previous state, so a briefly unreadable directory never looks like a mass deletion.

## Labels

Both sources label their secrets for policy rules (see [labels](README.md#labels)): an env secret
carries `env.variable` and, when `prefix` is set, `env.prefix`; a file secret carries `file.root`,
`file.path` (the absolute path) and `file.format`.

## Least privilege

- Run scrim as its own user. Make secret files owned by that user with mode `0600`, and the root
  directory mode `0700`. scrim does not refuse wider permissions, but any other local user who can
  read the file can read the secret without scrim.
- Point `root` at a directory that holds only secrets meant for scrim, never at `/` or a home
  directory: every regular file under it can be referenced and listed by name.
- Agents never read these values back through scrim. They see references and names only, like for
  every store.
- For env, prefer an explicit `allow` list, and pass secrets only to scrim's process (for example
  through a systemd `EnvironmentFile=` readable only by scrim), not to the whole session.

## Limitations

- Environment variables reach Go as immutable strings. scrim wipes its own copies, but the process
  environment keeps the value for as long as scrim runs, and it is visible in `/proc/<pid>/environ`
  to the same user and to root. Use the file source or a real store for anything sensitive and
  long-lived.
- Both sources are local to one machine and have no versions, so the previous value of a rotated
  file is kept only through scrim's own retention of old values in the redaction set.
- File content is read whole into memory (up to `max-size`) and wiped after the fields are copied
  out. Watch reads each watched file at every poll to compare digests; keep watched prefixes small.
- SOPS-encrypted files and the OS keyring are separate sources, not formats of this one.
