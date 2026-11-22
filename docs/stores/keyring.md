# OS keyring source

A read-only store adapter for secrets kept in the operating system's keyring: the Secret Service on
Linux (gnome-keyring, KeePassXC, KWallet through its Secret Service bridge), the Keychain on macOS,
and the Credential Manager on Windows. Use it on a workstation where tokens already live in the
keyring, so scrim can redact them and inject them toward their bound hosts without copying them into
a file or an environment variable. scrim cannot write to the keyring.

## Capabilities

| Backend | OS | read | list | watch | write | generate | dynamic | glob |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `secret-service` | Linux | yes | yes | no | no | no | no | yes |
| `keychain` | macOS | yes | no | no | no | no | no | no |
| `wincred` | Windows | yes | no | no | no | no | no | no |

The backend follows the operating system scrim runs on; there is nothing to choose. A write or
generate targeting the keyring is refused before the keyring is contacted, with an error such as
`store kr: write kr://scrim/new: operation not supported by this store: keyring source is
read-only`.

Nothing is watched. The refresher reads the configured secrets again every `refresh.interval`
(default `5m`), so a rotated keyring item is picked up at the next refresh.

On macOS and Windows the backend cannot enumerate items without reading their values, so only
single secrets can be redact targets there: `kr://scrim/github-token`, not `kr://scrim/*`. A
folder or glob target on those systems is refused at start-up.

The Linux backend is tested against gnome-keyring in CI, the macOS backend against a throwaway
keychain on a macOS runner. The Windows backend is built but not tested: scrim does not ship
Windows binaries yet.

## References

```text
<instance>://<service>/<account>[#value]
```

The first path segment is the service, the rest is the account, which may itself contain `/`:
`kr://scrim/ci/deploy` is service `scrim`, account `ci/deploy`. A keyring secret has one field,
`value`, so `#value` is accepted and any other field is not found. Version selectors are refused.

How a service and an account map to an item:

| Backend | Item |
| --- | --- |
| `secret-service` | An item in the configured collection whose attribute `service` is the service and `username` the account (the attribute names are configurable). This is what `secret-tool store --label=... service scrim username ci/deploy`, Python `keyring` and go-keyring create. |
| `keychain` | A generic password with service (`-s`) and account (`-a`), as `security add-generic-password -s scrim -a ci/deploy -w` creates. |
| `wincred` | A generic credential whose target name is `<service>:<account>` (the go-keyring convention). |

Listing (Linux only) takes the service as an exact first segment and matches the account by path
segments: `kr://scrim` lists every visible account of `scrim`, `kr://scrim/ci` lists `ci` and
`ci/...`. End it with `*` to match by plain prefix: `kr://scrim/ci-*` covers `ci-deploy` and
`ci-npm/token`. A `*` in the service segment is refused. Two items with the same service and account
in one collection are refused as a conflict rather than guessed between.

## Configuration

```yaml
stores:
  kr:
    kind: keyring
    services: [scrim]
    allow:
      - scrim/github-token
      - scrim/ci-*
```

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `stores.<name>.kind` | string | | `keyring` |
| `stores.<name>.services` | list of strings | required | The keyring services scrim may read. Exact names, no `/` or glob characters. As an environment variable, separate entries with commas. |
| `stores.<name>.allow` | list of strings | empty | When set, only `<service>/<account>` paths matching one of these exact paths or glob patterns (`*`, `?`, `[a-z]`; `*` does not cross `/`) are visible. |
| `stores.<name>.timeout` | duration | `10s` | Longest wait for one call to the keyring. A keyring that does not answer in time reads as unavailable. |
| `stores.<name>.collection` | string | `default` | Linux: the collection to read, by alias (`default`, `login`, `session`) or label. Items in other collections are invisible. |
| `stores.<name>.bus-address` | string | session bus | Linux: the D-Bus address of the session bus, for example `unix:path=/run/user/1000/bus`. Without it scrim uses `DBUS_SESSION_BUS_ADDRESS`, then `$XDG_RUNTIME_DIR/bus`. It never launches a bus. |
| `stores.<name>.attributes.service` | string | `service` | Linux: the item attribute that holds the service. |
| `stores.<name>.attributes.account` | string | `username` | Linux: the item attribute that holds the account. |
| `stores.<name>.session` | string | `encrypted` | Linux: how values cross the bus. `encrypted` negotiates the Secret Service's Diffie-Hellman and AES-128 session, so a process monitoring the bus does not see them; `plain` sends them in clear and is only for a Secret Service that cannot encrypt. |
| `stores.<name>.keychain` | path | search list | macOS: absolute path of the keychain to read, for example `/Users/me/Library/Keychains/scrim.keychain-db`. Without it the user's keychain search list is used. |

An option of another system's backend is refused (a `collection` on macOS, a `keychain` on Linux),
like any unknown key, so a configuration moved between machines fails at start-up instead of
silently reading somewhere else.

To store a value for scrim, use the keyring's own tools, for example:

<!-- docs-test: skip: needs a desktop keyring session -->
```sh
secret-tool store --label='scrim: GitHub token' service scrim username github-token
```

## Labels

Every keyring secret carries, for policy rules (see [labels](README.md#labels)):

| Label | Backends | Meaning |
| --- | --- | --- |
| `keyring.backend` | all | `secret-service`, `keychain` or `wincred`. |
| `keyring.service` | all | The service. |
| `keyring.account` | all | The account. |
| `keyring.collection` | `secret-service` | The `collection` option. |
| `keyring.label` | `secret-service`, `keychain`, `wincred` | The item's display label (the credential's comment on Windows). |
| `keyring.keychain` | `keychain` | The `keychain` option, when set. |
| `keyring.meta.<attribute>` | `secret-service` | Every other item attribute (`xdg:schema` becomes `keyring.meta.xdg_schema`). |

Item attributes can be edited by any program in the session, so they are reported only under
`keyring.meta.`. An attribute named `collection` or `keyring.backend` becomes
`keyring.meta.collection` or `keyring.meta.keyring.backend` and never replaces a native label.
Labels are metadata, never values: on Linux and macOS they are read without fetching the secret
(`scrim catalog labels` and write rules cost no secret read). On Windows the Credential Manager
returns the value with the metadata, and scrim wipes it at once.

## Locked keyrings

scrim never unlocks a keyring and never opens a prompt. A read from a locked collection or keychain
is refused at once with `store locked`, the store reports `locked` and unhealthy, and injection of
its values is refused (see [freshness and outages](README.md#freshness-and-outages)). Unlock it in the
desktop session; scrim picks the values up at its next refresh.

- Linux: scrim calls only `OpenSession`, `ReadAlias`, `SearchItems`, property reads and `GetSecret`
  on an unlocked item. It never calls `Unlock`, so no password dialog appears on your desktop because
  of scrim.
- macOS: values are read with `/usr/bin/security`. A locked keychain is refused when the system
  reports that user interaction is not allowed, which is the case for a background service. In a
  logged-in desktop session, macOS itself may still show an unlock or "allow access" dialog for
  `security`, which scrim cannot suppress through that tool. Keep the keychain unlocked and give
  `/usr/bin/security` access to the items scrim reads (`security add-generic-password -T
  /usr/bin/security ...`, or "Always Allow" once), and the dialog never appears.

## Headless Linux

A server or container without a desktop session has no Secret Service until you start one. With
gnome-keyring:

<!-- docs-test: skip: starts a session bus and a keyring daemon -->
```sh
export $(dbus-launch)
printf '%s' "$KEYRING_PASSWORD" | gnome-keyring-daemon --unlock --components=secrets
```

`--unlock` reads the login keyring's password from standard input and creates the keyring on first
use. Point scrim at the same bus with `DBUS_SESSION_BUS_ADDRESS` or `bus-address`. On a host like
that, prefer the [file source](local.md) or a real store: the keyring adds a daemon and an unlock
step, and protects nothing a file readable only by scrim's user does not.

## Least privilege

- `services` is required. Your login keyring also holds browser, Wi-Fi, chat and SSH passphrases;
  scrim sees only the services you list, and everything else reads as not found without the
  keyring being asked. Add `allow` to narrow a service to the accounts scrim needs.
- Prefer a dedicated service name for what scrim reads (`scrim`), not the service of another
  program.
- On Linux, consider a separate collection for scrim's items (`collection: scrim`), so a lock of your
  login keyring does not stop scrim and scrim cannot see your login items at all.
- Any process running as your user can ask the Secret Service for the same items. The keyring
  protects values at rest and from other users, not from your own processes. scrim's own guarantees
  (agents never read values back, values redacted before providers) are unchanged.

## Limitations

- On macOS the value passes through the `security` process and its output pipe; scrim reads it into
  memory it wipes after use, and no value is ever put on a command line. On Linux the value arrives
  as bytes over D-Bus, encrypted by default, and never becomes a Go string.
- The keyring has no versions. The previous value of a rotated item is kept only through scrim's own
  retention of old values in the redaction set.
- macOS and Windows cannot list, so folder and glob targets work on Linux only.
