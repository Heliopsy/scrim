# Store and notifier plugins

A plugin adds a secret store or an approval notifier to scrim without changing scrim. It is a
separate executable that scrim starts, checks and talks to over a private socket. Plugins use the
same contract suites as the built-in adapters, so a plugin that passes them behaves like one.

This page is the contract. The schema is
[`proto/scrim/plugin/v1/plugin.proto`](../proto/scrim/plugin/v1/plugin.proto), the Go SDK is
[`pkg/plugin`](../pkg/plugin/plugin.go), and two example plugins are in
[`examples/plugins`](../examples/plugins/): `dirstore`, a store kept as files in one directory, and
`filenotify`, a notifier that appends signed JSON lines to a file. Both exist to show the contract
and to run the contract suites. `dirstore` keeps values unencrypted on disk; do not put real secrets
in it.

## Configuring a plugin

A store plugin is a store instance of kind `plugin`:

```yaml
stores:
  acme:
    kind: plugin
    command: /usr/local/libexec/scrim/scrim-store-acme
    args: [--region, eu]
    options:
      endpoint: https://vault.acme.example
    token: file:/run/secrets/acme-token
    capabilities: [read, list, watch]
    redact: ["acme://apps/*"]
```

A notifier plugin is an instance of the `notify.plugins` collection:

```yaml
notify:
  plugins:
    file:
      command: /usr/local/libexec/scrim/filenotify
      options:
        path: /var/lib/scrim/approvals.jsonl
      token: file:/run/secrets/approvals-hmac
```

| Field | Default | Meaning |
| ----- | ------- | ------- |
| `command` | required | Absolute path of the plugin binary. |
| `args` | none | Arguments after the program name. |
| `env` | none | The plugin's environment, as a map. Never put a credential here. |
| `options` | none | The plugin's own settings. scrim passes them as JSON and the plugin validates them. |
| `sha256` | none | Pins the binary: scrim refuses to start it unless its SHA-256 matches (quote the digest in YAML). |
| `timeout` | `10s` | Longest time one call (a read, a delivery) may take. |
| `start-timeout` | `5s` | Longest time the start, handshake and configuration may take. |
| `capabilities` | all declared | Stores only: the subset of the plugin's capabilities scrim uses, from `read`, `list`, `watch`, `write`, `glob`. `read` is required. |
| credential fields | none | References (`env:`, `file:`, `cred:`, a store reference), resolved at every start and sent to the plugin only. A store plugin takes the stores collection's credential fields (`token`, `password`, `client-secret`, ...); a notifier plugin takes `token`, `password`, `secret` and `credentials`. |

The generic store fields (`aliases`, `redact`, `refresh.*`, `labels`) work as for every store
([stores/README.md](stores/README.md)). Any other field is refused, so a misspelt option fails at
load instead of being ignored.

Configuration loading checks every plugin instance: scrim checks the binary, starts a throwaway copy,
handshakes, sends the options with the credential field names but no values, and stops it. `scrim
config validate` therefore reports a wrong binary, a protocol or kind mismatch, and each option the
plugin refuses, by name. The plugin that serves requests is started on first use.

## The binary

Before every start scrim resolves `command` (following symlinks) and refuses to run it unless:

- the path is absolute and names a regular, executable file;
- the file and every directory above it are owned by root or by scrim's user;
- none of them is writable by other users, or by a group other than root's; a world-writable
  directory with the sticky bit (`/tmp`) is accepted, since nobody can rename another user's entry
  there;
- with `sha256` set, the file's digest matches.

These checks make sure only root and scrim's own user can change what runs. The check and the
start are not one atomic step, so a user who can rewrite the file could swap it in between; that is
why no one else may write to it or to the directories above it.

The plugin starts with:

- the working directory `/`;
- stdin and stdout on `/dev/null`;
- stderr relayed line by line into scrim's log, through the same scrubbing as every log line, with
  `plugin=<instance>` (lines are capped at 2 KiB);
- file descriptor 3, one end of a Unix socketpair, and no other inherited descriptor;
- an environment of `PATH=/usr/local/bin:/usr/bin:/bin`, the `env` map, and `SCRIM_PLUGIN_FD=3`,
  `SCRIM_PLUGIN_PROTOCOL=1` and `SCRIM_PLUGIN_INSTANCE=<name>`; nothing of scrim's own
  environment;
- its own process group. On Linux it is killed when scrim dies; elsewhere it sees its socket close
  and must exit.

So a plugin only ever sees the configuration of its own instance.

## Transport and lifecycle

The plugin is a gRPC server on the socket it inherits as fd 3, and scrim is its only client
(HTTP/2 without TLS: nothing else can reach the socket). The plugin exits when the socket closes.

1. `Plugin.Handshake`: scrim sends the protocol version, the kind it configured (store or
   notifier) and the instance name. The plugin answers with its protocol, its kind, a name and
   version for logs, and, for a store, its capabilities. scrim stops a plugin that speaks another
   protocol, is of the other kind, declares an unknown capability or, as a store, lacks `read`.
2. `Plugin.Configure`: the options as a JSON object and the resolved credentials by field name.
   The plugin applies them without contacting its backend. A refusal is `INVALID_ARGUMENT`.
3. The kind's own service: `Store` (`Read`, `List`, `Watch`, `Write`, `Health`) or `Notifier`
   (`Notify`).

`Plugin.ValidateConfig` is only called on the throwaway validation process. It gets the options and
the names of the credential fields that are set, with empty values, and returns one problem per
invalid option. Problems name the option and never quote a value.

Every message carries `protocol` as field 1. Each side refuses a message whose protocol differs
from its own with `FAILED_PRECONDITION`. Adding a field or an optional call keeps the protocol at 1;
a change an older peer would misread bumps it.

## Store calls

References reach the plugin without their scheme: `Ref.path`, `Ref.field` (one field, or empty for
the whole secret) and `Ref.selectors` (the raw query, `version=3`).

| Call | Contract |
| ---- | -------- |
| `Read` | The secret at `path` with its metadata. With `field` set, only that field, `NOT_FOUND` if it is missing. A selector the plugin does not understand is `INVALID_ARGUMENT`, never ignored. |
| `List` | Metadata of every secret under the prefix, recursively. Never a value. |
| `Watch` | A stream. The first message has `ready` set and is sent once the watch is established: every change after it must be reported. Then one message per change (`CHANGED` or `DELETED`) with its path, never a value. It ends when scrim cancels it. A store without native notifications can poll, as `dirstore` does. |
| `Write` | Store the fields as a new version. `create_only` fails with `ALREADY_EXISTS` when the secret exists. A value the store cannot hold byte for byte is `UNIMPLEMENTED`, and nothing is stored. |
| `Health` | Reachability and credentials. |

Metadata carries the path, field names, a version, creation and update times, labels and a
write-only flag. A plugin reports its own attributes as `plugin.<attribute>` labels; scrim adds the
`store.*` labels and drops keys under another kind's prefix, as for any adapter
([labels](stores/README.md#labels)). Labels are metadata: never put a value in one.

Errors are gRPC status codes, which become scrim's error kinds:

| Code | Kind |
| ---- | ---- |
| `NOT_FOUND` | not found |
| `PERMISSION_DENIED` | permission denied by store |
| `UNIMPLEMENTED` | not supported |
| `UNAVAILABLE` | store unavailable |
| `ALREADY_EXISTS` | conflict |
| `FAILED_PRECONDITION` | store locked |
| `INVALID_ARGUMENT` | invalid reference |
| anything else | store unavailable |

scrim never prints, logs or returns a plugin's status message: a store's own message can echo
request data. To explain a failure, log it to stderr without the value.

A missing backend is an outage (`UNAVAILABLE`), never "every secret was deleted": reporting not
found during an outage would make scrim retire the values it is redacting.

## Notifier calls

`Notify` gets the approval ID, agent, action, secret reference, destination (method, host and path
without its query), tool, rule, reason and expiry, scrim's title and summary lines (the ones the
built-in notifiers show), and the two single-use decision links. Whoever opens a decision link
decides the request, so send the links only to the people who approve and never log them. A
notifier only delivers: its answer never approves anything, and a failure leaves the approval
pending on the other notifiers until it times out.

## Failure handling

scrim fails closed on every plugin fault and says which plugin and what happened:

| Fault | What scrim does |
| ----- | --------------- |
| The binary fails a check | The plugin is not started; the error names the check. |
| No answer to the handshake or configuration within `start-timeout` | The process is killed; the start fails. |
| Protocol or kind mismatch, no `read`, an unknown capability | The process is killed; the start fails, naming both sides. |
| The plugin exits | The call in flight fails with "plugin exited during read (exit status 2)". |
| A call runs past `timeout` | The call fails and the process group is killed. |
| An answer out of contract (another path, a listing outside the prefix, a watch that never confirms) | The call fails as unavailable; the answer is discarded. |
| Capabilities change across a restart | The restart fails. |

Every one of these is `store unavailable` to the rest of scrim. The refresher keeps the store's last
known values in the redaction set and reports the store degraded, exactly as for an outage. The next
call starts the plugin again, at most once per backoff, which doubles from 1s to 30s and resets after
a successful call; a call during the backoff fails at once with "next start in 1.2s". A restart
resolves the credentials again and sends them with a fresh `Configure`. An open watch is opened again
on the restarted plugin; the refresher's full refreshes cover changes made in between.

## Secret handling

- `Field.value` and `ConfigRequest.secrets` are the only fields that hold secret material.
- scrim copies a value out of its secret store into the request, and the codec zeroes those copies
  in the message once it is marshalled, and the marshalled bytes when gRPC releases them. A value
  received in a `ReadResponse` is copied into scrim's secret type and the message is zeroed. gRPC's
  own transport buffers are out of reach; the same limitation applies to the data plane boundary.
- The Go SDK zeroes credentials when `Configure` returns, written values when `Write` returns, and
  read values once they are sent. Copy what you need to keep.
- scrim adds a store plugin's credentials to the redaction set, so an agent that finds one cannot
  send it to a model provider. A notifier plugin's credentials are handled like the built-in
  notifiers' tokens: resolved from their reference at every start and reload, in the redaction set
  (see [configuration](configuration.md)), sent in `Configure`, and the copy made for the request
  is zeroed.
- A plugin must never write a value to stderr or into an error. scrim scrubs its log against every
  value it holds, but a value it does not hold yet cannot be scrubbed.

## Writing a plugin in Go

Implement `plugin.Store` or `plugin.Notifier` from `github.com/heliopsy/scrim/pkg/plugin` and serve
it from `main`:

```go
func main() {
    if err := plugin.ServeStore(&myStore{}); err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}
```

The SDK does the handshake and the protocol checks, refuses calls before `Configure` and calls
outside the declared capabilities without reaching your code, maps the error variables
(`plugin.ErrNotFound`, `plugin.ErrUnavailable`, ...) to status codes and sends only the kind, never
your error text. `examples/plugins/dirstore` and `examples/plugins/filenotify` import nothing else
from scrim.

In another language, generate the `Plugin` service and `Store` or `Notifier` from the proto file,
serve them on the connected socket in `SCRIM_PLUGIN_FD`, and follow the rules on this page.

## Testing a plugin

A store plugin passes the store conformance suite (`internal/stores/storetest`) through the plugin
bridge, and a notifier plugin the notifier contract suite (`internal/notify/notifytest`). The
example plugins run them in CI (job "Plugin contract"); copy their harnesses from
`internal/stores/plugin/plugin_test.go` and `internal/notify/plugin/plugin_test.go`:

```sh
go test -race ./internal/plugin/... ./internal/stores/plugin/ ./internal/notify/plugin/ ./internal/notify/notifytest/ ./pkg/plugin/...
```

The store suite needs a way to make the backend unreachable (an outage) and to delete a secret out
of band to check every case; without them those cases are skipped. The tests build the plugins with
the Go toolchain and need no container.
