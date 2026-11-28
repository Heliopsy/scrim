# scrim edge

<!-- Generated from the command tree by `just cli-docs`. Do not edit. -->

Global flags are listed in [the CLI reference](README.md#global-flags).

## scrim edge

Forward an agent pod's ssh-agent, database ports and agent API to a central scrim.

```text
scrim edge
scrim edge [command]

Serves SSH_AUTH_SOCK, loopback database ports and the agent API socket (the exec broker included) in an agent pod and
carries every connection to the central scrim's edge listener over TLS, with the pod's projected service account token.
It holds no secret: keys, database passwords and exec secrets stay in the central scrim. A connection the central scrim
cannot take is refused. Settings: edge-forwarder.*.
```

| Subcommand | Description |
| --- | --- |
| [`scrim edge check`](#scrim-edge-check) | Check that the central scrim accepts this pod (for a startup probe) |

## scrim edge check

Check that the central scrim accepts this pod (for a startup probe).

```text
scrim edge check

Connects to the central scrim's edge listener with this pod's token and prints the agent it was verified as. Exits
non-zero when the central scrim is unreachable, its certificate does not verify against scrim's CA, or it refuses the
token.
```
