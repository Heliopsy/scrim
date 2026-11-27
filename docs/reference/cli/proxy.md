# scrim proxy

<!-- Generated from the command tree by `just cli-docs`. Do not edit. -->

Global flags are listed in [the CLI reference](README.md#global-flags).

## scrim proxy

Run the scrim daemon: LLM proxy, tool proxy, agent API and admin API.

```text
scrim proxy [flags]

Runs the control plane and the data plane until SIGINT or SIGTERM: the LLM proxy base URL (proxy.listen), the optional
Unix socket, forward proxy and tool proxy listeners, the agent API socket (api.socket), the entry page, the admin API
(admin.url) and, with metrics.enabled, Prometheus metrics and health on metrics.listen.

--metrics turns on metrics.enabled for this run on the default 127.0.0.1:9792; --metrics=ADDR also sets metrics.listen.

Traffic is refused until the data plane holds its first snapshot. The configuration reloads on SIGHUP and on file
changes; listener addresses need a restart.

--capture=DIR turns on capture mode: every provider request exactly as it left, and the response as received, is written
to DIR (mode 0700; --capture alone uses $XDG_STATE_HOME/scrim/capture) so you can check what the provider saw. The value
is optional, so it needs the = form; a directory after a space is refused as an extra argument. Agent credentials are
masked in captured headers.

Examples:
  scrim proxy
  scrim proxy --metrics
  scrim proxy --capture
  scrim proxy --capture="$HOME/scrim-capture"
  ANTHROPIC_BASE_URL=http://127.0.0.1:9790/anthropic claude
```

Flags:

```text
      --capture string[="             default"]\x00capture mode: write every provider request and response to this
                                      directory, given as --capture=DIR (proxy.capture.dir); --capture alone uses
                                      $XDG_STATE_HOME/scrim/capture
      --metrics string[="             default"]\x00serve Prometheus metrics (metrics.enabled); --metrics=ADDR also
                                      sets metrics.listen
```
