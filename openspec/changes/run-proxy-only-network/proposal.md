## Why

`scrim run` sets base URLs and proxy variables for the agent, but a command that ignores
`HTTPS_PROXY`, clears its environment or dials a provider's address goes straight out
(docs/limitations.md, "How traffic reaches scrim"). Enforcement today needs root: nftables per UID
or cgroup, or eBPF (`sudo scrim install --system --transparent`, `--ebpf`). A developer on a normal
workstation has no enforced mode.

## What Changes

- New setting `run.network` (`open` default, `proxy-only`; flag `--run-network`). With
  `proxy-only` on Linux, the namespace helper of the session filesystem view also creates a network
  namespace with loopback only, inside the unprivileged user namespace it already uses. It binds
  listening sockets at the addresses of scrim's LLM base URL and forward proxy (same address inside
  as outside, so the environment does not change) and hands them to `scrim run` over a Unix socket
  before executing the agent; `scrim run` serves them from outside by splicing to scrim's real
  listeners. No pasta or slirp4netns, no new runtime dependency.
- DNS: no resolver is reachable inside; names are resolved by the forward proxy from `CONNECT`.
  ssh and git over ssh fail by design (HTTPS remotes go through the proxy); database proxies and
  chained upstreams are not reachable from the session.
- Unix sockets that would act outside the namespace are covered for the agent: the session bus,
  the systemd user manager, rootless podman and docker, the docker daemon, tmux; the host's name
  resolvers (system bus, systemd-resolved, nscd, avahi), so names cannot carry data out; X11 and
  Wayland displays, with `DISPLAY` and `WAYLAND_DISPLAY` removed.
- Fail closed: `proxy-only` refuses to start the agent when the namespace or a listener cannot be
  set up, when scrim's listeners are not on loopback, on platforms other than Linux, and when scrim
  is unavailable even with `run.allow-unredacted-start`.
- `scrim status` ("Agent network (scrim run)", `run_network`) and `scrim doctor` (`run-network`)
  report the mode and whether `proxy-only` works on the host; `--print-env` lists the reachable
  listeners, masked paths and gaps. macOS: not supported.

## Impact

- Affected specs: interception (new "Proxy-only agent network" requirement; "Doctor and status
  report protections" unchanged in substance).
- Affected code: internal/fsview (helper_linux.go, network.go), internal/run (network.go, run.go,
  settings.go), internal/cli (run.go, status.go), internal/status, test/e2e/harness,
  test/e2e/tools, .github/workflows/ci.yaml.
- Docs: run.md, interception.md, limitations.md, configuration.md (`run.network`).
