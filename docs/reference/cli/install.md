# scrim install

<!-- Generated from the command tree by `just cli-docs`. Do not edit. -->

Global flags are listed in [the CLI reference](README.md#global-flags).

## scrim install

Run scrim as a service: a systemd user unit, a hardened system unit, or a podman Quadlet container.

```text
scrim install (--user | --system | --quadlet [--system] | --hooks | --managed-settings) [flags]

Shows every change before making it and records it in a manifest, so `scrim uninstall` reverts exactly those changes.
Running it again with a new binary upgrades the service.

--user: a systemd user unit for this user, sockets in $XDG_RUNTIME_DIR/scrim, the CA trusted through `scrim ca install
--user`.
--system (as root): the dedicated system user scrim, /etc/scrim/config.yaml, state in /var/lib/scrim, sockets in
/run/scrim (the agent API for the group scrim-agents), a hardened unit, the CA in the system trust store.
--quadlet: the container image under rootless podman for this user; with --system under root's podman as the user scrim.

Host-level interception, with --system (Linux):
--transparent: nftables rules redirect TCP 80 and 443 of the --cover-user users and --cover-cgroup control groups to
scrim's transparent listener, which routes by TLS server name; their direct and QUIC egress is rejected, so an agent
needs no configuration and cannot reach providers around scrim. The rules load from scrim-transparent.service and stay
while scrim is stopped (connections fail instead of going direct).
--ebpf: the same for the --cover-cgroup control groups with eBPF cgroup hooks instead of nftables: scrim-ebpf.service
runs `scrim ebpf attach` at every boot, before the network and scrim, and the pinned programs stay attached while scrim
is stopped. Needs root (CAP_BPF and CAP_NET_ADMIN) and cgroup v2; --dry-run prints the unit and drop-in without either.
--dns: provider host names resolve to scrim's SNI listener through /etc/hosts. Connections made by address bypass it;
combine it with --transparent where that matters.
Each adds the CA to the Java truststores as well as the system store.

Agent-side modes, recorded in a manifest of their own and also reverted by `scrim uninstall`:
--hooks: scrim's PostToolUse and UserPromptSubmit hooks in this user's Claude Code and Codex configuration (partial
protection: tool results and prompts only; see docs/interception.md, method 6).
--managed-settings (as root): Claude Code's managed settings drop-in and Codex's requirements.toml, pinning each agent
to scrim's endpoint so its own settings cannot point it elsewhere.

See docs/service.md and docs/interception.md.
```

Flags:

```text
      --agent strings                   with --hooks or --managed-settings: claude or codex (repeatable; default
                                        the agents found on this machine)
      --agent-user strings              with --system: add this user to the group scrim-agents and map it to an
                                        agent of the same name (repeatable)
      --block-unrouted[=true|false]     with --transparent, --ebpf or --dns: close connections to hosts scrim has
                                        no route for instead of passing them through untouched
      --cover-cgroup strings            with --transparent or --ebpf: a control group below /sys/fs/cgroup, such
                                        as agents.slice, whose connections are redirected (repeatable)
      --cover-user strings              with --transparent: a user whose connections are redirected (repeatable)
      --dns[=true|false]                with --system: resolve provider host names to scrim's SNI listener through
                                        /etc/hosts (connections by address bypass it)
      --dns-address string              with --dns: the loopback address the names resolve to; the SNI listener
                                        binds port 443 on it (default "127.0.83.1")
      --dns-host strings                with --dns: a host name to resolve to scrim (repeatable; default the
                                        provider hosts of the configured routes)
      --dry-run[=true|false]            show the changes without making them
      --ebpf[=true|false]               with --system: attach scrim's eBPF hooks to the --cover-cgroup control
                                        groups at every boot, redirecting their provider connections to scrim and
                                        denying their direct egress
      --forward-proxy[=true|false]      with --managed-settings: also pin Claude Code's HTTPS_PROXY to scrim's
                                        forward proxy (the CA must be in the system trust store)
      --hooks[=true|false]              install scrim's hooks into this user's agent configuration (partial protection)
      --image string                    image for --quadlet (default ghcr.io/heliopsy/scrim:<this version>)
      --java-home strings               with --transparent, --ebpf or --dns: a JDK outside /usr/lib/jvm whose
                                        truststore gets the CA (repeatable)
      --managed-settings[=true|false]   write the agents' managed settings so they can only use scrim's endpoint
                                        (needs root)
      --quadlet[=true|false]            run the container image through a podman Quadlet unit (rootless, or with
                                        --system as root)
      --system[=true|false]             install system-wide, as the dedicated user scrim (needs root)
      --transparent[=true|false]        with --system: redirect the covered users' and control groups' provider
                                        connections to scrim with nftables and block their direct egress
      --transparent-port int            with --transparent or --ebpf: the port of the transparent listener on
                                        127.0.0.1 and ::1 (default 9793)
      --user[=true|false]               install a systemd user unit for this user
```
