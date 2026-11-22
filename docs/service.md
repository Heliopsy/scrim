# Running scrim as a service

`scrim install` sets scrim up as a service on a Linux machine with systemd, and `scrim uninstall`
takes it out again. Three modes:

| Mode | Command | Runs as | Sockets | CA trust |
| --- | --- | --- | --- | --- |
| User unit | `scrim install --user` | you, under your systemd user manager | `$XDG_RUNTIME_DIR/scrim/` | your per-user stores (`scrim ca install --user`) |
| System unit | `sudo scrim install --system` | the dedicated system user `scrim` | `/run/scrim/`, agent API for the group `scrim-agents` | the system trust store |
| Quadlet | `scrim install --quadlet` | the container image under your rootless podman | `$XDG_RUNTIME_DIR/scrim/` | your per-user bundle files |
| Quadlet, system | `sudo scrim install --quadlet --system` | the image under root's podman, as the user `scrim` | `/run/scrim/` | the system trust store |

Pick the user unit for a workstation where the agents run as you. Pick the system unit when the
agents run as other users, or when the CA key and the state should be out of the agents' reach:
an agent running as you can read everything a user unit keeps in your home directory
([ca.md](ca.md)). Quadlet runs the signed release image instead of the binary.

macOS (a launch agent) is not automated yet; run `scrim proxy` from a launchd plist of your own.

## What install does

Every change is printed before it is made and recorded in a manifest. `--dry-run` prints the
changes and makes none:

```text
$ sudo scrim install --system --agent-user alice --dry-run
scrim install (system service) would make these changes, in order:
+ would create the directory /etc/scrim
+ would create the system group scrim (groupadd --system scrim)
+ would create the system group scrim-agents (groupadd --system scrim-agents)
+ would create the system user scrim, no login, home /var/lib/scrim (useradd --system --gid scrim ...)
+ would add alice to the group scrim-agents, so its agents can use the sockets (usermod -a -G scrim-agents alice)
+ would write /usr/local/bin/scrim (the scrim binary /home/alice/Downloads/scrim, mode 0755)
+ would write /etc/scrim/config.yaml (the configuration file, mode 0640)
+ would let systemd create the state directory /var/lib/scrim at the first start (kept by uninstall unless --purge)
+ would write /etc/systemd/system/scrim.service (the unit, mode 0644)
+ would reload the systemd system manager (systemctl daemon-reload)
+ would enable and start scrim.service (systemctl enable --now)
+ would trust the scrim CA system-wide: write /usr/local/share/ca-certificates/scrim-ca.crt, then run update-ca-certificates
```

After starting the service, install waits until scrim reports ready on its admin socket (up to 90
seconds), then installs the CA the running service reports. A failure stops the install and says
so; `scrim uninstall` then reverts what was made up to that point.

| | User unit | System unit |
| --- | --- | --- |
| Binary | `~/.local/bin/scrim` | `/usr/local/bin/scrim` |
| Unit | `~/.config/systemd/user/scrim.service` | `/etc/systemd/system/scrim.service` |
| Config | `~/.config/scrim/config.yaml` (yours, not touched) | `/etc/scrim/config.yaml` (written when missing) |
| State | `~/.local/state/scrim` | `/var/lib/scrim` (systemd `StateDirectory`, mode 0700) |
| Sockets | `$XDG_RUNTIME_DIR/scrim/` | `/run/scrim/` (systemd `RuntimeDirectory`) |
| Manifest | `~/.local/state/scrim/install.json` | `/etc/scrim/install.json` |
| Logs | `journalctl --user -u scrim` | `journalctl -u scrim` |

The binary is copied from the one you run, unless it already is the installed one. Directories
install creates (`~/.local/bin`, `~/.config/systemd/user` and their parents) are recorded too, so
uninstall removes them when they are empty again. A file at one of these paths that scrim did not
write stops the install; an existing `/etc/scrim/config.yaml` is kept as it is.

### The system configuration file

When `/etc/scrim/config.yaml` does not exist, install writes one. It maps each `--agent-user` to
an agent of the same name, by user ID, and includes `conf.d/` next to it:

```yaml
apiVersion: scrim.dev/v1
kind: Config
include:
  - {path: conf.d, optional: true}
identity:
  peers:
    alice: "uid:1000"
```

Put your own settings (stores, catalog, providers, policy) in `/etc/scrim/conf.d/*.yaml`, so the
generated file stays as written and uninstall can remove it. The file is owned by root, group
`scrim-agents`, mode 0640: `scrim run` and the agent tools of those users read it too. It holds
references, never secret values. Users outside the group cannot read it, and `scrim` refuses to
run for them.

## How agents find the service

Nothing to configure. `scrim run`, `scrim mcp` and `scrim secret` look in this order:

1. `admin.url` or `api.socket`, when set.
2. This user's daemon: `$XDG_RUNTIME_DIR/scrim/admin.sock` (a user unit, a rootless Quadlet or a
   `scrim proxy` you started).
3. The system service: `/run/scrim/api.sock`. Its admin socket accepts only the user `scrim` and
   root, so agents of other users ask the agent API instead (`GET /v1/endpoints`: readiness, the
   base URL, the forward proxy, the bypass list and the public CA, nothing secret).
4. None of these: `scrim run` starts a private daemon for the run, as before.

A system service that does not answer or is not ready is an error, not a reason to start a private
daemon. A user outside `scrim-agents` cannot read `/etc/scrim/config.yaml`, so every `scrim`
command refuses with "permission denied" on that file. With a configuration of its own
(`--config`), it is refused by the socket instead, and the error names the group. Group membership
takes effect at the next login.

Each agent user must also be mapped in `identity.peers`; an unmapped user cannot mint a session.
`--agent-user` does both. To add a user later:

```sh
sudo usermod -a -G scrim-agents bob
sudo tee /etc/scrim/conf.d/bob.yaml <<'EOF'
apiVersion: scrim.dev/v1
kind: Config
identity:
  peers:
    bob: "uid:1001"
EOF
sudo systemctl restart scrim
```

Changes made this way are yours: uninstall does not revert them, and reports `/etc/scrim` as not
empty when `conf.d` is still there.

## Hardening

The system unit runs as `scrim` with the agent group as a supplementary group, and confines it as
far as scrim allows:

| Setting | Why |
| --- | --- |
| `User=scrim`, `Group=scrim`, `SupplementaryGroups=scrim-agents` | its own user; the agent group only to give `api.sock` to it (`api.group`) |
| `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes` | read-only system, no home directories, private `/tmp` and `/dev`; writable only `/var/lib/scrim` and `/run/scrim` |
| `NoNewPrivileges=yes`, `CapabilityBoundingSet=` (empty), `AmbientCapabilities=` | no privileges at all, no way to gain any |
| `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectKernelLogs`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`, `RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`, `RemoveIPC` | the kernel surfaces scrim never needs |
| `MemoryDenyWriteExecute=yes` | no writable and executable memory |
| `LockPersonality=yes`, `SystemCallArchitectures=native` | no personality or foreign-ABI tricks |
| `SystemCallFilter=@system-service`, `SystemCallErrorNumber=EPERM` | the system call set of an ordinary service |
| `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK` | sockets, TCP to providers and stores; netlink for the resolver of a glibc data plane |
| `LimitMEMLOCK=infinity` | the data plane locks its memory, so values are never swapped |
| `LimitCORE=0`, `UMask=0077` | no core dumps of a process that holds values; private files by default |

`MemoryDenyWriteExecute` is compatible with how scrim starts its data plane (design D11): the
embedded binary is written to a sealed memfd and executed through `execve`, which maps the image
read-only and executable, never writable and executable. Neither half compiles code at run time.
The VM test runs with it on, with the data plane started from memory.

`ProtectProc` stays at its default: scrim reads `/proc/<pid>/stat` of the agents that connect, to
bind sessions to their process trees ([identity.md](identity.md)). `PrivateUsers` is off for the
same reason: peer credentials must show the agents' real user IDs. `systemd-analyze security
scrim.service` rates the unit 1.7 ("OK").

The user unit keeps to the hardening a user manager can apply without user namespaces: `UMask`,
`LimitCORE=0`, `NoNewPrivileges`, `LockPersonality`, `MemoryDenyWriteExecute`, `RestrictRealtime`,
`RestrictSUIDSGID`, `RestrictAddressFamilies`, `SystemCallFilter`. It raises `LimitMEMLOCK` only
when your hard limit is already unlimited, since systemd refuses to start a unit that asks for
more; otherwise install says so and the data plane warns that its memory is not locked. Raise the
limit (`/etc/security/limits.conf`, or `DefaultLimitMEMLOCK=` for the user manager) or use
`--system`.

The Quadlet containers run with a read-only root filesystem, every capability dropped,
`no-new-privileges` and core dumps off, on the host network (the listeners stay on loopback as on
the host) and in the host PID namespace (session binding reads the agents' `/proc` entries). The
rootless one maps your user to the image's UID 65532 (`UserNS=keep-id`), so the sockets and the
state volume are yours. The system one runs as `scrim` with `scrim-agents` added, with the same
paths and environment as the system unit and `memlock` unlimited.

## The user service and logins

A user unit runs while you are logged in. To start it at boot and keep it running without a
session:

```sh
loginctl enable-linger
```

Install prints this reminder when lingering is off; it does not turn it on for you.

## Upgrade

Install the new binary the same way: run `scrim install` again with the new release. Changes
already recorded stay; files whose content changed (the binary, the unit) are replaced and the
service is restarted:

```text
$ sudo ./scrim install --system
+ replace /usr/local/bin/scrim with the scrim binary /home/alice/scrim-0.2.0/scrim
+ restart scrim.service (systemctl restart)
```

A file install wrote and you edited since is not replaced; install stops and names it. For
Quadlet, pass the new tag with `--image`. A CA rotation needs no reinstall for the per-user bundle
files; for the system trust store, run `scrim install --system` again after `scrim ca rotate` so
the new CA is added before the overlap ends.

## Logs and status

```sh
journalctl -u scrim -f            # system unit and system Quadlet
journalctl --user -u scrim -f     # user unit and rootless Quadlet
scrim status                      # includes the installed service and its state
```

`scrim status` reads the manifest and asks systemd about the unit:

```text
Service
  scrim.service: active (system service, manifest /etc/scrim/install.json)
```

An installed service that is not active is listed under Degraded. Run as root, `scrim status`
reports the system service's state in `/var/lib/scrim`.

## Uninstall

```sh
scrim uninstall --user [--purge]
sudo scrim uninstall --system [--purge]
```

Uninstall reverts what the manifest lists, newest first: the CA trust, the service, the unit (and
a `daemon-reload`), the configuration file, the binary, the group memberships, the user and the
groups, and the directories install created. Without `--user` or `--system` it picks the system
install as root and yours otherwise; the manifest says whether it was a unit or Quadlet.

`scrim uninstall --user` also reverts the agent hooks of `scrim install --hooks`, and
`scrim uninstall --system` the managed agent settings of `scrim install --managed-settings`; each
has a manifest of its own (`agent-hooks.json` in the state directory,
`/etc/scrim/managed-settings.json`), and `scrim uninstall --hooks` or `--managed-settings` reverts
only that one ([interception.md](interception.md)).

The state (CA and key, placeholder keys, the state database, the audit log) is kept unless you
pass `--purge`, and so are the Quadlet volume and the pulled image. A kept item stays in the
manifest, so a later `scrim uninstall --purge` removes it.

Accounts and groups that existed before install are used as they are and never deleted. A change
that cannot be reverted is left in the manifest and listed with the manual step, and the command
exits 1:

```text
not reverted: /etc/scrim/config.yaml
    manual step: rm /etc/scrim/config.yaml (check whether you still need the changes)
```

A file install wrote and you changed since is such a change: scrim does not delete your edits.

## Host-level interception

With `--system`, three more flags install interception that needs no agent configuration
([interception.md](interception.md), methods 3 and 4):

```sh
sudo scrim install --system --transparent --cover-user agent1 --cover-cgroup agents.slice
sudo scrim install --system --ebpf --cover-cgroup agents.slice
sudo scrim install --system --dns
```

Each can be added to an existing system install; run the command again with the flag.
`--transparent` and `--ebpf` are alternatives: nftables rules for users and control groups, or
eBPF cgroup hooks for control groups only. What they add, each change printed first and recorded
in the manifest:

| Change | `--transparent` | `--ebpf` | `--dns` |
| --- | --- | --- | --- |
| `/etc/systemd/system/scrim.service.d/interception.conf` | turns on the transparent listener (`127.0.0.1:9793`, `[::1]:9793`) | the same | turns on the SNI listener (`127.0.83.1:443`) and grants `CAP_NET_BIND_SERVICE` |
| `/etc/scrim/transparent.nft`, `scrim-transparent.service`, the nftables table `inet scrim` | the redirect and deny rules for the covered users and cgroups | | |
| `/etc/systemd/system/scrim-ebpf.service`, the pinned links under `/sys/fs/bpf/scrim` | | a oneshot unit that runs `scrim ebpf attach` for the covered control groups at every boot and `scrim ebpf detach` when stopped | |
| `/etc/hosts` | | | one marked block resolving the provider hosts to scrim |
| Java truststores | the CA, checked in the stores the system trust tool rebuilds and imported into other JDKs' `cacerts` (`--java-home` for one outside `/usr/lib/jvm`) | the same | the same |

The rules unit is separate from `scrim.service` and keeps the rules loaded while scrim is stopped,
so covered agents fail closed. `--block-unrouted` closes connections to hosts scrim has no route
for instead of relaying them untouched. Uninstall deletes the table, removes the hosts block (or
leaves an edited one with the manual step), removes the CA from every truststore it was added to,
including a Java store the system trust tool kept it in, and removes the files.

### eBPF at boot

`scrim-ebpf.service` is ordered like the nftables unit: before `network-pre.target` and before
`scrim.service`, without the default dependencies, so a covered control group has no window at
boot in which it reaches a provider directly. It pulls in each covered slice (`Wants=` and
`After=agents.slice`), since the programs attach to an existing control group; any other control
group must exist when it runs. The loader pins the links in bpffs, so they stay after the oneshot
exits and while scrim is stopped. Stopping the unit, or shutting down, detaches them. Running the
install again with other `--cover-cgroup` values reattaches in place (`systemctl reload`) and
detaches the control groups that are no longer listed.

The install needs root, or `CAP_BPF` and `CAP_NET_ADMIN`, and the cgroup v2 hierarchy; it checks
both before changing anything and names what is missing. `--dry-run` needs neither and prints the
unit and the drop-in it would write. It refuses `--cover-user` (use `--transparent`) and a control
group that holds `scrim.service` (`system.slice` or below): the programs cannot exempt scrim's own
user the way the nftables rules do, so scrim's upstream connections would come back to itself.
With a `--transparent-port` other than 9793 there is nothing else to set: while
`interception.ebpf.port` is unset, `scrim status`, `scrim doctor` and `scrim ebpf attach` use the
port the installed unit attaches with. A value you set yourself takes precedence.

Uninstall detaches each recorded control group first and waits until the kernel confirms it, then
stops and disables the unit and removes it and the drop-in, reloading systemd after each. Running
it again finds nothing to do.

`scrim status` lists the active modes under Interception, and `direct egress blocked` as active
while the transparent listener runs.

## Verified in a VM test

`test/service/vm-test.sh` (`just service-vm-test`) runs a Debian systemd host in rootless podman
as a disposable VM. For the system and the user unit it snapshots the file system, installs,
checks the unit is active, runs a test agent with `scrim run` and a client that trusts only the
system store through the forward proxy against the fake provider, checks the secret never reaches
the provider and that `scrim status` reports the service, uninstalls with `--purge` and compares
the file system with the snapshot. Left out of the comparison: `/proc`, `/sys`, `/dev`, `/run`,
`/tmp`, logs and caches, systemd's own bookkeeping in `/var/lib/systemd`, and the backup files
the shadow tools rewrite on every account change (`/etc/passwd-` and friends). `/run/scrim` is
checked separately.

`test/service/transparent-test.sh` (`just service-transparent-test`) does the same for
`--transparent` and `--dns` in a host with nftables, a JDK and a stand-in provider address in its
own network namespace, and also compares `nft list ruleset` and the certificates in the Java
truststores. The Java keystores are compared by the certificates they hold, not their bytes, since
the trust tool rewrites them; dpkg's backup `/var/lib/dpkg/status-old` is left out, since Debian's
ca-certificates-java hook rewrites it when it runs dpkg triggers (the status file is compared).

`--ebpf` needs `CAP_BPF` in the initial user namespace, which no rootless container has, so
`test/ebpf/install-test.sh` (`just ebpf-install-vm-test`, CI job `ebpf-install`) boots a real
kernel in qemu with a Debian root file system built by podman and systemd as PID 1, and boots the
same disk twice. First boot: snapshot, a dry run as an unprivileged user (prints the unit, changes
nothing), an unprivileged install (refused), the install, the unit active and enabled, the control
group verified attached with the kernel, the drop-in's listener on `127.0.0.1:9793` and
`[::1]:9793`. An agent in `agents.slice` with no scrim configuration then runs curl against
`https://api.anthropic.com`, which resolves to a stand-in provider: scrim's transparent listener
gets the connection with its original destination, and scrim's upstream receives the request with
a placeholder where the generated secret was. Plain HTTP by address to ports 80 and 443 is
refused, connections made straight to the listener's port from outside the slice (no original
destination) are closed, the agent fails while scrim is stopped, the stand-in provider is never
reached directly, and a process outside the slice is untouched. Second boot: the unit attached
again before `scrim.service` started, the agent still redacted through scrim, then
`uninstall --purge` (no unit, no pins, nothing recorded, the slice reaches the stand-in directly
again), the file system identical to the snapshot, and a second uninstall that does nothing.

## Not covered yet

- Firefox profiles; Firefox uses its own store unless `security.enterprise_roots.enabled` is set.
- Managed agent settings (task 13.4); install will record those the same way.
- Transparent mode, eBPF and the DNS override on a Quadlet install: they need the system unit.
- A launch agent on macOS.
- Quadlet runs in the unit tests only; the VM test covers the system and user units.
