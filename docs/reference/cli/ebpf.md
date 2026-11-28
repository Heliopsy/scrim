# scrim ebpf

<!-- Generated from the command tree by `just cli-docs`. Do not edit. -->

Global flags are listed in [the CLI reference](README.md#global-flags).

## scrim ebpf

Attach, detach and inspect the eBPF transparent mode (Linux, cgroup v2).

```text
scrim ebpf [command]

The eBPF transparent mode attaches programs to the connect, sendmsg and egress hooks of selected control groups. Their
TCP connections to ports 80 and 443 of any address that is not loopback are rewritten to scrim's transparent listener on
127.0.0.1 and ::1 (interception.ebpf.port), their QUIC (UDP 443) is refused, and any packet to those ports that still
leaves for another address is dropped. Processes outside the control groups are not affected.

attach and detach are the privileged loader: they need root, or CAP_BPF and CAP_NET_ADMIN with write access to
/sys/fs/bpf/scrim. The programs stay attached when scrim or the loader stops, so covered connections then fail instead
of going direct; they last until `scrim ebpf detach` or a reboot. The listener itself is the transparent listener
(proxy.transparent-listen), which terminates TLS with scrim's CA: clients in the control groups must trust it.
```

| Subcommand | Description |
| --- | --- |
| [`scrim ebpf attach`](#scrim-ebpf-attach) | Attach the programs to the control groups (privileged; replaces an existing attachment in place) |
| [`scrim ebpf detach`](#scrim-ebpf-detach) | Detach the programs from the control groups (privileged) |
| [`scrim ebpf status`](#scrim-ebpf-status) | Report each covered control group; only a process with CAP_NET_ADMIN can confirm one as active |

## scrim ebpf attach

Attach the programs to the control groups (privileged; replaces an existing attachment in place).

```text
scrim ebpf attach [flags]
```

Flags:

```text
      --cgroup strings                   control group below /sys/fs/cgroup (repeatable; default
                                         interception.ebpf.cgroups)
      --no-listener-check[=true|false]   do not warn when nothing listens on the port yet (the boot unit of scrim
                                         install --ebpf attaches before scrim starts)
      --port int                         transparent listener port (default interception.ebpf.port) (default 9793)
```

## scrim ebpf detach

Detach the programs from the control groups (privileged).

```text
scrim ebpf detach [flags]

Removes the pinned links of each control group, which detaches its programs, and waits until the kernel confirms it.
With --all, every control group the loader's record lists. Afterwards the control groups reach providers directly again
unless another mode covers them.
```

Flags:

```text
      --all[=true|false]   detach every control group the loader attached
      --cgroup strings     control group below /sys/fs/cgroup (repeatable; default interception.ebpf.cgroups)
```

## scrim ebpf status

Report each covered control group; only a process with CAP_NET_ADMIN can confirm one as active.

```text
scrim ebpf status [flags]
```

Flags:

```text
      --json[=true|false]   shorthand for --output json
  -o, --output string       output format: text or json (default "text")
```
