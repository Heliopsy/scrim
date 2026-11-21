#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Kernel test of the eBPF transparent mode (tasks.md 15.1): boots a Linux
# kernel in qemu with an initramfs holding only test/ebpf/vminit as PID 1 and
# the internal/bpfredirect test binary, which then runs as root on that
# kernel: it creates control groups, loads and attaches the programs, checks
# per-cgroup redirect and direct-egress denial, and detaches them. Nothing
# touches this host's kernel, control groups or network; qemu runs as the
# invoking user.
#
#   test/ebpf/vm-test.sh                       # kernel from SCRIM_VM_KERNEL or /boot
#   SCRIM_VM_KERNEL=/path/to/vmlinuz test/ebpf/vm-test.sh
#   SCRIM_VM_TEST_ARGS='-test.run TestKernelEgressDenyAlone' test/ebpf/vm-test.sh
#
# The kernel needs cgroup v2, BPF syscall and cgroup BPF, BPF links (5.7 or
# later), clone3 into a cgroup, IPv6 and an 8250 serial console built in, as
# distribution kernels (Debian, Ubuntu, Fedora) have. /dev/kvm is used when
# it is writable; without it qemu emulates, slowly. x86_64 only.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"

kernel="${SCRIM_VM_KERNEL:-}"
if [ -z "$kernel" ]; then
  for k in "/boot/vmlinuz-$(uname -r)" /boot/vmlinuz-*; do
    if [ -r "$k" ]; then kernel="$k"; break; fi
  done
fi
if [ -z "$kernel" ] || [ ! -r "$kernel" ]; then
  echo "vm-test: no readable kernel; set SCRIM_VM_KERNEL to a vmlinuz (distribution kernels in /boot are often root-only)" >&2
  exit 2
fi
command -v qemu-system-x86_64 >/dev/null || { echo "vm-test: qemu-system-x86_64 not installed" >&2; exit 2; }
command -v cpio >/dev/null || { echo "vm-test: cpio not installed" >&2; exit 2; }

work="$(mktemp -d "${TMPDIR:-/tmp}/scrim-ebpf-vm.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/root"

cd "$root"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o "$work/root/ebpf.test" ./internal/bpfredirect
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$work/root/init" ./test/ebpf/vminit
(cd "$work/root" && printf '%s\n' init ebpf.test | cpio -o -H newc --quiet) >"$work/initrd"

accel=()
if [ -w /dev/kvm ]; then accel=(-enable-kvm -cpu host); fi
echo "vm-test: booting $kernel"
timeout "${SCRIM_VM_TIMEOUT:-600}" qemu-system-x86_64 "${accel[@]}" -m 1024 -smp 2 \
  -nographic -no-reboot -nodefaults -serial stdio -display none \
  -kernel "$kernel" -initrd "$work/initrd" \
  -append "console=ttyS0 panic=-1 quiet rdinit=/init SCRIM_VM_TEST_ARGS=\"${SCRIM_VM_TEST_ARGS:-}\"" \
  | tee "$work/console.log"

result="$(grep -ao 'SCRIM-VM-RESULT [0-9]*' "$work/console.log" | tail -1 | cut -d' ' -f2)"
if [ "$result" != 0 ]; then
  echo "vm-test: FAIL (result ${result:-missing})" >&2
  exit 1
fi
echo "vm-test: PASS"
