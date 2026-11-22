#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# VM test of `scrim install --system --ebpf` and `scrim uninstall` (tasks.md
# 15.1a). The eBPF loader needs CAP_BPF in the initial user namespace, which a
# rootless container never has, so this boots a real kernel in qemu with a
# Debian root file system whose PID 1 is systemd. It boots the disk twice:
#
#   1. snapshot, dry run, install, an agent in agents.slice reaches the
#      provider through scrim (redacted) and fails while scrim is stopped,
#      a process outside the slice is untouched; power off.
#   2. after the reboot scrim-ebpf.service attached again before scrim.service
#      started, the agent is still redirected; uninstall --purge detaches,
#      the agent reaches the stand-in provider directly again, the file system
#      matches the snapshot, and a second uninstall is a no-op.
#
# The guest side is test/ebpf/install-guest.sh. Nothing touches this host's
# kernel, systemd, bpffs or network: podman (rootless) builds the root file
# system, `podman unshare` turns it into an ext4 image with its owners, and
# qemu runs as the invoking user.
#
#   test/ebpf/install-test.sh                 # builds bin/scrim with `just build`
#   SCRIM_SVC_BIN=path/to/scrim SCRIM_VM_KERNEL=/path/to/vmlinuz test/ebpf/install-test.sh
#
# The kernel needs what test/ebpf/vm-test.sh needs; the virtio disk and ext4
# may be modules, which are copied from /lib/modules/<release> of the kernel
# (SCRIM_VM_MODULES overrides the directory). /dev/kvm is used when writable.
# SCRIM_SVC_KEEP_IMAGE=1 keeps the image. x86_64 only.
set -euo pipefail

export PATH="$PATH:/usr/sbin:/sbin"
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
image=localhost/scrim-ebpf-install:test
name="scrim-ebpf-rootfs-$$"
built_image=0

kernel="${SCRIM_VM_KERNEL:-}"
if [ -z "$kernel" ]; then
  for k in "/boot/vmlinuz-$(uname -r)" /boot/vmlinuz-*; do
    if [ -r "$k" ]; then kernel="$k"; break; fi
  done
fi
if [ -z "$kernel" ] || [ ! -r "$kernel" ]; then
  echo "install-test: no readable kernel; set SCRIM_VM_KERNEL to a vmlinuz (distribution kernels in /boot are often root-only)" >&2
  exit 2
fi
for t in qemu-system-x86_64 cpio mkfs.ext4 podman; do
  command -v "$t" >/dev/null || { echo "install-test: $t not installed" >&2; exit 2; }
done

work="$(mktemp -d "${TMPDIR:-/tmp}/scrim-ebpf-install.XXXXXX")"
cleanup() {
  podman rm -f -v "$name" >/dev/null 2>&1 || true
  if [ "$built_image" = 1 ] && [ -z "${SCRIM_SVC_KEEP_IMAGE:-}" ]; then
    podman rmi -f "$image" >/dev/null 2>&1 || true
  fi
  # The extracted tree belongs to the user namespace's IDs.
  podman unshare rm -rf "$work" 2>/dev/null || rm -rf "$work"
}
trap cleanup EXIT
log() { printf '\n== %s\n' "$*"; }

if [ -z "${SCRIM_SVC_BIN:-}" ]; then
  (cd "$root" && just build)
  SCRIM_SVC_BIN="$root/bin/scrim"
fi

log "guest files"
mkdir -p "$work/test" "$work/initrd/modules"
install -m 0755 "$SCRIM_SVC_BIN" "$work/test/scrim"
(cd "$root" && CGO_ENABLED=0 go build -trimpath -o "$work/test/scrim-fakeprovider" ./internal/testing/fakeprovider/cmd/scrim-fakeprovider)
install -m 0755 "$here/install-guest.sh" "$root/test/service/snapshot.sh" "$work/test/"
cat > "$work/test/scrim-vmtest.service" <<'EOF'
[Unit]
Description=scrim eBPF install VM test (test/ebpf/install-guest.sh)
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/opt/scrim-test/install-guest.sh
StandardOutput=tty
StandardError=tty
TTYPath=/dev/ttyS0

[Install]
WantedBy=multi-user.target
EOF

log "root file system"
if ! podman image exists "$image"; then
  podman build -q -t "$image" -f "$here/Containerfile.install" "$here" >/dev/null
  built_image=1
fi
podman create --name "$name" "$image" /bin/true >/dev/null
podman export -o "$work/rootfs.tar" "$name"
podman rm -f -v "$name" >/dev/null
truncate -s 2G "$work/disk.img"
# Inside the user namespace the archive's owners are the guest's (root is 0),
# and mkfs.ext4 -d copies them into the image.
podman unshare sh -euc '
  w="$1"
  mkdir "$w/rootfs"
  tar -C "$w/rootfs" -xf "$w/rootfs.tar"
  mkdir -p "$w/rootfs/opt/scrim-test/state"
  cp "$w/test/"* "$w/rootfs/opt/scrim-test/"
  mv "$w/rootfs/opt/scrim-test/scrim-vmtest.service" "$w/rootfs/etc/systemd/system/"
  ln -s /etc/systemd/system/scrim-vmtest.service "$w/rootfs/etc/systemd/system/multi-user.target.wants/scrim-vmtest.service"
  # A fixed machine ID: no first-boot setup between the two boots.
  echo 5c41ab0e2f7d4d0f9a3c6b1e8d2f4a70 > "$w/rootfs/etc/machine-id"
  echo scrim-ebpf-vm > "$w/rootfs/etc/hostname"
  mkfs.ext4 -q -F -L root -d "$w/rootfs" "$w/disk.img"
  rm -rf "$w/rootfs"
' sh "$work"
rm -f "$work/rootfs.tar"

log "initramfs"
release="$(file -bL "$kernel" | sed -n 's/.*version \([^ ]*\).*/\1/p')"
release="${release:-$(uname -r)}"
mods="${SCRIM_VM_MODULES:-/lib/modules/$release}"
n=0
if [ -d "$mods" ]; then
  # modprobe prints each module and its dependencies in load order, or
  # "builtin" for those compiled in.
  for m in virtio_pci virtio_blk ext4; do
    while read -r verb path _; do
      [ "$verb" = insmod ] || continue
      n=$((n + 1))
      out="$work/initrd/modules/$(printf '%02d' "$n")-$(basename "${path%%.ko*}").ko"
      case "$path" in
        *.zst) zstd -dqc "$path" >"$out" ;;
        *.xz) xz -dc "$path" >"$out" ;;
        *.gz) gzip -dc "$path" >"$out" ;;
        *) cp "$path" "$out" ;;
      esac
    done < <(modprobe -S "$release" --show-depends "$m" 2>/dev/null || true)
  done
fi
echo "kernel $kernel ($release), $n module(s) in the initramfs"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$work/initrd/init" "$root/test/ebpf/vmboot"
(cd "$work/initrd" && find . -mindepth 1 | cpio -o -H newc --quiet) >"$work/initrd.img"

accel=()
if [ -w /dev/kvm ]; then accel=(-enable-kvm -cpu host); fi
for phase in 1 2; do
  log "boot $phase"
  timeout "${SCRIM_VM_TIMEOUT:-600}" qemu-system-x86_64 "${accel[@]}" -m 2048 -smp 2 \
    -nographic -no-reboot -nodefaults -serial stdio -display none \
    -kernel "$kernel" -initrd "$work/initrd.img" \
    -drive "file=$work/disk.img,format=raw,if=virtio" \
    -append "console=ttyS0 panic=-1 quiet rdinit=/init systemd.show_status=0 systemd.log_level=warning" \
    | tee "$work/console-$phase.log"
  result="$(grep -ao 'SCRIM-VM-RESULT [0-9]*' "$work/console-$phase.log" | tail -1 | cut -d' ' -f2)"
  if [ "$result" != 0 ]; then
    echo "install-test: FAIL in boot $phase (result ${result:-missing})" >&2
    exit 1
  fi
done
echo "install-test: PASS"
