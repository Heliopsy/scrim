// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

// Command vmboot is the initramfs init of test/ebpf/install-test.sh: it
// loads the kernel modules the script copied into /modules (the virtio disk
// and ext4 where the kernel has them as modules), mounts the root file
// system from /dev/vda and hands over to its systemd, as an initramfs would
// on a real machine.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"golang.org/x/sys/unix"
)

func main() {
	if err := boot(); err != nil {
		fmt.Fprintf(os.Stderr, "vmboot: %v\nSCRIM-VM-RESULT 2\n", err)
		unix.Sync()
		_ = unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
		time.Sleep(time.Minute)
	}
}

func boot() error {
	for _, m := range []struct{ src, dst, typ string }{
		{"proc", "/proc", "proc"},
		{"sysfs", "/sys", "sysfs"},
		{"devtmpfs", "/dev", "devtmpfs"},
	} {
		_ = os.MkdirAll(m.dst, 0o755)
		if err := unix.Mount(m.src, m.dst, m.typ, 0, ""); err != nil {
			return fmt.Errorf("mount %s: %w", m.dst, err)
		}
	}
	mods, _ := filepath.Glob("/modules/*.ko")
	slices.Sort(mods)
	for _, m := range mods {
		if err := load(m); err != nil {
			return fmt.Errorf("load %s: %w", m, err)
		}
	}
	var err error
	for range 100 {
		if _, err = os.Stat("/dev/vda"); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		return fmt.Errorf("no root disk: %w", err)
	}
	if err := os.MkdirAll("/newroot", 0o755); err != nil {
		return err
	}
	if err := unix.Mount("/dev/vda", "/newroot", "ext4", 0, ""); err != nil {
		return fmt.Errorf("mount /dev/vda: %w", err)
	}
	for _, d := range []string{"/proc", "/sys", "/dev"} {
		if err := unix.Unmount(d, unix.MNT_DETACH); err != nil {
			return fmt.Errorf("unmount %s: %w", d, err)
		}
	}
	// switch_root: the initramfs cannot be pivoted away, so the new root is
	// moved over / and entered with chroot.
	if err := unix.Chdir("/newroot"); err != nil {
		return err
	}
	if err := unix.Mount(".", "/", "", unix.MS_MOVE, ""); err != nil {
		return fmt.Errorf("move the root: %w", err)
	}
	if err := unix.Chroot("."); err != nil {
		return err
	}
	if err := unix.Chdir("/"); err != nil {
		return err
	}
	return unix.Exec("/sbin/init", []string{"/sbin/init"}, os.Environ())
}

// load inserts a module; one the kernel already has is not an error.
func load(path string) error {
	f, err := os.Open(path) // #nosec G304 -- the initramfs' own modules
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	err = unix.FinitModule(int(f.Fd()), "", 0) // #nosec G115 -- an fd
	if err == unix.EEXIST {                    //nolint:errorlint // a raw errno
		return nil
	}
	return err
}
