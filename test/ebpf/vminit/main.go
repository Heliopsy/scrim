// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

// Command vminit is PID 1 of the throwaway kernel test/ebpf/vm-test.sh
// boots: it mounts what the eBPF kernel test needs, gives the loopback
// interface two addresses that stand in for a provider, runs /ebpf.test
// and powers the machine off. The serial console carries the test output
// and a final "SCRIM-VM-RESULT <exit code>" line.
package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	target4 = "10.99.0.1"
	target6 = "2001:db8::99"
)

func main() {
	code := run()
	fmt.Printf("SCRIM-VM-RESULT %d\n", code) //nolint:forbidigo // the serial console is the only output
	_ = os.Stdout.Sync()
	unix.Sync()
	_ = unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
	time.Sleep(time.Minute)
}

func run() int {
	for _, m := range []struct{ src, dst, typ string }{
		{"proc", "/proc", "proc"},
		{"sysfs", "/sys", "sysfs"},
		{"devtmpfs", "/dev", "devtmpfs"},
		{"tmpfs", "/tmp", "tmpfs"},
		{"tmpfs", "/run", "tmpfs"},
		{"cgroup2", "/sys/fs/cgroup", "cgroup2"},
		{"bpf", "/sys/fs/bpf", "bpf"},
	} {
		_ = os.MkdirAll(m.dst, 0o755)
		if err := unix.Mount(m.src, m.dst, m.typ, 0, ""); err != nil {
			fail("mount %s: %v", m.dst, err)
			return 2
		}
	}
	if err := loopbackUp(); err != nil {
		fail("loopback: %v", err)
		return 2
	}
	for _, a := range []string{target4 + "/32", target6 + "/128"} {
		if err := addAddr(netip.MustParsePrefix(a)); err != nil {
			fail("address %s: %v", a, err)
			return 2
		}
	}
	var uts unix.Utsname
	_ = unix.Uname(&uts)
	fmt.Printf("kernel %s\n", unix.ByteSliceToString(uts.Release[:])) //nolint:forbidigo // console

	args := append([]string{"-test.v", "-test.count=1"}, strings.Fields(os.Getenv("SCRIM_VM_TEST_ARGS"))...)
	cmd := exec.Command("/ebpf.test", args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.Env = []string{
		"PATH=/", "HOME=/tmp", "TMPDIR=/tmp",
		"SCRIM_TEST_EBPF=1", "SCRIM_TEST_EBPF_TARGET4=" + target4, "SCRIM_TEST_EBPF_TARGET6=" + target6,
	}
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok { //nolint:errorlint // direct result of Run
			return ee.ExitCode()
		}
		fail("run: %v", err)
		return 2
	}
	return 0
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "vminit: "+format+"\n", args...)
}

func loopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

// addAddr adds an address to lo with one RTM_NEWADDR netlink request.
func addAddr(p netip.Prefix) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	family, addr := uint8(unix.AF_INET), p.Addr().AsSlice()
	if p.Addr().Is6() {
		family = unix.AF_INET6
	}
	attr := func(typ uint16, data []byte) []byte {
		b := make([]byte, unix.SizeofRtAttr, unix.SizeofRtAttr+len(data)+3)
		binary.NativeEndian.PutUint16(b[0:], uint16(unix.SizeofRtAttr+len(data))) // #nosec G115 -- small
		binary.NativeEndian.PutUint16(b[2:], typ)
		b = append(b, data...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		return b
	}
	body := []byte{family, uint8(p.Bits()), unix.IFA_F_NODAD, unix.RT_SCOPE_HOST, 1, 0, 0, 0} // ifaddrmsg, lo is index 1
	body = append(body, attr(unix.IFA_LOCAL, addr)...)
	body = append(body, attr(unix.IFA_ADDRESS, addr)...)
	msg := make([]byte, unix.SizeofNlMsghdr, unix.SizeofNlMsghdr+len(body))
	binary.NativeEndian.PutUint32(msg[0:], uint32(unix.SizeofNlMsghdr+len(body))) // #nosec G115 -- small
	binary.NativeEndian.PutUint16(msg[4:], unix.RTM_NEWADDR)
	binary.NativeEndian.PutUint16(msg[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_EXCL)
	binary.NativeEndian.PutUint32(msg[8:], 1)
	msg = append(msg, body...)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return err
	}
	if n < unix.SizeofNlMsghdr+4 || binary.NativeEndian.Uint16(buf[4:]) != unix.NLMSG_ERROR {
		return fmt.Errorf("unexpected netlink reply of %d bytes", n)
	}
	if e := int32(binary.NativeEndian.Uint32(buf[unix.SizeofNlMsghdr:])); e != 0 { // #nosec G115 -- errno
		return unix.Errno(-e)
	}
	return nil
}
