// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package bpfredirect

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// The kernel test needs root on a throwaway kernel: it creates control
// groups, loads and attaches programs and pins links. test/ebpf/vm-test.sh
// (`just ebpf-vm-test`) boots one in qemu with this test binary as the only
// workload and sets these variables; anywhere else the test is skipped.
//
//	SCRIM_TEST_EBPF=1                  run it
//	SCRIM_TEST_EBPF_TARGET4=10.99.0.1  a non-loopback local IPv4 address
//	SCRIM_TEST_EBPF_TARGET6=2001:db8::99
//
// The targets stand in for a provider: the test listens on them from outside
// every covered control group, so a connection that reaches them went direct.
const childEnv = "SCRIM_TEST_EBPF_CHILD"

func TestMain(m *testing.M) {
	if op := os.Getenv(childEnv); op != "" {
		os.Exit(child(op))
	}
	os.Exit(m.Run())
}

// child runs one network operation from inside a control group and prints
// "ok <reply>" or "err <errno>".
func child(op string) int {
	kind, addr, _ := strings.Cut(op, " ")
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		fmt.Println("err", err) //nolint:forbidigo // child protocol
		return 0
	}
	reply, err := dialRaw(kind, ap)
	if err != nil {
		var errno unix.Errno
		if errors.Is(err, unix.EINPROGRESS) || errors.Is(err, unix.EAGAIN) {
			// SO_SNDTIMEO or SO_RCVTIMEO expired: nothing answered.
			fmt.Println("err timeout") //nolint:forbidigo // child protocol
		} else if errors.As(err, &errno) {
			fmt.Println("err", unix.ErrnoName(errno)) //nolint:forbidigo // child protocol
		} else {
			fmt.Println("err", err) //nolint:forbidigo // child protocol
		}
		return 0
	}
	fmt.Println("ok", reply) //nolint:forbidigo // child protocol
	return 0
}

// dialRaw uses the socket calls directly, so the address family and the
// IPv4-mapped form are exactly what the test asks for.
func dialRaw(kind string, ap netip.AddrPort) (string, error) {
	var (
		family int
		sa     unix.Sockaddr
	)
	if strings.HasPrefix(kind, "tcp6") || strings.HasPrefix(kind, "udp6") {
		family, sa = unix.AF_INET6, &unix.SockaddrInet6{Port: int(ap.Port()), Addr: ap.Addr().As16()}
	} else {
		family, sa = unix.AF_INET, &unix.SockaddrInet4{Port: int(ap.Port()), Addr: ap.Addr().As4()}
	}
	typ := unix.SOCK_STREAM
	if strings.HasPrefix(kind, "udp") {
		typ = unix.SOCK_DGRAM
	}
	fd, err := unix.Socket(family, typ, 0)
	if err != nil {
		return "", err
	}
	defer func() { _ = unix.Close(fd) }()
	if family == unix.AF_INET6 {
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 0)
	}
	tv := unix.Timeval{Sec: 1}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)
	switch kind {
	case "udp4-send", "udp6-send":
		return "sent", unix.Sendto(fd, []byte("x"), 0, sa)
	case "udp4", "udp6":
		if err := unix.Connect(fd, sa); err != nil {
			return "", err
		}
		_, err := unix.Write(fd, []byte("x"))
		return "sent", err
	}
	if err := unix.Connect(fd, sa); err != nil {
		return "", err
	}
	buf := make([]byte, 64)
	n, err := unix.Read(fd, buf)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buf[:n])), nil
}

type kernelEnv struct {
	t       *testing.T
	target4 string
	target6 string
	cgroups []string
}

func newKernelEnv(t *testing.T) *kernelEnv {
	if os.Getenv("SCRIM_TEST_EBPF") != "1" {
		t.Skip("needs root on a throwaway kernel; run `just ebpf-vm-test`")
	}
	e := &kernelEnv{t: t, target4: os.Getenv("SCRIM_TEST_EBPF_TARGET4"), target6: os.Getenv("SCRIM_TEST_EBPF_TARGET6")}
	if e.target4 == "" || e.target6 == "" {
		t.Fatal("SCRIM_TEST_EBPF_TARGET4 and SCRIM_TEST_EBPF_TARGET6 must name non-loopback local addresses")
	}
	t.Cleanup(func() {
		for i := len(e.cgroups) - 1; i >= 0; i-- {
			_ = os.Remove(filepath.Join(CgroupRoot, e.cgroups[i]))
		}
	})
	return e
}

func (e *kernelEnv) cgroup(name string) string {
	e.t.Helper()
	if err := os.Mkdir(filepath.Join(CgroupRoot, name), 0o755); err != nil {
		e.t.Fatal(err)
	}
	e.cgroups = append(e.cgroups, name)
	return name
}

// serve answers every TCP connection on addr with name.
func (e *kernelEnv) serve(network, addr, name string) net.Listener {
	e.t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte(name + "\n"))
			_ = c.Close()
		}
	}()
	return ln
}

// run performs op from inside a control group.
func (e *kernelEnv) run(cgroup, kind, addr string) string {
	e.t.Helper()
	f, err := os.Open(filepath.Join(CgroupRoot, cgroup))
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	cmd := exec.Command(os.Args[0]) // #nosec G204 -- the test binary itself
	cmd.Env = append(os.Environ(), childEnv+"="+kind+" "+addr)
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(f.Fd())}
	out, err := cmd.Output()
	if err != nil {
		e.t.Fatalf("child %s %s in %s: %v", kind, addr, cgroup, err)
	}
	return strings.TrimSpace(string(out))
}

func (e *kernelEnv) expect(cgroup, kind, addr, want string) {
	e.t.Helper()
	if got := e.run(cgroup, kind, addr); got != want {
		e.t.Errorf("%s %s from %s: got %q, want %q", kind, addr, cgroup, got, want)
	}
}

func hp(h string, p int) string { return net.JoinHostPort(h, strconv.Itoa(p)) }

// TestKernelRedirectAndDeny is tasks.md 15.1's verify: per-cgroup redirect
// and direct-egress denial on a real kernel.
func TestKernelRedirectAndDeny(t *testing.T) {
	e := newKernelEnv(t)
	const port, port2 = 19792, 19793
	t4, t6 := e.target4, e.target6
	mapped := "::ffff:" + t4

	for _, p := range []int{80, 443, 8443} {
		e.serve("tcp4", hp(t4, p), "provider")
		e.serve("tcp6", hp(t6, p), "provider")
	}
	scrim4 := e.serve("tcp4", hp("127.0.0.1", port), "scrim")
	e.serve("tcp6", hp("::1", port), "scrim")
	e.serve("tcp4", hp("127.0.0.1", port2), "scrim2")
	udp, err := net.ListenPacket("udp4", hp(t4, 443))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udp.Close() }()

	in := e.cgroup("scrim-test-in")
	nested := e.cgroup("scrim-test-in/agent")
	out := e.cgroup("scrim-test-out")

	// Without the programs every covered connection goes direct: this is
	// what the assertions below catch when the redirect is broken.
	e.expect(in, "tcp4", hp(t4, 443), "ok provider")
	e.expect(in, "udp4-send", hp(t4, 443), "ok sent")

	dir := t.TempDir()
	l := Loader{PinRoot: filepath.Join(PinRoot, "test"), RecordPath: filepath.Join(dir, "attachments.json")}
	t.Cleanup(func() { _ = os.RemoveAll(l.PinRoot) })
	a, err := l.Attach(in, port)
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	// Attach closed every descriptor: only the pins keep the links.

	t.Run("redirect", func(t *testing.T) {
		e.t = t
		for _, cg := range []string{in, nested} {
			e.expect(cg, "tcp4", hp(t4, 443), "ok scrim")
			e.expect(cg, "tcp4", hp(t4, 80), "ok scrim")
			e.expect(cg, "tcp6", hp(t6, 443), "ok scrim")
			e.expect(cg, "tcp6", hp(mapped, 443), "ok scrim")
			e.expect(cg, "tcp4", hp(t4, 8443), "ok provider")
			e.expect(cg, "tcp4", hp("127.0.0.1", port), "ok scrim")
		}
	})
	t.Run("deny", func(t *testing.T) {
		e.t = t
		e.expect(in, "udp4-send", hp(t4, 443), "err EPERM")
		e.expect(in, "udp4", hp(t4, 443), "err EPERM")
		e.expect(in, "udp6-send", hp(t6, 443), "err EPERM")
		e.expect(in, "udp6-send", hp(mapped, 443), "err EPERM")
		e.expect(in, "udp4-send", hp(t4, 53), "ok sent")
	})
	t.Run("other control groups untouched", func(t *testing.T) {
		e.t = t
		e.expect(out, "tcp4", hp(t4, 443), "ok provider")
		e.expect(out, "tcp6", hp(t6, 443), "ok provider")
		e.expect(out, "udp4-send", hp(t4, 443), "ok sent")
	})
	t.Run("status", func(t *testing.T) {
		e.t = t
		in2 := Inspector{RecordPath: l.RecordPath}
		r := Inspect(in2, []string{in}, port)
		if r == nil || len(r.Cgroups) != 1 || r.Cgroups[0].State != Active || !r.ListenerUp {
			t.Fatalf("root inspect: %+v", r)
		}
		in2.Caps = func() Caps { return 0 }
		if r := Inspect(in2, []string{in}, port); r.Cgroups[0].State != Unverified {
			t.Fatalf("unprivileged inspect: %+v", r.Cgroups[0])
		}
		// The kernel lists the very programs the record names.
		got, err := queryKernel(filepath.Join(CgroupRoot, in))
		if err != nil || len(got["egress"]) != 1 || got["egress"][0] != a.Programs["egress"] {
			t.Fatalf("query: %v %v", got, err)
		}
	})
	t.Run("fails closed without a listener", func(t *testing.T) {
		e.t = t
		_ = scrim4.Close()
		e.expect(in, "tcp4", hp(t4, 443), "err ECONNREFUSED")
	})
	t.Run("replace keeps the group covered", func(t *testing.T) {
		e.t = t
		b, err := l.Attach(in, port2)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(a.PinDir); !os.IsNotExist(err) {
			t.Errorf("old pins %s still there: %v", a.PinDir, err)
		}
		e.expect(in, "tcp4", hp(t4, 443), "ok scrim2")
		a = b
	})
	t.Run("detach", func(t *testing.T) {
		e.t = t
		if err := l.Detach(in); err != nil {
			t.Fatal(err)
		}
		e.expect(in, "tcp4", hp(t4, 443), "ok provider")
		e.expect(in, "udp4-send", hp(t4, 443), "ok sent")
		if _, err := os.Stat(a.PinDir); !os.IsNotExist(err) {
			t.Errorf("pins %s still there: %v", a.PinDir, err)
		}
		rec, err := ReadRecord(l.RecordPath)
		if err != nil || len(rec.Attachments) != 0 {
			t.Errorf("record after detach: %+v %v", rec, err)
		}
		if r := Inspect(Inspector{RecordPath: l.RecordPath}, []string{in}, port); r.Cgroups[0].State != NotAttached {
			t.Errorf("inspect after detach: %+v", r.Cgroups[0])
		}
	})
}

// TestKernelEgressDenyAlone attaches only the egress program, so the deny is
// shown to hold on its own, for whatever reaches the wire without passing
// the connect hooks.
func TestKernelEgressDenyAlone(t *testing.T) {
	e := newKernelEnv(t)
	t4, t6 := e.target4, e.target6
	for _, p := range []int{80, 443, 8443} {
		e.serve("tcp4", hp(t4, p), "provider")
		e.serve("tcp6", hp(t6, p), "provider")
	}
	cg := e.cgroup("scrim-test-egress")
	e.expect(cg, "tcp4", hp(t4, 443), "ok provider")

	spec, err := loadRedirect()
	if err != nil {
		t.Fatal(err)
	}
	var objs redirectObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = objs.Close() }()
	lk, err := link.AttachCgroup(link.CgroupOptions{Path: filepath.Join(CgroupRoot, cg), Attach: ebpf.AttachCGroupInetEgress, Program: objs.ScrimEgress})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lk.Close() }()

	// A dropped SYN is retransmitted until the connect times out.
	e.expect(cg, "tcp4", hp(t4, 443), "err timeout")
	e.expect(cg, "tcp6", hp(t6, 443), "err timeout")
	e.expect(cg, "tcp4", hp(t4, 80), "err timeout")
	e.expect(cg, "udp4-send", hp(t4, 443), "err EPERM")
	e.expect(cg, "tcp4", hp(t4, 8443), "ok provider")
	e.expect(cg, "tcp6", hp(t6, 8443), "ok provider")
}

// TestKernelLoadVerifies loads every program, so the verifier's verdict on
// the committed objects is part of the kernel run.
func TestKernelLoadVerifies(t *testing.T) {
	newKernelEnv(t)
	spec, err := loadRedirect()
	if err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats}})
	if err != nil {
		t.Fatalf("%+v", err)
	}
	defer coll.Close()
	for name, p := range coll.Programs {
		info, err := p.Info()
		if err != nil {
			t.Fatal(err)
		}
		insns, _ := info.Instructions()
		t.Logf("%s: %d instructions, verifier: %s", name, len(insns), strings.TrimSpace(p.VerifierLog))
	}
}
