// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package bpfredirect

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

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

// serveListener answers every TCP connection on addr as scrim's
// transparent listener sees it: name, then the original destination the
// listener reads with SO_ORIGINAL_DST, or "none". Before reading it, the
// listener calls before (when set). With clientCloses it waits for the
// client to close first, otherwise it closes first.
func (e *kernelEnv) serveListener(network, addr, name string, clientCloses bool, before func()) net.Listener {
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
			if before != nil {
				before()
			}
			orig := "none"
			if o, err := originalDst(c.(*net.TCPConn)); err == nil {
				orig = o.String()
			}
			_, _ = c.Write([]byte(name + " " + orig + "\n"))
			if clientCloses {
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				_, _ = io.Copy(io.Discard, c)
			}
			_ = c.Close()
		}
	}()
	return ln
}

// originalDst is what the data plane's original_dst does
// (dataplane/crates/scrim-dataplane/src/listeners.rs): SO_ORIGINAL_DST at
// SOL_IP for an IPv4 or IPv4-mapped local address, IP6T_SO_ORIGINAL_DST at
// SOL_IPV6 otherwise. The getsockopt wrappers are borrowed for their buffer
// sizes: IPv6Mreq (20 bytes) holds a sockaddr_in, IPv6MTUInfo (32 bytes)
// starts with a sockaddr_in6.
func originalDst(c *net.TCPConn) (netip.AddrPort, error) {
	const soOriginalDst = 80
	rc, err := c.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	local := c.LocalAddr().(*net.TCPAddr).AddrPort()
	var (
		orig netip.AddrPort
		gerr error
	)
	err = rc.Control(func(fd uintptr) {
		if local.Addr().Unmap().Is4() {
			m, err := unix.GetsockoptIPv6Mreq(int(fd), unix.SOL_IP, soOriginalDst) // #nosec G115 -- an fd
			if err != nil {
				gerr = err
				return
			}
			b := m.Multiaddr
			if f := binary.NativeEndian.Uint16(b[0:2]); f != unix.AF_INET {
				gerr = fmt.Errorf("family %d", f)
				return
			}
			orig = netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[4:8])), binary.BigEndian.Uint16(b[2:4]))
			return
		}
		m, err := unix.GetsockoptIPv6MTUInfo(int(fd), unix.SOL_IPV6, soOriginalDst) // #nosec G115 -- an fd
		if err != nil {
			gerr = err
			return
		}
		if m.Addr.Family != unix.AF_INET6 {
			gerr = fmt.Errorf("family %d", m.Addr.Family)
			return
		}
		port := binary.BigEndian.Uint16(binary.NativeEndian.AppendUint16(nil, m.Addr.Port))
		orig = netip.AddrPortFrom(netip.AddrFrom16(m.Addr.Addr), port)
	})
	if err != nil {
		return netip.AddrPort{}, err
	}
	return orig, gerr
}

// connMaps opens the maps of an attachment's sockops program.
func connMaps(t *testing.T, a Attachment) (pending, conns *ebpf.Map) {
	t.Helper()
	prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(a.Programs["sockops"]))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = prog.Close() }()
	info, err := prog.Info()
	if err != nil {
		t.Fatal(err)
	}
	ids, _ := info.MapIDs()
	for _, id := range ids {
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			t.Fatal(err)
		}
		mi, err := m.Info()
		if err != nil {
			t.Fatal(err)
		}
		switch mi.Name {
		case "scrim_pending":
			pending = m
		case "scrim_origdst":
			conns = m
		default:
			_ = m.Close()
		}
	}
	if pending == nil || conns == nil {
		t.Fatalf("maps of program %d: %v", a.Programs["sockops"], ids)
	}
	t.Cleanup(func() { _ = pending.Close(); _ = conns.Close() })
	return pending, conns
}

func countEntries(m *ebpf.Map) int {
	n := 0
	var k, v []byte
	it := m.Iterate()
	for it.Next(&k, &v) {
		n++
	}
	return n
}

// expectNoEntries waits for an attachment's maps to empty once its
// connections closed.
func expectNoEntries(t *testing.T, a Attachment) {
	t.Helper()
	pending, conns := connMaps(t, a)
	var np, nc int
	for range 100 {
		if np, nc = countEntries(pending), countEntries(conns); np == 0 && nc == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("%d pending and %d connection entries left after every connection closed", np, nc)
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
	// wipe, when set, empties the connection map before the listener reads
	// the original destination: a missing entry.
	var wipe atomic.Pointer[ebpf.Map]
	before := func() {
		if m := wipe.Load(); m != nil {
			var k, v []byte
			for it := m.Iterate(); it.Next(&k, &v); {
				_ = m.Delete(k)
			}
		}
	}
	scrim4 := e.serveListener("tcp4", hp("127.0.0.1", port), "scrim", true, before)
	e.serveListener("tcp6", hp("::1", port), "scrim", true, before)
	e.serveListener("tcp4", hp("127.0.0.1", port2), "scrim2", false, nil)
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

	t.Run("redirect with the original destination", func(t *testing.T) {
		e.t = t
		for _, cg := range []string{in, nested} {
			e.expect(cg, "tcp4", hp(t4, 443), "ok scrim "+hp(t4, 443))
			e.expect(cg, "tcp4", hp(t4, 80), "ok scrim "+hp(t4, 80))
			e.expect(cg, "tcp6", hp(t6, 443), "ok scrim "+hp(t6, 443))
			// The dual-stack socket lands on the IPv4 listener, which
			// reads an IPv4 destination.
			e.expect(cg, "tcp6", hp(mapped, 443), "ok scrim "+hp(t4, 443))
			e.expect(cg, "tcp4", hp(t4, 8443), "ok provider")
			// Not redirected: no original destination.
			e.expect(cg, "tcp4", hp("127.0.0.1", port), "ok scrim none")
		}
		// A connection to the listener from outside the covered control
		// groups has none either.
		e.expect(out, "tcp4", hp("127.0.0.1", port), "ok scrim none")
		e.expect(out, "tcp6", hp("::1", port), "ok scrim none")
	})
	t.Run("entries go when the client closes first", func(t *testing.T) {
		e.t = t
		expectNoEntries(t, a)
	})
	t.Run("a missing entry fails closed", func(t *testing.T) {
		e.t = t
		_, conns := connMaps(t, a)
		wipe.Store(conns)
		defer wipe.Store(nil)
		e.expect(in, "tcp4", hp(t4, 443), "ok scrim none")
		e.expect(in, "tcp6", hp(t6, 443), "ok scrim none")
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
		if err != nil || len(got["egress"]) != 1 || got["egress"][0] != a.Programs["egress"] ||
			!slices.Contains(got["sockops"], a.Programs["sockops"]) {
			t.Fatalf("query: %v %v", got, err)
		}
		got, err = queryKernel(CgroupRoot)
		if err != nil || !slices.Contains(got["getsockopt"], a.Programs["getsockopt"]) {
			t.Fatalf("query %s: %v %v", CgroupRoot, got, err)
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
		e.expect(in, "tcp4", hp(t4, 443), "ok scrim2 "+hp(t4, 443))
		e.expect(in, "tcp6", hp(mapped, 80), "ok scrim2 "+hp(t4, 80))
		// This listener closes first.
		expectNoEntries(t, b)
		if got, _ := queryKernel(CgroupRoot); slices.Contains(got["getsockopt"], a.Programs["getsockopt"]) {
			t.Errorf("the old getsockopt program %d is still attached to %s", a.Programs["getsockopt"], CgroupRoot)
		}
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
		if got, _ := queryKernel(CgroupRoot); slices.Contains(got["getsockopt"], a.Programs["getsockopt"]) {
			t.Errorf("getsockopt program %d still attached to %s", a.Programs["getsockopt"], CgroupRoot)
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
