// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package fsview

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// HelperName is argv[0] of the scrim executable started to set up the
// namespace view; ProbeName of the one that only checks it can.
const (
	HelperName = "scrim-fsview"
	ProbeName  = "scrim-fsview-probe"
)

// Status bytes on the helper's status pipe: ready is written just before
// the agent is executed (the pipe then closes on exec), failed precedes an
// error message.
const (
	statusReady  = 'R'
	statusFailed = 'E'
	probeOK      = "scrim-fsview-ok"
)

// Inherited descriptors in the helper. fdNet, present with a network
// namespace only, is a Unix socket the listening sockets go back on.
const (
	fdSpec   = 3
	fdStatus = 4
	fdNet    = 5
)

// probeNetArg asks the probe to check the network namespace as well.
const probeNetArg = "net"

// maxListeners bounds the listening sockets one helper hands back.
const maxListeners = 32

// spec is what the helper receives on fdSpec.
type spec struct {
	Path    string   `json:"path"`
	Args    []string `json:"args"`
	Mounts  []mount  `json:"mounts"`
	Network *Network `json:"network,omitempty"`
}

type mount struct {
	Source string `json:"source"`
	Target string `json:"target"`
	// ReadOnly remounts the bind read-only (hidden paths).
	ReadOnly bool `json:"read_only,omitempty"`
}

// Main runs the helper when this process was started as one, and never
// returns then. Call it first thing in main and in TestMain.
func Main() {
	switch filepath.Base(os.Args[0]) {
	case HelperName:
		os.Exit(helper())
	case ProbeName:
		os.Exit(probe())
	}
}

// probe checks it can make the mount tree private and bind-mount a file in
// its new namespace: what the helper does.
func probe() int {
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "making the mount tree private: %v\n", err)
		return 1
	}
	exe, err := os.Executable()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	if err := unix.Mount(exe, exe, "", unix.MS_BIND, ""); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "bind mount: %v\n", err)
		return 1
	}
	if len(os.Args) > 1 && os.Args[1] == probeNetArg {
		if err := loopbackUp(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
			return 1
		}
		fd, err := listenFD(Listen{Addr: "127.0.0.1:0"})
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
			return 1
		}
		_ = unix.Close(fd)
	}
	_, _ = fmt.Fprintln(os.Stdout, probeOK)
	return 0
}

func helper() int {
	statusOut := os.NewFile(fdStatus, "status")
	fail := func(format string, a ...any) int {
		if statusOut != nil {
			_, _ = statusOut.Write(append([]byte{statusFailed}, fmt.Sprintf(format, a...)...))
		}
		return 125
	}
	in := os.NewFile(fdSpec, "spec")
	if in == nil || statusOut == nil {
		return fail("the filesystem view helper was started without its descriptors")
	}
	data, err := io.ReadAll(in)
	_ = in.Close()
	if err != nil {
		return fail("reading the view: %v", err)
	}
	var s spec
	if err := json.Unmarshal(data, &s); err != nil || s.Path == "" || len(s.Args) == 0 {
		return fail("the filesystem view helper got no usable view")
	}
	// The thread that drops the capabilities is the one that executes the
	// agent.
	runtime.LockOSThread()
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fail("making the session's mount tree private failed: %v", err)
	}
	for _, m := range s.Mounts {
		if err := unix.Mount(m.Source, m.Target, "", unix.MS_BIND, ""); err != nil {
			return fail("mounting the session's view over %s failed: %v", m.Target, err)
		}
		if m.ReadOnly {
			// Keep the flags the kernel locked (nosuid, nodev, ...) and
			// add rdonly.
			flags := uintptr(0)
			var st unix.Statfs_t
			if err := unix.Statfs(m.Target, &st); err == nil {
				for stf, msf := range map[int64]uintptr{unix.ST_NOSUID: unix.MS_NOSUID, unix.ST_NODEV: unix.MS_NODEV,
					unix.ST_NOEXEC: unix.MS_NOEXEC, unix.ST_NOATIME: unix.MS_NOATIME, unix.ST_NODIRATIME: unix.MS_NODIRATIME,
					unix.ST_RELATIME: unix.MS_RELATIME} {
					if st.Flags&stf != 0 {
						flags |= msf
					}
				}
			}
			if err := unix.Mount("", m.Target, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY|flags, ""); err != nil {
				return fail("making the hidden %s read-only failed: %v", m.Target, err)
			}
		}
	}
	if s.Network != nil {
		if msg := network(s.Network); msg != "" {
			return fail("%s", msg)
		}
	}
	// The agent runs with no capability: it cannot unmount the view, and
	// the kernel locks the mounts against a namespace it creates itself.
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fail("dropping capabilities failed: %v", err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fail("setting no_new_privs failed: %v", err)
	}
	unix.CloseOnExec(fdStatus)
	if _, err := statusOut.Write([]byte{statusReady}); err != nil {
		return 125
	}
	err = unix.Exec(s.Path, s.Args, os.Environ())
	// The ready byte is already written; a second message follows it.
	return fail("starting %s failed: %v", s.Args[0], err)
}

// network sets up the agent's network namespace: the launcher sockets
// masked, loopback up, the listeners bound and sent back on fdNet. It
// returns why it failed, or "".
func network(n *Network) string {
	for _, m := range n.Mask {
		if err := mask(m); err != nil {
			return fmt.Sprintf("masking %s for the agent failed: %v", m, err)
		}
	}
	if err := loopbackUp(); err != nil {
		return err.Error()
	}
	if len(n.Listen) > maxListeners {
		return fmt.Sprintf("%d listeners asked for, at most %d", len(n.Listen), maxListeners)
	}
	var fds []int
	defer func() {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
	}()
	var bound []string
	for _, l := range n.Listen {
		fd, err := listenFD(l)
		if err != nil {
			if l.Optional {
				continue
			}
			return fmt.Sprintf("listening on %s in the agent's network namespace failed: %v", l.Addr, err)
		}
		fds = append(fds, fd)
		bound = append(bound, l.Addr)
	}
	payload, err := json.Marshal(bound)
	if err != nil {
		return err.Error()
	}
	var oob []byte
	if len(fds) > 0 {
		oob = unix.UnixRights(fds...)
	}
	if err := unix.Sendmsg(fdNet, payload, oob, nil, 0); err != nil {
		return fmt.Sprintf("handing the listeners to scrim run failed: %v", err)
	}
	_ = unix.Close(fdNet)
	return ""
}

// mask covers path for the agent: a directory by an empty read-only tmpfs,
// anything else by /dev/null. A path that does not exist is skipped, and so
// is one inside a directory the view already hid (mode 0000): the agent
// cannot reach it either.
func mask(path string) error {
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) || errors.Is(err, unix.ENOTDIR) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		// Cover what it leads to; a dangling link leads nowhere.
		if path, err = filepath.EvalSymlinks(path); err != nil {
			return nil //nolint:nilerr // nothing to cover
		}
		if st, err = os.Stat(path); err != nil {
			return nil //nolint:nilerr // nothing to cover
		}
	}
	if st.IsDir() {
		return unix.Mount("scrim-masked", path, "tmpfs", unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "size=4k,mode=0500")
	}
	return unix.Mount("/dev/null", path, "", unix.MS_BIND, "")
}

// loopbackUp brings lo up in a new network namespace.
func loopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("opening a socket in the agent's network namespace failed: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("reading the loopback interface failed: %w", err)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP | unix.IFF_RUNNING)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("bringing the loopback interface up failed: %w", err)
	}
	return nil
}

// listenFD binds and listens on a loopback TCP address.
func listenFD(l Listen) (int, error) {
	ap, err := netAddrPort(l.Addr)
	if err != nil {
		return -1, err
	}
	family := unix.AF_INET6
	var sa unix.Sockaddr = &unix.SockaddrInet6{Port: int(ap.Port()), Addr: ap.Addr().As16()}
	if ap.Addr().Is4() {
		family = unix.AF_INET
		sa = &unix.SockaddrInet4{Port: int(ap.Port()), Addr: ap.Addr().As4()}
	}
	fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if family == unix.AF_INET6 {
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1)
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	if err := unix.Bind(fd, sa); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if err := unix.Listen(fd, unix.SOMAXCONN); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// Probe reports whether exe, started as the probe in a new user and mount
// namespace, can set up the view on this host.
func Probe(ctx context.Context, exe string) Availability {
	return probeWith(ctx, exe, false)
}

// ProbeNetwork reports whether exe can also start the agent in a network
// namespace of its own with loopback up (run.network: proxy-only).
func ProbeNetwork(ctx context.Context, exe string) Availability {
	return probeWith(ctx, exe, true)
}

func probeWith(ctx context.Context, exe string, withNet bool) Availability {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, exe) //nolint:gosec // scrim's own executable
	cmd.Args = []string{ProbeName}
	if withNet {
		cmd.Args = append(cmd.Args, probeNetArg)
	}
	cmd.Env = []string{}
	cmd.Stdout, cmd.Stderr = &out, &errb
	cmd.SysProcAttr = sysProcAttr(withNet)
	err := cmd.Run()
	if err == nil && strings.TrimSpace(out.String()) == probeOK {
		return Availability{Namespace: true}
	}
	reason := strings.TrimSpace(errb.String())
	switch {
	case err != nil && reason == "":
		reason = err.Error()
	case err == nil:
		reason = "the probe did not run as the filesystem view helper"
	}
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EINVAL) {
		reason = "creating a user namespace is not allowed: " + reason
	}
	return Availability{Reason: reason + availabilityHint()}
}

func availabilityHint() string {
	if b, err := os.ReadFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"); err == nil && strings.TrimSpace(string(b)) == "1" {
		return " (AppArmor restricts unprivileged user namespaces: kernel.apparmor_restrict_unprivileged_userns=1)"
	}
	if b, err := os.ReadFile("/proc/sys/user/max_user_namespaces"); err == nil && strings.TrimSpace(string(b)) == "0" {
		return " (user.max_user_namespaces=0)"
	}
	if b, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil && strings.TrimSpace(string(b)) == "0" {
		return " (kernel.unprivileged_userns_clone=0)"
	}
	return ""
}

func sysProcAttr(withNet bool) *syscall.SysProcAttr {
	uid, gid := os.Getuid(), os.Getgid()
	a := &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: uid, HostID: uid, Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: gid, HostID: gid, Size: 1}},
		GidMappingsEnableSetgroups: false,
		AmbientCaps:                []uintptr{unix.CAP_SYS_ADMIN},
	}
	if withNet {
		a.Cloneflags |= syscall.CLONE_NEWNET
		a.AmbientCaps = append(a.AmbientCaps, unix.CAP_NET_ADMIN, unix.CAP_NET_BIND_SERVICE)
	}
	return a
}

// Launch is a command wrapped by [Wrap].
type Launch struct {
	spec, status *os.File // the parent's ends
	net          *os.File // the parent's end of fdNet, with a network
	child        []*os.File
	listeners    []Listener
}

// Wrap turns cmd (Path the resolved agent, Args its command line) into a
// start of the helper exe in a new user and mount namespace, which mounts
// the plan's entries and then executes the agent in place. With n, the
// namespace has its own network as well (see [Network]). p may be nil when
// n is not. Call Started right after cmd.Start, and Close when done.
func Wrap(cmd *exec.Cmd, exe string, p *Plan, n *Network) (*Launch, error) {
	if n == nil && (p == nil || p.Mode != ModeNamespace) {
		return nil, errors.New("the plan is not a namespace view")
	}
	if p != nil && p.Mode != ModeNamespace {
		p = nil
	}
	s := spec{Path: cmd.Path, Args: cmd.Args, Network: n}
	var entries []Entry
	if p != nil {
		entries = p.Entries
	}
	for _, e := range entries {
		m := mount{Source: e.Source, Target: e.Target}
		if e.Hidden() {
			m.Source, m.ReadOnly = filepath.Join(p.dir, hiddenFile), true
			if e.Dir {
				m.Source = filepath.Join(p.dir, hiddenDir)
			}
		}
		s.Mounts = append(s.Mounts, m)
	}
	data, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	specR, specW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	statusR, statusW, err := os.Pipe()
	if err != nil {
		_ = specR.Close()
		_ = specW.Close()
		return nil, err
	}
	l := &Launch{spec: specW, status: statusR, child: []*os.File{specR, statusW}}
	if len(cmd.ExtraFiles) > 0 {
		l.Close()
		return nil, errors.New("the filesystem view cannot wrap a command with extra descriptors")
	}
	if n != nil {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			l.Close()
			return nil, fmt.Errorf("creating the listener channel failed: %w", err)
		}
		l.net = os.NewFile(uintptr(fds[0]), "net")
		l.child = append(l.child, os.NewFile(uintptr(fds[1]), "net-child"))
	}
	go func() {
		_, _ = specW.Write(data)
		_ = specW.Close()
	}()
	cmd.Path, cmd.Args = exe, []string{HelperName}
	cmd.ExtraFiles = l.child
	cmd.SysProcAttr = sysProcAttr(n != nil)
	return l, nil
}

// Started waits until the helper executed the agent, or returns why it did
// not.
func (l *Launch) Started() error {
	for _, f := range l.child {
		_ = f.Close()
	}
	l.child = nil
	b, err := io.ReadAll(l.status)
	_ = l.status.Close()
	if err != nil {
		return fmt.Errorf("reading the filesystem view helper's status: %w", err)
	}
	switch {
	case len(b) == 0:
		return errors.New("the filesystem view helper did not run (the executable does not call fsview.Main)")
	case b[0] == statusReady && len(b) == 1:
		if l.net != nil {
			return l.receive()
		}
		return nil
	case b[0] == statusReady:
		b = b[1:]
	}
	return errors.New(strings.TrimPrefix(string(b), string(rune(statusFailed))))
}

// receive takes the listening sockets the helper sent before it executed
// the agent. The message is already queued: it never waits.
func (l *Launch) receive() error {
	buf := make([]byte, 64*1024)
	oob := make([]byte, unix.CmsgSpace(4*maxListeners))
	n, oobn, _, _, err := unix.Recvmsg(int(l.net.Fd()), buf, oob, unix.MSG_DONTWAIT|unix.MSG_CMSG_CLOEXEC)
	if err != nil {
		return fmt.Errorf("the helper handed over no listeners for the agent's network namespace: %w", err)
	}
	var fds []int
	if oobn > 0 {
		msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			return fmt.Errorf("reading the listeners: %w", err)
		}
		for _, m := range msgs {
			got, err := unix.ParseUnixRights(&m)
			if err != nil {
				return fmt.Errorf("reading the listeners: %w", err)
			}
			fds = append(fds, got...)
		}
	}
	var addrs []string
	if err := json.Unmarshal(buf[:n], &addrs); err != nil || len(addrs) != len(fds) {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
		return errors.New("the helper handed over a malformed listener list")
	}
	for i, fd := range fds {
		f := os.NewFile(uintptr(fd), "listener")
		ln, err := net.FileListener(f)
		_ = f.Close()
		if err != nil {
			for _, fd := range fds[i+1:] {
				_ = unix.Close(fd)
			}
			return fmt.Errorf("using the listener for %s: %w", addrs[i], err)
		}
		l.listeners = append(l.listeners, Listener{Addr: addrs[i], Listener: ln})
	}
	return nil
}

// Listeners are the listening sockets bound inside the agent's network
// namespace, valid after Started returned nil. Close closes them.
func (l *Launch) Listeners() []Listener { return l.listeners }

// Close releases the descriptors and closes the listeners.
func (l *Launch) Close() {
	for _, f := range append(l.child, l.spec, l.status, l.net) {
		if f != nil {
			_ = f.Close()
		}
	}
	for _, ln := range l.listeners {
		_ = ln.Listener.Close()
	}
	l.child, l.listeners = nil, nil
}

// netAddrPort parses an IP host:port.
func netAddrPort(addr string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%q is not an IP address and port: %w", addr, err)
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}
