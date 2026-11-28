// SPDX-License-Identifier: AGPL-3.0-only

package run

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"time"

	"github.com/heliopsy/scrim/internal/fsview"
)

// NetworkOptions configure the agent's network (run.network).
type NetworkOptions struct {
	// Mode is run.network; empty is open.
	Mode string
	// Probe checks the network namespace works; nil is
	// fsview.ProbeNetwork.
	Probe func(ctx context.Context, helper string) fsview.Availability
}

// NetworkPlan is the agent's network for one session.
type NetworkPlan struct {
	// Mode is run.network: open or proxy-only.
	Mode string `json:"mode"`
	// Bridges are scrim's listeners reachable inside the agent's network
	// namespace, at the same address as outside it (proxy-only).
	Bridges []Bridge `json:"bridges,omitempty"`
	// Masked are the launcher sockets and directories covered for the
	// agent (proxy-only), so a service outside the namespace cannot run a
	// command for it.
	Masked []string `json:"masked,omitempty"`
	// Gaps are what the mode does not stop.
	Gaps []string `json:"gaps,omitempty"`
}

// ProxyOnly reports whether the agent gets a network namespace.
func (n *NetworkPlan) ProxyOnly() bool { return n != nil && n.Mode == NetworkProxyOnly }

// Bridge is one of scrim's listeners served inside the agent's network
// namespace.
type Bridge struct {
	// Addr is host:port, the same inside and outside the namespace.
	Addr string `json:"addr"`
	// What names the listener.
	What string `json:"what"`
}

// displayVars point GUI clients at a display; proxy-only removes them.
var displayVars = []string{"DISPLAY", "WAYLAND_DISPLAY"}

// Gap texts of run.network.
var (
	gapsNetworkOpen = []string{
		"a command that ignores HTTPS_PROXY and the base URLs, or dials a provider's address itself, reaches it directly and unredacted; run.network: proxy-only stops that on Linux",
	}
	gapsNetworkProxyOnly = []string{
		"Unix sockets of programs running outside the session, other than the masked ones (screen, an IDE or editor server, an ssh ControlMaster socket), can still run commands or open connections outside the namespace",
		"ssh and git over ssh cannot connect (no route, no DNS): use HTTPS remotes, which go through scrim's forward proxy",
		"scrim's database proxies and chained local upstreams are not reachable from the session",
		"the system and session buses, X11 and Wayland are masked: GUI programs, the clipboard, notifications, the Secret Service keyring and NetworkManager's CLI do not work in the session",
	}
)

// NetworkGaps lists what a run.network mode does not stop.
func NetworkGaps(mode string) []string {
	if mode == NetworkProxyOnly {
		return append([]string(nil), gapsNetworkProxyOnly...)
	}
	return append([]string(nil), gapsNetworkOpen...)
}

// buildNetwork plans the agent's network: for proxy-only, the listeners to
// bridge and the sockets to mask, after checking the host can create the
// namespace. It refuses rather than start the agent with an open network.
func (p *Prepared) buildNetwork(ctx context.Context, ep Endpoints) error {
	o := p.opts
	mode := o.Network.Mode
	if mode == "" {
		mode = NetworkOpen
	}
	n := &NetworkPlan{Mode: mode, Gaps: NetworkGaps(mode)}
	p.Plan.Network = n
	switch mode {
	case NetworkOpen:
		return nil
	case NetworkProxyOnly:
	default:
		return refused("run.network %q is not one of %s, %s", mode, NetworkOpen, NetworkProxyOnly)
	}
	if runtime.GOOS != "linux" {
		return refused("run.network is proxy-only, which needs Linux network namespaces; %s has none (set run.network: open)", runtime.GOOS)
	}
	add := func(raw, what string) error {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return refused("run.network is proxy-only, but scrim's %s %q is not a URL", what, raw)
		}
		if !loopbackHost(u.Hostname()) {
			return refused("run.network is proxy-only, but scrim's %s listens on %s, not on loopback: only loopback listeners can be served inside the agent's network namespace", what, u.Host)
		}
		addr := u.Host
		if u.Port() == "" {
			port := "80"
			if u.Scheme == "https" {
				port = "443"
			}
			addr = net.JoinHostPort(u.Hostname(), port)
		}
		n.Bridges = append(n.Bridges, Bridge{Addr: addr, What: what})
		return nil
	}
	if err := add(ep.LLMBaseURL, "LLM base URL"); err != nil {
		return err
	}
	if ep.ForwardProxy == "" {
		p.Plan.Warnings = append(p.Plan.Warnings, "run.network is proxy-only and scrim has no forward proxy: tools in the session have no network at all")
	} else if err := add(ep.ForwardProxy, "forward proxy"); err != nil {
		return err
	}
	n.Masked = launcherSockets(envMap(o.environ()), os.Getuid())
	// The display sockets are masked; clients that find no display fail
	// at once instead of trying a TCP display.
	for _, v := range displayVars {
		p.Plan.Set = slices.DeleteFunc(p.Plan.Set, func(x Var) bool { return x.Name == v })
		if _, ok := envMap(o.environ())[v]; ok && !slices.Contains(p.Plan.Unset, v) {
			p.Plan.Unset = append(p.Plan.Unset, v)
		}
	}
	slices.Sort(p.Plan.Unset)
	probe := o.Network.Probe
	if probe == nil {
		probe = fsview.ProbeNetwork
	}
	if a := probe(ctx, o.FSView.helper()); !a.Namespace {
		return refused("run.network is proxy-only, but this host cannot give the agent a network namespace of its own: %s", a.Reason)
	}
	return nil
}

// loopbackHost reports whether host is localhost or a loopback IP.
func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

// launcherSockets are the Unix sockets, and directories of them, through
// which a process in the session could get something done outside it:
//
//   - run a command: the D-Bus session bus, the systemd user manager,
//     rootless podman and docker, the docker daemon, tmux;
//   - resolve a name, which carries data out in its labels: the system bus
//     (systemd-resolved, NetworkManager), resolved's varlink sockets, nscd
//     and avahi (mdns);
//   - type into a terminal outside: X11 and Wayland displays.
//
// Both the agent's XDG_RUNTIME_DIR and the standard /run/user/<uid> are
// covered. systemd's user database (/run/systemd/userdb) stays, so user
// lookups keep working.
func launcherSockets(env map[string]string, uid int) []string {
	var out []string
	add := func(p string) {
		if !filepath.IsAbs(p) {
			return
		}
		p = filepath.Clean(p)
		for _, q := range out {
			if q == p {
				return
			}
		}
		out = append(out, p)
	}
	for _, rt := range []string{env["XDG_RUNTIME_DIR"], "/run/user/" + strconv.Itoa(uid)} {
		if rt == "" {
			continue
		}
		add(filepath.Join(rt, "bus"))
		add(filepath.Join(rt, "systemd", "private"))
		add(filepath.Join(rt, "podman"))
		add(filepath.Join(rt, "docker.sock"))
		if m, err := filepath.Glob(filepath.Join(rt, "wayland-*")); err == nil {
			for _, w := range m {
				add(w)
			}
		}
	}
	add("/run/docker.sock")
	add("/var/run/docker.sock")
	for _, run := range []string{"/run", "/var/run"} {
		add(filepath.Join(run, "dbus", "system_bus_socket"))
		add(filepath.Join(run, "systemd", "resolve"))
		add(filepath.Join(run, "nscd"))
		add(filepath.Join(run, "avahi-daemon"))
	}
	add("/tmp/.X11-unix")
	tmux := env["TMUX_TMPDIR"]
	if tmux == "" {
		tmux = "/tmp"
	}
	add(filepath.Join(tmux, "tmux-"+strconv.Itoa(uid)))
	return out
}

// fsNetwork is what the namespace helper needs: each bridge's addresses
// (both halves of localhost) and the masks.
func (n *NetworkPlan) fsNetwork() (*fsview.Network, map[string]string) {
	fn := &fsview.Network{Mask: n.Masked}
	targets := map[string]string{}
	for _, b := range n.Bridges {
		host, port, _ := net.SplitHostPort(b.Addr)
		if host == "localhost" {
			v4, v6 := net.JoinHostPort("127.0.0.1", port), net.JoinHostPort("::1", port)
			fn.Listen = append(fn.Listen, fsview.Listen{Addr: v4}, fsview.Listen{Addr: v6, Optional: true})
			targets[v4], targets[v6] = b.Addr, b.Addr
			continue
		}
		fn.Listen = append(fn.Listen, fsview.Listen{Addr: b.Addr})
		targets[b.Addr] = b.Addr
	}
	return fn, targets
}

// serveBridge accepts connections on a listener inside the agent's network
// namespace and splices each to target, scrim's listener outside it, until
// ln is closed.
func serveBridge(ln net.Listener, target string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go splice(c, target)
	}
}

func splice(c net.Conn, target string) {
	defer func() { _ = c.Close() }()
	up, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}
	defer func() { _ = up.Close() }()
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(up, c)
		closeWrite(up)
		close(done)
	}()
	_, _ = io.Copy(c, up)
	closeWrite(c)
	<-done
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// Summary is the one-line description print-env shows.
func (n *NetworkPlan) Summary() string {
	if n.ProxyOnly() {
		return fmt.Sprintf("proxy-only (network namespace with loopback only; %d of scrim's listeners reachable)", len(n.Bridges))
	}
	return "open (the host's network)"
}
