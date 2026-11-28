// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package run

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/fsview"
	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/localapi"
)

// TestRunNetworkProxyOnly: under run.network proxy-only the agent's
// provider requests (through the LLM base URL) and its tool call (through
// HTTPS_PROXY) still work and are redacted, and the session is identified;
// dialling the tool server's address itself, or fetching with the proxy
// settings ignored, fails. With run.network open the same direct attempts
// succeed, so the failures come from the namespace.
func TestRunNetworkProxyOnly(t *testing.T) {
	requireNetwork(t)
	for _, tc := range []struct {
		mode, direct string
	}{{NetworkProxyOnly, "fail"}, {NetworkOpen, "ok"}} {
		t.Run(tc.mode, func(t *testing.T) {
			h := newHarness(t, true)
			// tool.test resolves nowhere: the forward proxy takes it by
			// name in the CONNECT.
			toolURL := "https://tool.test/"
			work := seedFile(t, h.seeds)
			var out, errb syncBuf
			err := Run(context.Background(), Options{
				Command: []string{selfAgent(t)},
				Environ: baseEnv(t, envAgent+"=net", "TEST_TOOL_URL="+toolURL,
					"TEST_DIRECT_ADDR="+h.tool.Listener.Addr().String()),
				Dir: work, Daemon: h.daemon(), Stdout: &out, Stderr: &errb, RuntimeDir: t.TempDir(),
				Network: NetworkOptions{Mode: tc.mode},
			})
			var xe *ExitError
			if !errors.As(err, &xe) || xe.Code != 7 {
				t.Fatalf("want agent exit 7, got %v\nstdout: %s\nstderr: %s", err, out.String(), errb.String())
			}
			got := out.String()
			t.Logf("agent saw:\n%s", got)
			if !strings.Contains(got, "agent=") || !strings.Contains(got, "tool=tool-ok") {
				t.Errorf("the session or the tool call through the forward proxy did not work:\n%s", got)
			}
			if tc.mode == NetworkProxyOnly {
				for _, k := range []string{"direct-dial", "no-proxy-ip", "no-proxy-host"} {
					if !strings.Contains(got, k+"=fail") {
						t.Errorf("%s did not fail under proxy-only", k)
					}
				}
			} else if !strings.Contains(got, "direct-dial=ok") || !strings.Contains(got, "no-proxy-ip=ok") {
				t.Errorf("direct attempts failed with run.network open: the test proves nothing:\n%s", got)
			}
			checker := leak.NewChecker(h.seeds)
			ex := h.fake.Exchanges()
			if len(ex) < 2 {
				t.Fatalf("provider saw %d requests", len(ex))
			}
			for _, e := range ex {
				if f := checker.Check(e.Capture); len(f) > 0 {
					t.Errorf("%d leak findings in the %s request", len(f), e.API)
				}
			}
		})
	}
}

// TestRunNetworkRefusals: proxy-only refuses to start the agent when the
// namespace cannot be created, when scrim's listener is not on loopback,
// and when scrim is unavailable even with run.allow-unredacted-start.
func TestRunNetworkRefusals(t *testing.T) {
	no := func(context.Context, string) fsview.Availability {
		return fsview.Availability{Reason: "creating a user namespace is not allowed"}
	}
	h := newHarness(t, true)
	var out syncBuf
	err := Run(context.Background(), Options{
		Command: []string{selfAgent(t)}, Environ: baseEnv(t, envAgent+"=env"), Daemon: h.daemon(),
		Stdout: &out, RuntimeDir: t.TempDir(), Network: NetworkOptions{Mode: NetworkProxyOnly, Probe: no},
	})
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "cannot give the agent a network namespace") {
		t.Errorf("no namespace: want a refusal, got %v", err)
	}
	if out.String() != "" {
		t.Errorf("the agent ran: %q", out.String())
	}

	ep := h.ep
	ep.LLMBaseURL = "http://192.0.2.10:9790"
	err = Run(context.Background(), Options{
		Command: []string{selfAgent(t)}, Environ: baseEnv(t, envAgent+"=env"), Daemon: Fixed{Instance: &Static{EP: ep}},
		Stdout: &out, RuntimeDir: t.TempDir(), Network: NetworkOptions{Mode: NetworkProxyOnly},
	})
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "not on loopback") {
		t.Errorf("remote listener: want a refusal, got %v", err)
	}

	err = Run(context.Background(), Options{
		Command: []string{selfAgent(t)}, Environ: baseEnv(t, envAgent+"=env"), Daemon: Unavailable{},
		AllowUnredacted: true, Stdout: &out, RuntimeDir: t.TempDir(), Network: NetworkOptions{Mode: NetworkProxyOnly},
	})
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "proxy-only") {
		t.Errorf("unavailable scrim with allow-unredacted-start: want a refusal, got %v", err)
	}
	if out.String() != "" {
		t.Errorf("the agent ran: %q", out.String())
	}
}

// TestRunNetworkPrintEnv: --print-env shows the bridged listeners, masked
// sockets and gaps of proxy-only.
func TestRunNetworkPrintEnv(t *testing.T) {
	h := newHarness(t, true)
	yes := func(context.Context, string) fsview.Availability { return fsview.Availability{Namespace: true} }
	plan, err := PrintEnv(context.Background(), Options{Command: []string{"claude"}, Environ: baseEnv(t), Daemon: h.daemon(),
		Network: NetworkOptions{Mode: NetworkProxyOnly, Probe: yes}})
	if err != nil {
		t.Fatal(err)
	}
	n := plan.Network
	if !n.ProxyOnly() || len(n.Bridges) != 2 || len(n.Masked) == 0 || len(n.Gaps) == 0 {
		t.Fatalf("network plan = %+v", n)
	}
	if n.Bridges[0].Addr != strings.TrimPrefix(h.ep.LLMBaseURL, "http://") {
		t.Errorf("LLM bridge = %+v, want %s", n.Bridges[0], h.ep.LLMBaseURL)
	}
}

// TestFSViewNamespaceWithNetwork: the namespace view and the proxy-only
// network together, set up by one helper: the view checks of
// TestFSViewNamespace hold, and the agent is still identified by its
// session over the API socket.
func TestFSViewNamespaceWithNetwork(t *testing.T) {
	requireUserns(t)
	requireNetwork(t)
	viewNetwork = NetworkProxyOnly
	t.Cleanup(func() { viewNetwork = "" })
	home := plantHome(t, t.TempDir())
	r, stderr, err := runView(t, home, FSViewOptions{Mode: fsview.ModeNamespace, PasswdHome: home.dir})
	if err != nil {
		t.Fatalf("run: %v\n%s", err, stderr)
	}
	checkNamespaceView(t, r, home)
}

// TestRunNetworkMasksResolversAndDisplays: under proxy-only the agent
// cannot reach a Wayland display in its runtime directory, nor the host's
// name resolvers and displays over Unix sockets (system bus, resolved's
// varlink socket, nscd, avahi, X11) where this host has them; a name
// lookup through the C library fails quickly instead of reaching a
// resolver; DISPLAY and WAYLAND_DISPLAY are removed. With run.network open
// the same sockets answer, so the failures come from the masks.
func TestRunNetworkMasksResolversAndDisplays(t *testing.T) {
	requireNetwork(t)
	env := baseEnv(t, envAgent+"=dial", "DISPLAY=:99", "WAYLAND_DISPLAY=wayland-0")
	rt := envMap(env)["XDG_RUNTIME_DIR"]
	if err := os.MkdirAll(rt, 0o700); err != nil {
		t.Fatal(err)
	}
	wayland := filepath.Join(rt, "wayland-0")
	ln, err := net.Listen("unix", wayland)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	dial := []string{wayland}
	x11, _ := filepath.Glob("/tmp/.X11-unix/X*")
	for _, p := range append([]string{"/run/dbus/system_bus_socket", "/run/systemd/resolve/io.systemd.Resolve",
		"/run/nscd/socket", "/run/avahi-daemon/socket"}, x11...) {
		if c, err := net.DialTimeout("unix", p, time.Second); err == nil {
			_ = c.Close()
			dial = append(dial, p)
		}
	}
	t.Logf("sockets reachable on this host: %v", dial)
	env = append(env, "TEST_DIAL="+strings.Join(dial, ","))

	for _, mode := range []string{NetworkProxyOnly, NetworkOpen} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t, true)
			var out, errb syncBuf
			err := Run(context.Background(), Options{
				Command: []string{selfAgent(t)}, Environ: env, Dir: t.TempDir(), Daemon: h.daemon(),
				Stdout: &out, Stderr: &errb, RuntimeDir: t.TempDir(), Network: NetworkOptions{Mode: mode},
			})
			if err != nil {
				t.Fatalf("run: %v\n%s", err, errb.String())
			}
			got := out.String()
			t.Logf("agent saw:\n%s", got)
			want := "ok"
			if mode == NetworkProxyOnly {
				want = "fail"
			}
			for _, p := range dial {
				if !strings.Contains(got, "dial "+p+"="+want) {
					t.Errorf("%s: want %s", p, want)
				}
			}
			if mode != NetworkProxyOnly {
				return
			}
			if !strings.Contains(got, `DISPLAY="" WAYLAND_DISPLAY=""`) {
				t.Error("the display variables reached the agent")
			}
			if strings.Contains(got, "getent=ok") {
				t.Error("a name resolved inside the session")
			}
			if strings.Contains(got, "getent=") && !strings.Contains(got, "seconds=0") && !strings.Contains(got, "seconds=1") {
				t.Error("a failed name lookup took more than a second: something waited on a resolver")
			}
		})
	}
}

// TestLauncherSocketsList: the resolvers, buses and displays are in the
// mask list, with the Wayland sockets found at plan time, and systemd's user
// database is not.
func TestLauncherSocketsList(t *testing.T) {
	rt := t.TempDir()
	for _, f := range []string{"wayland-1", "wayland-1.lock"} {
		if err := os.WriteFile(filepath.Join(rt, f), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := launcherSockets(map[string]string{"XDG_RUNTIME_DIR": rt}, 1000)
	for _, want := range []string{"/run/dbus/system_bus_socket", "/var/run/dbus/system_bus_socket", "/run/systemd/resolve",
		"/run/nscd", "/var/run/nscd", "/run/avahi-daemon", "/tmp/.X11-unix", filepath.Join(rt, "wayland-1"),
		filepath.Join(rt, "wayland-1.lock"), filepath.Join(rt, "bus"), "/run/user/1000/bus", "/tmp/tmux-1000"} {
		if !slices.Contains(got, want) {
			t.Errorf("%s is not masked", want)
		}
	}
	for _, p := range got {
		if strings.Contains(p, "userdb") {
			t.Errorf("%s masked: user lookups would break", p)
		}
	}
}

// TestFSViewOwnFilesWithNetwork: the namespace view with scrim's own files
// hidden and the proxy-only network, set up by one helper. The own files
// stay unreadable, the session still reaches the agent API, and a masked
// launcher path inside a directory the view hides as one of scrim's own
// (here TMUX_TMPDIR) does not stop the start: the view's mount already
// makes it unreachable.
func TestFSViewOwnFilesWithNetwork(t *testing.T) {
	requireUserns(t)
	requireNetwork(t)
	viewNetwork = NetworkProxyOnly
	t.Cleanup(func() { viewNetwork = "" })
	home := plantHome(t, t.TempDir())
	h := newHarness(t, true)
	cfg, unlock, outside, env := ownView(t, h, home)
	tmux := t.TempDir()
	if err := os.Mkdir(filepath.Join(tmux, fmt.Sprintf("tmux-%d", os.Getuid())), 0o700); err != nil {
		t.Fatal(err)
	}
	own := append(h.ownPaths(), localapi.OwnPath{Path: tmux, Origin: "test: a directory of scrim's"})
	h.setOwn(own...)
	r, stderr, err := runViewWith(t, h, home, FSViewOptions{Mode: fsview.ModeNamespace, PasswdHome: home.dir}, env, "TMUX_TMPDIR="+tmux)
	if err != nil {
		t.Fatalf("run: %v\n%s", err, stderr)
	}
	checkNamespaceView(t, r, home)
	for _, p := range []string{cfg, unlock, outside} {
		if got, ok := r.Own[p]; !ok || !strings.HasPrefix(got, "ERR:") {
			t.Errorf("%s readable in the session: %q", p, got)
		}
	}
}

func (h *harness) ownPaths() []localapi.OwnPath {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]localapi.OwnPath(nil), h.own...)
}
