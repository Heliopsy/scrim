// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/secret"
)

// The agent API tells callers that cannot reach the admin API (agents of
// other users, with scrim as a system service) where the daemon listens.
func TestAgentAPIServesEndpoints(t *testing.T) {
	h := newHarness(t, seed(t, "tok-"))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	d, err := Start(ctx, h.opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Shutdown(context.Background()) }()
	if err := d.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	c := localapi.NewClient(d.Addrs().AgentAPI, secret.Value{})
	defer c.Close()
	ep, err := c.Endpoints(ctx)
	if err != nil {
		t.Fatal(err)
	}
	a := d.Addrs()
	if !ep.Ready || ep.BaseURL != a.BaseURL || ep.ForwardProxy != a.ForwardProxy || !strings.Contains(ep.CAPEM, "BEGIN CERTIFICATE") {
		t.Fatalf("endpoints = %+v, addrs = %+v", ep, a)
	}
	if strings.Contains(ep.CAPEM, "PRIVATE KEY") {
		t.Fatal("the endpoints carry a private key")
	}
}

// fakeSystemService serves the agent API's endpoints route in a temporary
// system runtime directory.
func fakeSystemService(t *testing.T, ep localapi.Endpoints) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "scrim-sys")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	old := localapi.SystemRuntimeDir
	localapi.SystemRuntimeDir = dir
	t.Cleanup(func() { localapi.SystemRuntimeDir = old })
	ln, err := localapi.Listen(localapi.SystemSocketPath(), localapi.ListenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	mgr := identity.NewManager(identity.NewMemorySessions(), identity.ManagerOptions{})
	srv := &localapi.Server{Sessions: mgr, SweepEvery: -1, Endpoints: func() localapi.Endpoints { return ep }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("agent API: %v", err)
		}
	})
	return dir
}

func systemLeaseOptions(t *testing.T) Options {
	t.Helper()
	// No user daemon: an empty runtime directory and nothing configured.
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	return Options{Config: config.Options{Registry: config.Default, Environ: []string{"HOME=" + t.TempDir()},
		ConfigPaths: []string{writeEmptyConfig(t)}}}
}

func writeEmptyConfig(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("apiVersion: "+config.APIVersion+"\nkind: Config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLeaseFindsTheSystemService(t *testing.T) {
	ca := "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"
	fakeSystemService(t, localapi.Endpoints{Ready: true, BaseURL: "http://127.0.0.1:9790", ForwardProxy: "127.0.0.1:9791",
		CAPEM: ca, Bypass: []string{"127.0.0.1:8787"}})
	o := systemLeaseOptions(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	l, err := Acquire(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Release(ctx) }()
	if !l.Shared() {
		t.Fatal("the lease started a daemon although the system service runs")
	}
	ep := l.Endpoints()
	if ep.APISocket != localapi.SystemSocketPath() || ep.LLMBaseURL != "http://127.0.0.1:9790" || ep.ForwardProxy != "http://127.0.0.1:9791" ||
		!bytes.Equal(ep.CACertPEM, []byte(ca)) || strings.Join(ep.Bypass, ",") != "127.0.0.1:8787" {
		t.Fatalf("endpoints = %+v", ep)
	}
	if err := l.Ready(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestLeaseRefusesASystemServiceThatIsNotReady(t *testing.T) {
	fakeSystemService(t, localapi.Endpoints{Ready: false, Problems: map[string]string{"dataplane": "no snapshot"}})
	_, err := Acquire(context.Background(), systemLeaseOptions(t))
	if err == nil || !strings.Contains(err.Error(), "not ready") {
		t.Fatalf("err = %v", err)
	}
}

func TestLeaseNamesTheGroupWhenRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("socket groups are Unix only")
	}
	if os.Geteuid() == 0 {
		t.Skip("root connects regardless of the socket mode")
	}
	fakeSystemService(t, localapi.Endpoints{Ready: true, BaseURL: "http://127.0.0.1:9790"})
	if err := os.Chmod(localapi.SystemSocketPath(), 0); err != nil {
		t.Fatal(err)
	}
	_, err := Acquire(context.Background(), systemLeaseOptions(t))
	if err == nil || !strings.Contains(err.Error(), localapi.SystemAgentGroup) {
		t.Fatalf("err = %v", err)
	}
}
