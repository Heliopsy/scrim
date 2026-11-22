// SPDX-License-Identifier: AGPL-3.0-only

// Package localapitest starts a real local API server on a Unix socket over
// the agent tools fakes, for tests of the API's clients.
package localapitest

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/heliopsy/scrim/internal/agenttools/agenttoolstest"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/localapi"
)

// Server is a running test server.
type Server struct {
	*agenttoolstest.Env
	API      *localapi.Server
	Sessions *identity.Manager
	Socket   string
}

// Start runs a server whose only mapped user is the current one, as agent
// "dev". It is stopped when the test ends.
func Start(t testing.TB) *Server {
	t.Helper()
	return StartWith(t, nil)
}

// StartWith is [Start] with setup adjusting the server before it serves.
func StartWith(t testing.TB, setup func(*localapi.Server)) *Server {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("peer credentials are implemented on Linux and macOS")
	}
	e := agenttoolstest.NewEnv(t)
	peers, err := identity.NewPeerMap([]identity.PeerRule{{Agent: "dev", UIDs: []uint32{uint32(os.Getuid())}}}, nil) // #nosec G115 -- uid_t is 32 bits
	if err != nil {
		t.Fatal(err)
	}
	mgr := identity.NewManager(identity.NewMemorySessions(), identity.ManagerOptions{})
	api := &localapi.Server{Resolver: identity.Resolver{Peers: peers, Sessions: mgr}, Sessions: mgr,
		Tools: e.Service, Auditor: e.Audit, ServerVersion: "test", SweepEvery: -1}
	if setup != nil {
		setup(api)
	}
	// Unix socket paths are limited to about 100 bytes; keep this one short.
	dir, err := os.MkdirTemp("", "scrim")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "api.sock")
	ln, err := localapi.Listen(sock, localapi.ListenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- api.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("local API: %v", err)
		}
	})
	return &Server{Env: e, API: api, Sessions: mgr, Socket: sock}
}
