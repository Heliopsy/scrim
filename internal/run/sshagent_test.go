// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

// scrim run serves no ssh-agent on Windows (docs/limitations.md, Platforms).

package run

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh/agent"

	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/sshagent"
)

func TestBuildSSHAgent(t *testing.T) {
	in := input("claude")
	in.Environ = append(in.Environ, "SSH_AUTH_SOCK=/tmp/ssh-x/agent.1", "SSH_AGENT_PID=42")
	if _, ok := vars(mustBuild(t, in))["SSH_AUTH_SOCK"]; ok {
		t.Fatal("SSH_AUTH_SOCK set although run.ssh-agent is off")
	}
	in.SSHAgent = true
	p := mustBuild(t, in)
	if v := vars(p)["SSH_AUTH_SOCK"]; v.Value != "/run/user/1000/scrim/run/s1/"+FileSSHAgent {
		t.Fatalf("SSH_AUTH_SOCK = %q", v.Value)
	}
	if !slices.Contains(p.Unset, "SSH_AGENT_PID") {
		t.Errorf("SSH_AGENT_PID is kept: %v", p.Unset)
	}
	if !slices.ContainsFunc(p.Warnings, func(w string) bool { return strings.Contains(w, "SSH_AUTH_SOCK") }) {
		t.Errorf("replacing the user's agent is not said: %v", p.Warnings)
	}
	// Without a session there is nobody for scrim's agent to sign as.
	in.Token = false
	if _, ok := vars(mustBuild(t, in))["SSH_AUTH_SOCK"]; ok {
		t.Error("SSH_AUTH_SOCK set without a session")
	}
}

// sessionKeys is a stand-in for the control plane's keyring: it records who
// asked.
type sessionKeys struct {
	mu  sync.Mutex
	ids []identity.Identity
}

func (s *sessionKeys) Keys(_ context.Context, id identity.Identity, _ []sshagent.Binding) ([]sshagent.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ids = append(s.ids, id)
	return []sshagent.Key{}, nil
}

func (s *sessionKeys) Sign(context.Context, identity.Identity, sshagent.SignRequest) (sshagent.Signature, error) {
	return sshagent.Signature{}, nil
}

func TestPrepareServesSSHAgentAsTheSession(t *testing.T) {
	h := newHarness(t, false)
	keys := &sessionKeys{}
	h.api.API.SSH = keys
	p, err := Prepare(context.Background(), Options{Command: []string{"true"}, Environ: baseEnv(t),
		Daemon: h.daemon(), SSHAgent: true, RuntimeDir: shortDir(t)})
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(p.Dir, FileSSHAgent)
	st, err := os.Stat(sock)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("socket: %v %v", st, err)
	}
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agent.NewClient(c).List(); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	keys.mu.Lock()
	ids := keys.ids
	keys.mu.Unlock()
	if len(ids) != 1 || ids[0].Source != identity.SourceSession || ids[0].SessionID != p.Session.ID {
		t.Fatalf("the agent asked as %+v", ids)
	}
	p.Close(context.Background())
	if _, err := net.Dial("unix", sock); err == nil {
		t.Fatal("the agent socket outlives the session")
	}
}

// shortDir is a session root short enough for a Unix socket path.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "scrim-r")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}
