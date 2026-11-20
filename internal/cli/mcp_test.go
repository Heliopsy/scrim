// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/localapi"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// TestMCPOverStdio drives `scrim mcp` with newline-delimited JSON-RPC on
// stdin, as Claude Code or Codex would.
func TestMCPOverStdio(t *testing.T) {
	ts := cliServer(t)
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"secrets_list","arguments":{}}}`,
	}, "\n") + "\n"
	// A client keeps stdin open while it waits for answers.
	r, w := io.Pipe()
	var out, errb syncBuf
	e := &Env{Stdin: r, Stdout: &out, Stderr: &errb, Registry: config.Default,
		Environ: []string{localapi.EnvSocket + "=" + ts.Socket}}
	done := make(chan int, 1)
	go func() { done <- Run(context.Background(), e, []string{"mcp"}) }()
	if _, err := io.WriteString(w, in); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for (!strings.Contains(out.String(), `"id":2`) || !strings.Contains(out.String(), `"id":3`)) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	_ = w.Close()
	if code := <-done; code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	res := result{stdout: out.String()}
	for _, want := range []string{`"name":"scrim"`, `"secret_capture"`, `"secret_ask_human"`, `bao://kv/agents/github`} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("output lacks %s:\n%s", want, res.stdout)
		}
	}
	if strings.Contains(res.stdout, string(cliSeeded)) {
		t.Fatal("MCP output contains a seeded value")
	}
}

func TestAPIWhoAmI(t *testing.T) {
	ts := cliServer(t)
	res := runCLI(ts, nil, "api", "whoami")
	if res.code != 0 || !strings.HasPrefix(res.stdout, "agent dev via peer") {
		t.Fatalf("exit %d: %q %q", res.code, res.stdout, res.stderr)
	}
	res = runCLI(ts, nil, "api", "whoami", "-o", "json")
	if !strings.Contains(res.stdout, `"source": "peer"`) {
		t.Fatalf("%q", res.stdout)
	}
}
