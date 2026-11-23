// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package matrix

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/heliopsy/scrim/internal/leak"
	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
	"github.com/heliopsy/scrim/test/e2e/harness"
)

// mcpCall is one tool call the MCP-only agent makes.
type mcpCall struct {
	Name   string         `json:"name"`
	Args   map[string]any `json:"args"`
	Result string         `json:"result"` // the tool result as the model would see it
	Error  bool           `json:"error"`
}

// mcpRules allow the agent's tool calls under this cell's prefix.
func mcpRules(cs *cellStore) string {
	return fmt.Sprintf(`default: deny
rules:
  - name: matrix-tools
    decision: allow
    when: op == "mcp.tool" && agent.kind == "session"
  - name: matrix-writes
    decision: allow
    when: op in ["store.write", "secret.gen"] && agent.kind == "session" && secret.ref.startsWith(%q)
`, cs.Ref(""))
}

// runMCPCell is the MCP-only mode: scrim carries no model traffic. An agent
// under `scrim run` lists the seeded secrets, generates one, captures one
// from a command's output and requests a grant through `scrim mcp`, then
// sends every tool result to the provider directly. Neither the tool results
// nor what the provider received may hold a seeded, generated or captured
// value.
func runMCPCell(t *testing.T, bin harness.Binaries, cs *cellStore, res *Result) {
	ctx := t.Context()
	seeds := leak.GenerateSet()
	values := map[string]string{}
	for i, s := range seeds {
		values[fmt.Sprintf("seed-%d", i)] = s.Value()
	}
	if err := cs.Put(ctx, values); err != nil {
		t.Fatalf("seed the %s store: %v", cs.server.Kind, err)
	}

	fake := fp.New(fp.Options{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: fake, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	d := startDaemon(t, bin, daemonOptions{store: cs, upstream: "http://127.0.0.1:9", rules: mcpRules(cs)})

	// The value a command prints and secret_capture stores.
	captured := leak.Generate(leak.KindGitHubToken)
	work := filepath.Join(d.Dir, "work")
	if err := os.WriteFile(filepath.Join(work, "token.json"), []byte(`{"token":"`+captured.Value()+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(d.Dir, "mcp-calls.json")
	log := &harness.SyncBuffer{}
	cmd := startAgent(t, d, false, "TestMatrixMCPAgent", append(cs.env,
		"SCRIM_MATRIX_MCP_OUT="+out, "SCRIM_MATRIX_SCRIM="+bin.Scrim, "SCRIM_MATRIX_FAKE=http://"+ln.Addr().String(),
		"SCRIM_MATRIX_PREFIX="+cs.Ref(""), "SCRIM_MATRIX_GEN_REF="+cs.FieldRef("generated"),
		"SCRIM_MATRIX_CAPTURE_REF="+cs.FieldRef("captured"), "SCRIM_MATRIX_REQUEST_REF="+cs.FieldRef("seed-0"),
	), log)
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()
	select {
	case err := <-waitErr:
		if err != nil {
			t.Fatalf("the MCP agent failed: %v\n%s", err, log.String())
		}
	case <-time.After(3 * time.Minute):
		_ = cmd.Process.Kill()
		t.Fatalf("the MCP agent did not finish:\n%s", log.String())
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("the MCP agent wrote no calls: %v\n%s", err, log.String())
	}
	var calls []mcpCall
	if err := json.Unmarshal(raw, &calls); err != nil {
		t.Fatal(err)
	}
	res.MCPCalls = len(calls)
	byName := map[string]mcpCall{}
	for _, c := range calls {
		byName[c.Name] = c
	}

	// What the tools did.
	list := byName["secrets_list"]
	if list.Error || strings.Count(list.Result, cs.Ref("seed-")) < len(seeds) {
		t.Errorf("secrets_list did not list the %d seeded secrets: %.600s", len(seeds), list.Result)
	}
	all := append([]leak.Seed{}, seeds...)
	all = append(all, captured)
	for _, name := range []string{"generated", "captured"} {
		v, err := cs.Get(ctx, name)
		if err != nil {
			t.Fatalf("read %s back: %v", name, err)
		}
		call := byName[map[string]string{"generated": "secret_gen", "captured": "secret_capture"}[name]]
		switch {
		case cs.Writable() && (v == "" || call.Error):
			t.Errorf("%s: nothing stored in the writable %s store: %s", call.Name, cs.server.Kind, call.Result)
		case !cs.Writable() && !call.Error:
			t.Errorf("%s succeeded on the read-only file store: %s", call.Name, call.Result)
		}
		if v != "" {
			all = append(all, leak.NewSeed(name, leak.KindPassword, v))
		}
	}
	if name := "captured"; cs.Writable() {
		if v, _ := cs.Get(ctx, name); v != captured.Value() {
			t.Errorf("secret_capture stored something else than the command printed")
		}
	}

	// Nothing the model could see holds a value: neither the tool results
	// nor any request the provider received.
	checker := leak.NewChecker(all)
	for i, c := range calls {
		if f := checker.Check(leak.Capture{Seq: i + 1, Method: "MCP", Path: c.Name, Body: []byte(c.Result)}); len(f) > 0 {
			b, _ := json.Marshal(f)
			t.Errorf("leak in the %s result: %s", c.Name, b)
		}
	}
	ex := fake.Exchanges()
	if len(ex) == 0 {
		t.Fatal("the agent's model request did not reach the provider")
	}
	for _, e := range ex {
		if f := checker.Check(e.Capture); len(f) > 0 {
			b, _ := json.Marshal(f)
			t.Errorf("leak in provider request %d: %s", e.Seq, b)
		}
	}
	res.GatedLeaks = 0
	if t.Failed() {
		res.GatedLeaks = -1
	}
	checkLog(t, d, all)
}

// TestMatrixMCPAgent is the agent of the MCP-only cell, started under
// `scrim run` by runMCPCell. It skips otherwise.
func TestMatrixMCPAgent(t *testing.T) {
	out := os.Getenv("SCRIM_MATRIX_MCP_OUT")
	if out == "" {
		t.Skip("started by the matrix only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	client := sdk.NewClient(&sdk.Implementation{Name: "scrim-matrix-agent", Version: "1"}, nil)
	session, err := client.Connect(ctx, &sdk.CommandTransport{Command: exec.Command(os.Getenv("SCRIM_MATRIX_SCRIM"), "mcp")}, nil) //nolint:gosec // the binary under test
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()

	calls := []mcpCall{
		{Name: "secrets_list", Args: map[string]any{"prefix": os.Getenv("SCRIM_MATRIX_PREFIX")}},
		{Name: "secret_gen", Args: map[string]any{"ref": os.Getenv("SCRIM_MATRIX_GEN_REF"), "length": 40}},
		{Name: "secret_capture", Args: map[string]any{"ref": os.Getenv("SCRIM_MATRIX_CAPTURE_REF"),
			"command": []string{"cat", "token.json"}, "json_path": ".token"}},
		{Name: "secret_request", Args: map[string]any{"ref": os.Getenv("SCRIM_MATRIX_REQUEST_REF"), "duration": "5m",
			"reason": "end-to-end matrix"}},
	}
	for i := range calls {
		r, err := session.CallTool(ctx, &sdk.CallToolParams{Name: calls[i].Name, Arguments: calls[i].Args})
		if err != nil {
			t.Fatalf("%s: %v", calls[i].Name, err)
		}
		var text strings.Builder
		for _, c := range r.Content {
			if tc, ok := c.(*sdk.TextContent); ok {
				text.WriteString(tc.Text)
			}
		}
		if r.StructuredContent != nil {
			b, _ := json.Marshal(r.StructuredContent)
			text.Write(b)
		}
		calls[i].Result, calls[i].Error = text.String(), r.IsError
	}

	// The conversation goes to the provider directly: in this mode scrim
	// is not on the model path.
	var content []map[string]any
	var uses []map[string]any
	for i, c := range calls {
		id := fmt.Sprintf("toolu_matrix_%d", i)
		uses = append(uses, map[string]any{"type": "tool_use", "id": id, "name": "mcp__scrim__" + c.Name, "input": c.Args})
		content = append(content, map[string]any{"type": "tool_result", "tool_use_id": id, "content": c.Result, "is_error": c.Error})
	}
	body, _ := json.Marshal(map[string]any{"model": "claude-sonnet-4-5", "max_tokens": 64, "messages": []any{
		map[string]any{"role": "user", "content": "Set up the deploy secrets with scrim."},
		map[string]any{"role": "assistant", "content": uses},
		map[string]any{"role": "user", "content": content},
	}})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, os.Getenv("SCRIM_MATRIX_FAKE")+"/v1/messages", bytes.NewReader(body))
	req.Header.Set("content-type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("x-api-key", "agent-own-provider-key")
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the provider answered %s", resp.Status)
	}
	b, _ := json.Marshal(calls)
	if err := os.WriteFile(out, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
