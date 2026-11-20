// SPDX-License-Identifier: AGPL-3.0-only

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/agenttools/agenttoolstest"
	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/localapi/localapitest"
	"github.com/heliopsy/scrim/internal/secret"
)

var update = flag.Bool("update", false, "rewrite golden files")

// recorder keeps every byte the server writes.
type recorder struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (r *recorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.Write(p)
}

func (r *recorder) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return bytes.Clone(r.buf.Bytes())
}

type session struct {
	cs   *sdk.ClientSession
	out  *recorder // server to client
	in   *recorder // client to server
	stop func()
}

// connect runs the server over pipes, recording both directions, and
// returns a connected client.
func connect(t *testing.T, api API) *session {
	t.Helper()
	srv := NewServer(api, "test")
	c2sR, c2sW := io.Pipe()
	s2cR, s2cW := io.Pipe()
	out, in := &recorder{}, &recorder{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = Serve(ctx, srv, io.TeeReader(c2sR, in), io.MultiWriter(s2cW, out))
		_ = s2cW.Close()
	}()
	client := sdk.NewClient(&sdk.Implementation{Name: "test-client", Version: "1"}, nil)
	cs, err := client.Connect(ctx, &sdk.IOTransport{Reader: s2cR, Writer: c2sW}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := &session{cs: cs, out: out, in: in, stop: func() {
		_ = cs.Close()
		_ = c2sW.Close()
		cancel()
		<-done
	}}
	t.Cleanup(s.stop)
	return s
}

func (s *session) call(t *testing.T, name string, args map[string]any) (map[string]any, bool) {
	t.Helper()
	res, err := s.cs.CallTool(context.Background(), &sdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error %v", name, err)
	}
	if len(res.Content) != 1 {
		t.Fatalf("%s: %d content blocks", name, len(res.Content))
	}
	text := res.Content[0].(*sdk.TextContent).Text
	var obj map[string]any
	if err := json.Unmarshal([]byte(text), &obj); err != nil {
		t.Fatalf("%s: result is not JSON: %v", name, err)
	}
	return obj, res.IsError
}

func errCode(obj map[string]any) string {
	e, _ := obj["error"].(map[string]any)
	c, _ := e["code"].(string)
	return c
}

func TestToolListGolden(t *testing.T) {
	s := connect(t, nil)
	res, err := s.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	type entry struct {
		Name        string `json:"name"`
		ReadOnly    bool   `json:"read_only"`
		InputSchema any    `json:"input_schema"`
	}
	var got []entry
	for _, tl := range res.Tools {
		got = append(got, entry{Name: tl.Name, ReadOnly: tl.Annotations != nil && tl.Annotations.ReadOnlyHint, InputSchema: tl.InputSchema})
	}
	sort.Slice(got, func(i, j int) bool { return got[i].Name < got[j].Name })
	raw, _ := json.MarshalIndent(got, "", "  ")
	raw = append(raw, '\n')
	path := filepath.Join("testdata", "tools.golden.json")
	if *update {
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, want) {
		t.Fatalf("tool list differs from %s; run go test ./internal/mcp -update after reviewing:\n%s", path, raw)
	}
	names := map[string]bool{}
	for _, e := range got {
		names[e.Name] = true
	}
	for _, n := range []string{"secrets_list", "secret_request", "secret_gen", "secret_capture", "secret_ask_human", "approval_status", "grants_list"} {
		if !names[n] {
			t.Errorf("missing tool %s", n)
		}
	}
	if len(names) != 7 {
		t.Errorf("%d tools, want 7", len(names))
	}
}

// valueLike matches argument names that could carry a value.
var valueLike = regexp.MustCompile(`(?i)value|secret|passw|token|key|cred|content|data|body|stdin|payload|plain`)

// TestNoToolSchemaAcceptsAValue is half of the 8.2 verification: no input
// schema has a property that could carry a value, and every schema refuses
// properties it does not list.
func TestNoToolSchemaAcceptsAValue(t *testing.T) {
	s := connect(t, nil)
	res, err := s.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range res.Tools {
		raw, _ := json.Marshal(tl.InputSchema)
		var schema map[string]any
		_ = json.Unmarshal(raw, &schema)
		if schema["additionalProperties"] != false {
			t.Errorf("%s accepts unlisted properties", tl.Name)
		}
		walk(t, tl.Name, schema)
		// Smuggling a value in an extra argument is refused before the tool runs.
		r, err := s.cs.CallTool(context.Background(), &sdk.CallToolParams{Name: tl.Name,
			Arguments: map[string]any{"ref": "bao://kv/agents/x", "value": "smuggle-test-value"}})
		if err != nil || !r.IsError {
			t.Errorf("%s accepted a value argument", tl.Name)
		}
	}
}

func walk(t *testing.T, tool string, schema map[string]any) {
	props, _ := schema["properties"].(map[string]any)
	for name, p := range props {
		if valueLike.MatchString(name) {
			t.Errorf("%s has argument %q, which could carry a value", tool, name)
		}
		if ps, ok := p.(map[string]any); ok {
			walk(t, tool, ps)
			if items, ok := ps["items"].(map[string]any); ok {
				walk(t, tool, items)
			}
		}
	}
}

// Generated test values, never real secrets.
var (
	seededGitHub = []byte("ghp_TEST0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d")
	seededProd   = []byte("prod-test-value-5e4d3c2b1a09")
	captured     = []byte("cap-test-value-77aa88bb99cc")
	entered      = []byte("ask-test-value-1f2e3d4c5b6a")
)

// TestNoResponseContainsAValue is the other half of 8.2: every tool, on
// success and failure, against seeded, generated, captured and entered
// values, with every byte the server wrote searched for each value.
func TestNoResponseContainsAValue(t *testing.T) {
	ts := localapitest.Start(t)
	ts.Store.Seed(agenttools.SecretInfo{Ref: "bao://kv/agents/github", Name: "github", Bindings: []string{"api.github.com"}}, seededGitHub)
	ts.Store.Seed(agenttools.SecretInfo{Ref: "bao://kv/prod/payments", Name: "payments"}, seededProd)
	client := localapi.NewClient(ts.Socket, secret.Value{})
	defer client.Close()
	s := connect(t, client)

	capFile := filepath.Join(t.TempDir(), "api-response.json")
	if err := os.WriteFile(capFile, []byte(`{"id":1,"token":"`+string(captured)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	ls, isErr := s.call(t, "secrets_list", nil)
	if isErr || len(ls["secrets"].([]any)) != 1 {
		t.Fatalf("secrets_list = %v", ls)
	}

	g, isErr := s.call(t, "secret_request", map[string]any{"ref": "bao://kv/agents/github", "duration": "30m", "reason": "open a PR"})
	if isErr || g["status"] != "granted" {
		t.Fatalf("secret_request = %v", g)
	}
	p, _ := s.call(t, "secret_request", map[string]any{"ref": "bao://kv/agents/ask/hetzner", "duration": "3h", "reason": "deploy"})
	if p["status"] != "pending" || p["capped"] != true {
		t.Fatalf("pending request = %v", p)
	}
	st, _ := s.call(t, "approval_status", map[string]any{"id": p["approval_id"]})
	if st["status"] != "pending" {
		t.Fatalf("approval_status = %v", st)
	}
	if err := ts.Approvals.Settle(p["approval_id"].(string), true); err != nil {
		t.Fatal(err)
	}
	st, _ = s.call(t, "approval_status", map[string]any{"id": p["approval_id"]})
	if st["status"] != "approved" {
		t.Fatalf("approval_status after approval = %v", st)
	}

	gen, isErr := s.call(t, "secret_gen", map[string]any{"ref": "bao://kv/agents/app-db#password", "length": 32})
	if isErr || gen["status"] != "stored" {
		t.Fatalf("secret_gen = %v", gen)
	}
	generated, _ := ts.Store.Value("bao://kv/agents/app-db#password")
	if len(generated) != 32 {
		t.Fatalf("generated %d bytes", len(generated))
	}

	c, isErr := s.call(t, "secret_capture", map[string]any{"ref": "bao://kv/agents/new-token", "command": []string{"cat", capFile}, "json_path": ".token"})
	if isErr || c["status"] != "stored" || c["exit_code"] != float64(0) {
		t.Fatalf("secret_capture = %v", c)
	}
	if v, _ := ts.Store.Value("bao://kv/agents/new-token"); !bytes.Equal(v, captured) {
		t.Fatal("captured value not stored")
	}
	// A failing capture whose output and error output both hold a value.
	f, isErr := s.call(t, "secret_capture", map[string]any{"ref": "bao://kv/agents/fail",
		"command": []string{"sh", "-c", "cat " + capFile + "; cat " + capFile + " >&2; exit 4"}})
	if !isErr || errCode(f) != "invalid" {
		t.Fatalf("failing capture = %v", f)
	}
	nf, isErr := s.call(t, "secret_capture", map[string]any{"ref": "bao://kv/agents/nf", "command": []string{"cat", capFile}, "json_path": ".missing"})
	if !isErr || errCode(nf) != "invalid" {
		t.Fatalf("no match = %v", nf)
	}

	notices := ts.Notifier.Chan()
	go func() {
		n := <-notices
		_ = ts.Service.SubmitAsk(context.Background(), agenttoolstest.TokenOf(n.URL), secret.New(entered))
	}()
	a, isErr := s.call(t, "secret_ask_human", map[string]any{"ref": "bao://kv/agents/hcloud", "prompt": "Hetzner Cloud API token", "wait_seconds": 10})
	if isErr || a["status"] != "stored" {
		t.Fatalf("secret_ask_human = %v", a)
	}
	if v, _ := ts.Store.Value("bao://kv/agents/hcloud"); !bytes.Equal(v, entered) {
		t.Fatal("entered value not stored")
	}
	link := ts.Notifier.Notices[0].URL

	gl, isErr := s.call(t, "grants_list", nil)
	if isErr || len(gl["grants"].([]any)) != 2 {
		t.Fatalf("grants_list = %v", gl)
	}

	// Failures.
	d, isErr := s.call(t, "secret_gen", map[string]any{"ref": "bao://kv/prod/payments", "overwrite": true})
	if !isErr || errCode(d) != "denied" {
		t.Fatalf("denied gen = %v", d)
	}
	ts.Store.WriteErr = valueError(seededProd)
	w, isErr := s.call(t, "secret_gen", map[string]any{"ref": "bao://kv/agents/other"})
	if !isErr || errCode(w) != "unavailable" {
		t.Fatalf("failed write = %v", w)
	}
	nf2, isErr := s.call(t, "approval_status", map[string]any{"id": "apr_9999"})
	if !isErr || errCode(nf2) != "not_found" {
		t.Fatalf("unknown approval = %v", nf2)
	}

	values := [][]byte{seededGitHub, seededProd, generated, captured, entered}
	agenttoolstest.AssertNoValues(t, "MCP server output", s.out.bytes(), values...)
	agenttoolstest.AssertNoValues(t, "MCP client input", s.in.bytes(), values...)
	audit, _ := json.Marshal(ts.Audit.All())
	agenttoolstest.AssertNoValues(t, "audit log", audit, values...)
	if bytes.Contains(s.out.bytes(), []byte(agenttoolstest.TokenOf(link))) {
		t.Error("the entry link reached the agent")
	}
}

type valueError []byte

func (v valueError) Error() string { return "store said: " + string(v) }

// fakeAPI answers with fixed results, to test error mapping and defaults
// without a server.
type fakeAPI struct {
	mu   sync.Mutex
	asks []agenttools.AskInput
}

func (f *fakeAPI) List(context.Context, agenttools.ListInput) (agenttools.ListOutput, error) {
	return agenttools.ListOutput{}, agenttools.Errorf(agenttools.CodeUnauthenticated, "no identity")
}

func (f *fakeAPI) Request(context.Context, agenttools.RequestInput) (agenttools.RequestOutput, error) {
	return agenttools.RequestOutput{}, io.ErrUnexpectedEOF
}

func (f *fakeAPI) Generate(context.Context, agenttools.GenInput) (agenttools.WriteOutput, error) {
	return agenttools.WriteOutput{Status: "stored", Ref: "r", Store: "s"}, nil
}

func (f *fakeAPI) Capture(context.Context, agenttools.CaptureInput) (agenttools.CaptureOutput, error) {
	return agenttools.CaptureOutput{}, nil
}

func (f *fakeAPI) Ask(_ context.Context, in agenttools.AskInput) (agenttools.AskOutput, error) {
	f.mu.Lock()
	f.asks = append(f.asks, in)
	f.mu.Unlock()
	return agenttools.AskOutput{ID: "ask_1", Status: "pending", Ref: in.Ref, ExpiresAt: time.Unix(0, 0).UTC()}, nil
}

func (f *fakeAPI) Status(context.Context, agenttools.StatusInput) (agenttools.StatusOutput, error) {
	return agenttools.StatusOutput{}, nil
}

func (f *fakeAPI) Grants(context.Context) (agenttools.GrantsOutput, error) {
	return agenttools.GrantsOutput{Grants: []agenttools.Grant{}}, nil
}

func TestErrorsAndDefaults(t *testing.T) {
	f := &fakeAPI{}
	s := connect(t, f)
	e, isErr := s.call(t, "secrets_list", nil)
	if !isErr || errCode(e) != "unauthenticated" {
		t.Fatalf("list = %v", e)
	}
	e, isErr = s.call(t, "secret_request", map[string]any{"ref": "x", "reason": "r"})
	if !isErr || errCode(e) != "internal" || strings.Contains(e["error"].(map[string]any)["message"].(string), "EOF") {
		t.Fatalf("internal error leaks its text: %v", e)
	}
	_, _ = s.call(t, "secret_ask_human", map[string]any{"ref": "x", "prompt": "p"})
	_, _ = s.call(t, "secret_ask_human", map[string]any{"ref": "x", "prompt": "p", "wait_seconds": 0})
	if len(f.asks) != 2 || f.asks[0].WaitSeconds != DefaultAskWait || f.asks[1].WaitSeconds != 0 {
		t.Fatalf("asks = %+v", f.asks)
	}
	r, err := s.cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "secret_gen", Arguments: map[string]any{}})
	if err != nil || !r.IsError {
		t.Fatal("missing ref accepted")
	}
	init := s.cs.InitializeResult()
	if init == nil || init.ServerInfo.Name != "scrim" || !strings.Contains(init.Instructions, "Never paste a secret value") {
		t.Fatalf("initialize = %+v", init)
	}
}
