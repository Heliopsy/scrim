// SPDX-License-Identifier: AGPL-3.0-only

package localapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/agenttools/agenttoolstest"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/secret"
)

// The helper process mints a session over the socket in $SCRIM_API_SOCKET,
// prints the (test-only) token, and lives until its stdin closes. It plays a
// second agent started by its own `scrim run`.
func TestMain(m *testing.M) {
	if os.Getenv("SCRIM_LOCALAPI_HELPER") == "mint" {
		c := FromEnv()
		got, err := c.Mint(context.Background(), MintInput{Name: "helper"})
		if err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}
		_ = got.Token.Expose(func(b []byte) error { fmt.Println(string(b)); return nil })
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type harness struct {
	env    *agenttoolstest.Env
	srv    *Server
	socket string
	peer   *Client
	audit  *agenttoolstest.Audit
}

func start(t *testing.T) *harness {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("peer credentials are implemented on Linux and macOS")
	}
	e := agenttoolstest.NewEnv(t)
	e.Store.Seed(agenttools.SecretInfo{Ref: "bao://kv/agents/hetzner", Name: "hetzner"}, []byte("hz-test-0f9e8d7c6b5a"))
	peers, err := identity.NewPeerMap([]identity.PeerRule{{Agent: "dev", UIDs: []uint32{uint32(os.Getuid())}}}, nil) // #nosec G115
	if err != nil {
		t.Fatal(err)
	}
	mgr := identity.NewManager(identity.NewMemorySessions(), identity.ManagerOptions{})
	srv := &Server{Resolver: identity.Resolver{Peers: peers, Sessions: mgr}, Sessions: mgr, Tools: e.Service,
		Auditor: e.Audit, ServerVersion: "test", SweepEvery: -1}
	// Unix socket paths are short on macOS; keep the directory shallow.
	dir, err := os.MkdirTemp("", "scrim-api")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "api.sock")
	ln, err := Listen(sock, ListenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	c := NewClient(sock, secret.Value{})
	t.Cleanup(c.Close)
	return &harness{env: e, srv: srv, socket: sock, peer: c, audit: e.Audit}
}

func codeOf(t *testing.T, err error) agenttools.Code {
	t.Helper()
	if err == nil {
		t.Fatal("want an error")
	}
	var e *agenttools.Error
	if !errors.As(err, &e) {
		t.Fatalf("%v is not an *agenttools.Error", err)
	}
	return e.Code
}

var bg = context.Background()

func TestSocketIsPrivate(t *testing.T) {
	h := start(t)
	fi, err := os.Stat(h.socket)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v", fi.Mode().Perm())
	}
	if _, err := Listen(h.socket, ListenOptions{}); err == nil || !strings.Contains(err.Error(), "another scrim") {
		t.Fatalf("second listener: %v", err)
	}
	plain := filepath.Join(filepath.Dir(h.socket), "file")
	if err := os.WriteFile(plain, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(plain, ListenOptions{}); err == nil {
		t.Fatal("listened over a regular file")
	}
}

func TestSocketPathTooLong(t *testing.T) {
	_, err := Listen("/tmp/"+strings.Repeat("d", 120)+"/api.sock", ListenOptions{})
	if err == nil || !strings.Contains(err.Error(), "api.socket") {
		t.Fatalf("err = %v", err)
	}
}

func TestStaleSocketIsReplaced(t *testing.T) {
	dir, _ := os.MkdirTemp("", "scrim-api")
	defer func() { _ = os.RemoveAll(dir) }()
	sock := filepath.Join(dir, "api.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ul := ln.(*net.UnixListener)
	ul.SetUnlinkOnClose(false)
	_ = ln.Close()
	ln2, err := Listen(sock, ListenOptions{Mode: 0o660})
	if err != nil {
		t.Fatalf("stale socket: %v", err)
	}
	_ = ln2.Close()
}

func TestPeerIdentityAndTools(t *testing.T) {
	h := start(t)
	v, err := h.peer.Version(bg)
	if err != nil || v.API != Version || v.Server != "test" {
		t.Fatalf("version: %+v %v", v, err)
	}
	who, err := h.peer.WhoAmI(bg)
	if err != nil || who.Agent != "dev" || who.Source != identity.SourcePeer || who.Peer.PID != int32(os.Getpid()) { // #nosec G115
		t.Fatalf("whoami: %+v %v", who, err)
	}
	ls, err := h.peer.List(bg, agenttools.ListInput{Prefix: "bao://kv/agents/"})
	if err != nil || len(ls.Secrets) != 1 {
		t.Fatalf("list: %+v %v", ls, err)
	}
	rq, err := h.peer.Request(bg, agenttools.RequestInput{Ref: "bao://kv/agents/ask/x", Duration: "30m", Reason: "r"})
	if err != nil || rq.Status != agenttools.StatusPending {
		t.Fatalf("request: %+v %v", rq, err)
	}
	st, err := h.peer.Status(bg, agenttools.StatusInput{ID: rq.ApprovalID})
	if err != nil || st.Status != agenttools.ApprovalPending {
		t.Fatalf("status: %+v %v", st, err)
	}
	gen, err := h.peer.Generate(bg, agenttools.GenInput{Ref: "bao://kv/agents/app#pw", Length: 24})
	if err != nil || gen.Status != agenttools.StatusStored || gen.Length != 24 {
		t.Fatalf("generate: %+v %v", gen, err)
	}
	gs, err := h.peer.Grants(bg)
	if err != nil || gs.Grants == nil {
		t.Fatalf("grants: %+v %v", gs, err)
	}
	if last := h.audit.Last(); last.Agent != "dev" || last.PID != int32(os.Getpid()) { // #nosec G115
		t.Fatalf("audit = %+v", last)
	}
	if _, err := h.peer.Generate(bg, agenttools.GenInput{Ref: "bao://kv/prod/x"}); codeOf(t, err) != agenttools.CodeDenied {
		t.Fatalf("denied: %v", err)
	}
}

func TestPutCarriesTheValueOnlyInTheBody(t *testing.T) {
	h := start(t)
	val := "put-test-value-a1b2c3d4e5f6"
	out, err := h.peer.Put(bg, agenttools.PutInput{Ref: "bao://kv/agents/new"}, secret.FromString(val))
	if err != nil || out.Status != agenttools.StatusStored || out.Length != len(val) {
		t.Fatalf("put: %+v %v", out, err)
	}
	if got, _ := h.env.Store.Value("bao://kv/agents/new"); string(got) != val {
		t.Fatal("value not stored as sent")
	}
	raw, _ := json.Marshal(out)
	agenttoolstest.AssertNoValues(t, "put response", raw, []byte(val))
	_, err = h.peer.Put(bg, agenttools.PutInput{Ref: "bao://kv/agents/new"}, secret.FromString(val))
	if codeOf(t, err) != agenttools.CodeConflict {
		t.Fatalf("second put: %v", err)
	}
	if _, err := h.peer.Put(bg, agenttools.PutInput{Ref: "bao://kv/agents/new", Overwrite: true}, secret.FromString("v2-test-value")); err != nil {
		t.Fatal(err)
	}
	big := secret.New(bytes.Repeat([]byte("x"), agenttools.MaxValueSize+1))
	if _, err := h.peer.Put(bg, agenttools.PutInput{Ref: "bao://kv/agents/big"}, big); codeOf(t, err) != agenttools.CodeInvalid {
		t.Fatalf("too big: %v", err)
	}
}

func TestCaptureRunsOnTheClientSide(t *testing.T) {
	h := start(t)
	val := "cap-test-value-0123456789ab"
	out, err := h.peer.Capture(bg, agenttools.CaptureInput{Ref: "bao://kv/agents/cap",
		Command: []string{"sh", "-c", `printf '{"token":"` + val + `"}'`}, JSONPath: ".token"})
	if err != nil || out.Status != agenttools.StatusStored || out.ExitCode != 0 {
		t.Fatalf("capture: %+v %v", out, err)
	}
	if got, _ := h.env.Store.Value("bao://kv/agents/cap"); string(got) != val {
		t.Fatal("captured value not stored")
	}
	if h.audit.Last().Tool != agenttools.ToolSecretCapture {
		t.Fatalf("audit tool = %s", h.audit.Last().Tool)
	}
	marker := filepath.Join(t.TempDir(), "ran")
	_, err = h.peer.Capture(bg, agenttools.CaptureInput{Ref: "bao://kv/prod/cap", Command: []string{"touch", marker}})
	if codeOf(t, err) != agenttools.CodeDenied {
		t.Fatalf("denied capture: %v", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a denied capture ran its command")
	}
}

func TestRequestBodiesAreStrict(t *testing.T) {
	h := start(t)
	for _, body := range []string{
		`{"ref":"bao://kv/agents/x","value":"smuggled-value"}`,
		`{"ref":"bao://kv/agents/x"} {"ref":"y"}`,
		`not json`,
	} {
		resp := raw(t, h.socket, http.MethodPost, "/v1/secrets/generate", "application/json", body, "")
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status %d", body, resp.StatusCode)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if strings.Contains(string(b), "smuggled-value") {
			t.Error("error echoes the body")
		}
	}
	resp := raw(t, h.socket, http.MethodPut, "/v1/secrets/value?ref=bao://kv/agents/x", "text/plain", "v", "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("text/plain value: status %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	resp = raw(t, h.socket, http.MethodGet, "/v2/secrets", "", "", "")
	if resp.StatusCode != http.StatusNotFound || resp.Header.Get(HeaderAPIVersion) != Version {
		t.Errorf("unknown version: status %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func raw(t *testing.T, sock, method, path, ctype, body, token string) *http.Response {
	t.Helper()
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	req, _ := http.NewRequest(method, "http://scrim"+path, strings.NewReader(body))
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestSessionLifecycle(t *testing.T) {
	h := start(t)
	m, err := h.peer.Mint(bg, MintInput{Name: "claude", TTLSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	if m.Session.Agent != "dev" || m.Session.RootPID != int32(os.Getpid()) || m.Session.ExpiresAt.Sub(m.Session.CreatedAt) != time.Hour { // #nosec G115
		t.Fatalf("session = %+v", m.Session)
	}
	sc := NewClient(h.socket, m.Token)
	defer sc.Close()
	who, err := sc.WhoAmI(bg)
	if err != nil || who.Source != identity.SourceSession || who.SessionID != m.Session.ID || who.SessionName != "claude" {
		t.Fatalf("whoami: %+v %v", who, err)
	}
	// A session cannot mint further sessions.
	if _, err := sc.Mint(bg, MintInput{}); codeOf(t, err) != agenttools.CodeForbidden {
		t.Fatalf("session mint: %v", err)
	}
	// Grants and approvals of the peer identity are invisible to the session.
	rq, _ := h.peer.Request(bg, agenttools.RequestInput{Ref: "bao://kv/agents/ask/x", Reason: "r"})
	if _, err := sc.Status(bg, agenttools.StatusInput{ID: rq.ApprovalID}); codeOf(t, err) != agenttools.CodeNotFound {
		t.Fatalf("session sees peer approval: %v", err)
	}
	if err := sc.EndSession(bg); err != nil {
		t.Fatal(err)
	}
	if _, err := sc.WhoAmI(bg); codeOf(t, err) != agenttools.CodeUnauthenticated {
		t.Fatalf("after end: %v", err)
	}
	last := h.audit.Last()
	if last.Tool != ToolAuth || last.Outcome != agenttools.OutcomeRefused || last.Detail != string(identity.RefusedRevoked) || last.SessionID != m.Session.ID {
		t.Fatalf("audit = %+v", last)
	}
	if err := h.peer.EndSession(bg); codeOf(t, err) != agenttools.CodeInvalid {
		t.Fatalf("peer end: %v", err)
	}
	m2, _ := h.peer.Mint(bg, MintInput{})
	if err := h.peer.RevokeSession(bg, m2.Session.ID); err != nil {
		t.Fatal(err)
	}
	if err := h.peer.RevokeSession(bg, "nosuchsession000"); codeOf(t, err) != agenttools.CodeNotFound {
		t.Fatalf("unknown revoke: %v", err)
	}
	bad := raw(t, h.socket, http.MethodGet, "/v1/grants", "", "", "Basic abc")
	if bad.StatusCode != http.StatusUnauthorized {
		t.Fatalf("basic auth: %d", bad.StatusCode)
	}
	_ = bad.Body.Close()
	junk := raw(t, h.socket, http.MethodGet, "/v1/grants", "", "", "Bearer scrim_st_garbage")
	if junk.StatusCode != http.StatusUnauthorized {
		t.Fatalf("junk token: %d", junk.StatusCode)
	}
	_ = junk.Body.Close()
}

// TestTokenFromAnotherProcessTreeIsRefused is the 8.1 verification with real
// kernel peer credentials: a second process mints its own session (as a
// second `scrim run` would), and this process, which is not in that
// process's tree, presents the token and is refused. When the helper exits,
// the sweep revokes its session.
func TestTokenFromAnotherProcessTreeIsRefused(t *testing.T) {
	h := start(t)
	cmd := exec.Command(os.Args[0], "-test.run=^$") // #nosec G204 -- re-executes the test binary
	cmd.Env = append(os.Environ(), "SCRIM_LOCALAPI_HELPER=mint", EnvSocket+"="+h.socket, EnvToken+"=")
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("helper: %v", err)
	}
	tok := strings.TrimSpace(line)
	if !identity.LooksLikeToken([]byte(tok)) {
		t.Fatalf("helper did not print a token: %q", strings.SplitN(tok, " ", 2)[0])
	}
	stolen := NewClient(h.socket, secret.FromString(tok))
	defer stolen.Close()
	_, err = stolen.Grants(bg)
	if codeOf(t, err) != agenttools.CodeUnauthenticated {
		t.Fatalf("stolen token: %v", err)
	}
	if last := h.audit.Last(); last.Detail != string(identity.RefusedWrongTree) || last.PID != int32(os.Getpid()) { // #nosec G115
		t.Fatalf("audit = %+v", last)
	}
	if strings.Contains(err.Error(), tok) {
		t.Fatal("error contains the token")
	}

	_ = stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper exit: %v", err)
	}
	h.srv.SweepOnce(bg)
	if last := h.audit.Last(); last.Tool != "session_revoke" || last.Detail != identity.RevokeRootExited {
		t.Fatalf("sweep audit = %+v", last)
	}
}

func TestUnknownCallersAreRefused(t *testing.T) {
	e := agenttoolstest.NewEnv(t)
	peers, _ := identity.NewPeerMap([]identity.PeerRule{{Agent: "dev", UIDs: []uint32{1000}}}, nil)
	srv := &Server{Resolver: identity.Resolver{Peers: peers}, Tools: e.Service, Auditor: e.Audit}
	h := srv.Handler()
	for _, ctx := range []context.Context{
		context.WithValue(bg, peerKey, identity.Peer{UID: 4242, PID: 9}),
		bg, // no peer credentials at all
	} {
		for _, path := range []string{"/v1/secrets", "/v1/grants"} {
			req := httptest.NewRequestWithContext(ctx, http.MethodGet, path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized {
				t.Errorf("%s: status %d", path, w.Code)
			}
		}
	}
	if last := e.Audit.Last(); last.Tool != ToolAuth || last.Outcome != agenttools.OutcomeRefused || last.Detail != "unknown caller" {
		t.Fatalf("audit = %+v", last)
	}
	req := httptest.NewRequestWithContext(context.WithValue(bg, peerKey, identity.Peer{UID: 4242}), http.MethodGet, "/v1/whoami", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var who identity.Identity
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &who) != nil || who.Source != identity.SourceUnknown {
		t.Fatalf("whoami for unknown: %d %s", w.Code, w.Body.String())
	}
	// Mint without session support configured.
	req = httptest.NewRequestWithContext(context.WithValue(bg, peerKey, identity.Peer{UID: 1000, PID: 1}), http.MethodPost, "/v1/sessions", strings.NewReader(`{}`))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("mint without sessions: %d", w.Code)
	}
}

func TestClientReportsAnUnreachableServer(t *testing.T) {
	c := NewClient(filepath.Join(t.TempDir(), "none.sock"), secret.Value{})
	_, err := c.Grants(bg)
	if codeOf(t, err) != agenttools.CodeUnavailable || !strings.Contains(err.Error(), "none.sock") {
		t.Fatalf("err = %v", err)
	}
}

func TestSocketPathFromEnvironment(t *testing.T) {
	t.Setenv(EnvSocket, "/run/custom.sock")
	if SocketPath() != "/run/custom.sock" {
		t.Fatal(SocketPath())
	}
	t.Setenv(EnvSocket, "")
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	if DefaultSocketPath() != "/run/user/1000/scrim/api.sock" {
		t.Fatal(DefaultSocketPath())
	}
	t.Setenv("XDG_RUNTIME_DIR", "")
	if !strings.HasSuffix(DefaultSocketPath(), fmt.Sprintf("scrim-%d/api.sock", os.Getuid())) {
		t.Fatal(DefaultSocketPath())
	}
}
