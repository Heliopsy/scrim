// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/heliopsy/scrim/internal/approval"
	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/config"
	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/testing/testhome"
)

// syncBuffer is a log sink the daemon writes to from many goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func seed(t *testing.T, prefix string) string {
	t.Helper()
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

type harness struct {
	dir, fakeDir, admin string
	opts                Options
	logs                *syncBuffer
}

// newHarness writes a config with an env store holding token, a memory
// store for captures, a catalog entry binding the token to a host, and
// every listener in a temporary directory. Sockets live under a short
// directory: Unix socket paths are limited to about 100 bytes.
func newHarness(t *testing.T, token string, extraEnv ...string) *harness {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("peer credentials are implemented on Linux and macOS")
	}
	sock, err := os.MkdirTemp("", "scrim-d")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sock) })
	dir := t.TempDir()
	h := &harness{dir: dir, fakeDir: filepath.Join(dir, "fake"), admin: filepath.Join(sock, "admin.sock"), logs: &syncBuffer{}}
	if err := os.MkdirAll(h.fakeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	rules := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(rules, []byte(`default: deny
rules:
  - name: capture-issued
    decision: allow
    when: op == "store.write" && secret.store == "vault"
  - name: inject-ask
    decision: ask
    when: op == "inject"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := "apiVersion: " + config.APIVersion + "\nkind: Config\n" + `state:
  backend: sqlite
  sqlite: {path: ` + filepath.Join(dir, "state.db") + `}
stores:
  testenv:
    kind: env
    prefix: SCRIMTEST_
    redact: ["testenv://SCRIMTEST_TOKEN"]
  vault:
    kind: memory
catalog:
  entries:
    acme:
      ref: testenv://SCRIMTEST_TOKEN
      hosts: [api.acme.test]
      placeholder: SCRIM_ACME_KEY
policy:
  rules-file: ` + rules + `
approvals:
  timeout: 2s
notify:
  terminal: {enabled: false}
api:
  socket: ` + filepath.Join(sock, "api.sock") + `
admin:
  url: unix:` + h.admin + `
metrics:
  listen: 127.0.0.1:0
proxy:
  listen: 127.0.0.1:0
  forward-listen: 127.0.0.1:0
redaction:
  placeholder-key-dir: ` + filepath.Join(dir, "keys") + `
tool-proxy:
  ca: {dir: ` + filepath.Join(dir, "ca") + `}
  capture-rules:
    issued:
      hosts: [api.example.com]
      json-pointer: /token
      store-ref: vault://issued/token
dataplane:
  push-debounce: 10ms
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SCRIMTEST_TOKEN", token)
	h.opts = Options{
		Config: config.Options{Registry: config.Default, ConfigPaths: []string{cfgPath}, SystemDir: dir,
			Environ: testhome.Environ(t, "SCRIM_DATAPLANE_PATH="+exe)},
		LogOutput:    h.logs,
		DataPlaneEnv: append([]string{"SCRIM_FAKE_DP=1", "SCRIM_FAKE_DIR=" + h.fakeDir}, extraEnv...),
	}
	return h
}

func (h *harness) snapshot(t *testing.T) *pb.Snapshot {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(h.fakeDir, "snap.pb"))
	if err != nil {
		t.Fatal(err)
	}
	var s pb.Snapshot
	if err := proto.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	return &s
}

func eventually(t *testing.T, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !fn() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func valueFor(s *pb.Snapshot, ref string) *pb.ValueEntry {
	for _, v := range s.GetValues() {
		if v.GetRef() == ref {
			return v
		}
	}
	return nil
}

// TestDaemonServesAndPushes starts the whole daemon against a fake data
// plane and checks every wire: the first snapshot (values with bindings,
// placeholder key, policy table, listeners, capture rules, CA), the admin
// API and info file, metrics and health, the ask and capture callbacks, the
// event audit, the push after a capture, the agent API socket, shutdown, and
// that no seeded value reaches any log.
func TestDaemonServesAndPushes(t *testing.T) {
	token := seed(t, "tok-")
	captured := seed(t, "cap-")
	h := newHarness(t, token, "SCRIM_FAKE_ASK_REF=testenv://SCRIMTEST_TOKEN",
		"SCRIM_FAKE_CAPTURE_REF=vault://issued/token", "SCRIM_FAKE_CAPTURE_VALUE="+captured)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	d, err := Start(ctx, h.opts)
	if err != nil {
		t.Fatal(err)
	}
	stopped := false
	defer func() {
		if !stopped {
			_ = d.Shutdown(context.Background())
		}
	}()
	if err := d.WaitReady(ctx); err != nil {
		t.Fatalf("%v\n%s", err, h.logs.String())
	}

	// First snapshot.
	s := h.snapshot(t)
	v := valueFor(s, "testenv://SCRIMTEST_TOKEN#value")
	if v == nil || string(v.GetValue()) != token {
		t.Fatalf("token not in snapshot: %v", s.GetValues())
	}
	if v.GetName() != "acme" || v.GetSlug() != "acme" || strings.Join(v.GetBoundHosts(), ",") != "api.acme.test" ||
		strings.Join(v.GetDeclaredPlaceholders(), ",") != "SCRIM_ACME_KEY" || v.GetClass() != pb.ValueClass_VALUE_CLASS_CREDENTIAL {
		t.Fatalf("binding = %v", v)
	}
	if len(s.GetPlaceholderKeys()) != 1 || !s.GetPlaceholderKeys()[0].GetCurrent() || len(s.GetPlaceholderKeys()[0].GetKey()) < 16 {
		t.Fatalf("keys = %v", s.GetPlaceholderKeys())
	}
	// The two file rules, then the built-in injection rule; the ask timeout
	// is approvals.timeout.
	if tb := s.GetPolicy().GetTable(); len(tb) != 3 || tb[2].GetName() != policy.BuiltinInjectRule ||
		s.GetPolicy().GetDefaultEffect() != pb.Effect_EFFECT_DENY || s.GetPolicy().GetAskTimeoutMillis() == 0 {
		t.Fatalf("policy = %v", s.GetPolicy())
	}
	if len(s.GetListeners()) != 2 || len(s.GetRoutes()) != 5 || len(s.GetCaptureRules()) != 1 || s.GetCaptureRules()[0].GetStoreRef() != "vault://issued/token" {
		t.Fatalf("listeners %v routes %v capture rules %v", s.GetListeners(), s.GetRoutes(), s.GetCaptureRules())
	}
	if len(s.GetToolProxyCa()) != 1 || !s.GetToolProxyCa()[0].GetCurrent() || !strings.Contains(string(s.GetToolProxyCa()[0].GetKeyPem()), "PRIVATE KEY") {
		t.Fatal("tool-proxy CA missing from the snapshot")
	}
	caKey := string(s.GetToolProxyCa()[0].GetKeyPem())

	// Addresses and discovery.
	addrs := d.Addrs()
	if !strings.HasPrefix(addrs.BaseURL, "http://127.0.0.1:") || addrs.ForwardProxy == "" || addrs.AgentAPI == "" || addrs.Admin != "unix:"+h.admin || addrs.Metrics == "" {
		t.Fatalf("addrs = %+v", addrs)
	}
	cfg, err := config.Build(h.opts.Config)
	if err != nil {
		t.Fatal(err)
	}
	info, err := Connect(ctx, cfg)
	if err != nil || !info.Ready || info.PID != os.Getpid() || info.Addrs.AgentAPI != addrs.AgentAPI {
		t.Fatalf("Connect = %+v %v", info, err)
	}
	if _, err := os.Stat(InfoPath(addrs.Admin)); err != nil {
		t.Fatalf("info file: %v", err)
	}

	// Admin API over the socket, attributed by peer credentials.
	ac, err := approval.NewClient(addrs.Admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ac.ListApprovals(ctx, "", ""); err != nil {
		t.Fatalf("admin API: %v", err)
	}
	trust := httpGetUnix(t, h.admin, "/v1/ca")
	if !strings.Contains(trust, "BEGIN CERTIFICATE") || strings.Contains(trust, "PRIVATE KEY") {
		t.Fatalf("GET /v1/ca = %q", trust)
	}

	// Health and metrics.
	if body := httpGet(t, "http://"+addrs.Metrics+"/readyz"); !strings.Contains(body, `"ok"`) {
		t.Fatalf("readyz = %s", body)
	}

	// The ask goes through the gate: an inject ask by an unknown agent is
	// held for approval and denied when it times out.
	eventually(t, "the ask answer", func() bool { _, err := os.Stat(filepath.Join(h.fakeDir, fakeAskFile)); return err == nil })
	if ans := readJSON(t, filepath.Join(h.fakeDir, fakeAskFile)); ans["effect"] != "EFFECT_DENY" {
		t.Fatalf("ask answer = %v", ans)
	}

	// The capture is written to the memory store, answered with the
	// placeholder of the stored value, and pushed in a new snapshot.
	eventually(t, "the capture result", func() bool { _, err := os.Stat(filepath.Join(h.fakeDir, fakeCaptureFile)); return err == nil })
	res := readJSON(t, filepath.Join(h.fakeDir, fakeCaptureFile))
	ph, _ := res["placeholder"].(string)
	if res["error"] != "" || !strings.HasPrefix(ph, "⟦scrim:vault-issued-token-value:01") {
		t.Fatalf("capture result = %v", res)
	}
	eventually(t, "the captured value in a snapshot", func() bool {
		e := valueFor(h.snapshot(t), "vault://issued/token#value")
		return e != nil && string(e.GetValue()) == captured && len(e.GetBoundHosts()) == 0
	})

	// The data plane's event is in the audit log, metadata only.
	eventually(t, "the redaction audit entry", func() bool {
		var found bool
		_ = d.App().State.View(ctx, func(tx state.Tx) error {
			es, err := tx.QueryAudit(ctx, state.AuditQuery{Action: "dataplane.redaction"})
			found = err == nil && len(es) == 1 && es[0].RequestID == "req-1" && es[0].Outcome == audit.OutcomeOK
			return nil
		})
		return found
	})

	// Graceful shutdown removes the sockets and the info file.
	if err := d.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	stopped = true
	for _, p := range []string{h.admin, addrs.AgentAPI, InfoPath(addrs.Admin)} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s still exists after shutdown (%v)", p, err)
		}
	}
	if _, err := Connect(ctx, cfg); err == nil {
		t.Fatal("Connect succeeded after shutdown")
	}

	logs := h.logs.String()
	for name, v := range map[string]string{"token": token, "captured value": captured, "CA key": caKey} {
		if strings.Contains(logs, v) {
			t.Fatalf("%s appears in the daemon log", name)
		}
	}
	if !strings.Contains(logs, "scrim daemon started") || !strings.Contains(logs, "snapshot applied") {
		t.Fatalf("log = %s", logs)
	}
}

func TestStartRefusesOpenCaptureDir(t *testing.T) {
	h := newHarness(t, seed(t, "tok-"))
	dir := filepath.Join(h.dir, "capture")
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // the test needs an open directory
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // as above
		t.Fatal(err)
	}
	h.opts.Capture = dir
	if _, err := Start(context.Background(), h.opts); err == nil || !strings.Contains(err.Error(), "group or others") {
		t.Fatalf("Start = %v", err)
	}
}

func TestCaptureFlagReachesSnapshot(t *testing.T) {
	h := newHarness(t, seed(t, "tok-"))
	h.opts.Capture = filepath.Join(h.dir, "capture")
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
	env := strings.Join(d.Supervisor().Options.ExtraEnv, "\n")
	if !strings.Contains(env, "SCRIM_DP_CAPTURE_DIR="+h.opts.Capture+"\n") || !strings.Contains(env, "SCRIM_DP_CAPTURE_RETENTION_SECS=604800") {
		t.Fatalf("data plane environment = %q", env)
	}
	if fi, err := os.Stat(h.opts.Capture); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("capture dir: %v %v", fi, err)
	}
	if d.Info().Capture != h.opts.Capture {
		t.Fatalf("info = %+v", d.Info())
	}
}

// TestSecondDaemonRefused: the SQLite file and the sockets belong to one
// daemon; Ensure reuses it instead of starting another.
func TestEnsureReusesRunningDaemon(t *testing.T) {
	h := newHarness(t, seed(t, "tok-"))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	in, d, err := Ensure(ctx, h.opts)
	if err != nil || d == nil || !in.Ready {
		t.Fatalf("first Ensure = %+v %v %v", in, d, err)
	}
	defer func() { _ = d.Shutdown(context.Background()) }()
	in2, d2, err := Ensure(ctx, h.opts)
	if err != nil || d2 != nil || in2.PID != in.PID || in2.Addrs.BaseURL != in.Addrs.BaseURL {
		t.Fatalf("second Ensure = %+v %v %v", in2, d2, err)
	}
	if _, err := Start(ctx, h.opts); err == nil {
		t.Fatal("a second daemon started on the same state and sockets")
	}
}

func httpGet(t *testing.T, url string) string {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func httpGetUnix(t *testing.T, sock, path string) string {
	t.Helper()
	hc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://scrim"+path, nil)
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}
