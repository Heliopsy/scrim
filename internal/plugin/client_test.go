// SPDX-License-Identifier: AGPL-3.0-only

package plugin_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/heliopsy/scrim/internal/obs"
	hostplugin "github.com/heliopsy/scrim/internal/plugin"
	sdk "github.com/heliopsy/scrim/pkg/plugin"
	pb "github.com/heliopsy/scrim/pkg/plugin/pluginv1"
)

// The test binary doubles as a misbehaving plugin: started by scrim (fd 3
// set), it serves in the mode SCRIM_TEST_PLUGIN_MODE names.
func TestMain(m *testing.M) {
	if os.Getenv("SCRIM_PLUGIN_FD") != "" {
		os.Exit(servePlugin(os.Getenv("SCRIM_TEST_PLUGIN_MODE")))
	}
	os.Exit(m.Run())
}

// testStore is a small in-memory store whose Read misbehaves on request.
type testStore struct {
	mode   string
	marker string
	mu     sync.Mutex
	data   map[string][]byte
}

func (s *testStore) Info() sdk.Info {
	return sdk.Info{Name: "test", Version: "0", Capabilities: []sdk.Capability{sdk.CapRead, sdk.CapWrite}}
}
func (s *testStore) ValidateConfig(sdk.Config) []string { return nil }
func (s *testStore) Configure(_ context.Context, c sdk.Config) error {
	if s.mode == "echo-credential" {
		// A badly written plugin: scrim's log must scrub this.
		fmt.Fprintf(os.Stderr, "configured with token %s\n", c.Secrets["token"])
	}
	if s.mode == "refuse-config" {
		return errors.New("bad options")
	}
	return nil
}

func (s *testStore) Read(_ context.Context, ref sdk.Ref) (sdk.Secret, error) {
	switch s.mode {
	case "crash-once":
		if _, err := os.Stat(s.marker); err != nil {
			_ = os.WriteFile(s.marker, nil, 0o600)
			os.Exit(3)
		}
	case "hang":
		select {}
	case "leak-in-status":
		// The value travels in the error text; scrim must drop it.
		return sdk.Secret{}, fmt.Errorf("%w: value was %s", sdk.ErrNotFound, s.data[ref.Path])
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[ref.Path]
	if !ok {
		return sdk.Secret{}, sdk.ErrNotFound
	}
	return sdk.Secret{Meta: sdk.Metadata{Path: ref.Path}, Fields: map[string][]byte{"value": bytes.Clone(v)}}, nil
}

func (s *testStore) List(context.Context, string) ([]sdk.Metadata, error) {
	return nil, sdk.ErrUnsupported
}

func (s *testStore) Watch(context.Context, string) (<-chan sdk.Change, error) {
	return nil, sdk.ErrUnsupported
}

func (s *testStore) Write(_ context.Context, path string, f map[string][]byte, _ sdk.WriteOptions) (sdk.Metadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[path] = bytes.Clone(f["value"])
	return sdk.Metadata{Path: path}, nil
}

func (s *testStore) Health(context.Context) error { return nil }

func servePlugin(mode string) int {
	switch mode {
	case "exit-at-start":
		return 2
	case "slow-handshake":
		time.Sleep(time.Minute)
		return 0
	case "wrong-protocol":
		return serveRaw(&rawPlugin{protocol: 99, kind: pb.Kind_KIND_STORE})
	case "no-read":
		return serveRaw(&rawPlugin{protocol: hostplugin.Protocol, kind: pb.Kind_KIND_STORE})
	}
	s := &testStore{mode: mode, marker: os.Getenv("SCRIM_TEST_MARKER"), data: map[string][]byte{}}
	if err := sdk.ServeStore(s); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// rawPlugin answers the handshake with whatever it is told to.
type rawPlugin struct {
	pb.UnimplementedPluginServer
	protocol uint32
	kind     pb.Kind
}

func (r *rawPlugin) Handshake(context.Context, *pb.HandshakeRequest) (*pb.HandshakeResponse, error) {
	return &pb.HandshakeResponse{Protocol: r.protocol, Kind: r.kind}, nil
}

type oneListener struct {
	c    chan net.Conn
	done chan struct{}
	once sync.Once
}

func (l *oneListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.c:
		return c, nil
	case <-l.done:
		return nil, errors.New("closed")
	}
}
func (l *oneListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *oneListener) Addr() net.Addr { return &net.UnixAddr{Name: "plugin", Net: "unix"} }

func serveRaw(p pb.PluginServer) int {
	f := os.NewFile(3, "scrim")
	nc, err := net.FileConn(f)
	if err != nil {
		return 1
	}
	l := &oneListener{c: make(chan net.Conn, 1), done: make(chan struct{})}
	l.c <- nc
	srv := grpc.NewServer()
	pb.RegisterPluginServer(srv, p)
	_ = srv.Serve(l)
	return 0
}

func self(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Copy the test binary somewhere private: the build cache directory may
	// be group-writable under some umasks.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(exe) //nolint:gosec // the running test binary
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "plugin")
	if err := os.WriteFile(out, b, 0o700); err != nil { //nolint:gosec // an executable
		t.Fatal(err)
	}
	return out
}

var selfOnce struct {
	sync.Once
	path string
}

func binary(t *testing.T) string {
	selfOnce.Do(func() { selfOnce.path = self(t) })
	if _, err := os.Stat(selfOnce.path); err != nil {
		selfOnce.path = self(t)
	}
	return selfOnce.path
}

func config(t *testing.T, mode string) hostplugin.Config {
	return hostplugin.Config{
		Instance: "test", Kind: pb.Kind_KIND_STORE, Command: binary(t),
		Env:          map[string]string{"SCRIM_TEST_PLUGIN_MODE": mode, "SCRIM_TEST_MARKER": filepath.Join(t.TempDir(), "marker")},
		StartTimeout: 2 * time.Second, CallTimeout: 2 * time.Second, Backoff: 200 * time.Millisecond,
	}
}

func configure(ctx context.Context, conn *grpc.ClientConn) error {
	_, err := pb.NewPluginClient(conn).Configure(ctx, &pb.ConfigRequest{Protocol: hostplugin.Protocol, Instance: "test",
		OptionsJson: []byte("{}"), Secrets: map[string][]byte{"token": []byte(credential)}})
	return err
}

const credential = "cred-0f3a9c1d7e2b4a6f8e0d1c2b"

func read(ctx context.Context, c *hostplugin.Client, path string) (*pb.ReadResponse, error) {
	var resp *pb.ReadResponse
	err := c.Call(ctx, "read", func(ctx context.Context, conn *grpc.ClientConn) error {
		var err error
		resp, err = pb.NewStoreClient(conn).Read(ctx, &pb.ReadRequest{Protocol: hostplugin.Protocol, Ref: &pb.Ref{Path: path}})
		return err
	})
	return resp, err
}

func write(ctx context.Context, c *hostplugin.Client, path, value string) error {
	return c.Call(ctx, "write", func(ctx context.Context, conn *grpc.ClientConn) error {
		_, err := pb.NewStoreClient(conn).Write(ctx, &pb.WriteRequest{Protocol: hostplugin.Protocol, Path: path,
			Fields: []*pb.Field{{Name: "value", Value: []byte(value)}}})
		return err
	})
}

func wantFailure(t *testing.T, err error, want string) {
	t.Helper()
	var f *hostplugin.Failure
	if !errors.As(err, &f) {
		t.Fatalf("err = %v, want a plugin failure", err)
	}
	if f.Code != codes.Unavailable {
		t.Errorf("code = %s, want Unavailable (fail closed)", f.Code)
	}
	if !strings.Contains(err.Error(), "plugin test: ") || !strings.Contains(err.Error(), want) {
		t.Errorf("err = %q, want it to name the plugin and say %q", err, want)
	}
}

func TestWorkingPlugin(t *testing.T) {
	c := hostplugin.NewClient(config(t, "ok"), nil, configure)
	defer func() { _ = c.Close() }()
	if err := write(t.Context(), c, "a", "v1"); err != nil {
		t.Fatal(err)
	}
	resp, err := read(t.Context(), c, "a")
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.GetFields()[0].GetValue()) != "v1" {
		t.Fatal("wrong value")
	}
	if _, err := read(t.Context(), c, "missing"); hostplugin.Code(err) != codes.NotFound {
		t.Fatalf("missing: %v", err)
	}
}

// A crash fails the call closed with a clear error, the next call within
// the backoff is refused without a start, and after the backoff the plugin
// is started again and configured afresh.
func TestCrashFailsClosedAndRestarts(t *testing.T) {
	c := hostplugin.NewClient(config(t, "crash-once"), nil, configure)
	defer func() { _ = c.Close() }()
	if err := write(t.Context(), c, "a", "v1"); err != nil {
		t.Fatal(err)
	}
	_, err := read(t.Context(), c, "a")
	wantFailure(t, err, "exited during read")
	_, err = read(t.Context(), c, "a")
	wantFailure(t, err, "next start in")
	if n := c.Starts(); n != 1 {
		t.Fatalf("%d starts during the backoff, want 1", n)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err = read(t.Context(), c, "a")
		if hostplugin.Code(err) == codes.NotFound {
			break // restarted: the in-memory data went with the old process
		}
		if time.Now().After(deadline) {
			t.Fatalf("no restart after the backoff: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if n := c.Starts(); n != 2 {
		t.Fatalf("%d starts, want 2", n)
	}
}

// A call that hangs past the timeout fails closed and the plugin process is
// killed, not left running.
func TestHangFailsClosedAndKills(t *testing.T) {
	cfg := config(t, "hang")
	cfg.CallTimeout = 300 * time.Millisecond
	c := hostplugin.NewClient(cfg, nil, configure)
	defer func() { _ = c.Close() }()
	if err := write(t.Context(), c, "a", "v1"); err != nil {
		t.Fatal(err)
	}
	pid := c.Pid()
	start := time.Now()
	_, err := read(t.Context(), c, "a")
	wantFailure(t, err, "did not answer read within 300ms; stopped it")
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("hung call took %s", d)
	}
	deadline := time.Now().Add(3 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			t.Fatalf("plugin %d still running after the timeout", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestStartFailures(t *testing.T) {
	for _, tc := range []struct{ mode, want string }{
		{"exit-at-start", "exited during the handshake"},
		{"slow-handshake", "no answer to the handshake within 500ms"},
		{"wrong-protocol", "speaks plugin protocol 99, scrim speaks 1"},
		{"no-read", "store plugin without the read capability"},
		{"refuse-config", "refused its configuration"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			cfg := config(t, tc.mode)
			cfg.StartTimeout = 500 * time.Millisecond
			c := hostplugin.NewClient(cfg, nil, configure)
			defer func() { _ = c.Close() }()
			_, err := read(t.Context(), c, "a")
			if tc.mode == "refuse-config" {
				var f *hostplugin.Failure
				if !errors.As(err, &f) || f.Code != codes.InvalidArgument || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("err = %v", err)
				}
				return
			}
			wantFailure(t, err, tc.want)
		})
	}
}

func TestKindMismatch(t *testing.T) {
	cfg := config(t, "ok")
	cfg.Kind = pb.Kind_KIND_NOTIFIER
	_, err := hostplugin.Validate(t.Context(), cfg, nil)
	wantFailure(t, err, "is a store plugin, configured as a notifier plugin")
}

// A plugin's status message is never repeated: only its code survives, so
// a value a plugin echoes into an error cannot reach scrim's errors.
func TestStatusMessageDropped(t *testing.T) {
	c := hostplugin.NewClient(config(t, "leak-in-status"), nil, configure)
	defer func() { _ = c.Close() }()
	value := "val-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if err := write(t.Context(), c, "a", value); err != nil {
		t.Fatal(err)
	}
	_, err := read(t.Context(), c, "a")
	if hostplugin.Code(err) != codes.NotFound {
		t.Fatalf("code = %s", hostplugin.Code(err))
	}
	if hostplugin.Detail(err) != "" {
		t.Fatalf("detail %q from a plugin status", hostplugin.Detail(err))
	}
	// The SDK sends only the kind's text, so even the raw status is clean.
	if strings.Contains(fmt.Sprintf("%v %+v", err, err), value) {
		t.Fatal("the plugin's status carried the value across")
	}
}

// The plugin's stderr goes through scrim's scrubbing logger.
func TestStderrScrubbed(t *testing.T) {
	var buf syncBuffer
	log := obs.NewLogger(&buf, obs.LogOptions{Scrubber: obs.ReplaceAll(credential)})
	c := hostplugin.NewClient(config(t, "echo-credential"), log, configure)
	if err := write(t.Context(), c, "a", "v"); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(buf.String(), "configured with token") {
		if time.Now().After(deadline) {
			t.Fatalf("plugin stderr not relayed: %q", buf.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if strings.Contains(buf.String(), credential) {
		t.Fatal("the credential reached the log")
	}
	if !strings.Contains(buf.String(), "plugin=test") {
		t.Fatalf("relayed line does not name the plugin: %q", buf.String())
	}
}

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

// The plugin gets only the environment its configuration names.
func TestEnvironment(t *testing.T) {
	t.Setenv("SCRIM_TEST_AMBIENT", "must-not-leak")
	cfg := config(t, "ok")
	cfg.Env["FOO"] = "bar"
	c := hostplugin.NewClient(cfg, nil, configure)
	defer func() { _ = c.Close() }()
	if err := write(t.Context(), c, "a", "v"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", c.Pid()))
	if err != nil {
		t.Skipf("no /proc: %v", err)
	}
	env := strings.Split(string(b), "\x00")
	for _, want := range []string{"FOO=bar", "SCRIM_PLUGIN_FD=3", "SCRIM_PLUGIN_PROTOCOL=1", "SCRIM_PLUGIN_INSTANCE=test", "PATH=" + hostplugin.DefaultPath} {
		if !contains(env, want) {
			t.Errorf("environment lacks %s: %q", want, env)
		}
	}
	for _, e := range env {
		if strings.HasPrefix(e, "SCRIM_TEST_AMBIENT=") || strings.HasPrefix(e, "HOME=") {
			t.Errorf("plugin inherited %s", e)
		}
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
