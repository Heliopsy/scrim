// SPDX-License-Identifier: AGPL-3.0-only

package plugin_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/plugin/plugintest"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	storeplugin "github.com/heliopsy/scrim/internal/stores/plugin"
	"github.com/heliopsy/scrim/internal/stores/refresh"
	"github.com/heliopsy/scrim/internal/stores/storeconfig"
	"github.com/heliopsy/scrim/internal/stores/storetest"
)

func TestMain(m *testing.M) {
	if os.Getenv("SCRIM_PLUGIN_FD") != "" && os.Getenv("SCRIM_TEST_RAW") == "1" {
		os.Exit(serveRaw())
	}
	code := m.Run()
	plugintest.Cleanup()
	os.Exit(code)
}

func noResolve(context.Context, config.SecretRef) (secret.Value, error) {
	return secret.Value{}, errors.New("no credentials in this test")
}

// open builds a plugin-backed adapter for the example dirstore plugin.
func open(t testing.TB, root string, extra map[string]any) stores.Adapter {
	t.Helper()
	bin := plugintest.Build(t, "./examples/plugins/dirstore")
	opts := map[string]any{
		"command": bin,
		"options": map[string]any{"root": root, "poll-interval": "50ms"},
		"timeout": "5s",
	}
	for k, v := range extra {
		opts[k] = v
	}
	a, err := stores.DefaultRegistry.Open(context.Background(), stores.Instance{
		Name: "dir", Kind: storeplugin.Kind, Options: opts, Resolve: noResolve,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return a
}

func newRoot(t testing.TB) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "store")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

// The store conformance suite through the plugin bridge, against the
// example plugin (tasks.md 15.6).
func TestConformance(t *testing.T) {
	storetest.Run(t, func(t storetest.TB) storetest.Harness {
		root := newRoot(t.(testing.TB))
		a := open(t.(testing.TB), root, nil)
		return storetest.Harness{
			Adapter: a,
			Delete: func(t storetest.TB, ref stores.Ref) {
				if err := os.Remove(filepath.Join(root, filepath.FromSlash(ref.Path)) + ".secret.json"); err != nil {
					t.Fatalf("delete: %v", err)
				}
			},
			// The store's directory disappearing is an outage.
			Outage: func(t storetest.TB) func() {
				if err := os.Rename(root, root+".down"); err != nil {
					t.Fatalf("outage: %v", err)
				}
				return func() {
					if err := os.Rename(root+".down", root); err != nil {
						t.Fatalf("restore: %v", err)
					}
				}
			},
			VersionSelector: true,
			Labels:          true,
			WatchTimeout:    5 * time.Second,
		}
	})
}

// With capabilities narrowed to read and list, scrim refuses writes and
// watches before the plugin sees them, and the suite still passes.
func TestConformanceNarrowed(t *testing.T) {
	storetest.Run(t, func(t storetest.TB) storetest.Harness {
		root := newRoot(t.(testing.TB))
		writer := open(t.(testing.TB), root, nil)
		t.Cleanup(func() { _ = writer.Close() })
		a := open(t.(testing.TB), root, map[string]any{"capabilities": []any{"read", "list"}})
		if a.Capabilities() != stores.CapRead|stores.CapList {
			t.Fatalf("capabilities = %s", a.Capabilities())
		}
		return storetest.Harness{
			Adapter: a,
			Seed: func(t storetest.TB, ref stores.Ref, fields map[string]secret.Value) {
				if _, err := writer.Write(t.Context(), ref, fields, stores.WriteOptions{}); err != nil {
					t.Fatalf("seed: %v", err)
				}
			},
		}
	})
}

func TestCapabilitiesBeyondThePluginRefused(t *testing.T) {
	bin := plugintest.Build(t, "./examples/plugins/dirstore")
	_, err := stores.DefaultRegistry.Open(t.Context(), stores.Instance{Name: "dir", Kind: storeplugin.Kind, Resolve: noResolve,
		Options: map[string]any{"command": bin, "options": map[string]any{"root": "/nonexistent"}, "capabilities": []any{"read", "glob"}}})
	if err == nil || !strings.Contains(err.Error(), "glob") {
		t.Fatalf("err = %v, want a refusal naming glob", err)
	}
}

func build(t *testing.T, yaml string, environ ...string) (*config.Config, error) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "scrim.yaml")
	if err := os.WriteFile(p, []byte("apiVersion: scrim.dev/v1\nkind: Config\n"+yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return config.Build(config.Options{ConfigPaths: []string{p}, Environ: environ, SystemDir: dir})
}

// Configuration loading validates a plugin store through the stores
// collection: the plugin itself checks its options, scrim checks the
// binary and the fields it owns.
func TestConfigValidation(t *testing.T) {
	bin := plugintest.Build(t, "./examples/plugins/dirstore")
	root := newRoot(t)
	writable := filepath.Join(t.TempDir(), "writable")
	b, err := os.ReadFile(bin) //nolint:gosec // test binary
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(writable, b, 0o755); err != nil { //nolint:gosec // executable on purpose
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o757); err != nil { //nolint:gosec // world-writable on purpose
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, yaml, want string
	}{
		{"valid", "stores:\n  dir:\n    kind: plugin\n    command: " + bin + "\n    options: {root: " + root + "}\n", ""},
		{"plugin refuses an option", "stores:\n  dir:\n    kind: plugin\n    command: " + bin + "\n    options: {root: relative/path}\n", "options.root must be an absolute"},
		{"plugin refuses an unknown option", "stores:\n  dir:\n    kind: plugin\n    command: " + bin + "\n    options: {root: " + root + ", colour: blue}\n", "colour"},
		{"unknown field", "stores:\n  dir:\n    kind: plugin\n    command: " + bin + "\n    colour: blue\n", "unknown field colour"},
		{"relative command", "stores:\n  dir:\n    kind: plugin\n    command: bin/dirstore\n", "not an absolute path"},
		{"missing command", "stores:\n  dir:\n    kind: plugin\n    options: {root: " + root + "}\n", "command is required"},
		{"world-writable binary", "stores:\n  dir:\n    kind: plugin\n    command: " + writable + "\n", "writable by every user"},
		{"pinned digest mismatch", "stores:\n  dir:\n    kind: plugin\n    command: " + bin + "\n    sha256: \"" + strings.Repeat("0", 64) + "\"\n    options: {root: " + root + "}\n", "sha256 is"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := build(t, tc.yaml)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("valid configuration refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

// A credential field reaches the plugin resolved, and the plugin's refusal
// of it is reported without the value.
func TestCredentialsNeverInErrors(t *testing.T) {
	bin := plugintest.Build(t, "./examples/plugins/dirstore")
	root := newRoot(t)
	token := "tok-" + strings.Repeat("ab", 12) + time.Now().Format("150405.000000")
	cfg, err := build(t, "stores:\n  dir:\n    kind: plugin\n    command: "+bin+"\n    options: {root: "+root+"}\n    token: env:DIR_TOKEN\n",
		"DIR_TOKEN="+token)
	if err == nil {
		t.Fatal("dirstore takes no credentials; validation must refuse the token field")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatal("validation error contains the credential")
	}
	_ = cfg
	if !strings.Contains(err.Error(), "remove token") {
		t.Fatalf("err = %v, want the plugin's problem naming the field", err)
	}
}

// The adapter is found through the configuration like any other store.
func TestOpenThroughStoreConfig(t *testing.T) {
	bin := plugintest.Build(t, "./examples/plugins/dirstore")
	root := newRoot(t)
	cfg, err := build(t, "stores:\n  dir:\n    kind: plugin\n    command: "+bin+"\n    options: {root: "+root+"}\n")
	if err != nil {
		t.Fatal(err)
	}
	o, err := storeconfig.Open(t.Context(), cfg, stores.DefaultRegistry)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	ref := stores.MustParseRef("dir://app/db")
	v := secret.FromString("generated-" + time.Now().Format("150405.000000"))
	if _, err := o.Set.Write(t.Context(), ref, map[string]secret.Value{"password": v}, stores.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	got, err := o.Set.Read(t.Context(), ref.WithField("password"))
	if err != nil {
		t.Fatal(err)
	}
	defer got.Wipe()
	if !got.Fields["password"].Equal(v) {
		t.Fatal("value did not round-trip through the plugin")
	}
}

// specs/secret-stores "Plugin crashes": a store plugin that dies leaves the
// store degraded with its last known values still in the redaction set,
// and is restarted with backoff.
func TestCrashKeepsLastKnownValues(t *testing.T) {
	root := newRoot(t)
	a := open(t, root, nil)
	defer func() { _ = a.Close() }()
	ref := stores.MustParseRef("dir://app/api")
	value := "generated-" + time.Now().Format("150405.000000")
	if _, err := a.Write(t.Context(), ref, map[string]secret.Value{"token": secret.FromString(value)}, stores.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	target, err := refresh.ParseTarget("dir://app/*")
	if err != nil {
		t.Fatal(err)
	}
	r := refresh.New(a, refresh.Config{Targets: []refresh.Target{target}, Jitter: -1})
	defer r.Close()
	if err := r.RefreshNow(t.Context()); err != nil {
		t.Fatal(err)
	}

	client := a.(*storeplugin.Adapter).Client()
	pid := client.Pid()
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	for client.Pid() == pid {
		time.Sleep(10 * time.Millisecond)
	}
	err = r.RefreshNow(t.Context())
	if !errors.Is(err, stores.ErrUnavailable) || !strings.Contains(err.Error(), "plugin exited (signal: killed)") {
		t.Fatalf("refresh after the crash: %v, want ErrUnavailable naming the plugin", err)
	}
	if st := r.Status(); st.State != refresh.StateDegraded {
		t.Fatalf("state %s after the crash, want degraded", st.State)
	}
	held := false
	r.EachValue(func(_ refresh.Source, v secret.Value) {
		_ = v.Expose(func(b []byte) error { held = held || string(b) == value; return nil })
	})
	if !held {
		t.Fatal("the last known value left the redaction set when the plugin crashed")
	}
	// After the backoff the plugin is started again and the store recovers.
	deadline := time.Now().Add(5 * time.Second)
	for r.RefreshNow(t.Context()) != nil {
		if time.Now().After(deadline) {
			t.Fatal("store did not recover after the plugin restart")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if st := r.Status(); st.State != refresh.StateReady || client.Starts() != 2 {
		t.Fatalf("state %s after %d starts", st.State, client.Starts())
	}
}
