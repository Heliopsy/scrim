// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/app"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/secret"
)

// storeRefFixture is a file store named "files" with one generated secret
// per name, and the config options that configure it.
type storeRefFixture struct {
	dir, root string
	values    map[string]string
}

func newStoreRefFixture(t *testing.T) *storeRefFixture {
	t.Helper()
	dir := t.TempDir()
	f := &storeRefFixture{dir: dir, root: filepath.Join(dir, "store"), values: map[string]string{}}
	if err := os.MkdirAll(f.root, 0o700); err != nil {
		t.Fatal(err)
	}
	return f
}

// put writes a generated value under name and returns its reference.
func (f *storeRefFixture) put(t *testing.T, name string) config.SecretRef {
	t.Helper()
	v := leak.Generate(leak.KindAPIKey).Value()
	if err := os.WriteFile(filepath.Join(f.root, name), []byte(v), 0o600); err != nil {
		t.Fatal(err)
	}
	f.values[name] = v
	return config.SecretRef("files://" + name)
}

// options writes the config file (the store plus extra YAML) and returns
// options reading it and env.
func (f *storeRefFixture) options(t *testing.T, extra string, env ...string) config.Options {
	t.Helper()
	path := filepath.Join(f.dir, "scrim.yaml")
	doc := "apiVersion: scrim.dev/v1\nkind: Config\nstores:\n  files:\n    kind: file\n    root: " + f.root + "\n" + extra
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return config.Options{
		Registry:    config.Default,
		ConfigPaths: []string{path},
		Environ:     append([]string{"HOME=" + f.dir, "XDG_CONFIG_HOME=" + f.dir, "XDG_STATE_HOME=" + f.dir}, env...),
		SystemDir:   f.dir,
	}
}

func equalTo(v secret.Value, want string) bool {
	ok := false
	_ = v.Expose(func(b []byte) error { ok = string(b) == want; return nil })
	return ok
}

// TestStoreReferencesInSettingsResolve: every secret-ref setting and every
// collection secret field outside `stores` accepts a store reference, and
// the running configuration holds the value read from the store. The
// settings are taken from the registry, so a new one is covered without
// editing this test.
func TestStoreReferencesInSettingsResolve(t *testing.T) {
	f := newStoreRefFixture(t)
	var env, keys []string
	for _, s := range config.Default.Settings() {
		if s.Kind != config.KindSecretRef {
			continue
		}
		name := "s-" + strings.ReplaceAll(s.Key, ".", "-")
		env = append(env, s.EnvVar()+"="+string(f.put(t, name)))
		keys = append(keys, s.Key)
	}
	if len(keys) < 10 {
		t.Fatalf("only %d secret-ref settings found", len(keys))
	}
	// Collections with secret fields: each is listed here, so a new one
	// fails the test until it is covered.
	collections := map[string]string{
		"databases": "databases:\n  app:\n    kind: postgres\n    address: 127.0.0.1:1\n    user: app\n    password: " +
			string(f.put(t, "c-db")) + "\n",
		"redaction.placeholder-keys": "redaction:\n  placeholder-keys:\n    k1:\n      version: 1\n      key: " +
			string(f.put(t, "c-pk")) + "\n",
		// A store's credential from another store: TestIdentityFromAnotherStore
		// (internal/stores/sops); into itself or around a cycle:
		// TestStoreCredentialStoreReferenceRejected (storeconfig).
		"stores": "",
	}
	for _, c := range config.Default.Collections() {
		if len(c.SecretFields) == 0 {
			continue
		}
		if _, ok := collections[c.Key]; !ok {
			t.Errorf("collection %s has secret fields and no case in this test", c.Key)
		}
	}
	extra := collections["databases"] + collections["redaction.placeholder-keys"]

	var logs bytes.Buffer
	a, err := app.New(context.Background(), f.options(t, extra, env...), &logs)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	defer func() { _ = a.Close() }()
	cfg := a.Config.Current()
	if u := cfg.Unresolved(); len(u) > 0 {
		t.Errorf("unresolved after start: %v", u)
	}
	for _, key := range keys {
		want := f.values["s-"+strings.ReplaceAll(key, ".", "-")]
		v, ok := cfg.SecretAt(key)
		if !ok || !equalTo(v, want) {
			t.Errorf("%s: store reference did not resolve to the stored value (resolved %v)", key, ok)
		}
	}
	for key, name := range map[string]string{"databases.app.password": "c-db", "redaction.placeholder-keys.k1.key": "c-pk"} {
		if v, ok := cfg.SecretAt(key); !ok || !equalTo(v, f.values[name]) {
			t.Errorf("%s: store reference did not resolve to the stored value (resolved %v)", key, ok)
		}
	}
	// References outside settings (identity.store-credentials, catalog)
	// resolve through the running configuration too.
	ref := f.put(t, "r-agent-token")
	v, err := cfg.ResolveRef(context.Background(), ref)
	if err != nil || !equalTo(v, f.values["r-agent-token"]) {
		t.Errorf("ResolveRef(%s): %v", ref, err)
	}
	for name, val := range f.values {
		if strings.Contains(logs.String(), val) {
			t.Errorf("value of %s in the log", name)
		}
	}
}

// appendConfig adds YAML to the harness's config file.
func (h *harness) appendConfig(t *testing.T, yaml string) {
	t.Helper()
	p := h.opts.Config.ConfigPaths[0]
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, append(b, yaml...), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestMetricsTokenFromStore: metrics.auth.token given as a store reference
// guards the scrape endpoint with the stored token. Unresolved, the
// listener served metrics without any token.
func TestMetricsTokenFromStore(t *testing.T) {
	scrapeToken := seed(t, "scrape-")
	h := newHarness(t, seed(t, "tok-"))
	t.Setenv("SCRIMTEST_METRICS_TOKEN", scrapeToken)
	h.opts.Config.Environ = append(h.opts.Config.Environ, "SCRIM_METRICS_ENABLED=true",
		"SCRIM_METRICS_AUTH_TOKEN=testenv://SCRIMTEST_METRICS_TOKEN")
	d := startDaemon(t, h)
	addr := d.Addrs().Metrics
	if code, _ := scrapeMetrics(t, addr, "/metrics", ""); code != http.StatusUnauthorized {
		t.Fatalf("scrape without token = %d, want 401", code)
	}
	code, page := scrapeMetrics(t, addr, "/metrics", scrapeToken)
	if code != http.StatusOK {
		t.Fatalf("scrape with the stored token = %d", code)
	}
	assertNoLeak(t, page+h.logs.String(), scrapeToken)
}

// TestAdminTokenFromStore: admin.token given as a store reference lets the
// daemon serve a TCP admin listener guarded by the stored token, and a
// client whose configuration is built without stores (scrim approve, scrim
// status, scrim run) reads the token from the store to call it.
func TestAdminTokenFromStore(t *testing.T) {
	adminToken := seed(t, "admin-")
	h := newHarness(t, seed(t, "tok-"))
	t.Setenv("SCRIMTEST_ADMIN_TOKEN", adminToken)
	h.opts.Config.Environ = append(h.opts.Config.Environ, "SCRIM_ADMIN_URL=http://127.0.0.1:0",
		"SCRIM_ADMIN_TOKEN=testenv://SCRIMTEST_ADMIN_TOKEN")
	d := startDaemon(t, h)
	addr := d.Addrs().Admin

	resp, err := http.Get(addr + "/v1/daemon")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("admin API without token = %d, want 401", resp.StatusCode)
	}
	opts := h.opts.Config
	opts.Environ = append(slices.Clone(opts.Environ), "SCRIM_ADMIN_URL="+addr)
	client, err := config.Build(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(client.Unresolved(), AdminToken.Name()) {
		t.Fatalf("client configuration resolved the store reference itself: %v", client.Unresolved())
	}
	in, err := Connect(t.Context(), client)
	if err != nil {
		t.Fatalf("client with the token from the store: %v", err)
	}
	if !in.Ready {
		t.Fatalf("daemon info %+v", in)
	}
	assertNoLeak(t, h.logs.String(), adminToken)
}

// TestProviderCredentialFromStore: a cloud provider credential is a store
// reference no redact target or catalog entry covers; it is loaded with its
// store and travels in the snapshot with the route that names it. Before,
// nothing loaded it and the route answered credential_unavailable.
func TestProviderCredentialFromStore(t *testing.T) {
	key := seed(t, "cloud-")
	h := newHarness(t, seed(t, "tok-"))
	t.Setenv("SCRIMTEST_CLOUD_KEY", key)
	h.appendConfig(t, "providers:\n  azure:\n    kind: foundry\n    resource: res\n    api-key: testenv://SCRIMTEST_CLOUD_KEY\n")
	startDaemon(t, h)
	eventually(t, "the provider credential in the snapshot", func() bool {
		snap := h.snapshot(t)
		var ref string
		for _, r := range snap.GetRoutes() {
			if r.GetName() == "azure" {
				ref = r.GetAuth().GetHeader().GetValueRef()
			}
		}
		if ref == "" {
			return false
		}
		for _, e := range snap.GetValues() {
			if e.GetRef() == ref && string(e.GetValue()) == key {
				return true
			}
		}
		return false
	})
	assertNoLeak(t, h.logs.String(), key)
}

// TestStoreReferenceSettingsReload: a store reference in a setting is read
// again on every reload, so a rotated value applies with the next reload;
// a reference the stores cannot resolve stops start-up naming the setting
// and the reference, and a reload that cannot resolve one is rejected and
// keeps the running value.
func TestStoreReferenceSettingsReload(t *testing.T) {
	f := newStoreRefFixture(t)
	ref := f.put(t, "webhook")
	opts := f.options(t, "", "SCRIM_NOTIFY_WEBHOOK_SECRET="+string(ref))
	var logs bytes.Buffer
	a, err := app.New(context.Background(), opts, &logs)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	first := f.values["webhook"]
	f.put(t, "webhook")
	if res := a.Config.Reload(t.Context(), "test"); !res.Applied || !slices.Contains(res.Changed, "notify.webhook.secret") {
		t.Fatalf("reload after rotation: %+v", res)
	}
	if v, ok := a.Config.Current().SecretAt("notify.webhook.secret"); !ok || !equalTo(v, f.values["webhook"]) {
		t.Fatal("the rotated value is not in force after the reload")
	}
	if err := os.Remove(filepath.Join(f.root, "webhook")); err != nil {
		t.Fatal(err)
	}
	if res := a.Config.Reload(t.Context(), "test"); res.Applied {
		t.Fatalf("reload with a missing secret applied: %+v", res)
	}
	if v, ok := a.Config.Current().SecretAt("notify.webhook.secret"); !ok || !equalTo(v, f.values["webhook"]) {
		t.Fatal("a rejected reload changed the running value")
	}

	bad := f.options(t, "", "SCRIM_NOTIFY_WEBHOOK_SECRET=files://nosuch", "SCRIM_ADMIN_TOKEN=nostore://x")
	b, err := app.New(context.Background(), bad, &logs)
	if err == nil {
		_ = b.Close()
		t.Fatal("started with store references that do not resolve")
	}
	for _, want := range []string{"notify.webhook.secret", "files://nosuch", "admin.token", "nostore://x"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("start-up error %q does not name %s", err, want)
		}
	}
	for _, v := range []string{first, f.values["webhook"]} {
		if strings.Contains(logs.String(), v) || strings.Contains(err.Error(), v) {
			t.Error("a value reached the log or an error")
		}
	}
}
