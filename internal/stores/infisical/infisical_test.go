// SPDX-License-Identifier: AGPL-3.0-only

package infisical

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/storetest"
)

// resolver serves secret-valued options from a map, as the config loader
// would from env:, file: and friends.
func resolver(m map[string]string) func(context.Context, config.SecretRef) (secret.Value, error) {
	return func(_ context.Context, ref config.SecretRef) (secret.Value, error) {
		v, ok := m[string(ref)]
		if !ok && !strings.Contains(string(ref), ":") {
			// A literal resolves to itself, as in the config loader.
			return secret.FromString(string(ref)), nil
		}
		if !ok {
			return secret.Value{}, fmt.Errorf("reference %s does not resolve", ref)
		}
		return secret.FromString(v), nil
	}
}

func instance(name, addr, clientID, clientSecret string, extra map[string]any) stores.Instance {
	opts := map[string]any{
		"address": addr,
		"auth": map[string]any{
			"method": "universal-auth",
		},
		"client-id":     clientID,
		"client-secret": config.SecretRef("env:INF_SECRET"),
	}
	for k, v := range extra {
		opts[k] = v
	}
	return stores.Instance{
		Name: name, Kind: Kind, Options: opts,
		Resolve: resolver(map[string]string{"env:INF_SECRET": clientSecret}),
	}
}

func newAdapter(t testing.TB, f *fake, extra map[string]any) *Adapter {
	t.Helper()
	a, err := New(t.Context(), instance("inf", f.srv.URL, f.clientID, f.clientSecret, extra))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a.(*Adapter)
}

func plain(t testing.TB, v secret.Value) string {
	t.Helper()
	var s string
	_ = v.Expose(func(b []byte) error { s = string(b); return nil })
	return s
}

func TestConformanceFake(t *testing.T) {
	f := newFake(t)
	runConformance(t, func(t storetest.TB) storetest.Harness {
		a := newAdapter(t.(testing.TB), f, map[string]any{"watch.interval": "50ms", "watch.max-backoff": "200ms"})
		return storetest.Harness{
			Adapter:         a,
			Prefix:          "proj/dev/conf-" + randID(4),
			SingleField:     Field,
			VersionSelector: true,
			Labels:          true,
			Delete: func(t storetest.TB, ref stores.Ref) {
				l, _ := splitSecret(ref.Path)
				f.mu.Lock()
				delete(f.secrets, skey(f.projects["proj"], l.env, l.folder, l.key))
				f.mu.Unlock()
			},
			Outage: func(storetest.TB) func() {
				f.setDown(true)
				return func() { f.setDown(false) }
			},
			Reject: func(t storetest.TB) stores.Ref {
				return stores.Ref{Scheme: "inf", Path: "proj/prod/REJECTED"}
			},
			WatchTimeout: 5 * time.Second,
		}
	})
}

func TestRegistered(t *testing.T) {
	f := newFake(t)
	a, err := stores.DefaultRegistry.Open(t.Context(), instance("inf", f.srv.URL, f.clientID, f.clientSecret, nil))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = a.Close() }()
	if got := a.Capabilities().String(); got != "read,list,watch,write" {
		t.Errorf("capabilities = %s", got)
	}
	f.mu.Lock()
	n := len(f.lastRequests)
	f.mu.Unlock()
	if n != 0 {
		t.Errorf("the factory contacted the store (%d requests)", n)
	}
}

func TestOptions(t *testing.T) {
	ok := func(extra map[string]any) stores.Instance {
		return instance("inf", "https://inf.example.test", "cid", "cs-value", extra)
	}
	cases := []struct {
		name string
		inst stores.Instance
		want string
	}{
		{"typo suggests the closest key", ok(map[string]any{"watch.intervall": "1s"}), "did you mean watch.interval"},
		{"nested typo", ok(map[string]any{"tls": map[string]any{"ca-fil": "/x"}}), "did you mean tls.ca-file"},
		{"bad duration", ok(map[string]any{"timeout": "soon"}), "option timeout"},
		{"negative duration", ok(map[string]any{"watch.interval": "-1s"}), "must be positive"},
		{"bad bool", ok(map[string]any{"create-folders": "maybe"}), "true or false"},
		{"unsupported auth", func() stores.Instance {
			i := ok(nil)
			i.Options["auth"].(map[string]any)["method"] = "kubernetes"
			return i
		}(), "unsupported method"},
		{"dotted and nested duplicate", ok(map[string]any{"auth.method": "universal-auth"}), "set twice"},
		{"missing ca file", ok(map[string]any{"tls.ca-file": "/nonexistent/ca.pem"}), "tls.ca-file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(t.Context(), tc.inst)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New: %v, want an error containing %q", err, tc.want)
			}
			if !errors.Is(err, stores.ErrInvalidRef) {
				t.Errorf("configuration error does not wrap ErrInvalidRef: %v", err)
			}
			if strings.Contains(err.Error(), "cs-value") {
				t.Errorf("configuration error contains the client secret")
			}
		})
	}

	t.Run("missing address", func(t *testing.T) {
		inst := ok(nil)
		delete(inst.Options, "address")
		if _, err := New(t.Context(), inst); err == nil || !strings.Contains(err.Error(), "address is required") {
			t.Fatalf("New: %v", err)
		}
	})
	t.Run("unresolvable secret stops start-up", func(t *testing.T) {
		inst := ok(nil)
		inst.Resolve = resolver(nil)
		_, err := New(t.Context(), inst)
		if err == nil || !strings.Contains(err.Error(), "env:INF_SECRET") {
			t.Fatalf("New: %v, want it to name the reference", err)
		}
	})
	t.Run("empty secret is refused", func(t *testing.T) {
		inst := ok(nil)
		inst.Resolve = resolver(map[string]string{"env:INF_SECRET": ""})
		if _, err := New(t.Context(), inst); err == nil || !strings.Contains(err.Error(), "empty") {
			t.Fatalf("New: %v", err)
		}
	})
	t.Run("dotted keys decode like nested ones", func(t *testing.T) {
		inst := stores.Instance{Name: "inf", Kind: Kind, Options: map[string]any{
			"address":        "https://inf.example.test/",
			"client-id":      "cid",
			"client-secret":  "env:INF_SECRET",
			"watch.interval": 5 * time.Second,
			"create-folders": false,
		}, Resolve: resolver(map[string]string{"env:INF_SECRET": "x"})}
		a, err := New(t.Context(), inst)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		s := a.(*Adapter).s
		if s.watchInterval != 5*time.Second || s.createFolders || s.address.String() != "https://inf.example.test" {
			t.Errorf("decoded %+v", s)
		}
	})
}

func TestRelogin(t *testing.T) {
	f := newFake(t)
	a := newAdapter(t, f, nil)
	defer func() { _ = a.Close() }()
	ref := stores.MustParseRef("inf://proj/dev/RELOGIN")
	if _, err := a.Write(t.Context(), ref, map[string]secret.Value{Field: secret.FromString("v-" + randID(8))}, stores.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	f.expireTokens()
	s, err := a.Read(t.Context(), ref)
	if err != nil {
		t.Fatalf("Read after the token was revoked: %v", err)
	}
	s.Wipe()
	f.mu.Lock()
	logins := f.logins
	f.mu.Unlock()
	if logins != 2 {
		t.Errorf("logins = %d, want 2 (one re-login)", logins)
	}
}

func TestTokenRenewedBeforeExpiry(t *testing.T) {
	f := newFake(t)
	f.tokenTTL = 60
	a := newAdapter(t, f, nil)
	defer func() { _ = a.Close() }()
	now := time.Now()
	a.c.now = func() time.Time { return now }
	if err := a.Health(t.Context()); err != nil {
		t.Fatal(err)
	}
	// 60s token, 30s margin: still fresh at +20s, renewed at +31s.
	now = now.Add(20 * time.Second)
	_ = a.Health(t.Context())
	now = now.Add(11 * time.Second)
	_ = a.Health(t.Context())
	f.mu.Lock()
	logins := f.logins
	f.mu.Unlock()
	if logins != 2 {
		t.Errorf("logins = %d, want 2", logins)
	}
}

func TestBadCredentials(t *testing.T) {
	f := newFake(t)
	wrong := "cs-wrong-" + randID(12)
	a, err := New(t.Context(), instance("inf", f.srv.URL, f.clientID, wrong, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	err = a.Health(t.Context())
	if !errors.Is(err, stores.ErrPermission) {
		t.Fatalf("Health with a wrong secret: %v, want ErrPermission", err)
	}
	if strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), wrong) {
		t.Errorf("error contains the client secret")
	}
	_, err = a.Read(t.Context(), stores.MustParseRef("inf://proj/dev/X"))
	if !errors.Is(err, stores.ErrPermission) {
		t.Errorf("Read with a wrong secret: %v", err)
	}
}

func TestCredentials(t *testing.T) {
	f := newFake(t)
	a := newAdapter(t, f, nil)
	defer func() { _ = a.Close() }()
	if got := a.Credentials(); len(got) != 1 || plain(t, got[0]) != f.clientSecret {
		t.Fatalf("before login: %d credentials", len(got))
	}
	if err := a.Health(t.Context()); err != nil {
		t.Fatal(err)
	}
	got := a.Credentials()
	if len(got) != 2 || !strings.HasPrefix(plain(t, got[1]), "tok-") {
		t.Fatalf("after login: %d credentials", len(got))
	}
	// Copies: wiping them leaves the adapter working.
	for _, v := range got {
		v.Wipe()
	}
	if err := a.Health(t.Context()); err != nil {
		t.Errorf("Health after wiping the copies: %v", err)
	}
}

func TestReferenceShape(t *testing.T) {
	f := newFake(t)
	a := newAdapter(t, f, nil)
	defer func() { _ = a.Close() }()
	ctx := t.Context()
	if _, err := a.Read(ctx, stores.MustParseRef("inf://proj/dev")); !errors.Is(err, stores.ErrInvalidRef) {
		t.Errorf("Read of a two-segment ref: %v", err)
	}
	if _, err := a.List(ctx, stores.MustParseRef("inf://proj")); !errors.Is(err, stores.ErrInvalidRef) {
		t.Errorf("List of a one-segment ref: %v", err)
	}
	if _, err := a.Read(ctx, stores.MustParseRef("inf://proj/dev/X?version=zero")); !errors.Is(err, stores.ErrInvalidRef) {
		t.Errorf("Read with a bad version: %v", err)
	}
	if _, err := a.Read(ctx, stores.MustParseRef("inf://unknown-project/dev/X")); !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("Read in an unknown project: %v", err)
	}
	v := secret.FromString("v-" + randID(8))
	_, err := a.Write(ctx, stores.MustParseRef("inf://proj/dev/MULTI"), map[string]secret.Value{"user": v, "pass": v}, stores.WriteOptions{})
	if !errors.Is(err, stores.ErrUnsupported) || !strings.Contains(err.Error(), "single field") {
		t.Errorf("multi-field Write: %v", err)
	}
	// A listing prefix with a trailing /* is accepted.
	if _, err := a.Write(ctx, stores.MustParseRef("inf://proj/dev/bulk/API_KEY"), map[string]secret.Value{Field: v}, stores.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	ms, err := a.List(ctx, stores.MustParseRef("inf://proj/dev/bulk/*"))
	if err != nil || len(ms) != 1 || ms[0].Ref.Path != "proj/dev/bulk/API_KEY" {
		t.Errorf("List with /*: %v %v", ms, err)
	}
}

func TestCreateFoldersOff(t *testing.T) {
	f := newFake(t)
	a := newAdapter(t, f, map[string]any{"create-folders": false})
	defer func() { _ = a.Close() }()
	_, err := a.Write(t.Context(), stores.MustParseRef("inf://proj/dev/missing/folder/KEY"),
		map[string]secret.Value{Field: secret.FromString("v-" + randID(8))}, stores.WriteOptions{})
	if !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("Write into a missing folder with create-folders off: %v", err)
	}
}

// TestStoreEchoWithheld checks that a store error echoing the written value
// back does not carry it into scrim's error.
func TestStoreEchoWithheld(t *testing.T) {
	f := newFake(t)
	val := "echoed-" + randID(12)
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/auth/universal-auth/login":
			f.srv.Config.Handler.ServeHTTP(w, r)
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v4/secrets/"):
			apiErr(w, 400, "BadRequest", "invalid secret value '"+val+"'")
		default:
			apiErr(w, 500, "Internal", "boom")
		}
	}))
	defer echo.Close()
	a, err := New(t.Context(), instance("inf", echo.URL, f.clientID, f.clientSecret, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	ref := stores.MustParseRef("inf://6a1b2c3d-0000-4000-8000-000000000000/dev/X")
	_, err = a.Write(t.Context(), ref, map[string]secret.Value{Field: secret.FromString(val)}, stores.WriteOptions{})
	if err == nil {
		t.Fatal("Write succeeded")
	}
	if s := fmt.Sprintf("%v %+v %#v", err, err, err); strings.Contains(s, val) {
		t.Errorf("error carries the echoed value")
	}
	if !strings.Contains(err.Error(), "withheld") || !strings.Contains(err.Error(), ref.Path) {
		t.Errorf("error = %v", err)
	}
	if _, err := a.Read(t.Context(), ref); !errors.Is(err, stores.ErrUnavailable) {
		t.Errorf("Read on a 500: %v, want ErrUnavailable", err)
	}
}

func TestWatchStartsDuringOutage(t *testing.T) {
	f := newFake(t)
	a := newAdapter(t, f, map[string]any{"watch.interval": "30ms", "watch.max-backoff": "60ms"})
	defer func() { _ = a.Close() }()
	if err := a.Health(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.setDown(true)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ch, err := a.Watch(ctx, stores.MustParseRef("inf://proj/dev"))
	if err != nil {
		t.Fatalf("Watch during an outage: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	f.setDown(false)
	ref := stores.MustParseRef("inf://proj/dev/LATE")
	if _, err := a.Write(t.Context(), ref, map[string]secret.Value{Field: secret.FromString("v-" + randID(8))}, stores.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	timeout := time.After(5 * time.Second)
	for {
		select {
		case c := <-ch:
			if c.Ref.Path == ref.Path && c.Kind == stores.Changed {
				return
			}
		case <-timeout:
			t.Fatal("no change after the store came back")
		}
	}
}

func TestJitterSpread(t *testing.T) {
	seen := map[time.Duration]bool{}
	for range 50 {
		d := jitter(time.Second)
		if d < 800*time.Millisecond || d >= 1200*time.Millisecond {
			t.Fatalf("jitter out of range: %s", d)
		}
		seen[d] = true
	}
	if len(seen) < 10 {
		t.Errorf("jitter barely varies: %d distinct values", len(seen))
	}
}
