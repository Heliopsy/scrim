// SPDX-License-Identifier: AGPL-3.0-only

package doppler

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/storetest"
)

func instance(name, addr, token string, extra map[string]any) stores.Instance {
	opts := map[string]any{"address": addr, "token": "env:DOPPLER_TOKEN"}
	maps.Copy(opts, extra)
	return stores.Instance{
		Name: name, Kind: Kind, Options: opts,
		Resolve: func(_ context.Context, ref config.SecretRef) (secret.Value, error) {
			if ref != "env:DOPPLER_TOKEN" {
				return secret.Value{}, fmt.Errorf("unknown reference %s", ref)
			}
			return secret.FromString(token), nil
		},
	}
}

func newAdapter(t testing.TB, addr, token string, extra map[string]any) *Adapter {
	t.Helper()
	a, err := New(t.Context(), instance("dop", addr, token, extra))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a.(*Adapter)
}

func plain(t testing.TB, v secret.Value) string {
	t.Helper()
	var s string
	_ = v.Expose(func(b []byte) error { s = string(b); return nil })
	return s
}

func ref(path string) stores.Ref { return stores.MustParseRef("dop://" + path) }

// noValue fails if any text holds one of the values.
func noValue(t *testing.T, what string, x any, values ...string) {
	t.Helper()
	text := fmt.Sprintf("%v %+v %#v", x, x, x)
	if err, ok := x.(error); ok {
		for e := err; e != nil; e = errors.Unwrap(e) {
			text += " " + e.Error()
		}
		var se *stores.Error
		if errors.As(err, &se) && se.Cause != nil {
			text += " " + se.Cause.Error()
		}
	}
	for _, v := range values {
		if v != "" && strings.Contains(text, v) {
			t.Errorf("%s carries a value", what)
		}
	}
}

func conformanceHarness(f *fake, token, prefix string) storetest.Factory {
	return func(tb storetest.TB) storetest.Harness {
		t := tb.(testing.TB)
		a := newAdapter(t, f.srv.URL, token, map[string]any{"watch.interval": "50ms", "watch.max-backoff": "200ms"})
		return storetest.Harness{
			Adapter:     a,
			Prefix:      prefix + "/conf-" + randID(4),
			SingleField: Field,
			Delete: func(_ storetest.TB, r stores.Ref) {
				l, _ := splitSecret(r.Path)
				f.remove(l.project+"/"+l.config, l.name)
			},
			Outage: func(storetest.TB) func() {
				f.setDown(true)
				return func() { f.setDown(false) }
			},
			Reject:       func(storetest.TB) stores.Ref { return ref("billing/prd/REJECTED") },
			Unstorable:   func(p string) bool { return strings.Contains(p, "${") },
			WatchTimeout: 5 * time.Second,
		}
	}
}

// TestConformanceFake runs the shared suite against the fake with a service
// account token, which may write billing/dev but only read billing/prd.
func TestConformanceFake(t *testing.T) {
	f, toks := newFake(t)
	storetest.Run(t, conformanceHarness(f, toks[tokSA], "billing/dev"))
}

// TestConformanceServiceToken runs it with a read/write service token, which
// opens billing/dev alone.
func TestConformanceServiceToken(t *testing.T) {
	f, toks := newFake(t)
	storetest.Run(t, conformanceHarness(f, toks[tokServiceDev], "billing/dev"))
}

func TestRegistered(t *testing.T) {
	f, toks := newFake(t)
	a, err := stores.DefaultRegistry.Open(t.Context(), instance("dop", f.srv.URL, toks[tokSA], nil))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = a.Close() }()
	if got := a.Capabilities().String(); got != "read,list,watch,write,glob" {
		t.Errorf("capabilities = %s", got)
	}
	if n := len(f.requests); n != 0 {
		t.Errorf("the factory contacted the store (%d requests)", n)
	}
	if got := a.(stores.CredentialHolder).Credentials(); len(got) != 0 {
		t.Errorf("the factory resolved the token")
	}
}

func TestOptions(t *testing.T) {
	ok := func(extra map[string]any) stores.Instance {
		return instance("dop", "https://api.doppler.example", "dp.st.x", extra)
	}
	noToken := ok(nil)
	delete(noToken.Options, "token")
	cases := []struct {
		name string
		inst stores.Instance
		want string
	}{
		{"typo suggests the closest key", ok(map[string]any{"watch.intervall": "1s"}), "did you mean watch.interval"},
		{"bad duration", ok(map[string]any{"timeout": "soon"}), "option timeout"},
		{"negative duration", ok(map[string]any{"watch.interval": "-1s"}), "must be positive"},
		{"bad address", ok(map[string]any{"address": "ftp://x"}), "option address"},
		{"missing token", noToken, "option token is required"},
		{"missing ca file", ok(map[string]any{"tls.ca-file": "/nonexistent/ca.pem"}), "tls.ca-file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(t.Context(), tc.inst)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New: %v, want an error containing %q", err, tc.want)
			}
			if !errors.Is(err, stores.ErrInvalidRef) {
				t.Errorf("error kind: %v", err)
			}
		})
	}
	// The default address is Doppler's API.
	inst := ok(nil)
	delete(inst.Options, "address")
	a, err := New(t.Context(), inst)
	if err != nil {
		t.Fatalf("New without address: %v", err)
	}
	if got := a.(*Adapter).s.address.String(); got != defaultAddress {
		t.Errorf("default address = %s", got)
	}
}

func TestReadComputedValue(t *testing.T) {
	f, toks := newFake(t)
	user, host := "u-"+randID(6), "h-"+randID(6)
	f.put("billing/dev", "USER", user, nil)
	f.put("billing/dev", "DATABASE", "${USER}@"+host+":9876", nil)
	f.put("billing/prd", "SHARED", "prd-"+randID(6), nil)
	f.put("billing/dev", "FROM_PRD", "x${prd.SHARED}", nil)
	a := newAdapter(t, f.srv.URL, toks[tokSA], nil)
	s, err := a.Read(t.Context(), ref("billing/dev/DATABASE"))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	defer s.Wipe()
	if got := plain(t, s.Fields[Field]); got != user+"@"+host+":9876" {
		t.Errorf("Read returned the raw value, want the computed one")
	}
	s2, err := a.Read(t.Context(), ref("billing/dev/FROM_PRD#value"))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	defer s2.Wipe()
	if !strings.HasPrefix(plain(t, s2.Fields[Field]), "xprd-") {
		t.Errorf("cross-config reference not resolved")
	}
}

func TestReadErrors(t *testing.T) {
	f, toks := newFake(t)
	v := "v-" + randID(8)
	f.put("billing/dev", "KEY", v, nil)
	a := newAdapter(t, f.srv.URL, toks[tokSA], nil)
	cases := []struct {
		path string
		kind error
	}{
		{"billing/dev/MISSING", stores.ErrNotFound},
		{"billing/nope/KEY", stores.ErrNotFound},
		{"billing/dev", stores.ErrInvalidRef},
		{"billing/dev/bad name", stores.ErrInvalidRef},
		{"billing/dev/" + strings.Repeat("A", 201), stores.ErrInvalidRef},
	}
	for _, tc := range cases {
		_, err := a.Read(t.Context(), ref(tc.path))
		if !errors.Is(err, tc.kind) {
			t.Errorf("Read %s: %v, want %v", tc.path, err, tc.kind)
		}
		noValue(t, "read error", err, v)
	}
	r := ref("billing/dev/KEY")
	r.Selectors = "version=2"
	if _, err := a.Read(t.Context(), r); !errors.Is(err, stores.ErrInvalidRef) || !strings.Contains(err.Error(), `"version"`) {
		t.Errorf("Read with a selector: %v", err)
	}
	if _, err := a.Read(t.Context(), ref("billing/dev/KEY#other")); !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("Read of another field: %v", err)
	}
	// A wrong token is a permission error, not an outage.
	bad := newAdapter(t, f.srv.URL, "dp.st.wrong", nil)
	if _, err := bad.Read(t.Context(), ref("billing/dev/KEY")); !errors.Is(err, stores.ErrPermission) {
		t.Errorf("Read with a bad token: %v", err)
	}
	if err := bad.Health(t.Context()); !errors.Is(err, stores.ErrPermission) {
		t.Errorf("Health with a bad token: %v", err)
	}
	// A service token outside its config.
	st := newAdapter(t, f.srv.URL, toks[tokServiceRO], nil)
	if _, err := st.Read(t.Context(), ref("billing/dev/KEY")); !errors.Is(err, stores.ErrPermission) {
		t.Errorf("Read outside the service token's config: %v", err)
	}
}

// TestRestrictedValueRefused: Doppler returns null for a restricted value to
// a user token. The read is a permission error, never an empty value.
func TestRestrictedValueRefused(t *testing.T) {
	f, toks := newFake(t)
	v := "r-" + randID(8)
	f.put("billing/dev", "HIDDEN", v, func(s *fakeSecret) { s.visibility = "restricted" })
	f.put("billing/dev", "REFERS", "pre-${HIDDEN}", nil)
	user := newAdapter(t, f.srv.URL, toks[tokPersonal], nil)
	for _, name := range []string{"HIDDEN", "REFERS"} {
		s, err := user.Read(t.Context(), ref("billing/dev/"+name))
		if !errors.Is(err, stores.ErrPermission) {
			s.Wipe()
			t.Errorf("Read %s with a personal token: %v, want ErrPermission", name, err)
		}
		noValue(t, "restricted error", err, v)
	}
	sa := newAdapter(t, f.srv.URL, toks[tokSA], nil)
	s, err := sa.Read(t.Context(), ref("billing/dev/REFERS"))
	if err != nil {
		t.Fatalf("Read with a service account token: %v", err)
	}
	defer s.Wipe()
	if plain(t, s.Fields[Field]) != "pre-"+v {
		t.Errorf("wrong computed value")
	}
	if got := s.Meta.Labels["doppler.computed-visibility"]; got != "restricted" {
		t.Errorf("doppler.computed-visibility = %q", got)
	}
	if got := s.Meta.Labels["doppler.visibility"]; got != "masked" {
		t.Errorf("doppler.visibility = %q", got)
	}
}

func TestListNeverFetchesValues(t *testing.T) {
	f, toks := newFake(t)
	var all []string
	for _, n := range []string{"APP_A", "APP_B", "OTHER", "dir/one", "dir/sub/two", "dirx"} {
		v := "l-" + randID(8)
		all = append(all, v)
		f.put("billing/dev", n, v, nil)
	}
	a := newAdapter(t, f.srv.URL, toks[tokSA], nil)
	before := f.values()
	cases := map[string][]string{
		"billing/dev":        {"APP_A", "APP_B", "OTHER", "dir/one", "dir/sub/two", "dirx"},
		"billing/dev/*":      {"APP_A", "APP_B", "OTHER", "dir/one", "dir/sub/two", "dirx"},
		"billing/dev/APP_*":  {"APP_A", "APP_B"},
		"billing/dev/dir":    {"dir/one", "dir/sub/two"},
		"billing/dev/dir/":   {"dir/one", "dir/sub/two"},
		"billing/dev/dir*":   {"dir/one", "dir/sub/two", "dirx"},
		"billing/dev/OTHER":  {"OTHER"},
		"billing/dev/NOPE_*": nil,
	}
	for p, want := range cases {
		ms, err := a.List(t.Context(), ref(strings.TrimSuffix(p, "/")))
		if err != nil {
			t.Fatalf("List %s: %v", p, err)
		}
		var got []string
		for _, m := range ms {
			noValue(t, "list metadata", m, all...)
			got = append(got, strings.TrimPrefix(m.Ref.Path, "billing/dev/"))
			if m.Labels["doppler.project"] != "billing" || m.Labels["doppler.config"] != "dev" {
				t.Errorf("List %s: labels %v", p, m.Labels)
			}
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("List %s = %v, want %v", p, got, want)
		}
	}
	if f.values() != before {
		t.Errorf("List fetched values")
	}
	for _, p := range []string{"billing", "billing/dev*", "billing/dev/a*b*"} {
		if _, err := a.List(t.Context(), ref(p)); !errors.Is(err, stores.ErrInvalidRef) {
			t.Errorf("List %s: %v, want ErrInvalidRef", p, err)
		}
	}
	if _, err := a.List(t.Context(), ref("billing/nope")); !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("List of a missing config: %v", err)
	}
}

// TestManagedSecrets: Doppler's DOPPLER_* secrets hold the project, config
// and environment names. Listing leaves them out so scrim does not redact
// "dev" everywhere; an explicit reference still reads them.
func TestManagedSecrets(t *testing.T) {
	f, toks := newFake(t)
	f.put("billing/dev", "KEY", "k-"+randID(6), nil)
	a := newAdapter(t, f.srv.URL, toks[tokSA], nil)
	ms, err := a.List(t.Context(), ref("billing/dev"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].Ref.Path != "billing/dev/KEY" {
		t.Errorf("List = %v, want KEY alone", ms)
	}
	s, err := a.Read(t.Context(), ref("billing/dev/DOPPLER_CONFIG"))
	if err != nil {
		t.Fatalf("Read DOPPLER_CONFIG: %v", err)
	}
	defer s.Wipe()
	if plain(t, s.Fields[Field]) != "dev" || s.Meta.Labels["doppler.managed"] != "true" {
		t.Errorf("DOPPLER_CONFIG: wrong value or labels %v", s.Meta.Labels)
	}
	if _, err := a.ReadMetadata(t.Context(), ref("billing/dev/DOPPLER_CONFIG")); err != nil {
		t.Errorf("ReadMetadata of a managed secret: %v", err)
	}
}

func TestWrite(t *testing.T) {
	f, toks := newFake(t)
	a := newAdapter(t, f.srv.URL, toks[tokSA], nil)
	ctx := t.Context()
	v1, v2 := "w1-"+randID(8), "w2-"+randID(8)
	r := ref("billing/dev/NEW_KEY")
	if _, err := a.Write(ctx, r, map[string]secret.Value{Field: secret.FromString(v1)}, stores.WriteOptions{CreateOnly: true}); err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err := a.Write(ctx, r, map[string]secret.Value{Field: secret.FromString(v2)}, stores.WriteOptions{CreateOnly: true})
	if !errors.Is(err, stores.ErrConflict) {
		t.Errorf("create-only over an existing secret: %v", err)
	}
	if _, err := a.Write(ctx, r, map[string]secret.Value{Field: secret.FromString(v2)}, stores.WriteOptions{}); err != nil {
		t.Fatalf("update: %v", err)
	}
	f.mu.Lock()
	got := f.configs["billing/dev"].secrets["NEW_KEY"]
	f.mu.Unlock()
	if got.raw != v2 || got.visibility != "masked" {
		t.Errorf("update stored the new value: %v, visibility %s", got.raw == v2, got.visibility)
	}
	// An update keeps the visibility a person chose.
	f.put("billing/dev", "KEEP", "k", func(s *fakeSecret) { s.visibility = "restricted" })
	if _, err := a.Write(ctx, ref("billing/dev/KEEP"), map[string]secret.Value{Field: secret.FromString(v1)}, stores.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	vis := f.configs["billing/dev"].secrets["KEEP"].visibility
	f.mu.Unlock()
	if vis != "restricted" {
		t.Errorf("update changed the visibility to %s", vis)
	}

	refused := []struct {
		name   string
		ref    stores.Ref
		fields map[string]secret.Value
		kind   error
	}{
		{"reference marker", ref("billing/dev/REF"), map[string]secret.Value{Field: secret.FromString("a${B}" + v1)}, stores.ErrUnsupported},
		{"two fields", ref("billing/dev/TWO"), map[string]secret.Value{Field: secret.FromString(v1), "x": secret.FromString(v2)}, stores.ErrUnsupported},
		{"wrong field", ref("billing/dev/WF"), map[string]secret.Value{"password": secret.FromString(v1)}, stores.ErrUnsupported},
		{"not UTF-8", ref("billing/dev/BIN"), map[string]secret.Value{Field: secret.New([]byte{0xff, 0xfe})}, stores.ErrUnsupported},
		{"read-only config", ref("billing/prd/X"), map[string]secret.Value{Field: secret.FromString(v1)}, stores.ErrPermission},
		{"bad name", ref("billing/dev/a b"), map[string]secret.Value{Field: secret.FromString(v1)}, stores.ErrInvalidRef},
	}
	for _, tc := range refused {
		_, err := a.Write(ctx, tc.ref, tc.fields, stores.WriteOptions{})
		if !errors.Is(err, tc.kind) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.kind)
		}
		noValue(t, tc.name+" error", err, v1, v2)
		for _, v := range tc.fields {
			if v.Wiped() {
				t.Errorf("%s: the caller's value was wiped", tc.name)
			}
		}
	}
	f.mu.Lock()
	_, stored := f.configs["billing/dev"].secrets["REF"]
	f.mu.Unlock()
	if stored {
		t.Errorf("a value with a reference marker was stored")
	}
}

// TestWriteErrorEchoWithheld: a Doppler error message that quotes the value
// is replaced, never passed on.
func TestWriteErrorEchoWithheld(t *testing.T) {
	f, toks := newFake(t)
	f.echoValue = true
	f.permissive = false
	a := newAdapter(t, f.srv.URL, toks[tokSA], nil)
	v := "echo-" + randID(8)
	_, err := a.Write(t.Context(), ref("billing/dev/lower_case"), map[string]secret.Value{Field: secret.FromString(v)}, stores.WriteOptions{})
	if !errors.Is(err, stores.ErrInvalidRef) {
		t.Fatalf("Write of a name Classic naming rejects: %v", err)
	}
	noValue(t, "echoed error", err, v)
	if !strings.Contains(err.Error(), "withheld") {
		t.Errorf("error %q does not say the message was withheld", err)
	}
}

func TestOutageIsUnavailable(t *testing.T) {
	f, toks := newFake(t)
	a := newAdapter(t, f.srv.URL, toks[tokSA], nil)
	f.setDown(true)
	if _, err := a.Read(t.Context(), ref("billing/dev/K")); !errors.Is(err, stores.ErrUnavailable) {
		t.Errorf("Read: %v", err)
	}
	f.srv.Close()
	if err := a.Health(t.Context()); !errors.Is(err, stores.ErrUnavailable) {
		t.Errorf("Health with the server gone: %v", err)
	}
}

func TestRateLimitIsUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "30")
		apiErr(w, http.StatusTooManyRequests, "Rate limit exceeded")
	}))
	defer srv.Close()
	a := newAdapter(t, srv.URL, "dp.st.x", nil)
	if _, err := a.Read(t.Context(), ref("p/c/K")); !errors.Is(err, stores.ErrUnavailable) {
		t.Errorf("Read rate limited: %v", err)
	}
}

func TestCredentials(t *testing.T) {
	f, toks := newFake(t)
	a := newAdapter(t, f.srv.URL, toks[tokSA], nil)
	if err := a.Health(t.Context()); err != nil {
		t.Fatal(err)
	}
	creds := a.Credentials()
	if len(creds) != 1 || plain(t, creds[0]) != toks[tokSA] {
		t.Fatalf("Credentials did not return the token")
	}
	creds[0].Wipe()
	// Wiping the copy leaves the adapter working.
	if err := a.Health(t.Context()); err != nil {
		t.Errorf("Health after wiping a copy: %v", err)
	}
	_ = a.Close()
	if len(a.Credentials()) != 0 {
		t.Errorf("Close kept the token")
	}
}

// TestWatchETag: an unchanged config is a 304 that carries no value; a
// change is reported for the secret that changed only.
func TestWatchETag(t *testing.T) {
	f, toks := newFake(t)
	f.put("billing/dev", "A", "a-"+randID(6), nil)
	f.put("billing/dev", "B", "b-"+randID(6), nil)
	a := newAdapter(t, f.srv.URL, toks[tokSA], map[string]any{"watch.interval": "20ms"})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ch, err := a.Watch(ctx, ref("billing/dev"))
	if err != nil {
		t.Fatal(err)
	}
	base := f.values()
	time.Sleep(200 * time.Millisecond)
	if n := f.count("GET /v3/configs/config/secrets/download"); n < 3 {
		t.Fatalf("watch polled %d times", n)
	}
	if f.values() != base {
		t.Errorf("polling an unchanged config fetched values")
	}
	select {
	case c := <-ch:
		t.Fatalf("change %v reported for an unchanged config", c)
	default:
	}
	f.put("billing/dev", "B", "b2-"+randID(6), nil)
	select {
	case c := <-ch:
		if c.Ref.Path != "billing/dev/B" || c.Kind != stores.Changed {
			t.Errorf("got %v %s, want B changed", c.Ref, c.Kind)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no change reported")
	}
	// A change to a referenced secret changes the computed value of the
	// secret that references it.
	f.put("billing/dev", "C", "${A}", nil)
	f.put("billing/dev", "A", "a2-"+randID(6), nil)
	seen := map[string]bool{}
	deadline := time.After(5 * time.Second)
	for !seen["billing/dev/A"] || !seen["billing/dev/C"] {
		select {
		case c := <-ch:
			seen[c.Ref.Path] = true
		case <-deadline:
			t.Fatalf("saw %v, want A and C", seen)
		}
	}
}

func TestWatchErrors(t *testing.T) {
	f, toks := newFake(t)
	a := newAdapter(t, f.srv.URL, toks[tokSA], nil)
	if _, err := a.Watch(t.Context(), ref("billing")); !errors.Is(err, stores.ErrInvalidRef) {
		t.Errorf("Watch of a project: %v", err)
	}
	if _, err := a.Watch(t.Context(), ref("billing/nope")); !errors.Is(err, stores.ErrNotFound) {
		t.Errorf("Watch of a missing config: %v", err)
	}
}

// TestWatchStartsDuringOutage: a watch started while Doppler is down
// reports everything once it comes back.
func TestWatchStartsDuringOutage(t *testing.T) {
	f, toks := newFake(t)
	f.put("billing/dev", "A", "a-"+randID(6), nil)
	a := newAdapter(t, f.srv.URL, toks[tokSA], map[string]any{"watch.interval": "20ms", "watch.max-backoff": "50ms"})
	f.setDown(true)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ch, err := a.Watch(ctx, ref("billing/dev"))
	if err != nil {
		t.Fatalf("Watch during an outage: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	f.setDown(false)
	select {
	case c := <-ch:
		if c.Ref.Path != "billing/dev/A" {
			t.Errorf("got %v", c.Ref)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nothing reported after the outage")
	}
}

// fixtureServer serves the recorded responses in testdata for one secret
// read, as Doppler's API reference documents them.
func fixtureServer(t *testing.T, secretFile string) *httptest.Server {
	t.Helper()
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v3/me":
			_, _ = w.Write(read("me.json"))
		case "/v3/configs/config":
			_, _ = w.Write(read("config.json"))
		case "/v3/configs/config/secret":
			_, _ = w.Write(read(secretFile))
		case "/v3/configs/config/secrets/names":
			_, _ = w.Write(read("names.json"))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write(read("error.json"))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestRecordedFixtures decodes the documented response shapes: the example
// from the API reference, the CLI's string visibilities, the reference's
// object visibilities, and a restricted value.
func TestRecordedFixtures(t *testing.T) {
	for _, tc := range []struct {
		file, name, value, vis, valueType string
		kind                              error
	}{
		{"secret-get.json", "DATABASE", "brian@aws.dynamodb.com:9876", "", "", nil},
		{"secret-get-cli.json", "DATABASE", "brian@aws.dynamodb.com:9876", "masked", "url", nil},
		{"secret-get-object-visibility.json", "STRIPE", "stripe-fixture-not-a-key-0001", "masked", "string", nil},
		{"secret-get-restricted.json", "STRIPE", "", "", "", stores.ErrPermission},
	} {
		t.Run(tc.file, func(t *testing.T) {
			srv := fixtureServer(t, tc.file)
			a := newAdapter(t, srv.URL, "dp.st.fixture", nil)
			r := ref("ed0c2a68b6/prd_aws/" + tc.name)
			s, err := a.Read(t.Context(), r)
			if tc.kind != nil {
				if !errors.Is(err, tc.kind) {
					t.Fatalf("Read: %v, want %v", err, tc.kind)
				}
				return
			}
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			defer s.Wipe()
			if plain(t, s.Fields[Field]) != tc.value {
				t.Errorf("value differs from the fixture's computed value")
			}
			want := map[string]string{
				"doppler.workplace":           "2faa85f6610102d983522",
				"doppler.workplace.name":      "Doppler University",
				"doppler.project":             "ed0c2a68b6",
				"doppler.config":              "prd_aws",
				"doppler.environment":         "prd",
				"doppler.config.root":         "false",
				"doppler.config.locked":       "false",
				"doppler.secret":              tc.name,
				"doppler.managed":             "false",
				"doppler.visibility":          tc.vis,
				"doppler.computed-visibility": tc.vis,
				"doppler.value-type":          tc.valueType,
			}
			for k, v := range want {
				if v == "" {
					if _, ok := s.Meta.Labels[k]; ok {
						t.Errorf("label %s set to %q, want none", k, s.Meta.Labels[k])
					}
					continue
				}
				if s.Meta.Labels[k] != v {
					t.Errorf("label %s = %q, want %q", k, s.Meta.Labels[k], v)
				}
			}
			// The note, the raw value and the computed value stay out
			// of the labels.
			noValue(t, "labels", s.Meta.Labels, "hunter2", "${USER}", tc.value)

			m, err := a.ReadMetadata(t.Context(), r)
			if err != nil {
				t.Fatalf("ReadMetadata: %v", err)
			}
			for k, v := range m.Labels {
				if s.Meta.Labels[k] != v {
					t.Errorf("ReadMetadata label %s = %q, Read says %q", k, v, s.Meta.Labels[k])
				}
			}
			_, err = a.ReadMetadata(t.Context(), ref("ed0c2a68b6/prd_aws/MISSING"))
			if !errors.Is(err, stores.ErrNotFound) {
				t.Errorf("ReadMetadata of a missing secret: %v", err)
			}
		})
	}
}
