// SPDX-License-Identifier: AGPL-3.0-only

package refresh_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/env"
	"github.com/heliopsy/scrim/internal/stores/memstore"
	"github.com/heliopsy/scrim/internal/stores/refresh"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func gen(t *testing.T) string {
	t.Helper()
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "val_" + hex.EncodeToString(b)
}

func plain(v secret.Value) string {
	var s string
	_ = v.Expose(func(b []byte) error { s = string(b); return nil })
	return s
}

// set returns the plain redaction set, for assertions.
func set(r *refresh.Refresher) map[string]refresh.Source {
	out := map[string]refresh.Source{}
	r.EachValue(func(src refresh.Source, v secret.Value) { out[plain(v)] = src })
	return out
}

func seed(s *memstore.Store, path string, fields map[string]string) {
	m := map[string]secret.Value{}
	for k, v := range fields {
		m[k] = secret.FromString(v)
	}
	s.Seed(stores.Ref{Scheme: s.Name(), Path: path}, m)
}

func newRefresher(t *testing.T, a stores.Adapter, c *clock, targets ...string) *refresh.Refresher {
	t.Helper()
	cfg := refresh.Config{
		Interval: 50 * time.Millisecond, Jitter: -1, Retention: time.Hour,
		Staleness: 10 * time.Minute, MaxBackoff: 100 * time.Millisecond,
	}
	if c != nil {
		cfg.Now = c.now
	}
	for _, s := range targets {
		tg, err := refresh.ParseTarget(s)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Targets = append(cfg.Targets, tg)
	}
	r := refresh.New(a, cfg)
	t.Cleanup(r.Close)
	return r
}

func TestParseTarget(t *testing.T) {
	tg, err := refresh.ParseTarget("bao://kv/agents/*")
	if err != nil || !tg.Prefix || tg.Ref.Path != "kv/agents" || tg.String() != "bao://kv/agents/*" {
		t.Fatalf("got %+v, %v", tg, err)
	}
	if _, err := refresh.ParseTarget("bao://kv/agents/*#token"); err == nil {
		t.Fatal("prefix with a field accepted")
	}
	if _, err := refresh.ParseTarget("not a ref"); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestNotReadyUntilFirstLoad(t *testing.T) {
	s := memstore.New("mem")
	v := gen(t)
	seed(s, "agents/a", map[string]string{"token": v})
	r := newRefresher(t, s, nil, "mem://agents/*")
	err := r.Ready(t.Context())
	if err == nil || !strings.Contains(err.Error(), "redaction is not ready") || !strings.Contains(err.Error(), "mem") {
		t.Fatalf("Ready before load: %v", err)
	}
	if st := r.Status(); st.State != refresh.StateLoading || st.Healthy {
		t.Fatalf("status before load: %+v", st)
	}
	if err := r.RefreshNow(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := r.Ready(t.Context()); err != nil {
		t.Fatalf("Ready after load: %v", err)
	}
	if _, ok := set(r)[v]; !ok {
		t.Fatal("loaded value not in the redaction set")
	}
	if st := r.Status(); st.State != refresh.StateReady || !st.Healthy || st.Secrets != 1 || st.Values != 1 {
		t.Fatalf("status after load: %+v", st)
	}
}

func TestStoreDownAtStartup(t *testing.T) {
	s := memstore.New("mem")
	seed(s, "agents/a", map[string]string{"token": gen(t)})
	s.SetDown(true)
	r := newRefresher(t, s, nil, "mem://agents/*")
	if err := r.RefreshNow(t.Context()); !errors.Is(err, stores.ErrUnavailable) {
		t.Fatalf("refresh with the store down: %v", err)
	}
	if err := r.Ready(t.Context()); err == nil {
		t.Fatal("ready with a store that never loaded")
	}
	st := r.Status()
	if st.State != refresh.StateUnavailable || st.Healthy || st.Loaded {
		t.Fatalf("status: %+v", st)
	}
	_, err := r.Resolve(t.Context(), stores.MustParseRef("mem://agents/a#token"))
	if !errors.Is(err, stores.ErrUnavailable) || !strings.Contains(err.Error(), "mem://agents/a#token") {
		t.Fatalf("Resolve with the store down: %v", err)
	}
}

// TestOutageKeepsLastKnownSet stops the store after a successful load.
func TestOutageKeepsLastKnownSet(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	s := memstore.New("mem")
	v := gen(t)
	seed(s, "agents/a", map[string]string{"token": v})
	r := newRefresher(t, s, c, "mem://agents/*")
	if err := r.RefreshNow(t.Context()); err != nil {
		t.Fatal(err)
	}
	s.SetDown(true)
	c.add(time.Minute)
	err := r.RefreshNow(t.Context())
	if !errors.Is(err, stores.ErrUnavailable) {
		t.Fatalf("refresh during the outage: %v", err)
	}
	if strings.Contains(err.Error(), v) {
		t.Fatal("refresh error contains a value")
	}
	if _, ok := set(r)[v]; !ok {
		t.Fatal("outage dropped a loaded value from the redaction set")
	}
	st := r.Status()
	if st.State != refresh.StateDegraded || !st.Loaded || st.LastError == "" {
		t.Fatalf("status during the outage: %+v", st)
	}
	if !st.Healthy {
		t.Fatal("unhealthy before the staleness limit")
	}
	if err := r.Ready(t.Context()); err != nil {
		t.Fatalf("readiness lost during an outage after load: %v", err)
	}
	// Within the staleness limit the confirmed value can still be injected.
	got, err := r.Resolve(t.Context(), stores.MustParseRef("mem://agents/a#token"))
	if err != nil || plain(got) != v {
		t.Fatalf("Resolve within staleness: %v", err)
	}
	got.Wipe()
	// Past it, injection fails closed; redaction does not.
	c.add(10 * time.Minute)
	_ = r.RefreshNow(t.Context())
	if r.Status().Healthy {
		t.Fatal("still healthy past the staleness limit")
	}
	_, err = r.Resolve(t.Context(), stores.MustParseRef("mem://agents/a#token"))
	if !errors.Is(err, stores.ErrUnavailable) || !strings.Contains(err.Error(), "mem://agents/a#token") {
		t.Fatalf("Resolve past staleness with the store down: %v", err)
	}
	if _, ok := set(r)[v]; !ok {
		t.Fatal("value left the redaction set past staleness")
	}
	s.SetDown(false)
	if err := r.RefreshNow(t.Context()); err != nil {
		t.Fatal(err)
	}
	if st := r.Status(); st.State != refresh.StateReady || !st.Healthy || st.LastError != "" {
		t.Fatalf("status after recovery: %+v", st)
	}
}

func TestRotationRetainsPreviousValue(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	s := memstore.New("mem")
	old, cur := gen(t), gen(t)
	seed(s, "agents/a", map[string]string{"token": old})
	r := newRefresher(t, s, c, "mem://agents/a")
	if err := r.RefreshNow(t.Context()); err != nil {
		t.Fatal(err)
	}
	seed(s, "agents/a", map[string]string{"token": cur})
	if err := r.RefreshNow(t.Context()); err != nil {
		t.Fatal(err)
	}
	vals := set(r)
	if src, ok := vals[old]; !ok || !src.Retained {
		t.Fatal("previous value not retained after rotation")
	}
	if src, ok := vals[cur]; !ok || src.Retained {
		t.Fatal("new value missing")
	}
	got, _ := r.Resolve(t.Context(), stores.MustParseRef("mem://agents/a"))
	if plain(got) != cur {
		t.Fatal("Resolve returned the previous value")
	}
	got.Wipe()
	c.add(time.Hour + time.Second)
	if err := r.RefreshNow(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, ok := set(r)[old]; ok {
		t.Fatal("previous value kept past retention")
	}
}

func TestDeletedSecretIsRetainedThenExpires(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	s := memstore.New("mem")
	v := gen(t)
	seed(s, "agents/a", map[string]string{"token": v})
	r := newRefresher(t, s, c, "mem://agents/*")
	_ = r.RefreshNow(t.Context())
	s.Delete(stores.MustParseRef("mem://agents/a"))
	if err := r.RefreshNow(t.Context()); err != nil {
		t.Fatal(err)
	}
	if src, ok := set(r)[v]; !ok || !src.Retained {
		t.Fatal("deleted secret's value not retained")
	}
	if _, err := r.Resolve(t.Context(), stores.MustParseRef("mem://agents/a#token")); !errors.Is(err, stores.ErrNotFound) {
		t.Fatalf("Resolve of a deleted secret: %v", err)
	}
	c.add(2 * time.Hour)
	_ = r.RefreshNow(t.Context())
	if len(set(r)) != 0 {
		t.Fatal("values kept past retention")
	}
}

// counting counts reads to check unchanged versions are not read again.
type counting struct {
	*memstore.Store
	reads atomic.Int32
}

func (c *counting) Read(ctx context.Context, ref stores.Ref) (stores.Secret, error) {
	c.reads.Add(1)
	return c.Store.Read(ctx, ref)
}

func TestUnchangedVersionsAreNotReadAgain(t *testing.T) {
	s := &counting{Store: memstore.New("mem")}
	seed(s.Store, "agents/a", map[string]string{"token": gen(t)})
	seed(s.Store, "agents/b", map[string]string{"token": gen(t)})
	r := newRefresher(t, s, nil, "mem://agents/*")
	_ = r.RefreshNow(t.Context())
	_ = r.RefreshNow(t.Context())
	if n := s.reads.Load(); n != 2 {
		t.Fatalf("%d reads over two refreshes of two unchanged secrets, want 2", n)
	}
	seed(s.Store, "agents/b", map[string]string{"token": gen(t)})
	_ = r.RefreshNow(t.Context())
	if n := s.reads.Load(); n != 3 {
		t.Fatalf("%d reads, want only the changed secret read again", n)
	}
}

// spying checks the redaction set while the store handles a write.
type spying struct {
	*memstore.Store
	r      *refresh.Refresher
	during map[string]refresh.Source
	refuse bool
}

func (s *spying) Write(ctx context.Context, ref stores.Ref, f map[string]secret.Value, o stores.WriteOptions) (stores.Metadata, error) {
	s.during = set(s.r)
	if s.refuse {
		e := stores.NewError(s.Name(), stores.OpWrite, ref, stores.ErrPermission, nil)
		e.Detail = "policy refuses"
		return stores.Metadata{}, e
	}
	return s.Store.Write(ctx, ref, f, o)
}

func TestWrittenValuesAreRedactedBeforeTheWriteReturns(t *testing.T) {
	sp := &spying{Store: memstore.New("mem")}
	r := newRefresher(t, sp, nil, "mem://agents/*")
	sp.r = r
	_ = r.RefreshNow(t.Context())
	v := gen(t)
	in := secret.FromString(v)
	m, err := r.Write(t.Context(), stores.MustParseRef("mem://agents/new"), map[string]secret.Value{"token": in}, stores.WriteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if src, ok := sp.during[v]; !ok || !src.Pending {
		t.Fatal("value not in the redaction set while the store was writing it")
	}
	if _, ok := set(r)[v]; !ok {
		t.Fatal("written value not in the redaction set")
	}
	if m.Ref.Path != "agents/new" || in.Wiped() {
		t.Fatalf("metadata %+v, caller value wiped %v", m, in.Wiped())
	}
	got, err := r.Resolve(t.Context(), stores.MustParseRef("mem://agents/new#token"))
	if err != nil || plain(got) != v {
		t.Fatalf("Resolve of a written value: %v", err)
	}
	got.Wipe()
	// The next refresh keeps it (the store now lists it too).
	_ = r.RefreshNow(t.Context())
	if _, ok := set(r)[v]; !ok {
		t.Fatal("refresh dropped a written value")
	}
}

func TestRejectedWriteDropsTheValue(t *testing.T) {
	sp := &spying{Store: memstore.New("mem"), refuse: true}
	r := newRefresher(t, sp, nil, "mem://agents/*")
	sp.r = r
	v := gen(t)
	_, err := r.Write(t.Context(), stores.MustParseRef("mem://agents/new"), map[string]secret.Value{"token": secret.FromString(v)}, stores.WriteOptions{})
	if !errors.Is(err, stores.ErrPermission) || !strings.Contains(err.Error(), "policy refuses") || !strings.Contains(err.Error(), "mem://agents/new") {
		t.Fatalf("rejected write: %v", err)
	}
	if strings.Contains(err.Error(), v) {
		t.Fatal("error contains the value")
	}
	if _, ok := set(r)[v]; ok {
		t.Fatal("rejected value kept in memory")
	}
}

func TestReadOnlyStoreRefusesWriteBeforeAnything(t *testing.T) {
	s := memstore.New("env", memstore.WithCapabilities(stores.CapRead|stores.CapList))
	var changes atomic.Int32
	r := refresh.New(s, refresh.Config{OnChange: func() { changes.Add(1) }})
	defer r.Close()
	_, err := r.Write(t.Context(), stores.MustParseRef("env://X"), map[string]secret.Value{"value": secret.FromString(gen(t))}, stores.WriteOptions{})
	if !errors.Is(err, stores.ErrUnsupported) || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("write to a read-only store: %v", err)
	}
	if changes.Load() != 0 || len(set(r)) != 0 {
		t.Fatal("refused write touched the redaction set")
	}
}

func TestResolveReadsOnDemandAndRedactsFirst(t *testing.T) {
	s := memstore.New("mem")
	v := gen(t)
	seed(s, "other/x", map[string]string{"user": "u-" + gen(t), "password": v})
	r := newRefresher(t, s, nil)
	_ = r.RefreshNow(t.Context())
	if _, err := r.Resolve(t.Context(), stores.MustParseRef("mem://other/x")); !errors.Is(err, stores.ErrInvalidRef) {
		t.Fatalf("multi-field secret without a field: %v", err)
	}
	got, err := r.Resolve(t.Context(), stores.MustParseRef("mem://other/x#password"))
	if err != nil || plain(got) != v {
		t.Fatalf("on-demand Resolve: %v", err)
	}
	got.Wipe()
	if _, ok := set(r)[v]; !ok {
		t.Fatal("value read on demand is not redacted")
	}
	if _, err := r.Resolve(t.Context(), stores.MustParseRef("mem://other/x#nope")); !errors.Is(err, stores.ErrNotFound) {
		t.Fatalf("missing field: %v", err)
	}
}

func TestEmptyValueIsNeverInjected(t *testing.T) {
	s := memstore.New("mem")
	seed(s, "agents/empty", map[string]string{"token": ""})
	r := newRefresher(t, s, nil, "mem://agents/*")
	_ = r.RefreshNow(t.Context())
	if _, err := r.Resolve(t.Context(), stores.MustParseRef("mem://agents/empty#token")); err == nil {
		t.Fatal("empty value injected")
	}
}

// locking is a store that reports itself locked.
type locking struct{ *memstore.Store }

func (l locking) Read(_ context.Context, ref stores.Ref) (stores.Secret, error) {
	return stores.Secret{}, stores.NewError(l.Name(), stores.OpRead, ref, stores.ErrLocked, nil)
}

func TestLockedStoreFailsClosed(t *testing.T) {
	s := locking{memstore.New("vw")}
	r := newRefresher(t, s, nil, "vw://Agents/GitHub")
	_ = r.RefreshNow(t.Context())
	if st := r.Status(); st.State != refresh.StateLocked || st.Healthy {
		t.Fatalf("status: %+v", st)
	}
	if err := r.Ready(t.Context()); err == nil {
		t.Fatal("ready with a locked store")
	}
	if _, err := r.Resolve(t.Context(), stores.MustParseRef("vw://Agents/GitHub#token")); !errors.Is(err, stores.ErrLocked) {
		t.Fatalf("Resolve from a locked store: %v", err)
	}
}

// credentialed reports a store credential.
type credentialed struct {
	*memstore.Store
	cred string
}

func (c credentialed) Credentials() []secret.Value { return []secret.Value{secret.FromString(c.cred)} }

func TestStoreCredentialsAreRedacted(t *testing.T) {
	c := credentialed{memstore.New("bao"), gen(t)}
	r := newRefresher(t, c, nil)
	_ = r.RefreshNow(t.Context())
	src, ok := set(r)[c.cred]
	if !ok || !src.Ref.IsZero() {
		t.Fatal("store credential not in the redaction set")
	}
}

// TestRunStopsAndRestartsTheStoreMidRun drives the real loop: load, watch,
// stop the store, check the set survives and status degrades, bring it back.
func TestRunStopsAndRestartsTheStoreMidRun(t *testing.T) {
	s := memstore.New("mem")
	v1 := gen(t)
	seed(s, "agents/a", map[string]string{"token": v1})
	var statuses sync.Map
	r := refresh.New(s, refresh.Config{
		Targets:  []refresh.Target{{Ref: stores.MustParseRef("mem://agents"), Prefix: true}},
		Interval: 30 * time.Millisecond, MaxBackoff: 60 * time.Millisecond,
		OnStatus: func(st refresh.Status) { statuses.Store(st.State, true) },
	})
	defer r.Close()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	waitFor(t, "first load", func() bool { return r.Ready(ctx) == nil })

	// A change arrives through the watch, well before the next refresh
	// would matter.
	v2 := gen(t)
	seed(s, "agents/b", map[string]string{"token": v2})
	waitFor(t, "watched change", func() bool { _, ok := set(r)[v2]; return ok })

	s.SetDown(true)
	waitFor(t, "degraded status", func() bool { return r.Status().State == refresh.StateDegraded })
	vals := set(r)
	if _, ok := vals[v1]; !ok {
		t.Fatal("value lost while the store is down")
	}
	if _, ok := vals[v2]; !ok {
		t.Fatal("watched value lost while the store is down")
	}
	s.SetDown(false)
	waitFor(t, "recovery", func() bool { return r.Status().State == refresh.StateReady })
	cancel()
	<-done
	for _, st := range []refresh.State{refresh.StateReady, refresh.StateDegraded} {
		if _, ok := statuses.Load(st); !ok {
			t.Errorf("OnStatus never reported %s", st)
		}
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestParseConfig(t *testing.T) {
	c, err := refresh.ParseConfig("bao", map[string]any{
		"redact":  []any{"bao://kv/agents/*", "bao://kv/ci/deploy#token"},
		"refresh": map[string]any{"interval": "1m", "staleness": "30m"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Targets) != 2 || !c.Targets[0].Prefix || c.Targets[1].Ref.Field != "token" || c.Interval != time.Minute || c.Staleness != 30*time.Minute || c.Retention != refresh.DefaultRetention {
		t.Fatalf("config %+v", c)
	}
	_, err = refresh.ParseConfig("bao", map[string]any{"redact": "inf://x/y", "refresh.intervl": "1m", "refresh.retention": "-1s"})
	if err == nil {
		t.Fatal("bad config accepted")
	}
	for _, want := range []string{"names another store", "did you mean refresh.interval", "refresh.retention must be positive"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
}

// mapEnv is an env store environment for tests.
type mapEnv map[string]string

func (m mapEnv) LookupEnv(name string) (string, bool) { v, ok := m[name]; return v, ok }
func (m mapEnv) Environ() []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	return out
}

// TestGlobTargetLoadsByNamePrefix is the README quickstart: an env store
// with `redact: [local://SCRIM_SECRET_*]`. The trailing `*` matches names
// by prefix; it is not a secret literally named SCRIM_SECRET_*.
func TestGlobTargetLoadsByNamePrefix(t *testing.T) {
	v, other := gen(t), gen(t)
	a := env.New("local", env.Config{Prefix: "SCRIM_SECRET_"}, env.WithEnvironment(mapEnv{
		"SCRIM_SECRET_X": v, "SCRIM_SECRETX": other, "HOME": other,
	}))
	tg, err := refresh.ParseTarget("local://SCRIM_SECRET_*")
	if err != nil || !tg.Glob || tg.Prefix || tg.String() != "local://SCRIM_SECRET_*" {
		t.Fatalf("target %+v, %v", tg, err)
	}
	r := newRefresher(t, a, nil, "local://SCRIM_SECRET_*")
	if err := r.RefreshNow(t.Context()); err != nil {
		t.Fatal(err)
	}
	got := set(r)
	if _, ok := got[v]; !ok || len(got) != 1 {
		t.Fatalf("redaction set has %d values, want SCRIM_SECRET_X only", len(got))
	}
	st := r.Status()
	if len(st.Targets) != 1 || st.Targets[0].Target != "local://SCRIM_SECRET_*" || st.Targets[0].Values != 1 {
		t.Fatalf("targets %+v", st.Targets)
	}
}

func TestParseTargetGlobRules(t *testing.T) {
	for _, bad := range []string{"bao://kv/a*b", "bao://kv/x*#token", "bao://*"} {
		if _, err := refresh.ParseTarget(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// TestGlobNeedsAStoreThatMatchesNames refuses a glob on a store that cannot
// expand one, instead of loading nothing.
func TestGlobNeedsAStoreThatMatchesNames(t *testing.T) {
	s := memstore.New("mem")
	seed(s, "agents/a", map[string]string{"token": gen(t)})
	r := newRefresher(t, s, nil, "mem://agents/a*")
	if err := r.RefreshNow(t.Context()); !errors.Is(err, stores.ErrUnsupported) {
		t.Fatalf("glob on memstore: %v", err)
	}
}

// TestEmptyTargetRefusesStartUp: a target that matches nothing on the first
// load is a configuration problem. Redaction stays not ready, the error
// names the target, and FirstLoad reports it so start-up fails.
func TestEmptyTargetRefusesStartUp(t *testing.T) {
	for _, target := range []string{"mem://agents/*", "mem://agents/missing", "mem://agents/x*"} {
		t.Run(target, func(t *testing.T) {
			s := memstore.New("mem")
			seed(s, "other/a", map[string]string{"token": gen(t)})
			var r *refresh.Refresher
			if strings.HasSuffix(target, "x*") {
				r = newRefresher(t, env.New("mem", env.Config{}, env.WithEnvironment(mapEnv{"OTHER": gen(t)})), nil, target)
			} else {
				r = newRefresher(t, s, nil, target)
			}
			err := r.RefreshNow(t.Context())
			if !errors.Is(err, refresh.ErrEmptyTarget) || !strings.Contains(err.Error(), target) ||
				!strings.Contains(err.Error(), "redaction.allow-empty-targets") {
				t.Fatalf("refresh: %v", err)
			}
			if err := r.Ready(t.Context()); err == nil || !strings.Contains(err.Error(), target) {
				t.Fatalf("ready with an empty target: %v", err)
			}
			if err := r.FirstLoad(t.Context()); !errors.Is(err, refresh.ErrEmptyTarget) {
				t.Fatalf("first load: %v", err)
			}
			st := r.Status()
			if st.State == refresh.StateReady || len(st.Targets) != 1 || st.Targets[0].Values != 0 {
				t.Fatalf("status %+v", st)
			}
		})
	}
}

// TestEmptyTargetAllowedIsDegraded: with the weakening setting the store
// loads, but its status says which target holds nothing.
func TestEmptyTargetAllowedIsDegraded(t *testing.T) {
	s := memstore.New("mem")
	v := gen(t)
	seed(s, "agents/a", map[string]string{"token": v})
	tgs := []refresh.Target{}
	for _, x := range []string{"mem://agents/*", "mem://empty/*"} {
		tg, err := refresh.ParseTarget(x)
		if err != nil {
			t.Fatal(err)
		}
		tgs = append(tgs, tg)
	}
	r := refresh.New(s, refresh.Config{Targets: tgs, AllowEmptyTargets: true, Jitter: -1})
	t.Cleanup(r.Close)
	if err := r.RefreshNow(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := r.Ready(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := r.FirstLoad(t.Context()); err != nil {
		t.Fatal(err)
	}
	st := r.Status()
	if st.State != refresh.StateDegraded || !strings.Contains(st.LastError, "mem://empty/*") {
		t.Fatalf("status %+v", st)
	}
	want := map[string]int{"mem://agents/*": 1, "mem://empty/*": 0}
	for _, ts := range st.Targets {
		if want[ts.Target] != ts.Values {
			t.Errorf("target %s: %d values", ts.Target, ts.Values)
		}
		delete(want, ts.Target)
	}
	if len(want) != 0 {
		t.Fatalf("targets %+v", st.Targets)
	}
}

// TestSecretLabels: a secret in memory is labelled from what its store
// reported, a new item from what it would get; a writer cannot forge the
// store's native label through write labels.
func TestSecretLabels(t *testing.T) {
	s := memstore.New("mem")
	ref := stores.MustParseRef("mem://team/a")
	if _, err := s.Write(t.Context(), ref, map[string]secret.Value{"token": secret.FromString(gen(t))},
		stores.WriteOptions{Labels: map[string]string{"scrim.hosts": "api.example.test", "memory.top": "forged", "store.kind": "forged"}}); err != nil {
		t.Fatal(err)
	}
	r := newRefresher(t, s, nil, "mem://team/*")
	if err := r.RefreshNow(t.Context()); err != nil {
		t.Fatal(err)
	}
	set := stores.NewSet()
	if err := set.Add(s); err != nil {
		t.Fatal(err)
	}
	set.SetLabeling("mem", memstore.Kind, nil)
	got, err := refresh.SecretLabels(t.Context(), set, []*refresh.Refresher{r}, ref.WithField("token"))
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{
		"scrim.hosts": "api.example.test", "memory.top": "team", "store.kind": "memory", "store.field": "token",
	} {
		if got[k] != want {
			t.Errorf("%s = %q, want %q (%v)", k, got[k], want, got)
		}
	}
	var seen map[string]string
	r.EachValue(func(src refresh.Source, _ secret.Value) {
		if src.Ref.Path == "team/a" {
			seen = src.Labels
		}
	})
	if seen["scrim.hosts"] != "api.example.test" {
		t.Errorf("EachValue labels = %v", seen)
	}
	got, err = refresh.SecretLabels(t.Context(), set, []*refresh.Refresher{r}, stores.MustParseRef("mem://ops/new"))
	if err != nil || got["memory.top"] != "ops" || got["scrim.hosts"] != "" || got["store.name"] != "mem" {
		t.Errorf("new item labels = %v", got)
	}
}

// trackingStore records every value its Read hands out and can fail reads.
type trackingStore struct {
	*memstore.Store
	handed  []secret.Value
	readErr error
	reads   int
}

func (s *trackingStore) Read(ctx context.Context, ref stores.Ref) (stores.Secret, error) {
	s.reads++
	if s.readErr != nil {
		return stores.Secret{}, s.readErr
	}
	sec, err := s.Store.Read(ctx, ref)
	for _, v := range sec.Fields {
		s.handed = append(s.handed, v)
	}
	return sec, err
}

// metaStore also reads metadata without values.
type metaStore struct{ *trackingStore }

func (s metaStore) ReadMetadata(_ context.Context, ref stores.Ref) (stores.Metadata, error) {
	return stores.Metadata{Ref: ref, Labels: map[string]string{"memory.top": "from-metadata"}}, nil
}

func labelSet(t *testing.T, a stores.Adapter) *stores.Set {
	t.Helper()
	set := stores.NewSet()
	if err := set.Add(a); err != nil {
		t.Fatal(err)
	}
	set.SetLabeling(a.Name(), memstore.Kind, nil)
	return set
}

// TestSecretLabelsOutsideTheRedactionSet: an existing item no refresher
// holds is labelled from its store's metadata; the fallback read wipes
// every value before returning, and a failed lookup is an error.
func TestSecretLabelsOutsideTheRedactionSet(t *testing.T) {
	ts := &trackingStore{Store: memstore.New("mem")}
	ref := stores.MustParseRef("mem://prod/db")
	if _, err := ts.Write(t.Context(), ref, map[string]secret.Value{"password": secret.FromString(gen(t))},
		stores.WriteOptions{Labels: map[string]string{"scrim.hosts": "db.example.test"}}); err != nil {
		t.Fatal(err)
	}
	set := labelSet(t, ts)
	got, err := refresh.SecretLabels(t.Context(), set, nil, ref)
	if err != nil || got["scrim.hosts"] != "db.example.test" || got["memory.top"] != "prod" {
		t.Fatalf("labels = %v, %v", got, err)
	}
	if len(ts.handed) == 0 {
		t.Fatal("no read was made")
	}
	for _, v := range ts.handed {
		if !v.Wiped() {
			t.Fatal("a value from the metadata read was not wiped")
		}
	}

	// Not found: a new item, labelled from its reference.
	got, err = refresh.SecretLabels(t.Context(), set, nil, stores.MustParseRef("mem://prod/new"))
	if err != nil || got["memory.top"] != "prod" || got["scrim.hosts"] != "" {
		t.Fatalf("new item = %v, %v", got, err)
	}

	// Any other failure is an error.
	ts.readErr = stores.NewError("mem", stores.OpRead, ref, stores.ErrUnavailable, nil)
	got, err = refresh.SecretLabels(t.Context(), set, nil, ref)
	if err == nil || got["store.name"] != "mem" {
		t.Fatalf("failed lookup = %v, %v", got, err)
	}

	// A MetadataReader is preferred: no value is read at all.
	ts.readErr, ts.reads = nil, 0
	got, err = refresh.SecretLabels(t.Context(), labelSet(t, metaStore{ts}), nil, ref)
	if err != nil || got["memory.top"] != "from-metadata" || ts.reads != 0 {
		t.Fatalf("metadata reader: %v, %v, %d reads", got, err, ts.reads)
	}
}
