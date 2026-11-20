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
