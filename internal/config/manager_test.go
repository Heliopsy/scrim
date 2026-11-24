// SPDX-License-Identifier: AGPL-3.0-only

package config_test

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
)

// syncBuffer is a log sink safe for the watcher goroutine.
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

func newManager(t *testing.T, w *world, paths ...string) (*config.Manager, *syncBuffer) {
	t.Helper()
	logs := &syncBuffer{}
	m, err := config.NewManager(w.opts(paths...), slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return m, logs
}

func TestReloadInvalidKeepsRunningConfig(t *testing.T) {
	w := newWorld(t)
	p := w.file("c.yaml", header+"approvals.timeout: 120s\n")
	m, logs := newManager(t, w, p)
	before := m.Current()
	notified := 0
	m.Subscribe(func(_, _ *config.Config) { notified++ })

	w.file("c.yaml", header+"approvals.timeout: soon\n")
	res := m.Reload(context.Background(), "test")
	if res.Applied || len(res.Problems) == 0 {
		t.Fatalf("invalid reload applied: %+v", res)
	}
	mustContain(t, strings.Join(res.Problems, "\n"), "approvals.timeout", p)
	if m.Current() != before || w.timeout.Get(m.Current()) != 2*time.Minute || notified != 0 {
		t.Fatal("running configuration changed after a rejected reload")
	}
	st := m.Status()
	if st.LastReload == nil || st.LastReload.Applied || st.Version != 1 {
		t.Fatalf("status = %+v", st)
	}
	mustContain(t, logs.String(), "configuration reload rejected", "approvals.timeout")
}

func TestReloadValidApplies(t *testing.T) {
	w := newWorld(t)
	p := w.file("c.yaml", header+"approvals.timeout: 120s\n")
	m, _ := newManager(t, w, p)
	var got []uint64
	var changedTimeout time.Duration
	m.Subscribe(func(old, cur *config.Config) {
		got = append(got, old.Version(), cur.Version())
		changedTimeout = w.timeout.Get(cur)
	})

	w.file("c.yaml", header+"approvals.timeout: 60s\n")
	res := m.Reload(context.Background(), "test")
	if !res.Applied || res.Version != 2 || !slices.Equal(res.Changed, []string{"approvals.timeout"}) {
		t.Fatalf("result = %+v", res)
	}
	if w.timeout.Get(m.Current()) != time.Minute || changedTimeout != time.Minute || !slices.Equal(got, []uint64{1, 2}) {
		t.Fatalf("subscriber saw %v, timeout %v", got, changedTimeout)
	}

	// Nothing changed: no new version, no notification.
	res = m.Reload(context.Background(), "test")
	if !res.Applied || res.Version != 2 || len(res.Changed) != 0 || len(got) != 2 {
		t.Fatalf("no-op reload: %+v, notifications %v", res, got)
	}
}

func TestReloadRestartRequired(t *testing.T) {
	w := newWorld(t)
	p := w.file("c.yaml", header+"proxy.listen: 127.0.0.1:9790\nlog.level: info\n")
	m, logs := newManager(t, w, p)

	w.file("c.yaml", header+"proxy.listen: 127.0.0.1:9999\nlog.level: warn\n")
	res := m.Reload(context.Background(), "test")
	if !res.Applied || !slices.Equal(res.PendingRestart, []string{"proxy.listen"}) || !slices.Equal(res.Changed, []string{"log.level"}) {
		t.Fatalf("result = %+v", res)
	}
	c := m.Current()
	if w.listen.Get(c) != "127.0.0.1:9790" || w.level.Get(c) != "warn" {
		t.Fatalf("listen = %s, level = %s", w.listen.Get(c), w.level.Get(c))
	}
	if st := m.Status(); !slices.Equal(st.PendingRestart, []string{"proxy.listen"}) {
		t.Fatalf("status pending = %v", st.PendingRestart)
	}
	mustContain(t, logs.String(), "needs a restart", "proxy.listen")

	// Reverting the edit clears the pending restart.
	w.file("c.yaml", header+"proxy.listen: 127.0.0.1:9790\nlog.level: warn\n")
	if res := m.Reload(context.Background(), "test"); len(res.PendingRestart) != 0 || len(m.Current().PendingRestart()) != 0 {
		t.Fatalf("pending after revert: %+v", res)
	}
}

func TestReloadSecretRotation(t *testing.T) {
	w := newWorld(t)
	tok := w.file("token", "first-token-value")
	p := w.file("c.yaml", header+"stores.openbao.token: file:"+tok+"\n")
	m, logs := newManager(t, w, p)
	w.file("token", "second-token-value")
	res := m.Reload(context.Background(), "test")
	if !slices.Equal(res.Changed, []string{"stores.openbao.token"}) {
		t.Fatalf("changed = %v", res.Changed)
	}
	v, _ := m.Current().Secret(w.token)
	if expose(t, v) != "second-token-value" {
		t.Fatal("rotated value not applied")
	}
	if strings.Contains(logs.String(), "token-value") {
		t.Fatal("secret value logged")
	}

	// A file that disappears rejects the reload and keeps the old value.
	if err := os.Remove(tok); err != nil {
		t.Fatal(err)
	}
	res = m.Reload(context.Background(), "test")
	if res.Applied {
		t.Fatal("reload with a missing secret file applied")
	}
	if v, ok := m.Current().Secret(w.token); !ok || expose(t, v) != "second-token-value" {
		t.Fatal("running secret lost after a rejected reload")
	}
}

func TestWeakeningWarnedAndListed(t *testing.T) {
	weakening := []string{"redaction.allow-unredacted-on-error", "state.sqlite.allow-network-filesystem"}
	for _, key := range weakening {
		t.Run(key, func(t *testing.T) {
			w := newWorld(t)
			s, _ := w.reg.Lookup(key)
			w.setenv(s.EnvVar() + "=true")
			m, logs := newManager(t, w)
			mustContain(t, logs.String(), "weakened protection active", "setting="+key)
			st := m.Status()
			if len(st.Weakened) != 1 || st.Weakened[0].Key != key || st.Weakened[0].Source != "env:"+s.EnvVar() {
				t.Fatalf("status weakened = %+v", st.Weakened)
			}
		})
	}
	t.Run("none by default", func(t *testing.T) {
		w := newWorld(t)
		m, logs := newManager(t, w)
		if strings.Contains(logs.String(), "weakened") || len(m.Status().Weakened) != 0 {
			t.Fatal("weakened reported with defaults")
		}
	})
	t.Run("warned again on reload while active", func(t *testing.T) {
		w := newWorld(t)
		p := w.file("c.yaml", header+"redaction.allow-unredacted-on-error: true\nlog.level: info\n")
		m, logs := newManager(t, w, p)
		w.file("c.yaml", header+"redaction.allow-unredacted-on-error: true\nlog.level: warn\n")
		m.Reload(context.Background(), "test")
		if n := strings.Count(logs.String(), "weakened protection active"); n != 2 {
			t.Fatalf("warned %d times, want at start-up and on reload", n)
		}
	})
}

// waitVersion waits for the Manager to publish version want.
func waitVersion(t *testing.T, m *config.Manager, want uint64, poke func()) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for m.Current().Version() < want {
		if time.Now().After(deadline) {
			t.Fatalf("version %d not reached, at %d; last reload %+v", want, m.Current().Version(), m.Status().LastReload)
		}
		if poke != nil {
			poke()
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func runManager(t *testing.T, m *config.Manager) {
	t.Helper()
	m.SetDebounce(20 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
}

func TestWatchReloadsOnFileChange(t *testing.T) {
	w := newWorld(t)
	base := w.file("etc/config.yaml", header+"approvals.timeout: 120s\ninclude: conf.d\n")
	w.file("etc/conf.d/.keep", "")
	m, _ := newManager(t, w, base)
	runManager(t, m)
	time.Sleep(100 * time.Millisecond) // let the watcher start

	// A new drop-in in an included directory.
	w.file("etc/conf.d/10.yaml", header+"approvals.timeout: 60s\n")
	waitVersion(t, m, 2, nil)
	if w.timeout.Get(m.Current()) != time.Minute {
		t.Fatalf("timeout = %v", w.timeout.Get(m.Current()))
	}

	// An editor replacing the file by rename.
	tmp := w.file("etc/.config.yaml.swp", header+"approvals.timeout: 30s\ninclude: conf.d\nlog.level: warn\n")
	if err := os.Rename(tmp, base); err != nil {
		t.Fatal(err)
	}
	waitVersion(t, m, 3, nil)
	if w.level.Get(m.Current()) != "warn" {
		t.Fatal("renamed file not reloaded")
	}

	// An invalid edit is rejected and the running config stays.
	w.file("etc/config.yaml", header+"approvals.timeout: [\n")
	deadline := time.Now().Add(10 * time.Second)
	for st := m.Status(); st.LastReload == nil || st.LastReload.Applied; st = m.Status() {
		if time.Now().After(deadline) {
			t.Fatal("invalid edit never reported")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if m.Current().Version() != 3 || w.level.Get(m.Current()) != "warn" {
		t.Fatal("invalid edit changed the running configuration")
	}
}
