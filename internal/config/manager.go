// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"context"
	"log/slog"
	"maps"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
)

// DefaultDebounce is how long [Manager.Run] waits after the last file event
// before reloading, so an editor's write-rename-chmod sequence is one reload.
const DefaultDebounce = 250 * time.Millisecond

// Manager owns the running configuration: it builds the first Config,
// reloads on SIGHUP and on file changes, and publishes each accepted Config
// to subscribers.
//
// A reload is all or nothing. The new configuration is built completely,
// secrets included, before anything changes; if any part is invalid the
// running Config stays in place and the reason is logged and kept for
// [Manager.Status]. Settings marked RestartRequired keep their running value
// and are reported as pending a restart instead of being applied.
type Manager struct {
	opts     Options
	log      *slog.Logger
	holder   *Holder
	debounce time.Duration

	reloadMu sync.Mutex
	statusMu sync.RWMutex
	loadedAt time.Time
	last     *ReloadResult
}

// ReloadResult describes one reload attempt. It never contains a secret.
type ReloadResult struct {
	At      time.Time `json:"at"`
	Trigger string    `json:"trigger"`
	// Applied is true when the configuration was valid. A valid reload
	// with no change applies nothing and keeps the version.
	Applied bool `json:"applied"`
	// Version is the version in effect after the attempt.
	Version uint64 `json:"version"`
	// Changed lists the settings whose effective value changed.
	Changed []string `json:"changed,omitempty"`
	// PendingRestart lists restart-only settings whose new value waits
	// for a restart.
	PendingRestart []string `json:"pendingRestart,omitempty"`
	// Problems says why a rejected reload was rejected.
	Problems []string `json:"problems,omitempty"`
}

// WeakenedSetting is an active weakening setting, for `scrim status`.
type WeakenedSetting struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	Source      string `json:"source"`
	Description string `json:"description"`
}

// Status is the configuration part of `scrim status`.
type Status struct {
	Version        uint64            `json:"version"`
	Profile        string            `json:"profile"`
	Files          []string          `json:"files"`
	LoadedAt       time.Time         `json:"loadedAt"`
	PendingRestart []string          `json:"pendingRestart,omitempty"`
	Weakened       []WeakenedSetting `json:"weakened"`
	Warnings       []string          `json:"warnings,omitempty"`
	LastReload     *ReloadResult     `json:"lastReload,omitempty"`
}

// NewManager builds the initial configuration from opts and logs its
// warnings and every active weakening setting. log may be nil.
func NewManager(opts Options, log *slog.Logger) (*Manager, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if opts.Environ == nil {
		// The environment of a running process does not change; freeze it
		// so a reload sees the same one.
		opts.Environ = os.Environ()
	}
	c, err := Build(opts)
	if err != nil {
		return nil, err
	}
	c.version = 1
	m := &Manager{opts: opts, log: log, holder: NewHolder(c), debounce: DefaultDebounce, loadedAt: time.Now()}
	LogWarnings(log, c)
	return m, nil
}

// Current returns the Config in effect. It is safe for concurrent use; keep
// the returned pointer for the duration of one operation so all its reads
// see one version.
func (m *Manager) Current() *Config { return m.holder.Current() }

// Subscribe calls fn with the previous and the new Config after every
// applied reload, in registration order, and returns a function that
// removes it. fn runs on the reloading goroutine and must not block or
// call [Manager.Reload].
func (m *Manager) Subscribe(fn func(old, cur *Config)) (cancel func()) {
	return m.holder.Subscribe(fn)
}

// Holder returns the Holder the Manager publishes to, for components that
// only need to read the current Config and subscribe.
func (m *Manager) Holder() *Holder { return m.holder }

// SetDebounce changes the file event debounce, for tests.
func (m *Manager) SetDebounce(d time.Duration) { m.debounce = d }

// Reload rebuilds the configuration and applies it if valid. trigger says
// what asked for it ("signal", "file", "api") and is recorded.
func (m *Manager) Reload(ctx context.Context, trigger string) ReloadResult {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()

	cur := m.holder.Current()
	res := ReloadResult{At: time.Now(), Trigger: trigger, Version: cur.version}
	opts := m.opts
	opts.Context = ctx
	next, err := Build(opts)
	if err != nil {
		for _, p := range Problems(err) {
			res.Problems = append(res.Problems, p.Error())
		}
		m.log.Error("configuration reload rejected; keeping the running configuration",
			"trigger", trigger, "version", cur.version, "problems", res.Problems)
		m.record(res)
		return res
	}
	res.Applied = true

	next.pending = carryRestartOnly(cur, next)
	res.PendingRestart = slices.Clone(next.pending)
	res.Changed = Changed(cur, next)
	if len(res.Changed) == 0 && !metaChanged(cur, next) {
		next.wipe()
		m.record(res)
		return res
	}
	next.version = cur.version + 1
	res.Version = next.version
	for _, key := range next.pending {
		m.log.Warn("setting changed but needs a restart to apply; keeping the running value", "setting", key)
	}
	m.log.Info("configuration reloaded", "trigger", trigger, "version", next.version, "changed", res.Changed)
	LogWarnings(m.log, next)
	m.holder.Swap(next)
	m.record(res)
	return res
}

func (m *Manager) record(res ReloadResult) {
	m.statusMu.Lock()
	defer m.statusMu.Unlock()
	m.last = &res
}

// Status reports the configuration state for `scrim status`.
func (m *Manager) Status() Status {
	c := m.Current()
	m.statusMu.RLock()
	defer m.statusMu.RUnlock()
	st := Status{
		Version:        c.version,
		Profile:        c.profile,
		Files:          c.Files(),
		LoadedAt:       m.loadedAt,
		PendingRestart: c.PendingRestart(),
		Weakened:       WeakenedSettings(c),
	}
	for _, w := range c.warnings {
		st.Warnings = append(st.Warnings, w.String())
	}
	if m.last != nil {
		last := *m.last
		st.LastReload = &last
	}
	return st
}

// WeakenedSettings lists the active weakening settings of c.
func WeakenedSettings(c *Config) []WeakenedSetting {
	out := []WeakenedSetting{}
	for _, e := range c.Weakened() {
		out = append(out, WeakenedSetting{
			Key: e.Setting.Key, Value: FormatValue(e.Value),
			Source: e.Source.String(), Description: e.Setting.Description,
		})
	}
	return out
}

// LogWarnings logs every warning of c and every active weakening setting,
// as at start-up and after each applied reload.
func LogWarnings(log *slog.Logger, c *Config) {
	for _, w := range c.warnings {
		log.Warn("configuration warning", "setting", w.Key, "source", w.Source.String(), "warning", w.Message)
	}
	for _, w := range WeakenedSettings(c) {
		log.Warn("weakened protection active", "setting", w.Key, "value", w.Value, "source", w.Source, "weakens", w.Description)
	}
}

// carryRestartOnly keeps the running value of every restart-only setting
// whose value changed, and returns those keys.
func carryRestartOnly(cur, next *Config) []string {
	var pending []string
	for _, s := range next.reg.Settings() {
		if !s.RestartRequired {
			continue
		}
		old, ok := cur.values[s.Key]
		if !ok {
			continue
		}
		oldSecret, hadSecret := cur.secrets[s.Key]
		newSecret, hasSecret := next.secrets[s.Key]
		sameSecret := hadSecret == hasSecret && (!hadSecret || oldSecret.Equal(newSecret))
		if equalValues(old.Value, next.values[s.Key].Value) && sameSecret {
			continue
		}
		pending = append(pending, s.Key)
		next.values[s.Key] = old
		if hasSecret {
			newSecret.Wipe()
			delete(next.secrets, s.Key)
		}
		if hadSecret {
			next.secrets[s.Key] = oldSecret
		}
		next.deferred = slices.DeleteFunc(next.deferred, func(k string) bool { return k == s.Key })
		if slices.Contains(cur.deferred, s.Key) {
			next.deferred = append(next.deferred, s.Key)
		}
	}
	for _, col := range next.reg.Collections() {
		if !col.RestartRequired || len(collectionChanges(col.Key, cur, next)) == 0 {
			continue
		}
		pending = append(pending, col.Key)
		prefix := col.Key + "."
		for k, v := range next.secrets {
			if strings.HasPrefix(k, prefix) {
				v.Wipe()
				delete(next.secrets, k)
			}
		}
		for k, v := range cur.secrets {
			if strings.HasPrefix(k, prefix) {
				next.secrets[k] = v
			}
		}
		next.deferred = slices.DeleteFunc(next.deferred, func(k string) bool { return strings.HasPrefix(k, prefix) })
		for _, k := range cur.deferred {
			if strings.HasPrefix(k, prefix) {
				next.deferred = append(next.deferred, k)
			}
		}
		old := make(colState, len(cur.collections[col.Key]))
		for name, inst := range cur.collections[col.Key] {
			old[name] = inst.clone()
		}
		next.collections[col.Key] = old
	}
	slices.Sort(pending)
	return pending
}

// collectionChanges lists the instances of a collection (as
// `<collection>.<name>`) that were added, removed or changed, including a
// changed resolved secret.
func collectionChanges(key string, a, b *Config) []string {
	sa, sb := a.collections[key], b.collections[key]
	names := map[string]bool{}
	for n := range sa {
		names[n] = true
	}
	for n := range sb {
		names[n] = true
	}
	var out []string
	for _, n := range slices.Sorted(maps.Keys(names)) {
		ia, okA := sa[n]
		ib, okB := sb[n]
		if okA != okB || !reflect.DeepEqual(ia.Fields, ib.Fields) || secretsDiffer(a, b, key+"."+n+".") {
			out = append(out, key+"."+n)
		}
	}
	return out
}

func secretsDiffer(a, b *Config, prefix string) bool {
	for k, va := range a.secrets {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		if vb, ok := b.secrets[k]; !ok || !va.Equal(vb) {
			return true
		}
	}
	for k := range b.secrets {
		if _, ok := a.secrets[k]; strings.HasPrefix(k, prefix) && !ok {
			return true
		}
	}
	return false
}

// Changed lists the settings whose effective value differs between a and
// b, including secret-ref settings whose resolved value changed while the
// reference stayed the same. Keys are sorted.
func Changed(a, b *Config) []string {
	var out []string
	for _, s := range b.reg.Settings() {
		ea, okA := a.values[s.Key]
		eb := b.values[s.Key]
		if !okA || !equalValues(ea.Value, eb.Value) {
			out = append(out, s.Key)
			continue
		}
		va, hasA := a.secrets[s.Key]
		vb, hasB := b.secrets[s.Key]
		if hasA != hasB || (hasA && !va.Equal(vb)) {
			out = append(out, s.Key)
		}
	}
	for _, col := range b.reg.Collections() {
		out = append(out, collectionChanges(col.Key, a, b)...)
	}
	slices.Sort(out)
	return out
}

// metaChanged reports a change that is not a value change but still
// matters for status and provenance: sources, files, warnings.
func metaChanged(a, b *Config) bool {
	if !slices.Equal(a.files, b.files) || a.profile != b.profile || !slices.Equal(a.pending, b.pending) ||
		!slices.Equal(a.warnings, b.warnings) {
		return true
	}
	for key, sb := range b.collections {
		sa := a.collections[key]
		for name, ib := range sb {
			if ia, ok := sa[name]; !ok || !maps.Equal(ia.Sources, ib.Sources) {
				return true
			}
		}
	}
	for k, eb := range b.values {
		ea := a.values[k]
		if ea.Source != eb.Source || len(ea.Sources) != len(eb.Sources) {
			return true
		}
		for mk, s := range eb.Sources {
			if ea.Sources[mk] != s {
				return true
			}
		}
	}
	return false
}

// Run reloads on SIGHUP and, while `config.watch` is true, on changes to
// the config files, their includes and the files secret references point
// to. It returns when ctx is done.
func (m *Manager) Run(ctx context.Context) error {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer func() { _ = w.Close() }()
	watched := map[string]bool{}
	targets := m.syncWatches(w, watched)

	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-hup:
			m.Reload(ctx, "signal")
			targets = m.syncWatches(w, watched)
		case ev, ok := <-w.Events:
			if !ok {
				return nil
			}
			if targets.relevant(ev.Name) {
				timer.Reset(m.debounce)
			}
		case <-timer.C:
			m.Reload(ctx, "file")
			targets = m.syncWatches(w, watched)
		case err, ok := <-w.Errors:
			if !ok {
				return nil
			}
			m.log.Warn("config file watch error", "error", err)
		}
	}
}

// watchTargets says which file events can change the configuration.
type watchTargets struct {
	files map[string]bool
	dirs  map[string]bool
}

func (t watchTargets) relevant(name string) bool {
	if t.files[name] {
		return true
	}
	base := filepath.Base(name)
	if !t.dirs[filepath.Dir(name)] {
		return false
	}
	// Kubernetes ConfigMap and Secret volumes swap a ..data symlink.
	return strings.HasPrefix(base, "..") || strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml")
}

// syncWatches makes the watcher cover exactly the current Config's files.
func (m *Manager) syncWatches(w *fsnotify.Watcher, watched map[string]bool) watchTargets {
	c := m.Current()
	t := watchTargets{files: map[string]bool{}, dirs: map[string]bool{}}
	want := map[string]bool{}
	if watchEnabled(c) {
		for _, f := range c.files {
			t.files[f] = true
			want[filepath.Dir(f)] = true
		}
		for _, d := range c.watchDirs {
			t.dirs[d] = true
			want[d] = true
		}
		for _, f := range c.secretFiles() {
			t.files[f] = true
			want[filepath.Dir(f)] = true
			t.dirs[filepath.Dir(f)] = true
		}
	}
	for d := range watched {
		if !want[d] {
			_ = w.Remove(d)
			delete(watched, d)
		}
	}
	for _, d := range slices.Sorted(maps.Keys(want)) {
		if watched[d] {
			continue
		}
		if err := w.Add(d); err != nil {
			m.log.Warn("cannot watch config directory; use SIGHUP to reload", "dir", d, "error", err)
			continue
		}
		watched[d] = true
	}
	return t
}

// watchEnabled reports `config.watch` for c, true when the registry lacks it.
func watchEnabled(c *Config) bool {
	if e, ok := c.values["config.watch"]; ok {
		return e.Value.(bool)
	}
	return true
}

// secretFiles lists the files file: and cred: references point to.
func (c *Config) secretFiles() []string {
	var out []string
	for _, f := range c.secretFields() {
		ref := f.ref
		switch ref.Kind() {
		case RefFile:
			out = append(out, strings.TrimPrefix(string(ref), "file:"))
		case RefCredential:
			// systemd credentials do not change while the unit runs.
		case RefNone, RefLiteral, RefEnv, RefStore:
		}
	}
	slices.Sort(out)
	return out
}
