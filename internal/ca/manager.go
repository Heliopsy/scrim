// SPDX-License-Identifier: AGPL-3.0-only

// Package ca is the interception certificate authority of the tool proxy,
// held by the control plane (specs/credential-injection "Interception
// certificate authority").
//
// The CA is either generated and rotated by scrim, persisted in a private
// directory (tool-proxy.ca.dir, default $XDG_STATE_HOME/scrim/ca), or
// supplied by the operator by reference (tool-proxy.ca.cert-file and
// tool-proxy.ca.key), in which case scrim never rotates it and warns before
// it expires.
//
// A rotation keeps the previous generation for tool-proxy.ca.overlap: the
// data plane serves leaves with a cross certificate during that time, and
// the trust bundle carries both certificates. The private keys leave this
// package only through [Manager.Generations], for the data plane snapshot.
package ca

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
)

// Generation is one CA generation as pushed to the data plane.
type Generation struct {
	// ID names the generation (creation time and serial prefix, or
	// "operator" for an operator-supplied CA).
	ID string
	// CertPEM is the CA certificate.
	CertPEM string
	// Key is the PKCS#8 PEM private key. It is a fresh copy; the caller
	// wipes it.
	Key secret.Value
	// NotAfter is when the certificate expires.
	NotAfter time.Time
	// Current is true for the generation that signs leaves. The other one,
	// present only during an overlap, is the previous generation, which
	// signs the cross certificate.
	Current bool
	// OverlapUntil, on the previous generation, is when it stops being
	// trusted. Zero on the current generation.
	OverlapUntil time.Time
}

// Certificate is the public part of a generation.
type Certificate struct {
	ID       string
	PEM      string
	NotAfter time.Time
	Current  bool
}

// OperatorID is the generation ID of an operator-supplied CA.
const OperatorID = "operator"

// Options adjust [OpenWith]. The zero value is what [Open] uses.
type Options struct {
	// Dir overrides tool-proxy.ca.dir and the default directory.
	Dir string
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Getenv reads XDG_STATE_HOME and HOME for the default directory; nil
	// means os.Getenv.
	Getenv func(string) string
	// PublicOnly, for an operator-supplied CA, skips resolving the key: the
	// Manager can export and install the certificate but [Manager.Generations]
	// returns no key. A generated CA is always loaded whole.
	PublicOnly bool
	// PollInterval is how often Run re-reads the directory in case a change
	// from another process was missed; 0 means one minute.
	PollInterval time.Duration
}

// Manager holds the CA generations in use.
type Manager struct {
	log      *slog.Logger
	now      func() time.Time
	pol      policy
	dir      string
	operator bool
	certFile string
	poll     time.Duration

	mu           sync.RWMutex
	cur, prev    *generation
	overlapUntil time.Time
	raw          []byte // state.json as last loaded
	retryAt      time.Time
	warnedAt     time.Time

	changed chan struct{}
}

// Open loads the CA from the configuration, generating and persisting it
// when there is none yet, rotating it when it is due and dropping a
// previous generation whose overlap has ended.
func Open(ctx context.Context, cfg *config.Config, log *slog.Logger) (*Manager, error) {
	return OpenWith(ctx, cfg, log, Options{})
}

// OpenWith is [Open] with options.
func OpenWith(_ context.Context, cfg *config.Config, log *slog.Logger, o Options) (*Manager, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	pol, err := policyFrom(cfg)
	if err != nil {
		return nil, fmt.Errorf("ca: %w", err)
	}
	m := &Manager{log: log, now: o.Now, pol: pol, poll: o.PollInterval, changed: make(chan struct{}, 1)}
	if m.now == nil {
		m.now = time.Now
	}
	if m.poll <= 0 {
		m.poll = time.Minute
	}
	certFile, keyRef := CertFileSetting.Get(cfg), KeySetting.Get(cfg)
	if certFile != "" || keyRef != "" {
		if err := m.openOperator(cfg, certFile, keyRef, o.PublicOnly); err != nil {
			return nil, err
		}
		return m, nil
	}
	m.dir = o.Dir
	if m.dir == "" {
		m.dir = DirSetting.Get(cfg)
	}
	if m.dir == "" {
		if m.dir, err = DefaultDir(o.Getenv); err != nil {
			return nil, err
		}
	}
	if !filepath.IsAbs(m.dir) {
		return nil, fmt.Errorf("ca: %s %q must be an absolute path", DirSetting.Name(), m.dir)
	}
	if err := ensureDir(m.dir); err != nil {
		return nil, err
	}
	if _, err := m.update(false); err != nil {
		m.Close()
		return nil, err
	}
	return m, nil
}

func (m *Manager) openOperator(cfg *config.Config, certFile string, keyRef config.SecretRef, publicOnly bool) error {
	if certFile == "" || keyRef == "" {
		return fmt.Errorf("ca: %s and %s must be set together", CertFileSetting.Name(), KeySetting.Name())
	}
	if !filepath.IsAbs(certFile) {
		return fmt.Errorf("ca: %s %q must be an absolute path", CertFileSetting.Name(), certFile)
	}
	m.operator, m.certFile = true, certFile
	b, err := readFile(certFile)
	if err != nil {
		return fmt.Errorf("ca: %s: %w", CertFileSetting.Name(), err)
	}
	cert, err := parseCert(b)
	if err != nil {
		return fmt.Errorf("ca: %s %s: %w", CertFileSetting.Name(), certFile, err)
	}
	g := &generation{id: OperatorID, certPEM: string(b), cert: cert}
	if !publicOnly {
		v, ok := cfg.Secret(KeySetting)
		if !ok {
			return fmt.Errorf("ca: %s (%s) is set but could not be resolved", KeySetting.Name(), keyRef.Display())
		}
		g.key = cloneValue(v)
		if err := checkKey(cert, g.key); err != nil {
			g.wipe()
			return fmt.Errorf("ca: %s (%s): %w", KeySetting.Name(), keyRef.Display(), err)
		}
		if !m.now().Before(cert.NotAfter) {
			g.wipe()
			return fmt.Errorf("ca: the CA in %s expired at %s; replace %s and %s",
				certFile, cert.NotAfter.UTC().Format(time.RFC3339), CertFileSetting.Name(), KeySetting.Name())
		}
	}
	m.cur = g
	m.warnExpiry()
	return nil
}

func cloneValue(v secret.Value) secret.Value {
	var out secret.Value
	_ = v.Expose(func(b []byte) error {
		out = secret.New(b)
		return nil
	})
	return out
}

// Dir is the CA directory; empty for an operator-supplied CA.
func (m *Manager) Dir() string { return m.dir }

// Operator reports whether the CA is supplied by the operator by reference.
func (m *Manager) Operator() bool { return m.operator }

// Generations returns fresh copies of the generations in use: the current
// one first and, during an overlap, the previous one second. The caller
// wipes every Key.
func (m *Manager) Generations() []Generation {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []Generation{{ID: m.cur.id, CertPEM: m.cur.certPEM, Key: cloneValue(m.cur.key), NotAfter: m.cur.cert.NotAfter, Current: true}}
	if m.inOverlap() {
		out = append(out, Generation{ID: m.prev.id, CertPEM: m.prev.certPEM, Key: cloneValue(m.prev.key),
			NotAfter: m.prev.cert.NotAfter, OverlapUntil: m.overlapUntil})
	}
	return out
}

// Certificates returns the public certificates in use, current first.
func (m *Manager) Certificates() []Certificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []Certificate{{ID: m.cur.id, PEM: m.cur.certPEM, NotAfter: m.cur.cert.NotAfter, Current: true}}
	if m.inOverlap() {
		out = append(out, Certificate{ID: m.prev.id, PEM: m.prev.certPEM, NotAfter: m.prev.cert.NotAfter})
	}
	return out
}

// TrustBundlePEM returns the certificates clients must trust: the current
// CA and, during an overlap, the previous one.
func (m *Manager) TrustBundlePEM() string {
	var s string
	for _, c := range m.Certificates() {
		s += c.PEM
	}
	return s
}

// inOverlap is called with m.mu held.
func (m *Manager) inOverlap() bool {
	return m.prev != nil && m.now().Before(m.overlapUntil)
}

// Rotate makes a new generation current and keeps the current one as the
// previous generation for tool-proxy.ca.overlap. A previous generation
// still in its overlap is dropped. An operator-supplied CA is not rotated.
func (m *Manager) Rotate(_ context.Context) error {
	if m.operator {
		return fmt.Errorf("ca: the CA is supplied by %s and %s; scrim does not rotate it, replace those instead",
			CertFileSetting.Name(), KeySetting.Name())
	}
	_, err := m.update(true)
	return err
}

// Close wipes the keys held in memory.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cur.wipe()
	m.prev.wipe()
}

// Run keeps the CA up to date until ctx ends: it rotates when the current
// generation is due, drops the previous generation when its overlap ends,
// and picks up changes another process (`scrim ca rotate`) made to the
// directory. onChange is called after every change of the generations,
// including one made by [Manager.Rotate] in this process.
func (m *Manager) Run(ctx context.Context, onChange func()) {
	if onChange == nil {
		onChange = func() {}
	}
	var (
		events <-chan fsnotify.Event
		werrs  <-chan error
	)
	if !m.operator {
		if w, err := fsnotify.NewWatcher(); err != nil {
			m.log.Warn("CA directory watch unavailable, polling instead", "dir", m.dir, "err", err)
		} else {
			defer func() { _ = w.Close() }()
			if err := w.Add(m.dir); err != nil {
				m.log.Warn("CA directory watch unavailable, polling instead", "dir", m.dir, "err", err)
			} else {
				events, werrs = w.Events, w.Errors
			}
		}
	}
	poll := time.NewTicker(m.poll)
	defer poll.Stop()
	for {
		timer := time.NewTimer(m.nextCheck())
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-m.changed:
			onChange()
		case ev := <-events:
			if filepath.Base(ev.Name) == stateFile {
				m.refresh()
			}
		case err := <-werrs:
			m.log.Warn("CA directory watch", "dir", m.dir, "err", err)
		case <-poll.C:
			m.refresh()
		case <-timer.C:
			m.maintain()
		}
		timer.Stop()
	}
}

// nextCheck is how long until the next rotation or end of overlap is due,
// bounded so a suspended machine or a changed clock is noticed within an
// hour.
func (m *Manager) nextCheck() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := m.now()
	next := now.Add(time.Hour)
	if !m.operator {
		next = earliest(next, m.cur.cert.NotAfter.Add(-m.pol.rotateBefore))
		if m.prev != nil {
			next = earliest(next, m.overlapUntil)
		}
		if now.Before(m.retryAt) {
			next = m.retryAt
		}
	}
	return max(next.Sub(now), time.Second)
}

func earliest(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// maintain runs the time-based steps once.
func (m *Manager) maintain() {
	if m.operator {
		m.warnExpiry()
		return
	}
	if _, err := m.update(false); err != nil {
		m.log.Error("CA maintenance failed, retrying in a minute", "dir", m.dir, "err", err)
		m.mu.Lock()
		m.retryAt = m.now().Add(time.Minute)
		m.mu.Unlock()
	}
}

// refresh loads the directory again if another process changed it.
func (m *Manager) refresh() {
	if m.operator {
		return
	}
	if err := m.reload(); err != nil {
		m.log.Error("CA reload failed, keeping the generations in use", "dir", m.dir, "err", err)
	}
}

func (m *Manager) signal() {
	select {
	case m.changed <- struct{}{}:
	default:
	}
}

// warnExpiry logs, at most once a day, that an operator-supplied CA is close
// to or past its expiry.
func (m *Manager) warnExpiry() {
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	notAfter := m.cur.cert.NotAfter
	if now.Before(notAfter.Add(-m.pol.rotateBefore)) || now.Sub(m.warnedAt) < 24*time.Hour {
		return
	}
	m.warnedAt = now
	if !now.Before(notAfter) {
		m.log.Error("the operator-supplied CA has expired; clients will refuse the tool proxy until it is replaced",
			"cert_file", m.certFile, "not_after", notAfter.UTC())
		return
	}
	m.log.Warn("the operator-supplied CA expires soon; scrim does not rotate it, replace "+
		CertFileSetting.Name()+" and "+KeySetting.Name(), "cert_file", m.certFile, "not_after", notAfter.UTC())
}

// update brings the directory up to date under the exclusive lock: creates
// the first generation, rotates when due (or when force is set) and drops a
// previous generation whose overlap has ended, then loads the result.
func (m *Manager) update(force bool) (bool, error) {
	unlock, err := lockDir(m.dir, true)
	if err != nil {
		return false, err
	}
	defer unlock()
	st, _, ok, err := readState(m.dir)
	if err != nil {
		return false, err
	}
	now := m.now()
	dirty := false
	switch {
	case !ok:
		g, err := m.create(now)
		if err != nil {
			return false, err
		}
		st = diskState{Current: g.id}
		dirty = true
		m.log.Info("created the interception CA", "dir", m.dir, "generation", g.id, "not_after", g.cert.NotAfter.UTC())
	default:
		_, cur, err := loadCert(m.dir, st.Current)
		if err != nil {
			return false, err
		}
		if force || !now.Before(cur.NotAfter.Add(-m.pol.rotateBefore)) {
			g, err := m.create(now)
			if err != nil {
				return false, err
			}
			if st.Previous != "" {
				m.log.Info("dropped the previous CA generation before its overlap ended", "generation", st.Previous)
			}
			st.Previous, st.Current = st.Current, g.id
			st.OverlapUntil = earliest(now.Add(m.pol.overlap), cur.NotAfter).UTC()
			dirty = true
			m.log.Warn("rotated the interception CA; clients must trust the new CA before the overlap ends "+
				"(run `scrim ca install --user` again, or export the bundle with `scrim ca export`)",
				"dir", m.dir, "generation", g.id, "previous", st.Previous, "overlap_until", st.OverlapUntil)
		}
	}
	if st.Previous != "" && !now.Before(st.OverlapUntil) {
		m.log.Info("the CA overlap ended, the previous generation is no longer trusted", "generation", st.Previous)
		st.Previous, st.OverlapUntil = "", time.Time{}
		dirty = true
	}
	if dirty {
		if err := writeState(m.dir, st); err != nil {
			return false, err
		}
		if err := removeUnused(m.dir, st.Current, st.Previous); err != nil {
			m.log.Warn("could not remove unused CA generations", "err", err)
		}
	}
	changed, err := m.loadLocked()
	if err != nil {
		return false, err
	}
	if dirty {
		m.refreshTrustFiles()
	}
	return changed, nil
}

func (m *Manager) create(now time.Time) (*generation, error) {
	g, err := newGeneration(now, m.pol.validity)
	if err != nil {
		return nil, err
	}
	defer g.wipe()
	if err := writeGeneration(m.dir, g); err != nil {
		return nil, err
	}
	return g, nil
}

// reload loads the directory under the shared lock if state.json changed.
func (m *Manager) reload() error {
	unlock, err := lockDir(m.dir, false)
	if err != nil {
		return err
	}
	_, _, ok, err := readState(m.dir)
	if err == nil && !ok {
		unlock()
		m.log.Warn("the CA state disappeared from the CA directory; creating a new CA", "dir", m.dir)
		_, err = m.update(false)
		return err
	}
	defer unlock()
	if err != nil {
		return err
	}
	_, err = m.loadLocked()
	return err
}

// loadLocked replaces the generations in memory with the ones on disk if
// state.json differs from what was loaded last. A lock is held.
func (m *Manager) loadLocked() (bool, error) {
	st, raw, ok, err := readState(m.dir)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, errors.New("ca: no state.json in " + m.dir)
	}
	m.mu.RLock()
	same := m.raw != nil && string(m.raw) == string(raw)
	m.mu.RUnlock()
	if same {
		return false, nil
	}
	cur, err := loadGeneration(m.dir, st.Current)
	if err != nil {
		return false, err
	}
	var prev *generation
	if st.Previous != "" {
		if prev, err = loadGeneration(m.dir, st.Previous); err != nil {
			cur.wipe()
			return false, err
		}
	}
	m.mu.Lock()
	oldCur, oldPrev := m.cur, m.prev
	m.cur, m.prev, m.overlapUntil, m.raw = cur, prev, st.OverlapUntil, raw
	m.mu.Unlock()
	oldCur.wipe()
	oldPrev.wipe()
	if oldCur != nil {
		m.signal()
	}
	return true, nil
}
