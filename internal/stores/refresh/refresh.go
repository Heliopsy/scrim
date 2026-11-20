// SPDX-License-Identifier: AGPL-3.0-only

// Package refresh keeps the values of one store in memory for redaction and
// injection, and decides what happens when the store goes away
// (specs/secret-stores: "Known values load into the redaction set", "Watch
// and refresh", "Store outage keeps the last known redaction set",
// "Injection fails closed when a value is unavailable", "New and written
// values are redacted at once"; specs/observability: "Store health and
// freshness").
//
// A [Refresher] loads every secret its targets name at start, then refreshes
// on an interval with jitter and, where the adapter can watch, re-reads what
// changed as soon as the store reports it. Secrets whose listed version has
// not changed are not read again.
//
// The rules it enforces:
//
//   - Redaction never weakens. A value stays in the redaction set while the
//     store is unreachable, and a rotated or deleted value stays for the
//     retention period. Only a successful refresh replaces a value.
//   - Redaction is not ready until the first load completes. [Refresher.Ready]
//     fails until then, so requests that depend on the store are refused.
//   - Injection fails closed. [Refresher.Resolve] returns a value only if it
//     is in memory and was confirmed by the store within the staleness limit,
//     or can be read from the store now. It never returns an empty value, a
//     value past the staleness limit, or anything for a locked store.
//   - Written values are redacted before the write is reported. [Refresher.Write]
//     adds the values to the set first and removes them only if the store
//     refuses the write.
//
// Values live only in memory, as secret.Value, and are wiped when they leave
// the set.
package refresh

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// Defaults for [Config].
const (
	DefaultInterval   = 5 * time.Minute
	DefaultRetention  = 24 * time.Hour
	DefaultStaleness  = 15 * time.Minute
	DefaultJitter     = 0.2
	DefaultMaxBackoff = 5 * time.Minute
)

// Target is something the configuration marks for redaction: one secret, or
// every secret under a prefix.
type Target struct {
	Ref    stores.Ref
	Prefix bool
}

// ParseTarget parses a configured target. A reference ending in `/*` is a
// prefix; anything else names one secret. A field selector is allowed on a
// single secret and limits loading to that field.
func ParseTarget(s string) (Target, error) {
	prefix := strings.HasSuffix(s, "/*")
	r, err := stores.ParseRef(strings.TrimSuffix(s, "/*"))
	if err != nil {
		return Target{}, err
	}
	if prefix && (r.Field != "" || r.Selectors != "") {
		return Target{}, fmt.Errorf("%w: a prefix target takes no field or selector", stores.ErrInvalidRef)
	}
	return Target{Ref: r, Prefix: prefix}, nil
}

func (t Target) String() string {
	if t.Prefix {
		return t.Ref.String() + "/*"
	}
	return t.Ref.String()
}

// covers reports whether ref (a whole secret) is under t.
func (t Target) covers(ref stores.Ref) bool {
	if t.Prefix {
		return ref.Path == t.Ref.Path || strings.HasPrefix(ref.Path, t.Ref.Path+"/")
	}
	return ref.Path == t.Ref.Path
}

// Config tunes a Refresher.
type Config struct {
	// Targets are the secrets loaded at start and kept fresh.
	Targets []Target
	// Interval is the full refresh period; default 5m.
	Interval time.Duration
	// Jitter spreads each wait by up to this fraction either way; default
	// 0.2. Negative disables jitter (tests).
	Jitter float64
	// Retention is how long a rotated, deleted or overwritten value stays
	// in the redaction set; default 24h.
	Retention time.Duration
	// Staleness is how long a value confirmed by the store may be injected
	// without a newer confirmation, and how long the store may be
	// unreachable before it is reported unhealthy; default 15m.
	Staleness time.Duration
	// MaxBackoff bounds the retry delay after failed loads; default 5m.
	MaxBackoff time.Duration
	// Now is the clock; default time.Now.
	Now func() time.Time
	// OnChange, if set, is called after every change to the value set
	// (load, refresh, write, expiry), outside any lock. The data plane
	// dictionary is rebuilt from it.
	OnChange func()
	// OnStatus, if set, is called with the new status after every refresh
	// attempt, for metrics.
	OnStatus func(Status)
}

func (c *Config) defaults() {
	if c.Interval <= 0 {
		c.Interval = DefaultInterval
	}
	if c.Jitter == 0 {
		c.Jitter = DefaultJitter
	}
	if c.Retention <= 0 {
		c.Retention = DefaultRetention
	}
	if c.Staleness <= 0 {
		c.Staleness = DefaultStaleness
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = DefaultMaxBackoff
	}
	if c.MaxBackoff < c.Interval {
		c.MaxBackoff = c.Interval
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

// State is a store's condition as reported by status and health.
type State string

// States.
const (
	// StateLoading: the first load has not finished and has not failed yet.
	StateLoading State = "loading"
	// StateReady: the last refresh succeeded.
	StateReady State = "ready"
	// StateDegraded: values were loaded, but the last refresh failed. The
	// last known values are still redacted.
	StateDegraded State = "degraded"
	// StateUnavailable: no load has ever succeeded. Redaction is not ready.
	StateUnavailable State = "unavailable"
	// StateLocked: the store is reachable but locked (Vaultwarden without
	// its unlock key). Injection from it is refused.
	StateLocked State = "locked"
)

// Status is a snapshot of a store's freshness. It holds no value.
type Status struct {
	Store string `json:"store"`
	State State  `json:"state"`
	// Loaded is true once the first load has completed.
	Loaded bool `json:"loaded"`
	// Healthy is false when the store never loaded, is locked, or has not
	// refreshed successfully for longer than the staleness limit.
	Healthy bool `json:"healthy"`
	// LastSuccess is the last successful refresh; LastAttempt the last try.
	LastSuccess time.Time `json:"last_success,omitzero"`
	LastAttempt time.Time `json:"last_attempt,omitzero"`
	// LastError is the last refresh error, from stores.Error messages,
	// which carry no value.
	LastError string `json:"last_error,omitempty"`
	// Secrets and Values count what is held: current secrets, and values
	// in the redaction set including retained previous ones.
	Secrets int `json:"secrets"`
	Values  int `json:"values"`
}

type entry struct {
	meta   stores.Metadata
	fields map[string]secret.Value
	// verified is when the store last confirmed these values.
	verified time.Time
	// written marks values scrim wrote itself (the only values a
	// write-only secret has in memory).
	written bool
}

func (e *entry) wipe() {
	for _, v := range e.fields {
		v.Wipe()
	}
}

type retired struct {
	ref     stores.Ref
	field   string
	v       secret.Value
	expires time.Time
}

// Refresher holds one store's values. It is safe for concurrent use.
type Refresher struct {
	a   stores.Adapter
	cfg Config

	mu          sync.RWMutex
	entries     map[string]*entry // by Ref.Secret().String()
	retired     []retired
	pending     map[*secret.Value]stores.Ref // values of writes in flight
	creds       []secret.Value
	loaded      bool
	locked      bool
	lastSuccess time.Time
	lastAttempt time.Time
	lastErr     error

	kick chan struct{} // asks Run for a refresh now
}

// New returns a Refresher over a. It does not contact the store until Run
// or RefreshNow.
func New(a stores.Adapter, cfg Config) *Refresher {
	cfg.defaults()
	return &Refresher{
		a: a, cfg: cfg,
		entries: map[string]*entry{},
		pending: map[*secret.Value]stores.Ref{},
		kick:    make(chan struct{}, 1),
	}
}

// Store returns the adapter's name.
func (r *Refresher) Store() string { return r.a.Name() }

func key(ref stores.Ref) string { return ref.Secret().String() }

func (r *Refresher) err(op stores.Op, ref stores.Ref, kind error, detail string, cause error) *stores.Error {
	e := stores.NewError(r.a.Name(), op, ref, kind, cause)
	e.Detail = detail
	return e
}

func (r *Refresher) changed() {
	if r.cfg.OnChange != nil {
		r.cfg.OnChange()
	}
}

func (r *Refresher) jitter(d time.Duration) time.Duration {
	if r.cfg.Jitter <= 0 {
		return d
	}
	spread := int64(float64(d) * r.cfg.Jitter)
	if spread <= 0 {
		return d
	}
	return d - time.Duration(spread) + time.Duration(rand.Int64N(2*spread+1))
}

// Run loads the store, then refreshes it until ctx ends. A failed load is
// retried with exponential backoff; a failed refresh keeps the last known
// values and marks the store degraded. Run returns when ctx ends.
func (r *Refresher) Run(ctx context.Context) {
	var wg sync.WaitGroup
	defer wg.Wait()
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()

	wait := r.cfg.Interval
	first := true
	for {
		if !first {
			t := time.NewTimer(r.jitter(wait))
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			case <-r.kick:
				t.Stop()
			}
		}
		err := r.RefreshNow(ctx)
		if ctx.Err() != nil {
			return
		}
		switch {
		case err == nil:
			wait = r.cfg.Interval
			if first {
				first = false
				if r.a.Capabilities().Has(stores.CapWatch) {
					for _, t := range r.cfg.Targets {
						wg.Go(func() { r.watch(wctx, t) })
					}
				}
			}
		case !r.Status().Loaded:
			// Before the first load, retry soon: redaction is not ready
			// and requests are being refused.
			if first {
				first = false
				wait = min(time.Second, r.cfg.Interval)
			} else {
				wait = min(wait*2, r.cfg.MaxBackoff)
			}
		default:
			wait = min(max(wait, r.cfg.Interval/4), r.cfg.MaxBackoff)
		}
	}
}

// watch re-reads secrets under t as the adapter reports changes, restarting
// the watch with backoff if it cannot be started.
func (r *Refresher) watch(ctx context.Context, t Target) {
	prefix := t.Ref.Secret()
	if !t.Prefix {
		// Watch the folder holding the secret and filter.
		if i := strings.LastIndexByte(prefix.Path, '/'); i > 0 {
			prefix.Path = prefix.Path[:i]
		}
	}
	backoff := time.Second
	for ctx.Err() == nil {
		ch, err := r.a.Watch(ctx, prefix)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(r.jitter(backoff)):
			}
			backoff = min(backoff*2, r.cfg.MaxBackoff)
			continue
		}
		backoff = time.Second
		for c := range ch {
			if !t.covers(c.Ref) {
				continue
			}
			r.applyChange(ctx, t, c)
		}
	}
}

func (r *Refresher) applyChange(ctx context.Context, t Target, c stores.Change) {
	switch c.Kind {
	case stores.Deleted:
		r.mu.Lock()
		r.retireLocked(key(c.Ref))
		r.mu.Unlock()
		r.changed()
	case stores.Changed:
		ref := c.Ref.Secret()
		if !t.Prefix {
			ref = t.Ref
		}
		// A failure here is covered by the next full refresh.
		_ = r.load(ctx, ref, stores.Metadata{})
	}
}

// RefreshNow runs one full refresh: list each prefix target, read each
// secret whose version changed (or every one, for stores without versions),
// retire what disappeared. On failure the previous values are kept.
func (r *Refresher) RefreshNow(ctx context.Context) error {
	now := r.cfg.Now()
	err := r.refresh(ctx)
	r.mu.Lock()
	r.lastAttempt = now
	r.locked = errors.Is(err, stores.ErrLocked)
	if err == nil {
		r.lastSuccess = now
		r.loaded = true
		r.lastErr = nil
	} else {
		r.lastErr = err
	}
	r.expireLocked(now)
	if h, ok := r.a.(stores.CredentialHolder); ok {
		for _, v := range r.creds {
			v.Wipe()
		}
		r.creds = h.Credentials()
	}
	r.mu.Unlock()
	r.changed()
	if r.cfg.OnStatus != nil {
		r.cfg.OnStatus(r.Status())
	}
	return err
}

func (r *Refresher) refresh(ctx context.Context) error {
	var errs []error
	seen := map[string]bool{}
	for _, t := range r.cfg.Targets {
		if !t.Prefix {
			seen[key(t.Ref)] = true
			if err := r.load(ctx, t.Ref, stores.Metadata{}); err != nil {
				if errors.Is(err, stores.ErrNotFound) {
					r.mu.Lock()
					r.retireLocked(key(t.Ref))
					r.mu.Unlock()
					continue
				}
				errs = append(errs, err)
			}
			continue
		}
		if !r.a.Capabilities().Has(stores.CapList) {
			errs = append(errs, r.err(stores.OpList, t.Ref, stores.ErrUnsupported, "a prefix target needs a store that can list", nil))
			continue
		}
		ms, err := r.a.List(ctx, t.Ref)
		if err != nil {
			errs = append(errs, err)
			// Keep everything under the prefix: the listing failed, so
			// nothing is known to be gone.
			r.mu.RLock()
			for k, e := range r.entries {
				if t.covers(e.meta.Ref) {
					seen[k] = true
				}
			}
			r.mu.RUnlock()
			continue
		}
		for _, m := range ms {
			seen[key(m.Ref)] = true
			if err := r.load(ctx, m.Ref.Secret(), m); err != nil && !errors.Is(err, stores.ErrNotFound) {
				errs = append(errs, err)
			}
		}
	}
	// Secrets no target lists any more are gone from the store: their
	// values are retired, not dropped.
	r.mu.Lock()
	for k, e := range r.entries {
		if !seen[k] && !e.written {
			r.retireLocked(k)
		}
	}
	r.mu.Unlock()
	return errors.Join(errs...)
}

// load reads one secret (unless listed says its version is unchanged or it
// is write-only) and installs it, retiring replaced values.
func (r *Refresher) load(ctx context.Context, ref stores.Ref, listed stores.Metadata) error {
	k := key(ref)
	now := r.cfg.Now()
	r.mu.Lock()
	cur := r.entries[k]
	if listed.WriteOnly {
		// Never read back; keep only what scrim wrote, still confirmed by
		// the listing.
		if cur != nil {
			cur.verified = now
			cur.meta.Version = listed.Version
		}
		r.mu.Unlock()
		return nil
	}
	if cur != nil && listed.Version != "" && cur.meta.Version == listed.Version && !cur.written {
		cur.verified = now
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()

	s, err := r.a.Read(ctx, ref)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur := r.entries[k]; cur != nil {
		r.retireReplacedLocked(cur, s.Fields)
	}
	r.entries[k] = &entry{meta: s.Meta, fields: s.Fields, verified: now}
	return nil
}

// retireReplacedLocked moves values of cur that next does not hold into the
// retained set, and wipes duplicates.
func (r *Refresher) retireReplacedLocked(cur *entry, next map[string]secret.Value) {
	exp := r.cfg.Now().Add(r.cfg.Retention)
	for f, old := range cur.fields {
		if nv, ok := next[f]; ok && nv.Equal(old) {
			old.Wipe()
			continue
		}
		r.retired = append(r.retired, retired{ref: cur.meta.Ref, field: f, v: old, expires: exp})
	}
}

func (r *Refresher) retireLocked(k string) {
	e, ok := r.entries[k]
	if !ok {
		return
	}
	delete(r.entries, k)
	exp := r.cfg.Now().Add(r.cfg.Retention)
	for f, v := range e.fields {
		r.retired = append(r.retired, retired{ref: e.meta.Ref, field: f, v: v, expires: exp})
	}
}

func (r *Refresher) expireLocked(now time.Time) {
	kept := r.retired[:0]
	for _, x := range r.retired {
		if now.After(x.expires) {
			x.v.Wipe()
			continue
		}
		kept = append(kept, x)
	}
	clear(r.retired[len(kept):])
	r.retired = kept
}

// Ready returns nil once the first load has completed. Until then it
// returns an error naming the store, and provider requests that depend on
// it must be refused (specs/secret-stores, "Start-up before stores are
// loaded"). It has the signature of an obs readiness check.
func (r *Refresher) Ready(context.Context) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.loaded {
		return nil
	}
	detail := "redaction is not ready: the first load has not completed"
	if r.lastErr != nil {
		detail += ": " + r.lastErr.Error()
	}
	return r.err("load", stores.Ref{}, stores.ErrUnavailable, detail, nil)
}

// Status reports the store's freshness.
func (r *Refresher) Status() Status {
	r.mu.RLock()
	defer r.mu.RUnlock()
	now := r.cfg.Now()
	st := Status{
		Store: r.a.Name(), Loaded: r.loaded,
		LastSuccess: r.lastSuccess, LastAttempt: r.lastAttempt,
		Secrets: len(r.entries), Values: len(r.retired),
	}
	for _, e := range r.entries {
		st.Values += len(e.fields)
	}
	if r.lastErr != nil {
		st.LastError = r.lastErr.Error()
	}
	switch {
	case r.locked:
		st.State = StateLocked
	case r.lastAttempt.IsZero():
		st.State = StateLoading
	case !r.loaded:
		st.State = StateUnavailable
	case r.lastErr != nil:
		st.State = StateDegraded
	default:
		st.State = StateReady
	}
	st.Healthy = r.loaded && !r.locked && now.Sub(r.lastSuccess) <= r.cfg.Staleness
	return st
}

// Source says where a value in the redaction set comes from. It holds no
// value.
type Source struct {
	// Ref is the secret and field the value belongs to; zero for the
	// store's own credentials.
	Ref stores.Ref
	// Retained marks a previous value kept after rotation or deletion.
	Retained bool
	// Pending marks the value of a write in flight.
	Pending bool
}

// EachValue calls fn for every value in this store's redaction set: current
// values, retained previous values, values of writes in flight and the
// adapter's own credentials. fn runs under a read lock and must not retain
// v or call back into the Refresher.
func (r *Refresher) EachValue(fn func(src Source, v secret.Value)) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	keys := make([]string, 0, len(r.entries))
	for k := range r.entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		e := r.entries[k]
		names := make([]string, 0, len(e.fields))
		for f := range e.fields {
			names = append(names, f)
		}
		sort.Strings(names)
		for _, f := range names {
			fn(Source{Ref: e.meta.Ref.WithField(f)}, e.fields[f])
		}
	}
	for _, x := range r.retired {
		fn(Source{Ref: x.ref.WithField(x.field), Retained: true}, x.v)
	}
	for v, ref := range r.pending {
		fn(Source{Ref: ref, Pending: true}, *v)
	}
	for _, v := range r.creds {
		fn(Source{}, v)
	}
}

// Resolve returns a copy of the value ref names, for injection toward a
// destination. The caller wipes it. It fails closed:
//
//   - a locked store refuses (ErrLocked);
//   - a value in memory is returned only if the store confirmed it within
//     the staleness limit; past that, the store is asked again, and if it
//     cannot answer the request is refused (ErrUnavailable);
//   - a value not in memory is read from the store now, and added to the
//     redaction set, before it is returned;
//   - a write-only secret yields only the value scrim wrote;
//   - a secret with several fields needs a field selector, unless it has
//     exactly one.
//
// Every error names the reference and carries no value.
func (r *Refresher) Resolve(ctx context.Context, ref stores.Ref) (secret.Value, error) {
	if v, ok, err := r.fromMemory(ref); ok || err != nil {
		return v, err
	}
	r.mu.RLock()
	locked := r.locked
	e := r.entries[key(ref)]
	r.mu.RUnlock()
	if locked {
		return secret.Value{}, r.err(stores.OpRead, ref, stores.ErrLocked, "store is locked; cannot inject", nil)
	}
	if e != nil && (e.meta.WriteOnly || e.written && !r.a.Capabilities().Has(stores.CapRead)) {
		return secret.Value{}, r.err(stores.OpRead, ref, stores.ErrUnavailable,
			"write-only secret past the staleness limit; the store cannot confirm it", nil)
	}
	if err := r.load(ctx, ref.Secret(), stores.Metadata{}); err != nil {
		var se *stores.Error
		if errors.As(err, &se) {
			return secret.Value{}, r.err(stores.OpRead, ref, se.Kind, "cannot inject: "+se.Detail, err)
		}
		return secret.Value{}, r.err(stores.OpRead, ref, stores.ErrUnavailable, "cannot inject", err)
	}
	r.changed()
	v, ok, err := r.fromMemory(ref)
	if !ok && err == nil {
		err = r.err(stores.OpRead, ref, stores.ErrUnavailable, "value not available", nil)
	}
	return v, err
}

// fromMemory returns a fresh-enough in-memory value. ok is false when the
// caller should go to the store.
func (r *Refresher) fromMemory(ref stores.Ref) (secret.Value, bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.locked {
		return secret.Value{}, false, r.err(stores.OpRead, ref, stores.ErrLocked, "store is locked; cannot inject", nil)
	}
	e, ok := r.entries[key(ref)]
	if !ok {
		return secret.Value{}, false, nil
	}
	if r.cfg.Now().Sub(e.verified) > r.cfg.Staleness {
		return secret.Value{}, false, nil
	}
	field := ref.Field
	if field == "" {
		if len(e.fields) != 1 {
			return secret.Value{}, false, r.err(stores.OpRead, ref, stores.ErrInvalidRef,
				fmt.Sprintf("secret has %d fields; name one with #<field>", len(e.fields)), nil)
		}
		for f := range e.fields {
			field = f
		}
	}
	v, ok := e.fields[field]
	if !ok {
		return secret.Value{}, false, r.err(stores.OpRead, ref, stores.ErrNotFound, "no such field", nil)
	}
	if v.IsZero() {
		// Never inject an empty string in place of a credential.
		return secret.Value{}, false, r.err(stores.OpRead, ref, stores.ErrUnavailable, "value is empty", nil)
	}
	return copyValue(v), true, nil
}

// Write writes fields to ref through the adapter, adding every value to the
// redaction set before the write is attempted and keeping it there once the
// store accepts it. If the store refuses, the values are removed and wiped
// from the set and the error (which names the reference and the store's
// reason, never a value) is returned. The caller keeps ownership of fields.
func (r *Refresher) Write(ctx context.Context, ref stores.Ref, fields map[string]secret.Value, opts stores.WriteOptions) (stores.Metadata, error) {
	ref = ref.Secret()
	if !r.a.Capabilities().Has(stores.CapWrite) {
		return stores.Metadata{}, r.err(stores.OpWrite, ref, stores.ErrUnsupported,
			fmt.Sprintf("store %s is read-only", r.a.Name()), nil)
	}
	own := make(map[string]secret.Value, len(fields))
	keys := make([]*secret.Value, 0, len(fields))
	r.mu.Lock()
	for f, v := range fields {
		c := copyValue(v)
		own[f] = c
		keys = append(keys, &c)
		r.pending[&c] = ref.WithField(f)
	}
	r.mu.Unlock()
	r.changed()

	m, err := r.a.Write(ctx, ref, fields, opts)

	r.mu.Lock()
	for _, p := range keys {
		delete(r.pending, p)
	}
	if err != nil {
		r.mu.Unlock()
		for _, v := range own {
			v.Wipe()
		}
		r.changed()
		return m, err
	}
	k := key(ref)
	if cur := r.entries[k]; cur != nil {
		r.retireReplacedLocked(cur, own)
	}
	if m.Ref.IsZero() {
		m.Ref = ref
	}
	r.entries[k] = &entry{meta: m, fields: own, verified: r.cfg.Now(), written: true}
	r.mu.Unlock()
	r.changed()
	return m, nil
}

// Close wipes every value held. The Refresher is unusable afterwards.
func (r *Refresher) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.entries {
		e.wipe()
	}
	clear(r.entries)
	for _, x := range r.retired {
		x.v.Wipe()
	}
	r.retired = nil
	for _, v := range r.creds {
		v.Wipe()
	}
	r.creds = nil
}

// Kick asks a running Run loop to refresh now.
func (r *Refresher) Kick() {
	select {
	case r.kick <- struct{}{}:
	default:
	}
}

func copyValue(v secret.Value) secret.Value {
	var out secret.Value
	_ = v.Expose(func(b []byte) error {
		out = secret.New(b)
		return nil
	})
	return out
}
