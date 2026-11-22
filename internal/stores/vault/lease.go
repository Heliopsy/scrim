// SPDX-License-Identifier: AGPL-3.0-only

package vault

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/vaultapi"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

// Dynamic secrets. Issue asks the engine for a new credential and keeps its
// lease for the holder (a grant): every leases.check-interval, and before
// each renewal, the holder is asked whether it is still active. While it
// is, the lease is renewed two thirds into its TTL, never past the time the
// holder said it ends; once it is not, or that time has passed, or Release
// names it, the lease is revoked. Because renewals stop at the holder's
// end, a credential whose revocation fails still expires then at the
// latest.

// Issue implements stores.DynamicIssuer. The reference names a path in a
// dynamic secrets engine (database/creds/<role>, aws/creds/<role>,
// pki/issue/<role>, ...). Selectors are sent as request parameters with a
// POST (pki/issue/web?common_name=app.example.com); without selectors the
// path is read with GET. A response without a lease is refused and its
// values wiped: scrim could not revoke that credential when the grant ends.
func (a *Adapter) Issue(ctx context.Context, ref stores.Ref, holder stores.LeaseHolder) (stores.Secret, stores.LeaseInfo, error) {
	const op = stores.OpRead
	if holder.ID == "" {
		return stores.Secret{}, stores.LeaseInfo{}, a.err(op, ref, stores.ErrInvalidRef, "a dynamic secret needs a lease holder")
	}
	loc := a.locate(ctx, ref, ref.Path)
	if loc.engine != dynamic {
		return stores.Secret{}, stores.LeaseInfo{}, a.err(op, ref, stores.ErrInvalidRef,
			"not a dynamic secrets path: list it in dynamic-paths or check that its mount is not KV")
	}
	if holder.Active != nil {
		_, active, err := holder.Active(ctx)
		if err != nil {
			return stores.Secret{}, stores.LeaseInfo{}, a.err(op, ref, stores.ErrUnavailable, "cannot check the lease holder "+holder.ID+": "+err.Error())
		}
		if !active {
			return stores.Secret{}, stores.LeaseInfo{}, a.err(op, ref, stores.ErrPermission, "lease holder "+holder.ID+" has ended")
		}
	}
	req := vaultapi.Request{Op: op, Ref: ref, Method: http.MethodGet, Path: vaultapi.EscapePath(ref.Path)}
	if ref.Selectors != "" {
		q, err := url.ParseQuery(ref.Selectors)
		if err != nil {
			return stores.Secret{}, stores.LeaseInfo{}, a.err(op, ref, stores.ErrInvalidRef, "selectors are not a valid query")
		}
		params := map[string]string{}
		for k := range q {
			params[k] = q.Get(k)
		}
		b, err := json.Marshal(params)
		if err != nil {
			return stores.Secret{}, stores.LeaseInfo{}, a.err(op, ref, stores.ErrInvalidRef, "selectors cannot be encoded")
		}
		req.Method, req.Body = http.MethodPost, wire.NewBody(b)
	}
	start := a.c.Now()
	resp, err := a.c.Do(ctx, req)
	defer resp.Wipe()
	if err != nil {
		return stores.Secret{}, stores.LeaseInfo{}, err
	}
	var ir struct {
		LeaseID       string              `json:"lease_id"`
		LeaseDuration int64               `json:"lease_duration"`
		Renewable     bool                `json:"renewable"`
		Data          map[string]wire.Raw `json:"data"`
	}
	if err := json.Unmarshal(resp.Body, &ir); err != nil {
		wipeRaw(ir.Data)
		return stores.Secret{}, stores.LeaseInfo{}, a.err(op, ref, stores.ErrUnavailable, "malformed response")
	}
	defer wipeRaw(ir.Data)
	if ir.LeaseID == "" {
		return stores.Secret{}, stores.LeaseInfo{}, a.err(op, ref, stores.ErrUnsupported,
			"the engine issued this secret without a lease, so scrim could not revoke it when the grant ends; "+
				"configure the role to lease its secrets (pki: generate_lease=true)")
	}
	ttl := time.Duration(ir.LeaseDuration) * time.Second
	info := stores.LeaseInfo{
		ID: ir.LeaseID, Ref: ref.Secret(), Holder: holder.ID, Issued: start,
		Expires: start.Add(ttl), Renewable: ir.Renewable,
	}
	meta := stores.Metadata{Ref: ref.Secret(), CreatedAt: start, UpdatedAt: start, Labels: a.dynamicLabels(ctx, ref, loc, info, ttl)}
	s, err := a.secretFrom(op, ref, meta, ir.Data)
	if err != nil {
		_ = a.revoke(info)
		return stores.Secret{}, stores.LeaseInfo{}, err
	}
	if err := a.leases.hold(info, holder, ttl); err != nil {
		s.Wipe()
		_ = a.revoke(info)
		return stores.Secret{}, stores.LeaseInfo{}, a.err(op, ref, stores.ErrUnavailable, err.Error())
	}
	return s, info, nil
}

// dynamicLabels are the labels of an issued secret: the reference, the
// namespace, the mount and the lease (never the lease's secret).
func (a *Adapter) dynamicLabels(ctx context.Context, ref stores.Ref, loc location, info stores.LeaseInfo, ttl time.Duration) map[string]string {
	l := map[string]string{}
	set := func(attr string, v ...string) { stores.SetNative(l, Kind, attr, v...) }
	set("mount", loc.mount)
	set("engine", "dynamic")
	if ns := a.opts.Namespace; ns != "" {
		set("namespace", ns)
		set("namespaces", append(vaultapi.Ancestors(ns), ns)...)
	}
	if loc.rest != "" {
		vaultapi.PathLabels(l, Kind, loc.rest)
	}
	if mi := a.mountInfo(ctx, ref, loc); mi != nil {
		vaultapi.MountLabels(l, Kind, mi)
	}
	set("dynamic", "true")
	set("lease_duration", strconv.FormatInt(int64(ttl/time.Second), 10))
	set("lease_renewable", strconv.FormatBool(info.Renewable))
	set("lease_holder", info.Holder)
	return l
}

// Release implements stores.DynamicIssuer.
func (a *Adapter) Release(_ context.Context, holderID string) error {
	var errs []error
	for _, h := range a.leases.take(func(h *held) bool { return h.info.Holder == holderID }) {
		if err := a.revoke(h.info); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Leases implements stores.DynamicIssuer.
func (a *Adapter) Leases() []stores.LeaseInfo {
	a.leases.mu.Lock()
	defer a.leases.mu.Unlock()
	out := make([]stores.LeaseInfo, 0, len(a.leases.m))
	for _, h := range a.leases.m {
		out = append(out, h.snapshot())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// revoke revokes one lease within leases.revoke-timeout, logging a failure
// (the lease ID, never a value). Renewals already stop at the holder's end,
// so a lease whose revocation failed lapses then at the latest.
func (a *Adapter) revoke(info stores.LeaseInfo) error {
	ctx, cancel := context.WithTimeout(context.Background(), a.opts.RevokeTimeout)
	defer cancel()
	err := a.c.RevokeLease(ctx, stores.OpRead, info.Ref, info.ID)
	if err != nil {
		a.c.Log.Warn("Vault lease revocation failed; it lapses at its expiry",
			"store", a.c.Name(), "lease_id", info.ID, "holder", info.Holder, "error", err)
	}
	return err
}

// leaseManager holds the leases of issued secrets.
type leaseManager struct {
	a      *Adapter
	mu     sync.Mutex
	m      map[string]*held
	closed bool
	wg     sync.WaitGroup
}

// held is one lease and its renewal loop.
type held struct {
	info   stores.LeaseInfo
	holder stores.LeaseHolder
	ttl    time.Duration
	// until is the latest end the holder reported; zero means unknown.
	until  time.Time
	stop   chan struct{}
	stopMu sync.Once
	mu     sync.Mutex
}

func (h *held) snapshot() stores.LeaseInfo {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.info
}

func (h *held) halt() { h.stopMu.Do(func() { close(h.stop) }) }

func (l *leaseManager) init(a *Adapter) {
	l.a = a
	l.m = map[string]*held{}
}

var errClosed = errors.New("adapter closed")

// hold starts keeping info's lease for holder.
func (l *leaseManager) hold(info stores.LeaseInfo, holder stores.LeaseHolder, ttl time.Duration) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errClosed
	}
	h := &held{info: info, holder: holder, ttl: ttl, stop: make(chan struct{})}
	if old, ok := l.m[info.ID]; ok {
		// Lease IDs are unique; a store that repeats one gets the old loop
		// stopped rather than orphaned.
		old.halt()
	}
	l.m[info.ID] = h
	l.wg.Add(1)
	go l.run(h)
	return nil
}

// take removes and stops the leases that match, returning them.
func (l *leaseManager) take(match func(*held) bool) []*held {
	l.mu.Lock()
	var out []*held
	for id, h := range l.m {
		if match(h) {
			delete(l.m, id)
			out = append(out, h)
		}
	}
	l.mu.Unlock()
	for _, h := range out {
		h.halt()
	}
	return out
}

// drop forgets h without revoking it (the store already dropped it).
func (l *leaseManager) drop(h *held) {
	l.mu.Lock()
	if l.m[h.info.ID] == h {
		delete(l.m, h.info.ID)
	}
	l.mu.Unlock()
}

// end revokes h and forgets it, unless Release or Close took it first.
func (l *leaseManager) end(h *held) {
	l.mu.Lock()
	mine := l.m[h.info.ID] == h
	if mine {
		delete(l.m, h.info.ID)
	}
	l.mu.Unlock()
	if mine {
		_ = l.a.revoke(h.snapshot())
	}
}

func (l *leaseManager) close() {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	all := l.take(func(*held) bool { return true })
	if l.a.opts.RevokeOnClose {
		var wg sync.WaitGroup
		for _, h := range all {
			wg.Go(func() { _ = l.a.revoke(h.snapshot()) })
		}
		wg.Wait()
	}
	l.wg.Wait()
}

// run keeps h until its holder ends, then revokes it.
func (l *leaseManager) run(h *held) {
	defer l.wg.Done()
	a := l.a
	now := a.c.Now()
	h.mu.Lock()
	renewAt := now.Add(h.ttl * 2 / 3)
	expires := h.info.Expires
	h.mu.Unlock()
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		now = a.c.Now()
		next := now.Add(a.opts.LeaseCheck)
		for _, t := range []time.Time{renewAt, h.until, expires} {
			if !t.IsZero() && t.Before(next) {
				next = t
			}
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(max(next.Sub(now), 10*time.Millisecond))
		select {
		case <-h.stop:
			return
		case <-timer.C:
		}
		now = a.c.Now()
		if h.holder.Active != nil {
			ctx, cancel := context.WithTimeout(context.Background(), a.opts.Timeout)
			until, active, err := h.holder.Active(ctx)
			cancel()
			switch {
			case err != nil:
				// Not an answer: keep the lease until the last known end,
				// without renewing past it, and ask again.
			case !active:
				l.end(h)
				return
			default:
				h.until = until
			}
		}
		if !h.until.IsZero() && !now.Before(h.until) {
			l.end(h)
			return
		}
		if !expires.IsZero() && !now.Before(expires) {
			// The store has dropped it already.
			l.drop(h)
			return
		}
		if now.Before(renewAt) {
			continue
		}
		h.mu.Lock()
		renewable := h.info.Renewable
		h.mu.Unlock()
		if !renewable {
			renewAt = expires
			continue
		}
		inc := a.opts.LeaseIncrement
		if inc == 0 {
			inc = h.ttl
		}
		if !h.until.IsZero() {
			inc = min(inc, h.until.Sub(now))
		}
		inc = max(inc.Round(time.Second), time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), a.opts.Timeout)
		ttl, again, err := a.c.RenewLease(ctx, stores.OpRead, h.info.Ref, h.info.ID, inc)
		cancel()
		if err != nil {
			if errors.Is(err, stores.ErrNotFound) || errors.Is(err, stores.ErrInvalidRef) {
				// Expired or revoked in the store.
				l.drop(h)
				return
			}
			a.c.Log.Warn("Vault lease renewal failed; retrying", "store", a.c.Name(), "lease_id", h.info.ID, "error", err)
			renewAt = now.Add(a.opts.LeaseCheck)
			continue
		}
		expires = now.Add(ttl)
		renewAt = now.Add(ttl * 2 / 3)
		h.mu.Lock()
		h.info.Expires = expires
		// A renewal shorter than asked for hit the lease's max TTL: the
		// credential ends then, whatever the holder.
		h.info.Renewable = again && ttl >= inc
		h.mu.Unlock()
	}
}
