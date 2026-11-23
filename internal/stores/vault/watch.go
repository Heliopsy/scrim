// SPDX-License-Identifier: AGPL-3.0-only

package vault

import (
	"context"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/rand/v2"
	"sort"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/stores"
)

// defaultJitter spreads d by up to 20% either way, so replicas and stores
// polling on the same interval drift apart (specs/secret-stores, "Refreshes
// are spread out").
func defaultJitter(d time.Duration) time.Duration {
	spread := int64(d) / 5
	if spread <= 0 {
		return d
	}
	return d - time.Duration(spread) + time.Duration(rand.Int64N(2*spread+1))
}

func newDigestKey(k *[32]byte) {
	_, _ = crand.Read(k[:])
}

// digest is a keyed hash of a secret's fields, so a KV v1 change can be
// seen without keeping a value. The key is random per adapter and never
// leaves memory.
func (a *Adapter) digest(s stores.Secret) string {
	h := hmac.New(sha256.New, a.digestKey[:])
	names := make([]string, 0, len(s.Fields))
	for n := range s.Fields {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		h.Write([]byte(n))
		h.Write([]byte{0})
		_ = s.Fields[n].Expose(func(b []byte) error { h.Write(b); return nil })
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// snapshot maps each live secret path under prefix to its current version
// (KV v2) or a digest of its fields (KV v1, which keeps no versions: each
// poll reads every secret under the prefix).
func (a *Adapter) snapshot(ctx context.Context, prefix stores.Ref) (map[string]string, error) {
	ms, err := a.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(ms))
	for _, m := range ms {
		if m.Version != "" || m.WriteOnly || m.Labels[Kind+".engine"] != "kv-v1" {
			out[m.Ref.Path] = m.Version
			continue
		}
		s, err := a.Read(ctx, m.Ref)
		if errors.Is(err, stores.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out[m.Ref.Path] = a.digest(s)
		s.Wipe()
	}
	return out, nil
}

// Watch implements stores.Adapter by polling under prefix every
// watch.interval (with jitter). A poll that fails backs off exponentially
// up to watch.max-backoff and the watch carries on; it never closes because
// of a store error, only when ctx ends. Changes carry no value: the caller
// reads the secret again.
//
// The first snapshot is the baseline and reports nothing. If the store is
// unreachable when the watch starts, the first successful poll reports every
// secret as changed, so nothing is missed.
func (a *Adapter) Watch(ctx context.Context, prefix stores.Ref) (<-chan stores.Change, error) {
	prefix = prefix.Secret()
	prefix.Path = strings.TrimSuffix(strings.TrimSuffix(prefix.Path, "*"), "/")
	if prefix.Selectors != "" {
		return nil, a.err(stores.OpWatch, prefix, stores.ErrInvalidRef, "selectors do not apply to a watch")
	}
	base, err := a.snapshot(ctx, prefix)
	if err != nil && !errors.Is(err, stores.ErrUnavailable) {
		var se *stores.Error
		if errors.As(err, &se) {
			se.Op = stores.OpWatch
		}
		return nil, err
	}
	ch := make(chan stores.Change, 64)
	go a.poll(ctx, prefix, base, ch)
	return ch, nil
}

func (a *Adapter) poll(ctx context.Context, prefix stores.Ref, prev map[string]string, ch chan<- stores.Change) {
	defer close(ch)
	interval, maxBackoff := a.opts.WatchInterval, a.opts.WatchMaxBackoff
	wait := interval
	timer := time.NewTimer(a.jitter(wait))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		cur, err := a.snapshot(ctx, prefix)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			wait = min(wait*2, maxBackoff)
			timer.Reset(a.jitter(wait))
			continue
		}
		wait = interval
		if !emit(ctx, ch, prefix, prev, cur) {
			return
		}
		prev = cur
		timer.Reset(a.jitter(wait))
	}
}

// emit sends the differences between prev and cur. A nil prev (no baseline)
// reports everything in cur as changed. It returns false if ctx ended.
func emit(ctx context.Context, ch chan<- stores.Change, prefix stores.Ref, prev, cur map[string]string) bool {
	send := func(c stores.Change) bool {
		select {
		case ch <- c:
			return true
		case <-ctx.Done():
			return false
		}
	}
	for p, v := range cur {
		if old, ok := prev[p]; prev == nil || !ok || old != v {
			if !send(stores.Change{Ref: stores.Ref{Scheme: prefix.Scheme, Path: p}, Kind: stores.Changed}) {
				return false
			}
		}
	}
	for p := range prev {
		if _, ok := cur[p]; !ok {
			if !send(stores.Change{Ref: stores.Ref{Scheme: prefix.Scheme, Path: p}, Kind: stores.Deleted}) {
				return false
			}
		}
	}
	return true
}
