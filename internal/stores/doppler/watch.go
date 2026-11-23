// SPDX-License-Identifier: AGPL-3.0-only

package doppler

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	mrand "math/rand/v2"
	"net/http"
	"net/url"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

// Watch implements stores.Adapter. Doppler's public API has no change feed
// (the CLI's server-sent event stream is undocumented), and no call returns a
// per-secret version without the value. The adapter polls the download
// endpoint every watch.interval (+-20% jitter) with the ETag of the previous
// answer: an unchanged config costs a 304 with no values in it. When the
// config changed, the values that arrive are fingerprinted with HMAC-SHA256
// under a random key that lives only in this watch, wiped at once, and the
// fingerprints are compared to tell which secrets changed. Errors back off
// exponentially up to watch.max-backoff; the channel stays open through an
// outage and closes only when ctx ends.
func (a *Adapter) Watch(ctx context.Context, prefix stores.Ref) (<-chan stores.Change, error) {
	m, ok := splitPrefix(prefix.Path)
	if !ok {
		return nil, a.refuse(stores.OpWatch, prefix, stores.ErrInvalidRef, prefixForm)
	}
	w := &watcher{a: a, m: m, scheme: prefix.Scheme, key: make([]byte, 32)}
	if _, err := rand.Read(w.key); err != nil {
		return nil, stores.NewError(a.name, stores.OpWatch, prefix, stores.ErrUnavailable, err)
	}
	// The baseline is taken before Watch returns, so a change made right
	// after the call is reported.
	base, err := w.snapshot(ctx, snapshot{})
	if err != nil && !errors.Is(err, stores.ErrUnavailable) {
		secret.WipeBytes(w.key)
		return nil, a.fail(stores.OpWatch, prefix, err)
	}
	ch := make(chan stores.Change, 64)
	go w.poll(ctx, base, err == nil, ch)
	return ch, nil
}

type watcher struct {
	a      *Adapter
	m      match
	scheme string
	key    []byte
}

// snapshot is one download's fingerprints by secret name, and its ETag.
type snapshot struct {
	etag   string
	prints map[string][sha256.Size]byte
}

// snapshot downloads the config, or reuses prev when Doppler says it has not
// changed since prev was taken.
func (w *watcher) snapshot(ctx context.Context, prev snapshot) (snapshot, error) {
	q := url.Values{
		"project":                 {w.m.project},
		"config":                  {w.m.config},
		"format":                  {"json"},
		"include_dynamic_secrets": {"false"},
	}
	var h http.Header
	if prev.etag != "" && prev.prints != nil {
		h = http.Header{"If-None-Match": {prev.etag}}
	}
	r, err := w.a.c.send(ctx, http.MethodGet, w.a.c.url("/v3/configs/config/secrets/download", q), nil, h)
	if err != nil {
		return snapshot{}, err
	}
	defer secret.WipeBytes(r.body)
	switch {
	case r.status == http.StatusNotModified && h != nil:
		return prev, nil
	case r.status < 200 || r.status >= 300:
		return snapshot{}, classify(r.status, r.body, nil)
	}
	var values map[string]wire.Raw
	err = json.Unmarshal(r.body, &values)
	defer func() {
		for _, v := range values {
			v.Wipe()
		}
	}()
	if err != nil {
		return snapshot{}, &apiError{kind: stores.ErrUnavailable, msg: "malformed download response"}
	}
	cur := snapshot{etag: r.header.Get("ETag"), prints: make(map[string][sha256.Size]byte, len(values))}
	for name, v := range values {
		mac := hmac.New(sha256.New, w.key)
		mac.Write(v)
		var sum [sha256.Size]byte
		copy(sum[:], mac.Sum(nil))
		cur.prints[name] = sum
	}
	return cur, nil
}

// watched reports whether a change to name is reported by this watch.
func (w *watcher) watched(name string) bool { return !managedNames[name] && w.m.matches(name) }

func jitter(d time.Duration) time.Duration {
	// Uniform in [0.8d, 1.2d).
	return time.Duration(float64(d) * (0.8 + 0.4*mrand.Float64()))
}

func (w *watcher) poll(ctx context.Context, prev snapshot, haveBase bool, ch chan<- stores.Change) {
	defer close(ch)
	defer secret.WipeBytes(w.key)
	interval, maxBackoff := w.a.s.watchInterval, w.a.s.watchBackoff
	backoff := time.Duration(0)
	for {
		wait := jitter(interval)
		if backoff > 0 {
			wait = jitter(backoff)
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		cur, err := w.snapshot(ctx, prev)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if backoff == 0 {
				backoff = interval
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}
		backoff = 0
		if !haveBase {
			// No baseline yet (Doppler was down when Watch started):
			// everything present is reported once as changed, so the
			// consumer reloads it.
			prev, haveBase = snapshot{prints: map[string][sha256.Size]byte{}}, true
		}
		for name, p := range cur.prints {
			if old, ok := prev.prints[name]; w.watched(name) && (!ok || old != p) {
				if !send(ctx, ch, stores.Change{Ref: w.m.ref(w.scheme, name), Kind: stores.Changed}) {
					return
				}
			}
		}
		for name := range prev.prints {
			if _, ok := cur.prints[name]; !ok && w.watched(name) {
				if !send(ctx, ch, stores.Change{Ref: w.m.ref(w.scheme, name), Kind: stores.Deleted}) {
					return
				}
			}
		}
		prev = cur
	}
}

func send(ctx context.Context, ch chan<- stores.Change, c stores.Change) bool {
	select {
	case ch <- c:
		return true
	case <-ctx.Done():
		return false
	}
}
