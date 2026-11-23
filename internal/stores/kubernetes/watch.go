// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/heliopsy/scrim/internal/stores"
)

// Watch backoff after a failed list or watch call.
const (
	watchMinBackoff = 500 * time.Millisecond
	watchMaxBackoff = 10 * time.Second
	// watchSeconds is roughly how long the API server keeps one watch open
	// before the adapter starts the next from the last resource version.
	watchSeconds = 300
)

// Watch implements stores.Adapter with the API server's own watch, on the
// metadata-only form of Secrets: events carry names and resource versions,
// never data. One watch runs per namespace the prefix covers.
//
// Each namespace starts with a list (its resource version and the baseline
// of what exists), then watches from that version. A watch the server ends
// is resumed from the last version seen, bookmarks included. When the
// version has expired (410 Gone) or a call fails, the namespace is listed
// again and the difference against what the adapter last knew is reported:
// a Secret created, changed or deleted while the watch was down is still
// reported once the API server is back. Failures back off up to
// watchMaxBackoff; the channel closes only when ctx ends.
//
// If the first list fails because the API server is unreachable, the watch
// starts anyway and reports every selected Secret as changed once it can
// list. Any other first failure (permission, invalid prefix) is returned.
func (a *Adapter) Watch(ctx context.Context, prefix stores.Ref) (<-chan stores.Change, error) {
	prefix = prefix.Secret()
	sel, err := a.selectionFor(stores.OpWatch, prefix)
	if err != nil {
		return nil, err
	}
	c, err := a.client(stores.OpWatch, prefix)
	if err != nil {
		return nil, err
	}
	ws := make([]*nsWatch, 0, len(sel.namespaces))
	for _, ns := range sel.namespaces {
		w := &nsWatch{a: a, c: c, ns: ns, sel: sel, scheme: prefix.Scheme}
		if err := w.list(ctx); err != nil {
			if !errors.Is(err, stores.ErrUnavailable) {
				var se *stores.Error
				if errors.As(err, &se) {
					se.Ref = prefix
				}
				return nil, err
			}
			w.known = nil
		}
		ws = append(ws, w)
	}
	ch := make(chan stores.Change, 64)
	var wg sync.WaitGroup
	for _, w := range ws {
		wg.Go(func() { w.run(ctx, ch) })
	}
	go func() {
		wg.Wait()
		close(ch)
	}()
	return ch, nil
}

// nsWatch follows one namespace.
type nsWatch struct {
	a      *Adapter
	c      *Clients
	ns     string
	sel    selection
	scheme string
	// known maps each selected Secret to its resource version; nil means
	// no baseline yet, so the next list reports everything.
	known map[string]string
	// rv is where the next watch starts.
	rv string
}

// listChanges lists the namespace's metadata and records the baseline, returning
// the changes since the previous baseline.
func (w *nsWatch) listChanges(ctx context.Context) ([]stores.Change, error) {
	cur := map[string]string{}
	opts := metav1.ListOptions{Limit: listPage}
	var rv string
	for {
		rctx, cancel := w.a.ctx(ctx)
		l, err := w.c.Meta.Resource(secretsGVR).Namespace(w.ns).List(rctx, opts)
		cancel()
		if err != nil {
			return nil, w.a.apiErr(stores.OpWatch, stores.Ref{Scheme: w.scheme, Path: w.ns}, err)
		}
		for _, it := range l.Items {
			if w.sel.match(it.Name) {
				cur[it.Name] = it.ResourceVersion
			}
		}
		if rv == "" {
			rv = l.ResourceVersion
		}
		if l.Continue == "" {
			break
		}
		opts.Continue = l.Continue
	}
	var out []stores.Change
	for n, v := range cur {
		if old, ok := w.known[n]; w.known == nil || !ok || old != v {
			out = append(out, w.change(n, stores.Changed))
		}
	}
	for n := range w.known {
		if _, ok := cur[n]; !ok {
			out = append(out, w.change(n, stores.Deleted))
		}
	}
	w.known, w.rv = cur, rv
	return out, nil
}

// list sets the baseline without reporting anything.
func (w *nsWatch) list(ctx context.Context) error {
	w.known = map[string]string{}
	_, err := w.listChanges(ctx)
	return err
}

func (w *nsWatch) change(name string, kind stores.ChangeKind) stores.Change {
	return stores.Change{Ref: stores.Ref{Scheme: w.scheme, Path: w.a.path(w.ns, name)}, Kind: kind}
}

func send(ctx context.Context, ch chan<- stores.Change, cs ...stores.Change) bool {
	for _, c := range cs {
		select {
		case ch <- c:
		case <-ctx.Done():
			return false
		}
	}
	return true
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// run lists when it has to and watches until ctx ends.
func (w *nsWatch) run(ctx context.Context, ch chan<- stores.Change) {
	backoff := watchMinBackoff
	relist := w.known == nil
	for ctx.Err() == nil {
		if relist {
			cs, err := w.listChanges(ctx)
			if err != nil {
				if !sleep(ctx, backoff) {
					return
				}
				backoff = min(backoff*2, watchMaxBackoff)
				continue
			}
			if !send(ctx, ch, cs...) {
				return
			}
		}
		start := time.Now()
		ok, resume := w.follow(ctx, ch)
		if !ok {
			return
		}
		relist = !resume
		if resume && time.Since(start) > time.Second {
			// A watch that ran a while and was closed by the server or
			// the connection: resume from the last version at once.
			backoff = watchMinBackoff
			continue
		}
		if !sleep(ctx, backoff) {
			return
		}
		backoff = min(backoff*2, watchMaxBackoff)
	}
}

// follow runs one watch from w.rv. It returns ok=false when ctx ended, and
// resume=true when the watch channel closed and the next watch can start
// from w.rv (if the API server is unreachable by then, that call fails and
// the caller relists). A failed call or an error event (410 Gone when w.rv
// has expired) returns resume=false: the caller lists again.
func (w *nsWatch) follow(ctx context.Context, ch chan<- stores.Change) (ok, resume bool) {
	timeout := int64(watchSeconds + rand.IntN(watchSeconds/5))
	wi, err := w.c.Meta.Resource(secretsGVR).Namespace(w.ns).Watch(ctx, metav1.ListOptions{
		ResourceVersion:     w.rv,
		AllowWatchBookmarks: true,
		TimeoutSeconds:      &timeout,
	})
	if err != nil {
		return ctx.Err() == nil, false
	}
	defer wi.Stop()
	for {
		select {
		case <-ctx.Done():
			return false, false
		case ev, open := <-wi.ResultChan():
			if !open {
				return ctx.Err() == nil, true
			}
			if ev.Type == watch.Error {
				return ctx.Err() == nil, false
			}
			m, isMeta := ev.Object.(*metav1.PartialObjectMetadata)
			if !isMeta {
				continue
			}
			if m.ResourceVersion != "" {
				w.rv = m.ResourceVersion
			}
			if ev.Type == watch.Bookmark || !w.sel.match(m.Name) {
				continue
			}
			var c stores.Change
			switch ev.Type {
			case watch.Added, watch.Modified:
				if w.known[m.Name] == m.ResourceVersion {
					continue
				}
				w.known[m.Name] = m.ResourceVersion
				c = w.change(m.Name, stores.Changed)
			case watch.Deleted:
				delete(w.known, m.Name)
				c = w.change(m.Name, stores.Deleted)
			default:
				continue
			}
			if !send(ctx, ch, c) {
				return false, false
			}
		}
	}
}
