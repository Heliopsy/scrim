// SPDX-License-Identifier: AGPL-3.0-only

package storetest_test

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/memstore"
	"github.com/heliopsy/scrim/internal/stores/storetest"
)

// memHarness is the reference harness: the memory store with every
// optional behaviour the suite can check out of band.
func memHarness(wrap func(*memstore.Store) stores.Adapter) storetest.Factory {
	return func(t storetest.TB) storetest.Harness {
		s := memstore.New("mem")
		var a stores.Adapter = s
		if wrap != nil {
			a = wrap(s)
		}
		return storetest.Harness{
			Adapter: a,
			Seed: func(_ storetest.TB, ref stores.Ref, fields map[string]secret.Value) {
				s.Seed(ref, fields)
			},
			Delete: func(_ storetest.TB, ref stores.Ref) { s.Delete(ref) },
			Outage: func(storetest.TB) func() {
				s.SetDown(true)
				return func() { s.SetDown(false) }
			},
			Labels:       true,
			WatchTimeout: 2 * time.Second,
		}
	}
}

func TestMemstorePasses(t *testing.T) {
	storetest.Run(t, memHarness(nil))
}

func TestReadOnlyMemstorePasses(t *testing.T) {
	storetest.Run(t, func(t storetest.TB) storetest.Harness {
		s := memstore.New("ro", memstore.WithCapabilities(stores.CapRead|stores.CapList))
		return storetest.Harness{
			Adapter:     s,
			SingleField: "value",
			Seed: func(_ storetest.TB, ref stores.Ref, fields map[string]secret.Value) {
				s.Seed(ref, fields)
			},
		}
	})
}

// recorder is a storetest.TB that records failures instead of failing the
// real test, so a broken adapter's failure can be asserted.
type recorder struct {
	ctx      context.Context
	mu       sync.Mutex
	failures []string
	cleanups []func()
}

func (r *recorder) Helper()                  {}
func (r *recorder) Logf(string, ...any)      {}
func (r *recorder) Context() context.Context { return r.ctx }
func (r *recorder) Cleanup(f func()) {
	r.mu.Lock()
	r.cleanups = append(r.cleanups, f)
	r.mu.Unlock()
}

func (r *recorder) Errorf(format string, args ...any) {
	r.mu.Lock()
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
	r.mu.Unlock()
}

func (r *recorder) Fatalf(format string, args ...any) {
	r.Errorf(format, args...)
	runtime.Goexit()
}

// run executes one case against f and returns what it reported.
func run(t *testing.T, f storetest.Factory, name string) []string {
	t.Helper()
	var c storetest.Case
	for _, x := range storetest.Cases() {
		if x.Name == name {
			c = x
		}
	}
	if c.Run == nil {
		t.Fatalf("no case %s", name)
	}
	ctx, cancel := context.WithCancel(t.Context())
	r := &recorder{ctx: ctx}
	done := make(chan struct{})
	go func() {
		defer close(done)
		storetest.Check(r, f, c)
	}()
	<-done
	cancel()
	for i := len(r.cleanups) - 1; i >= 0; i-- {
		r.cleanups[i]()
	}
	return r.failures
}

// broken wraps the memory store and overrides one behaviour.
type broken struct {
	*memstore.Store
	caps  stores.Capabilities
	read  func(ctx context.Context, ref stores.Ref) (stores.Secret, error)
	write func(ctx context.Context, ref stores.Ref, f map[string]secret.Value, o stores.WriteOptions) (stores.Metadata, error)
	list  func(ctx context.Context, prefix stores.Ref) ([]stores.Metadata, error)
	watch func(ctx context.Context, prefix stores.Ref) (<-chan stores.Change, error)
}

func (b *broken) Capabilities() stores.Capabilities {
	if b.caps != 0 {
		return b.caps
	}
	return b.Store.Capabilities()
}

func (b *broken) Read(ctx context.Context, ref stores.Ref) (stores.Secret, error) {
	if b.read != nil {
		return b.read(ctx, ref)
	}
	return b.Store.Read(ctx, ref)
}

func (b *broken) Write(ctx context.Context, ref stores.Ref, f map[string]secret.Value, o stores.WriteOptions) (stores.Metadata, error) {
	if b.write != nil {
		return b.write(ctx, ref, f, o)
	}
	return b.Store.Write(ctx, ref, f, o)
}

func (b *broken) List(ctx context.Context, prefix stores.Ref) ([]stores.Metadata, error) {
	if b.list != nil {
		return b.list(ctx, prefix)
	}
	return b.Store.List(ctx, prefix)
}

func (b *broken) Watch(ctx context.Context, prefix stores.Ref) (<-chan stores.Change, error) {
	if b.watch != nil {
		return b.watch(ctx, prefix)
	}
	return b.Store.Watch(ctx, prefix)
}

func plainOf(v secret.Value) string {
	var s string
	_ = v.Expose(func(b []byte) error { s = string(b); return nil })
	return s
}

// TestSuiteCatchesBrokenAdapters runs each case against an adapter broken
// in the way that case exists to catch, and requires the case to fail.
func TestSuiteCatchesBrokenAdapters(t *testing.T) {
	tests := []struct {
		name string
		kase string
		wrap func(s *memstore.Store) stores.Adapter
	}{
		{"value leaked into a not-found error", "ReadField", func(s *memstore.Store) stores.Adapter {
			b := &broken{Store: s}
			b.read = func(ctx context.Context, ref stores.Ref) (stores.Secret, error) {
				if ref.Field == "absent" {
					whole, _ := s.Read(ctx, ref.Secret())
					defer whole.Wipe()
					var vals []string
					for _, v := range whole.Fields {
						vals = append(vals, plainOf(v))
					}
					e := stores.NewError(s.Name(), stores.OpRead, ref, stores.ErrNotFound, nil)
					e.Detail = "fields present: " + strings.Join(vals, ",")
					return stores.Secret{}, e
				}
				return s.Read(ctx, ref)
			}
			return b
		}},
		{"value leaked only through the error cause", "ReadField", func(s *memstore.Store) stores.Adapter {
			b := &broken{Store: s}
			b.read = func(ctx context.Context, ref stores.Ref) (stores.Secret, error) {
				if ref.Field == "absent" {
					whole, _ := s.Read(ctx, ref.Secret())
					defer whole.Wipe()
					v, _ := whole.Field("token")
					cause := errors.New("store said: no field, but token is " + plainOf(v))
					return stores.Secret{}, stores.NewError(s.Name(), stores.OpRead, ref, stores.ErrNotFound, cause)
				}
				return s.Read(ctx, ref)
			}
			return b
		}},
		{"store echoes the written value in its error", "WriteCreateOnly", func(s *memstore.Store) stores.Adapter {
			b := &broken{Store: s}
			b.write = func(ctx context.Context, ref stores.Ref, f map[string]secret.Value, o stores.WriteOptions) (stores.Metadata, error) {
				m, err := s.Write(ctx, ref, f, o)
				if err != nil {
					return m, fmt.Errorf("rejected body {\"value\":%q}: %w", plainOf(f["value"]), err)
				}
				return m, nil
			}
			return b
		}},
		{"field selector ignored", "ReadField", func(s *memstore.Store) stores.Adapter {
			b := &broken{Store: s}
			b.read = func(ctx context.Context, ref stores.Ref) (stores.Secret, error) {
				return s.Read(ctx, ref.Secret())
			}
			return b
		}},
		{"missing secret reported as an outage", "ReadMissing", func(s *memstore.Store) stores.Adapter {
			b := &broken{Store: s}
			b.read = func(ctx context.Context, ref stores.Ref) (stores.Secret, error) {
				sec, err := s.Read(ctx, ref)
				if errors.Is(err, stores.ErrNotFound) {
					return sec, stores.NewError(s.Name(), stores.OpRead, ref, stores.ErrUnavailable, nil)
				}
				return sec, err
			}
			return b
		}},
		{"plain error instead of stores.Error", "ReadMissing", func(s *memstore.Store) stores.Adapter {
			b := &broken{Store: s}
			b.read = func(ctx context.Context, ref stores.Ref) (stores.Secret, error) {
				sec, err := s.Read(ctx, ref)
				if err != nil {
					return sec, fmt.Errorf("oops: %w", stores.ErrNotFound)
				}
				return sec, nil
			}
			return b
		}},
		{"unknown selector ignored", "ReadUnknownSelector", func(s *memstore.Store) stores.Adapter {
			b := &broken{Store: s}
			b.read = func(ctx context.Context, ref stores.Ref) (stores.Secret, error) {
				ref.Selectors = ""
				return s.Read(ctx, ref)
			}
			return b
		}},
		{"values trimmed on read", "ValueFidelity", func(s *memstore.Store) stores.Adapter {
			b := &broken{Store: s}
			b.read = func(ctx context.Context, ref stores.Ref) (stores.Secret, error) {
				sec, err := s.Read(ctx, ref)
				for k, v := range sec.Fields {
					sec.Fields[k] = secret.FromString(strings.TrimSpace(plainOf(v)))
					v.Wipe()
				}
				return sec, err
			}
			return b
		}},
		{"read-only store accepts writes", "UnsupportedRefused", func(s *memstore.Store) stores.Adapter {
			return &broken{Store: s, caps: stores.CapRead | stores.CapList | stores.CapWatch}
		}},
		{"list leaks a value into labels", "List", func(s *memstore.Store) stores.Adapter {
			b := &broken{Store: s}
			b.list = func(ctx context.Context, prefix stores.Ref) ([]stores.Metadata, error) {
				ms, err := s.List(ctx, prefix)
				for i := range ms {
					sec, _ := s.Read(ctx, ms[i].Ref)
					ms[i].Labels = map[string]string{}
					for k, v := range sec.Fields {
						ms[i].Labels[k] = plainOf(v)
					}
					sec.Wipe()
				}
				return ms, err
			}
			return b
		}},
		{"list ignores the prefix boundary", "List", func(s *memstore.Store) stores.Adapter {
			b := &broken{Store: s}
			b.list = func(ctx context.Context, prefix stores.Ref) ([]stores.Metadata, error) {
				all, err := s.List(ctx, stores.Ref{Scheme: prefix.Scheme, Path: ""})
				var out []stores.Metadata
				for _, m := range all {
					if strings.HasPrefix(m.Ref.Path, prefix.Path) {
						out = append(out, m)
					}
				}
				return out, err
			}
			return b
		}},
		{"write wipes the caller's value", "WriteRoundTrip", func(s *memstore.Store) stores.Adapter {
			b := &broken{Store: s}
			b.write = func(ctx context.Context, ref stores.Ref, f map[string]secret.Value, o stores.WriteOptions) (stores.Metadata, error) {
				m, err := s.Write(ctx, ref, f, o)
				for _, v := range f {
					v.Wipe()
				}
				return m, err
			}
			return b
		}},
		{"second write silently dropped", "WriteRoundTrip", func(s *memstore.Store) stores.Adapter {
			b := &broken{Store: s}
			b.write = func(ctx context.Context, ref stores.Ref, f map[string]secret.Value, o stores.WriteOptions) (stores.Metadata, error) {
				if sec, err := s.Read(ctx, ref.Secret()); err == nil {
					sec.Wipe()
					return sec.Meta, nil
				}
				return s.Write(ctx, ref, f, o)
			}
			return b
		}},
		{"create-only ignored", "WriteCreateOnly", func(s *memstore.Store) stores.Adapter {
			b := &broken{Store: s}
			b.write = func(ctx context.Context, ref stores.Ref, f map[string]secret.Value, o stores.WriteOptions) (stores.Metadata, error) {
				o.CreateOnly = false
				return s.Write(ctx, ref, f, o)
			}
			return b
		}},
		{"labels dropped", "WriteLabels", func(s *memstore.Store) stores.Adapter {
			b := &broken{Store: s}
			b.write = func(ctx context.Context, ref stores.Ref, f map[string]secret.Value, o stores.WriteOptions) (stores.Metadata, error) {
				o.Labels = nil
				return s.Write(ctx, ref, f, o)
			}
			return b
		}},
		{"watch never closes", "Watch", func(s *memstore.Store) stores.Adapter {
			b := &broken{Store: s}
			b.watch = func(ctx context.Context, prefix stores.Ref) (<-chan stores.Change, error) {
				in, err := s.Watch(context.Background(), prefix)
				if err != nil {
					return nil, err
				}
				out := make(chan stores.Change, 16)
				go func() {
					for c := range in {
						out <- c
					}
				}()
				return out, nil
			}
			return b
		}},
		{"watch reports nothing", "Watch", func(s *memstore.Store) stores.Adapter {
			b := &broken{Store: s}
			b.watch = func(ctx context.Context, _ stores.Ref) (<-chan stores.Change, error) {
				out := make(chan stores.Change)
				go func() { <-ctx.Done(); close(out) }()
				return out, nil
			}
			return b
		}},
		{"deletion not reported", "WatchDelete", func(s *memstore.Store) stores.Adapter {
			b := &broken{Store: s}
			b.watch = func(ctx context.Context, prefix stores.Ref) (<-chan stores.Change, error) {
				in, err := s.Watch(ctx, prefix)
				if err != nil {
					return nil, err
				}
				out := make(chan stores.Change, 16)
				go func() {
					defer close(out)
					for c := range in {
						if c.Kind != stores.Deleted {
							out <- c
						}
					}
				}()
				return out, nil
			}
			return b
		}},
		{"outage served from a stale copy", "Outage", func(s *memstore.Store) stores.Adapter {
			b := &broken{Store: s}
			var mu sync.Mutex
			cache := map[string]stores.Secret{}
			b.read = func(ctx context.Context, ref stores.Ref) (stores.Secret, error) {
				sec, err := s.Read(ctx, ref)
				mu.Lock()
				defer mu.Unlock()
				if err == nil {
					cache[ref.String()] = stores.Secret{Meta: sec.Meta, Fields: maps.Clone(sec.Fields)}
					return sec, nil
				}
				if c, ok := cache[ref.String()]; ok && errors.Is(err, stores.ErrUnavailable) {
					return c, nil
				}
				return sec, err
			}
			return b
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			failures := run(t, memHarness(tc.wrap), tc.kase)
			if len(failures) == 0 {
				t.Fatalf("case %s passed against an adapter with %q", tc.kase, tc.name)
			}
			t.Logf("case %s caught it: %s", tc.kase, failures[0])
		})
	}
}

// TestCleanAdapterPassesEveryCaseInRecorder makes sure the recorder itself
// does not report failures for a correct adapter, so the broken-adapter
// results above mean something.
func TestCleanAdapterPassesEveryCaseInRecorder(t *testing.T) {
	for _, c := range storetest.Cases() {
		if failures := run(t, memHarness(nil), c.Name); len(failures) > 0 {
			t.Errorf("case %s failed on the memory store: %v", c.Name, failures)
		}
	}
}

// TestUnstorableMustBeRefused: a store that silently changes a value it
// cannot hold fails ValueFidelity even when the harness declares it.
func TestUnstorableMustBeRefused(t *testing.T) {
	trims := func(p string) bool { return strings.TrimSpace(p) != p }
	f := func(tb storetest.TB) storetest.Harness {
		h := memHarness(func(s *memstore.Store) stores.Adapter {
			b := &broken{Store: s}
			b.write = func(ctx context.Context, ref stores.Ref, f map[string]secret.Value, o stores.WriteOptions) (stores.Metadata, error) {
				out := map[string]secret.Value{}
				for k, v := range f {
					out[k] = secret.FromString(strings.TrimSpace(plainOf(v)))
				}
				return s.Write(ctx, ref, out, o)
			}
			return b
		})(tb)
		h.Seed = nil
		h.Unstorable = trims
		return h
	}
	if failures := run(t, f, "ValueFidelity"); len(failures) == 0 {
		t.Fatal("ValueFidelity passed against a store that trims unstorable values")
	}
}
