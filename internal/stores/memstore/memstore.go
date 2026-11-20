// SPDX-License-Identifier: AGPL-3.0-only

// Package memstore is an in-memory store adapter. It backs tests, the
// conformance suite's reference run and throwaway local sessions. Values
// live only in process memory and are wiped when replaced or on Close.
package memstore

import (
	"context"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// Kind is the adapter kind this package registers.
const Kind = "memory"

func init() {
	stores.Register(Kind, func(_ context.Context, inst stores.Instance) (stores.Adapter, error) {
		return New(inst.Name), nil
	})
}

type entry struct {
	meta   stores.Metadata
	fields map[string]secret.Value
}

// Store is the in-memory adapter.
type Store struct {
	name string
	caps stores.Capabilities
	now  func() time.Time

	mu       sync.RWMutex
	data     map[string]*entry // by path
	watchers map[chan stores.Change]stores.Ref
	down     bool
	closed   bool
}

// Option configures a Store.
type Option func(*Store)

// WithCapabilities overrides the declared capabilities, to exercise
// read-only sources and the unsupported-operation path.
func WithCapabilities(c stores.Capabilities) Option { return func(s *Store) { s.caps = c } }

// WithClock sets the time source for metadata timestamps.
func WithClock(now func() time.Time) Option { return func(s *Store) { s.now = now } }

// New returns an empty store named name, supporting read, list, watch and
// write.
func New(name string, opts ...Option) *Store {
	s := &Store{
		name:     name,
		caps:     stores.CapRead | stores.CapList | stores.CapWatch | stores.CapWrite,
		now:      time.Now,
		data:     map[string]*entry{},
		watchers: map[chan stores.Change]stores.Ref{},
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Name implements stores.Adapter.
func (s *Store) Name() string { return s.name }

// Capabilities implements stores.Adapter.
func (s *Store) Capabilities() stores.Capabilities { return s.caps }

// SetDown simulates an outage: every operation fails with
// stores.ErrUnavailable until SetDown(false).
func (s *Store) SetDown(down bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.down = down
}

func (s *Store) fail(op stores.Op, ref stores.Ref, c stores.Capability) error {
	if s.closed {
		return stores.NewError(s.name, op, ref, stores.ErrUnavailable, nil)
	}
	if c != 0 && !s.caps.Has(c) {
		return stores.NewError(s.name, op, ref, stores.ErrUnsupported, nil)
	}
	if s.down {
		return stores.NewError(s.name, op, ref, stores.ErrUnavailable, nil)
	}
	return nil
}

// Read implements stores.Adapter.
func (s *Store) Read(_ context.Context, ref stores.Ref) (stores.Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.fail(stores.OpRead, ref, stores.CapRead); err != nil {
		return stores.Secret{}, err
	}
	if ref.Selectors != "" {
		// The memory store keeps one version; a selector it cannot honour
		// is refused rather than ignored.
		return stores.Secret{}, stores.NewError(s.name, stores.OpRead, ref, stores.ErrInvalidRef, nil)
	}
	e, ok := s.data[ref.Path]
	if !ok {
		return stores.Secret{}, stores.NewError(s.name, stores.OpRead, ref, stores.ErrNotFound, nil)
	}
	out := stores.Secret{Meta: cloneMeta(e.meta, ref.Secret()), Fields: map[string]secret.Value{}}
	for name, v := range e.fields {
		if ref.Field != "" && name != ref.Field {
			continue
		}
		out.Fields[name] = copyValue(v)
	}
	if ref.Field != "" && len(out.Fields) == 0 {
		return stores.Secret{}, stores.NewError(s.name, stores.OpRead, ref, stores.ErrNotFound, nil)
	}
	return out, nil
}

// List implements stores.Adapter.
func (s *Store) List(_ context.Context, prefix stores.Ref) ([]stores.Metadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.fail(stores.OpList, prefix, stores.CapList); err != nil {
		return nil, err
	}
	var out []stores.Metadata
	for _, path := range slices.Sorted(maps.Keys(s.data)) {
		if under(path, prefix.Path) {
			ref := stores.Ref{Scheme: prefix.Scheme, Path: path}
			out = append(out, cloneMeta(s.data[path].meta, ref))
		}
	}
	return out, nil
}

// Watch implements stores.Adapter.
func (s *Store) Watch(ctx context.Context, prefix stores.Ref) (<-chan stores.Change, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.fail(stores.OpWatch, prefix, stores.CapWatch); err != nil {
		return nil, err
	}
	ch := make(chan stores.Change, 16)
	s.watchers[ch] = prefix
	go func() {
		<-ctx.Done()
		s.mu.Lock()
		defer s.mu.Unlock()
		if _, ok := s.watchers[ch]; ok {
			delete(s.watchers, ch)
			close(ch)
		}
	}()
	return ch, nil
}

// Write implements stores.Adapter.
func (s *Store) Write(_ context.Context, ref stores.Ref, fields map[string]secret.Value, opts stores.WriteOptions) (stores.Metadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ref = ref.Secret()
	if err := s.fail(stores.OpWrite, ref, stores.CapWrite); err != nil {
		return stores.Metadata{}, err
	}
	return s.put(ref, fields, opts)
}

// Seed stores fields at ref regardless of declared capabilities, so tests
// can populate a read-only store. It is not part of stores.Adapter.
func (s *Store) Seed(ref stores.Ref, fields map[string]secret.Value) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.put(ref.Secret(), fields, stores.WriteOptions{})
}

// Delete removes the secret at ref, notifying watchers. It is not part of
// stores.Adapter: scrim never deletes from a store.
func (s *Store) Delete(ref stores.Ref) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.data[ref.Path]; ok {
		wipe(e.fields)
		delete(s.data, ref.Path)
		s.notify(stores.Change{Ref: ref.Secret(), Kind: stores.Deleted})
	}
}

func (s *Store) put(ref stores.Ref, fields map[string]secret.Value, opts stores.WriteOptions) (stores.Metadata, error) {
	now := s.now().UTC()
	e, exists := s.data[ref.Path]
	if exists && opts.CreateOnly {
		return stores.Metadata{}, stores.NewError(s.name, stores.OpWrite, ref, stores.ErrConflict, nil)
	}
	if !exists {
		e = &entry{meta: stores.Metadata{CreatedAt: now}}
		s.data[ref.Path] = e
	}
	wipe(e.fields)
	e.fields = make(map[string]secret.Value, len(fields))
	for name, v := range fields {
		e.fields[name] = copyValue(v)
	}
	version, _ := strconv.Atoi(e.meta.Version)
	e.meta.Version = strconv.Itoa(version + 1)
	e.meta.UpdatedAt = now
	e.meta.Fields = slices.Sorted(maps.Keys(fields))
	if opts.Labels != nil {
		e.meta.Labels = maps.Clone(opts.Labels)
	}
	s.notify(stores.Change{Ref: ref, Kind: stores.Changed})
	return cloneMeta(e.meta, ref), nil
}

// notify sends without blocking; a watcher that does not drain loses
// changes, which the periodic refresh covers.
func (s *Store) notify(c stores.Change) {
	for ch, prefix := range s.watchers {
		if under(c.Ref.Path, prefix.Path) {
			c.Ref.Scheme = prefix.Scheme
			select {
			case ch <- c:
			default:
			}
		}
	}
}

// Health implements stores.Adapter.
func (s *Store) Health(context.Context) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fail(stores.OpHealth, stores.Ref{}, 0)
}

// Close implements stores.Adapter. It wipes every value.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.data {
		wipe(e.fields)
	}
	clear(s.data)
	for ch := range s.watchers {
		close(ch)
	}
	clear(s.watchers)
	s.closed = true
	return nil
}

func under(path, prefix string) bool {
	return prefix == "" || path == prefix || strings.HasPrefix(path, strings.TrimSuffix(prefix, "/")+"/")
}

func cloneMeta(m stores.Metadata, ref stores.Ref) stores.Metadata {
	m.Ref = ref
	m.Fields = slices.Clone(m.Fields)
	m.Labels = maps.Clone(m.Labels)
	return m
}

func copyValue(v secret.Value) secret.Value {
	var out secret.Value
	_ = v.Expose(func(b []byte) error {
		out = secret.New(b)
		return nil
	})
	return out
}

func wipe(fields map[string]secret.Value) {
	for _, v := range fields {
		v.Wipe()
	}
}
