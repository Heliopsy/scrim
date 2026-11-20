// SPDX-License-Identifier: AGPL-3.0-only

package stores

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
)

// Instance is the configuration of one store instance, as the loader hands
// it to a [Factory].
type Instance struct {
	// Name is the instance name, also its primary scheme.
	Name string
	// Kind is the adapter kind ("openbao").
	Kind string
	// Aliases are extra schemes that address this instance.
	Aliases []string
	// Options are the adapter's own settings, decoded from configuration.
	// Credentials appear here only as config.SecretRef and are resolved
	// with Resolve.
	Options map[string]any
	// Resolve turns a secret reference into its value. The adapter owns the
	// returned value and wipes it when no longer needed.
	Resolve func(ctx context.Context, ref config.SecretRef) (secret.Value, error)
}

// Factory builds an adapter for one instance. It must not contact the store;
// connection happens on first use or in Health, so start-up can report every
// store at once.
type Factory func(ctx context.Context, inst Instance) (Adapter, error)

// Registry maps adapter kinds to factories.
type Registry struct {
	mu        sync.RWMutex
	factories map[string]Factory
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{factories: map[string]Factory{}} }

// DefaultRegistry holds the adapters compiled into the binary. Adapter
// packages call [Register] from init, and internal/app imports each adapter
// package for its side effect, one file per adapter.
var DefaultRegistry = NewRegistry()

// Register adds a factory to [DefaultRegistry]. It panics on a duplicate
// kind.
func Register(kind string, f Factory) {
	if err := DefaultRegistry.Register(kind, f); err != nil {
		panic(err)
	}
}

// Register adds a factory for kind.
func (r *Registry) Register(kind string, f Factory) error {
	if !schemePattern.MatchString(kind) {
		return fmt.Errorf("stores: invalid adapter kind %q", kind)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.factories[kind]; dup {
		return fmt.Errorf("stores: adapter kind %q registered twice", kind)
	}
	r.factories[kind] = f
	return nil
}

// Kinds lists the registered kinds, sorted.
func (r *Registry) Kinds() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.factories))
	for k := range r.factories {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Open builds an adapter for inst.
func (r *Registry) Open(ctx context.Context, inst Instance) (Adapter, error) {
	r.mu.RLock()
	f, ok := r.factories[inst.Kind]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("stores: instance %s: %w %q", inst.Name, ErrUnknownKind, inst.Kind)
	}
	return f(ctx, inst)
}

// Set is the configured store instances, addressed by scheme. It checks
// capabilities before calling an adapter, so an unsupported operation is
// refused before anything is attempted.
type Set struct {
	mu       sync.RWMutex
	byScheme map[string]Adapter
	order    []Adapter
}

// NewSet returns an empty set.
func NewSet() *Set { return &Set{byScheme: map[string]Adapter{}} }

// Add registers adapter a under its name and aliases.
func (s *Set) Add(a Adapter, aliases ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	schemes := append([]string{a.Name()}, aliases...)
	for _, sc := range schemes {
		if !schemePattern.MatchString(sc) {
			return fmt.Errorf("stores: invalid scheme %q for %s", sc, a.Name())
		}
		if other, dup := s.byScheme[sc]; dup {
			return fmt.Errorf("stores: scheme %q used by both %s and %s", sc, other.Name(), a.Name())
		}
	}
	for _, sc := range schemes {
		s.byScheme[sc] = a
	}
	s.order = append(s.order, a)
	return nil
}

// Adapters returns every adapter in the order added.
func (s *Set) Adapters() []Adapter {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Adapter(nil), s.order...)
}

// Lookup returns the adapter for ref's scheme.
func (s *Set) Lookup(ref Ref) (Adapter, error) {
	s.mu.RLock()
	a, ok := s.byScheme[ref.Scheme]
	s.mu.RUnlock()
	if !ok {
		return nil, NewError(ref.Scheme, "lookup", ref, ErrUnknownStore, nil)
	}
	return a, nil
}

func (s *Set) adapterFor(ref Ref, op Op, c Capability) (Adapter, error) {
	a, err := s.Lookup(ref)
	if err != nil {
		return nil, err
	}
	if !a.Capabilities().Has(c) {
		return nil, NewError(a.Name(), op, ref, ErrUnsupported, nil)
	}
	return a, nil
}

// Read reads ref from its store.
func (s *Set) Read(ctx context.Context, ref Ref) (Secret, error) {
	a, err := s.adapterFor(ref, OpRead, CapRead)
	if err != nil {
		return Secret{}, err
	}
	return a.Read(ctx, ref)
}

// List lists under prefix in its store.
func (s *Set) List(ctx context.Context, prefix Ref) ([]Metadata, error) {
	a, err := s.adapterFor(prefix, OpList, CapList)
	if err != nil {
		return nil, err
	}
	return a.List(ctx, prefix)
}

// Write writes to ref's store.
func (s *Set) Write(ctx context.Context, ref Ref, fields map[string]secret.Value, opts WriteOptions) (Metadata, error) {
	a, err := s.adapterFor(ref, OpWrite, CapWrite)
	if err != nil {
		return Metadata{}, err
	}
	return a.Write(ctx, ref, fields, opts)
}

// Close closes every adapter and returns the first error.
func (s *Set) Close() error {
	var first error
	for _, a := range s.Adapters() {
		if err := a.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
