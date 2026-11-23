// SPDX-License-Identifier: AGPL-3.0-only

// Package storeconfig turns the `stores` configuration collection into
// running store adapters and refreshers.
//
//	stores:
//	  bao:
//	    kind: openbao
//	    aliases: [bao-prod]
//	    address: https://bao.example.com:8200
//	    auth: {method: approle}
//	    role-id: file:/run/secrets/bao-role-id
//	    secret-id: file:/run/secrets/bao-secret-id
//	    redact: [bao://kv/agents/*]
//	    refresh: {interval: 5m, staleness: 15m}
//
// Each instance's name is its primary reference scheme. The generic fields
// (kind, aliases, redact, refresh.*) are read here; every other field is
// the adapter's own and is passed to its factory, which validates it
// strictly. Credential fields are secret fields of the collection: they are
// resolved at load, masked in `scrim config show`, and handed to the adapter
// through stores.Instance.Resolve.
package storeconfig

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/refresh"
)

// Key is the collection key.
const Key = "stores"

// Generic fields of every instance.
const (
	FieldKind    = "kind"
	FieldAliases = "aliases"
	// FieldLabels derives the instance's own policy labels from the labels
	// its adapter reports (stores.LabelMapping).
	FieldLabels = "labels"
)

// SecretFields are the credential fields any adapter may use. They are
// top-level names so the collection can resolve and mask them; an adapter
// that needs another adds it here.
var SecretFields = []string{"token", "role-id", "secret-id", "client-id", "client-secret", "password", "unlock", "age-identity", "credentials", "certificate", "access-key-id", "secret-access-key", "jwt"}

// AllowEmptyTargets lets scrim start while a redact target loads no value.
var AllowEmptyTargets = config.Register(config.Spec[bool]{
	Key:             refresh.AllowEmptyTargetsKey,
	Weakening:       true,
	RestartRequired: true,
	Description: "Start even when a store's redact target matches no secret on the first load. Off, such a target stops start-up " +
		"with an error naming it, since it usually means a misspelt name or pattern and redaction would protect nothing. " +
		"On, the store starts and status reports the target as degraded with 0 values.",
})

// Collection is the registered `stores` collection.
var Collection = config.RegisterCollection(config.CollectionSpec{
	Key: Key,
	Description: "Secret store instances by name. The name is the instance's reference scheme " +
		"(`bao://...` for an instance named bao); `kind` picks the adapter, `aliases` adds schemes, " +
		"`redact` lists references and prefixes loaded into the redaction set, `refresh.*` tunes " +
		"refresh and outage handling, `labels` derives policy labels from the store's own labels " +
		"(docs/policy.md, \"Labels from stores\"), and every other field is the adapter's own. See docs/stores.",
	FieldSchemas:    map[string]map[string]any{FieldLabels: labelsSchema},
	SecretFields:    SecretFields,
	RequiredFields:  []string{FieldKind},
	RestartRequired: true,
	Validate:        func(inst config.Instance) error { return Validate(stores.DefaultRegistry, inst) },
	ValidateAll:     checkCredentialGraph,
})

// labelsSchema is the JSON schema of the labels field.
var labelsSchema = map[string]any{
	"type":          "object",
	"description":   "Derived policy labels by name: a source label name to copy, or {from, regex, value}.",
	"propertyNames": map[string]any{"pattern": `^[a-z0-9_-]+(\.[a-z0-9_-]+)*$`},
	"additionalProperties": map[string]any{"anyOf": []any{
		map[string]any{"type": "string", "minLength": 1},
		map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"properties": map[string]any{
				"from":  map[string]any{"type": "string", "minLength": 1},
				"regex": map[string]any{"type": "string"},
				"value": map[string]any{"type": "string"},
			},
		},
	}},
}

// split separates an instance's generic fields from the adapter's options.
func split(inst config.Instance) (kind string, aliases []string, adapterOpts, refreshOpts map[string]any, err error) {
	var errs []error
	kind, ok := inst.Fields[FieldKind].(string)
	if !ok || kind == "" {
		errs = append(errs, errors.New("kind must be an adapter kind such as openbao"))
	}
	switch a := inst.Fields[FieldAliases].(type) {
	case nil:
	case string:
		for _, s := range strings.Split(a, ",") {
			if s = strings.TrimSpace(s); s != "" {
				aliases = append(aliases, s)
			}
		}
	case []any:
		for _, x := range a {
			s, ok := x.(string)
			if !ok {
				errs = append(errs, errors.New("aliases must be a list of schemes"))
				break
			}
			aliases = append(aliases, s)
		}
	default:
		errs = append(errs, errors.New("aliases must be a list of schemes"))
	}
	adapterOpts, refreshOpts = map[string]any{}, map[string]any{}
	for k, v := range inst.Fields {
		switch k {
		case FieldKind, FieldAliases, FieldLabels:
		case refresh.KeyRedact, "refresh":
			refreshOpts[k] = v
		default:
			adapterOpts[k] = v
		}
	}
	return kind, aliases, adapterOpts, refreshOpts, errors.Join(errs...)
}

// Validate checks one instance without contacting its store: the kind is
// known, the aliases are valid schemes, the refresh options parse and the
// adapter accepts its options. Errors carry no secret values (credential
// fields hold references at this point).
func Validate(reg *stores.Registry, inst config.Instance) error {
	kind, aliases, aopts, ropts, err := split(inst)
	if err != nil {
		return err
	}
	if err := checkSelfRefs(inst, aliases); err != nil {
		return err
	}
	if !slices.Contains(reg.Kinds(), kind) {
		return fmt.Errorf("%w %q (known: %s)", stores.ErrUnknownKind, kind, strings.Join(reg.Kinds(), ", "))
	}
	for _, a := range aliases {
		if _, err := stores.ParseRef(a + "://x"); err != nil {
			return fmt.Errorf("alias %q is not a valid scheme", a)
		}
	}
	rc, err := refresh.ParseConfig(inst.Name, ropts)
	if err != nil {
		return err
	}
	if _, err := stores.ParseLabelMapping(kind, inst.Fields[FieldLabels]); err != nil {
		return err
	}
	a, err := reg.Open(context.Background(), stores.Instance{
		Name: inst.Name, Kind: kind, Aliases: aliases, Options: aopts,
		Resolve: func(context.Context, config.SecretRef) (secret.Value, error) {
			return secret.Value{}, errors.New("not resolved during validation")
		},
	})
	if err != nil {
		return err
	}
	if err := checkTargets(a, rc); err != nil {
		_ = a.Close()
		return err
	}
	return a.Close()
}

// credentialRefs returns the credential fields of inst that are store
// references, by field.
func credentialRefs(inst config.Instance) map[string]config.SecretRef {
	out := map[string]config.SecretRef{}
	for _, f := range SecretFields {
		if s, ok := inst.Fields[f].(string); ok {
			if ref := config.SecretRef(s); ref.Kind() == config.RefStore {
				out[f] = ref
			}
		}
	}
	return out
}

// checkSelfRefs refuses a credential that is a store reference into the
// instance itself: the store would need to read it to open.
func checkSelfRefs(inst config.Instance, aliases []string) error {
	var errs []error
	for _, f := range slices.Sorted(maps.Keys(credentialRefs(inst))) {
		ref := config.SecretRef(inst.Fields[f].(string))
		if s := ref.Scheme(); s == inst.Name || slices.Contains(aliases, s) {
			errs = append(errs, fmt.Errorf("%s: %s refers to this store; a store's own credentials cannot come from itself, "+
				"use an env:, file: or cred: reference or another store", f, ref.Display()))
		}
	}
	return errors.Join(errs...)
}

// checkCredentialGraph checks the credentials that are references into
// other stores: each names a configured store, and no chain of them leads
// back to where it started (a store would need its own credential to read
// it). Called before any credential is resolved.
func checkCredentialGraph(insts []config.Instance) error {
	byScheme := map[string]string{}
	for _, inst := range insts {
		byScheme[inst.Name] = inst.Name
		if _, aliases, _, _, err := split(inst); err == nil {
			for _, a := range aliases {
				byScheme[a] = inst.Name
			}
		}
	}
	var errs []error
	deps := map[string][]string{}
	for _, inst := range insts {
		refs := credentialRefs(inst)
		for _, f := range slices.Sorted(maps.Keys(refs)) {
			target, ok := byScheme[refs[f].Scheme()]
			switch {
			case !ok:
				errs = append(errs, fmt.Errorf("%s.%s: %s names no configured store", inst.Name, f, refs[f].Display()))
			case target != inst.Name && !slices.Contains(deps[inst.Name], target):
				deps[inst.Name] = append(deps[inst.Name], target)
			}
		}
	}
	// Depth-first search for a cycle; each one is reported once, from its
	// alphabetically first store.
	const (
		unseen = iota
		active
		done
	)
	mark := map[string]int{}
	var path []string
	var visit func(n string)
	visit = func(n string) {
		mark[n] = active
		path = append(path, n)
		for _, d := range deps[n] {
			switch mark[d] {
			case active:
				i := slices.Index(path, d)
				cycle := append(slices.Clone(path[i:]), d)
				errs = append(errs, fmt.Errorf("store credentials form a cycle (%s): each store needs the next one open to "+
					"read its credential; give one of them an env:, file: or cred: reference", strings.Join(cycle, " -> ")))
			case unseen:
				visit(d)
			}
		}
		path = path[:len(path)-1]
		mark[n] = done
	}
	for _, n := range slices.Sorted(maps.Keys(deps)) {
		if mark[n] == unseen {
			visit(n)
		}
	}
	return errors.Join(errs...)
}

// checkTargets refuses a glob target on a store that cannot expand one: it
// would load nothing.
func checkTargets(a stores.Adapter, rc refresh.Config) error {
	for _, t := range rc.Targets {
		if t.Glob && !a.Capabilities().Has(stores.CapGlob) {
			return fmt.Errorf("option %s: %s: store %s (capabilities %s) does not match names by a trailing *; "+
				"use a folder prefix (dir/*) or name each secret", refresh.KeyRedact, t, a.Name(), a.Capabilities())
		}
	}
	return nil
}

// Instance builds the stores.Instance for one configured instance, with a
// Resolve that returns the collection's resolved secret fields and resolves
// any other reference through cfg. A credential that is a reference into
// another store is read through set at each use (each login), so the
// store's credential follows rotation in the other store; the collection
// check guarantees the chain of such references ends.
func Instance(cfg *config.Config, inst config.Instance, set *stores.Set) (stores.Instance, refresh.Config, error) {
	kind, aliases, aopts, ropts, err := split(inst)
	if err != nil {
		return stores.Instance{}, refresh.Config{}, fmt.Errorf("store %s: %w", inst.Name, err)
	}
	rc, err := refresh.ParseConfig(inst.Name, ropts)
	if err != nil {
		return stores.Instance{}, refresh.Config{}, err
	}
	return stores.Instance{
		Name: inst.Name, Kind: kind, Aliases: aliases, Options: aopts,
		Resolve: func(ctx context.Context, ref config.SecretRef) (secret.Value, error) {
			if ref.Kind() == config.RefStore && set != nil {
				v, err := set.ResolveSecret(ctx, string(ref))
				if err != nil {
					return secret.Value{}, fmt.Errorf("reference %s: %w", ref.Display(), err)
				}
				return v, nil
			}
			for _, f := range SecretFields {
				if s, ok := inst.Fields[f].(string); ok && s == string(ref) {
					if v, ok := cfg.SecretAt(inst.Key(Key, f)); ok {
						// The Config keeps its copy; the adapter wipes its own.
						return copyValue(v), nil
					}
				}
			}
			return cfg.ResolveRef(ctx, ref)
		},
	}, rc, nil
}

// Opened is the result of [Open].
type Opened struct {
	Set        *stores.Set
	Refreshers []*refresh.Refresher
}

// Close closes every adapter and wipes every refresher.
func (o *Opened) Close() error {
	for _, r := range o.Refreshers {
		r.Close()
	}
	return o.Set.Close()
}

// Options are hooks [OpenWith] installs on every Refresher.
type Options struct {
	// OnChange is called with the store's name after every change to its
	// value set, outside any lock. The data plane snapshot is rebuilt from
	// it. It must not block.
	OnChange func(store string)
	// OnStatus is called after every refresh attempt, for metrics.
	OnStatus func(refresh.Status)
	// Log is handed to every adapter for its warnings. Nil discards them.
	Log *slog.Logger
	// Redact lists store references that configuration uses as secret
	// values outside the stores collection (database passwords). Each
	// becomes a redact target of the store its scheme names, so its value
	// is loaded with the store, refreshed with it and kept in the redaction
	// set. A reference must name one secret of a configured store.
	Redact []string
}

// addTarget adds t, a whole secret, to ts unless a target already covers
// it. A target naming one field of the same secret is widened to the whole
// secret, which only adds values to the redaction set.
func addTarget(ts []refresh.Target, t refresh.Target) []refresh.Target {
	for i, have := range ts {
		if !have.Covers(t.Ref) {
			continue
		}
		if !have.Prefix && !have.Glob {
			ts[i].Ref.Field = ""
		}
		return ts
	}
	return append(ts, t)
}

// Open builds every configured store's adapter (without contacting it),
// adds it to a Set under its name and aliases, and pairs it with a
// Refresher. Nothing runs until the caller starts each Refresher.
func Open(ctx context.Context, cfg *config.Config, reg *stores.Registry) (*Opened, error) {
	return OpenWith(ctx, cfg, reg, Options{})
}

// OpenWith is [Open] with hooks on every Refresher.
func OpenWith(ctx context.Context, cfg *config.Config, reg *stores.Registry, opts Options) (*Opened, error) {
	o := &Opened{Set: stores.NewSet()}
	type opened struct {
		a  stores.Adapter
		rc refresh.Config
	}
	var (
		errs []error
		all  []opened
	)
	for _, ci := range Collection.Get(cfg) {
		inst, rc, err := Instance(cfg, ci, o.Set)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		inst.Log = opts.Log
		a, err := reg.Open(ctx, inst)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := checkTargets(a, rc); err != nil {
			_ = a.Close()
			errs = append(errs, fmt.Errorf("store %s: %w", inst.Name, err))
			continue
		}
		mapping, err := stores.ParseLabelMapping(inst.Kind, ci.Fields[FieldLabels])
		if err != nil {
			_ = a.Close()
			errs = append(errs, fmt.Errorf("store %s: %w", inst.Name, err))
			continue
		}
		if err := o.Set.Add(a, inst.Aliases...); err != nil {
			_ = a.Close()
			errs = append(errs, err)
			continue
		}
		o.Set.SetLabeling(a.Name(), inst.Kind, mapping)
		if opts.OnChange != nil {
			name := a.Name()
			rc.OnChange = func() { opts.OnChange(name) }
		}
		rc.OnStatus = opts.OnStatus
		rc.AllowEmptyTargets = AllowEmptyTargets.Get(cfg)
		all = append(all, opened{a: a, rc: rc})
	}
	for _, raw := range opts.Redact {
		t, err := refresh.ParseTarget(raw)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("reference %s: %w", config.SecretRef(raw).Display(), err))
			continue
		case t.Prefix || t.Glob:
			errs = append(errs, fmt.Errorf("reference %s: must name one secret", config.SecretRef(raw).Display()))
			continue
		}
		a, err := o.Set.Lookup(t.Ref)
		if err != nil {
			errs = append(errs, fmt.Errorf("reference %s: no configured store has the scheme %s", config.SecretRef(raw).Display(), t.Ref.Scheme))
			continue
		}
		// The whole secret is the target: a target limited to one field
		// next to a prefix or whole-secret target over the same secret
		// would replace its other fields at every refresh.
		t.Ref.Scheme, t.Ref.Field = a.Name(), ""
		for i := range all {
			if all[i].a == a {
				all[i].rc.Targets = addTarget(all[i].rc.Targets, t)
			}
		}
	}
	for _, x := range all {
		o.Refreshers = append(o.Refreshers, refresh.New(x.a, x.rc))
	}
	if err := errors.Join(errs...); err != nil {
		_ = o.Close()
		return nil, err
	}
	return o, nil
}

func copyValue(v secret.Value) secret.Value {
	var out secret.Value
	_ = v.Expose(func(b []byte) error {
		out = secret.New(b)
		return nil
	})
	return out
}

// Resolver resolves store references in configuration values
// (config.StoreResolver) by reading them from a store Set. The Set can be
// replaced: the daemon resolves through stores opened for start-up until
// its running stores are open, then through those.
type Resolver struct{ set atomic.Pointer[stores.Set] }

// Use makes r read through s.
func (r *Resolver) Use(s *stores.Set) { r.set.Store(s) }

// ResolveSecret implements config.StoreResolver. Errors name the reference,
// never a value.
func (r *Resolver) ResolveSecret(ctx context.Context, ref string) (secret.Value, error) {
	s := r.set.Load()
	if s == nil {
		return secret.Value{}, errors.New("no secret stores are open")
	}
	return s.ResolveSecret(ctx, ref)
}

// Resolved returns cfg with the store references of the settings named by
// keys (all of them when keys is empty) read from the stores cfg
// configures. It is for a client, such as the CLI, that builds its
// configuration without stores and needs one of these values. It returns
// cfg itself when none of the settings holds an unresolved store
// reference. done closes the stores it opened; the returned Config keeps
// the values it read.
func Resolved(ctx context.Context, cfg *config.Config, reg *stores.Registry, keys ...string) (_ *config.Config, done func(), _ error) {
	need := false
	for _, k := range cfg.Unresolved() {
		need = need || len(keys) == 0 || slices.Contains(keys, k)
	}
	if !need {
		return cfg, func() {}, nil
	}
	o, err := Open(ctx, cfg, reg)
	if err != nil {
		return nil, nil, err
	}
	done = func() { _ = o.Close() }
	n, err := cfg.ResolveStores(ctx, o.Set, keys...)
	if err != nil {
		done()
		return nil, nil, err
	}
	return n, done, nil
}
