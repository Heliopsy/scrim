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
	"slices"
	"strings"

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
)

// SecretFields are the credential fields any adapter may use. They are
// top-level names so the collection can resolve and mask them; an adapter
// that needs another adds it here.
var SecretFields = []string{"token", "role-id", "secret-id", "client-id", "client-secret", "password"}

// Collection is the registered `stores` collection.
var Collection = config.RegisterCollection(config.CollectionSpec{
	Key: Key,
	Description: "Secret store instances by name. The name is the instance's reference scheme " +
		"(`bao://...` for an instance named bao); `kind` picks the adapter, `aliases` adds schemes, " +
		"`redact` lists references and prefixes loaded into the redaction set, `refresh.*` tunes " +
		"refresh and outage handling, and every other field is the adapter's own. See docs/stores.",
	SecretFields:    SecretFields,
	RequiredFields:  []string{FieldKind},
	RestartRequired: true,
	Validate:        func(inst config.Instance) error { return Validate(stores.DefaultRegistry, inst) },
})

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
		case FieldKind, FieldAliases:
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
	if !slices.Contains(reg.Kinds(), kind) {
		return fmt.Errorf("%w %q (known: %s)", stores.ErrUnknownKind, kind, strings.Join(reg.Kinds(), ", "))
	}
	for _, a := range aliases {
		if _, err := stores.ParseRef(a + "://x"); err != nil {
			return fmt.Errorf("alias %q is not a valid scheme", a)
		}
	}
	if _, err := refresh.ParseConfig(inst.Name, ropts); err != nil {
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
	return a.Close()
}

// Instance builds the stores.Instance for one configured instance, with a
// Resolve that returns the collection's resolved secret fields and resolves
// any other reference through cfg.
func Instance(cfg *config.Config, inst config.Instance) (stores.Instance, refresh.Config, error) {
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

// Open builds every configured store's adapter (without contacting it),
// adds it to a Set under its name and aliases, and pairs it with a
// Refresher. Nothing runs until the caller starts each Refresher.
func Open(ctx context.Context, cfg *config.Config, reg *stores.Registry) (*Opened, error) {
	o := &Opened{Set: stores.NewSet()}
	var errs []error
	for _, ci := range Collection.Get(cfg) {
		inst, rc, err := Instance(cfg, ci)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		a, err := reg.Open(ctx, inst)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := o.Set.Add(a, inst.Aliases...); err != nil {
			_ = a.Close()
			errs = append(errs, err)
			continue
		}
		o.Refreshers = append(o.Refreshers, refresh.New(a, rc))
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
