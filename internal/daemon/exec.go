// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"

	"github.com/heliopsy/scrim/internal/agentapi"
	"github.com/heliopsy/scrim/internal/catalog"
	"github.com/heliopsy/scrim/internal/execbroker"
	"github.com/heliopsy/scrim/internal/gate"
	"github.com/heliopsy/scrim/internal/obs"
	"github.com/heliopsy/scrim/internal/placeholder"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/refresh"
)

// wireExec serves the exec broker on the agent API (POST /v1/exec). It
// decides through g, the control plane's gate, and redacts command output
// with the data plane's redactor, the same as POST /v1/redact.
func (d *Daemon) wireExec(g *gate.Gate) error {
	b, err := execbroker.New(execbroker.Deps{
		Config: func() (execbroker.Config, error) { return execbroker.ConfigFrom(d.app.Config.Current()) },
		Values: execValues{d: d},
		Gate:   g,
		Redactor: func(ctx context.Context, text []byte) (execbroker.Redacted, error) {
			r, err := d.redact(ctx, text)
			return execbroker.Redacted{Text: r.Text, Replacements: r.Replacements}, err
		},
		Auditor: agentapi.Audit{State: d.app.State},
		Logger:  obs.WithComponent(d.app.Log, "exec"),
	})
	if err != nil {
		return err
	}
	d.runtime.SetExec(b.Run)
	return nil
}

// execValues finds credentials by placeholder in the stores' redaction
// sets. Only a current value with a store reference qualifies: a retained
// (rotated) value, a write in flight, a store's own credential, a session
// token and a project file value are redacted but never handed to a
// command.
type execValues struct{ d *Daemon }

func (e execValues) Find(_ context.Context, occurs func(string) bool) ([]execbroker.Match, error) {
	b := e.d.builder
	var cat *catalog.Catalog
	if e.d.catalog != nil {
		cat = e.d.catalog.Current()
	}
	var out []execbroker.Match
	var ferr error
	for _, r := range e.d.app.Refreshers {
		r.EachValue(func(s refresh.Source, v secret.Value) {
			if ferr != nil || s.Retained || s.Pending || s.Ref.IsZero() {
				return
			}
			bd := catalog.Binding{Ref: s.Ref}
			if cat != nil {
				bd = cat.Ref(s.Ref)
			}
			forms, err := b.placeholderForms(s.Ref, bd, v)
			if err != nil {
				ferr = err
				return
			}
			for _, f := range forms {
				if !occurs(f) {
					continue
				}
				var cp secret.Value
				_ = v.Expose(func(raw []byte) error { cp = secret.New(raw); return nil })
				out = append(out, execbroker.Match{Form: f, Ref: s.Ref, Name: bd.Name, Class: string(bd.Class), Value: cp})
			}
		})
	}
	if ferr != nil {
		for _, m := range out {
			m.Value.Wipe()
		}
		return nil, ferr
	}
	return out, nil
}

// placeholderForms are every text that names v: its placeholder under each
// key version (old placeholders keep resolving during a rotation), the
// format-preserving form where the catalog asks for one, the declared
// placeholder and the reference placeholders {{scrim:<ref>}} and
// {{scrim:<name>}}.
func (b *SnapshotBuilder) placeholderForms(ref stores.Ref, bd catalog.Binding, v secret.Value) ([]string, error) {
	slug := SlugFor(bd, ref)
	shaped := bd.PlaceholderFormat == placeholder.FormatShape && bd.Class != catalog.ClassDisplay
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.keys == nil || len(b.keys.Keys) == 0 {
		return nil, errors.New("no placeholder key")
	}
	forms := make([]string, 0, 2*len(b.keys.Keys)+3)
	for _, k := range b.keys.Keys {
		p, err := placeholder.Derive(k, slug, v)
		if err != nil {
			return nil, err
		}
		forms = append(forms, p)
		if shaped {
			if p, err := placeholder.Shaped(k, slug, v); err == nil {
				forms = append(forms, p)
			}
		}
	}
	if bd.Placeholder != "" {
		forms = append(forms, bd.Placeholder)
	}
	forms = append(forms, "{{scrim:"+ref.String()+"}}")
	if bd.Name != "" {
		forms = append(forms, "{{scrim:"+bd.Name+"}}")
	}
	return forms, nil
}
