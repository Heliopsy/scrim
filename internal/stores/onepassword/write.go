// SPDX-License-Identifier: AGPL-3.0-only

package onepassword

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"slices"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

// Write implements stores.Adapter.
//
// A new item is created in the vault with the configured category
// (write.category), titled with the rest of the path, every field
// CONCEALED; "<section>/<field>" names put a field in that section, created
// if missing. On an existing item the named fields get their new values,
// keeping their type, and fields that do not exist yet are added; every other
// part of the item (other fields, sections, URLs, tags, files) is sent back
// unchanged, so rotating a password keeps the username. Connect replaces the
// item as a new version.
//
// CreateOnly is checked with a title lookup just before the create, so two
// writers racing on one new title can still create two items; reads of that
// title are then refused as ambiguous rather than picking one.
//
// 1Password items have no place for scrim's own labels, so a write with
// WriteOptions.Labels is refused instead of dropping them.
func (a *Adapter) Write(ctx context.Context, ref stores.Ref, fields map[string]secret.Value, opts stores.WriteOptions) (stores.Metadata, error) {
	ref = ref.Secret()
	loc, err := a.checkRef(stores.OpWrite, ref)
	if err != nil {
		return stores.Metadata{}, err
	}
	if len(opts.Labels) > 0 {
		return stores.Metadata{}, a.refuse(stores.OpWrite, ref, stores.ErrUnsupported, "1Password items cannot hold scrim labels")
	}
	if len(fields) == 0 {
		return stores.Metadata{}, a.refuse(stores.OpWrite, ref, stores.ErrInvalidRef, "no fields to write")
	}
	names := slices.Sorted(maps.Keys(fields))
	quoted := make(map[string][]byte, len(fields))
	defer func() {
		for _, b := range quoted {
			secret.WipeBytes(b)
		}
	}()
	for _, n := range names {
		if _, _, ok := splitFieldName(n); !ok {
			return stores.Metadata{}, a.refuse(stores.OpWrite, ref, stores.ErrInvalidRef, "field name "+quote(n)+" must be <field> or <section>/<field>")
		}
		b, err := wire.AppendValue(nil, fields[n])
		if err != nil {
			secret.WipeBytes(b)
			return stores.Metadata{}, a.refuse(stores.OpWrite, ref, stores.ErrUnsupported, "field "+quote(n)+": 1Password stores text only and the value is not valid UTF-8")
		}
		quoted[n] = b
	}
	involved := slices.Collect(maps.Values(fields))

	f, err := a.locate(ctx, loc, false)
	switch {
	case errors.Is(err, stores.ErrNotFound) && f == nil && a.vaultKnown(ctx, loc):
		return a.create(ctx, ref, loc, names, quoted, involved)
	case err != nil:
		return stores.Metadata{}, a.fail(stores.OpWrite, ref, err)
	case opts.CreateOnly:
		return stores.Metadata{}, a.refuse(stores.OpWrite, ref, stores.ErrConflict, "item already exists")
	}
	return a.update(ctx, ref, f, names, quoted, involved)
}

// vaultKnown reports whether the vault of loc resolves, so a "not found"
// from locate means the item is missing rather than the vault: scrim never
// creates vaults.
func (a *Adapter) vaultKnown(ctx context.Context, loc location) bool {
	_, err := a.c.vault(ctx, loc.vault)
	return err == nil
}

// object is a JSON object whose members are kept as raw JSON, so values
// pass through without becoming strings. Members are wiped after use.
type object map[string]json.RawMessage

func (o object) wipe() {
	for _, v := range o {
		secret.WipeBytes(v)
	}
}

// appendObject encodes o with sorted keys. Raw members are copied verbatim.
func appendObject(dst []byte, o object) []byte {
	dst = append(dst, '{')
	for i, k := range slices.Sorted(maps.Keys(o)) {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst, _ = wire.AppendQuoted(dst, []byte(k))
		dst = append(dst, ':')
		dst = append(dst, o[k]...)
	}
	return append(dst, '}')
}

func appendArray(dst []byte, os []object) []byte {
	dst = append(dst, '[')
	for i, o := range os {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = appendObject(dst, o)
	}
	return append(dst, ']')
}

// js is the JSON text of a value that is never secret.
func js(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

const idAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

// newID returns a fresh 26-character ID in 1Password's alphabet, for new
// fields and sections.
func newID() string {
	b := make([]byte, 26)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = idAlphabet[int(b[i])%len(idAlphabet)]
	}
	return string(b)
}

// newField is the JSON object of a field scrim adds. value is borrowed.
func newField(label, sectionID string, value []byte) object {
	o := object{
		"id":    js(newID()),
		"type":  js("CONCEALED"),
		"label": js(label),
		"value": slices.Clone(value),
	}
	if sectionID != "" {
		o["section"] = js(sectionRef{ID: sectionID})
	}
	return o
}

// sectionFor returns the ID of the section labelled (or with ID) name,
// adding one when there is none.
func sectionFor(sections *[]apiSection, name string) string {
	for _, s := range *sections {
		if s.Label == name || s.ID == name {
			return s.ID
		}
	}
	id := newID()
	*sections = append(*sections, apiSection{ID: id, Label: name})
	return id
}

func (a *Adapter) create(ctx context.Context, ref stores.Ref, loc location, names []string, quoted map[string][]byte, involved []secret.Value) (stores.Metadata, error) {
	v, err := a.c.vault(ctx, loc.vault)
	if err != nil {
		return stores.Metadata{}, a.fail(stores.OpWrite, ref, err)
	}
	var sections []apiSection
	var fs []object
	defer func() {
		for _, o := range fs {
			o.wipe()
		}
	}()
	for _, n := range names {
		sec, label, _ := splitFieldName(n)
		sid := ""
		if sec != "" {
			sid = sectionFor(&sections, sec)
		}
		fs = append(fs, newField(label, sid, quoted[n]))
	}
	top := object{
		"vault":    js(sectionRef{ID: v.ID}),
		"title":    js(loc.item),
		"category": js(a.s.category),
	}
	if len(sections) > 0 {
		top["sections"] = js(sections)
	}
	b := appendObject(nil, top)
	b = append(b[:len(b)-1], `,"fields":`...)
	b = appendArray(b, fs)
	b = append(b, '}')
	body := wire.NewBody(b)
	defer body.Wipe()
	resp, err := a.c.do(ctx, http.MethodPost, "/v1/vaults/"+v.ID+"/items", nil, body, involved)
	if err != nil {
		return stores.Metadata{}, a.fail(stores.OpWrite, ref, err)
	}
	return a.written(ref, v, resp)
}

func (a *Adapter) update(ctx context.Context, ref stores.Ref, f *found, names []string, quoted map[string][]byte, involved []secret.Value) (stores.Metadata, error) {
	it, raw, err := a.c.item(ctx, f.vault.ID, f.sum.ID)
	if err != nil {
		return stores.Metadata{}, a.fail(stores.OpWrite, ref, err)
	}
	defer secret.WipeBytes(raw)
	defer it.wipe()
	var top object
	if err := json.Unmarshal(raw, &top); err != nil {
		return stores.Metadata{}, a.refuse(stores.OpWrite, ref, stores.ErrUnavailable, "malformed item")
	}
	defer top.wipe()
	var gf []object
	if fr, ok := top["fields"]; ok {
		if err := json.Unmarshal(fr, &gf); err != nil || len(gf) != len(it.Fields) {
			return stores.Metadata{}, a.refuse(stores.OpWrite, ref, stores.ErrUnavailable, "malformed item fields")
		}
	}
	defer func() {
		for _, o := range gf {
			o.wipe()
		}
	}()
	views := fieldViews(it)
	sections := slices.Clone(it.Sections)
	for _, n := range names {
		v, msg, notFound := selectField(views, n)
		switch {
		case v != nil:
			i := 0
			for j := range it.Fields {
				if &it.Fields[j] == v.f {
					i = j
				}
			}
			secret.WipeBytes(gf[i]["value"])
			gf[i]["value"] = slices.Clone(quoted[n])
		case notFound:
			sec, label, _ := splitFieldName(n)
			sid := ""
			if sec != "" {
				sid = sectionFor(&sections, sec)
			}
			gf = append(gf, newField(label, sid, quoted[n]))
		default:
			return stores.Metadata{}, a.refuse(stores.OpWrite, ref, stores.ErrInvalidRef, msg)
		}
	}
	out := object{}
	for k, v := range top {
		if k != "fields" && k != "sections" {
			out[k] = v
		}
	}
	if len(sections) > 0 {
		out["sections"] = js(sections)
	}
	b := appendObject(nil, out)
	b = append(b[:len(b)-1], `,"fields":`...)
	b = appendArray(b, gf)
	b = append(b, '}')
	body := wire.NewBody(b)
	defer body.Wipe()
	resp, err := a.c.do(ctx, http.MethodPut, "/v1/vaults/"+f.vault.ID+"/items/"+f.sum.ID, nil, body, involved)
	if err != nil {
		return stores.Metadata{}, a.fail(stores.OpWrite, ref, err)
	}
	return a.written(ref, f.vault, resp)
}

// written turns the item Connect returns after a write into metadata,
// wiping the values it carries.
func (a *Adapter) written(ref stores.Ref, v apiVault, resp []byte) (stores.Metadata, error) {
	defer secret.WipeBytes(resp)
	var it apiItem
	err := json.Unmarshal(resp, &it)
	defer it.wipe()
	if err != nil {
		return stores.Metadata{}, a.refuse(stores.OpWrite, ref, stores.ErrUnavailable, "malformed response to the write")
	}
	f := &found{vault: v, sum: it.apiSummary}
	m := a.meta(ref, f)
	for _, fv := range fieldViews(&it) {
		if fv.hasValue() {
			m.Fields = append(m.Fields, fv.key)
		}
	}
	slices.Sort(m.Fields)
	return m, nil
}
