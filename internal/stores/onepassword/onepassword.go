// SPDX-License-Identifier: AGPL-3.0-only

// Package onepassword is the store adapter for 1Password through a 1Password
// Connect server (specs/secret-stores, "1Password adapter"), addressed as
//
//	<scheme>://<vault>/<item>[#[<section>/]<field>]
//
// which is op://<vault>/<item>/[<section>/]<field> with the field moved to
// the fragment. <vault> and <item> are names (titles) or IDs; an item title
// may contain "/", so <item> is everything after the vault. See fields.go
// for how fields are named and selected.
//
// The adapter talks to the Connect REST API (v1) with a small typed client.
// Values travel between the HTTP body and secret.Value through package wire
// and are never Go strings, except the Connect token, which net/http takes
// as a string header built for each request and dropped after it.
//
// 1Password service accounts are not supported. They are only reachable
// through 1Password's SDKs, whose Go module (onepassword-sdk-go) runs a
// WebAssembly core on wazero: it needs no CGO, but it embeds about 9 MB of
// WebAssembly, returns every value as a Go string, and only talks to the
// 1Password domains hard-coded in the module, so it can be neither kept off
// the heap as a string nor tested against a fake. Connect speaks a
// documented REST API scrim can hold to its own rules.
//
// Per-agent identity takes a Connect access token issued for each agent by
// the same Connect server and scoped to the agent's own vaults, held in
// identity.store-credentials. Before scrim reads a reference with its own
// token, AgentCan (agent.go) lists the item's summary in its vault with the
// agent's token, which needs no value; Connect scopes tokens per vault, so
// that is exactly the agent's read access. Writes cannot be checked without
// writing. With no service accounts there is no token exchange and no
// Kubernetes passthrough.
package onepassword

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// Kind is the adapter kind this package registers.
const Kind = "onepassword"

func init() {
	stores.DeclareMulti(Kind, multiAttrs...)
	stores.Register(Kind, New)
}

// Adapter is one configured Connect server.
type Adapter struct {
	name string
	s    *settings
	c    *client
}

var (
	_ stores.Adapter          = (*Adapter)(nil)
	_ stores.CredentialHolder = (*Adapter)(nil)
	_ stores.MetadataReader   = (*Adapter)(nil)
	_ stores.WriteLabeler     = (*Adapter)(nil)
)

// New builds an adapter from its configuration. It validates the options and
// neither resolves the token nor contacts Connect.
func New(_ context.Context, inst stores.Instance) (stores.Adapter, error) {
	s, err := decodeSettings(inst)
	if err != nil {
		return nil, &stores.Error{Store: inst.Name, Op: "configure", Kind: stores.ErrInvalidRef, Detail: err.Error()}
	}
	c, err := newClient(s)
	if err != nil {
		return nil, &stores.Error{Store: inst.Name, Op: "configure", Kind: stores.ErrInvalidRef, Detail: err.Error()}
	}
	return &Adapter{name: inst.Name, s: s, c: c}, nil
}

// Name implements stores.Adapter.
func (a *Adapter) Name() string { return a.name }

// Capabilities implements stores.Adapter.
func (a *Adapter) Capabilities() stores.Capabilities {
	return stores.CapRead | stores.CapList | stores.CapWatch | stores.CapWrite | stores.CapGlob
}

// Credentials implements stores.CredentialHolder.
func (a *Adapter) Credentials() []secret.Value { return a.c.credentials() }

// Close implements stores.Adapter.
func (a *Adapter) Close() error {
	a.c.close()
	return nil
}

func (a *Adapter) fail(op stores.Op, ref stores.Ref, err error) error {
	var ae *apiError
	if errors.As(err, &ae) {
		return &stores.Error{Store: a.name, Op: op, Ref: ref, Kind: ae.kind, Detail: ae.msg, Cause: ae.cause}
	}
	var se *stores.Error
	if errors.As(err, &se) {
		return se
	}
	return stores.NewError(a.name, op, ref, stores.ErrUnavailable, err)
}

func (a *Adapter) refuse(op stores.Op, ref stores.Ref, kind error, detail string) error {
	return &stores.Error{Store: a.name, Op: op, Ref: ref, Kind: kind, Detail: detail}
}

// location is a reference split into vault and item.
type location struct {
	vault string
	item  string
}

func splitSecret(path string) (location, bool) {
	vault, item, ok := strings.Cut(path, "/")
	if !ok || vault == "" || item == "" {
		return location{}, false
	}
	return location{vault: vault, item: item}, true
}

const refShape = "want <vault>/<item>[#[<section>/]<field>]"

func (a *Adapter) checkRef(op stores.Op, ref stores.Ref) (location, error) {
	loc, ok := splitSecret(ref.Path)
	if !ok {
		return location{}, a.refuse(op, ref, stores.ErrInvalidRef, refShape)
	}
	if ref.Selectors != "" {
		return location{}, a.refuse(op, ref, stores.ErrInvalidRef, "1Password Connect serves only the current version of an item; selectors are not supported")
	}
	return loc, nil
}

// found is an item located by reference.
type found struct {
	vault apiVault
	sum   apiSummary
	full  *apiItem // set when the full item was asked for
	body  []byte   // the full item's response body
}

func (f *found) wipe() {
	if f.full != nil {
		f.full.wipe()
	}
	if f.body != nil {
		secret.WipeBytes(f.body)
	}
}

// locate finds the item loc names. With full set it fetches the whole item,
// values included; otherwise it uses item summaries only and never asks
// Connect for a value.
func (a *Adapter) locate(ctx context.Context, loc location, full bool) (*found, error) {
	v, err := a.c.vault(ctx, loc.vault)
	if err != nil {
		return nil, err
	}
	out := &found{vault: v}
	if full && isID(loc.item) {
		it, body, err := a.c.item(ctx, v.ID, loc.item)
		if err == nil {
			out.full, out.body, out.sum = it, body, it.apiSummary
			return out, nil
		}
		if !errors.Is(err, stores.ErrNotFound) {
			return nil, a.vaultGone(loc, err)
		}
	}
	sums, err := a.c.items(ctx, v.ID, loc.item)
	if err != nil {
		return nil, a.vaultGone(loc, err)
	}
	if len(sums) == 0 && isID(loc.item) && !full {
		all, err := a.c.items(ctx, v.ID, "")
		if err != nil {
			return nil, a.vaultGone(loc, err)
		}
		for _, s := range all {
			if s.ID == loc.item {
				sums = append(sums, s)
			}
		}
	}
	switch len(sums) {
	case 0:
		return nil, &apiError{kind: stores.ErrNotFound, msg: "no item " + quote(loc.item) + " in vault " + quote(loc.vault)}
	case 1:
	default:
		return nil, &apiError{kind: stores.ErrInvalidRef, msg: strconv.Itoa(len(sums)) + " items are titled " + quote(loc.item) + "; use the item ID"}
	}
	out.sum = sums[0]
	if full {
		it, body, err := a.c.item(ctx, v.ID, sums[0].ID)
		if err != nil {
			return nil, err
		}
		out.full, out.body, out.sum = it, body, it.apiSummary
	}
	return out, nil
}

// vaultGone drops the cached vault when Connect no longer knows it, so the
// next call looks the name up again.
func (a *Adapter) vaultGone(loc location, err error) error {
	if errors.Is(err, stores.ErrNotFound) {
		a.c.forgetVault(loc.vault)
	}
	return err
}

func (a *Adapter) meta(ref stores.Ref, f *found) stores.Metadata {
	m := stores.Metadata{
		Ref:       ref.Secret(),
		CreatedAt: f.sum.CreatedAt,
		UpdatedAt: f.sum.UpdatedAt,
		Labels:    labelsFor(f.vault, f.sum),
	}
	if f.sum.Version > 0 {
		m.Version = strconv.Itoa(f.sum.Version)
	}
	return m
}

// Read implements stores.Adapter.
func (a *Adapter) Read(ctx context.Context, ref stores.Ref) (stores.Secret, error) {
	loc, err := a.checkRef(stores.OpRead, ref)
	if err != nil {
		return stores.Secret{}, err
	}
	f, err := a.locate(ctx, loc, true)
	if err != nil {
		return stores.Secret{}, a.fail(stores.OpRead, ref, err)
	}
	defer f.wipe()
	m := a.meta(ref, f)
	views := fieldViews(f.full)
	for _, v := range views {
		if v.hasValue() {
			m.Fields = append(m.Fields, v.key)
		}
	}
	slices.Sort(m.Fields)
	sec := stores.Secret{Meta: m, Fields: map[string]secret.Value{}}
	if ref.Field != "" {
		v, msg, _ := selectField(views, ref.Field)
		if v == nil {
			kind := stores.ErrNotFound
			if !strings.HasPrefix(msg, "no field") {
				kind = stores.ErrInvalidRef
			}
			return stores.Secret{}, a.refuse(stores.OpRead, ref, kind, msg)
		}
		if !v.hasValue() {
			return stores.Secret{}, a.refuse(stores.OpRead, ref, stores.ErrNotFound, "field "+quote(ref.Field)+" is empty")
		}
		val, err := v.f.Value.Value()
		if err != nil {
			return stores.Secret{}, a.refuse(stores.OpRead, ref, stores.ErrUnavailable, "field "+quote(ref.Field)+": malformed value")
		}
		sec.Fields[ref.Field] = val
		return sec, nil
	}
	for _, v := range views {
		if !v.hasValue() {
			continue
		}
		val, err := v.f.Value.Value()
		if err != nil {
			sec.Wipe()
			return stores.Secret{}, a.refuse(stores.OpRead, ref, stores.ErrUnavailable, "field "+quote(v.key)+": malformed value")
		}
		sec.Fields[v.key] = val
	}
	return sec, nil
}

// ReadMetadata implements stores.MetadataReader. It uses the item listing
// (filtered by title), which carries no fields, so no value is fetched.
// Metadata.Fields stays empty: field names come only with the full item.
func (a *Adapter) ReadMetadata(ctx context.Context, ref stores.Ref) (stores.Metadata, error) {
	ref = ref.Secret()
	loc, err := a.checkRef(stores.OpRead, ref)
	if err != nil {
		return stores.Metadata{}, err
	}
	f, err := a.locate(ctx, loc, false)
	if err != nil {
		return stores.Metadata{}, a.fail(stores.OpRead, ref, err)
	}
	return a.meta(ref, f), nil
}

// listPrefix is a listing prefix: a vault and an optional title prefix.
type listPrefix struct {
	vault string
	title string // "" for the whole vault
	glob  bool   // title ends where a trailing * was
}

func splitPrefix(path string) (listPrefix, bool) {
	vault, rest, _ := strings.Cut(path, "/")
	if vault == "" || vault == "*" {
		return listPrefix{}, false
	}
	p := listPrefix{vault: vault}
	switch {
	case rest == "" || rest == "*":
	case strings.HasSuffix(rest, "/*"):
		p.title = strings.TrimSuffix(rest, "/*")
	case strings.HasSuffix(rest, "*"):
		p.title, p.glob = strings.TrimSuffix(rest, "*"), true
	default:
		p.title = rest
	}
	return p, true
}

func (p listPrefix) match(title string) bool {
	switch {
	case p.title == "":
		return true
	case p.glob:
		return strings.HasPrefix(title, p.title)
	}
	return title == p.title || strings.HasPrefix(title, p.title+"/")
}

// representable reports whether an item title can be a reference path
// segment as is; other items are listed by ID.
func representable(title string) bool {
	return title != "" && strings.Trim(title, "/") == title && !strings.Contains(title, "//") &&
		!strings.ContainsAny(title, "?#")
}

// List implements stores.Adapter. It reads the vault's item summaries only,
// never a value. Items whose title cannot be a reference path (empty, with
// "//", "?" or "#", or shared by several items) are listed by item ID.
func (a *Adapter) List(ctx context.Context, prefix stores.Ref) ([]stores.Metadata, error) {
	p, ok := splitPrefix(prefix.Path)
	if !ok {
		return nil, a.refuse(stores.OpList, prefix, stores.ErrInvalidRef, "want <vault>[/<item title prefix>][*]")
	}
	v, err := a.c.vault(ctx, p.vault)
	if err != nil {
		return nil, a.fail(stores.OpList, prefix, err)
	}
	sums, err := a.c.items(ctx, v.ID, "")
	if err != nil {
		return nil, a.fail(stores.OpList, prefix, a.vaultGone(location{vault: p.vault}, err))
	}
	titles := map[string]int{}
	for _, s := range sums {
		titles[s.Title]++
	}
	out := []stores.Metadata{}
	for _, s := range sums {
		if !p.match(s.Title) {
			continue
		}
		name := s.Title
		if !representable(name) || titles[name] > 1 {
			name = s.ID
		}
		ref := stores.Ref{Scheme: prefix.Scheme, Path: p.vault + "/" + name}
		out = append(out, a.meta(ref, &found{vault: v, sum: s}))
	}
	return out, nil
}

// WriteLabels implements stores.WriteLabeler: the labels an item written at
// ref gets, from the reference, the configured category and the vault cache,
// without contacting Connect.
func (a *Adapter) WriteLabels(ref stores.Ref) map[string]string {
	loc, ok := splitSecret(ref.Path)
	if !ok {
		return nil
	}
	v, cached := a.c.cachedVault(loc.vault)
	if !cached && !isID(loc.vault) {
		v.Name = loc.vault
	}
	if !cached && isID(loc.vault) {
		v.ID = loc.vault
	}
	return labelsFor(v, apiSummary{Title: loc.item, Category: a.s.category})
}

// Health implements stores.Adapter: the server answers its heartbeat and
// accepts the token.
func (a *Adapter) Health(ctx context.Context) error {
	if err := a.c.heartbeat(ctx); err != nil {
		return a.fail(stores.OpHealth, stores.Ref{}, err)
	}
	var vs []apiVault
	if err := a.c.getJSON(ctx, "/v1/vaults", nil, &vs); err != nil {
		return a.fail(stores.OpHealth, stores.Ref{}, err)
	}
	return nil
}
