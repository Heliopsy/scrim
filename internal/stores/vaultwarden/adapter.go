// SPDX-License-Identifier: AGPL-3.0-only

// Package vaultwarden is the store adapter for Vaultwarden and other
// Bitwarden-compatible servers (specs/secret-stores, "Vaultwarden adapter").
//
// The server is zero-knowledge, so the adapter logs in (API key preferred,
// password login as a fallback), syncs the vault and decrypts it locally with
// the master password, which it obtains from a configured reference at
// start. Item metadata (names, folders, collections, field names and
// scrim.* labels) is decrypted into an index; values are decrypted only when
// read, returned as secret.Value and not cached by the adapter.
//
// References address items by path:
//
//	vw://<folder or collection>/<item name>[?org=<organisation>][#<field>]
//	vw://<item name>#<field>            (item with no folder or collection)
//
// Field selectors are username, password, totp and notes on login items,
// private-key and public-key on SSH key items, notes on every item, and any
// custom field by name. Custom fields whose names start with "scrim." are
// catalog labels, never values. Every item also carries native
// "vaultwarden.*" labels describing its organisation, collections, folder
// and attributes (labels.go), which policy rules see as secret.labels.
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/fsperm"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/vaultwarden/bwcrypto"
)

// Kind is the adapter kind this package registers.
const Kind = "vaultwarden"

func init() {
	stores.DeclareMulti(Kind, multiAttrs...)
	stores.Register(Kind, func(_ context.Context, inst stores.Instance) (stores.Adapter, error) {
		o, err := decodeOptions(inst.Name, inst.Options)
		if err != nil {
			return nil, err
		}
		return New(inst.Name, o, inst.Resolve)
	})
}

// Resolver turns a secret reference into its value.
type Resolver func(ctx context.Context, ref config.SecretRef) (secret.Value, error)

// unlockRetry is the minimum time between two attempts to unlock with a
// missing or wrong unlock key, so a locked store does not run the KDF on
// every request.
const unlockRetry = 5 * time.Second

// Adapter is a Vaultwarden store instance.
type Adapter struct {
	name    string
	opts    Options
	resolve Resolver
	cl      *client

	mu          sync.Mutex
	sess        *session
	keys        *keyring
	v           *vault
	dirty       bool
	lockedErr   error
	lockedUntil time.Time
	orgWarnings []string
	closed      bool
}

var (
	_ stores.Adapter        = (*Adapter)(nil)
	_ stores.MetadataReader = (*Adapter)(nil)
	_ stores.WriteLabeler   = (*Adapter)(nil)
)

// New builds an adapter. It does not contact the server.
func New(name string, o Options, resolve Resolver) (*Adapter, error) {
	if o.URL == nil {
		return nil, fmt.Errorf("vaultwarden %s: no URL", name)
	}
	if err := o.validate(name); err != nil {
		return nil, err
	}
	if resolve == nil {
		return nil, fmt.Errorf("vaultwarden %s: no secret resolver", name)
	}
	if o.PollInterval == 0 {
		o.PollInterval = 30 * time.Second
	}
	if o.Timeout == 0 {
		o.Timeout = 30 * time.Second
	}
	hc, err := o.httpClient()
	if err != nil {
		return nil, err
	}
	return &Adapter{
		name:    name,
		opts:    o,
		resolve: resolve,
		cl:      newClient(o.URL, hc, o.deviceID(name)),
	}, nil
}

// Name implements stores.Adapter.
func (a *Adapter) Name() string { return a.name }

// Capabilities implements stores.Adapter. Watch polls the account revision
// date, which changes on any vault change, and syncs only then.
func (a *Adapter) Capabilities() stores.Capabilities {
	return stores.CapRead | stores.CapList | stores.CapWatch | stores.CapWrite
}

func (a *Adapter) fail(op stores.Op, ref stores.Ref, kind error, detail string, cause error) error {
	e := stores.NewError(a.name, op, ref, kind, cause)
	e.Detail = detail
	return e
}

// classify maps a client error to a store error kind.
func (a *Adapter) classify(op stores.Op, ref stores.Ref, what string, err error) error {
	if errors.Is(err, stores.ErrLocked) || errors.Is(err, stores.ErrUnavailable) ||
		errors.Is(err, stores.ErrPermission) || errors.Is(err, stores.ErrNotFound) {
		return err
	}
	if isTransport(err) {
		return a.fail(op, ref, stores.ErrUnavailable, what+": "+err.Error(), err)
	}
	switch st := httpStatus(err); {
	case st == 401 || st == 403:
		return a.fail(op, ref, stores.ErrPermission, what+": "+err.Error(), err)
	case st == 404:
		return a.fail(op, ref, stores.ErrNotFound, what+": "+err.Error(), err)
	case st == 409:
		return a.fail(op, ref, stores.ErrConflict, what+": "+err.Error(), err)
	case st == 400 && what == "login":
		// invalid_client / invalid_grant: the credentials are wrong.
		return a.fail(op, ref, stores.ErrPermission, what+": "+err.Error(), err)
	case st == 400 && strings.Contains(strings.ToLower(err.Error()), "out of date"):
		return a.fail(op, ref, stores.ErrConflict, what+": "+err.Error(), err)
	}
	return a.fail(op, ref, stores.ErrUnavailable, what+": "+err.Error(), err)
}

// resolveRef resolves a reference and checks it is not empty. A file
// reference is also checked to be readable by its owner only.
func (a *Adapter) resolveRef(ctx context.Context, ref config.SecretRef) (secret.Value, error) {
	if p, ok := strings.CutPrefix(string(ref), "file:"); ok {
		if fi, err := os.Stat(p); err == nil {
			if loose, detail, _ := fsperm.Loose(p, fi); loose {
				return secret.Value{}, fmt.Errorf("%s is readable by group or others (%s); restrict it to scrim", p, detail)
			}
		}
	}
	v, err := a.resolve(ctx, ref)
	if err != nil {
		return secret.Value{}, err
	}
	if v.IsZero() {
		v.Wipe()
		return secret.Value{}, errors.New("the reference resolved to an empty value")
	}
	return v, nil
}

// login obtains a session. The caller holds a.mu.
func (a *Adapter) login(ctx context.Context, op stores.Op) error {
	if a.sess != nil && time.Now().Before(a.sess.expires.Add(-time.Minute)) {
		return nil
	}
	a.dropSession()
	var (
		s   session
		err error
	)
	if a.opts.ClientID != "" {
		cs, rerr := a.resolveRef(ctx, a.opts.ClientSecret)
		if rerr != nil {
			return a.fail(op, stores.Ref{}, stores.ErrPermission, "client secret "+string(a.opts.ClientSecret)+": "+rerr.Error(), rerr)
		}
		s, err = a.cl.loginAPIKey(ctx, a.opts.ClientID, cs)
		cs.Wipe()
	} else {
		var hash secret.Value
		hash, err = a.passwordHash(ctx, op)
		if err != nil {
			return err
		}
		s, err = a.cl.loginPassword(ctx, a.opts.Email, hash)
		hash.Wipe()
	}
	if err != nil {
		return a.classify(op, stores.Ref{}, "login", err)
	}
	a.sess = &s
	return nil
}

// passwordHash derives the server authentication hash for password login.
func (a *Adapter) passwordHash(ctx context.Context, op stores.Op) (secret.Value, error) {
	p, err := a.cl.prelogin(ctx, a.opts.Email)
	if err != nil {
		return secret.Value{}, a.classify(op, stores.Ref{}, "prelogin", err)
	}
	pw, err := a.unlockSecret(ctx, op)
	if err != nil {
		return secret.Value{}, err
	}
	defer pw.Wipe()
	mk, err := bwcrypto.MasterKey(pw, a.opts.Email, p)
	if err != nil {
		return secret.Value{}, a.fail(op, stores.Ref{}, stores.ErrLocked, err.Error(), err)
	}
	defer mk.Wipe()
	h, err := bwcrypto.MasterPasswordHash(mk, pw)
	if err != nil {
		return secret.Value{}, a.fail(op, stores.Ref{}, stores.ErrLocked, err.Error(), err)
	}
	return h, nil
}

func (a *Adapter) unlockSecret(ctx context.Context, op stores.Op) (secret.Value, error) {
	if time.Now().Before(a.lockedUntil) && a.lockedErr != nil {
		return secret.Value{}, a.lockedErr
	}
	pw, err := a.resolveRef(ctx, a.opts.Unlock)
	if err != nil {
		a.lockedErr = a.fail(op, stores.Ref{}, stores.ErrLocked, "unlock key "+string(a.opts.Unlock)+" unavailable: "+err.Error(), err)
		a.lockedUntil = time.Now().Add(unlockRetry)
		return secret.Value{}, a.lockedErr
	}
	return pw, nil
}

func (a *Adapter) dropSession() {
	if a.sess != nil {
		a.sess.token.Wipe()
		a.sess = nil
	}
}

// unlock derives the user key and the organisation keys. The caller holds
// a.mu and has a session and a fresh sync.
func (a *Adapter) unlock(ctx context.Context, op stores.Op, s *syncResponse) error {
	if a.keys != nil {
		a.orgWarnings = append(a.orgWarnings, a.keys.addOrgs(s.Profile)...)
		return nil
	}
	email := s.Profile.Email
	if a.opts.Email != "" && !strings.EqualFold(strings.TrimSpace(a.opts.Email), strings.TrimSpace(email)) {
		return a.fail(op, stores.Ref{}, stores.ErrPermission, "the API key belongs to a different account than "+OptEmail, nil)
	}
	pw, err := a.unlockSecret(ctx, op)
	if err != nil {
		return err
	}
	defer pw.Wipe()
	uk, err := bwcrypto.UnlockUserKey(pw, email, a.sess.resp.params(), s.Profile.Key)
	if err != nil {
		var detail string
		switch {
		case errors.Is(err, bwcrypto.ErrMAC):
			detail = "the unlock key does not decrypt the account key (wrong master password?)"
		case errors.Is(err, bwcrypto.ErrUnsupported):
			detail = "the account key uses legacy unauthenticated encryption; rotate the account encryption key in a Bitwarden client"
		default:
			detail = err.Error()
		}
		a.lockedErr = a.fail(op, stores.Ref{}, stores.ErrLocked, detail, err)
		a.lockedUntil = time.Now().Add(unlockRetry)
		return a.lockedErr
	}
	a.keys = &keyring{user: uk, orgs: map[string]bwcrypto.SymmetricKey{}}
	a.lockedErr = nil
	a.orgWarnings = a.keys.addOrgs(s.Profile)
	return nil
}

// current returns an up-to-date vault: it logs in if needed, checks the
// revision date and syncs when it changed. Every call checks the server, so
// an outage is reported rather than hidden behind the last sync.
func (a *Adapter) current(ctx context.Context, op stores.Op) (*vault, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, a.fail(op, stores.Ref{}, stores.ErrUnavailable, "adapter closed", nil)
	}
	v, err := a.refresh(ctx, op)
	if err != nil && httpStatus(err) == 401 {
		a.dropSession()
		v, err = a.refresh(ctx, op)
	}
	return v, err
}

func (a *Adapter) refresh(ctx context.Context, op stores.Op) (*vault, error) {
	if err := a.login(ctx, op); err != nil {
		return nil, err
	}
	rev, err := a.cl.revisionDate(ctx, *a.sess)
	if err != nil {
		if httpStatus(err) == 401 {
			a.dropSession()
		}
		return nil, a.classify(op, stores.Ref{}, "revision date", err)
	}
	if a.v != nil && a.keys != nil && !a.dirty && a.v.revision == rev {
		return a.v, nil
	}
	s, err := a.cl.sync(ctx, *a.sess)
	if err != nil {
		if httpStatus(err) == 401 {
			a.dropSession()
		}
		return nil, a.classify(op, stores.Ref{}, "sync", err)
	}
	if err := a.unlock(ctx, op, s); err != nil {
		return nil, err
	}
	a.v = buildVault(s, a.keys, rev, a.opts.Scope, a.opts.MetaLabels)
	for _, o := range a.orgWarnings {
		a.v.warnings = append(a.v.warnings, "organisation key does not unwrap: "+o)
	}
	a.dirty = false
	return a.v, nil
}

func (a *Adapter) checkRef(op stores.Op, ref stores.Ref) error {
	if ref.Scheme == "" || ref.Path == "" {
		return a.fail(op, ref, stores.ErrInvalidRef, "empty path", nil)
	}
	for _, k := range selectorKeys(ref) {
		if k != "org" {
			return a.fail(op, ref, stores.ErrInvalidRef, "unknown selector "+strconv.Quote(k)+" (only org is supported)", nil)
		}
	}
	return nil
}

func selectorKeys(ref stores.Ref) []string {
	if ref.Selectors == "" {
		return nil
	}
	var keys []string
	for _, kv := range strings.Split(ref.Selectors, "&") {
		k, _, _ := strings.Cut(kv, "=")
		keys = append(keys, k)
	}
	return keys
}

func (a *Adapter) inScope(path string) bool {
	return inScope([]string{path}, a.opts.Scope)
}

func (a *Adapter) metadata(ref stores.Ref, path string, it *item) stores.Metadata {
	m := stores.Metadata{
		Ref:       stores.Ref{Scheme: ref.Scheme, Path: path, Selectors: ref.Selectors},
		Fields:    slices.Clone(it.fields),
		Version:   it.raw.RevisionDate,
		CreatedAt: it.created,
		UpdatedAt: it.updated,
	}
	if len(it.all) > 0 {
		m.Labels = maps.Clone(it.all)
	}
	return m
}

// locate finds the in-scope item ref names in an up-to-date vault. On
// success it returns with a.mu held and the keyring present, so the keys
// cannot be wiped while the caller uses the item; the caller unlocks.
func (a *Adapter) locate(ctx context.Context, op stores.Op, ref stores.Ref) (*item, error) {
	if err := a.checkRef(op, ref); err != nil {
		return nil, err
	}
	if !a.inScope(ref.Path) {
		return nil, a.fail(op, ref, stores.ErrNotFound, "outside the configured scope", nil)
	}
	v, err := a.current(ctx, op)
	if err != nil {
		return nil, err
	}
	it, path, err := v.lookup(ref.Path, ref.Selector("org"))
	if err != nil {
		return nil, a.fail(op, ref, stores.ErrInvalidRef, path, err)
	}
	if it == nil {
		return nil, a.fail(op, ref, stores.ErrNotFound, "", nil)
	}
	a.mu.Lock()
	if a.keys == nil {
		a.mu.Unlock()
		return nil, a.fail(op, ref, stores.ErrLocked, "", nil)
	}
	return it, nil
}

// ReadMetadata implements stores.MetadataReader. Everything it returns
// comes from the index built at the last sync (names, folders, collections,
// field names and labels, decrypted with the account and organisation keys
// as item metadata), so it decrypts no secret field. It checks the server
// and fails the way Read does: outside the scope or missing is
// ErrNotFound, an ambiguous path ErrInvalidRef, a locked or unreachable
// store its error. The labels are the ones Read reports for the item.
func (a *Adapter) ReadMetadata(ctx context.Context, ref stores.Ref) (stores.Metadata, error) {
	it, err := a.locate(ctx, stores.OpRead, ref)
	if err != nil {
		return stores.Metadata{}, err
	}
	defer a.mu.Unlock()
	if ref.Field != "" && !slices.Contains(it.fields, ref.Field) {
		return stores.Metadata{}, a.fail(stores.OpRead, ref, stores.ErrNotFound, "no field "+strconv.Quote(ref.Field), nil)
	}
	m := a.metadata(ref, ref.Path, it)
	m.Ref = ref.Secret()
	return m, nil
}

// Read implements stores.Adapter.
func (a *Adapter) Read(ctx context.Context, ref stores.Ref) (stores.Secret, error) {
	it, err := a.locate(ctx, stores.OpRead, ref)
	if err != nil {
		return stores.Secret{}, err
	}
	defer a.mu.Unlock()
	keys := a.keys
	want := it.fields
	if ref.Field != "" {
		want = []string{ref.Field}
	}
	out := stores.Secret{Meta: a.metadata(ref, ref.Path, it), Fields: map[string]secret.Value{}}
	out.Meta.Ref = ref.Secret()
	for _, f := range want {
		val, ok, err := it.decryptField(keys, f)
		if err != nil {
			out.Wipe()
			return stores.Secret{}, a.fail(stores.OpRead, ref, stores.ErrPermission, "field "+strconv.Quote(f)+" does not decrypt", err)
		}
		if !ok {
			if ref.Field != "" {
				out.Wipe()
				return stores.Secret{}, a.fail(stores.OpRead, ref, stores.ErrNotFound, "no field "+strconv.Quote(f), nil)
			}
			continue
		}
		out.Fields[f] = val
	}
	return out, nil
}

// List implements stores.Adapter. It returns one entry per matching path:
// an item in two collections under the prefix is listed twice.
func (a *Adapter) List(ctx context.Context, prefix stores.Ref) ([]stores.Metadata, error) {
	if err := a.checkRef(stores.OpList, prefix); err != nil {
		return nil, err
	}
	v, err := a.current(ctx, stores.OpList)
	if err != nil {
		return nil, err
	}
	org := prefix.Selector("org")
	var out []stores.Metadata
	for _, it := range v.items {
		if !it.inScope || !it.matchesOrg(org) {
			continue
		}
		for _, p := range it.paths {
			if underPrefix(p, prefix.Path) && a.inScope(p) {
				out = append(out, a.metadata(prefix, p, it))
			}
		}
	}
	slices.SortFunc(out, func(x, y stores.Metadata) int { return strings.Compare(x.Ref.Path, y.Ref.Path) })
	return out, nil
}

// Watch implements stores.Adapter by polling the account revision date every
// PollInterval and diffing item revisions under prefix.
func (a *Adapter) Watch(ctx context.Context, prefix stores.Ref) (<-chan stores.Change, error) {
	if err := a.checkRef(stores.OpWatch, prefix); err != nil {
		return nil, err
	}
	snapshot := func() (map[string]string, error) {
		v, err := a.current(ctx, stores.OpWatch)
		if err != nil {
			return nil, err
		}
		org := prefix.Selector("org")
		m := map[string]string{}
		for _, it := range v.items {
			if !it.inScope || !it.matchesOrg(org) {
				continue
			}
			for _, p := range it.paths {
				if underPrefix(p, prefix.Path) {
					m[p] = it.raw.ID + "@" + it.raw.RevisionDate
				}
			}
		}
		return m, nil
	}
	prev, err := snapshot()
	if err != nil && !errors.Is(err, stores.ErrUnavailable) {
		return nil, err
	}
	ch := make(chan stores.Change, 16)
	go func() {
		defer close(ch)
		t := time.NewTicker(a.opts.PollInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			cur, err := snapshot()
			if err != nil {
				continue // outage: keep the last snapshot and try again
			}
			var changes []stores.Change
			for p, r := range cur {
				if prev[p] != r {
					changes = append(changes, stores.Change{Ref: stores.Ref{Scheme: prefix.Scheme, Path: p, Selectors: prefix.Selectors}, Kind: stores.Changed})
				}
			}
			for p := range prev {
				if _, ok := cur[p]; !ok {
					changes = append(changes, stores.Change{Ref: stores.Ref{Scheme: prefix.Scheme, Path: p, Selectors: prefix.Selectors}, Kind: stores.Deleted})
				}
			}
			prev = cur
			for _, c := range changes {
				select {
				case ch <- c:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return ch, nil
}

// Health implements stores.Adapter: it logs in, unlocks and checks the
// revision date.
func (a *Adapter) Health(ctx context.Context) error {
	_, err := a.current(ctx, stores.OpHealth)
	return err
}

// Close implements stores.Adapter. It wipes the session token and keys.
func (a *Adapter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	a.dropSession()
	a.keys.wipe()
	a.keys = nil
	a.v = nil
	return nil
}

// Lock drops the keys and the session; the next operation unlocks again
// from the unlock reference.
func (a *Adapter) Lock() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.dropSession()
	a.keys.wipe()
	a.keys = nil
	a.v = nil
}

// Advice returns doctor findings for this instance: the dedicated-account
// recommendation (design D6), whether meta labels are on, and items that
// could not be decrypted.
func (a *Adapter) Advice(ctx context.Context) ([]string, error) {
	v, err := a.current(ctx, stores.OpHealth)
	if err != nil {
		return nil, err
	}
	var out []string
	outside := 0
	for _, it := range v.items {
		if !it.inScope {
			outside++
		}
	}
	switch {
	case len(a.opts.Scope) == 0 && len(v.items) > 0:
		out = append(out, fmt.Sprintf("vaultwarden %s: no %s is configured, so scrim can read all %d items of the account; a dedicated agent account or organisation is recommended", a.name, OptScope, len(v.items)))
	case outside > 0:
		out = append(out, fmt.Sprintf("vaultwarden %s: the account holds %d items outside the configured scope; a dedicated agent account or organisation is recommended", a.name, outside))
	}
	if a.opts.MetaLabels {
		out = append(out, fmt.Sprintf("vaultwarden %s: %s is on, so text custom fields are reported as vaultwarden.meta.* labels, visible in policy views and audit; keep secrets in hidden fields", a.name, OptMetaLabels))
	}
	out = append(out, v.warnings...)
	return out, nil
}

func jsonUnmarshal(b []byte, v any) error {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	return json.Unmarshal(b, v)
}
