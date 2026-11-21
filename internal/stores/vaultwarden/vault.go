// SPDX-License-Identifier: AGPL-3.0-only

package vaultwarden

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores/vaultwarden/bwcrypto"
)

// LabelPrefix marks custom fields that hold catalog metadata instead of a
// value: a field named "scrim.hosts" on an item is returned as the label
// scrim.hosts and is never treated as a secret.
const LabelPrefix = "scrim."

// Built-in field selectors. A custom field with one of these names is
// shadowed by the built-in on login items.
const (
	FieldUsername   = "username"
	FieldPassword   = "password"
	FieldTOTP       = "totp"
	FieldNotes      = "notes"
	FieldPrivateKey = "private-key"
	FieldPublicKey  = "public-key"
)

// keyring holds the unlocked keys of an account: the user key and the keys
// of the organisations the account belongs to.
type keyring struct {
	user bwcrypto.SymmetricKey
	orgs map[string]bwcrypto.SymmetricKey
}

func (k *keyring) wipe() {
	if k == nil {
		return
	}
	k.user.Wipe()
	for _, o := range k.orgs {
		o.Wipe()
	}
}

// addOrgs unwraps organisation keys the keyring does not hold yet. A key
// that does not unwrap leaves that organisation inaccessible, it does not
// fail the whole vault.
func (k *keyring) addOrgs(p profileJSON) []string {
	var missing []string
	var pk *bwcrypto.PrivateKey
	for _, o := range p.Organizations {
		if _, ok := k.orgs[o.ID]; ok || o.Key == "" {
			continue
		}
		if pk == nil {
			key, err := bwcrypto.DecryptPrivateKey(k.user, p.PrivateKey)
			if err != nil {
				return append(missing, "all organisations: private key does not decrypt")
			}
			pk = &key
		}
		ok, err := pk.DecryptKey(o.Key)
		if err != nil {
			missing = append(missing, o.Name)
			continue
		}
		k.orgs[o.ID] = ok
	}
	return missing
}

// item is one cipher with its metadata decrypted. Values stay encrypted
// until a read asks for them.
type item struct {
	raw      cipherJSON
	name     string
	orgID    string
	orgName  string
	paths    []string
	fields   []string          // value-bearing field selectors present on the item
	custom   map[string]int    // custom field name -> index in raw.Fields
	labels   map[string]string // scrim.* label name -> value
	labelIdx map[string]int    // scrim.* label name -> index in raw.Fields
	// all is what metadata reports: the scrim.* labels, the text custom
	// fields as vaultwarden.meta.* that passed the guard, and the native
	// vaultwarden.* labels.
	all map[string]string
	// meta holds vaultwarden.meta.* candidates until guardMeta checks them;
	// native holds the native labels.
	meta     map[string]string
	native   nativeLabels
	created  time.Time
	updated  time.Time
	inScope  bool
	personal bool
}

// vault is an immutable decrypted index of one sync.
type vault struct {
	revision    int64
	email       string
	userID      string
	orgNames    map[string]string // id -> name
	orgRoles    map[string]int    // id -> this account's role
	folders     map[string]string // id -> name
	collections map[string]collectionJSON
	collNames   map[string]string // id -> decrypted name
	items       []*item
	warnings    []string
	// metaLabels copies text custom fields into vaultwarden.meta.* labels.
	metaLabels bool
	// scope is the configured scope; text field values and secret values
	// of items outside it are never decrypted for meta labels.
	scope []string
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

// buildVault decrypts the metadata of a sync response with the keyring.
// metaLabels reports text custom fields as vaultwarden.meta.* labels.
// Items whose key is unavailable or whose metadata does not decrypt are
// skipped and reported in warnings, by id only.
func buildVault(s *syncResponse, keys *keyring, revision int64, scope []string, metaLabels bool) *vault {
	v := &vault{
		metaLabels:  metaLabels,
		scope:       scope,
		revision:    revision,
		email:       s.Profile.Email,
		userID:      s.Profile.ID,
		orgNames:    map[string]string{},
		orgRoles:    map[string]int{},
		folders:     map[string]string{},
		collections: map[string]collectionJSON{},
		collNames:   map[string]string{},
	}
	for _, o := range s.Profile.Organizations {
		v.orgNames[o.ID] = o.Name
		if o.Type != nil {
			v.orgRoles[o.ID] = *o.Type
		}
	}
	for _, f := range s.Folders {
		name, err := keys.user.DecryptMetadata(f.Name)
		if err != nil {
			v.warnings = append(v.warnings, "folder "+f.ID+" name does not decrypt")
			continue
		}
		v.folders[f.ID] = name
	}
	for _, c := range s.Collections {
		ok, has := keys.orgs[c.OrganizationID]
		if !has {
			continue
		}
		name, err := ok.DecryptMetadata(c.Name)
		if err != nil {
			v.warnings = append(v.warnings, "collection "+c.ID+" name does not decrypt")
			continue
		}
		v.collections[c.ID] = c
		v.collNames[c.ID] = name
	}
	for i := range s.Ciphers {
		c := s.Ciphers[i]
		if c.DeletedDate != nil {
			continue
		}
		it, err := v.decryptItem(c, keys)
		if err != nil {
			v.warnings = append(v.warnings, "item "+c.ID+": "+err.Error())
			continue
		}
		it.inScope = inScope(it.paths, scope)
		v.items = append(v.items, it)
	}
	if metaLabels {
		guardMeta(v.items, v.inScopeItems(), keys)
	}
	return v
}

// cipherKey returns the key an item's strings are encrypted with: its own
// item key if it has one, otherwise its organisation's key or the user key.
// The caller wipes the result when owned is true.
func cipherKey(c cipherJSON, keys *keyring) (k bwcrypto.SymmetricKey, owned bool, err error) {
	base := keys.user
	if c.OrganizationID != nil && *c.OrganizationID != "" {
		ok, has := keys.orgs[*c.OrganizationID]
		if !has {
			return bwcrypto.SymmetricKey{}, false, errors.New("organisation key unavailable")
		}
		base = ok
	}
	if c.Key == nil || *c.Key == "" {
		return base, false, nil
	}
	ik, err := base.DecryptKey(*c.Key)
	if err != nil {
		return bwcrypto.SymmetricKey{}, false, fmt.Errorf("item key: %w", err)
	}
	return ik, true, nil
}

func (v *vault) decryptItem(c cipherJSON, keys *keyring) (*item, error) {
	k, owned, err := cipherKey(c, keys)
	if err != nil {
		return nil, err
	}
	if owned {
		defer k.Wipe()
	}
	name, err := k.DecryptMetadata(c.Name)
	if err != nil {
		return nil, fmt.Errorf("name: %w", err)
	}
	it := &item{
		raw:      c,
		name:     name,
		custom:   map[string]int{},
		labels:   map[string]string{},
		labelIdx: map[string]int{},
		created:  parseTime(c.CreationDate),
		updated:  parseTime(c.RevisionDate),
	}
	if c.OrganizationID != nil && *c.OrganizationID != "" {
		it.orgID = *c.OrganizationID
		it.orgName = v.orgNames[it.orgID]
	} else {
		it.personal = true
	}
	var folder, folderID string
	if c.FolderID != nil {
		if f, ok := v.folders[*c.FolderID]; ok {
			it.paths = append(it.paths, f+"/"+name)
			folder, folderID = f, *c.FolderID
		}
	}
	var colls []string
	for _, cid := range c.CollectionIDs {
		if cn, ok := v.collNames[cid]; ok {
			it.paths = append(it.paths, cn+"/"+name)
			colls = append(colls, cid)
		}
	}
	if len(it.paths) == 0 {
		it.paths = []string{name}
	}

	add := func(f string) {
		if !slices.Contains(it.fields, f) {
			it.fields = append(it.fields, f)
		}
	}
	if c.Type == cipherLogin && c.Login != nil {
		if c.Login.Username != nil && *c.Login.Username != "" {
			add(FieldUsername)
		}
		if c.Login.Password != nil && *c.Login.Password != "" {
			add(FieldPassword)
		}
		if c.Login.Totp != nil && *c.Login.Totp != "" {
			add(FieldTOTP)
		}
	}
	if c.Type == cipherSSHKey && len(c.SSHKey) > 0 {
		add(FieldPrivateKey)
		add(FieldPublicKey)
	}
	if c.Notes != nil && *c.Notes != "" {
		add(FieldNotes)
	}
	for i, f := range c.Fields {
		if f.Name == nil || f.Type == fieldLinked {
			continue
		}
		fn, err := k.DecryptMetadata(*f.Name)
		if err != nil {
			return nil, fmt.Errorf("field name: %w", err)
		}
		if strings.HasPrefix(fn, LabelPrefix) {
			// Catalog metadata: decrypted eagerly, never a value.
			val := ""
			if f.Value != nil {
				if val, err = k.DecryptMetadata(*f.Value); err != nil {
					return nil, fmt.Errorf("label %s: %w", fn, err)
				}
			}
			if _, dup := it.labels[fn]; !dup {
				it.labels[fn] = val
				it.labelIdx[fn] = i
			}
			continue
		}
		if _, dup := it.custom[fn]; dup {
			continue // first field of a name wins, as in Bitwarden clients
		}
		if f.Type == fieldText && v.metaLabels && f.Value != nil && inScope(it.paths, v.scope) {
			// A text field is shown in clear by Bitwarden clients: item
			// metadata. Hidden fields never become labels.
			if val, err := k.DecryptMetadata(*f.Value); err == nil {
				if it.meta == nil {
					it.meta = map[string]string{}
				}
				addMeta(it.meta, fn, val)
			}
		}
		it.custom[fn] = i
		if c.Type == cipherLogin && isLoginBuiltin(fn) {
			continue // shadowed by the built-in
		}
		add(fn)
	}
	sort.Strings(it.fields)
	it.native = v.native(it, k, folder, folderID, colls)
	it.finish()
	return it, nil
}

// finish computes the reported labels from the scrim.* labels, the meta
// candidates still standing and the native labels.
func (it *item) finish() {
	user := maps.Clone(it.labels)
	if user == nil {
		user = map[string]string{}
	}
	maps.Copy(user, it.meta)
	it.all = mergeNative(user, it.native)
}

// inScopeItems returns the items inside the configured scope.
func (v *vault) inScopeItems() []*item {
	var out []*item
	for _, it := range v.items {
		if it.inScope {
			out = append(out, it)
		}
	}
	return out
}

// guardMeta is the second guard on vaultwarden.meta.* labels: it drops every
// candidate of targets whose value equals or contains a secret value of any
// of sources (passwords, usernames, TOTP seeds, notes, SSH keys and hidden
// custom fields), the values scrim can load into the redaction set from this
// store. Text and boolean custom fields are not secret values here: they are
// what meta labels describe. Values are decrypted one at a time and wiped.
// If a value does not decrypt, the guard cannot vouch for anything and drops
// every candidate. Only targets change, so items shared with readers can be
// left out of them. Callers pass only in-scope items as sources: items
// outside the configured scope are never decrypted (design D6), so a text
// field repeating an out-of-scope secret is not caught.
func guardMeta(targets, sources []*item, keys *keyring) {
	var cands []*item
	for _, it := range targets {
		if len(it.meta) > 0 {
			cands = append(cands, it)
		}
	}
	if len(cands) == 0 {
		return
	}
	failed := false
	for _, it := range sources {
		for _, f := range it.secretFields() {
			val, ok, err := it.decryptField(keys, f)
			if err != nil {
				failed = true
				continue
			}
			if !ok {
				continue
			}
			_ = val.Expose(func(b []byte) error {
				if len(b) == 0 {
					return nil
				}
				for _, c := range cands {
					for k, m := range c.meta {
						if bytes.Contains([]byte(m), b) {
							delete(c.meta, k)
						}
					}
				}
				return nil
			})
			val.Wipe()
		}
	}
	for _, c := range cands {
		if failed {
			c.meta = nil
		}
		c.finish()
	}
}

// secretFields lists the item's value selectors other than text and boolean
// custom fields.
func (it *item) secretFields() []string {
	var out []string
	for _, f := range it.fields {
		if i, ok := it.custom[f]; ok && !isLoginBuiltinOn(it, f) {
			if t := it.raw.Fields[i].Type; t == fieldText || t == fieldBoolean {
				continue
			}
		}
		out = append(out, f)
	}
	return out
}

// isLoginBuiltinOn reports whether f names a built-in field of the item
// rather than its custom field of the same name.
func isLoginBuiltinOn(it *item, f string) bool {
	switch {
	case f == FieldNotes:
		return true
	case it.raw.Type == cipherSSHKey:
		return f == FieldPrivateKey || f == FieldPublicKey
	}
	return it.raw.Type == cipherLogin && isLoginBuiltin(f)
}

// native computes the native labels of an item from the sync data. k is the
// item's key, used only to decrypt login URIs.
func (v *vault) native(it *item, k bwcrypto.SymmetricKey, folder, folderID string, colls []string) nativeLabels {
	c := it.raw
	n := nativeLabels{}
	n.set("id", c.ID)
	n.set("name", it.name)
	n.set("type", typeName(c.Type))
	if it.personal {
		n.set("owner", "personal")
	} else {
		n.set("owner", "org")
		n.set("org.id", it.orgID)
		if it.orgName != "" {
			n.set("org", it.orgName)
		}
		if r, ok := v.orgRoles[it.orgID]; ok {
			n.set("org.role", orgRole(r))
		}
	}
	if folder != "" {
		n.set("folder", folder)
		n.set("folder-id", folderID)
		for _, f := range ancestors(folder) {
			n[nativePrefix+"folder."+f] = "true"
		}
	}
	v.addCollections(n, colls)
	n.setBool("favorite", c.Favorite)
	n.setBool("reprompt", c.Reprompt != 0)
	n.setBool("item-key", c.Key != nil && *c.Key != "")
	n.setBool("has-notes", c.Notes != nil && *c.Notes != "")
	n.setBool("has-attachments", hasEntries(c.Attachments))
	if c.Edit != nil {
		n.setBool("edit", *c.Edit)
	}
	if c.ViewPassword != nil {
		n.setBool("view-password", *c.ViewPassword)
	}
	if c.RevisionDate != "" {
		n.set("revision-date", c.RevisionDate)
	}
	if c.CreationDate != "" {
		n.set("creation-date", c.CreationDate)
	}
	if c.Type == cipherLogin {
		l := c.Login
		if l == nil {
			l = &loginJSON{}
		}
		set := func(p *string) bool { return p != nil && *p != "" }
		n.setBool("has-username", set(l.Username))
		n.setBool("has-password", set(l.Password))
		n.setBool("has-totp", set(l.Totp))
		n.setBool("has-passkey", hasEntries(l.Fido2Credentials))
		if set(l.PasswordRevisionDate) {
			n.set("password-revision-date", *l.PasswordRevisionDate)
		}
		n.setMulti("uri-host", false, uriHosts(loginURIs(l.URIs, k))...)
	}
	return n
}

// addCollections records the collections with the given ids and this
// account's permissions on them.
func (v *vault) addCollections(n nativeLabels, ids []string) {
	var names, readOnly, hide, manage []string
	for _, cid := range ids {
		cn := v.collNames[cid]
		names = append(names, cn)
		cj := v.collections[cid]
		if cj.ReadOnly {
			readOnly = append(readOnly, cn)
		}
		if cj.HidePasswords {
			hide = append(hide, cn)
		}
		if cj.Manage != nil && *cj.Manage {
			manage = append(manage, cn)
		}
	}
	n.setMulti("collection", true, names...)
	n.setMulti("collection-id", false, ids...)
	n.setMulti("collection-read-only", true, readOnly...)
	n.setMulti("collection-hide-passwords", true, hide...)
	n.setMulti("collection-manage", true, manage...)
}

// loginURIs decrypts the URIs of a login item, skipping those matched as
// regular expressions and those that do not decrypt.
func loginURIs(raw []byte, k bwcrypto.SymmetricKey) []string {
	var uris []struct {
		URI   *string `json:"uri"`
		Match *int    `json:"match"`
	}
	if err := jsonUnmarshal(raw, &uris); err != nil {
		return nil
	}
	var out []string
	for _, u := range uris {
		if u.URI == nil || *u.URI == "" || (u.Match != nil && *u.Match == uriMatchRegex) {
			continue
		}
		if s, err := k.DecryptMetadata(*u.URI); err == nil {
			out = append(out, s)
		}
	}
	return out
}

// hasEntries reports whether a JSON array has at least one element.
func hasEntries(raw []byte) bool {
	var xs []json.RawMessage
	return jsonUnmarshal(raw, &xs) == nil && len(xs) > 0
}

func isLoginBuiltin(name string) bool {
	switch name {
	case FieldUsername, FieldPassword, FieldTOTP, FieldNotes:
		return true
	}
	return false
}

// inScope reports whether any path lies under one of the scope prefixes. An
// empty scope admits everything.
func inScope(paths, scope []string) bool {
	if len(scope) == 0 {
		return true
	}
	for _, p := range paths {
		for _, s := range scope {
			if underPrefix(p, s) {
				return true
			}
		}
	}
	return false
}

// underPrefix reports whether path equals prefix or lies below it on a
// segment boundary.
func underPrefix(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

// errAmbiguous is returned when a path matches more than one item.
var errAmbiguous = errors.New("ambiguous")

// lookup finds the in-scope item at path, optionally restricted to one
// organisation (by name or id).
func (v *vault) lookup(path, org string) (*item, string, error) {
	var found *item
	n := 0
	for _, it := range v.items {
		if !it.inScope || !it.matchesOrg(org) || !slices.Contains(it.paths, path) {
			continue
		}
		found = it
		n++
	}
	switch {
	case n == 0:
		return nil, "", nil
	case n > 1:
		return nil, fmt.Sprintf("%d items match; rename one or add ?org=", n), errAmbiguous
	}
	return found, path, nil
}

func (it *item) matchesOrg(org string) bool {
	if org == "" {
		return true
	}
	return it.orgID == org || it.orgName == org
}

// decryptField decrypts one field selector of the item. ok is false when the
// item has no such field.
func (it *item) decryptField(keys *keyring, field string) (val secret.Value, ok bool, err error) {
	k, owned, err := cipherKey(it.raw, keys)
	if err != nil {
		return secret.Value{}, false, err
	}
	if owned {
		defer k.Wipe()
	}
	dec := func(p *string) (secret.Value, bool, error) {
		if p == nil || *p == "" {
			return secret.Value{}, false, nil
		}
		v, err := k.DecryptString(*p)
		return v, err == nil, err
	}
	c := it.raw
	if c.Type == cipherLogin && c.Login != nil {
		switch field {
		case FieldUsername:
			return dec(c.Login.Username)
		case FieldPassword:
			return dec(c.Login.Password)
		case FieldTOTP:
			return dec(c.Login.Totp)
		}
	}
	if field == FieldNotes {
		return dec(c.Notes)
	}
	if c.Type == cipherSSHKey && (field == FieldPrivateKey || field == FieldPublicKey) {
		var sk struct {
			PrivateKey *string `json:"privateKey"`
			PublicKey  *string `json:"publicKey"`
		}
		if err := jsonUnmarshal(c.SSHKey, &sk); err != nil {
			return secret.Value{}, false, err
		}
		if field == FieldPrivateKey {
			return dec(sk.PrivateKey)
		}
		return dec(sk.PublicKey)
	}
	if strings.HasPrefix(field, LabelPrefix) {
		return secret.Value{}, false, nil
	}
	i, has := it.custom[field]
	if !has {
		return secret.Value{}, false, nil
	}
	return dec(c.Fields[i].Value)
}
