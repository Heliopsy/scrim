// SPDX-License-Identifier: AGPL-3.0-only

package vaultwarden

import (
	"errors"
	"fmt"
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
	folders     map[string]string // id -> name
	collections map[string]collectionJSON
	collNames   map[string]string // id -> decrypted name
	items       []*item
	warnings    []string
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

// buildVault decrypts the metadata of a sync response with the keyring.
// Items whose key is unavailable or whose metadata does not decrypt are
// skipped and reported in warnings, by id only.
func buildVault(s *syncResponse, keys *keyring, revision int64, scope []string) *vault {
	v := &vault{
		revision:    revision,
		email:       s.Profile.Email,
		userID:      s.Profile.ID,
		orgNames:    map[string]string{},
		folders:     map[string]string{},
		collections: map[string]collectionJSON{},
		collNames:   map[string]string{},
	}
	for _, o := range s.Profile.Organizations {
		v.orgNames[o.ID] = o.Name
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
	if c.FolderID != nil {
		if f, ok := v.folders[*c.FolderID]; ok {
			it.paths = append(it.paths, f+"/"+name)
		}
	}
	for _, cid := range c.CollectionIDs {
		if cn, ok := v.collNames[cid]; ok {
			it.paths = append(it.paths, cn+"/"+name)
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
		it.custom[fn] = i
		if c.Type == cipherLogin && isLoginBuiltin(fn) {
			continue // shadowed by the built-in
		}
		add(fn)
	}
	sort.Strings(it.fields)
	return it, nil
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
