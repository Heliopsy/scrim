// SPDX-License-Identifier: AGPL-3.0-only

package vaultwarden

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/vaultwarden/bwcrypto"
)

// Write implements stores.Adapter.
//
// On an existing item, the named fields are replaced and every other part of
// the item (other fields, URIs, history, attachments) is kept, so rotating a
// password keeps the username. Built-in selectors (username, password, totp)
// map to login fields on login items, notes to the item notes, and any other
// name to a hidden custom field. Labels are stored as text custom fields
// named "scrim.<key>".
//
// A new item is created as a login item. Without ?org= it goes into the
// personal vault, in the folder named by the path prefix (created if
// missing). With ?org= it goes into that organisation, in the existing
// collection named by the path prefix.
func (a *Adapter) Write(ctx context.Context, ref stores.Ref, fields map[string]secret.Value, opts stores.WriteOptions) (stores.Metadata, error) {
	ref = ref.Secret()
	if err := a.checkRef(stores.OpWrite, ref); err != nil {
		return stores.Metadata{}, err
	}
	if !a.inScope(ref.Path) {
		return stores.Metadata{}, a.fail(stores.OpWrite, ref, stores.ErrPermission, "outside the configured scope", nil)
	}
	if len(fields) == 0 {
		return stores.Metadata{}, a.fail(stores.OpWrite, ref, stores.ErrInvalidRef, "no fields to write", nil)
	}
	for name := range fields {
		if name == "" || strings.HasPrefix(name, LabelPrefix) {
			return stores.Metadata{}, a.fail(stores.OpWrite, ref, stores.ErrInvalidRef,
				"field name "+strconv.Quote(name)+" is empty or reserved for labels", nil)
		}
	}
	v, err := a.current(ctx, stores.OpWrite)
	if err != nil {
		return stores.Metadata{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.keys == nil {
		return stores.Metadata{}, a.fail(stores.OpWrite, ref, stores.ErrLocked, "", nil)
	}
	if a.sess == nil {
		return stores.Metadata{}, a.fail(stores.OpWrite, ref, stores.ErrUnavailable, "no session", nil)
	}
	it, detail, err := v.lookup(ref.Path, ref.Selector("org"))
	if err != nil {
		return stores.Metadata{}, a.fail(stores.OpWrite, ref, stores.ErrInvalidRef, detail, err)
	}
	var resp *cipherJSON
	if it != nil {
		if opts.CreateOnly {
			return stores.Metadata{}, a.fail(stores.OpWrite, ref, stores.ErrConflict, "item exists", nil)
		}
		resp, err = a.update(ctx, ref, v, it, fields, opts.Labels)
	} else {
		resp, err = a.create(ctx, ref, v, fields, opts.Labels)
	}
	if err != nil {
		return stores.Metadata{}, err
	}
	// The next operation syncs; the response is enough for the metadata.
	a.dirty = true
	written, derr := v.decryptItem(*resp, a.keys)
	if derr != nil {
		return stores.Metadata{Ref: ref, Version: resp.RevisionDate}, nil
	}
	if v.metaLabels {
		// Only the new item is guarded here: the vault's items are shared
		// with readers, and the next sync rebuilds them.
		guardMeta([]*item{written}, append(v.inScopeItems(), written), a.keys)
	}
	m := a.metadata(ref, ref.Path, written)
	m.Ref = ref
	return m, nil
}

// encFields encrypts fields into the cipher c, encrypted with key k.
// existing maps decrypted custom field names to their index in c.Fields.
func encFields(c *cipherJSON, k bwcrypto.SymmetricKey, fields map[string]secret.Value, existing map[string]int) error {
	for _, name := range slices.Sorted(maps.Keys(fields)) {
		enc, err := k.Encrypt(fields[name])
		if err != nil {
			return err
		}
		s := enc.String()
		if c.Type == cipherLogin && c.Login != nil {
			switch name {
			case FieldUsername:
				c.Login.Username = &s
				continue
			case FieldPassword:
				c.Login.Password = &s
				continue
			case FieldTOTP:
				c.Login.Totp = &s
				continue
			}
		}
		if name == FieldNotes {
			c.Notes = &s
			continue
		}
		if i, ok := existing[name]; ok {
			c.Fields[i].Value = &s
			continue
		}
		en, err := k.EncryptMetadata(name)
		if err != nil {
			return err
		}
		ns := en.String()
		c.Fields = append(c.Fields, fieldJSON{Type: fieldHidden, Name: &ns, Value: &s})
		existing[name] = len(c.Fields) - 1
	}
	return nil
}

// labelName normalises a label key to its custom field name.
func labelName(k string) string {
	if strings.HasPrefix(k, LabelPrefix) {
		return k
	}
	return LabelPrefix + k
}

func encLabels(c *cipherJSON, k bwcrypto.SymmetricKey, labels map[string]string, existing map[string]int) error {
	for _, key := range slices.Sorted(maps.Keys(labels)) {
		name := labelName(key)
		ev, err := k.EncryptMetadata(labels[key])
		if err != nil {
			return err
		}
		vs := ev.String()
		if i, ok := existing[name]; ok {
			c.Fields[i].Value = &vs
			c.Fields[i].Type = fieldText
			continue
		}
		en, err := k.EncryptMetadata(name)
		if err != nil {
			return err
		}
		ns := en.String()
		c.Fields = append(c.Fields, fieldJSON{Type: fieldText, Name: &ns, Value: &vs})
		existing[name] = len(c.Fields) - 1
	}
	return nil
}

func (a *Adapter) update(ctx context.Context, ref stores.Ref, v *vault, it *item, fields map[string]secret.Value, labels map[string]string) (*cipherJSON, error) {
	if it.raw.Type != cipherLogin && it.raw.Type != cipherSecureNote {
		return nil, a.fail(stores.OpWrite, ref, stores.ErrUnsupported, "only login and secure note items can be written", nil)
	}
	k, owned, err := cipherKey(it.raw, a.keys)
	if err != nil {
		return nil, a.fail(stores.OpWrite, ref, stores.ErrPermission, err.Error(), err)
	}
	if owned {
		defer k.Wipe()
	}
	c := it.raw // copy; deep-copy the parts that change
	c.Fields = slices.Clone(it.raw.Fields)
	if it.raw.Login != nil {
		l := *it.raw.Login
		c.Login = &l
	}
	existing := maps.Clone(it.custom)
	for name, i := range it.labelIdx {
		existing[name] = i
	}
	if err := encFields(&c, k, fields, existing); err != nil {
		return nil, a.fail(stores.OpWrite, ref, stores.ErrPermission, "encryption failed", err)
	}
	if err := encLabels(&c, k, labels, existing); err != nil {
		return nil, a.fail(stores.OpWrite, ref, stores.ErrPermission, "encryption failed", err)
	}
	rev := it.raw.RevisionDate
	req := &cipherRequest{cipherJSON: c, LastKnownRevisionDate: &rev, EncryptedFor: v.userID}
	resp, err := a.cl.updateCipher(ctx, *a.sess, it.raw.ID, req)
	if err != nil {
		return nil, a.classify(stores.OpWrite, ref, "update item", err)
	}
	return resp, nil
}

func (a *Adapter) create(ctx context.Context, ref stores.Ref, v *vault, fields map[string]secret.Value, labels map[string]string) (*cipherJSON, error) {
	container, name := "", ref.Path
	if i := strings.LastIndexByte(ref.Path, '/'); i >= 0 {
		container, name = ref.Path[:i], ref.Path[i+1:]
	}
	c := cipherJSON{Type: cipherLogin, Login: &loginJSON{}}
	var (
		key         = a.keys.user
		collections []string
	)
	if org := ref.Selector("org"); org != "" {
		orgID := ""
		for id, n := range v.orgNames {
			if id == org || n == org {
				orgID = id
			}
		}
		ok, has := a.keys.orgs[orgID]
		if orgID == "" || !has {
			return nil, a.fail(stores.OpWrite, ref, stores.ErrNotFound, "organisation "+strconv.Quote(org)+" not found or its key is unavailable", nil)
		}
		if container == "" {
			return nil, a.fail(stores.OpWrite, ref, stores.ErrInvalidRef, "an organisation item needs a collection: <collection>/<item>", nil)
		}
		for id, cn := range v.collNames {
			if cn == container && v.collections[id].OrganizationID == orgID {
				if v.collections[id].ReadOnly {
					return nil, a.fail(stores.OpWrite, ref, stores.ErrPermission, "collection "+strconv.Quote(container)+" is read-only for this account", nil)
				}
				collections = append(collections, id)
			}
		}
		if len(collections) == 0 {
			return nil, a.fail(stores.OpWrite, ref, stores.ErrNotFound, "collection "+strconv.Quote(container)+" not found in the organisation", nil)
		}
		key = ok
		c.OrganizationID = &orgID
	} else if container != "" {
		folderID := ""
		for id, fn := range v.folders {
			if fn == container {
				folderID = id
				break
			}
		}
		if folderID == "" {
			en, err := a.keys.user.EncryptMetadata(container)
			if err != nil {
				return nil, a.fail(stores.OpWrite, ref, stores.ErrPermission, "encryption failed", err)
			}
			id, err := a.cl.createFolder(ctx, *a.sess, en.String())
			if err != nil {
				return nil, a.classify(stores.OpWrite, ref, "create folder", err)
			}
			folderID = id
		}
		c.FolderID = &folderID
	}
	en, err := key.EncryptMetadata(name)
	if err != nil {
		return nil, a.fail(stores.OpWrite, ref, stores.ErrPermission, "encryption failed", err)
	}
	c.Name = en.String()
	existing := map[string]int{}
	if err := encFields(&c, key, fields, existing); err != nil {
		return nil, a.fail(stores.OpWrite, ref, stores.ErrPermission, "encryption failed", err)
	}
	if err := encLabels(&c, key, labels, existing); err != nil {
		return nil, a.fail(stores.OpWrite, ref, stores.ErrPermission, "encryption failed", err)
	}
	resp, err := a.cl.createCipher(ctx, *a.sess, &cipherRequest{cipherJSON: c, EncryptedFor: v.userID}, collections)
	if err != nil {
		if errors.Is(err, stores.ErrConflict) {
			return nil, err
		}
		return nil, a.classify(stores.OpWrite, ref, "create item", err)
	}
	return resp, nil
}

// WriteLabels returns the native labels the item at ref carries after a
// write, so store.write rules can match where a write lands before it
// happens. For an existing item these are its current labels; for a new one
// they are derived from the reference the way create places the item: the
// organisation from ?org=, then the collection (with ?org=) or the folder
// (without) from the path prefix. It uses the last sync and never contacts
// the server; before the first sync it falls back to the reference alone.
func (a *Adapter) WriteLabels(ref stores.Ref) map[string]string {
	ref = ref.Secret()
	a.mu.Lock()
	v := a.v
	a.mu.Unlock()
	org := ref.Selector("org")
	if v != nil {
		if it, _, err := v.lookup(ref.Path, org); err == nil && it != nil {
			return maps.Clone(it.all)
		}
	}
	container, name := "", ref.Path
	if i := strings.LastIndexByte(ref.Path, '/'); i >= 0 {
		container, name = ref.Path[:i], ref.Path[i+1:]
	}
	n := nativeLabels{}
	n.set("name", name)
	n.set("type", typeName(cipherLogin))
	if org == "" {
		n.set("owner", "personal")
		if container != "" {
			n.setFolder(container)
			if v != nil {
				for id, fn := range v.folders {
					if fn == container {
						n.set("folder-id", id)
					}
				}
			}
		}
		return mergeNative(nil, n)
	}
	n.set("owner", "org")
	orgID := ""
	if v != nil {
		for id, on := range v.orgNames {
			if id == org || on == org {
				orgID = id
			}
		}
	}
	if orgID == "" {
		// No sync yet or an unknown organisation: report what the
		// reference says. create refuses an unknown organisation.
		if isUUID(org) {
			n.set("org.id", strings.ToLower(org))
		} else {
			n.set("org", org)
		}
	} else {
		n.set("org.id", orgID)
		if on := v.orgNames[orgID]; on != "" {
			n.set("org", on)
		}
		if r, ok := v.orgRoles[orgID]; ok {
			n.set("org.role", orgRole(r))
		}
	}
	if container != "" {
		var ids []string
		if orgID != "" {
			for id, cn := range v.collNames {
				if cn == container && v.collections[id].OrganizationID == orgID {
					ids = append(ids, id)
				}
			}
		}
		if len(ids) > 0 {
			v.addCollections(n, ids)
		} else {
			n.setNested("collection", container)
		}
	}
	return mergeNative(nil, n)
}

// isUUID reports whether s has the 8-4-4-4-12 hex form of a Bitwarden id.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
				return false
			}
		}
	}
	return true
}
