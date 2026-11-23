// SPDX-License-Identifier: AGPL-3.0-only

package openbao

import (
	"context"

	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/vaultapi"
)

// Store-native labels (docs/stores/openbao.md "Labels").
//
// Every attribute OpenBao reports about a secret, its mount and the
// configured namespace goes into stores.Metadata.Labels under
// "openbao.<attr>", so policy rules can match on them through
// secret.labels. A list attribute is stored comma-joined under its key and
// once more as one presence key per value, verbatim
// ("openbao.ancestors": "prod,prod/eu", "openbao.ancestors.prod": "true",
// ...). KV v2 custom metadata appears as "openbao.meta.<key>" and, as
// before, under its own key, except keys under "openbao." or "store.".
// Native keys are set first and never overwritten. Labels carry metadata
// only, never a value.
//
// The keys follow the shared convention of stores.SetNative,
// stores.UserMeta and stores.LabelKey; the list attributes are declared
// multi-valued in init.

// multiAttrs are the list attributes: they get presence keys even with one
// value.
var multiAttrs = vaultapi.MultiAttrs

// The label builder is shared with the vault adapter (vaultapi.KVLabels).
type (
	labelInput = vaultapi.KVLabelInput
	secretMeta = vaultapi.KVMetadata
)

// mountInfo is what the store says about a mount (vaultapi.MountInfo).
type mountInfo = vaultapi.MountInfo

// mountTTL is how long mount information, or the lack of it, is kept.
const mountTTL = vaultapi.MountTTL

// mount returns the mount's information, asking the store at most once per
// mountTTL (vaultapi.Client.Mount). It is optional: a refusal or any other
// failure gives nil.
func (a *Adapter) mount(ctx context.Context, ref stores.Ref, mount string) *mountInfo {
	if !a.opts.LabelLookups {
		return nil
	}
	return a.c.Mount(ctx, &a.mounts, ref, mount)
}

// cachedMount returns cached mount information without asking the store.
func (a *Adapter) cachedMount(mount string) *mountInfo {
	info, _ := a.mounts.Get(mount, a.c.Now())
	return info
}

// labels builds the label set for in: native attributes first, then custom
// metadata where it does not collide with them.
func (a *Adapter) labels(in labelInput) map[string]string {
	return vaultapi.KVLabels(Kind, a.opts.Namespace, a.c.Now(), in)
}

// future reports whether an RFC 3339 deletion time is still to come, as it
// is when delete_version_after scheduled it. An unparsable time counts as
// past, so the version is treated as deleted.
func (a *Adapter) future(ts string) bool { return vaultapi.Future(ts, a.c.Now()) }

// WriteLabels returns the labels a secret written at ref would carry, for
// policy rules on store.write. It makes no request: mount information comes
// from the cache when an earlier read or list filled it.
func (a *Adapter) WriteLabels(ref stores.Ref) map[string]string {
	mount, rest := a.split(ref.Secret().Path)
	return a.labels(labelInput{Mount: mount, Path: rest, MountInfo: a.cachedMount(mount)})
}

// setNative sets the native attribute attr (stores.SetNative for Kind).
func setNative(l map[string]string, attr string, values ...string) {
	stores.SetNative(l, Kind, attr, values...)
}

// ancestors returns every proper ancestor folder of p.
func ancestors(p string) []string { return vaultapi.Ancestors(p) }
