// SPDX-License-Identifier: AGPL-3.0-only

package stores

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
)

// Store-native labels (specs/secret-stores "Store-native metadata labels").
//
// Adapters describe where a secret lives in their store through
// [Metadata.Labels], so policy rules can match on it as secret.labels. The
// convention, shared by every adapter:
//
//   - Native attributes live under "<kind>." where kind is the adapter kind
//     ("openbao", "infisical", "vaultwarden", "file", "env", ...):
//     "vaultwarden.org", "openbao.mount", "infisical.environment".
//   - A multi-valued attribute is one comma-joined key plus one presence key
//     per value: "vaultwarden.collection" = "Prod,Shared",
//     "vaultwarden.collection.Prod" = "true",
//     "vaultwarden.collection.Shared" = "true". A rule tests membership
//     exactly with `"vaultwarden.collection.Prod" in secret.labels`.
//   - Custom metadata a store user can edit (custom fields, item notes
//     metadata, secret tags) lives under "<kind>.meta.<key>". It never
//     replaces a native key, so whoever can edit an item cannot forge a
//     native label.
//   - "scrim.*" keys keep their meaning (bound hosts, catalog entries).
//   - "store.*" is reserved for the generic labels scrim sets for every
//     secret (store.name, store.kind, store.path, store.container,
//     store.field); an adapter's store.* keys are replaced.
//
// The kind and attribute parts of a key are lower-case ASCII letters,
// digits, '-' and '_', separated by dots ([LabelKey] folds anything else to
// '_'). The value part of a presence key is the value verbatim. Values are
// metadata only, never secret values.

// Label key prefixes with a fixed meaning.
const (
	// StoreLabelPrefix is the prefix of the generic labels scrim derives for
	// every secret from its reference and store instance.
	StoreLabelPrefix = "store."
	// ScrimLabelPrefix is the prefix of scrim's own metadata conventions
	// (scrim.hosts, scrim.class, ...), unchanged.
	ScrimLabelPrefix = "scrim."
	// metaSegment separates user metadata from native attributes.
	metaSegment = "meta"
)

// Generic labels set for every secret (see [GenericLabels]).
const (
	LabelStoreName      = "store.name"
	LabelStoreKind      = "store.kind"
	LabelStorePath      = "store.path"
	LabelStoreContainer = "store.container"
	LabelStoreField     = "store.field"
)

var multi struct {
	sync.RWMutex
	attrs map[string]bool
}

// DeclareMulti declares attributes of kind as multi-valued, so [SetNative]
// writes their presence keys even for a single value. Call it from the
// adapter's init, next to [Register].
func DeclareMulti(kind string, attrs ...string) {
	multi.Lock()
	defer multi.Unlock()
	if multi.attrs == nil {
		multi.attrs = map[string]bool{}
	}
	for _, a := range attrs {
		multi.attrs[NativeKey(kind, a)] = true
	}
}

// IsMulti reports whether attr of kind was declared with [DeclareMulti].
func IsMulti(kind, attr string) bool {
	multi.RLock()
	defer multi.RUnlock()
	return multi.attrs[NativeKey(kind, attr)]
}

// LabelKey folds s into a label key: lower-case ASCII letters, digits, '-'
// and '_' in dot-separated segments. Other characters become '_', empty
// segments are dropped. It returns "" when nothing is left.
func LabelKey(s string) string {
	var b strings.Builder
	for seg := range strings.SplitSeq(strings.ToLower(s), ".") {
		if seg == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		for _, c := range seg {
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
				b.WriteRune(c)
			default:
				b.WriteByte('_')
			}
		}
	}
	return b.String()
}

// NativeKey is the label key of a native attribute: "<kind>.<attr>", both
// folded with [LabelKey].
func NativeKey(kind, attr string) string {
	k, a := LabelKey(kind), LabelKey(attr)
	if k == "" || a == "" {
		return ""
	}
	return k + "." + a
}

// SetNative sets the native attribute attr of kind in labels, replacing
// whatever is there (native attributes win over user metadata and over
// keys an adapter copied from the store):
//
//   - one value of an attribute not declared multi: "<kind>.<attr>" = value;
//   - several values, or any number of values of an attribute declared with
//     [DeclareMulti]: "<kind>.<attr>" = the values joined by "," (in the
//     order given, duplicates dropped) and "<kind>.<attr>.<value>" = "true"
//     for each value.
//
// Empty values are skipped; with none left SetNative does nothing. An attr
// in the "meta" namespace is ignored: that is [UserMeta]'s. labels must not
// be nil.
func SetNative(labels map[string]string, kind, attr string, values ...string) {
	key := NativeKey(kind, attr)
	if key == "" || LabelKey(attr) == metaSegment || strings.HasPrefix(LabelKey(attr), metaSegment+".") {
		return
	}
	vals := make([]string, 0, len(values))
	for _, v := range values {
		if v != "" && !slices.Contains(vals, v) {
			vals = append(vals, v)
		}
	}
	if len(vals) == 0 {
		return
	}
	labels[key] = strings.Join(vals, ",")
	if len(vals) > 1 || IsMulti(kind, attr) {
		for _, v := range vals {
			labels[key+"."+v] = "true"
		}
	}
}

// UserMeta records user-editable store metadata as "<kind>.meta.<key>" (key
// folded with [LabelKey]). It never overwrites a key that is already set,
// so a native label set earlier, or an earlier user key that folds to the
// same name, wins. Empty keys are ignored. labels must not be nil.
func UserMeta(labels map[string]string, kind, key, value string) {
	k := LabelKey(key)
	base := NativeKey(kind, metaSegment)
	if k == "" || base == "" {
		return
	}
	full := base + "." + k
	if _, taken := labels[full]; taken {
		return
	}
	labels[full] = value
}

// MetadataReader is implemented by adapters that can return a secret's
// metadata, labels included, without reading its values. Policy uses it to
// label a request naming a secret that is not in a redaction set (a write
// to an existing item); without it scrim reads the secret and wipes the
// values at once. It returns [ErrNotFound] for a secret that does not exist.
type MetadataReader interface {
	ReadMetadata(ctx context.Context, ref Ref) (Metadata, error)
}

// WriteLabeler is implemented by adapters that know labels a secret would
// get before it exists (from its reference alone, without a store call), so
// a store.write or secret.gen rule sees them for a new item. The result
// follows the same convention as [Metadata.Labels]; generic store.* labels
// are added by scrim and must not be returned.
type WriteLabeler interface {
	WriteLabels(ref Ref) map[string]string
}

// GenericLabels are the store.* labels scrim derives for every secret from
// its store instance and reference, whatever the backend:
//
//   - store.name: the instance name (not an alias);
//   - store.kind: the adapter kind, when known;
//   - store.path: the reference path, without selectors or field;
//   - store.container: the path before its last segment, "" at the top;
//   - store.field: the field, when the reference names one.
func GenericLabels(name, kind string, ref Ref) map[string]string {
	out := map[string]string{LabelStoreName: name, LabelStorePath: ref.Path, LabelStoreContainer: ""}
	if kind != "" {
		out[LabelStoreKind] = kind
	}
	if i := strings.LastIndexByte(ref.Path, '/'); i >= 0 {
		out[LabelStoreContainer] = ref.Path[:i]
	}
	if ref.Field != "" {
		out[LabelStoreField] = ref.Field
	}
	return out
}

// ComposeLabels is the label set policy sees for a secret of the instance
// name (of adapter kind) at ref, given the labels its adapter reported:
//
//  1. the adapter's labels, except store.* keys and keys under another
//     registered adapter kind's prefix (an adapter speaks only for its own
//     kind);
//  2. the generic store.* labels ([GenericLabels]), replacing anything
//     there;
//  3. the operator's derived labels ([LabelMapping]), computed from 1 and
//     2, never replacing a key either already holds.
//
// The result is a new map; native is not modified.
func ComposeLabels(name, kind string, ref Ref, native map[string]string, m LabelMapping) map[string]string {
	out := make(map[string]string, len(native))
	foreign := foreignKinds(kind)
	for k, v := range native {
		if strings.HasPrefix(k, StoreLabelPrefix) {
			continue
		}
		if head, _, ok := strings.Cut(k, "."); ok && foreign[head] {
			continue
		}
		out[k] = v
	}
	for k, v := range GenericLabels(name, kind, ref) {
		out[k] = v
	}
	m.apply(out)
	return out
}

// foreignKinds is every registered adapter kind except kind.
func foreignKinds(kind string) map[string]bool {
	out := map[string]bool{}
	for _, k := range DefaultRegistry.Kinds() {
		if k != kind {
			out[k] = true
		}
	}
	return out
}

// Metadata looks up the metadata of the secret ref names, never keeping a
// value: through the adapter's [MetadataReader] when it has one, otherwise
// by reading the secret and wiping every value before returning. exists is
// false (with a nil error) when the store says the secret does not exist.
// Any other failure, including a store that can neither read metadata nor
// read secrets, is an error; errors carry no value.
func (s *Set) Metadata(ctx context.Context, ref Ref) (m Metadata, exists bool, err error) {
	a, err := s.Lookup(ref)
	if err != nil {
		return Metadata{}, false, err
	}
	ref = ref.Secret()
	if mr, ok := a.(MetadataReader); ok {
		m, err = mr.ReadMetadata(ctx, ref)
	} else if a.Capabilities().Has(CapRead) {
		var sec Secret
		sec, err = a.Read(ctx, ref)
		sec.Wipe()
		m = sec.Meta
	} else {
		return Metadata{}, false, fmt.Errorf("store %s can neither read metadata nor read secrets", a.Name())
	}
	switch {
	case errors.Is(err, ErrNotFound):
		return Metadata{}, false, nil
	case err != nil:
		return Metadata{}, false, err
	}
	return m, true, nil
}
