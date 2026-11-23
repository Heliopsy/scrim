// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/heliopsy/scrim/internal/stores"
)

// Store-native labels (docs/stores/kubernetes.md "Labels").
//
// The adapter kind is "kubernetes", so its native labels live under
// "kubernetes." like every adapter's under its own kind (stores.SetNative
// derives the prefix from the kind, and stores.ComposeLabels keeps only an
// adapter's own kind prefix). A "k8s." prefix would need a kind "k8s";
// instance names are free, so an instance can still be called k8s.
//
// Native attributes come from what the API server fixes for an object:
//
//   - kubernetes.namespace and kubernetes.name, its address;
//   - kubernetes.type, the Secret type (Opaque, kubernetes.io/tls, ...),
//     which cannot change after creation.
//
// Object labels and annotations are editable by anyone who may update the
// Secret, so they are user metadata under "kubernetes.meta.label.<key>" and
// "kubernetes.meta.annotation.<key>" (stores.UserMeta), set after the native
// keys and never replacing one: editing a label cannot forge a native key.
// Annotations whose key starts with "scrim." are also reported under their
// own key (scrim.hosts, ...), which is where Write keeps WriteOptions.Labels.
//
// kubectl's last-applied-configuration annotation holds the whole object
// as last applied, data included, so it is never read into a label.

// lastApplied is kubectl's annotation holding the applied object.
const lastApplied = "kubectl.kubernetes.io/last-applied-configuration"

// labels builds a Secret's labels from its metadata and type.
func labels(m *metav1.ObjectMeta, typ string) map[string]string {
	l := map[string]string{}
	stores.SetNative(l, Kind, "namespace", m.Namespace)
	stores.SetNative(l, Kind, "name", m.Name)
	stores.SetNative(l, Kind, "type", typ)
	for _, k := range sortedKeys(m.Labels) {
		stores.UserMeta(l, Kind, "label."+k, m.Labels[k])
	}
	for _, k := range sortedKeys(m.Annotations) {
		if k == lastApplied {
			continue
		}
		stores.UserMeta(l, Kind, "annotation."+k, m.Annotations[k])
		if strings.HasPrefix(k, stores.ScrimLabelPrefix) {
			if _, taken := l[k]; !taken {
				l[k] = m.Annotations[k]
			}
		}
	}
	return l
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// WriteLabels implements stores.WriteLabeler: the namespace and name a
// write to ref would use. The type is left out, since an existing Secret
// keeps its own.
func (a *Adapter) WriteLabels(ref stores.Ref) map[string]string {
	t, err := a.secretTarget(stores.OpWrite, ref.Secret())
	if err != nil {
		return nil
	}
	l := map[string]string{}
	stores.SetNative(l, Kind, "namespace", t.ns)
	stores.SetNative(l, Kind, "name", t.name)
	return l
}
