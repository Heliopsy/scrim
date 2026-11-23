// SPDX-License-Identifier: AGPL-3.0-only

package gcpsm

import (
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/stores"
)

// Store-native policy labels (docs/stores/gcp.md, "Policy labels").
//
// Secret Manager's own attributes of a secret go into stores.Metadata.Labels
// under "gcpsm.<attr>", so policy rules can match on project, location,
// replication, version, aliases and the rest. Secret labels and annotations
// are editable by whoever may update the secret, so they go under
// "gcpsm.meta.<key>" (a label wins over an annotation with the same key).
// Annotations are also copied under their own key, so catalog bindings such
// as scrim.hosts kept as annotations work as with other stores; annotation
// keys in the "gcpsm." namespace are dropped, and native keys are set before
// user metadata, which never overwrites a key, so neither can forge a native
// attribute. Labels hold metadata only, never a payload.

// labelPrefix is the namespace of every label this adapter derives.
const labelPrefix = Kind + "."

// multiAttrs are the multi-valued attributes: they get presence keys even
// for a single value.
var multiAttrs = []string{"replica", "kms-key", "topic", "alias", "version-alias"}

// isReserved reports whether a user-supplied key falls in the adapter's
// namespace. Case and surrounding space are ignored.
func isReserved(key string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(key)), labelPrefix)
}

// labels builds the labels of sec at path. ver is the version the
// metadata describes (nil when unknown), version its number.
func (a *Adapter) labels(project, path string, sec *apiSecret, ver *apiVersion, version string) map[string]string {
	out := map[string]string{}
	for k, v := range sec.Annotations {
		if !isReserved(k) {
			out[k] = v
		}
	}
	a.nativeLocation(out, project, path, lastSegment(sec.Name))
	// Google names resources with the project number, whatever the
	// request used.
	if seg := strings.Split(sec.Name, "/"); len(seg) > 1 && seg[0] == "projects" && isDigits(seg[1]) {
		stores.SetNative(out, Kind, "project.number", seg[1])
	}
	switch {
	case a.s.location != "":
		stores.SetNative(out, Kind, "replication", "regional")
		if sec.CustomerManagedEncryption != nil {
			stores.SetNative(out, Kind, "kms-key", sec.CustomerManagedEncryption.KmsKeyName)
		}
	case sec.Replication != nil && sec.Replication.UserManaged != nil:
		stores.SetNative(out, Kind, "replication", "user-managed")
		var locs, keys []string
		for _, r := range sec.Replication.UserManaged.Replicas {
			locs = append(locs, r.Location)
			if r.CustomerManagedEncryption != nil {
				keys = append(keys, r.CustomerManagedEncryption.KmsKeyName)
			}
		}
		stores.SetNative(out, Kind, "replica", locs...)
		stores.SetNative(out, Kind, "kms-key", keys...)
	case sec.Replication != nil && sec.Replication.Automatic != nil:
		stores.SetNative(out, Kind, "replication", "automatic")
		if sec.Replication.Automatic.CustomerManagedEncryption != nil {
			stores.SetNative(out, Kind, "kms-key", sec.Replication.Automatic.CustomerManagedEncryption.KmsKeyName)
		}
	}
	setTime(out, "created", sec.CreateTime)
	setTime(out, "expires", sec.ExpireTime)
	if sec.Rotation != nil {
		setTime(out, "rotation.next", sec.Rotation.NextRotationTime)
		stores.SetNative(out, Kind, "rotation.period", sec.Rotation.RotationPeriod)
	}
	topics := make([]string, 0, len(sec.Topics))
	for _, t := range sec.Topics {
		topics = append(topics, t.Name)
	}
	stores.SetNative(out, Kind, "topic", topics...)
	aliases := slices.Sorted(maps.Keys(sec.VersionAliases))
	stores.SetNative(out, Kind, "alias", aliases...)
	if version != "" {
		stores.SetNative(out, Kind, "version", version)
		var mine []string
		for _, al := range aliases {
			if string(sec.VersionAliases[al]) == version {
				mine = append(mine, al)
			}
		}
		stores.SetNative(out, Kind, "version-alias", mine...)
	}
	if ver != nil && ver.State != "" {
		stores.SetNative(out, Kind, "version.state", strings.ToLower(ver.State))
	}
	for _, k := range slices.Sorted(maps.Keys(sec.Labels)) {
		stores.UserMeta(out, Kind, k, sec.Labels[k])
	}
	for _, k := range slices.Sorted(maps.Keys(sec.Annotations)) {
		stores.UserMeta(out, Kind, k, sec.Annotations[k])
	}
	return out
}

// nativeLocation sets the labels that follow from where a secret is.
func (a *Adapter) nativeLocation(out map[string]string, project, path, id string) {
	stores.SetNative(out, Kind, "project", project)
	loc := a.s.location
	if loc == "" {
		loc = "global"
	}
	stores.SetNative(out, Kind, "location", loc)
	stores.SetNative(out, Kind, "secret", id)
	stores.SetNative(out, Kind, "path", path)
}

// WriteLabels implements stores.WriteLabeler: the labels a secret written
// at ref would get, from the reference and configuration alone. The project
// is the configured one, or the one the credentials named once scrim has
// used them.
func (a *Adapter) WriteLabels(ref stores.Ref) map[string]string {
	id, err := a.names.Name(ref.Path)
	if err != nil {
		return nil
	}
	project := a.s.project
	if project == "" {
		project = a.c.auth.knownProject()
	}
	out := map[string]string{}
	a.nativeLocation(out, project, ref.Path, id)
	return out
}

func setTime(labels map[string]string, attr string, t time.Time) {
	if !t.IsZero() {
		stores.SetNative(labels, Kind, attr, t.UTC().Format(time.RFC3339Nano))
	}
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// fingerprint is a digest of a label set, for change detection.
func fingerprint(labels map[string]string) string {
	h := sha256.New()
	for _, k := range slices.Sorted(maps.Keys(labels)) {
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write([]byte(labels[k]))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)[:12])
}
