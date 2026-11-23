// SPDX-License-Identifier: AGPL-3.0-only

package vaultapi

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/stores"
)

// Store-native labels of a KV secret, shared by the openbao and vault
// adapters (docs/stores/openbao.md and docs/stores/vault.md, "Labels").
//
// Every attribute the store reports about a secret, its mount and the
// configured namespace goes into stores.Metadata.Labels under
// "<kind>.<attr>". A list attribute is stored comma-joined under its key
// and once more as one presence key per value, verbatim
// ("openbao.ancestors": "prod,prod/eu", "openbao.ancestors.prod": "true",
// ...). KV v2 custom metadata appears as "<kind>.meta.<key>" and under its
// own key, except keys under "<kind>." or "store.". Native keys are set
// first and never overwritten. Labels carry metadata only, never a value.

// MultiAttrs are the list attributes: they get presence keys even with one
// value. Adapters declare them with stores.DeclareMulti.
var MultiAttrs = []string{"ancestors", "segments", "namespaces"}

// KVMetadata is a KV v2 secret's metadata (metadata/ or
// detailed-metadata/).
type KVMetadata struct {
	CreatedTime        string            `json:"created_time"`
	UpdatedTime        string            `json:"updated_time"`
	CurrentVersion     int               `json:"current_version"`
	OldestVersion      int               `json:"oldest_version"`
	MaxVersions        int               `json:"max_versions"`
	CASRequired        bool              `json:"cas_required"`
	DeleteVersionAfter string            `json:"delete_version_after"`
	CustomMetadata     map[string]string `json:"custom_metadata"`
	Versions           map[string]struct {
		CreatedTime  string `json:"created_time"`
		DeletionTime string `json:"deletion_time"`
		Destroyed    bool   `json:"destroyed"`
	} `json:"versions"`
}

// KVLabelInput is what is known about one secret when its labels are
// built. Any part may be missing.
type KVLabelInput struct {
	Mount, Path string
	// Engine is reported when the mount information is missing; empty
	// means kv-v2.
	Engine string
	// Meta is the secret's KV v2 metadata.
	Meta *KVMetadata
	// Version is the version described: the one read, or the current one.
	Version int
	// VersionCreated, Deletion and Destroyed describe that version.
	VersionCreated, Deletion string
	Destroyed                *bool
	// Custom is the custom metadata, from Meta or from a data read.
	Custom    map[string]string
	MountInfo *MountInfo
}

// KVLabels builds the label set of a KV secret for adapter kind: native
// attributes first, then custom metadata where it does not collide with
// them. namespace is the configured namespace; now decides whether a
// deletion time has passed.
func KVLabels(kind, namespace string, now time.Time, in KVLabelInput) map[string]string {
	l := map[string]string{}
	set := func(attr string, values ...string) { stores.SetNative(l, kind, attr, values...) }
	custom := in.Custom
	if custom == nil && in.Meta != nil {
		custom = in.Meta.CustomMetadata
	}

	set("mount", in.Mount)
	if in.Engine != "" {
		set("engine", in.Engine)
	} else {
		set("engine", "kv-v2")
	}
	if ns := namespace; ns != "" {
		set("namespace", ns)
		set("namespaces", append(Ancestors(ns), ns)...)
	}
	if in.Path != "" {
		PathLabels(l, kind, in.Path)
	}

	if mi := in.MountInfo; mi != nil {
		MountLabels(l, kind, mi)
	}

	version := in.Version
	if m := in.Meta; m != nil {
		if version == 0 {
			version = m.CurrentVersion
		}
		set("current_version", Positive(m.CurrentVersion))
		set("oldest_version", Positive(m.OldestVersion))
		set("max_versions", strconv.Itoa(m.MaxVersions))
		set("cas_required", strconv.FormatBool(m.CASRequired))
		set("delete_version_after", m.DeleteVersionAfter)
		set("created_time", m.CreatedTime)
		set("updated_time", m.UpdatedTime)
		if m.Versions != nil {
			deleted, destroyed := 0, 0
			for _, v := range m.Versions {
				if v.Destroyed {
					destroyed++
				} else if v.DeletionTime != "" && !Future(v.DeletionTime, now) {
					deleted++
				}
			}
			set("versions", strconv.Itoa(len(m.Versions)))
			set("deleted_versions", strconv.Itoa(deleted))
			set("destroyed_versions", strconv.Itoa(destroyed))
			if v, ok := m.Versions[strconv.Itoa(version)]; ok {
				if in.VersionCreated == "" {
					in.VersionCreated = v.CreatedTime
				}
				if in.Deletion == "" {
					in.Deletion = v.DeletionTime
				}
				if in.Destroyed == nil {
					d := v.Destroyed
					in.Destroyed = &d
				}
			}
		}
	}
	set("version", Positive(version))
	set("version_created_time", in.VersionCreated)
	set("deletion_time", in.Deletion)
	if in.Destroyed != nil {
		set("destroyed", strconv.FormatBool(*in.Destroyed))
	}
	CustomLabels(l, kind, custom)
	return l
}

// PathLabels sets the attributes derived from a path inside the mount:
// path, ancestors, folder, name and segments.
func PathLabels(l map[string]string, kind, p string) {
	stores.SetNative(l, kind, "path", p)
	anc := Ancestors(p)
	stores.SetNative(l, kind, "ancestors", anc...)
	if len(anc) > 0 {
		stores.SetNative(l, kind, "folder", anc[len(anc)-1])
	}
	segs := strings.Split(p, "/")
	stores.SetNative(l, kind, "name", segs[len(segs)-1])
	stores.SetNative(l, kind, "segments", segs...)
}

// MountLabels sets the attributes from the mount information.
func MountLabels(l map[string]string, kind string, mi *MountInfo) {
	set := func(attr string, values ...string) { stores.SetNative(l, kind, attr, values...) }
	set("engine", mi.Engine())
	set("mount_type", mi.Type)
	set("mount_version", mi.Options["version"])
	set("mount_description", mi.Description)
	set("mount_accessor", mi.Accessor)
	set("mount_plugin_version", mi.PluginVersion)
	set("mount_local", strconv.FormatBool(mi.Local))
	set("mount_seal_wrap", strconv.FormatBool(mi.SealWrap))
	set("mount_external_entropy_access", strconv.FormatBool(mi.ExternalAccess))
	for k, v := range mi.Options {
		if nk := stores.LabelKey(k); nk != "" {
			set("mount_option."+nk, v)
		}
	}
	for k, v := range mi.Config {
		if nk := stores.LabelKey(k); nk != "" {
			set("mount_config."+nk, configValue(v))
		}
	}
}

// passThrough reports whether a custom metadata key is also copied under
// its own name: every key except those claiming the native or the generic
// store namespace.
func passThrough(kind, key string) bool {
	k := strings.ToLower(key)
	return !strings.HasPrefix(k, kind+".") && !strings.HasPrefix(k, "store.")
}

// CustomLabels files custom metadata after the native labels: under
// <kind>.meta in sorted key order (the first of several keys that fold to
// the same one wins), and under its own key where passThrough allows.
func CustomLabels(l map[string]string, kind string, custom map[string]string) {
	keys := make([]string, 0, len(custom))
	for k := range custom {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		stores.UserMeta(l, kind, k, custom[k])
		if _, taken := l[k]; passThrough(kind, k) && !taken {
			l[k] = custom[k]
		}
	}
}

// Ancestors returns every proper ancestor folder of p: "a/b/c" gives "a"
// and "a/b".
func Ancestors(p string) []string {
	segs := strings.Split(p, "/")
	out := make([]string, 0, len(segs))
	for i := 1; i < len(segs); i++ {
		out = append(out, strings.Join(segs[:i], "/"))
	}
	return out
}

// Future reports whether an RFC 3339 deletion time is still to come at
// now, as it is when delete_version_after scheduled it. An unparsable time
// counts as past, so the version is treated as deleted.
func Future(ts string, now time.Time) bool {
	t := ParseTime(ts)
	return !t.IsZero() && t.After(now)
}

// ParseTime parses an RFC 3339 time, giving the zero time when it cannot.
func ParseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

// Positive renders n, or "" when it is not positive.
func Positive(n int) string {
	if n <= 0 {
		return ""
	}
	return strconv.Itoa(n)
}

// configValue renders a mount config entry: scalars as text, lists of
// scalars comma-joined, anything else as JSON.
func configValue(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			parts = append(parts, configValue(e))
		}
		return strings.Join(parts, ",")
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}
