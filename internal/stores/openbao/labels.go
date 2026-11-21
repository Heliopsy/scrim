// SPDX-License-Identifier: AGPL-3.0-only

package openbao

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/heliopsy/scrim/internal/stores"
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
// The helpers follow the convention of stores.SetNative, stores.UserMeta
// and stores.LabelKey (feat/store-labels-core) with the same semantics, so
// they can be swapped for those once both land.

// labelPrefix starts every native label key.
const labelPrefix = Kind + "."

// metaAttr is the attribute custom metadata is filed under.
const metaAttr = "meta"

// multiAttrs are the list attributes: they get presence keys even with one
// value.
var multiAttrs = map[string]bool{"ancestors": true, "segments": true, "namespaces": true}

// labelKey folds s into a label key: lower-case ASCII letters, digits, '-'
// and '_' in dot-separated segments. Other characters become '_', empty
// segments are dropped. It returns "" when nothing is left.
func labelKey(s string) string {
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

// setNative sets the native attribute attr, replacing what is there. One
// value of a single-valued attribute is stored as it is; several values, or
// any values of a list attribute, are stored comma-joined (duplicates
// dropped) with a presence key "openbao.<attr>.<value>" = "true" for each.
// Empty values are skipped; with none left nothing is set.
func setNative(l map[string]string, attr string, values ...string) {
	a := labelKey(attr)
	if a == "" || a == metaAttr || strings.HasPrefix(a, metaAttr+".") {
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
	key := labelPrefix + a
	l[key] = strings.Join(vals, ",")
	if len(vals) > 1 || multiAttrs[a] {
		for _, v := range vals {
			l[key+"."+v] = "true"
		}
	}
}

// userMeta files one custom metadata entry as openbao.meta.<folded key>,
// never overwriting a key already set.
func userMeta(l map[string]string, key, value string) {
	k := labelKey(key)
	if k == "" {
		return
	}
	full := labelPrefix + metaAttr + "." + k
	if _, taken := l[full]; !taken {
		l[full] = value
	}
}

// passThrough reports whether a custom metadata key is also copied under
// its own name: every key except those claiming the native or the generic
// store namespace.
func passThrough(key string) bool {
	k := strings.ToLower(key)
	return !strings.HasPrefix(k, labelPrefix) && !strings.HasPrefix(k, "store.")
}

// customLabels files custom metadata after the native labels: under
// openbao.meta in sorted key order (the first of several keys that fold to
// the same one wins), and under its own key where passThrough allows.
func customLabels(l map[string]string, custom map[string]string) {
	keys := make([]string, 0, len(custom))
	for k := range custom {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		userMeta(l, k, custom[k])
		if _, taken := l[k]; passThrough(k) && !taken {
			l[k] = custom[k]
		}
	}
}

// ancestors returns every proper ancestor folder of p: "a/b/c" gives "a"
// and "a/b".
func ancestors(p string) []string {
	segs := strings.Split(p, "/")
	out := make([]string, 0, len(segs))
	for i := 1; i < len(segs); i++ {
		out = append(out, strings.Join(segs[:i], "/"))
	}
	return out
}

// mountInfo is what sys/internal/ui/mounts or sys/mounts says about a mount.
type mountInfo struct {
	Type           string            `json:"type"`
	Description    string            `json:"description"`
	Accessor       string            `json:"accessor"`
	Local          bool              `json:"local"`
	SealWrap       bool              `json:"seal_wrap"`
	PluginVersion  string            `json:"plugin_version"`
	Options        map[string]string `json:"options"`
	Config         map[string]any    `json:"config"`
	ExternalAccess bool              `json:"external_entropy_access"`
}

// engine names the secrets engine: kv-v2 or kv-v1 for KV, else the type.
func (m *mountInfo) engine() string {
	if m.Type == "kv" || m.Type == "generic" {
		if m.Options["version"] == "2" {
			return "kv-v2"
		}
		return "kv-v1"
	}
	return m.Type
}

// mountTTL is how long mount information, or the lack of it, is kept.
const mountTTL = 5 * time.Minute

type mountEntry struct {
	info *mountInfo
	at   time.Time
}

// mountCache keeps mount information per mount path.
type mountCache struct {
	mu sync.Mutex
	m  map[string]mountEntry
}

func (c *mountCache) get(mount string, now time.Time) (*mountInfo, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[mount]
	if !ok || now.Sub(e.at) >= mountTTL {
		return nil, false
	}
	return e.info, true
}

func (c *mountCache) put(mount string, info *mountInfo, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]mountEntry{}
	}
	c.m[mount] = mountEntry{info: info, at: now}
}

// mount returns the mount's information, asking the store at most once per
// mountTTL. It is optional: a refusal or any other failure gives nil and is
// remembered for the same time, so a token without access costs one request
// per mount per period, not one per read.
func (a *Adapter) mount(ctx context.Context, ref stores.Ref, mount string) *mountInfo {
	if !a.c.opts.LabelLookups {
		return nil
	}
	now := a.c.now()
	if info, ok := a.mounts.get(mount, now); ok {
		return info
	}
	var info *mountInfo
	// sys/internal/ui/mounts answers any token with a capability on the
	// mount; sys/mounts/<path> needs read on that sys path.
	for _, p := range []string{"sys/internal/ui/mounts/", "sys/mounts/"} {
		if info = a.fetchMount(ctx, ref, p+escapePath(mount)); info != nil {
			break
		}
	}
	if ctx.Err() == nil {
		a.mounts.put(mount, info, now)
	}
	return info
}

func (a *Adapter) fetchMount(ctx context.Context, ref stores.Ref, path string) *mountInfo {
	resp, err := a.c.do(ctx, request{op: stores.OpRead, ref: ref, method: http.MethodGet, path: path, optional: true})
	defer resp.wipe()
	if err != nil {
		return nil
	}
	var mr struct {
		Data *mountInfo `json:"data"`
	}
	if json.Unmarshal(resp.body, &mr) != nil || mr.Data == nil || mr.Data.Type == "" {
		return nil
	}
	return mr.Data
}

// cachedMount returns cached mount information without asking the store.
func (a *Adapter) cachedMount(mount string) *mountInfo {
	info, _ := a.mounts.get(mount, a.c.now())
	return info
}

// labelInput is what is known about one secret when its labels are built.
// Any part may be missing.
type labelInput struct {
	mount, path string
	// meta is the secret's metadata (metadata/ or detailed-metadata/).
	meta *secretMeta
	// version is the version described: the one read, or the current one.
	version int
	// versionCreated, deletion and destroyed describe that version.
	versionCreated, deletion string
	destroyed                *bool
	// custom is the custom metadata, from meta or from a data read.
	custom    map[string]string
	mountInfo *mountInfo
}

// labels builds the label set for in: native attributes first, then custom
// metadata where it does not collide with them.
func (a *Adapter) labels(in labelInput) map[string]string {
	l := map[string]string{}
	custom := in.custom
	if custom == nil && in.meta != nil {
		custom = in.meta.CustomMetadata
	}

	setNative(l, "mount", in.mount)
	setNative(l, "engine", "kv-v2")
	if ns := a.c.opts.Namespace; ns != "" {
		setNative(l, "namespace", ns)
		setNative(l, "namespaces", append(ancestors(ns), ns)...)
	}
	if in.path != "" {
		setNative(l, "path", in.path)
		anc := ancestors(in.path)
		setNative(l, "ancestors", anc...)
		if len(anc) > 0 {
			setNative(l, "folder", anc[len(anc)-1])
		}
		segs := strings.Split(in.path, "/")
		setNative(l, "name", segs[len(segs)-1])
		setNative(l, "segments", segs...)
	}

	if mi := in.mountInfo; mi != nil {
		setNative(l, "engine", mi.engine())
		setNative(l, "mount_type", mi.Type)
		setNative(l, "mount_version", mi.Options["version"])
		setNative(l, "mount_description", mi.Description)
		setNative(l, "mount_accessor", mi.Accessor)
		setNative(l, "mount_plugin_version", mi.PluginVersion)
		setNative(l, "mount_local", strconv.FormatBool(mi.Local))
		setNative(l, "mount_seal_wrap", strconv.FormatBool(mi.SealWrap))
		setNative(l, "mount_external_entropy_access", strconv.FormatBool(mi.ExternalAccess))
		for k, v := range mi.Options {
			if nk := labelKey(k); nk != "" {
				setNative(l, "mount_option."+nk, v)
			}
		}
		for k, v := range mi.Config {
			if nk := labelKey(k); nk != "" {
				setNative(l, "mount_config."+nk, configValue(v))
			}
		}
	}

	version := in.version
	if m := in.meta; m != nil {
		if version == 0 {
			version = m.CurrentVersion
		}
		setNative(l, "current_version", positive(m.CurrentVersion))
		setNative(l, "oldest_version", positive(m.OldestVersion))
		setNative(l, "max_versions", strconv.Itoa(m.MaxVersions))
		setNative(l, "cas_required", strconv.FormatBool(m.CASRequired))
		setNative(l, "delete_version_after", m.DeleteVersionAfter)
		setNative(l, "created_time", m.CreatedTime)
		setNative(l, "updated_time", m.UpdatedTime)
		if m.Versions != nil {
			deleted, destroyed := 0, 0
			for _, v := range m.Versions {
				if v.Destroyed {
					destroyed++
				} else if v.DeletionTime != "" && !a.future(v.DeletionTime) {
					deleted++
				}
			}
			setNative(l, "versions", strconv.Itoa(len(m.Versions)))
			setNative(l, "deleted_versions", strconv.Itoa(deleted))
			setNative(l, "destroyed_versions", strconv.Itoa(destroyed))
			if v, ok := m.Versions[strconv.Itoa(version)]; ok {
				if in.versionCreated == "" {
					in.versionCreated = v.CreatedTime
				}
				if in.deletion == "" {
					in.deletion = v.DeletionTime
				}
				if in.destroyed == nil {
					d := v.Destroyed
					in.destroyed = &d
				}
			}
		}
	}
	setNative(l, "version", positive(version))
	setNative(l, "version_created_time", in.versionCreated)
	setNative(l, "deletion_time", in.deletion)
	if in.destroyed != nil {
		setNative(l, "destroyed", strconv.FormatBool(*in.destroyed))
	}
	customLabels(l, custom)
	return l
}

// future reports whether an RFC 3339 deletion time is still to come, as it
// is when delete_version_after scheduled it. An unparsable time counts as
// past, so the version is treated as deleted.
func (a *Adapter) future(ts string) bool {
	t := parseTime(ts)
	return !t.IsZero() && t.After(a.c.now())
}

func positive(n int) string {
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

// WriteLabels returns the labels a secret written at ref would carry, for
// policy rules on store.write. It makes no request: mount information comes
// from the cache when an earlier read or list filled it.
func (a *Adapter) WriteLabels(ref stores.Ref) map[string]string {
	mount, rest := a.split(ref.Secret().Path)
	return a.labels(labelInput{mount: mount, path: rest, mountInfo: a.cachedMount(mount)})
}
