// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"maps"
	"path/filepath"
	"slices"
	"strings"
)

// Origins of [OwnPath] entries that are not a setting key.
const (
	// OwnOriginConfigFile is a config file scrim read.
	OwnOriginConfigFile = "config file"
	// OwnOriginStateDir is scrim's local state directory (StateDir).
	OwnOriginStateDir = "state directory"
)

// OwnPath is a file or directory scrim reads secrets or key material from:
// the target of a file: reference, a config file, the state directory, a
// key-material setting or store field. It is a path, never content.
type OwnPath struct {
	// Path is absolute and clean.
	Path string `json:"path"`
	// Origin names what points at it: the setting or field key, or one of
	// the OwnOrigin constants.
	Origin string `json:"origin"`
}

// OwnPaths lists the files and directories this configuration makes scrim
// read secrets or key material from, by path, each once (the first origin
// wins), sorted by path. Relative paths are left out. `scrim run` hides
// them from sessions (specs/credential-injection, "Session filesystem view
// hides scrim's own files").
func (c *Config) OwnPaths() []OwnPath {
	var out []OwnPath
	seen := map[string]bool{}
	add := func(p, origin string) {
		if p == "" || !filepath.IsAbs(p) {
			return
		}
		p = filepath.Clean(p)
		if seen[p] {
			return
		}
		seen[p] = true
		out = append(out, OwnPath{Path: p, Origin: origin})
	}
	for _, f := range c.secretFields() {
		if f.ref.Kind() == RefFile {
			add(strings.TrimPrefix(string(f.ref), "file:"), f.key)
		}
	}
	for _, e := range c.Entries() {
		if !e.Setting.KeyMaterial {
			continue
		}
		p, _ := e.Value.(string)
		if p == "" || !filepath.IsAbs(p) {
			continue
		}
		add(p, e.Setting.Key)
		for _, suffix := range e.Setting.Companions {
			add(p+suffix, e.Setting.Key)
		}
	}
	if c.reg != nil {
		for _, col := range c.reg.Collections() {
			st := c.collections[col.Key]
			for _, name := range slices.Sorted(maps.Keys(st)) {
				inst := st[name]
				for _, f := range col.KeyMaterialFields {
					p := inst.String(f)
					if p == "" {
						p, _ = inst.Fields[f].(string)
					}
					add(p, inst.Key(col.Key, f))
				}
			}
		}
	}
	if dir, err := c.StateDir(); err == nil {
		add(dir, OwnOriginStateDir)
	}
	for _, f := range c.files {
		add(f, OwnOriginConfigFile)
	}
	slices.SortFunc(out, func(a, b OwnPath) int { return strings.Compare(a.Path, b.Path) })
	return out
}
