// SPDX-License-Identifier: AGPL-3.0-only

package profiles

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"
	"sync"

	"go.yaml.in/yaml/v4"

	"github.com/heliopsy/scrim/internal/catalog"
	"github.com/heliopsy/scrim/internal/config"
)

//go:embed builtin/*.yaml
var builtinFS embed.FS

// collectionKey holds user-defined and overriding profiles in the
// configuration.
const collectionKey = "tool-profiles"

// Auto and None are the special words of run.profiles.
const (
	Auto = "auto"
	None = "none"
)

// Settings.
var (
	// Enabled selects the profiles scrim run applies.
	Enabled = config.Register(config.Spec[[]string]{
		Key:     "run.profiles",
		Default: []string{Auto},
		Description: "Tool profiles scrim run applies: profile names, `auto` for every profile at least one catalog entry " +
			"fills (an entry naming the profile in its tools list), or `none`. Profiles a selected one requires are added. " +
			"See docs/cli-tools.md.",
		Flag: true,
		Validate: func(v []string) error {
			if slices.Contains(v, None) && len(v) > 1 {
				return errors.New("none cannot be combined with other profiles")
			}
			for _, n := range v {
				if n != Auto && n != None && !namePattern.MatchString(n) {
					return fmt.Errorf("%q is not a profile name", n)
				}
			}
			return nil
		},
	})

	// Definitions holds user-defined profiles and overrides of built-in ones.
	Definitions = config.RegisterCollection(config.CollectionSpec{
		Key: collectionKey,
		Description: "Tool profiles by name: description, tools, requires, credentials (name, hosts, inject, required), " +
			"params, env, unset, dirs, files (path, content), paths (home, generated), test (command, expect), notes. A name that " +
			"matches a built-in profile overrides the fields it sets (params are merged key by key). Templates hold " +
			"placeholders only, never values. See docs/cli-tools.md.",
		Validate: func(inst config.Instance) error {
			_, err := fromInstance(inst)
			return err
		},
	})
)

func init() {
	catalog.RegisterToolDefaults(func(c *config.Config, tool string) (catalog.ToolDefaults, bool) {
		set, err := cachedSet(c)
		if err != nil {
			return catalog.ToolDefaults{}, false
		}
		return set.ToolDefaults(tool)
	})
}

// spec is the file and configuration format of a profile.
type spec struct {
	Description string            `json:"description"`
	Tools       []string          `json:"tools"`
	Requires    []string          `json:"requires"`
	Credentials []Slot            `json:"credentials"`
	Params      map[string]string `json:"params"`
	Env         map[string]string `json:"env"`
	Unset       []string          `json:"unset"`
	Files       []fileSpec        `json:"files"`
	Dirs        []string          `json:"dirs"`
	Paths       []Path            `json:"paths"`
	Test        *Test             `json:"test"`
	Notes       []string          `json:"notes"`
}

type fileSpec struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// decode reads a profile from a decoded YAML or configuration tree. It
// returns the top-level keys present, for overrides.
func decode(name string, tree map[string]any) (*Profile, map[string]bool, error) {
	b, err := json.Marshal(tree)
	if err != nil {
		return nil, nil, fmt.Errorf("%w %q: %w", ErrInvalid, name, err)
	}
	var s spec
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, nil, fmt.Errorf("%w %q: %s", ErrInvalid, name, strings.TrimPrefix(err.Error(), "json: "))
	}
	p := &Profile{Name: name, Description: s.Description, Tools: s.Tools, Requires: s.Requires,
		Credentials: s.Credentials, Params: s.Params, Env: s.Env, Unset: s.Unset, Dirs: s.Dirs, Paths: s.Paths,
		Test: s.Test, Notes: s.Notes}
	for _, f := range s.Files {
		p.Files = append(p.Files, File(f))
	}
	present := map[string]bool{}
	for k := range tree {
		present[k] = true
	}
	return p, present, nil
}

func fromInstance(inst config.Instance) (*Profile, error) {
	p, present, err := decode(inst.Name, inst.Fields)
	if err != nil {
		return nil, err
	}
	if b, ok := builtins()[inst.Name]; ok {
		p = override(b, p, present)
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return p, nil
}

// override applies the fields present in o to a copy of base.
func override(base, o *Profile, present map[string]bool) *Profile {
	p := base.clone()
	p.Overridden = true
	set := func(key string, apply func()) {
		if present[key] {
			apply()
		}
	}
	set("description", func() { p.Description = o.Description })
	set("tools", func() { p.Tools = o.Tools })
	set("requires", func() { p.Requires = o.Requires })
	set("credentials", func() { p.Credentials = o.Credentials })
	set("params", func() {
		if p.Params == nil {
			p.Params = map[string]string{}
		}
		maps.Copy(p.Params, o.Params)
	})
	set("env", func() { p.Env = o.Env })
	set("unset", func() { p.Unset = o.Unset })
	set("files", func() { p.Files = o.Files })
	set("dirs", func() { p.Dirs = o.Dirs })
	set("paths", func() { p.Paths = o.Paths })
	set("test", func() { p.Test = o.Test })
	set("notes", func() { p.Notes = o.Notes })
	return p
}

var builtins = sync.OnceValue(func() map[string]*Profile {
	out := map[string]*Profile{}
	files, err := fs.Glob(builtinFS, "builtin/*.yaml")
	if err != nil {
		panic(err)
	}
	for _, f := range files {
		data, err := builtinFS.ReadFile(f)
		if err != nil {
			panic(err)
		}
		p, err := ParseFile(strings.TrimSuffix(path.Base(f), ".yaml"), data)
		if err != nil {
			panic(fmt.Sprintf("built-in profile %s: %v", f, err))
		}
		p.Builtin = true
		out[p.Name] = p
	}
	return out
})

// ParseFile parses one profile in the built-in file format (a YAML mapping
// of the profile's fields) and validates it.
func ParseFile(name string, data []byte) (*Profile, error) {
	var tree map[string]any
	if err := yaml.Unmarshal(data, &tree); err != nil {
		return nil, fmt.Errorf("%w %q: %w", ErrInvalid, name, err)
	}
	p, _, err := decode(name, tree)
	if err != nil {
		return nil, err
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return p, nil
}

// Set is the built-in profiles plus those in the configuration.
type Set struct {
	byName map[string]*Profile
}

// Builtin returns the built-in profiles only.
func Builtin() *Set {
	return &Set{byName: maps.Clone(builtins())}
}

// Load returns the built-in profiles with the configuration's profiles
// added and its overrides applied.
func Load(c *config.Config) (*Set, error) {
	s := Builtin()
	var errs []error
	for _, inst := range Definitions.Get(c) {
		p, err := fromInstance(inst)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		s.byName[p.Name] = p
	}
	if err := s.checkRequires(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return s, nil
}

var cache struct {
	sync.Mutex
	cfg *config.Config
	set *Set
	err error
}

func cachedSet(c *config.Config) (*Set, error) {
	cache.Lock()
	defer cache.Unlock()
	if cache.cfg != c || cache.cfg == nil {
		cache.set, cache.err = Load(c)
		cache.cfg = c
	}
	return cache.set, cache.err
}

func (s *Set) checkRequires() error {
	var errs []error
	for _, n := range s.Names() {
		for _, r := range s.byName[n].Requires {
			if _, ok := s.byName[r]; !ok {
				errs = append(errs, fmt.Errorf("%w %q: requires unknown profile %q", ErrInvalid, n, r))
			}
		}
	}
	return errors.Join(errs...)
}

// Names returns every profile name, sorted.
func (s *Set) Names() []string { return slices.Sorted(maps.Keys(s.byName)) }

// Get returns a profile by name.
func (s *Set) Get(name string) (*Profile, bool) {
	p, ok := s.byName[name]
	return p, ok
}

// All returns every profile, sorted by name.
func (s *Set) All() []*Profile {
	out := make([]*Profile, 0, len(s.byName))
	for _, n := range s.Names() {
		out = append(out, s.byName[n])
	}
	return out
}

// ToolDefaults returns the hosts and injection locations of the slot a word
// from an entry's tools list names.
func (s *Set) ToolDefaults(tool string) (catalog.ToolDefaults, bool) {
	name, _, _ := strings.Cut(tool, ".")
	p, ok := s.byName[name]
	if !ok {
		return catalog.ToolDefaults{}, false
	}
	slot, ok := p.slotFor(tool)
	if !ok {
		return catalog.ToolDefaults{}, false
	}
	return catalog.ToolDefaults{Hosts: slices.Clone(slot.Hosts), Inject: slices.Clone(slot.Inject)}, true
}
