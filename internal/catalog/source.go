// SPDX-License-Identifier: AGPL-3.0-only

package catalog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"go.yaml.in/yaml/v4"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/stores"
)

// entriesKey is the configuration collection holding catalog entries.
const entriesKey = "catalog.entries"

// FileKind is the kind of a catalog file.
const FileKind = "Catalog"

// maxFile bounds the size of a catalog file.
const maxFile = 4 << 20

// Settings and the entries collection. Entries in the configuration live
// under catalog.entries.<name>, so they follow the configuration's
// precedence (flag, environment, file) and hot reload:
//
//	catalog:
//	  entries:
//	    github:
//	      ref: bao://kv/agents/github#token
//	      hosts: [api.github.com]
//	      placeholder: SCRIM_GITHUB_TOKEN
//
// and SCRIM_CATALOG_ENTRIES_GITHUB_REF in the environment.
var (
	Files = config.Register(config.Spec[[]string]{
		Key:         "catalog.files",
		Default:     []string{},
		Description: "Catalog files to load, in order. Each is a YAML document with `kind: Catalog` and an `entries` map. Reloaded when they change.",
	})
	Profile = config.Register(config.Spec[string]{
		Key:         "catalog.profile",
		Default:     "",
		Description: "Catalog profile (for example dev or prod) that selects per-profile references.",
		Flag:        true,
	})
	Environment = config.Register(config.Spec[string]{
		Key:         "catalog.environment",
		Default:     "",
		Description: "Catalog environment that selects per-environment references.",
		Flag:        true,
	})
	MetadataFrom = config.Register(config.Spec[[]string]{
		Key:         "catalog.metadata-from",
		Default:     []string{},
		Description: "Store prefixes (for example bao://kv/agents) whose secrets' metadata labels are read as catalog entries.",
	})
	MetadataPrefix = config.Register(config.Spec[string]{
		Key:         "catalog.metadata-prefix",
		Default:     "scrim.",
		Description: "Prefix of the store metadata keys read as catalog bindings: <prefix>hosts, <prefix>placeholder, <prefix>profiles, <prefix>name, <prefix>class, <prefix>field.",
	})
	ReloadInterval = config.Register(config.Spec[time.Duration]{
		Key:         "catalog.reload-interval",
		Default:     5 * time.Second,
		Description: "How often catalog files are checked for changes.",
		Validate: func(d time.Duration) error {
			if d < 100*time.Millisecond {
				return errors.New("must be at least 100ms")
			}
			return nil
		},
	})
	Entries = config.RegisterCollection(config.CollectionSpec{
		Key:         entriesKey,
		Description: "Catalog entries by logical name: ref, profiles, variants, prefix, template, hosts, placeholder, class, inject, tools, placeholder_format, aws_sigv4, client_certificate. References only, never values.",
		Validate: func(inst config.Instance) error {
			_, err := entryFromInstance(inst)
			return err
		},
	})
)

func decodeStrict(data []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

// fieldError rewrites a decode error without quoting values: encoding/json
// messages name the field and Go type only.
func fieldError(name string, err error) error {
	msg := err.Error()
	msg = strings.TrimPrefix(msg, "json: ")
	return fmt.Errorf("%w: entry %q: %s", ErrInvalid, name, msg)
}

func entryFromInstance(inst config.Instance) (Entry, error) {
	b, err := json.Marshal(inst.Fields)
	if err != nil {
		return Entry{}, fmt.Errorf("%w: entry %q: %w", ErrInvalid, inst.Name, err)
	}
	var e Entry
	if err := decodeStrict(b, &e); err != nil {
		return Entry{}, fieldError(inst.Name, err)
	}
	e.Name = inst.Name
	e.Source = Source{Kind: SourceConfig, Where: entriesKey + "." + inst.Name}
	if err := validateEntry(&e); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// ConfigEntries returns the entries in the configuration.
func ConfigEntries(c *config.Config) ([]Entry, error) {
	var out []Entry
	var errs []error
	for _, inst := range Entries.Get(c) {
		e, err := entryFromInstance(inst)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, e)
	}
	return out, errors.Join(errs...)
}

// ParseFile parses a catalog file. Unknown keys, literal values and invalid
// entries fail the whole file.
func ParseFile(path string, data []byte) ([]Entry, error) {
	var doc struct {
		APIVersion string                    `yaml:"apiVersion"`
		Kind       string                    `yaml:"kind"`
		Entries    map[string]map[string]any `yaml:"entries"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: %s: invalid YAML: %s", ErrInvalid, path, yamlMessage(err))
	}
	if doc.Kind != FileKind {
		return nil, fmt.Errorf("%w: %s: kind must be %s", ErrInvalid, path, FileKind)
	}
	if !slices.Contains(config.SupportedAPIVersions, doc.APIVersion) {
		return nil, fmt.Errorf("%w: %s: apiVersion must be one of %s", ErrInvalid, path, strings.Join(config.SupportedAPIVersions, ", "))
	}
	var out []Entry
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(doc.Entries)) {
		b, err := json.Marshal(doc.Entries[name])
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w: entry %q: %w", path, ErrInvalid, name, err))
			continue
		}
		var e Entry
		if err := decodeStrict(b, &e); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, fieldError(name, err)))
			continue
		}
		e.Name = name
		e.Source = Source{Kind: SourceFile, Where: path}
		if err := validateEntry(&e); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
			continue
		}
		out = append(out, e)
	}
	return out, errors.Join(errs...)
}

// yamlMessage keeps the line information of a YAML error and drops any
// quoted content, which could be a pasted value.
func yamlMessage(err error) string {
	msg := err.Error()
	if i := strings.IndexAny(msg, "`\"'"); i >= 0 {
		msg = strings.TrimSpace(msg[:i]) + " ..."
	}
	return msg
}

// LoadFiles reads and parses catalog files.
func LoadFiles(paths []string) ([]Entry, error) {
	var out []Entry
	var errs []error
	for _, p := range paths {
		data, err := readFile(p)
		if err != nil {
			errs = append(errs, fmt.Errorf("catalog file %s: %w", p, err))
			continue
		}
		es, err := ParseFile(p, data)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, es...)
	}
	return out, errors.Join(errs...)
}

func readFile(p string) ([]byte, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if fi.Size() > maxFile {
		return nil, fmt.Errorf("larger than %d bytes", maxFile)
	}
	return os.ReadFile(p) //nolint:gosec // the path is configuration
}

// EntriesFromMetadata turns store metadata labels into catalog entries.
// Only secrets carrying at least one <prefix>* label become entries:
//
//	<prefix>hosts        comma-separated hosts
//	<prefix>placeholder  declared placeholder
//	<prefix>profiles     comma-separated profiles the secret applies to
//	<prefix>name         logical name (default derived from the reference)
//	<prefix>class        credential or display
//	<prefix>field        field selector to bind (default the whole secret)
//
// Invalid labels are reported and the secret skipped.
func EntriesFromMetadata(metas []stores.Metadata, prefix string) ([]Entry, []string) {
	var out []Entry
	var warnings []string
	for _, m := range metas {
		get := func(k string) string { return strings.TrimSpace(m.Labels[prefix+k]) }
		has := false
		for k := range m.Labels {
			if strings.HasPrefix(k, prefix) {
				has = true
			}
		}
		if !has {
			continue
		}
		ref := m.Ref.Secret()
		if f := get("field"); f != "" {
			ref = ref.WithField(f)
		}
		e := Entry{
			Name:        get("name"),
			Placeholder: get("placeholder"),
			Hosts:       splitList(get("hosts")),
			Class:       Class(get("class")),
			Source:      Source{Kind: SourceMetadata, Where: m.Ref.Secret().String()},
		}
		if e.Name == "" {
			e.Name = nameFromRef(m.Ref)
		}
		if ps := splitList(get("profiles")); len(ps) > 0 {
			e.Profiles = map[string]string{}
			for _, p := range ps {
				e.Profiles[p] = ref.String()
			}
		} else {
			e.Ref = ref.String()
		}
		if err := validateEntry(&e); err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: labels ignored: %v", e.Source, err))
			continue
		}
		out = append(out, e)
	}
	return out, warnings
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// nameFromRef derives a logical name: the scheme and path, lower-cased,
// with every other character as a dash.
func nameFromRef(r stores.Ref) string {
	s := strings.ToLower(r.Scheme + "-" + r.Path)
	var b strings.Builder
	dash := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b.WriteByte(c)
			dash = false
			continue
		}
		if !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

// Lister lists secrets under a prefix; *stores.Set implements it.
type Lister interface {
	List(ctx context.Context, prefix stores.Ref) ([]stores.Metadata, error)
}

// Load gathers every source for c and compiles the catalog for sel. Store
// listings (bulk prefixes and metadata) are skipped with a warning when
// lister is nil or a store fails, so a store outage never blocks the
// catalog; entries from files and configuration still load.
func Load(ctx context.Context, c *config.Config, lister Lister, sel Selection) (*Catalog, error) {
	var in Input
	var errs []error
	fileEntries, err := LoadFiles(Files.Get(c))
	if err != nil {
		errs = append(errs, err)
	}
	cfgEntries, err := ConfigEntries(c)
	if err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	in.Entries = append(fileEntries, cfgEntries...) //nolint:gocritic // a new slice from both lists is intended
	var warnings []string
	in.Listings = map[string][]stores.Metadata{}
	for _, e := range in.Entries {
		if e.Prefix == "" || lister == nil {
			continue
		}
		p, _ := strings.CutSuffix(e.Prefix, "/*")
		ref, _ := stores.ParseRef(p)
		ms, err := lister.List(ctx, ref)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("bulk entry %q: listing %s failed: %v", e.Name, p, err))
			continue
		}
		in.Listings[e.Prefix] = ms
	}
	if lister != nil {
		for _, p := range MetadataFrom.Get(c) {
			ref, err := stores.ParseRef(p)
			if err != nil {
				return nil, fmt.Errorf("%w: %s: %w", ErrInvalid, MetadataFrom.Name(), err)
			}
			ms, err := lister.List(ctx, ref)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("store metadata %s: listing failed: %v", p, err))
				continue
			}
			es, w := EntriesFromMetadata(ms, MetadataPrefix.Get(c))
			in.Entries = append(in.Entries, es...)
			warnings = append(warnings, w...)
		}
	}
	if fn := toolDefaults.Load(); fn != nil {
		in.Tools = func(tool string) (ToolDefaults, bool) { return (*fn)(c, tool) }
	}
	cat, err := Compile(in, sel)
	if err != nil {
		return nil, err
	}
	cat.warnings = append(warnings, cat.warnings...)
	return cat, nil
}

// ToolDefaultsFunc returns the defaults of a tool profile slot under a
// configuration.
type ToolDefaultsFunc func(c *config.Config, tool string) (ToolDefaults, bool)

var toolDefaults atomic.Pointer[ToolDefaultsFunc]

// RegisterToolDefaults makes [Load] fill entries that name tool profiles
// from those profiles. internal/profiles registers itself in init; the
// catalog cannot import it, since profiles read the catalog.
func RegisterToolDefaults(fn ToolDefaultsFunc) { toolDefaults.Store(&fn) }

// SelectionFrom returns the selection configured in c.
func SelectionFrom(c *config.Config) Selection {
	return Selection{Profile: Profile.Get(c), Environment: Environment.Get(c)}
}
