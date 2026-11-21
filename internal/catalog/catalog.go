// SPDX-License-Identifier: AGPL-3.0-only

package catalog

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/heliopsy/scrim/internal/stores"
)

// Binding is an entry resolved for one selection: the reference to use and
// everything bound to it. It holds no value.
type Binding struct {
	Name        string     `json:"name"`
	Ref         stores.Ref `json:"ref"`
	Placeholder string     `json:"placeholder,omitempty"`
	Hosts       []string   `json:"hosts,omitempty"`
	Class       Class      `json:"class"`
	Inject      []string   `json:"inject,omitempty"`
	Tools       []string   `json:"tools,omitempty"`
	// PlaceholderFormat, AWSSigV4 and ClientCertificate are copied from
	// the entry.
	PlaceholderFormat string    `json:"placeholder_format,omitempty"`
	AWSSigV4          *AWSSigV4 `json:"aws_sigv4,omitempty"`
	ClientCertificate bool      `json:"client_certificate,omitempty"`
	Source            Source    `json:"source"`
	// Selected says which variant applied: "default" or the variant's
	// selection, for example "profile=dev".
	Selected string `json:"selected"`
}

// Injectable reports whether the binding names at least one host. A
// credential without a host binding is never injected.
func (b Binding) Injectable() bool { return len(b.Hosts) > 0 }

// AllowsHost reports whether host is one of the bound hosts. "*.example.com"
// matches subdomains of example.com, not example.com itself.
func (b Binding) AllowsHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, h := range b.Hosts {
		h = strings.ToLower(h)
		if suffix, ok := strings.CutPrefix(h, "*."); ok {
			if strings.HasSuffix(host, "."+suffix) {
				return true
			}
			continue
		}
		if h == host {
			return true
		}
	}
	return false
}

// Resolved is one catalog entry with its binding for the catalog's
// selection. OK is false when no variant applies and there is no default.
type Resolved struct {
	Entry   Entry   `json:"entry"`
	Binding Binding `json:"binding"`
	OK      bool    `json:"resolved"`
	// Overridden lists lower-precedence definitions of the same entry.
	Overridden []Source `json:"overridden,omitempty"`
}

// Catalog is a compiled, immutable catalog for one selection.
type Catalog struct {
	sel           Selection
	resolved      map[string]*Resolved
	byPlaceholder map[string]string     // placeholder -> name
	byRef         map[stores.Ref]string // secret ref (no field) -> name
	byExact       map[stores.Ref]string // resolved ref with its field -> name
	warnings      []string
}

// Input is everything a catalog is compiled from.
type Input struct {
	// Entries from every source; precedence follows Source.Kind.
	Entries []Entry
	// Listings holds, per bulk prefix (as written, with /*), the secrets
	// listed under it. A bulk entry without a listing stays unresolved.
	Listings map[string][]stores.Metadata
}

// Empty returns a catalog with no entries, which still resolves reference
// placeholders.
func Empty(sel Selection) *Catalog {
	c, _ := Compile(Input{}, sel)
	return c
}

// Compile validates the input and resolves every entry for sel. It fails
// on any invalid entry, on duplicate entries within one source kind, on
// duplicate placeholders and on ambiguous variants. Overridden definitions
// and differing metadata are reported as warnings.
func Compile(in Input, sel Selection) (*Catalog, error) {
	c := &Catalog{
		sel:           sel,
		resolved:      map[string]*Resolved{},
		byPlaceholder: map[string]string{},
		byRef:         map[stores.Ref]string{},
		byExact:       map[stores.Ref]string{},
	}
	var errs []error

	// Validate and merge by name and precedence.
	type def struct {
		e    Entry
		over []Source
	}
	defs := map[string]*def{}
	var metadata []Entry
	for _, e := range in.Entries {
		if err := validateEntry(&e); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", e.Source, err))
			continue
		}
		if e.Source.Kind == SourceMetadata {
			metadata = append(metadata, e)
			continue
		}
		d, ok := defs[e.Name]
		switch {
		case !ok:
			defs[e.Name] = &def{e: e}
		case d.e.Source.Kind == e.Source.Kind:
			errs = append(errs, fmt.Errorf("%w: entry %q is defined twice: %s and %s", ErrInvalid, e.Name, d.e.Source, e.Source))
		case e.Source.Kind > d.e.Source.Kind:
			c.warnings = append(c.warnings, fmt.Sprintf("entry %q from %s overrides %s", e.Name, e.Source, d.e.Source))
			defs[e.Name] = &def{e: e, over: append(d.over, d.e.Source)}
		default:
			c.warnings = append(c.warnings, fmt.Sprintf("entry %q from %s overrides %s", e.Name, d.e.Source, e.Source))
			d.over = append(d.over, e.Source)
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	// Expand bulk entries.
	var expanded []*def
	for _, name := range slices.Sorted(maps.Keys(defs)) {
		d := defs[name]
		if d.e.Prefix == "" {
			continue
		}
		listing, ok := in.Listings[d.e.Prefix]
		if !ok {
			c.warnings = append(c.warnings, fmt.Sprintf("bulk entry %q: %s was not listed; its secrets are not mapped", name, d.e.Prefix))
		}
		for _, m := range listing {
			seg := m.Ref.Path[strings.LastIndexByte(m.Ref.Path, '/')+1:]
			upper := envName(seg)
			e := d.e
			e.Name = name + "/" + upper
			e.Prefix, e.Template = "", ""
			e.Ref = m.Ref.Secret().String()
			e.Placeholder = strings.ReplaceAll(d.e.Template, "{NAME}", upper)
			e.Source = Source{Kind: d.e.Source.Kind, Where: d.e.Source.Where + " (" + d.e.Prefix + ")"}
			if err := validateEntry(&e); err != nil {
				errs = append(errs, err)
				continue
			}
			expanded = append(expanded, &def{e: e, over: d.over})
		}
	}

	add := func(d *def) {
		r := &Resolved{Entry: d.e, Overridden: d.over}
		b, selected, ok, err := resolveEntry(d.e, sel)
		if err != nil {
			errs = append(errs, err)
			return
		}
		r.OK = ok
		if ok {
			b.Selected = selected
			r.Binding = b
		}
		c.resolved[d.e.Name] = r
	}
	for _, name := range slices.Sorted(maps.Keys(defs)) {
		if defs[name].e.Prefix == "" {
			add(defs[name])
		}
	}
	for _, d := range expanded {
		if _, dup := c.resolved[d.e.Name]; dup {
			errs = append(errs, fmt.Errorf("%w: bulk entry %q collides with entry %q", ErrInvalid, d.e.Source.Where, d.e.Name))
			continue
		}
		add(d)
	}

	// Index references of file and config entries, for metadata merging and
	// reference placeholders. Every variant counts, so metadata never
	// shadows a reference the catalog maps under another selection.
	refOwner := map[stores.Ref]string{}
	for _, name := range slices.Sorted(maps.Keys(c.resolved)) {
		for _, r := range entryRefs(c.resolved[name].Entry) {
			if _, taken := refOwner[r]; !taken {
				refOwner[r] = name
			}
		}
	}

	// Store metadata: entries for secrets the catalog does not already map.
	for _, e := range metadata {
		ref, _ := stores.ParseRef(e.Ref)
		if owner, ok := refOwner[ref.Secret()]; ok {
			if diff := differs(c.resolved[owner].Entry, e); diff != "" {
				c.warnings = append(c.warnings, fmt.Sprintf("%s: %s differs from entry %q (%s), which takes precedence", e.Source, diff, owner, c.resolved[owner].Entry.Source))
			}
			c.resolved[owner].Overridden = append(c.resolved[owner].Overridden, e.Source)
			continue
		}
		if other, dup := c.resolved[e.Name]; dup {
			c.warnings = append(c.warnings, fmt.Sprintf("%s: name %q is already used by %s; metadata ignored", e.Source, e.Name, other.Entry.Source))
			continue
		}
		add(&def{e: e})
		refOwner[ref.Secret()] = e.Name
	}

	// Declared placeholders are unique across the whole catalog, whatever
	// the selection.
	for _, name := range slices.Sorted(maps.Keys(c.resolved)) {
		p := c.resolved[name].Entry.Placeholder
		if p == "" {
			continue
		}
		if other, dup := c.byPlaceholder[p]; dup {
			errs = append(errs, fmt.Errorf("%w: placeholder %s is declared by both %q (%s) and %q (%s)", ErrInvalid, p,
				other, c.resolved[other].Entry.Source, name, c.resolved[name].Entry.Source))
			continue
		}
		c.byPlaceholder[p] = name
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	for r, name := range refOwner {
		c.byRef[r] = name
	}
	// Two entries may map two fields of one secret (an AWS access key id and
	// its secret key): the exact reference picks the right one.
	for _, name := range slices.Sorted(maps.Keys(c.resolved)) {
		if r := c.resolved[name]; r.OK && r.Binding.Ref.Field != "" {
			if _, taken := c.byExact[r.Binding.Ref]; !taken {
				c.byExact[r.Binding.Ref] = name
			}
		}
	}
	return c, nil
}

// entryRefs lists every secret reference (without field) an entry maps.
func entryRefs(e Entry) []stores.Ref {
	var out []stores.Ref
	addRef := func(s string) {
		if r, err := stores.ParseRef(s); err == nil {
			out = append(out, r.Secret())
		}
	}
	if e.Ref != "" {
		addRef(e.Ref)
	}
	for _, p := range slices.Sorted(maps.Keys(e.Profiles)) {
		addRef(e.Profiles[p])
	}
	for _, v := range e.Variants {
		addRef(v.Ref)
	}
	return out
}

// differs names the binding fields where metadata disagrees with an entry.
func differs(e, m Entry) string {
	var d []string
	if len(m.Hosts) > 0 && !slices.Equal(sortedCopy(e.Hosts), sortedCopy(m.Hosts)) {
		d = append(d, "hosts")
	}
	if m.Placeholder != "" && m.Placeholder != e.Placeholder {
		d = append(d, "placeholder")
	}
	return strings.Join(d, " and ")
}

func sortedCopy(s []string) []string {
	c := slices.Clone(s)
	sort.Strings(c)
	return c
}

// resolveEntry picks the reference for sel: the matching variant with the
// most keys, or the default reference. Two matching variants with the same
// number of keys are ambiguous and fail.
func resolveEntry(e Entry, sel Selection) (Binding, string, bool, error) {
	variants := slices.Clone(e.Variants)
	for _, p := range slices.Sorted(maps.Keys(e.Profiles)) {
		variants = append(variants, Variant{When: map[string]string{KeyProfile: p}, Ref: e.Profiles[p]})
	}
	var (
		best      *Variant
		bestScore = -1
		tie       bool
	)
	for i := range variants {
		v := &variants[i]
		match := true
		for k, val := range v.When {
			if sel.get(k) != val {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		switch n := len(v.When); {
		case n > bestScore:
			best, bestScore, tie = v, n, false
		case n == bestScore:
			tie = true
		}
	}
	if tie {
		return Binding{}, "", false, fmt.Errorf("%w: entry %q: more than one variant matches %s equally; make one more specific", ErrInvalid, e.Name, sel)
	}
	refStr, selected := e.Ref, "default"
	if best != nil {
		refStr, selected = best.Ref, whenKey(best.When)
	}
	if refStr == "" {
		return Binding{}, "", false, nil
	}
	ref, err := stores.ParseRef(refStr)
	if err != nil {
		return Binding{}, "", false, fmt.Errorf("%w: entry %q: %w", ErrInvalid, e.Name, err)
	}
	return Binding{
		Name:        e.Name,
		Ref:         ref,
		Placeholder: e.Placeholder,
		Hosts:       slices.Clone(e.Hosts),
		Class:       e.Class,
		Inject:      slices.Clone(e.Inject),
		Tools:       slices.Clone(e.Tools),
		Source:      e.Source,

		PlaceholderFormat: e.PlaceholderFormat,
		AWSSigV4:          e.AWSSigV4,
		ClientCertificate: e.ClientCertificate,
	}, selected, true, nil
}

// envName turns a store key into the {NAME} form: upper case, every
// character other than A-Z and 0-9 an underscore, runs collapsed.
func envName(s string) string {
	var b strings.Builder
	last := byte('_')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			c -= 'a' - 'A'
		case c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		default:
			c = '_'
		}
		if c == '_' && last == '_' {
			continue
		}
		b.WriteByte(c)
		last = c
	}
	return strings.TrimSuffix(b.String(), "_")
}

// Selection returns the selection the catalog was compiled for.
func (c *Catalog) Selection() Selection { return c.sel }

// Warnings returns non-fatal findings: overridden entries, metadata that
// disagrees with the catalog, bulk prefixes that could not be listed.
func (c *Catalog) Warnings() []string { return slices.Clone(c.warnings) }

// Entries returns every entry with its resolution, sorted by name.
func (c *Catalog) Entries() []Resolved {
	out := make([]Resolved, 0, len(c.resolved))
	for _, name := range slices.Sorted(maps.Keys(c.resolved)) {
		out = append(out, *c.resolved[name])
	}
	return out
}

// Len is the number of entries.
func (c *Catalog) Len() int { return len(c.resolved) }

// ErrUnknown is returned for a name, placeholder or reference the catalog
// cannot resolve.
var ErrUnknown = errors.New("not in the catalog")

// ErrUnresolved is returned for an entry with no reference for the
// catalog's selection.
var ErrUnresolved = errors.New("no reference for this selection")

// Name resolves a logical name.
func (c *Catalog) Name(name string) (Binding, error) {
	r, ok := c.resolved[name]
	if !ok {
		return Binding{}, fmt.Errorf("catalog: %q: %w", name, ErrUnknown)
	}
	if !r.OK {
		return Binding{}, fmt.Errorf("catalog: %q: %w %s", name, ErrUnresolved, c.sel)
	}
	return r.Binding, nil
}

// Placeholder resolves a declared placeholder such as SCRIM_GITHUB_TOKEN.
func (c *Catalog) Placeholder(p string) (Binding, error) {
	name, ok := c.byPlaceholder[p]
	if !ok {
		return Binding{}, fmt.Errorf("catalog: placeholder %s: %w", p, ErrUnknown)
	}
	return c.Name(name)
}

// Placeholders returns every declared placeholder that resolves for the
// catalog's selection, sorted.
func (c *Catalog) Placeholders() []string {
	var out []string
	for p, name := range c.byPlaceholder {
		if c.resolved[name].OK {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// Ref returns the binding for a store reference. If the catalog maps the
// same secret, the reference keeps its own field selector and takes the
// entry's hosts, class and tools; the entry must resolve to that secret for
// the current selection, so a reference to another profile's secret is not
// bound. Otherwise the binding has no hosts and is not injectable.
func (c *Catalog) Ref(ref stores.Ref) Binding {
	if name, ok := c.byExact[ref]; ok {
		return c.resolved[name].Binding
	}
	if name, ok := c.byRef[ref.Secret()]; ok {
		if r := c.resolved[name]; r.OK && r.Binding.Ref.Secret() == ref.Secret() {
			b := r.Binding
			b.Ref = ref
			return b
		}
	}
	return Binding{Name: ref.String(), Ref: ref, Class: ClassCredential, Selected: "reference"}
}

// Lookup resolves any of the forms an agent, rule or tool profile may use:
// a logical name, a declared placeholder, a reference placeholder
// {{scrim:<ref>}} or a bare store reference.
func (c *Catalog) Lookup(s string) (Binding, error) {
	if ref, ok, err := ParseReferencePlaceholder(s); ok {
		if err != nil {
			return Binding{}, err
		}
		return c.Ref(ref), nil
	}
	if placeholderPattern.MatchString(s) {
		return c.Placeholder(s)
	}
	if strings.Contains(s, "://") {
		ref, err := stores.ParseRef(s)
		if err != nil {
			return Binding{}, err
		}
		return c.Ref(ref), nil
	}
	return c.Name(s)
}

// Reference placeholder delimiters.
const (
	refOpen  = "{{scrim:"
	refClose = "}}"
)

// ParseReferencePlaceholder parses {{scrim:<ref>}}. ok reports whether s
// has that form; err is set when it does but the reference is malformed.
func ParseReferencePlaceholder(s string) (stores.Ref, bool, error) {
	inner, ok := strings.CutPrefix(s, refOpen)
	if !ok {
		return stores.Ref{}, false, nil
	}
	inner, ok = strings.CutSuffix(inner, refClose)
	if !ok {
		return stores.Ref{}, false, nil
	}
	ref, err := stores.ParseRef(strings.TrimSpace(inner))
	if err != nil {
		return stores.Ref{}, true, fmt.Errorf("catalog: reference placeholder: %w", err)
	}
	return ref, true, nil
}

// ReferencePlaceholder renders the reference placeholder for ref.
func ReferencePlaceholder(ref stores.Ref) string { return refOpen + ref.String() + refClose }
