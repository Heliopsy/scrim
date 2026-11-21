// SPDX-License-Identifier: AGPL-3.0-only

// Package catalog is scrim's optional secret catalog (specs/secret-stores,
// "Optional secret catalog" and the requirements after it).
//
// The catalog maps logical names such as "github" to a store reference, the
// hosts the credential may be injected toward, its value class, tool
// profiles and an optional declared placeholder such as SCRIM_GITHUB_TOKEN.
// An entry may resolve to different references per profile, environment,
// agent or namespace, and a bulk entry maps every secret under a store
// prefix at once with a placeholder template.
//
// Without a catalog, store references work directly, and a reference
// placeholder such as {{scrim:bao://kv/agents/github#token}} resolves to
// its reference; its host binding then comes from store metadata or
// configuration.
//
// A catalog never holds values: every reference must parse as a store
// reference, unknown keys are rejected, and anything that looks like a
// literal secret fails validation.
package catalog

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/heliopsy/scrim/internal/stores"
)

// Class is how a value is used once restored (design D5).
type Class string

// Value classes.
const (
	// ClassCredential values are only ever injected at the network edge
	// toward their bound hosts. The default.
	ClassCredential Class = "credential"
	// ClassDisplay values are data the agent may need to see or keep in a
	// file; they follow the per-tool restore policy.
	ClassDisplay Class = "display"
)

// Selection keys a variant can match on.
const (
	KeyProfile     = "profile"
	KeyEnvironment = "environment"
	KeyAgent       = "agent"
	KeyNamespace   = "namespace"
)

var selectionKeys = []string{KeyAgent, KeyNamespace, KeyProfile, KeyEnvironment}

// Selection is the context an entry is resolved in. Empty fields match
// only variants that do not mention them.
type Selection struct {
	Profile     string
	Environment string
	Agent       string
	Namespace   string
}

func (s Selection) get(k string) string {
	switch k {
	case KeyProfile:
		return s.Profile
	case KeyEnvironment:
		return s.Environment
	case KeyAgent:
		return s.Agent
	case KeyNamespace:
		return s.Namespace
	}
	return ""
}

// String renders the non-empty fields, for display.
func (s Selection) String() string {
	var parts []string
	for _, k := range selectionKeys {
		if v := s.get(k); v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	if len(parts) == 0 {
		return "(none)"
	}
	return strings.Join(parts, ",")
}

// Variant is a reference used when every key of When matches the selection.
type Variant struct {
	When map[string]string `yaml:"when" json:"when"`
	Ref  string            `yaml:"ref" json:"ref"`
}

// Entry is one catalog entry as written in a catalog source.
type Entry struct {
	// Name is the logical name, for example "github". Set from the map key
	// in files.
	Name string `yaml:"-" json:"-"`
	// Ref is the default reference. Optional when variants cover every
	// selection that should resolve.
	Ref string `yaml:"ref,omitempty" json:"ref,omitempty"`
	// Profiles is shorthand for variants matching only on profile.
	Profiles map[string]string `yaml:"profiles,omitempty" json:"profiles,omitempty"`
	// Variants select a reference by profile, environment, agent or
	// namespace. The variant matching the most keys wins.
	Variants []Variant `yaml:"variants,omitempty" json:"variants,omitempty"`
	// Prefix makes this a bulk entry: every secret under the prefix,
	// written `<scheme>://<path>/*`.
	Prefix string `yaml:"prefix,omitempty" json:"prefix,omitempty"`
	// Template derives each bulk secret's placeholder; {NAME} is the last
	// path segment, upper-cased, with other characters as underscores.
	Template string `yaml:"template,omitempty" json:"template,omitempty"`
	// Hosts are the hosts the credential may be injected toward. A leading
	// "*." matches subdomains.
	Hosts []string `yaml:"hosts,omitempty" json:"hosts,omitempty"`
	// Placeholder is a user-declared placeholder string.
	Placeholder string `yaml:"placeholder,omitempty" json:"placeholder,omitempty"`
	// Class is credential (default) or display.
	Class Class `yaml:"class,omitempty" json:"class,omitempty"`
	// Inject names injection locations, for example "header:Authorization".
	Inject []string `yaml:"inject,omitempty" json:"inject,omitempty"`
	// Tools names tool profiles that use this secret, for example "gh".
	Tools []string `yaml:"tools,omitempty" json:"tools,omitempty"`
	// PlaceholderFormat "shape" asks for a format-preserving placeholder
	// (specs/redaction "Format-preserving placeholders"), for clients that
	// check a token's prefix or length. Credentials only.
	PlaceholderFormat string `yaml:"placeholder_format,omitempty" json:"placeholder_format,omitempty"`
	// AWSSigV4 marks an AWS secret access key: requests signed with its
	// access key id's placeholder are re-signed toward the bound hosts.
	AWSSigV4 *AWSSigV4 `yaml:"aws_sigv4,omitempty" json:"aws_sigv4,omitempty"`
	// ClientCertificate marks a value holding a PEM client certificate and
	// key, presented upstream when the agent presents its placeholder
	// certificate.
	ClientCertificate bool `yaml:"client_certificate,omitempty" json:"client_certificate,omitempty"`

	// Source says where the entry came from. Not part of the file format.
	Source Source `yaml:"-" json:"-"`
}

// AWSSigV4 binds an AWS secret access key entry to its access key id entry
// and to the regions and services requests may be signed for.
type AWSSigV4 struct {
	// AccessKeyID names the catalog entry holding the access key id.
	AccessKeyID string `yaml:"access_key_id" json:"access_key_id"`
	// Regions the credential scope may name. Empty allows every region.
	Regions []string `yaml:"regions,omitempty" json:"regions,omitempty"`
	// Services the credential scope may name, for example s3 and sts. Empty
	// allows every service.
	Services []string `yaml:"services,omitempty" json:"services,omitempty"`
}

// SourceKind orders catalog sources by precedence, lowest first.
type SourceKind int

// Sources, lowest precedence first.
const (
	SourceMetadata SourceKind = iota + 1
	SourceFile
	SourceConfig
)

func (k SourceKind) String() string {
	switch k {
	case SourceMetadata:
		return "store metadata"
	case SourceFile:
		return "catalog file"
	case SourceConfig:
		return "configuration"
	}
	return "unknown"
}

// Source is where an entry was defined.
type Source struct {
	Kind SourceKind `json:"kind"`
	// Where is a file path, a configuration key or a store reference.
	Where string `json:"where"`
}

func (s Source) String() string {
	if s.Where == "" {
		return s.Kind.String()
	}
	return s.Kind.String() + " " + s.Where
}

// MarshalText renders the source for JSON output.
func (k SourceKind) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

var (
	namePattern        = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*(/[A-Z0-9_]+)?$`)
	placeholderPattern = regexp.MustCompile(`^SCRIM_[A-Z0-9]+(_[A-Z0-9]+)*$`)
	templatePattern    = regexp.MustCompile(`^SCRIM_([A-Z0-9_]|\{NAME\})+$`)
	hostPattern        = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]*[a-z0-9])?(:[0-9]{1,5})?$`)
	wordPattern        = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`)
	injectPattern      = regexp.MustCompile(`^[a-z]+(:[A-Za-z0-9._-]+)?$`)
)

// ErrInvalid is wrapped by every validation error.
var ErrInvalid = errors.New("invalid catalog")

// literalPatterns are shapes of real credentials. A catalog string matching
// one is refused as a literal secret, whatever field it is in.
var literalPatterns = []*regexp.Regexp{
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`),
	regexp.MustCompile(`github_pat_[A-Za-z0-9_]{20,}`),
	regexp.MustCompile(`glpat-[A-Za-z0-9_-]{16,}`),
	regexp.MustCompile(`(AKIA|ASIA)[A-Z0-9]{16}`),
	regexp.MustCompile(`sk-[A-Za-z0-9_-]{16,}`),
	regexp.MustCompile(`xox[abposr]-[A-Za-z0-9-]{10,}`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.`),
	regexp.MustCompile(`[sr]k_(live|test)_[A-Za-z0-9]{16,}`),
	regexp.MustCompile(`AIza[A-Za-z0-9_-]{30,}`),
}

// looksLiteral reports whether s looks like a secret value rather than a
// name, reference or host: a known credential shape, or a long token with
// high character diversity and no structure.
func looksLiteral(s string) bool {
	for _, p := range literalPatterns {
		if p.MatchString(s) {
			return true
		}
	}
	return false
}

// highEntropy reports whether a path segment looks like random material.
func highEntropy(seg string) bool {
	if len(seg) < 24 {
		return false
	}
	var lower, upper, digit, other bool
	for _, r := range seg {
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		default:
			other = true
		}
	}
	classes := 0
	for _, b := range []bool{lower, upper, digit, other} {
		if b {
			classes++
		}
	}
	return classes >= 3 && !strings.ContainsAny(seg, "-_ .") // names have separators
}

// errLiteral is the message for a refused literal. It never quotes the
// string, which may be a real secret.
func errLiteral(entry, field string) error {
	return fmt.Errorf("%w: entry %q: %s looks like a literal secret, not a reference; catalogs hold references only", ErrInvalid, entry, field)
}

// parseRef validates one reference string. Errors never quote it.
func parseRef(entry, field, s string) (stores.Ref, error) {
	if looksLiteral(s) {
		return stores.Ref{}, errLiteral(entry, field)
	}
	r, err := stores.ParseRef(s)
	if err != nil {
		return stores.Ref{}, fmt.Errorf("%w: entry %q: %s is not a store reference (<scheme>://<path>[#field]): %w", ErrInvalid, entry, field, err)
	}
	for _, seg := range strings.Split(r.Path, "/") {
		if highEntropy(seg) {
			return stores.Ref{}, errLiteral(entry, field)
		}
	}
	if highEntropy(r.Field) {
		return stores.Ref{}, errLiteral(entry, field)
	}
	return r, nil
}

// validateEntry checks one entry's syntax. It does not resolve references
// against configured stores.
func validateEntry(e *Entry) error {
	if !namePattern.MatchString(e.Name) {
		if looksLiteral(e.Name) || highEntropy(e.Name) {
			return errLiteral("?", "the name")
		}
		return fmt.Errorf("%w: entry name %q must be lower-case words joined by dashes", ErrInvalid, e.Name)
	}
	n := e.Name
	if e.Class == "" {
		e.Class = ClassCredential
	}
	if e.Class != ClassCredential && e.Class != ClassDisplay {
		return fmt.Errorf("%w: entry %q: class must be credential or display", ErrInvalid, n)
	}
	for _, h := range e.Hosts {
		if looksLiteral(h) {
			return errLiteral(n, "a host")
		}
		if !hostPattern.MatchString(strings.ToLower(h)) {
			return fmt.Errorf("%w: entry %q: host %q is not a host name", ErrInvalid, n, h)
		}
	}
	for _, list := range []struct {
		what  string
		items []string
		re    *regexp.Regexp
	}{{"tool profile", e.Tools, wordPattern}, {"injection location", e.Inject, injectPattern}} {
		for _, it := range list.items {
			if looksLiteral(it) {
				return errLiteral(n, "a "+list.what)
			}
			if !list.re.MatchString(it) {
				return fmt.Errorf("%w: entry %q: %s %q is malformed", ErrInvalid, n, list.what, it)
			}
		}
	}
	if e.Placeholder != "" {
		if looksLiteral(e.Placeholder) {
			return errLiteral(n, "the placeholder")
		}
		if !placeholderPattern.MatchString(e.Placeholder) {
			return fmt.Errorf("%w: entry %q: placeholder %q must be SCRIM_ followed by upper-case words joined by _", ErrInvalid, n, e.Placeholder)
		}
	}
	switch e.PlaceholderFormat {
	case "", "shape":
	default:
		return fmt.Errorf("%w: entry %q: placeholder_format must be shape or empty", ErrInvalid, n)
	}
	if e.PlaceholderFormat != "" && e.Class == ClassDisplay {
		return fmt.Errorf("%w: entry %q: a display value keeps the bracket placeholder; placeholder_format is for credentials", ErrInvalid, n)
	}
	if a := e.AWSSigV4; a != nil {
		if !namePattern.MatchString(a.AccessKeyID) || a.AccessKeyID == n {
			return fmt.Errorf("%w: entry %q: aws_sigv4.access_key_id must name another catalog entry", ErrInvalid, n)
		}
		if e.ClientCertificate {
			return fmt.Errorf("%w: entry %q: an entry cannot be both an AWS secret and a client certificate", ErrInvalid, n)
		}
		for _, w := range slices.Concat(a.Regions, a.Services) {
			if !wordPattern.MatchString(w) {
				return fmt.Errorf("%w: entry %q: aws_sigv4 region or service %q is malformed", ErrInvalid, n, w)
			}
		}
	}
	if e.Prefix != "" {
		if e.Ref != "" || len(e.Profiles) > 0 || len(e.Variants) > 0 || e.Placeholder != "" {
			return fmt.Errorf("%w: entry %q: a bulk entry (prefix) takes a template, not ref, profiles, variants or placeholder", ErrInvalid, n)
		}
		p, ok := strings.CutSuffix(e.Prefix, "/*")
		if !ok {
			return fmt.Errorf("%w: entry %q: prefix must end in /*", ErrInvalid, n)
		}
		if _, err := parseRef(n, "prefix", p); err != nil {
			return err
		}
		if !strings.Contains(e.Template, "{NAME}") || !templatePattern.MatchString(e.Template) {
			return fmt.Errorf("%w: entry %q: template must be SCRIM_ upper-case words containing {NAME}", ErrInvalid, n)
		}
		return nil
	}
	if e.Template != "" {
		return fmt.Errorf("%w: entry %q: template needs a prefix", ErrInvalid, n)
	}
	if e.Ref == "" && len(e.Profiles) == 0 && len(e.Variants) == 0 {
		return fmt.Errorf("%w: entry %q: needs ref, profiles, variants or prefix", ErrInvalid, n)
	}
	if e.Ref != "" {
		if _, err := parseRef(n, "ref", e.Ref); err != nil {
			return err
		}
	}
	for p, r := range e.Profiles {
		if !wordPattern.MatchString(p) {
			return fmt.Errorf("%w: entry %q: profile name %q is malformed", ErrInvalid, n, p)
		}
		if _, err := parseRef(n, "profile "+p, r); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for i, v := range e.Variants {
		if len(v.When) == 0 {
			return fmt.Errorf("%w: entry %q: variant %d has no when; use ref for the default", ErrInvalid, n, i+1)
		}
		for k, val := range v.When {
			if !slices.Contains(selectionKeys, k) {
				return fmt.Errorf("%w: entry %q: variant %d: unknown key %q (use %s)", ErrInvalid, n, i+1, k, strings.Join(selectionKeys, ", "))
			}
			if !wordPattern.MatchString(val) {
				return fmt.Errorf("%w: entry %q: variant %d: value for %s is malformed", ErrInvalid, n, i+1, k)
			}
		}
		if _, err := parseRef(n, fmt.Sprintf("variant %d ref", i+1), v.Ref); err != nil {
			return err
		}
		key := whenKey(v.When)
		if seen[key] {
			return fmt.Errorf("%w: entry %q: two variants match the same selection %s", ErrInvalid, n, key)
		}
		seen[key] = true
	}
	for p := range e.Profiles {
		key := whenKey(map[string]string{KeyProfile: p})
		if seen[key] {
			return fmt.Errorf("%w: entry %q: profile %s is set in both profiles and variants", ErrInvalid, n, p)
		}
		seen[key] = true
	}
	return nil
}

func whenKey(w map[string]string) string {
	var parts []string
	for _, k := range selectionKeys {
		if v, ok := w[k]; ok {
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, ",")
}
