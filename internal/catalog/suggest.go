// SPDX-License-Identifier: AGPL-3.0-only

package catalog

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/stores"
)

// Suggestion is a draft catalog entry. It holds no value.
type Suggestion struct {
	Entry Entry
	// From says what the suggestion was derived from (".env:3", a store
	// reference).
	From string
	// Notes explain the candidate reference and hosts.
	Notes []string
}

// SuggestOptions says where suggestions come from.
type SuggestOptions struct {
	// Dir is the project directory scanned for .env files.
	Dir string
	// Store is the scheme and base path used for candidate references of
	// secrets not found in any store, for example "bao://kv/agents".
	Store string
	// Prefixes are store prefixes listed for secret names (never values).
	Prefixes []stores.Ref
	// Lister lists them; nil skips store contents.
	Lister Lister
	// Tools are configured tool profiles: profile name to the environment
	// variables it provides and the hosts it talks to.
	Tools map[string]ToolHint
	// Catalog is the current catalog; secrets it already maps are skipped.
	Catalog *Catalog
}

// ToolHint describes a tool profile for suggestions.
type ToolHint struct {
	Env   []string
	Hosts []string
}

// knownHosts maps a provider word in a variable name to its API host.
var knownHosts = map[string]string{
	"ANTHROPIC":    "api.anthropic.com",
	"CLOUDFLARE":   "api.cloudflare.com",
	"DATADOG":      "api.datadoghq.com",
	"DIGITALOCEAN": "api.digitalocean.com",
	"DOPPLER":      "api.doppler.com",
	"GEMINI":       "generativelanguage.googleapis.com",
	"GH":           "api.github.com",
	"GITHUB":       "api.github.com",
	"GITLAB":       "gitlab.com",
	"HF":           "huggingface.co",
	"HUGGINGFACE":  "huggingface.co",
	"LINEAR":       "api.linear.app",
	"MAILGUN":      "api.mailgun.net",
	"MISTRAL":      "api.mistral.ai",
	"NOTION":       "api.notion.com",
	"NPM":          "registry.npmjs.org",
	"OPENAI":       "api.openai.com",
	"PAGERDUTY":    "api.pagerduty.com",
	"POSTMARK":     "api.postmarkapp.com",
	"SENDGRID":     "api.sendgrid.com",
	"SENTRY":       "sentry.io",
	"SLACK":        "slack.com",
	"STRIPE":       "api.stripe.com",
	"TWILIO":       "api.twilio.com",
	"VERCEL":       "api.vercel.com",
}

var (
	secretWords = regexp.MustCompile(`(^|_)(TOKEN|KEY|SECRET|PASSWORD|PASSWD|PASS|PAT|CREDENTIALS?|AUTH|APIKEY|DSN|PRIVATE)(_|$)`)
	urlWords    = regexp.MustCompile(`(^|_)(URL|URI|HOST|ENDPOINT|BASE|ADDR|ADDRESS|SERVER)$`)
	envKey      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

type envVar struct {
	key, file string
	line      int
	empty     bool // no value, or already a placeholder
	host      string
	userinfo  bool // a URL with credentials in it
}

// scanEnvFile reads KEY=VALUE lines. Values of secret-looking keys are only
// inspected in place (empty or already a placeholder) and never copied out.
// URL values are parsed for their host only.
func scanEnvFile(path string) ([]envVar, error) {
	data, err := os.ReadFile(path) //nolint:gosec // a project file the user pointed at
	if err != nil {
		return nil, err
	}
	buf := secret.Adopt(data) // wiped below: an .env file holds values
	defer buf.Wipe()
	var out []envVar
	err = buf.Expose(func(b []byte) error {
		sc := bufio.NewScanner(bytes.NewReader(b))
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		n := 0
		for sc.Scan() {
			n++
			line := bytes.TrimSpace(sc.Bytes())
			if len(line) == 0 || line[0] == '#' {
				continue
			}
			line = bytes.TrimPrefix(line, []byte("export "))
			k, v, ok := bytes.Cut(line, []byte("="))
			if !ok {
				continue
			}
			key := string(bytes.TrimSpace(k))
			if !envKey.MatchString(key) {
				continue
			}
			v = bytes.Trim(bytes.TrimSpace(v), `"'`)
			ev := envVar{key: strings.ToUpper(key), file: path, line: n}
			ev.empty = len(v) == 0 || bytes.HasPrefix(v, []byte("SCRIM_")) || bytes.HasPrefix(v, []byte(refOpen)) ||
				bytes.HasPrefix(v, []byte("${")) || bytes.Equal(bytes.ToLower(v), []byte("changeme"))
			if bytes.Contains(v, []byte("://")) {
				if u, err := url.Parse(string(v)); err == nil && u.Host != "" {
					ev.host = strings.ToLower(u.Hostname())
					ev.userinfo = u.User != nil
				}
			}
			out = append(out, ev)
		}
		return sc.Err()
	})
	return out, err
}

// providerHost returns the host of the first known provider word in key.
func providerHost(key string) string {
	for _, w := range strings.Split(key, "_") {
		if h, ok := knownHosts[w]; ok {
			return h
		}
	}
	return ""
}

func entryName(key string) string {
	n := strings.ToLower(strings.TrimPrefix(key, "SCRIM_"))
	n = strings.Trim(regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(n, "-"), "-")
	if n == "" || n[0] < 'a' || n[0] > 'z' {
		n = "secret-" + n
	}
	return n
}

func placeholderFor(key string) string {
	if strings.HasPrefix(key, "SCRIM_") {
		return key
	}
	return "SCRIM_" + envName(key)
}

func normKey(s string) string {
	return strings.ToUpper(regexp.MustCompile(`[^A-Za-z0-9]+`).ReplaceAllString(s, "_"))
}

// Suggest proposes catalog entries from the project's .env files, the
// configured tool profiles and the names of secrets in the listed stores.
// It reads no store values and applies nothing.
func Suggest(ctx context.Context, o SuggestOptions) ([]Suggestion, []string, error) {
	var warnings []string
	mapped := func(placeholder string, ref stores.Ref) bool {
		if o.Catalog == nil {
			return false
		}
		if placeholder != "" {
			if _, err := o.Catalog.Placeholder(placeholder); err == nil {
				return true
			}
		}
		if !ref.IsZero() {
			if _, ok := o.Catalog.byRef[ref.Secret()]; ok {
				return true
			}
		}
		return false
	}

	// Store contents, names only.
	var listed []stores.Metadata
	if o.Lister != nil {
		for _, p := range o.Prefixes {
			ms, err := o.Lister.List(ctx, p)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("listing %s failed: %v", p, err))
				continue
			}
			listed = append(listed, ms...)
		}
	}
	findListed := func(key string) (stores.Metadata, bool) {
		for _, m := range listed {
			seg := m.Ref.Path[strings.LastIndexByte(m.Ref.Path, '/')+1:]
			if normKey(seg) == key {
				return m, true
			}
			for _, f := range m.Fields {
				if normKey(f) == key {
					m.Ref = m.Ref.WithField(f)
					return m, true
				}
			}
		}
		return stores.Metadata{}, false
	}

	// Project .env files.
	var vars []envVar
	if o.Dir != "" {
		matches, _ := filepath.Glob(filepath.Join(o.Dir, ".env*"))
		sort.Strings(matches)
		for _, f := range matches {
			if fi, err := os.Stat(f); err != nil || !fi.Mode().IsRegular() {
				continue
			}
			vs, err := scanEnvFile(f)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s: %v", f, err))
				continue
			}
			vars = append(vars, vs...)
		}
	}
	urlHost := map[string]string{} // provider prefix -> host from a URL variable
	for _, v := range vars {
		if v.host != "" && urlWords.MatchString(v.key) {
			pfx := urlWords.ReplaceAllString(v.key, "")
			pfx = strings.TrimSuffix(strings.TrimSuffix(pfx, "_API"), "_")
			urlHost[pfx] = v.host
		}
	}
	project := entryName(filepath.Base(absOr(o.Dir)))
	base := strings.TrimSuffix(o.Store, "/")
	if base == "" {
		base = "bao://kv/agents"
	}

	var out []Suggestion
	seen := map[string]bool{}
	used := map[string]bool{}
	for _, v := range vars {
		isSecret := secretWords.MatchString(v.key) || v.userinfo
		if !isSecret || seen[v.key] {
			continue
		}
		seen[v.key] = true
		ph := placeholderFor(v.key)
		s := Suggestion{From: fmt.Sprintf("%s:%d", filepath.Base(v.file), v.line)}
		e := Entry{Name: entryName(v.key), Placeholder: ph, Class: ClassCredential}
		if m, ok := findListed(v.key); ok {
			e.Ref = m.Ref.String()
			used[m.Ref.Secret().String()] = true
			s.Notes = append(s.Notes, "reference found in the store")
			if hs := splitList(m.Labels["scrim.hosts"]); len(hs) > 0 {
				e.Hosts = hs
				s.Notes = append(s.Notes, "hosts from store metadata")
			}
		} else {
			e.Ref = base + "/" + project + "/" + e.Name
			s.Notes = append(s.Notes, "candidate reference; move the value there or point ref at where it lives")
		}
		if len(e.Hosts) == 0 {
			if v.userinfo && v.host != "" {
				e.Hosts = []string{v.host}
				s.Notes = append(s.Notes, "host from the URL")
			} else if h := hostForKey(v.key, urlHost); h != "" {
				e.Hosts = []string{h}
				s.Notes = append(s.Notes, "host from a URL variable in the project")
			} else if h := providerHost(v.key); h != "" {
				e.Hosts = []string{h}
				s.Notes = append(s.Notes, "host from the provider name")
			} else {
				s.Notes = append(s.Notes, "no host found; add the hosts this credential may be sent to")
			}
		}
		for name, t := range o.Tools {
			if slices.Contains(t.Env, v.key) {
				e.Tools = append(e.Tools, name)
			}
		}
		sort.Strings(e.Tools)
		if v.empty {
			s.Notes = append(s.Notes, "the project already uses a placeholder or no value here")
		}
		if ref, err := stores.ParseRef(e.Ref); err == nil && mapped(ph, ref) {
			continue
		}
		if validateEntry(&e) != nil {
			continue
		}
		s.Entry = e
		out = append(out, s)
	}

	// Tool profiles whose credentials the project does not mention.
	for _, name := range slices.Sorted(maps.Keys(o.Tools)) {
		for _, key := range o.Tools[name].Env {
			key = strings.ToUpper(key)
			if seen[key] || !secretWords.MatchString(key) {
				continue
			}
			seen[key] = true
			e := Entry{Name: entryName(key), Placeholder: placeholderFor(key), Class: ClassCredential,
				Hosts: slices.Clone(o.Tools[name].Hosts), Tools: []string{name}}
			s := Suggestion{From: "tool profile " + name}
			if m, ok := findListed(key); ok {
				e.Ref = m.Ref.String()
				used[m.Ref.Secret().String()] = true
				s.Notes = append(s.Notes, "reference found in the store")
			} else {
				e.Ref = base + "/" + name + "/" + e.Name
				s.Notes = append(s.Notes, "candidate reference")
			}
			if ref, err := stores.ParseRef(e.Ref); err == nil && mapped(e.Placeholder, ref) {
				continue
			}
			if validateEntry(&e) != nil {
				continue
			}
			s.Entry = e
			out = append(out, s)
		}
	}

	// Store secrets nothing above matched.
	for _, m := range listed {
		if used[m.Ref.Secret().String()] || mapped("", m.Ref) {
			continue
		}
		seg := m.Ref.Path[strings.LastIndexByte(m.Ref.Path, '/')+1:]
		e := Entry{Name: entryName(normKey(seg)), Ref: m.Ref.Secret().String(), Placeholder: placeholderFor(normKey(seg)),
			Hosts: splitList(m.Labels["scrim.hosts"]), Class: ClassCredential}
		if e.Name == "" || seen[e.Placeholder] {
			continue
		}
		seen[e.Placeholder] = true
		s := Suggestion{From: m.Ref.Secret().String(), Notes: []string{"secret in the store not mapped by the catalog"}}
		if len(e.Hosts) == 0 {
			if h := providerHost(normKey(seg)); h != "" {
				e.Hosts = []string{h}
			} else {
				s.Notes = append(s.Notes, "no host found; add the hosts this credential may be sent to")
			}
		}
		if validateEntry(&e) != nil {
			continue
		}
		s.Entry = e
		out = append(out, s)
	}

	// Names must be unique in the draft.
	names := map[string]int{}
	for i := range out {
		n := out[i].Entry.Name
		names[n]++
		if names[n] > 1 {
			out[i].Entry.Name = fmt.Sprintf("%s-%d", n, names[n])
		}
	}
	return out, warnings, nil
}

func hostForKey(key string, urlHost map[string]string) string {
	parts := strings.Split(key, "_")
	for i := len(parts) - 1; i > 0; i-- {
		if h, ok := urlHost[strings.Join(parts[:i], "_")]; ok {
			return h
		}
	}
	return ""
}

func absOr(dir string) string {
	if dir == "" {
		dir = "."
	}
	if a, err := filepath.Abs(dir); err == nil {
		return a
	}
	return dir
}

// WriteSuggestions prints suggestions as a draft catalog file.
func WriteSuggestions(w io.Writer, sugg []Suggestion, warnings []string) error {
	var b strings.Builder
	b.WriteString("# scrim catalog suggest: draft entries only, nothing was applied.\n")
	b.WriteString("# Review and edit, then save as a catalog file (catalog.files) or copy into catalog.entries.\n")
	for _, w := range warnings {
		b.WriteString("# warning: " + oneLine(w) + "\n")
	}
	if len(sugg) == 0 {
		b.WriteString("# No suggestions: nothing unmapped was found.\n")
	}
	fmt.Fprintf(&b, "apiVersion: %s\nkind: %s\nentries:", config.APIVersion, FileKind)
	if len(sugg) == 0 {
		b.WriteString(" {}\n")
	} else {
		b.WriteString("\n")
	}
	for _, s := range sugg {
		e := s.Entry
		fmt.Fprintf(&b, "  %s:\n", e.Name)
		fmt.Fprintf(&b, "    # from %s; %s\n", oneLine(s.From), oneLine(strings.Join(s.Notes, "; ")))
		fmt.Fprintf(&b, "    ref: %s\n", yamlScalar(e.Ref))
		if len(e.Hosts) > 0 {
			fmt.Fprintf(&b, "    hosts: [%s]\n", strings.Join(e.Hosts, ", "))
		} else {
			b.WriteString("    hosts: []\n")
		}
		fmt.Fprintf(&b, "    placeholder: %s\n", e.Placeholder)
		if len(e.Tools) > 0 {
			fmt.Fprintf(&b, "    tools: [%s]\n", strings.Join(e.Tools, ", "))
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, s)
}

// yamlScalar double-quotes s; a Go-quoted string is a valid YAML scalar.
func yamlScalar(s string) string { return strconv.Quote(s) }
