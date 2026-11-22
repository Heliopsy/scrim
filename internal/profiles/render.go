// SPDX-License-Identifier: AGPL-3.0-only

package profiles

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/template"

	"github.com/heliopsy/scrim/internal/catalog"
)

// Bindings is what profiles read from the catalog; *catalog.Catalog
// implements it.
type Bindings interface {
	Entries() []catalog.Resolved
}

// Cred is one catalog entry filling a slot, as templates see it. It holds
// the placeholder, never a value.
type Cred struct {
	// Name is the catalog entry name.
	Name string
	// Placeholder is the entry's declared (or derived) placeholder.
	Placeholder string
	// Hosts are the bound hosts without wildcards.
	Hosts []string
	// Host is the first of Hosts, or "".
	Host string

	bound int // bound hosts, wildcards included
}

// Filled returns the entries filling each slot of p, keyed by slot name.
// Only resolved credential entries with a placeholder count.
func Filled(p *Profile, b Bindings) map[string][]Cred {
	out := map[string][]Cred{}
	if b == nil {
		return out
	}
	for _, r := range b.Entries() {
		bd := r.Binding
		if !r.OK || bd.Class == catalog.ClassDisplay || bd.Placeholder == "" {
			continue
		}
		for _, t := range bd.Tools {
			slot, ok := p.slotFor(t)
			if !ok {
				continue
			}
			c := Cred{Name: bd.Name, Placeholder: bd.Placeholder, bound: len(bd.Hosts)}
			for _, h := range bd.Hosts {
				if !strings.HasPrefix(h, "*.") {
					c.Hosts = append(c.Hosts, h)
				}
			}
			if len(c.Hosts) > 0 {
				c.Host = c.Hosts[0]
			}
			if !slices.ContainsFunc(out[slot.Name], func(o Cred) bool { return o.Name == c.Name }) {
				out[slot.Name] = append(out[slot.Name], c)
			}
		}
	}
	return out
}

// Selection is the outcome of [Set.Select].
type Selection struct {
	// Profiles are applied in this order.
	Profiles []*Profile
	// Warnings name profiles that were asked for but cannot apply, and why.
	Warnings []string
}

// Select picks the profiles for a session: the names in want (run.profiles),
// with "auto" standing for every profile the catalog fills, plus what they
// require. A profile with an unfilled required slot is left out with a
// warning. An unknown name is an error.
func (s *Set) Select(want []string, b Bindings) (Selection, error) {
	var sel Selection
	if slices.Contains(want, None) {
		return sel, nil
	}
	chosen := map[string]bool{}
	var order []string
	var add func(name string) error
	add = func(name string) error {
		p, ok := s.byName[name]
		if !ok {
			return fmt.Errorf("tool profile %q is not defined (run.profiles); scrim profiles list shows the profiles", name)
		}
		if chosen[name] {
			return nil
		}
		chosen[name] = true
		for _, r := range p.Requires {
			if err := add(r); err != nil {
				return err
			}
		}
		order = append(order, name)
		return nil
	}
	for _, n := range want {
		if n == Auto {
			continue
		}
		if err := add(n); err != nil {
			return sel, err
		}
	}
	if slices.Contains(want, Auto) {
		for _, n := range s.Names() {
			if len(Filled(s.byName[n], b)) > 0 {
				if err := add(n); err != nil {
					return sel, err
				}
			}
		}
	}
	for _, n := range order {
		p := s.byName[n]
		filled := Filled(p, b)
		var missing []string
		for _, slot := range p.Credentials {
			if slot.Required && len(filled[slot.Name]) == 0 {
				missing = append(missing, p.ToolName(slot.Name))
			}
		}
		if len(missing) > 0 {
			sel.Warnings = append(sel.Warnings, fmt.Sprintf("tool profile %s is not applied: no catalog entry names %s in its tools list",
				n, strings.Join(missing, " or ")))
			continue
		}
		sel.Profiles = append(sel.Profiles, p)
	}
	return sel, nil
}

// Session is where a session's profiles are rendered.
type Session struct {
	// Dir is the directory profiles write into; each profile gets
	// Dir/<name>. scrim run uses <session-dir>/profiles.
	Dir string
	// CABundle is the session's trust bundle (system roots plus scrim's CA),
	// for tools whose configuration names a CA file (kubeconfig).
	CABundle string
	// Home is the agent's home directory.
	Home string
	// Scrim is the scrim executable credential helpers run as; empty is
	// "scrim" from PATH.
	Scrim string
}

// EnvVar is one variable a profile sets.
type EnvVar struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Profile string `json:"profile"`
}

// GeneratedFile is one rendered file.
type GeneratedFile struct {
	// Path is relative to Session.Dir, slash-separated ("gh/hosts.yml").
	Path    string `json:"path"`
	Data    []byte `json:"-"`
	Profile string `json:"profile"`
}

// PathView is a fixed home-directory credential path and what a session
// filesystem view shows there.
type PathView struct {
	// Home is relative to the home directory.
	Home string `json:"home"`
	// Generated is the absolute path of the generated replacement, or ""
	// to hide Home.
	Generated string `json:"generated,omitempty"`
	Profile   string `json:"profile"`
}

// Rendered is everything the selected profiles change for a session. It
// holds placeholders and paths only.
type Rendered struct {
	// Profiles are the applied profile names, in order.
	Profiles []string `json:"profiles"`
	// Env are the variables to set, in a stable order.
	Env []EnvVar `json:"env,omitempty"`
	// Unset are inherited variables to remove.
	Unset []string `json:"unset,omitempty"`
	// Files are written under Session.Dir.
	Files []GeneratedFile `json:"files,omitempty"`
	// Dirs are directories to create under Session.Dir, slash-separated.
	Dirs []string `json:"dirs,omitempty"`
	// Paths are fixed credential paths for the session filesystem view.
	Paths []PathView `json:"paths,omitempty"`
	// Bin are credential helper names scrim run links to scrim in the
	// session's bin directory, first on PATH.
	Bin []string `json:"bin,omitempty"`
	// Hosts are the hosts each applied profile's credentials are bound to.
	Hosts map[string][]string `json:"hosts,omitempty"`
	// Warnings are shown before the agent starts.
	Warnings []string `json:"warnings,omitempty"`
}

// Render renders the profiles for one session. Variables set by two
// profiles to different values are an error.
func Render(ps []*Profile, b Bindings, sess Session) (*Rendered, error) {
	out := &Rendered{Hosts: map[string][]string{}}
	byName := map[string]int{}
	for _, p := range ps {
		filled := Filled(p, b)
		dir := filepath.Join(sess.Dir, p.Name)
		exec, err := p.executor(filled, sess)
		if err != nil {
			return nil, err
		}
		for _, k := range sortedKeys(p.Env) {
			v, err := exec("env:" + k)
			if err != nil {
				return nil, err
			}
			if v == "" && p.Env[k] != "" {
				continue // nothing to say: the slot or param it reads is empty
			}
			if i, ok := byName[k]; ok {
				if out.Env[i].Value != v {
					return nil, fmt.Errorf("tool profiles %s and %s both set %s to different values", out.Env[i].Profile, p.Name, k)
				}
				continue
			}
			byName[k] = len(out.Env)
			out.Env = append(out.Env, EnvVar{Name: k, Value: v, Profile: p.Name})
		}
		for _, f := range p.Files {
			v, err := exec("file:" + f.Path)
			if err != nil {
				return nil, err
			}
			if strings.TrimSpace(v) == "" {
				continue
			}
			out.Files = append(out.Files, GeneratedFile{Path: p.Name + "/" + f.Path, Data: []byte(v), Profile: p.Name})
		}
		for _, d := range p.Dirs {
			out.Dirs = append(out.Dirs, p.Name+"/"+d)
		}
		for _, u := range p.Unset {
			if !slices.Contains(out.Unset, u) {
				out.Unset = append(out.Unset, u)
			}
		}
		for _, b := range p.Bin {
			if !slices.Contains(out.Bin, b) {
				out.Bin = append(out.Bin, b)
			}
		}
		for _, pv := range p.Paths {
			v := PathView{Home: pv.Home, Profile: p.Name}
			if pv.Generated != "" {
				v.Generated = filepath.Join(dir, filepath.FromSlash(pv.Generated))
			}
			out.Paths = append(out.Paths, v)
		}
		var hosts []string
		for _, cs := range filled {
			for _, c := range cs {
				for _, h := range c.Hosts {
					if !slices.Contains(hosts, h) {
						hosts = append(hosts, h)
					}
				}
				if c.bound == 0 {
					out.Warnings = append(out.Warnings, fmt.Sprintf("tool profile %s: catalog entry %s has no bound hosts; its placeholder is never injected", p.Name, c.Name))
				}
			}
		}
		slices.Sort(hosts)
		out.Hosts[p.Name] = hosts
		out.Profiles = append(out.Profiles, p.Name)
	}
	for _, e := range out.Env {
		if slices.Contains(out.Unset, e.Name) {
			out.Unset = slices.DeleteFunc(out.Unset, func(s string) bool { return s == e.Name })
		}
	}
	slices.Sort(out.Unset)
	return out, nil
}

// executor returns a function rendering one of p's templates for a session.
func (p *Profile) executor(filled map[string][]Cred, sess Session) (func(name string) (string, error), error) {
	dir := filepath.Join(sess.Dir, p.Name)
	funcs := template.FuncMap{
		"placeholder": func(slot string) (string, error) {
			cs, err := slotCreds(p, filled, slot)
			if err != nil || len(cs) == 0 {
				return "", err
			}
			return cs[0].Placeholder, nil
		},
		"creds": func(slot string) ([]Cred, error) { return slotCreds(p, filled, slot) },
		"host": func(slot string) (string, error) {
			cs, err := slotCreds(p, filled, slot)
			if err != nil || len(cs) == 0 {
				return "", err
			}
			return cs[0].Host, nil
		},
		"param": func(k string) (string, error) {
			v, ok := p.Params[k]
			if !ok {
				return "", fmt.Errorf("param %q is not declared", k)
			}
			return v, nil
		},
		"path": func(rel string) (string, error) {
			if err := checkRel(rel); err != nil {
				return "", err
			}
			return filepath.Join(dir, filepath.FromSlash(rel)), nil
		},
		"dir":      func() string { return dir },
		"cabundle": func() string { return sess.CABundle },
		"home":     func() string { return sess.Home },
		"scrim": func() string {
			if sess.Scrim == "" {
				return "scrim"
			}
			return sess.Scrim
		},
		"authsjson": func(slot, user string, helper ...string) (string, error) {
			cs, err := slotCreds(p, filled, slot)
			if err != nil {
				return "", err
			}
			return authsJSON(cs, user, helper...)
		},
	}
	t, err := p.tmpl.Clone()
	if err != nil {
		return nil, err
	}
	t.Funcs(maps2(funcs, pureFuncs))
	return func(name string) (string, error) {
		var buf bytes.Buffer
		if err := t.ExecuteTemplate(&buf, name, nil); err != nil {
			return "", fmt.Errorf("tool profile %s: %w", p.Name, err)
		}
		return buf.String(), nil
	}, nil
}

// dockerHub are the names Docker Hub credentials are looked up under.
var dockerHub = []string{"docker.io", "index.docker.io", "registry-1.docker.io"}

// authsJSON is a container registry auth file ({"auths": {...}}) with a
// Basic credential of user and each entry's placeholder for each host. With
// a non-empty helper, credHelpers names it for each host, so the client
// asks docker-credential-<helper>, which answers from these auths.
func authsJSON(cs []Cred, user string, helper ...string) (string, error) {
	auths := map[string]map[string]string{}
	helpers := map[string]string{}
	h0 := ""
	if len(helper) > 0 {
		h0 = helper[0]
	}
	for _, c := range cs {
		for _, h := range c.Hosts {
			a := map[string]string{"auth": base64.StdEncoding.EncodeToString([]byte(user + ":" + c.Placeholder))}
			auths[h] = a
			if h0 != "" {
				helpers[h] = h0
			}
			if slices.Contains(dockerHub, h) {
				auths["https://index.docker.io/v1/"] = a
				if h0 != "" {
					helpers["docker.io"] = h0
				}
			}
		}
	}
	out := map[string]any{"auths": auths}
	if len(helpers) > 0 {
		out["credHelpers"] = helpers
	}
	b, err := json.MarshalIndent(out, "", "  ")
	return string(b) + "\n", err
}

// TestCommand renders p's test for a session: the command, its stdin and
// what its output must contain.
func TestCommand(p *Profile, b Bindings, sess Session) (cmd []string, stdin, expect string, err error) {
	if p.Test == nil {
		return nil, "", "", fmt.Errorf("tool profile %s has no test", p.Name)
	}
	exec, err := p.executor(Filled(p, b), sess)
	if err != nil {
		return nil, "", "", err
	}
	for i := range p.Test.Command {
		a, err := exec(fmt.Sprintf("test:arg%d", i))
		if err != nil {
			return nil, "", "", err
		}
		cmd = append(cmd, a)
	}
	if stdin, err = exec("test:stdin"); err != nil {
		return nil, "", "", err
	}
	if expect, err = exec("test:expect"); err != nil {
		return nil, "", "", err
	}
	return cmd, stdin, expect, nil
}

func slotCreds(p *Profile, filled map[string][]Cred, slot string) ([]Cred, error) {
	if _, ok := p.Slot(slot); !ok {
		return nil, fmt.Errorf("slot %q is not declared", slot)
	}
	return filled[slot], nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func maps2(a, b template.FuncMap) template.FuncMap {
	out := template.FuncMap{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// pureFuncs are the template functions that need no session.
var pureFuncs = template.FuncMap{
	"b64":   func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) },
	"basic": func(user, pass string) string { return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass)) },
	"json": func(v any) (string, error) {
		b, err := json.Marshal(v)
		return string(b), err
	},
	"envname": func(s string) string {
		var b strings.Builder
		for _, r := range s {
			switch {
			case r >= 'a' && r <= 'z':
				b.WriteRune(r - 'a' + 'A')
			case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
				b.WriteRune(r)
			default:
				b.WriteByte('_')
			}
		}
		return b.String()
	},
	"shquote": func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" },
	"stripport": func(h string) string {
		if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.Contains(h[i:], "]") {
			return h[:i]
		}
		return h
	},
}

// funcStubs lets templates parse before a session exists.
var funcStubs = maps2(template.FuncMap{
	"placeholder": func(string) (string, error) { return "", nil },
	"creds":       func(string) ([]Cred, error) { return nil, nil },
	"host":        func(string) (string, error) { return "", nil },
	"param":       func(string) (string, error) { return "", nil },
	"path":        func(string) (string, error) { return "", nil },
	"dir":         func() string { return "" },
	"cabundle":    func() string { return "" },
	"home":        func() string { return "" },
	"scrim":       func() string { return "" },
	"authsjson":   func(string, string, ...string) (string, error) { return "", nil },
}, pureFuncs)

// Write writes the rendered files under dir (Session.Dir) with directories
// 0700 and files 0600. scrim run removes dir when the session ends.
func (r *Rendered) Write(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, f := range r.Files {
		if err := checkRel(f.Path); err != nil {
			return fmt.Errorf("%s: %w", f.Path, err)
		}
		p := filepath.Join(dir, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(p, f.Data, 0o600); err != nil {
			return err
		}
	}
	for _, d := range r.Dirs {
		if err := checkRel(d); err != nil {
			return fmt.Errorf("%s: %w", d, err)
		}
		if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(d)), 0o700); err != nil {
			return err
		}
	}
	return nil
}
