// SPDX-License-Identifier: AGPL-3.0-only

package profiles

import (
	"errors"
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"
	"text/template"

	"github.com/heliopsy/scrim/internal/credhelper"
)

// Profile is one tool profile: where a command-line tool reads its
// credentials, which hosts it sends them to, and what scrim run generates so
// that the tool finds placeholders there.
type Profile struct {
	// Name is the profile name, also the word catalog entries name in their
	// tools list ("gh", or "aws.secret-access-key" for a slot other than the
	// first).
	Name string `yaml:"-" json:"name"`
	// Description is one line for `scrim profiles list`.
	Description string `yaml:"description" json:"description"`
	// Tools are the executables the profile is for, used by `scrim profiles
	// test` to find the tool and by auto-detection for display.
	Tools []string `yaml:"tools,omitempty" json:"tools,omitempty"`
	// Requires names profiles enabled together with this one (helm needs
	// kubectl's kubeconfig).
	Requires []string `yaml:"requires,omitempty" json:"requires,omitempty"`
	// Credentials are the slots catalog entries fill. The first is the
	// primary slot, which `tools: [<name>]` fills.
	Credentials []Slot `yaml:"credentials" json:"credentials"`
	// Params are named defaults the templates read with `param`; a
	// configuration override may change them.
	Params map[string]string `yaml:"params,omitempty" json:"params,omitempty"`
	// Env maps variable names to templates. A variable whose value renders
	// empty is not set.
	Env map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
	// Unset lists inherited variables removed when the profile is applied,
	// because they may hold the real credential (GITHUB_TOKEN,
	// AWS_SECRET_ACCESS_KEY). A trailing * removes every variable with that
	// prefix (TF_TOKEN_*).
	Unset []string `yaml:"unset,omitempty" json:"unset,omitempty"`
	// Files are generated under the profile's session directory. A file
	// whose content renders empty is not written.
	Files []File `yaml:"files,omitempty" json:"files,omitempty"`
	// Dirs are directories created under the profile's session directory
	// even when nothing is generated in them (GH_CONFIG_DIR), so the tool
	// finds an empty configuration instead of the real one and can write.
	Dirs []string `yaml:"dirs,omitempty" json:"dirs,omitempty"`
	// Paths are the fixed home-directory paths the tool reads credentials
	// from when no override variable points elsewhere. The session
	// filesystem view (10a.7) shows the generated file there, or hides the
	// path when Generated is empty.
	Paths []Path `yaml:"paths,omitempty" json:"paths,omitempty"`
	// Bin are credential helper executables (docker-credential-scrim) that
	// scrim run links to scrim in the session's bin directory, which it puts
	// first on PATH. Only names in credhelper.Binaries are accepted.
	Bin []string `yaml:"bin,omitempty" json:"bin,omitempty"`
	// Test is the command `scrim profiles test` and the session tests run to
	// show the tool reads only the generated configuration.
	Test *Test `yaml:"test,omitempty" json:"test,omitempty"`
	// Notes are caveats shown by `scrim profiles show`.
	Notes []string `yaml:"notes,omitempty" json:"notes,omitempty"`

	// Builtin is true for a profile shipped with scrim (possibly overridden).
	Builtin bool `yaml:"-" json:"builtin"`
	// Overridden is true when configuration changed a built-in profile.
	Overridden bool `yaml:"-" json:"overridden,omitempty"`

	tmpl *template.Template
}

// Slot is one credential a profile places.
type Slot struct {
	// Name is the slot name ("token", "secret-access-key").
	Name string `yaml:"name" json:"name"`
	// Description says what credential belongs here.
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	// Hosts are bound to an entry filling this slot when the entry names no
	// hosts itself. A leading "*." matches subdomains.
	Hosts []string `yaml:"hosts,omitempty" json:"hosts,omitempty"`
	// Inject are the injection locations the tool uses, applied the same way.
	Inject []string `yaml:"inject,omitempty" json:"inject,omitempty"`
	// Required slots must be filled for the profile to apply.
	Required bool `yaml:"required,omitempty" json:"required,omitempty"`
}

// File is one generated file.
type File struct {
	// Path is relative to the profile's session directory, slash-separated.
	Path string `yaml:"path" json:"path"`
	// Content is a text/template; see the package documentation.
	Content string `yaml:"content" json:"-"`
}

// Path is a fixed credential path in the home directory.
type Path struct {
	// Home is the path relative to the home directory (".aws/credentials").
	Home string `yaml:"home" json:"home"`
	// Generated is the file (relative to the profile's session directory)
	// shown at Home in a session filesystem view; empty hides Home.
	Generated string `yaml:"generated,omitempty" json:"generated,omitempty"`
}

// Test is a command that prints what the tool reads as its credential.
// Command, Stdin and Expect are templates rendered like the profile's files.
type Test struct {
	// Command is run with the profile's environment and an empty home.
	Command []string `yaml:"command" json:"command"`
	// Stdin is written to the command's standard input.
	Stdin string `yaml:"stdin,omitempty" json:"stdin,omitempty"`
	// Expect is what the output must contain, typically
	// `{{ placeholder "token" }}`.
	Expect string `yaml:"expect" json:"expect"`
}

var (
	namePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)
	envPattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	hostPattern = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]*[a-z0-9])?(:[0-9]{1,5})?$`)
)

// ErrInvalid wraps every profile validation error.
var ErrInvalid = errors.New("invalid tool profile")

// reservedEnv are variables a profile may not set or unset: scrim run owns
// them (proxy, trust, session) or changing them would change more than one
// tool (HOME, PATH, XDG_RUNTIME_DIR).
var reservedEnv = map[string]bool{
	"HOME": true, "PATH": true, "USER": true, "SHELL": true, "XDG_RUNTIME_DIR": true,
	"HTTPS_PROXY": true, "https_proxy": true, "HTTP_PROXY": true, "http_proxy": true,
	"ALL_PROXY": true, "all_proxy": true, "NO_PROXY": true, "no_proxy": true,
	"SSL_CERT_FILE": true, "SSL_CERT_DIR": true, "NODE_EXTRA_CA_CERTS": true,
	"LD_PRELOAD": true, "LD_LIBRARY_PATH": true,
}

// Reserved reports whether a profile may not touch the variable.
func Reserved(name string) bool {
	return reservedEnv[name] || strings.HasPrefix(name, "SCRIM_")
}

// Slot returns the named slot.
func (p *Profile) Slot(name string) (Slot, bool) {
	for _, s := range p.Credentials {
		if s.Name == name {
			return s, true
		}
	}
	return Slot{}, false
}

// ToolName is the word a catalog entry puts in its tools list to fill slot:
// the profile name for the primary slot, else "<profile>.<slot>".
func (p *Profile) ToolName(slot string) string {
	if len(p.Credentials) > 0 && p.Credentials[0].Name == slot {
		return p.Name
	}
	return p.Name + "." + slot
}

// slotFor maps a word from an entry's tools list to this profile's slot.
func (p *Profile) slotFor(tool string) (Slot, bool) {
	name, slot, dotted := strings.Cut(tool, ".")
	if name != p.Name || len(p.Credentials) == 0 {
		return Slot{}, false
	}
	if !dotted {
		return p.Credentials[0], true
	}
	return p.Slot(slot)
}

// validate checks the profile and compiles its templates.
func (p *Profile) validate() error {
	fail := func(format string, a ...any) error {
		return fmt.Errorf("%w %q: %s", ErrInvalid, p.Name, fmt.Sprintf(format, a...))
	}
	if !namePattern.MatchString(p.Name) {
		return fmt.Errorf("%w: name %q must be lower-case words joined by dashes", ErrInvalid, p.Name)
	}
	if strings.TrimSpace(p.Description) == "" {
		return fail("needs a description")
	}
	if len(p.Credentials) == 0 {
		return fail("declares no credentials")
	}
	seen := map[string]bool{}
	for _, s := range p.Credentials {
		if !namePattern.MatchString(s.Name) {
			return fail("credential slot %q must be lower-case words joined by dashes", s.Name)
		}
		if seen[s.Name] {
			return fail("credential slot %q is declared twice", s.Name)
		}
		seen[s.Name] = true
		for _, h := range s.Hosts {
			if !hostPattern.MatchString(h) {
				return fail("slot %s: host %q is not a host name", s.Name, h)
			}
		}
	}
	for _, r := range p.Requires {
		if !namePattern.MatchString(r) || r == p.Name {
			return fail("requires %q is not another profile's name", r)
		}
	}
	for k := range p.Params {
		if !namePattern.MatchString(k) {
			return fail("param %q must be lower-case words joined by dashes", k)
		}
	}
	for _, n := range slices.Concat(slices.Collect(maps.Keys(p.Env)), p.Unset) {
		if u, prefix := strings.CutSuffix(n, "*"); prefix && slices.Contains(p.Unset, n) {
			n = u + "X"
		}
		if !envPattern.MatchString(n) {
			return fail("%q is not an environment variable name", n)
		}
		if Reserved(n) {
			return fail("%s is set by scrim run itself and cannot be changed by a profile", n)
		}
	}
	for _, d := range p.Dirs {
		if err := checkRel(d); err != nil {
			return fail("dir %q: %v", d, err)
		}
	}
	files := map[string]bool{}
	for _, f := range p.Files {
		if err := checkRel(f.Path); err != nil {
			return fail("file %q: %v", f.Path, err)
		}
		if files[f.Path] {
			return fail("file %q is declared twice", f.Path)
		}
		files[f.Path] = true
	}
	for _, fp := range p.Paths {
		if err := checkRel(fp.Home); err != nil {
			return fail("path %q: %v", fp.Home, err)
		}
		if fp.Generated != "" && !files[fp.Generated] {
			if !hasFileUnder(files, fp.Generated) {
				return fail("path %q shows %q, which the profile does not generate", fp.Home, fp.Generated)
			}
		}
	}
	for _, b := range p.Bin {
		if !slices.Contains(credhelper.Binaries, b) {
			return fail("bin %q is not one of scrim's credential helpers (%s)", b, strings.Join(credhelper.Binaries, ", "))
		}
	}
	if p.Test != nil {
		if len(p.Test.Command) == 0 {
			return fail("test has no command")
		}
		if strings.TrimSpace(p.Test.Expect) == "" {
			return fail("test has no expect")
		}
	}
	return p.compile()
}

func hasFileUnder(files map[string]bool, dir string) bool {
	for f := range files {
		if strings.HasPrefix(f, dir+"/") {
			return true
		}
	}
	return false
}

// checkRel accepts a clean, relative, slash-separated path.
func checkRel(p string) error {
	switch {
	case p == "" || path.IsAbs(p) || strings.Contains(p, `\`):
		return errors.New("must be a relative path")
	case path.Clean(p) != p || p == "." || strings.HasPrefix(p, "../") || p == "..":
		return errors.New("must be a clean path inside the directory")
	}
	return nil
}

// compile parses every template once, so a broken template fails at load
// and not in the middle of a session.
func (p *Profile) compile() error {
	t := template.New(p.Name).Option("missingkey=error").Funcs(funcStubs)
	for _, k := range slices.Sorted(maps.Keys(p.Env)) {
		if _, err := t.New("env:" + k).Parse(p.Env[k]); err != nil {
			return fmt.Errorf("%w %q: env %s: %w", ErrInvalid, p.Name, k, err)
		}
	}
	for _, f := range p.Files {
		if _, err := t.New("file:" + f.Path).Parse(f.Content); err != nil {
			return fmt.Errorf("%w %q: file %s: %w", ErrInvalid, p.Name, f.Path, err)
		}
	}
	if p.Test != nil {
		for i, a := range p.Test.Command {
			if _, err := t.New(fmt.Sprintf("test:arg%d", i)).Parse(a); err != nil {
				return fmt.Errorf("%w %q: test command: %w", ErrInvalid, p.Name, err)
			}
		}
		if _, err := t.New("test:stdin").Parse(p.Test.Stdin); err != nil {
			return fmt.Errorf("%w %q: test stdin: %w", ErrInvalid, p.Name, err)
		}
		if _, err := t.New("test:expect").Parse(p.Test.Expect); err != nil {
			return fmt.Errorf("%w %q: test expect: %w", ErrInvalid, p.Name, err)
		}
	}
	p.tmpl = t
	return nil
}

// clone returns a deep copy without compiled templates.
func (p *Profile) clone() *Profile {
	c := *p
	c.Tools = slices.Clone(p.Tools)
	c.Requires = slices.Clone(p.Requires)
	c.Credentials = make([]Slot, len(p.Credentials))
	for i, s := range p.Credentials {
		s.Hosts, s.Inject = slices.Clone(s.Hosts), slices.Clone(s.Inject)
		c.Credentials[i] = s
	}
	c.Params = maps.Clone(p.Params)
	c.Env = maps.Clone(p.Env)
	c.Unset = slices.Clone(p.Unset)
	c.Files = slices.Clone(p.Files)
	c.Paths = slices.Clone(p.Paths)
	c.Dirs = slices.Clone(p.Dirs)
	c.Bin = slices.Clone(p.Bin)
	c.Notes = slices.Clone(p.Notes)
	if p.Test != nil {
		t := *p.Test
		t.Command = slices.Clone(p.Test.Command)
		c.Test = &t
	}
	c.tmpl = nil
	return &c
}
