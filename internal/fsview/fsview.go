// SPDX-License-Identifier: AGPL-3.0-only

// Package fsview builds the session filesystem view of `scrim run`
// (specs/credential-injection, "Session filesystem view for fixed paths" and
// "Filesystem view fallback without namespaces"; tasks 10a.7, 10a.8).
//
// Some tools read credentials from a fixed path in the home directory and
// have no variable to point them elsewhere (doctl's config.yaml), or find
// the home directory through the password database instead of HOME. The
// view covers those paths for the agent's process tree:
//
//   - namespace (Linux): the agent starts in an unprivileged user and mount
//     namespace that maps only the caller's own uid and gid. Each covered
//     path that exists, in $HOME and in the password-database home, has the
//     generated placeholder file bind-mounted over it, or an empty,
//     unreadable, read-only file or directory when it is hidden. The rest
//     of the filesystem is unchanged. The agent runs without capabilities,
//     so it cannot unmount them, and the kernel locks the mounts against a
//     nested namespace. The real files are not readable from the session.
//   - home (fallback, macOS and hosts without user namespaces): HOME points
//     at a session home that mirrors the real one with symbolic links,
//     except the covered paths, which link to the generated file or are
//     left out. Tools that bypass HOME still reach the real files; [Gaps]
//     names them and `scrim status` lists them.
//
// Covered paths are the fixed paths of the applied tool profiles
// (profiles.Rendered.Paths) and the patterns in run.fs-view-hide.
//
// The namespace is set up by the scrim executable itself, started again
// under the name [HelperName] by [Wrap]: Go cannot run code between fork and
// exec, so the mounts happen in that helper, which then executes the agent
// in place with every capability dropped. Programs that embed this package
// call [Main] first thing in main (and in TestMain), or the helper never
// runs and every wrapped start is refused.
package fsview

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/heliopsy/scrim/internal/config"
)

// Modes of run.fs-view and of a built [Plan].
const (
	// ModeAuto uses a namespace where the host allows one and the home
	// mirror elsewhere.
	ModeAuto = "auto"
	// ModeNamespace requires the namespace view: scrim run refuses to start
	// the agent when the host has no unprivileged user namespaces.
	ModeNamespace = "namespace"
	// ModeHome always uses the home mirror.
	ModeHome = "home"
	// ModeOff leaves the home directory as it is.
	ModeOff = "off"
)

// Settings owned by the filesystem view.
var (
	// Setting picks the view.
	Setting = config.Register(config.Spec[string]{
		Key:     "run.fs-view",
		Default: ModeAuto,
		Enum:    []string{ModeAuto, ModeNamespace, ModeHome, ModeOff},
		Description: "Session filesystem view for credential files at fixed home paths: auto (a user and mount namespace " +
			"where the host allows it, the home mirror elsewhere), namespace (refuse to start the agent without one), " +
			"home (HOME points at a mirror of the home directory without the real credential files) or off. " +
			"See docs/run.md.",
		Flag: true,
	})

	// Hide lists home-relative paths hidden in every session.
	Hide = config.Register(config.Spec[[]string]{
		Key:     "run.fs-view-hide",
		Default: DefaultHide,
		Description: "Home-relative paths or glob patterns hidden by the session filesystem view in addition to the " +
			"fixed paths of the applied tool profiles; a leading ! takes matches out again.",
		Validate: func(v []string) error {
			for _, p := range v {
				if err := checkPattern(strings.TrimPrefix(p, "!")); err != nil {
					return fmt.Errorf("%q: %w", p, err)
				}
			}
			return nil
		},
	})
)

// DefaultHide is run.fs-view-hide's default: ssh private keys, not their
// public halves.
var DefaultHide = []string{".ssh/id_*", "!.ssh/id_*.pub"}

// HideOrigin names run.fs-view-hide as the origin of an entry.
const HideOrigin = "run.fs-view-hide"

// Path is a home-relative path to cover.
type Path struct {
	// Home is relative to the home directory, slash-separated.
	Home string
	// Source is the absolute path of the generated replacement, or "" to
	// hide the path.
	Source string
	// Origin is the tool profile (or HideOrigin) that asked for it.
	Origin string
}

// Entry is one covered path in one home directory.
type Entry struct {
	// Home is the path relative to the home directory.
	Home string `json:"home"`
	// Target is the absolute path the agent sees.
	Target string `json:"target"`
	// Source is the generated replacement shown at Target; "" hides it.
	Source string `json:"source,omitempty"`
	// Dir is true when Target is a directory.
	Dir    bool   `json:"dir,omitempty"`
	Origin string `json:"origin"`
}

// Hidden reports whether the entry hides its target.
func (e Entry) Hidden() bool { return e.Source == "" }

// Availability says whether the namespace view works on this host.
type Availability struct {
	Namespace bool   `json:"namespace"`
	Reason    string `json:"reason,omitempty"`
}

// Input is what a plan is built from.
type Input struct {
	// Mode is run.fs-view; empty is off.
	Mode string
	// Available reports whether the namespace view works. It is called
	// only when the namespace view would cover something.
	Available func() Availability
	// Home is $HOME as the agent inherits it.
	Home string
	// PasswdHome is the home directory in the password database; empty
	// looks it up.
	PasswdHome string
	// Paths are the tool profiles' fixed paths.
	Paths []Path
	// Hide are run.fs-view-hide patterns.
	Hide []string
	// SessionDir is the session directory; the view keeps its files in
	// SessionDir/fsview.
	SessionDir string
}

// Plan is the view for one session. It holds paths only.
type Plan struct {
	// Mode is the view in effect: namespace, home or off.
	Mode string `json:"mode"`
	// Requested is run.fs-view.
	Requested string `json:"requested"`
	// Fallback is set when auto fell back to the home mirror, with the
	// reason the namespace view is unavailable.
	Fallback string `json:"fallback,omitempty"`
	// Homes are the home directories covered.
	Homes []string `json:"homes,omitempty"`
	// Entries are the covered paths, by target.
	Entries []Entry `json:"entries,omitempty"`
	// SessionHome is HOME for the agent in home mode.
	SessionHome string `json:"session_home,omitempty"`
	// Gaps are what the view does not cover.
	Gaps []string `json:"gaps,omitempty"`

	dir  string
	home string
}

// Active reports whether the view changes anything for the agent.
func (p *Plan) Active() bool { return p != nil && p.Mode != ModeOff && len(p.Entries) > 0 }

// Gap texts, shared by plans and status.
var (
	gapsNamespace = []string{
		"setuid programs (sudo, newuidmap and so rootless podman) gain no privileges inside the view's user namespace; use run.fs-view: home for such sessions",
		"services outside the session (systemd --user, D-Bus, ssh to localhost, a container engine's daemon) can still read the real files on the agent's behalf",
		"a covered path created after the session started is not covered",
	}
	gapsHome = []string{
		"tools that find the home directory through the password database instead of HOME (ssh, scp, sftp, git over ssh) read the real files",
		"the real files stay readable at their absolute paths in the real home directory: the mirror only changes where HOME leads",
		"new files at the top of the home directory or inside a mirrored credential directory stay in the session home and are removed with it",
	}
	gapsDarwin = "credentials kept in the macOS Keychain (git-credential-osxkeychain, docker-credential-osxkeychain, gh's keyring) are not files and are not covered"
	gapsOff    = []string{"the real credential files in the home directory are readable from the session"}
)

// Gaps lists what a view in mode does not cover.
func Gaps(mode string) []string {
	var out []string
	switch mode {
	case ModeNamespace:
		out = slices.Clone(gapsNamespace)
	case ModeHome:
		out = slices.Clone(gapsHome)
		if runtime.GOOS == "darwin" {
			out = append(out, gapsDarwin)
		}
	default:
		out = slices.Clone(gapsOff)
	}
	return out
}

// Resolve picks the view a requested mode gives on a host: the mode in
// effect, and the fallback reason when auto falls back.
func Resolve(requested string, avail Availability) (mode, fallback string, err error) {
	switch requested {
	case "", ModeOff:
		return ModeOff, "", nil
	case ModeHome:
		return ModeHome, "", nil
	case ModeNamespace:
		if !avail.Namespace {
			return "", "", fmt.Errorf("run.fs-view is namespace, but this host has no unprivileged user and mount namespaces: %s", avail.Reason)
		}
		return ModeNamespace, "", nil
	case ModeAuto:
		if avail.Namespace {
			return ModeNamespace, "", nil
		}
		return ModeHome, avail.Reason, nil
	}
	return "", "", fmt.Errorf("run.fs-view %q is not one of auto, namespace, home, off", requested)
}

// Build resolves the covered paths in the home directories and picks the
// view. It reads directory listings and file types, never file contents,
// and writes nothing; [Plan.Prepare] does.
func Build(in Input) (*Plan, error) {
	p := &Plan{Requested: in.Mode, Mode: ModeOff, dir: filepath.Join(in.SessionDir, "fsview"), home: filepath.Clean(in.Home)}
	if p.Requested == "" {
		p.Requested = ModeOff
	}
	if in.Mode == "" || in.Mode == ModeOff {
		p.Gaps = Gaps(ModeOff)
		return p, nil
	}
	if in.Home == "" || !filepath.IsAbs(in.Home) {
		return nil, errors.New("the session filesystem view needs an absolute HOME")
	}
	pw := in.PasswdHome
	if pw == "" {
		if u, err := user.Current(); err == nil {
			pw = u.HomeDir
		}
	}
	// Probe only when there is something to cover: a probe starts a
	// process, and a session with nothing to hide needs no namespace.
	homes := uniqueHomes(in.Home, pw)
	nsEntries, err := entries(homes, in.Paths, in.Hide, false)
	if err != nil {
		return nil, err
	}
	avail := Availability{Reason: "not checked"}
	if in.Mode == ModeNamespace || (in.Mode == ModeAuto && len(nsEntries) > 0) {
		if in.Available != nil {
			avail = in.Available()
		} else {
			avail = Availability{Reason: "no check available"}
		}
	}
	mode, fallback, err := Resolve(in.Mode, avail)
	if err != nil {
		return nil, err
	}
	p.Mode, p.Fallback = mode, fallback
	switch mode {
	case ModeNamespace:
		p.Homes, p.Entries = homes, nsEntries
	case ModeHome:
		p.Homes = []string{p.home}
		if p.Entries, err = entries(p.Homes, in.Paths, in.Hide, true); err != nil {
			return nil, err
		}
		if len(p.Entries) > 0 {
			p.SessionHome = filepath.Join(p.dir, "home")
		}
	}
	p.Gaps = Gaps(mode)
	return p, nil
}

// uniqueHomes returns the home directories to cover, one per real
// directory.
func uniqueHomes(homes ...string) []string {
	var out, seen []string
	for _, h := range homes {
		if h == "" || !filepath.IsAbs(h) {
			continue
		}
		h = filepath.Clean(h)
		real, err := filepath.EvalSymlinks(h)
		if err != nil {
			real = h
		}
		if slices.Contains(seen, real) {
			continue
		}
		seen = append(seen, real)
		out = append(out, h)
	}
	return out
}

// entries expands paths and hide patterns in each home. A replacement wins
// over a hide for the same path, the first replacement over a later one.
// keepMissing keeps replacements whose target does not exist (the home
// mirror can show them; a mount cannot).
func entries(homes []string, paths []Path, hide []string, keepMissing bool) ([]Entry, error) {
	var out []Entry
	for _, home := range homes {
		byRel := map[string]int{}
		add := func(e Entry) {
			if i, ok := byRel[e.Home]; ok {
				if out[i].Hidden() && !e.Hidden() {
					out[i] = e
				}
				return
			}
			byRel[e.Home] = len(out)
			out = append(out, e)
		}
		for _, pth := range paths {
			if err := checkPattern(pth.Home); err != nil {
				return nil, fmt.Errorf("tool profile %s: path %q: %w", pth.Origin, pth.Home, err)
			}
			e := Entry{Home: pth.Home, Target: filepath.Join(home, filepath.FromSlash(pth.Home)), Source: pth.Source, Origin: pth.Origin}
			st, err := os.Stat(e.Target)
			exists := err == nil
			if exists {
				e.Dir = st.IsDir()
			}
			if e.Source != "" {
				// The caller passes a source only when the profile generates
				// it; in a dry run it is not written yet.
				src, err := os.Stat(e.Source)
				switch {
				case err != nil && !errors.Is(err, os.ErrNotExist):
					return nil, fmt.Errorf("tool profile %s: %w", pth.Origin, err)
				case err != nil:
				case exists && src.IsDir() != e.Dir:
					// A file where the real path is a directory, or the
					// other way round: hide rather than guess.
					e.Source = ""
				case !exists:
					e.Dir = src.IsDir()
				}
			}
			if !exists && (e.Source == "" || !keepMissing) {
				continue
			}
			add(e)
		}
		matched, err := expandHide(home, hide)
		if err != nil {
			return nil, err
		}
		for _, rel := range matched {
			target := filepath.Join(home, filepath.FromSlash(rel))
			st, err := os.Stat(target)
			if err != nil {
				continue
			}
			add(Entry{Home: rel, Target: target, Dir: st.IsDir(), Origin: HideOrigin})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out, nil
}

// expandHide matches the hide patterns in home, applying ! exclusions in
// order.
func expandHide(home string, patterns []string) ([]string, error) {
	var out []string
	for _, pat := range patterns {
		neg := strings.HasPrefix(pat, "!")
		pat = strings.TrimPrefix(pat, "!")
		if err := checkPattern(pat); err != nil {
			return nil, fmt.Errorf("%s %q: %w", HideOrigin, pat, err)
		}
		if neg {
			out = slices.DeleteFunc(out, func(rel string) bool {
				ok, _ := filepath.Match(pat, rel)
				return ok
			})
			continue
		}
		matches, err := filepath.Glob(filepath.Join(home, filepath.FromSlash(pat)))
		if err != nil {
			return nil, fmt.Errorf("%s %q: %w", HideOrigin, pat, err)
		}
		for _, m := range matches {
			rel, err := filepath.Rel(home, m)
			if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
				continue
			}
			rel = filepath.ToSlash(rel)
			if !slices.Contains(out, rel) {
				out = append(out, rel)
			}
		}
	}
	return out, nil
}

func checkPattern(p string) error {
	switch {
	case p == "" || p == "." || p == "*":
		return errors.New("must name a path below the home directory")
	case filepath.IsAbs(p) || strings.HasPrefix(p, "/"):
		return errors.New("must be relative to the home directory")
	case slices.Contains(strings.Split(p, "/"), ".."):
		return errors.New("must not leave the home directory")
	}
	if _, err := filepath.Match(p, ""); err != nil {
		return err
	}
	return nil
}

// Var is an environment variable the view sets.
type Var struct {
	Name, Value, Why string
}

// Vars are the variables the home mirror sets: HOME and the XDG base
// directories that point into the real home. Other modes set none.
func (p *Plan) Vars(environ []string) []Var {
	if p == nil || p.Mode != ModeHome || p.SessionHome == "" {
		return nil
	}
	out := []Var{{Name: "HOME", Value: p.SessionHome, Why: "session home: mirrors the real one without its credential files (filesystem view fallback)"}}
	env := map[string]string{}
	for _, kv := range environ {
		k, v, _ := strings.Cut(kv, "=")
		env[k] = v
	}
	for _, k := range []string{"XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"} {
		v := env[k]
		if v == "" {
			continue
		}
		rel, err := filepath.Rel(p.home, v)
		if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
			continue
		}
		out = append(out, Var{Name: k, Value: filepath.Join(p.SessionHome, rel), Why: "moved into the session home with HOME"})
	}
	return out
}

// Files the namespace view mounts over hidden paths.
const (
	hiddenFile = "hidden"
	hiddenDir  = "hidden.d"
)

// Prepare writes what the view needs into the session directory: the empty
// files mounted over hidden paths, or the mirrored home. The session
// directory's removal removes them.
func (p *Plan) Prepare() error {
	if !p.Active() {
		return nil
	}
	if err := os.MkdirAll(p.dir, 0o700); err != nil {
		return err
	}
	switch p.Mode {
	case ModeNamespace:
		f, err := os.OpenFile(filepath.Join(p.dir, hiddenFile), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		if err := os.Mkdir(filepath.Join(p.dir, hiddenDir), 0o700); err != nil {
			return err
		}
		// Unreadable: `cat` of a hidden path fails instead of printing
		// nothing. The mounts are read-only, so the agent cannot chmod them.
		if err := os.Chmod(filepath.Join(p.dir, hiddenFile), 0); err != nil {
			return err
		}
		return os.Chmod(filepath.Join(p.dir, hiddenDir), 0)
	case ModeHome:
		return p.mirror()
	}
	return nil
}

// mirror builds the session home: symbolic links to every entry of the
// real home, real directories along the way to a covered path, a link to
// the generated file at a replaced path and nothing at a hidden one.
func (p *Plan) mirror() error {
	covered := map[string]Entry{}
	for _, e := range p.Entries {
		covered[e.Home] = e
	}
	return mirrorDir(p.home, p.SessionHome, "", covered)
}

func mirrorDir(real, mir, prefix string, covered map[string]Entry) error {
	if err := os.MkdirAll(mir, 0o700); err != nil {
		return err
	}
	names := map[string]bool{}
	if des, err := os.ReadDir(real); err == nil {
		for _, de := range des {
			names[de.Name()] = true
		}
	}
	for rel := range covered {
		if r, ok := strings.CutPrefix(rel, prefix); ok {
			first, _, _ := strings.Cut(r, "/")
			names[first] = true
		}
	}
	for name := range names {
		rel := prefix + name
		dst := filepath.Join(mir, name)
		if e, ok := covered[rel]; ok {
			if e.Source != "" {
				if err := os.Symlink(e.Source, dst); err != nil {
					return err
				}
			}
			continue
		}
		below := false
		for c := range covered {
			if strings.HasPrefix(c, rel+"/") {
				below = true
				break
			}
		}
		src := filepath.Join(real, name)
		if below {
			if st, err := os.Stat(src); err != nil || st.IsDir() {
				if err := mirrorDir(src, dst, rel+"/", covered); err != nil {
					return err
				}
				continue
			}
		}
		if _, err := os.Lstat(src); err != nil {
			continue
		}
		if err := os.Symlink(src, dst); err != nil {
			return err
		}
	}
	return nil
}
