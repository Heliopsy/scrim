// SPDX-License-Identifier: AGPL-3.0-only

package profiles

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/catalog"
)

// sampleBindings fills every slot of p with one entry named
// <profile>-<slot>, a placeholder SCRIM_<tag>_<PROFILE>_<SLOT> and the slot's
// hosts (or <profile>.scrim.test). Nothing in it is a value.
type sampleBindings struct {
	p   *Profile
	tag string
}

// SampleBindings returns bindings that fill every slot of p with a sample
// placeholder, for `scrim profiles test` and tests.
func SampleBindings(p *Profile, tag string) Bindings { return sampleBindings{p: p, tag: tag} }

// SamplePlaceholder is the placeholder SampleBindings gives a slot.
func SamplePlaceholder(p *Profile, slot, tag string) string {
	return "SCRIM_" + tag + "_" + envUpper(p.Name) + "_" + envUpper(slot)
}

func envUpper(s string) string { return strings.ToUpper(strings.ReplaceAll(s, "-", "_")) }

func (s sampleBindings) Entries() []catalog.Resolved {
	var out []catalog.Resolved
	for _, slot := range s.p.Credentials {
		var hosts []string
		for _, h := range slot.Hosts {
			if !strings.HasPrefix(h, "*.") {
				hosts = append(hosts, h)
			}
		}
		if len(hosts) == 0 {
			hosts = []string{s.p.Name + ".scrim.test"}
		}
		name := s.p.Name + "-" + slot.Name
		out = append(out, catalog.Resolved{OK: true, Binding: catalog.Binding{
			Name: name, Placeholder: SamplePlaceholder(s.p, slot.Name, s.tag), Hosts: hosts,
			Class: catalog.ClassCredential, Tools: []string{s.p.ToolName(slot.Name)},
		}})
	}
	return out
}

// CheckResult is the outcome of [Check].
type CheckResult struct {
	Command []string
	Output  string
	// Skipped says why the check did not run (the tool is not installed).
	Skipped string
}

// ErrToolMissing is returned when the profile's test command is not
// installed.
var ErrToolMissing = errors.New("tool not installed")

// Check runs p's test command the way a session would: with an empty home
// directory, the profile rendered into a session directory, and decoys
// that must not be read: the fixed home paths hold the profile's files
// rendered with other placeholders, and every variable the profile unsets
// is inherited with another placeholder. It fails unless the output holds
// the expected placeholder and none of the decoys. path is the PATH to run
// with; empty is the current one.
func Check(ctx context.Context, p *Profile, path string) (CheckResult, error) {
	if p.Test == nil {
		return CheckResult{}, fmt.Errorf("tool profile %s has no test", p.Name)
	}
	if path == "" {
		path = os.Getenv("PATH")
	}
	exe, err := lookPath(p.Test.Command[0], path)
	if err != nil {
		return CheckResult{Skipped: p.Test.Command[0] + " is not installed"}, fmt.Errorf("%w: %s", ErrToolMissing, p.Test.Command[0])
	}
	root, err := os.MkdirTemp("", "scrim-profile-check-")
	if err != nil {
		return CheckResult{}, err
	}
	defer func() { _ = os.RemoveAll(root) }()
	home, sessDir := filepath.Join(root, "home"), filepath.Join(root, "session")
	for _, d := range []string{home, sessDir, filepath.Join(root, "tmp")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return CheckResult{}, err
		}
	}
	sess := Session{Dir: sessDir, Home: home, CABundle: filepath.Join(root, "ca-bundle.pem")}
	// The session bundle exists in a session; tools check the path.
	if err := os.WriteFile(sess.CABundle, nil, 0o600); err != nil {
		return CheckResult{}, err
	}
	real := SampleBindings(p, "CHECK")
	r, err := Render([]*Profile{p}, real, sess)
	if err != nil {
		return CheckResult{}, err
	}
	if err := r.Write(sessDir); err != nil {
		return CheckResult{}, err
	}

	// Decoys: what the tool would read without the profile.
	decoy := SampleBindings(p, "DECOY")
	dr, err := Render([]*Profile{p}, decoy, Session{Dir: filepath.Join(root, "decoy"), Home: home, CABundle: sess.CABundle})
	if err != nil {
		return CheckResult{}, err
	}
	for _, pv := range p.Paths {
		if pv.Generated == "" {
			continue
		}
		for _, f := range dr.Files {
			if f.Path == p.Name+"/"+pv.Generated {
				dst := filepath.Join(home, filepath.FromSlash(pv.Home))
				if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
					return CheckResult{}, err
				}
				if err := os.WriteFile(dst, f.Data, 0o600); err != nil {
					return CheckResult{}, err
				}
			}
		}
	}
	env := []string{"PATH=" + path, "HOME=" + home, "LANG=C.UTF-8", "TERM=dumb", "TMPDIR=" + filepath.Join(root, "tmp"),
		"XDG_CONFIG_HOME=" + filepath.Join(home, ".config"), "XDG_CACHE_HOME=" + filepath.Join(home, ".cache"),
		"XDG_DATA_HOME=" + filepath.Join(home, ".local/share"), "XDG_STATE_HOME=" + filepath.Join(home, ".local/state")}
	var decoys []string
	for _, slot := range p.Credentials {
		decoys = append(decoys, SamplePlaceholder(p, slot.Name, "DECOY"))
	}
	for _, u := range p.Unset {
		if pre, ok := strings.CutSuffix(u, "*"); ok {
			u = pre + "DECOY"
		}
		env = append(env, u+"="+decoys[0])
	}
	env = Apply(env, r)

	cmdArgs, stdin, expect, err := TestCommand(p, real, sess)
	if err != nil {
		return CheckResult{}, err
	}
	res := CheckResult{Command: cmdArgs}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, cmdArgs[1:]...) //nolint:gosec // the profile's own test command
	cmd.Env, cmd.Dir = env, home
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	runErr := cmd.Run()
	res.Output = out.String()
	for _, d := range decoys {
		if strings.Contains(res.Output, d) {
			return res, fmt.Errorf("tool profile %s: %s read a decoy credential from outside the generated configuration", p.Name, cmdArgs[0])
		}
	}
	if !strings.Contains(res.Output, expect) {
		if runErr != nil {
			return res, fmt.Errorf("tool profile %s: %s failed (%w) and did not print %s", p.Name, strings.Join(cmdArgs, " "), runErr, expect)
		}
		return res, fmt.Errorf("tool profile %s: %s did not print %s", p.Name, strings.Join(cmdArgs, " "), expect)
	}
	return res, nil
}

// Apply returns environ with r's unsets removed (a trailing * removes a
// prefix) and its variables set.
func Apply(environ []string, r *Rendered) []string {
	set := map[string]string{}
	for _, e := range r.Env {
		set[e.Name] = e.Value
	}
	out := make([]string, 0, len(environ)+len(r.Env))
	for _, kv := range environ {
		k, _, _ := strings.Cut(kv, "=")
		if _, ok := set[k]; ok || Unsets(r.Unset, k) {
			continue
		}
		out = append(out, kv)
	}
	for _, e := range r.Env {
		out = append(out, e.Name+"="+e.Value)
	}
	return out
}

// Unsets reports whether name matches one of the unset entries.
func Unsets(unset []string, name string) bool {
	return slices.ContainsFunc(unset, func(u string) bool {
		if pre, ok := strings.CutSuffix(u, "*"); ok {
			return strings.HasPrefix(name, pre)
		}
		return u == name
	})
}

func lookPath(name, path string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	for _, dir := range filepath.SplitList(path) {
		if dir == "" {
			continue
		}
		f := filepath.Join(dir, name)
		if st, err := os.Stat(f); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return f, nil
		}
	}
	return "", fmt.Errorf("%s: not found in PATH", name)
}
