// SPDX-License-Identifier: AGPL-3.0-only

package profiles

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/catalog"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/stores"
)

func TestBuiltinsLoad(t *testing.T) {
	s := Builtin()
	want := []string{"aws", "az", "cargo", "docker", "doctl", "gcloud", "gh", "git", "glab", "hcloud", "helm", "kubectl", "npm", "pip", "podman", "terraform", "twine"}
	if got := s.Names(); !slices.Equal(got, want) {
		t.Fatalf("built-in profiles %v, want %v", got, want)
	}
	for _, p := range s.All() {
		r, err := Render([]*Profile{p}, SampleBindings(p, "T"), Session{Dir: "/s", Home: "/h", CABundle: "/s/ca.pem"})
		if err != nil {
			t.Errorf("%s: %v", p.Name, err)
			continue
		}
		var all strings.Builder
		for _, e := range r.Env {
			all.WriteString(e.Value + "\n")
		}
		for _, f := range r.Files {
			all.Write(f.Data)
		}
		ph := SamplePlaceholder(p, p.Credentials[0].Name, "T")
		basic := base64.StdEncoding.EncodeToString([]byte(p.Params["username"] + ":" + ph))
		if !strings.Contains(all.String(), ph) && !strings.Contains(all.String(), basic) {
			t.Errorf("%s: the primary placeholder appears nowhere in the generated env or files", p.Name)
		}
		for _, pv := range r.Paths {
			if pv.Generated != "" && !strings.HasPrefix(pv.Generated, "/s/"+p.Name+"/") {
				t.Errorf("%s: path view %s points outside the profile directory: %s", p.Name, pv.Home, pv.Generated)
			}
		}
	}
}

func TestKubeconfig(t *testing.T) {
	p, _ := Builtin().Get("kubectl")
	b := bindings{
		{Name: "prod", Placeholder: "SCRIM_PROD_K8S", Hosts: []string{"k8s.example.com:6443"}, Tools: []string{"kubectl"}},
		{Name: "dev", Placeholder: "SCRIM_DEV_K8S", Hosts: []string{"dev.example.com"}, Tools: []string{"kubectl.token"}},
	}
	r, err := Render([]*Profile{p}, b, Session{Dir: "/s", CABundle: "/s/ca.pem"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Files) != 1 || r.Env[0] != (EnvVar{Name: "KUBECONFIG", Value: "/s/kubectl/kubeconfig", Profile: "kubectl"}) {
		t.Fatalf("unexpected render: %+v", r)
	}
	got := string(r.Files[0].Data)
	for _, want := range []string{"server: https://k8s.example.com:6443", "server: https://dev.example.com", "token: SCRIM_PROD_K8S",
		"token: SCRIM_DEV_K8S", "certificate-authority: /s/ca.pem", "current-context: prod"} {
		if !strings.Contains(got, want) {
			t.Errorf("kubeconfig lacks %q:\n%s", want, got)
		}
	}
}

func TestSelect(t *testing.T) {
	s := Builtin()
	b := bindings{
		{Name: "github", Placeholder: "SCRIM_GITHUB", Hosts: []string{"api.github.com"}, Tools: []string{"gh", "git"}},
		{Name: "aws-id", Placeholder: "SCRIM_AWS_ID", Hosts: []string{"s3.amazonaws.com"}, Tools: []string{"aws"}},
	}
	sel, err := s.Select([]string{Auto}, b)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range sel.Profiles {
		names = append(names, p.Name)
	}
	if !slices.Equal(names, []string{"gh", "git"}) {
		t.Errorf("auto selected %v, want gh and git", names)
	}
	if len(sel.Warnings) != 1 || !strings.Contains(sel.Warnings[0], "aws.secret-access-key") {
		t.Errorf("want a warning naming the missing aws slot, got %v", sel.Warnings)
	}
	if sel, _ := s.Select([]string{None}, b); len(sel.Profiles) != 0 {
		t.Error("none selected profiles")
	}
	if _, err := s.Select([]string{"nope"}, b); err == nil {
		t.Error("an unknown profile was accepted")
	}
}

func TestRenderConflict(t *testing.T) {
	a := &Profile{Name: "a", Description: "a", Credentials: []Slot{{Name: "t"}}, Env: map[string]string{"X_CFG": "{{ path \"a\" }}"}}
	c := &Profile{Name: "c", Description: "c", Credentials: []Slot{{Name: "t"}}, Env: map[string]string{"X_CFG": "{{ path \"c\" }}"}}
	for _, p := range []*Profile{a, c} {
		if err := p.validate(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Render([]*Profile{a, c}, nil, Session{Dir: "/s"}); err == nil {
		t.Error("two profiles setting one variable differently were accepted")
	}
}

func TestValidate(t *testing.T) {
	for name, src := range map[string]string{
		"reserved env":   "description: x\ncredentials: [{name: t}]\nenv: {HTTPS_PROXY: x}\n",
		"scrim env":      "description: x\ncredentials: [{name: t}]\nunset: [SCRIM_API_TOKEN]\n",
		"escaping file":  "description: x\ncredentials: [{name: t}]\nfiles: [{path: ../x, content: y}]\n",
		"absolute file":  "description: x\ncredentials: [{name: t}]\nfiles: [{path: /etc/x, content: y}]\n",
		"bad template":   "description: x\ncredentials: [{name: t}]\nenv: {X: '{{ placeholder }'}\n",
		"no credentials": "description: x\n",
		"unknown field":  "description: x\ncredentials: [{name: t}]\nvalue: secret\n",
		"bad host":       "description: x\ncredentials: [{name: t, hosts: ['https://x']}]\n",
	} {
		if _, err := ParseFile("x", []byte(src)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
}

func TestConfigOverrideAndCustom(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "scrim.yaml")
	if err := os.WriteFile(cfgFile, []byte(`apiVersion: scrim.dev/v1
kind: Config
tool-profiles:
  acme:
    description: In-house acme CLI
    credentials:
      - name: token
        hosts: [api.acme.internal]
    env:
      ACME_TOKEN: '{{ placeholder "token" }}'
  docker:
    params: {username: robot}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Build(config.Options{ConfigPaths: []string{cfgFile}, Environ: []string{}, SystemDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	s, err := Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	acme, ok := s.Get("acme")
	if !ok {
		t.Fatal("custom profile missing")
	}
	d, _ := s.Get("docker")
	if !d.Overridden || d.Params["username"] != "robot" || d.Env["DOCKER_CONFIG"] == "" {
		t.Errorf("docker override not merged: %+v", d)
	}
	// The catalog takes the profile's hosts for an entry naming it.
	cat, err := catalog.Load(context.Background(), withEntry(t, cfgFile), nil, catalog.Selection{})
	if err != nil {
		t.Fatal(err)
	}
	bd, err := cat.Name("acme-key")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(bd.Hosts, []string{"api.acme.internal"}) || bd.Placeholder != "SCRIM_ACME_KEY" ||
		!slices.Equal(bd.Derived, []string{"hosts", "placeholder"}) {
		t.Errorf("binding not filled from the profile: %+v", bd)
	}
	out, err := Render([]*Profile{acme}, cat, Session{Dir: "/s"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Env) != 1 || out.Env[0].Value != "SCRIM_ACME_KEY" {
		t.Errorf("custom profile env: %+v", out.Env)
	}
}

func withEntry(t *testing.T, base string) *config.Config {
	t.Helper()
	extra := filepath.Join(filepath.Dir(base), "catalog.yaml")
	if err := os.WriteFile(extra, []byte(`apiVersion: scrim.dev/v1
kind: Config
catalog:
  entries:
    acme-key:
      ref: file://acme/key
      tools: [acme]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Build(config.Options{ConfigPaths: []string{base, extra}, Environ: []string{}, SystemDir: filepath.Dir(base)})
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// TestCheckBuiltins runs every built-in profile's test command with the
// real tool where it is installed: the tool must print the generated
// placeholder and none of the decoys at its fixed home paths or in the
// variables the profile unsets (tasks 10a.6, 10a.10).
func TestCheckBuiltins(t *testing.T) {
	for _, p := range Builtin().All() {
		if p.Test == nil {
			continue
		}
		t.Run(p.Name, func(t *testing.T) {
			path := toolPath(t, p.Test.Command[0])
			res, err := Check(context.Background(), p, path)
			if errors.Is(err, ErrToolMissing) {
				if os.Getenv("SCRIM_E2E_REQUIRE_TOOLS") == "1" {
					t.Fatalf("%s is not installed and SCRIM_E2E_REQUIRE_TOOLS is set", p.Test.Command[0])
				}
				t.Skip(res.Skipped)
			}
			if err != nil {
				t.Fatalf("%v\n%s", err, res.Output)
			}
		})
	}
}

// toolPath is a PATH with the real executable's directory first, through
// version manager shims that need the user's HOME.
func toolPath(t *testing.T, name string) string {
	t.Helper()
	if name == "npm" || name == "npx" || name == "pnpm" {
		if node, err := exec.LookPath("node"); err == nil {
			if out, err := exec.Command(node, "-p", "process.execPath").Output(); err == nil { //nolint:gosec // test helper
				return filepath.Dir(strings.TrimSpace(string(out))) + string(os.PathListSeparator) + os.Getenv("PATH")
			}
		}
	}
	p, err := exec.LookPath(name)
	if err != nil {
		return os.Getenv("PATH")
	}
	if strings.Contains(p, "/shims/") {
		if out, err := exec.Command("asdf", "which", name).Output(); err == nil { //nolint:gosec // test helper
			p = strings.TrimSpace(string(out))
		}
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	return filepath.Dir(p) + string(os.PathListSeparator) + os.Getenv("PATH")
}

// bindings is a fixed list of catalog bindings.
type bindings []catalog.Binding

func (b bindings) Entries() []catalog.Resolved {
	out := make([]catalog.Resolved, 0, len(b))
	for _, bd := range b {
		bd.Ref = stores.Ref{Scheme: "file", Path: "x/" + bd.Name}
		bd.Class = catalog.ClassCredential
		out = append(out, catalog.Resolved{OK: true, Binding: bd})
	}
	return out
}
