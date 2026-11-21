// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

// Package profiles runs real command-line tools (gh, git, kubectl, helm,
// podman, npm, terraform, tofu, gcloud, az, pip, twine, cargo, hcloud,
// doctl, aws) under `scrim run` with their tool profiles applied, against
// a fake of each tool's API on the tool's default host inside the sandbox
// (tasks 10a.1, 10a.5, 10a.6, 10a.10), and the session filesystem view
// (10a.7). Run it with `just e2e-profiles`.
//
// Each tool sees only placeholders: its credentials come from the
// variables and files the profile generates in the session directory, the
// API accepts only the real value, and the tool proxy injects it toward
// the bound hosts. Every output, the session's environment and every
// generated file are checked for the real values.
package profiles

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/test/e2e/harness"
)

// secrets are the store's values by name; each is a catalog entry of the
// same name.
var secretKinds = map[string]leak.Kind{
	"github": leak.KindGitHubToken, "k8s": leak.KindJWT, "registry": leak.KindPassword, "npm": leak.KindAPIKey,
	"terraform": leak.KindAPIKey, "gcp": leak.KindAPIKey, "azure": leak.KindPassword, "pypi": leak.KindAPIKey,
	"pypi-upload": leak.KindAPIKey, "crates": leak.KindAPIKey, "hcloud": leak.KindAPIKey, "digitalocean": leak.KindAPIKey,
	"aws-id": leak.KindAWSAccessKey, "aws-secret": leak.KindAWSSecret,
}

// catalog names each entry's tool profile; most take the profile's default
// hosts and a derived placeholder (SCRIM_<NAME>).
const catalogYAML = `    github: {ref: e2e://tools/github, tools: [gh, git]}
    k8s: {ref: e2e://tools/k8s, hosts: [k8s.scrim.test], tools: [kubectl]}
    registry: {ref: e2e://tools/registry, hosts: [registry.scrim.test], tools: [podman, docker, helm]}
    npm: {ref: e2e://tools/npm, tools: [npm]}
    terraform: {ref: e2e://tools/terraform, tools: [terraform]}
    gcp: {ref: e2e://tools/gcp, tools: [gcloud]}
    azure: {ref: e2e://tools/azure, tools: [az]}
    pypi: {ref: e2e://tools/pypi, hosts: [pypi.scrim.test], tools: [pip]}
    pypi-upload: {ref: e2e://tools/pypi-upload, tools: [twine]}
    crates: {ref: e2e://tools/crates, tools: [cargo]}
    hcloud: {ref: e2e://tools/hcloud, tools: [hcloud]}
    digitalocean: {ref: e2e://tools/digitalocean, tools: [doctl]}
    aws-id: {ref: e2e://tools/aws-id, tools: [aws]}
    aws-secret: {ref: e2e://tools/aws-secret, tools: [aws.secret-access-key]}
`

type env struct {
	d       *harness.Daemon
	fake    *fakeAPIs
	seeds   map[string]leak.Seed
	checker *leak.Checker
	repo    string
}

func setup(t *testing.T) *env {
	bin := harness.Require(t)
	e := &env{seeds: map[string]leak.Seed{}}
	vals := map[string]string{}
	var all []leak.Seed
	for name, k := range secretKinds {
		s := leak.Generate(k)
		e.seeds[name], vals[name] = s, s.Value()
		all = append(all, s)
	}
	e.checker = leak.NewChecker(all)
	pki := harness.NewPKI(t)

	e.d = harness.Start(t, bin, harness.Options{
		Secrets:    vals,
		Upstream:   "http://" + harness.FreePort(t), // no model traffic in this test
		Catalog:    catalogYAML,
		UpstreamCA: pki.CAPEM,
	})

	// A bare repository served as https://github.com/acme/repo.git.
	git := harness.LookPath(t, "git")
	out, err := exec.Command(git, "--exec-path").Output()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(e.d.Dir, "git")
	e.repo = filepath.Join(root, "acme", "repo.git")
	seed := filepath.Join(e.d.Dir, "seed-repo")
	run := func(dir string, args ...string) {
		cmd := exec.Command(git, args...)
		cmd.Dir, cmd.Env = dir, e.d.Env()
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("", "init", "-q", "--bare", "-b", "main", e.repo)
	run("", "init", "-q", "-b", "main", seed)
	if err := os.WriteFile(filepath.Join(seed, "README"), []byte("scrim e2e\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run(seed, "add", "README")
	run(seed, "-c", "user.name=e2e", "-c", "user.email=e2e@scrim.test", "commit", "-q", "-m", "initial")
	run(seed, "push", "-q", e.repo, "main")

	e.fake = newFake(vals, gitBackend(filepath.Join(strings.TrimSpace(string(out)), "git-http-backend"), root))
	harness.ServeTLSNames(t, pki, harness.ProfileAddr, harness.ProfileHosts, e.fake)
	return e
}

func (e *env) noSeeds(t *testing.T, what, s string) {
	t.Helper()
	if f := e.checker.Check(leak.Capture{Body: []byte(s)}); len(f) > 0 {
		raw, _ := json.Marshal(f)
		t.Errorf("%s holds a real value: %s", what, raw)
	}
}

// sh runs a script under scrim run in a fresh working directory.
func (e *env) sh(t *testing.T, work, script string, extra ...string) harness.Result {
	t.Helper()
	if work == "" {
		work = t.TempDir()
	}
	r := e.d.Run(t, work, extra, "sh", "-c", script)
	e.noSeeds(t, "tool output", r.Output())
	return r
}

func (e *env) authenticated(t *testing.T, host string) {
	t.Helper()
	if e.fake.count(host) == 0 {
		t.Errorf("%s received no request with the real credential (last Authorization scheme %q)", host, scheme(e.fake.lastAuth(host)))
	}
}

// scheme is the authorization scheme only, never the credential.
func scheme(a string) string {
	s, _, _ := strings.Cut(a, " ")
	return s
}

func must(t *testing.T, r harness.Result, what string) {
	t.Helper()
	if r.Code != 0 {
		t.Fatalf("%s: exit %d\n%s", what, r.Code, r.Output())
	}
}

func contains(t *testing.T, r harness.Result, want string) {
	t.Helper()
	if !strings.Contains(r.Output(), want) {
		t.Errorf("output lacks %q:\n%s", want, r.Output())
	}
}

func TestProfiles(t *testing.T) {
	e := setup(t)
	path := func(names ...string) string { return harness.PathWith(t, names...) }

	t.Run("session holds placeholders only", func(t *testing.T) {
		// Real values inherited from the caller's environment are removed.
		r := e.sh(t, "", `set -e
env
d=$(dirname "$(dirname "$KUBECONFIG")")
echo "PROFILES_DIR=$d"
find "$d" -type f -print -exec cat {} \;`,
			"GITHUB_TOKEN="+e.seeds["github"].Value(), "AWS_SECRET_ACCESS_KEY="+e.seeds["aws-secret"].Value(),
			"TF_TOKEN_app_terraform_io="+e.seeds["terraform"].Value())
		must(t, r, "session dump")
		for _, want := range []string{"GH_TOKEN=SCRIM_GITHUB\n", "NPM_TOKEN=SCRIM_NPM\n", "HCLOUD_TOKEN=SCRIM_HCLOUD\n",
			"token: SCRIM_K8S", "aws_secret_access_key = SCRIM_AWS_SECRET", `credentials "app.terraform.io"`,
			"https://x-access-token:SCRIM_GITHUB@github.com", "//registry.npmjs.org/:_authToken=SCRIM_NPM"} {
			contains(t, r, want)
		}
		for _, v := range []string{"KUBECONFIG", "AWS_SHARED_CREDENTIALS_FILE", "DOCKER_CONFIG", "GH_CONFIG_DIR",
			"NPM_CONFIG_USERCONFIG", "TF_CLI_CONFIG_FILE", "CLOUDSDK_CONFIG", "AZURE_CONFIG_DIR", "REGISTRY_AUTH_FILE",
			"HELM_REGISTRY_CONFIG", "HCLOUD_CONFIG"} {
			if !regexp.MustCompile(`(?m)^` + v + `=\S*/profiles/`).MatchString(r.Stdout) {
				t.Errorf("%s does not point into the session's profiles directory", v)
			}
		}
		m := regexp.MustCompile(`(?m)^PROFILES_DIR=(\S+)$`).FindStringSubmatch(r.Stdout)
		if m == nil {
			t.Fatal("no profiles directory printed")
		}
		if _, err := os.Stat(m[1]); !os.IsNotExist(err) {
			t.Errorf("the profiles directory %s was not removed when the session ended (%v)", m[1], err)
		}
	})

	t.Run("gh", func(t *testing.T) {
		harness.LookPath(t, "gh")
		r := e.sh(t, "", `gh api user --jq .login && gh auth token`, path("gh"))
		must(t, r, "gh")
		contains(t, r, "scrim-e2e")
		contains(t, r, "SCRIM_GITHUB")
		e.authenticated(t, "api.github.com")
	})

	t.Run("git over https", func(t *testing.T) {
		harness.LookPath(t, "git")
		r := e.sh(t, "", `set -e
git clone -q https://github.com/acme/repo.git work
git -C work log --format=%s -1`)
		must(t, r, "git clone")
		contains(t, r, "initial")
		e.authenticated(t, "github.com")
	})

	t.Run("kubectl", func(t *testing.T) {
		harness.LookPath(t, "kubectl")
		r := e.sh(t, "", `set -e
kubectl get --raw /api/v1/namespaces/default/pods
kubectl config view --raw`, path("kubectl"))
		must(t, r, "kubectl")
		contains(t, r, `"name":"scrim-e2e"`)
		contains(t, r, "token: SCRIM_K8S")
		e.authenticated(t, "k8s.scrim.test")
	})

	t.Run("helm", func(t *testing.T) {
		harness.LookPath(t, "helm")
		r := e.sh(t, "", `helm list -o json`, path("helm"))
		must(t, r, "helm list")
		contains(t, r, "[]")
		e.authenticated(t, "k8s.scrim.test")
	})

	t.Run("podman and docker registry login", func(t *testing.T) {
		// skopeo shares podman's registry client and auth file handling
		// (containers/image); podman itself needs a user namespace with
		// subordinate IDs, which the sandbox's nested namespace lacks.
		harness.LookPath(t, "skopeo")
		before := e.fake.count("registry.scrim.test")
		r := e.sh(t, "", `set -e
skopeo login registry.scrim.test
skopeo login --authfile "$DOCKER_CONFIG/config.json" registry.scrim.test
skopeo login --get-login registry.scrim.test`, path("skopeo"))
		must(t, r, "skopeo login")
		contains(t, r, "scrim")
		if n := e.fake.count("registry.scrim.test") - before; n < 2 {
			t.Errorf("%d authenticated registry logins, want 2 (REGISTRY_AUTH_FILE and DOCKER_CONFIG)", n)
		}
	})

	t.Run("npm", func(t *testing.T) {
		harness.LookPath(t, "node")
		r := e.sh(t, "", `npm whoami`, path("node"))
		must(t, r, "npm whoami")
		contains(t, r, "scrim-e2e")
		e.authenticated(t, "registry.npmjs.org")
	})

	for _, tf := range []string{"terraform", "tofu"} {
		t.Run(tf, func(t *testing.T) {
			harness.LookPath(t, tf)
			work := t.TempDir()
			if err := os.WriteFile(filepath.Join(work, "main.tf"), []byte(`module "m" {
  source  = "app.terraform.io/scrim/e2e/null"
  version = "1.0.0"
}
`), 0o600); err != nil {
				t.Fatal(err)
			}
			before := e.fake.count("app.terraform.io")
			r := e.sh(t, work, tf+` init -input=false -no-color`, path(tf))
			must(t, r, tf+" init")
			if e.fake.count("app.terraform.io") == before {
				t.Error("the registry received no request with the real token")
			}
		})
	}

	t.Run("gcloud", func(t *testing.T) {
		harness.LookPath(t, "gcloud")
		r := e.sh(t, "", `gcloud projects list --format='value(projectId)' && gcloud auth print-access-token`, path("gcloud"))
		must(t, r, "gcloud projects list")
		contains(t, r, "scrim-e2e")
		contains(t, r, "SCRIM_GCP")
		e.authenticated(t, "cloudresourcemanager.googleapis.com")
	})

	t.Run("az", func(t *testing.T) {
		harness.LookPath(t, "az")
		r := e.sh(t, "", `set -e
az login --service-principal -u `+clientID+` -p "$AZURE_CLIENT_SECRET" --tenant `+tenantID+` -o none
az account list --query '[].name' -o tsv`, path("az"))
		must(t, r, "az login")
		contains(t, r, "scrim-e2e")
		e.authenticated(t, "login.microsoftonline.com")
		e.authenticated(t, "management.azure.com")
	})

	t.Run("pip", func(t *testing.T) {
		py := harness.LookPath(t, "python3")
		if exec.Command(py, "-m", "pip", "--version").Run() != nil {
			harness.LookPath(t, "pip") // skips or fails with the reason
		}
		r := e.sh(t, "", `python3 -I -m pip --disable-pip-version-check index versions scrim-e2e`, path("python3"))
		must(t, r, "pip index versions")
		contains(t, r, "1.2.3")
		e.authenticated(t, "pypi.scrim.test")
	})

	t.Run("twine", func(t *testing.T) {
		harness.LookPath(t, "twine")
		work := t.TempDir()
		if err := os.WriteFile(filepath.Join(work, "scrim_e2e-1.2.3-py3-none-any.whl"), wheel(), 0o600); err != nil {
			t.Fatal(err)
		}
		r := e.sh(t, work, `twine upload --disable-progress-bar scrim_e2e-1.2.3-py3-none-any.whl`, path("twine"))
		must(t, r, "twine upload")
		e.authenticated(t, "upload.pypi.org")
	})

	t.Run("cargo", func(t *testing.T) {
		harness.LookPath(t, "cargo")
		r := e.sh(t, "", `cargo yank --version 1.2.3 scrim-e2e`, append([]string{path("cargo")}, cargoEnv(t)...)...)
		must(t, r, "cargo yank")
		e.authenticated(t, "crates.io")
	})

	t.Run("hcloud", func(t *testing.T) {
		harness.LookPath(t, "hcloud")
		r := e.sh(t, "", `hcloud server list -o noheader && hcloud context active`, path("hcloud"))
		must(t, r, "hcloud server list")
		e.authenticated(t, "api.hetzner.cloud")
	})

	t.Run("doctl", func(t *testing.T) {
		harness.LookPath(t, "doctl")
		r := e.sh(t, "", `doctl account get --format Email --no-header`, path("doctl"))
		must(t, r, "doctl account get")
		contains(t, r, "e2e@scrim.test")
		e.authenticated(t, "api.digitalocean.com")
	})

	t.Run("aws prints placeholders", func(t *testing.T) {
		harness.LookPath(t, "aws")
		r := e.sh(t, "", `aws configure get aws_access_key_id && aws configure get aws_secret_access_key`,
			path("aws"), "AWS_ACCESS_KEY_ID="+e.seeds["aws-id"].Value())
		must(t, r, "aws configure get")
		contains(t, r, "SCRIM_AWS_ID")
		contains(t, r, "SCRIM_AWS_SECRET")
	})

	// The session filesystem view (tasks.md 10a.7): with the override
	// variable removed, aws reads ~/.aws/credentials from the home
	// directory and finds the generated placeholder file mounted there; the
	// ssh key and doctl's config are hidden, so cat fails.
	t.Run("filesystem view", func(t *testing.T) {
		harness.LookPath(t, "aws")
		home := t.TempDir()
		decoy := leak.Generate(leak.KindAWSSecret).Value()
		for rel, data := range map[string]string{
			".aws/credentials":          "[default]\naws_access_key_id = AKIADECOY\naws_secret_access_key = " + decoy + "\n",
			".ssh/id_ed25519":           "-----BEGIN OPENSSH PRIVATE KEY-----\n" + decoy + "\n",
			".config/doctl/config.yaml": "access-token: " + decoy + "\n",
		} {
			p := filepath.Join(home, rel)
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		r := e.sh(t, "", `env -u AWS_SHARED_CREDENTIALS_FILE -u AWS_SECRET_ACCESS_KEY aws configure get aws_secret_access_key
cat "$HOME/.ssh/id_ed25519" && echo SSH-KEY-READ
cat "$HOME/.config/doctl/config.yaml" && echo DOCTL-READ
true`, path("aws"), "HOME="+home)
		must(t, r, "filesystem view")
		contains(t, r, "SCRIM_AWS_SECRET")
		for _, bad := range []string{decoy, "SSH-KEY-READ", "DOCTL-READ"} {
			if strings.Contains(r.Output(), bad) {
				t.Errorf("the session read a real file (%s):\n%s", strings.TrimSuffix(bad, decoy), r.Output())
			}
		}
		if b, err := os.ReadFile(filepath.Join(home, ".aws/credentials")); err != nil || !strings.Contains(string(b), decoy) {
			t.Errorf("the real file changed: %v", err)
		}
	})
}

// cargoEnv passes rustup's home through when cargo is a rustup proxy, so
// it finds its toolchain under the test's empty HOME.
func cargoEnv(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, k := range []string{"RUSTUP_HOME", "RUSTUP_TOOLCHAIN"} {
		if v := os.Getenv(k); v != "" {
			out = append(out, k+"="+v)
		}
	}
	if os.Getenv("RUSTUP_HOME") == "" {
		if h, err := os.UserHomeDir(); err == nil {
			if st, err := os.Stat(filepath.Join(h, ".rustup")); err == nil && st.IsDir() {
				out = append(out, "RUSTUP_HOME="+filepath.Join(h, ".rustup"))
			}
		}
	}
	return out
}
