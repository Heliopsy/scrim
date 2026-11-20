// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

// Package tools runs real tool clients (curl, git, Node.js fetch, Python
// requests) under `scrim run` against a real `scrim proxy` and TLS test
// servers on bound hosts (tasks.md 10.2). Run it with `just e2e-tools`.
package tools

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cgi"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/test/e2e/harness"
)

const gitUser = "e2e"

// echoAPI requires `Authorization: Bearer <token>` and echoes the
// authorization header, path and body back, the way APIs echo a submitted
// field. It records what arrived.
type echoAPI struct {
	token string
	mu    sync.Mutex
	got   []received
}

type received struct {
	Auth string
	Body string
}

func (a *echoAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	a.mu.Lock()
	a.got = append(a.got, received{Auth: r.Header.Get("Authorization"), Body: string(body)})
	a.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if a.token != "" && r.Header.Get("Authorization") != "Bearer "+a.token {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"bad token"}`)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"authorization": r.Header.Get("Authorization"), "path": r.URL.Path, "body": string(body)})
}

func (a *echoAPI) requests() []received {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]received(nil), a.got...)
}

func (a *echoAPI) reset() {
	a.mu.Lock()
	a.got = nil
	a.mu.Unlock()
}

// gitServer is git http-backend behind Basic authentication.
type gitServer struct {
	password string
	backend  http.Handler
	mu       sync.Mutex
	auths    []string
}

func (g *gitServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	g.auths = append(g.auths, r.Header.Get("Authorization"))
	g.mu.Unlock()
	u, p, ok := r.BasicAuth()
	if !ok || u != gitUser || p != g.password {
		w.Header().Set("WWW-Authenticate", `Basic realm="scrim e2e"`)
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	g.backend.ServeHTTP(w, r)
}

func (g *gitServer) authorizations() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.auths...)
}

type env struct {
	d       *harness.Daemon
	api     *echoAPI
	other   *echoAPI
	git     *gitServer
	repo    string
	token   leak.Seed
	gitPass leak.Seed
	checker *leak.Checker
}

func setup(t *testing.T) *env {
	bin := harness.Require(t)
	e := &env{token: leak.Generate(leak.KindAPIKey), gitPass: leak.Generate(leak.KindGitHubToken)}
	e.checker = leak.NewChecker([]leak.Seed{e.token, e.gitPass})
	pki := harness.NewPKI(t)
	e.api = &echoAPI{token: e.token.Value()}
	e.other = &echoAPI{}
	harness.ServeTLS(t, pki, harness.APIHost, e.api)
	harness.ServeTLS(t, pki, harness.OtherHost, e.other)

	e.d = harness.Start(t, bin, harness.Options{
		Secrets:  map[string]string{"api-token": e.token.Value(), "git-password": e.gitPass.Value()},
		Upstream: "http://" + harness.FreePort(t), // no model traffic in this test
		Catalog: `    api-token:
      ref: e2e://tools/api-token
      hosts: [` + harness.APIHost + `]
      placeholder: SCRIM_API_TOKEN
      inject: [header, body]
    git-password:
      ref: e2e://tools/git-password
      hosts: [` + harness.GitHost + `]
      placeholder: SCRIM_GIT_PASSWORD
      inject: ["header:Authorization"]
`,
		UpstreamCA: pki.CAPEM,
	})

	// Placeholder credentials in git's own credential store, as a user
	// would keep them.
	if err := os.WriteFile(filepath.Join(e.d.Home, ".gitconfig"), []byte(`[user]
	name = scrim e2e
	email = e2e@scrim.test
[credential]
	helper = store
[init]
	defaultBranch = main
`), 0o600); err != nil {
		t.Fatal(err)
	}
	creds := fmt.Sprintf("https://%s:SCRIM_GIT_PASSWORD@%s\n", gitUser, harness.GitHost)
	if err := os.WriteFile(filepath.Join(e.d.Home, ".git-credentials"), []byte(creds), 0o600); err != nil {
		t.Fatal(err)
	}
	// A bare repository with one commit, served by git http-backend.
	gitExec := harness.LookPath(t, "git")
	out, err := exec.Command(gitExec, "--exec-path").Output()
	if err != nil {
		t.Fatal(err)
	}
	backend := filepath.Join(strings.TrimSpace(string(out)), "git-http-backend")
	root := filepath.Join(e.d.Dir, "git")
	e.repo = filepath.Join(root, "repo.git")
	seedRepo := filepath.Join(e.d.Dir, "seed-repo")
	e.gitCmd(t, "", "init", "-q", "--bare", "-b", "main", e.repo)
	e.gitCmd(t, "", "-C", e.repo, "config", "http.receivepack", "true")
	e.gitCmd(t, "", "init", "-q", "-b", "main", seedRepo)
	if err := os.WriteFile(filepath.Join(seedRepo, "README"), []byte("scrim e2e\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.gitCmd(t, seedRepo, "add", "README")
	e.gitCmd(t, seedRepo, "commit", "-q", "-m", "initial")
	e.gitCmd(t, seedRepo, "push", "-q", e.repo, "main")
	e.git = &gitServer{password: e.gitPass.Value(), backend: &cgi.Handler{
		Path: backend, Root: "/",
		Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1", "GIT_CONFIG_NOSYSTEM=1"},
	}}
	harness.ServeTLS(t, pki, harness.GitHost, e.git)

	return e
}

func (e *env) gitCmd(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = e.d.Env()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// noSeeds fails when a seeded value appears in what the client saw.
func (e *env) noSeeds(t *testing.T, what, s string) {
	t.Helper()
	if f := e.checker.Check(leak.Capture{Body: []byte(s)}); len(f) > 0 {
		raw, _ := json.Marshal(f)
		t.Errorf("%s holds a seeded value: %s", what, raw)
	}
}

// sh runs a shell script under scrim run.
func (e *env) sh(t *testing.T, script string, extra ...string) harness.Result {
	t.Helper()
	work := t.TempDir()
	r := e.d.Run(t, work, extra, "sh", "-c", script)
	e.noSeeds(t, "client output", r.Output())
	return r
}

func TestTools(t *testing.T) {
	e := setup(t)

	t.Run("curl header", func(t *testing.T) {
		harness.LookPath(t, "curl")
		e.api.reset()
		r := e.sh(t, `curl -sS --fail-with-body -H "Authorization: Bearer $SCRIM_API_TOKEN" https://`+harness.APIHost+`/v1/whoami`)
		if r.Code != 0 {
			t.Fatalf("curl exit %d: %s", r.Code, r.Output())
		}
		got := e.api.requests()
		if len(got) != 1 || got[0].Auth != "Bearer "+e.token.Value() {
			t.Fatalf("the API did not receive the real token (%d requests)", len(got))
		}
		if !strings.Contains(r.Stdout, `"authorization":"Bearer SCRIM_API_TOKEN"`) {
			t.Errorf("the echoed token did not come back as the placeholder: %s", r.Stdout)
		}
	})

	t.Run("curl json body", func(t *testing.T) {
		harness.LookPath(t, "curl")
		e.api.reset()
		r := e.sh(t, `curl -sS --fail-with-body -H "Authorization: Bearer $SCRIM_API_TOKEN" -H 'Content-Type: application/json' `+
			`--data '{"name":"deploy","token":"SCRIM_API_TOKEN"}' https://`+harness.APIHost+`/v1/hooks`)
		if r.Code != 0 {
			t.Fatalf("curl exit %d: %s", r.Code, r.Output())
		}
		got := e.api.requests()
		if len(got) != 1 {
			t.Fatalf("%d requests reached the API, want 1", len(got))
		}
		var body map[string]string
		if err := json.Unmarshal([]byte(got[0].Body), &body); err != nil || body["token"] != e.token.Value() {
			t.Errorf("the JSON body did not carry the real token (%v)", err)
		}
		var echoed map[string]string
		if err := json.Unmarshal([]byte(r.Stdout), &echoed); err != nil || !strings.Contains(echoed["body"], `"token":"SCRIM_API_TOKEN"`) {
			t.Errorf("the echoed body did not come back with the placeholder: %s", r.Stdout)
		}
	})

	t.Run("unbound host", func(t *testing.T) {
		harness.LookPath(t, "curl")
		e.other.reset()
		r := e.sh(t, `curl -sS -D - -H "Authorization: Bearer $SCRIM_API_TOKEN" https://`+harness.OtherHost+`/collect`)
		if !strings.Contains(r.Stdout, " 403") || !strings.Contains(strings.ToLower(r.Stdout), "x-scrim-error: unbound_destination") {
			t.Errorf("want 403 unbound_destination, got: %s", r.Output())
		}
		if n := len(e.other.requests()); n != 0 {
			t.Errorf("%d requests reached the unbound host", n)
		}
		// Without a placeholder the unbound host is reachable: the refusal is
		// about the credential, not the host.
		r = e.sh(t, `curl -sS --fail-with-body https://`+harness.OtherHost+`/public`)
		if r.Code != 0 || len(e.other.requests()) != 1 {
			t.Errorf("plain request to the unbound host failed (exit %d): %s", r.Code, r.Output())
		}
	})

	t.Run("git clone and push", func(t *testing.T) {
		harness.LookPath(t, "git")
		r := e.sh(t, `set -e
git clone -q https://`+harness.GitHost+`/repo.git work
cd work
echo change > CHANGE
git add CHANGE
git commit -q -m "change through scrim"
git push -q origin main
git log --oneline -1`)
		if r.Code != 0 {
			t.Fatalf("git exit %d: %s", r.Code, r.Output())
		}
		head, err := exec.Command("git", "-C", e.repo, "log", "--format=%s", "-1", "main").Output()
		if err != nil || strings.TrimSpace(string(head)) != "change through scrim" {
			t.Fatalf("the push did not reach the server (%v): %q", err, head)
		}
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(gitUser+":"+e.gitPass.Value()))
		var ok int
		for _, a := range e.git.authorizations() {
			if a == want {
				ok++
			}
			if strings.Contains(a, base64.StdEncoding.EncodeToString([]byte(gitUser+":SCRIM_GIT_PASSWORD"))) {
				t.Error("the git server received the placeholder")
			}
		}
		if ok < 2 {
			t.Errorf("%d authenticated requests with the real password, want at least 2 (fetch and push)", ok)
		}
		creds, _ := os.ReadFile(filepath.Join(e.d.Home, ".git-credentials"))
		e.noSeeds(t, "~/.git-credentials", string(creds))
	})

	t.Run("node fetch", func(t *testing.T) {
		harness.LookPath(t, "node")
		e.api.reset()
		script := filepath.Join(t.TempDir(), "client.mjs")
		if err := os.WriteFile(script, []byte(`const r = await fetch("https://`+harness.APIHost+`/v1/items", {
  method: "POST",
  headers: {authorization: "Bearer " + process.env.SCRIM_API_TOKEN, "content-type": "application/json"},
  body: JSON.stringify({token: process.env.SCRIM_API_TOKEN}),
});
console.log(r.status, await r.text());
`), 0o600); err != nil {
			t.Fatal(err)
		}
		r := e.sh(t, `NODE_USE_ENV_PROXY=1 node `+script, harness.PathWith(t, "node"))
		if r.Code != 0 || !strings.HasPrefix(r.Stdout, "200 ") {
			t.Fatalf("node exit %d: %s", r.Code, r.Output())
		}
		got := e.api.requests()
		if len(got) != 1 || got[0].Auth != "Bearer "+e.token.Value() || !strings.Contains(got[0].Body, e.token.Value()) {
			t.Fatalf("the API did not receive the real token in header and body (%d requests)", len(got))
		}
		if !strings.Contains(r.Stdout, "Bearer SCRIM_API_TOKEN") {
			t.Errorf("the echoed token did not come back as the placeholder: %s", r.Stdout)
		}
	})

	t.Run("python requests", func(t *testing.T) {
		py := harness.LookPath(t, "python3")
		if exec.Command(py, "-c", "import requests").Run() != nil {
			if os.Getenv("SCRIM_E2E_REQUIRE_TOOLS") == "1" {
				t.Fatal("python3 has no requests module and SCRIM_E2E_REQUIRE_TOOLS is set")
			}
			t.Skip("python3 has no requests module")
		}
		e.api.reset()
		script := filepath.Join(t.TempDir(), "client.py")
		if err := os.WriteFile(script, []byte(`import os, requests
tok = os.environ["SCRIM_API_TOKEN"]
r = requests.post("https://`+harness.APIHost+`/v1/items", headers={"Authorization": "Bearer " + tok}, json={"token": tok}, timeout=30)
print(r.status_code, r.text)
`), 0o600); err != nil {
			t.Fatal(err)
		}
		r := e.sh(t, `python3 -I `+script)
		if r.Code != 0 || !strings.HasPrefix(r.Stdout, "200 ") {
			t.Fatalf("python exit %d: %s", r.Code, r.Output())
		}
		got := e.api.requests()
		if len(got) != 1 || got[0].Auth != "Bearer "+e.token.Value() || !strings.Contains(got[0].Body, e.token.Value()) {
			t.Fatalf("the API did not receive the real token in header and body (%d requests)", len(got))
		}
		if !strings.Contains(r.Stdout, "Bearer SCRIM_API_TOKEN") {
			t.Errorf("the echoed token did not come back as the placeholder: %s", r.Stdout)
		}
	})

	t.Run("CA rotation", func(t *testing.T) { testRotation(t, e) })
}

// testRotation rotates the CA with `scrim ca rotate` while the daemon runs:
// a client that trusts only the previous CA keeps working through the
// overlap (the leaf comes with a cross certificate), and so do a client
// that trusts only the new CA and a new scrim run session.
func testRotation(t *testing.T, e *env) {
	harness.LookPath(t, "curl")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	before, err := e.d.AdminGet(ctx, "/v1/ca")
	if err != nil {
		t.Fatal(err)
	}
	oldCerts := certs(t, before)
	if len(oldCerts) != 1 {
		t.Fatalf("%d CA certificates before the rotation, want 1", len(oldCerts))
	}
	oldFile := filepath.Join(t.TempDir(), "old-ca.pem")
	if err := os.WriteFile(oldFile, before, 0o600); err != nil {
		t.Fatal(err)
	}
	if r := e.d.Scrim(t, e.d.Dir, nil, "ca", "rotate"); r.Code != 0 {
		t.Fatalf("scrim ca rotate: %s", r.Output())
	}
	var after []byte
	for {
		after, err = e.d.AdminGet(ctx, "/v1/ca")
		if err == nil && len(certs(t, after)) == 2 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("the daemon did not pick up the rotation: %v", err)
		case <-time.After(200 * time.Millisecond):
		}
	}
	newCA := certs(t, after)[0]
	if newCA.Equal(oldCerts[0]) {
		t.Fatal("the current CA did not change")
	}
	newFile := filepath.Join(t.TempDir(), "new-ca.pem")
	if err := os.WriteFile(newFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newCA.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	// The data plane signs leaves with the new CA once it holds the new
	// snapshot; the served chain shows when.
	for {
		chain := servedChain(t, e.d, harness.APIHost)
		if len(chain) >= 2 && chain[0].CheckSignatureFrom(newCA) == nil {
			if chain[1].CheckSignatureFrom(oldCerts[0]) != nil {
				t.Fatal("the leaf is not served with a cross certificate signed by the previous CA")
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("the data plane still signs leaves with the previous CA")
		case <-time.After(200 * time.Millisecond):
		}
	}

	for name, bundle := range map[string]string{"previous CA only": oldFile, "new CA only": newFile} {
		e.api.reset()
		r := e.sh(t, `curl -sS --fail-with-body --cacert `+bundle+` -H "Authorization: Bearer $SCRIM_API_TOKEN" https://`+harness.APIHost+`/v1/whoami`)
		if r.Code != 0 || len(e.api.requests()) != 1 {
			t.Errorf("%s: curl exit %d: %s", name, r.Code, r.Output())
		}
	}
	// A new session gets both CAs in its bundle; curl, git, node and
	// python use it through the variables scrim run sets.
	e.api.reset()
	harness.LookPath(t, "node")
	harness.LookPath(t, "python3")
	r := e.sh(t, `curl -sS --fail-with-body -H "Authorization: Bearer $SCRIM_API_TOKEN" https://`+harness.APIHost+`/v1/whoami && `+
		`python3 -I -c 'import os,requests; print(requests.get("https://`+harness.APIHost+`/v1/whoami", headers={"Authorization": "Bearer " + os.environ["SCRIM_API_TOKEN"]}).status_code)' && `+
		`NODE_USE_ENV_PROXY=1 node -e 'fetch("https://`+harness.APIHost+`/v1/whoami", {headers: {authorization: "Bearer " + process.env.SCRIM_API_TOKEN}}).then(r => console.log(r.status))'`,
		harness.PathWith(t, "node", "python3"))
	if r.Code != 0 || len(e.api.requests()) != 3 {
		t.Errorf("new session after the rotation: exit %d, %d requests: %s", r.Code, len(e.api.requests()), r.Output())
	}
}

func certs(t *testing.T, b []byte) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return out
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
}

// servedChain opens a CONNECT tunnel through the forward proxy and returns
// the certificates scrim presents for host. No request is sent.
func servedChain(t *testing.T, d *harness.Daemon, host string) []*x509.Certificate {
	t.Helper()
	info, err := d.Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.DialTimeout("tcp", strings.TrimPrefix(info.Addrs.ForwardProxy, "http://"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = fmt.Fprintf(c, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", host, host)
	buf := make([]byte, 0, 512)
	one := make([]byte, 1)
	for !strings.HasSuffix(string(buf), "\r\n\r\n") {
		if _, err := c.Read(one); err != nil {
			t.Fatalf("CONNECT: %v (%q)", err, buf)
		}
		buf = append(buf, one[0])
	}
	if !strings.Contains(string(buf), " 200") {
		t.Fatalf("CONNECT refused: %q", buf)
	}
	tc := tls.Client(c, &tls.Config{ServerName: host, InsecureSkipVerify: true}) //nolint:gosec // inspecting the chain, not trusting it
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	return tc.ConnectionState().PeerCertificates
}
