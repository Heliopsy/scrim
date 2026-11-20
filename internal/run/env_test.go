// SPDX-License-Identifier: AGPL-3.0-only

package run

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	// Registers every setting scrim has, so ReservedBy sees them.
	_ "github.com/heliopsy/scrim/internal/app"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/secret"
)

var testCAPEM = []byte("-----BEGIN CERTIFICATE-----\nc2NyaW0tdGVzdA==\n-----END CERTIFICATE-----\n")

func input(cmd ...string) Input {
	return Input{
		Command: cmd,
		Environ: []string{"PATH=/usr/bin", "HOME=/home/u"},
		Endpoints: Endpoints{
			APISocket: "/run/user/1000/scrim/api.sock", LLMBaseURL: "http://127.0.0.1:9790/",
			ForwardProxy: "http://127.0.0.1:9791", CACertPEM: testCAPEM, Bypass: []string{"127.0.0.1:8787"},
		},
		SessionDir: "/run/user/1000/scrim/run/s1", SessionID: "s1", Token: true, MCP: true,
		ScrimPath: "/usr/local/bin/scrim", SystemRoots: []byte("-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----"),
	}
}

func vars(p *Plan) map[string]Var {
	m := map[string]Var{}
	for _, v := range p.Set {
		m[v.Name] = v
	}
	return m
}

func mustBuild(t *testing.T, in Input) *Plan {
	t.Helper()
	p, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBuildCommonEnvironment(t *testing.T) {
	p := mustBuild(t, input("/opt/bin/myagent", "--flag"))
	if p.Preset != "generic" || !slices.Equal(p.Args, []string{"/opt/bin/myagent", "--flag"}) {
		t.Fatalf("preset %s args %v", p.Preset, p.Args)
	}
	v := vars(p)
	want := map[string]string{
		"ANTHROPIC_BASE_URL":        "http://127.0.0.1:9790/anthropic",
		"OPENAI_BASE_URL":           "http://127.0.0.1:9790/openai/v1",
		"HTTPS_PROXY":               "http://s1:<session-token>@127.0.0.1:9791",
		"https_proxy":               "http://s1:<session-token>@127.0.0.1:9791",
		"HTTP_PROXY":                "http://s1:<session-token>@127.0.0.1:9791",
		"http_proxy":                "http://s1:<session-token>@127.0.0.1:9791",
		"NO_PROXY":                  "localhost,127.0.0.1,::1,127.0.0.1:8787",
		"no_proxy":                  "localhost,127.0.0.1,::1,127.0.0.1:8787",
		"NODE_EXTRA_CA_CERTS":       "/run/user/1000/scrim/run/s1/scrim-ca.pem",
		"SSL_CERT_FILE":             "/run/user/1000/scrim/run/s1/ca-bundle.pem",
		"REQUESTS_CA_BUNDLE":        "/run/user/1000/scrim/run/s1/ca-bundle.pem",
		"CURL_CA_BUNDLE":            "/run/user/1000/scrim/run/s1/ca-bundle.pem",
		"GIT_SSL_CAINFO":            "/run/user/1000/scrim/run/s1/ca-bundle.pem",
		"GIT_HTTP_PROXY_AUTHMETHOD": "basic",
		localapi.EnvSocket:          "/run/user/1000/scrim/api.sock",
		EnvSessionID:                "s1",
	}
	for k, w := range want {
		if v[k].Value != w {
			t.Errorf("%s = %q, want %q", k, v[k].Value, w)
		}
	}
	if tok := v[localapi.EnvToken]; !tok.Secret || tok.Value != "" {
		t.Errorf("token var %+v", tok)
	}
	if !v["HTTPS_PROXY"].Secret {
		t.Error("the proxy URL carries the token but is not secret")
	}
	if _, ok := v["ANTHROPIC_CUSTOM_HEADERS"]; ok {
		t.Error("generic preset set a Claude Code variable")
	}
	// Without a session the proxy carries no credentials.
	anon := input("/opt/bin/myagent")
	anon.Token, anon.SessionID = false, ""
	anonVars := vars(mustBuild(t, anon))
	if got := anonVars["HTTPS_PROXY"]; got.Value != "http://127.0.0.1:9791" || got.Secret {
		t.Errorf("anonymous proxy %+v", got)
	}
	if _, ok := anonVars["GIT_HTTP_PROXY_AUTHMETHOD"]; ok {
		t.Error("GIT_HTTP_PROXY_AUTHMETHOD set without proxy credentials")
	}
	if _, ok := v["CODEX_CA_CERTIFICATE"]; ok {
		t.Error("generic preset set a Codex variable")
	}
	if string(p.Files[FileCA]) != string(testCAPEM) {
		t.Error("CA file is not the scrim CA")
	}
	b := string(p.Files[FileBundle])
	if !strings.HasPrefix(b, "-----BEGIN CERTIFICATE-----\nroot") || !strings.HasSuffix(b, string(testCAPEM)) {
		t.Errorf("bundle is not roots plus CA: %q", b)
	}
	if len(p.Warnings) != 0 {
		t.Errorf("warnings on a clean environment: %v", p.Warnings)
	}
}

func TestBuildReplacesInheritedRouting(t *testing.T) {
	in := input("myagent")
	in.Environ = append(in.Environ, "ANTHROPIC_BASE_URL=http://127.0.0.1:8787", "HTTPS_PROXY=http://corp:3128",
		"NO_PROXY=*", "ALL_PROXY=socks5://x:1", "all_proxy=socks5://x:1", localapi.EnvToken+"=old")
	p := mustBuild(t, in)
	if !slices.Equal(p.Unset, []string{"ALL_PROXY", "all_proxy"}) {
		t.Errorf("unset %v", p.Unset)
	}
	if got := vars(p)["NO_PROXY"].Value; strings.Contains(got, "*") {
		t.Errorf("inherited NO_PROXY=* kept: %q", got)
	}
	joined := strings.Join(p.Warnings, "\n")
	for _, w := range []string{"ANTHROPIC_BASE_URL", "HTTPS_PROXY", "NO_PROXY"} {
		if !strings.Contains(joined, w) {
			t.Errorf("no warning for %s: %v", w, p.Warnings)
		}
	}
	env, err := p.Environ(in.Environ, secret.FromString("scrim_st_abc_def"))
	if err != nil {
		t.Fatal(err)
	}
	m := envMap(env)
	if m["ANTHROPIC_BASE_URL"] != "http://127.0.0.1:9790/anthropic" || m["HTTPS_PROXY"] != "http://s1:scrim_st_abc_def@127.0.0.1:9791" {
		t.Errorf("not overridden: %v", m)
	}
	if _, ok := m["ALL_PROXY"]; ok {
		t.Error("ALL_PROXY kept")
	}
	if m[localapi.EnvToken] != "scrim_st_abc_def" || m["PATH"] != "/usr/bin" {
		t.Errorf("token or PATH wrong: %v", m)
	}
	n := 0
	for _, kv := range env {
		if strings.HasPrefix(kv, localapi.EnvToken+"=") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d token entries", n)
	}
}

func TestEnvironNeedsToken(t *testing.T) {
	p := mustBuild(t, input("myagent"))
	if _, err := p.Environ(nil, secret.Value{}); err == nil {
		t.Fatal("environment built without the session token")
	}
}

func TestBuildWithoutForwardProxy(t *testing.T) {
	in := input("myagent")
	in.Endpoints.ForwardProxy, in.Endpoints.CACertPEM = "", nil
	in.Environ = append(in.Environ, "HTTPS_PROXY=http://corp:3128", "no_proxy=.corp.example")
	p := mustBuild(t, in)
	v := vars(p)
	for _, k := range append(slices.Clone(proxyVars), "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS") {
		if _, ok := v[k]; ok {
			t.Errorf("%s set without a forward proxy", k)
		}
	}
	if got := v["NO_PROXY"].Value; got != "localhost,127.0.0.1,::1,127.0.0.1:8787,.corp.example" {
		t.Errorf("NO_PROXY = %q", got)
	}
	if len(p.Files) != 0 {
		t.Errorf("generic preset without a forward proxy wrote files: %v", p.Files)
	}
}

func TestBuildRefusesUnsafeEndpoints(t *testing.T) {
	in := input("myagent")
	in.Endpoints.LLMBaseURL = ""
	if _, err := Build(in); err == nil {
		t.Error("built without an LLM base URL")
	}
	in = input("myagent")
	in.Endpoints.CACertPEM = nil
	if _, err := Build(in); err == nil {
		t.Error("built a forward proxy without a CA")
	}
}

func TestClaudePreset(t *testing.T) {
	p := mustBuild(t, input("/home/u/.local/bin/claude", "-p", "fix it"))
	if p.Preset != "claude" {
		t.Fatalf("preset %s", p.Preset)
	}
	want := []string{"/home/u/.local/bin/claude", "--mcp-config=/run/user/1000/scrim/run/s1/mcp.json", "-p", "fix it"}
	if !slices.Equal(p.Args, want) {
		t.Errorf("args %q, want %q", p.Args, want)
	}
	var cfg struct {
		MCPServers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(p.Files[FileMCP], &cfg); err != nil {
		t.Fatal(err)
	}
	if s := cfg.MCPServers["scrim"]; s.Command != "/usr/local/bin/scrim" || !slices.Equal(s.Args, []string{"mcp"}) {
		t.Errorf("mcp config %s", p.Files[FileMCP])
	}
	// The session header goes on every API request; inherited headers stay,
	// an inherited session header does not, and print-env never shows them.
	hin := input("claude")
	hin.Environ = append(hin.Environ, "ANTHROPIC_CUSTOM_HEADERS=X-Team: infra\nx-scrim-session: forged")
	hp := mustBuild(t, hin)
	if h := vars(hp)["ANTHROPIC_CUSTOM_HEADERS"]; !h.Secret || h.Value != "<inherited headers>\nx-scrim-session: <session-token>" {
		t.Errorf("custom headers var %+v", h)
	}
	henv, err := hp.Environ(hin.Environ, secret.FromString("scrim_st_abc_def"))
	if err != nil {
		t.Fatal(err)
	}
	if got := envMap(henv)["ANTHROPIC_CUSTOM_HEADERS"]; got != "X-Team: infra\nx-scrim-session: scrim_st_abc_def" {
		t.Errorf("ANTHROPIC_CUSTOM_HEADERS = %q", got)
	}

	in := input("claude")
	in.MCP = false
	if p := mustBuild(t, in); len(p.Args) != 1 || p.Files[FileMCP] != nil {
		t.Errorf("MCP registered with run.mcp off: %v", p.Args)
	}
	for _, v := range []string{"CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY"} {
		in := input("claude")
		in.Environ = append(in.Environ, v+"=1")
		if _, err := Build(in); err == nil || !strings.Contains(err.Error(), v) {
			t.Errorf("%s: %v", v, err)
		}
		in.Environ[len(in.Environ)-1] = v + "=0"
		if _, err := Build(in); err != nil {
			t.Errorf("%s=0 refused: %v", v, err)
		}
	}
}

func TestCodexPreset(t *testing.T) {
	p := mustBuild(t, input("codex", "exec", "fix it"))
	want := []string{"codex",
		"-c", `openai_base_url="http://127.0.0.1:9790/openai/v1"`,
		"-c", `mcp_servers.scrim.command="/usr/local/bin/scrim"`,
		"-c", `mcp_servers.scrim.args=["mcp"]`,
		"-c", `mcp_servers.scrim.env_vars=["SCRIM_API_SOCKET","SCRIM_SESSION_TOKEN","SCRIM_SESSION_ID"]`,
		"exec", "fix it"}
	if !slices.Equal(p.Args, want) {
		t.Errorf("args\n %q\nwant\n %q", p.Args, want)
	}
	if v := vars(p); v["CODEX_CA_CERTIFICATE"].Value != v["SSL_CERT_FILE"].Value || v["CODEX_CA_CERTIFICATE"].Value == "" {
		t.Errorf("CODEX_CA_CERTIFICATE %q", v["CODEX_CA_CERTIFICATE"].Value)
	}
	for _, a := range p.Args {
		if strings.Contains(a, "scrim_st_") {
			t.Error("token on the command line")
		}
	}
	in := input("codex")
	in.MCP = false
	in.Token, in.SessionID = false, ""
	in.Endpoints.ForwardProxy, in.Endpoints.CACertPEM = "", nil
	p = mustBuild(t, in)
	if len(p.Args) != 3 || vars(p)["CODEX_CA_CERTIFICATE"].Value != "" {
		t.Errorf("args %q", p.Args)
	}
}

func TestPresetSelection(t *testing.T) {
	for cmd, want := range map[string]string{"claude": "claude", "/x/codex": "codex", "aider": "generic", "claude-wrapper": "generic"} {
		if got := PresetFor(cmd).Name; got != want {
			t.Errorf("%s: %s, want %s", cmd, got, want)
		}
	}
	if p, err := PresetNamed("codex"); err != nil || p != CodexPreset {
		t.Errorf("PresetNamed: %v %v", p, err)
	}
	if _, err := PresetNamed("nope"); err == nil || !strings.Contains(err.Error(), "claude, codex, generic") {
		t.Errorf("PresetNamed(nope): %v", err)
	}
	in := input("my-claude-build")
	in.Preset = ClaudePreset
	if p := mustBuild(t, in); p.Preset != "claude" {
		t.Error("forced preset ignored")
	}
}

func TestPlaceholdersExported(t *testing.T) {
	in := input("myagent")
	in.Placeholders = []string{"SCRIM_ACME_KEY", "SCRIM_GITHUB_TOKEN", "SCRIM_API_SOCKET", "SCRIM_LOG_LEVEL", "SCRIM_STORES_BAO_TOKEN"}
	in.Reserved = ReservedBy(config.Default)
	in.Environ = append(in.Environ, "SCRIM_ACME_KEY=sk-real-looking")
	p := mustBuild(t, in)
	v := vars(p)
	if v["SCRIM_ACME_KEY"].Value != "SCRIM_ACME_KEY" || v["SCRIM_GITHUB_TOKEN"].Value != "SCRIM_GITHUB_TOKEN" {
		t.Errorf("placeholders not exported: %v", v)
	}
	if v[localapi.EnvSocket].Value != in.Endpoints.APISocket {
		t.Error("a placeholder replaced the API socket")
	}
	for _, n := range []string{"SCRIM_LOG_LEVEL", "SCRIM_STORES_BAO_TOKEN"} {
		if _, ok := v[n]; ok {
			t.Errorf("%s exported over a setting", n)
		}
	}
	joined := strings.Join(p.Warnings, "\n")
	for _, n := range []string{"SCRIM_API_SOCKET", "SCRIM_LOG_LEVEL", "SCRIM_STORES_BAO_TOKEN", "SCRIM_ACME_KEY from your environment"} {
		if !strings.Contains(joined, n) {
			t.Errorf("no warning for %s", n)
		}
	}
}

func TestTOMLString(t *testing.T) {
	for in, want := range map[string]string{
		`/usr/bin/scrim`:  `"/usr/bin/scrim"`,
		`/a "b"\c`:        `"/a \"b\"\\c"`,
		"line\nbreak\x7f": `"line\u000Abreak\u007F"`,
	} {
		if got := tomlString(in); got != want {
			t.Errorf("tomlString(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestTrustInputs(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := dir + "/" + name
		if err := writeFile(p, body); err != nil {
			t.Fatal(err)
		}
		return p
	}
	corp := write("corp.pem", "-----BEGIN CERTIFICATE-----\ncorp\n-----END CERTIFICATE-----\n")
	key := write("key.pem", "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----\n")
	roots, extra := trustInputs(map[string]string{"SSL_CERT_FILE": corp, "NODE_EXTRA_CA_CERTS": key})
	if !strings.Contains(string(roots), "corp") {
		t.Error("inherited SSL_CERT_FILE not used as the roots")
	}
	if extra != nil {
		t.Error("a file with a private key was copied")
	}
}

func writeFile(p, body string) error { return os.WriteFile(p, []byte(body), 0o600) }
