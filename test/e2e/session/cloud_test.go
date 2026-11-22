// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package session

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/leak"
	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
	"github.com/heliopsy/scrim/test/e2e/harness"
)

// cloudCase is Claude Code in one cloud provider mode against a faithful
// fake of that provider (fakeprovider.Cloud), which refuses any request not
// authenticated with the credentials scrim holds.
type cloudCase struct {
	name  string
	kind  fp.CloudKind
	sigv4 bool
	token bool
	// oauth: the route mints tokens (Google service account for vertex,
	// Entra ID client credentials for foundry) from a fake token service.
	oauth bool
	model string
	env   []string
}

var cloudCases = []cloudCase{
	{kind: fp.Bedrock, sigv4: true, token: true, model: "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
		env: []string{"CLAUDE_CODE_USE_BEDROCK=1", "AWS_REGION=us-east-1"}},
	{kind: fp.AnthropicAWS, sigv4: true, model: "claude-sonnet-4-5",
		env: []string{"CLAUDE_CODE_USE_ANTHROPIC_AWS=1", "AWS_REGION=us-east-1", "ANTHROPIC_AWS_WORKSPACE_ID=wrkspc_01E2eWorkspace"}},
	{kind: fp.BedrockMantle, model: "anthropic.claude-haiku-4-5",
		env: []string{"CLAUDE_CODE_USE_MANTLE=1", "AWS_REGION=us-east-1"}},
	{kind: fp.Foundry, model: "claude-sonnet-4-5",
		env: []string{"CLAUDE_CODE_USE_FOUNDRY=1"}},
	{name: "foundry-entra", kind: fp.Foundry, oauth: true, model: "claude-sonnet-4-5",
		env: []string{"CLAUDE_CODE_USE_FOUNDRY=1"}},
	{kind: fp.Vertex, oauth: true, model: "claude-sonnet-4-5@20250929",
		env: []string{"CLAUDE_CODE_USE_VERTEX=1", "CLOUD_ML_REGION=us-east5", "ANTHROPIC_VERTEX_PROJECT_ID=scrim-e2e"}},
}

// serviceAccount returns a Google service account key file for a key made
// now, and its public key.
func serviceAccount(t *testing.T, email string) (string, *rsa.PublicKey) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]string{"type": "service_account", "project_id": "scrim-e2e", "private_key_id": "e2e-key-1",
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email": email, "token_uri": "https://oauth2.googleapis.com/token"})
	return string(b), &k.PublicKey
}

// TestClaudeCodeCloudProviders runs the Claude Code session of
// TestClaudeCodeSession once per cloud provider mode (tasks.md 11.4):
// scrim run points Claude Code at scrim's provider route with Claude Code's
// own authentication off and dummy credentials in its environment, and the
// fake provider accepts only requests scrim authenticated after redaction
// with the credentials from the store: SigV4 over the exact bytes it
// received, or the API key.
func TestClaudeCodeCloudProviders(t *testing.T) {
	bin := harness.Require(t)
	claudeDir := filepath.Dir(harness.LookPath(t, "claude"))
	for _, c := range cloudCases {
		name := c.name
		if name == "" {
			name = string(c.kind)
		}
		t.Run(name, func(t *testing.T) {
			var cloud *fp.Cloud
			var issuer *fp.TokenIssuer
			var creds []leak.Seed
			s := newSessionWith(t, bin, model, func(secrets map[string]string, fake *fp.Server) string {
				o := fp.CloudOptions{Kind: c.kind, Region: "us-east-1"}
				var auth string
				add := func(name, field string, k leak.Kind) string {
					v := leak.Generate(k)
					creds = append(creds, v)
					secrets[name] = v.Value()
					return fmt.Sprintf("    %s: e2e://tools/%s\n", field, name)
				}
				switch {
				case c.oauth:
					issuer = &fp.TokenIssuer{}
					isrv := httptest.NewServer(issuer)
					t.Cleanup(isrv.Close)
					issuer.URL = isrv.URL
					o.Tokens = issuer
					if c.kind == fp.Vertex {
						sa, pub := serviceAccount(t, "scrim-e2e@scrim-e2e.iam.gserviceaccount.com")
						issuer.ServiceAccount, issuer.PublicKey = "scrim-e2e@scrim-e2e.iam.gserviceaccount.com", pub
						secrets["cloud-sa"] = sa
						creds = append(creds, leak.NewSeed("cloud-sa", leak.KindPrivateKey, sa))
						auth = "    service-account: e2e://tools/cloud-sa\n    token-url: " + isrv.URL + "/token\n"
					} else {
						auth = add("cloud-client-secret", "client-secret", leak.KindAPIKey)
						issuer.ClientID, issuer.ClientSecret = "scrim-e2e-app", secrets["cloud-client-secret"]
						auth += "    tenant-id: scrim-e2e-tenant\n    client-id: scrim-e2e-app\n    token-url: " + isrv.URL + "/scrim-e2e-tenant/oauth2/v2.0/token\n"
					}
				case c.sigv4:
					auth = add("cloud-akid", "access-key-id", leak.KindAWSAccessKey) + add("cloud-secret", "secret-access-key", leak.KindAWSSecret)
					o.AccessKeyID, o.SecretAccessKey = secrets["cloud-akid"], secrets["cloud-secret"]
					if c.token {
						auth += add("cloud-token", "session-token", leak.KindAPIKey)
						o.SessionToken = secrets["cloud-token"]
					}
				default:
					auth = add("cloud-key", "api-key", leak.KindAPIKey)
					o.APIKey = secrets["cloud-key"]
				}
				cloud = fp.NewCloud(fake, o)
				srv := httptest.NewServer(cloud)
				t.Cleanup(srv.Close)
				where := "    region: us-east-1\n"
				switch c.kind {
				case fp.Foundry:
					where = ""
				case fp.Vertex:
					where = "    region: us-east5\n"
				}
				return fmt.Sprintf("providers:\n  cloud:\n    kind: %s\n%s    upstream: %s\n%s", c.kind, where, srv.URL, auth)
			})
			env := append([]string{
				"PATH=" + claudeDir + string(os.PathListSeparator) + os.Getenv("PATH"),
				"DISABLE_AUTOUPDATER=1", "DISABLE_TELEMETRY=1", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
				// What the agent would hold without scrim: never sent.
				"AWS_BEARER_TOKEN_BEDROCK=agent-dummy-bedrock-key", "ANTHROPIC_AWS_API_KEY=agent-dummy-aws-key",
				"ANTHROPIC_FOUNDRY_API_KEY=agent-dummy-foundry-key", "ANTHROPIC_FOUNDRY_RESOURCE=agent-dummy-resource",
			}, c.env...)
			allowed := "Bash(cat:*),Bash(git diff:*),Bash(curl:*),mcp__scrim__secrets_list"
			r := s.d.Run(t, s.work, env, "claude", "-p", "Check the deploy setup and list the secrets scrim offers.",
				"--allowedTools", allowed, "--model", c.model)
			if r.Code != 0 {
				t.Fatalf("claude under scrim run: exit %d\n%s", r.Code, r.Output())
			}
			if !strings.Contains(r.Stdout, "Done.") {
				t.Errorf("the task did not complete: %s", r.Output())
			}

			// Every request the provider received was authenticated by
			// scrim, none carries what the agent held, and none holds a
			// seeded value.
			reqs := cloud.Requests()
			if len(reqs) == 0 {
				t.Fatal("the provider received nothing")
			}
			checker := leak.NewChecker(s.all)
			for _, q := range reqs {
				if q.Auth != "" {
					t.Errorf("request %d %s %s not authenticated: %s", q.Seq, q.Method, q.Path, q.Auth)
				}
				raw, _ := json.Marshal(q.Header)
				if strings.Contains(string(raw), "agent-dummy") || strings.Contains(string(raw), "skip-foundry-auth") {
					t.Errorf("request %d carries the agent's credentials: %s", q.Seq, raw)
				}
				if f := checker.Check(q.Capture); len(f) > 0 {
					b, _ := json.Marshal(f)
					t.Errorf("leak in provider request %d (%s): %s", q.Seq, q.Path, b)
				}
			}
			if issuer != nil {
				if n := len(issuer.Requests()); n != 1 || len(issuer.Refused()) != 0 {
					t.Errorf("token requests: %d, refused %v; want one token minted and cached", n, issuer.Refused())
				}
				for _, q := range issuer.Requests() {
					if f := checker.Check(q); len(f) > 0 {
						t.Errorf("a seeded value reached the token service: %v", f)
					}
				}
			}
			// The provider credentials reach the provider only: scrim's
			// capture of the outgoing requests holds none of them.
			scanCaptures(t, leak.NewChecker(creds), s.d.CaptureDir())

			var main []fp.Exchange
			for _, e := range s.checkLeaks(t) {
				var body map[string]any
				if json.Unmarshal(e.Body, &body) == nil && body["tools"] != nil {
					main = append(main, e)
				}
			}
			if len(main) < len(steps)+2 {
				t.Fatalf("%d tool-enabled requests, want %d", len(main), len(steps)+2)
			}
			results := toolResults(t, main[len(main)-1].Body)
			if len(results) < len(steps)+1 {
				t.Fatalf("%d tool results reached the model, want %d", len(results), len(steps)+1)
			}
			for i, st := range steps {
				if !fp.DefaultPlaceholderPattern.MatchString(results[i]) && !strings.Contains(results[i], "SCRIM_API_TOKEN") {
					t.Errorf("result of %q reached the model without placeholders: %.300s", st.command, results[i])
				}
			}
			if !strings.Contains(results[3], "deploy-bot") {
				t.Errorf("the tool API call failed: %.300s", results[3])
			}
			s.checkAPI(t)
		})
	}
}
