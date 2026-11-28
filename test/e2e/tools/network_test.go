// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package tools

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/heliopsy/scrim/internal/leak"
	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
	"github.com/heliopsy/scrim/test/e2e/harness"
)

// proxyOnlyScript is what a session does under run.network proxy-only:
// the well-behaved calls (a tool API through HTTPS_PROXY with the bound
// placeholder, a provider request through the LLM base URL carrying a
// secret) and the ones that try to go around scrim (curl with the proxy
// switched off, by hostname and by the provider's own address, and curl
// with the environment cleared). Each prints its exit status.
const proxyOnlyScript = `
curl -sS --max-time 10 -H "Authorization: Bearer SCRIM_API_TOKEN" https://` + harness.APIHost + `/v1/whoami; echo " proxied=$?"
curl -sS --max-time 10 -o /dev/null -w 'provider=%{http_code}' -H 'Content-Type: application/json' \
  -H 'X-Api-Key: fake-provider-key-not-a-seed' -H 'Anthropic-Version: 2023-06-01' \
  --data "{\"model\":\"claude-test\",\"max_tokens\":16,\"messages\":[{\"role\":\"user\",\"content\":\"deploy with $TEST_SECRET\"}]}" \
  "$ANTHROPIC_BASE_URL/v1/messages"; echo " provider-exit=$?"
curl -sS --max-time 5 -o /dev/null --noproxy '*' -k https://` + harness.APIHost + `/v1/whoami; echo "direct-host=$?"
curl -sS --max-time 5 -o /dev/null --noproxy '*' "http://$TEST_PROVIDER_ADDR/v1/messages"; echo "direct-ip=$?"
env -i "$TEST_CURL" -sS --max-time 5 -o /dev/null -k https://` + harness.APIHost + `/v1/whoami; echo "env-cleared=$?"
`

// TestProxyOnlyNetwork is the run.network proxy-only check with real curl
// and a real scrim proxy: through HTTPS_PROXY the tool API gets the real
// token and the agent sees the placeholder back, the fake provider gets
// the secret as a placeholder, and curl with the proxy switched off (by
// hostname or by the provider's IP) or with its environment cleared fails.
// The same script with run.network open reaches the hosts directly, so the
// failures come from the namespace.
func TestProxyOnlyNetwork(t *testing.T) {
	bin := harness.Require(t)
	curl := harness.LookPath(t, "curl")
	token := leak.Generate(leak.KindAPIKey)
	api := &echoAPI{token: token.Value()}
	pki := harness.NewPKI(t)
	harness.ServeTLS(t, pki, harness.APIHost, api)
	fake := fp.New(fp.Options{})
	provider := httptest.NewServer(fake)
	t.Cleanup(provider.Close)

	d := harness.Start(t, bin, harness.Options{
		Secrets:  map[string]string{"api-token": token.Value()},
		Upstream: provider.URL,
		Catalog: `    api-token:
      ref: e2e://tools/api-token
      hosts: [` + harness.APIHost + `]
      placeholder: SCRIM_API_TOKEN
`,
		UpstreamCA: pki.CAPEM,
	})
	checker := leak.NewChecker([]leak.Seed{token})
	env := []string{"TEST_SECRET=" + token.Value(), "TEST_CURL=" + curl,
		"TEST_PROVIDER_ADDR=" + strings.TrimPrefix(provider.URL, "http://")}

	for _, tc := range []struct {
		mode   string
		direct string // exit status of the direct attempts
	}{{"proxy-only", "fail"}, {"open", "0"}} {
		t.Run(tc.mode, func(t *testing.T) {
			api.reset()
			before := len(fake.Exchanges())
			r := d.Scrim(t, t.TempDir(), env, "run", "--run-network", tc.mode, "--", "sh", "-c", proxyOnlyScript)
			out := r.Output()
			t.Logf("session output:\n%s", out)
			if r.Code != 0 {
				t.Fatalf("scrim run exit %d", r.Code)
			}
			if !strings.Contains(r.Stdout, `"authorization":"Bearer SCRIM_API_TOKEN"`) || !strings.Contains(r.Stdout, "proxied=0") {
				t.Errorf("the tool call through HTTPS_PROXY failed or came back unredacted")
			}
			if got := api.requests(); len(got) == 0 || got[0].Auth != "Bearer "+token.Value() {
				t.Errorf("the tool API did not receive the real token (%d requests)", len(got))
			}
			if !strings.Contains(r.Stdout, "provider=200") {
				t.Errorf("the provider request through the LLM base URL failed")
			}
			ex := fake.Exchanges()[before:]
			if len(ex) == 0 {
				t.Fatal("the provider received nothing")
			}
			for _, e := range ex {
				if f := checker.Check(e.Capture); len(f) > 0 {
					raw, _ := json.Marshal(f)
					t.Errorf("leak in the provider request: %s", raw)
				}
			}
			if f := checker.Check(leak.Capture{Body: []byte(out)}); len(f) > 0 {
				t.Errorf("the session output holds the secret")
			}
			for _, k := range []string{"direct-host", "direct-ip", "env-cleared"} {
				status := lineValue(r.Stdout, k)
				switch {
				case tc.direct == "0" && k != "env-cleared" && status != "0":
					t.Errorf("%s exit %s with run.network open: the check proves nothing", k, status)
				case tc.direct == "fail" && (status == "" || status == "0"):
					t.Errorf("%s exit %q under proxy-only, want a failure", k, status)
				}
			}
		})
	}
}

// lineValue returns the value of the first key=value token in out.
func lineValue(out, key string) string {
	for _, f := range strings.Fields(out) {
		if v, ok := strings.CutPrefix(f, key+"="); ok {
			return v
		}
	}
	return ""
}
