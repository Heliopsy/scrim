// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/gate"
	"github.com/heliopsy/scrim/internal/run"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// fakeTokenReview is a Kubernetes API server that answers TokenReview for
// the service account tokens it issued, for audience scrim only.
type fakeTokenReview struct {
	srv      *httptest.Server
	reviewer string
	mu       sync.Mutex
	tokens   map[string][2]string // token -> namespace, service account
	calls    int
}

func newFakeTokenReview(t *testing.T) *fakeTokenReview {
	t.Helper()
	f := &fakeTokenReview{reviewer: "reviewer-" + seed(t, ""), tokens: map[string][2]string{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls++
		if r.Header.Get("Authorization") != "Bearer "+f.reviewer {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var tr struct {
			Spec struct {
				Token     string   `json:"token"`
				Audiences []string `json:"audiences"`
			} `json:"spec"`
		}
		_ = json.NewDecoder(r.Body).Decode(&tr)
		st := map[string]any{"authenticated": false}
		if sa, ok := f.tokens[tr.Spec.Token]; ok && len(tr.Spec.Audiences) == 1 && tr.Spec.Audiences[0] == "scrim" {
			st = map[string]any{"authenticated": true, "audiences": []string{"scrim"}, "user": map[string]any{
				"username": "system:serviceaccount:" + sa[0] + ":" + sa[1],
				"extra":    map[string][]string{"authentication.kubernetes.io/pod-name": {sa[1] + "-pod"}},
			}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "status": st})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// issue returns a new token for ns/sa.
func (f *fakeTokenReview) issue(ns, sa string) string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	p := base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, `{"aud":["scrim"],"exp":%d}`, time.Now().Add(time.Hour).Unix()))
	tok := h + "." + p + "." + base64.RawURLEncoding.EncodeToString([]byte(hex.EncodeToString(b)))
	f.mu.Lock()
	f.tokens[tok] = [2]string{ns, sa}
	f.mu.Unlock()
	return tok
}

// TestEndToEndKubernetesIdentity runs the daemon with the real data plane
// and Kubernetes identity against a fake TokenReview API, and sends traffic
// the way an agent pod does: tool traffic through
// HTTPS_PROXY=http://k8s:<token>@host:port and provider requests with
// `x-scrim-session: <token>`.
//
//   - Two service accounts get different outcomes from rules on
//     agent.labels.service_account, for injection and provider requests.
//   - A token minted for another audience, or not by the cluster, is an
//     unknown caller and refused injection.
//   - Neither the provider nor the tool API sees the token, the header or the
//     proxy credentials, and the token is in no log or audit entry.
func TestEndToEndKubernetesIdentity(t *testing.T) {
	bin := realDataPlane(t)
	fake := fakeprovider.New(fakeprovider.Options{})
	up := httptest.NewServer(fake)
	defer up.Close()
	pki := newTestPKI(t)
	bound := newToolAPI(t, pki)
	kapi := newFakeTokenReview(t)

	credential := seed(t, "sk-e2e-")
	h := newHarness(t, credential)
	if err := os.WriteFile(filepath.Join(h.dir, "rules.yaml"), []byte(`default: deny
rules:
  - name: no-inject-for-b
    decision: deny
    when: op == "inject" && agent.kind == "k8s" && agent.labels.service_account == "agent-b"
  - name: no-llm-for-b
    decision: deny
    when: op == "llm.forward" && agent.labels.service_account == "agent-b"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(h.dir, "config.yaml")
	cfg, err := os.ReadFile(cfgPath) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(h.dir, "kube-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: kapi.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	tokFile := filepath.Join(h.dir, "scrim-sa-token")
	if err := os.WriteFile(tokFile, []byte(kapi.reviewer), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg = []byte(strings.Replace(string(cfg), "hosts: [api.acme.test]", "hosts: ["+bound.host()+"]", 1) + `identity:
  kubernetes:
    enabled: true
    api-server: ` + kapi.srv.URL + `
    ca-file: ` + caFile + `
    token-file: ` + tokFile + `
`)
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	toolCA := filepath.Join(h.dir, "tool-api-ca.pem")
	if err := os.WriteFile(toolCA, pki.caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	// The tool API's CA reaches the data plane through dataplane.upstream-ca-file.
	h.opts.DataPlaneEnv = nil
	h.opts.Config.Environ = append(h.opts.Config.Environ, "SCRIM_DATAPLANE_PATH="+bin, "SCRIM_PROXY_UPSTREAM_ANTHROPIC="+up.URL,
		"SCRIM_DATAPLANE_UPSTREAM_CA_FILE="+toolCA)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	d, err := Start(ctx, h.opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Shutdown(context.Background()) }()
	eventually(t, "daemon ready", func() bool { return d.Ready(ctx) })

	tokA, tokB := kapi.issue("agents", "agent-a"), kapi.issue("agents", "agent-b")
	// A token the cluster never issued (or issued for another audience:
	// the fake API server refuses both alike, as a real one does).
	forged := kapi.issue("agents", "agent-a")
	kapi.mu.Lock()
	delete(kapi.tokens, forged)
	kapi.mu.Unlock()

	// The built-in rule injects toward bound hosts for any identified
	// agent; agent-b's rule denies it.
	// Provider requests: agent-b is denied by its rule, agent-a and the
	// forged token (unknown) go through redacted.
	if code, body := postMessages(t, ctx, d.Addrs().BaseURL, map[string]string{run.SessionHeader: tokA}, "hello from a"); code != http.StatusOK {
		t.Fatalf("agent-a provider request: %d %s\n%s", code, body, h.logs.String())
	}
	if code, _ := postMessages(t, ctx, d.Addrs().BaseURL, map[string]string{run.SessionHeader: tokB}, "hello from b"); code == http.StatusOK {
		t.Fatal("agent-b provider request allowed")
	}
	// Injection through the forward proxy with the token as the k8s user's
	// password.
	via := func(tok string) *http.Client {
		return proxyClient(t, &url.URL{Scheme: "http", User: url.UserPassword("k8s", tok), Host: d.Addrs().ForwardProxy}, d.TrustBundlePEM())
	}
	if code, body := toolGet(t, ctx, via(tokA), "https://"+bound.host()+"/v1/thing"); code != http.StatusOK {
		t.Fatalf("agent-a injection: %d %s\n%s", code, body, h.logs.String())
	}
	for name, tok := range map[string]string{"agent-b": tokB, "forged": forged} {
		if code, body := toolGet(t, ctx, via(tok), "https://"+bound.host()+"/v1/thing"); code != http.StatusForbidden || !strings.Contains(body, "policy_denied") {
			t.Fatalf("%s injection: %d %s", name, code, body)
		}
	}
	got := bound.requests()
	if len(got) != 1 || got[0].Get("Authorization") != "Bearer "+credential {
		t.Fatalf("the bound host got %d requests", len(got))
	}

	// Nothing downstream, logged or audited holds a token.
	secrets := []string{tokA, tokB, forged, kapi.reviewer}
	leaks := func(where, s string) {
		for _, tok := range secrets {
			if strings.Contains(s, tok[len(tok)-24:]) {
				t.Errorf("a token reached %s", where)
			}
		}
	}
	for _, ex := range fake.Exchanges() {
		for k, vs := range ex.Header {
			if strings.EqualFold(k, run.SessionHeader) || strings.EqualFold(k, "proxy-authorization") {
				t.Errorf("the provider received %s", k)
			}
			leaks("the provider", strings.Join(vs, " "))
		}
		leaks("the provider", string(ex.Body))
	}
	for k, vs := range mergeHeaders(got) {
		if strings.EqualFold(k, "proxy-authorization") || strings.EqualFold(k, run.SessionHeader) {
			t.Errorf("the tool API received %s", k)
		}
		leaks("the tool API", strings.Join(vs, " "))
	}
	leaks("the log", h.logs.String())
	var decisions []string
	_ = d.App().State.View(ctx, func(tx state.Tx) error {
		es, err := tx.QueryAudit(ctx, state.AuditQuery{})
		for _, e := range es {
			b, _ := json.Marshal(e)
			leaks("the audit log", string(b))
			if e.Action == gate.ActionDecision {
				decisions = append(decisions, e.Attrs["action"]+"/"+e.Attrs["caller"]+"/"+e.Agent.ID+"/"+e.Attrs["status"])
			}
		}
		return err
	})
	all := strings.Join(decisions, " ")
	for _, want := range []string{
		"llm.forward/kubernetes/agents/agent-a/allowed", "llm.forward/kubernetes/agents/agent-b/denied",
		"inject/kubernetes/agents/agent-a/allowed", "inject/kubernetes/agents/agent-b/denied", "inject/refused//denied",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("no %q decision: %s", want, all)
		}
	}
}
