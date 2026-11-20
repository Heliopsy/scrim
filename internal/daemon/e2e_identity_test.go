// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/approval"
	"github.com/heliopsy/scrim/internal/gate"
	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/run"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// toolAPI is a fake HTTPS tool API that records what reached it.
type toolAPI struct {
	srv *httptest.Server
	mu  sync.Mutex
	got []http.Header
}

// testPKI is a CA and a leaf for 127.0.0.1 signed by it: the data plane's
// verifier refuses a self-signed CA certificate used as a server
// certificate, which is what httptest serves.
type testPKI struct {
	caPEM []byte
	leaf  tls.Certificate
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "scrim e2e test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return testPKI{caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		leaf: tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}
}

func newToolAPI(t *testing.T, pki testPKI) *toolAPI {
	t.Helper()
	a := &toolAPI{}
	a.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.got = append(a.got, r.Header.Clone())
		a.mu.Unlock()
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	a.srv.TLS = &tls.Config{Certificates: []tls.Certificate{pki.leaf}, MinVersion: tls.VersionTLS12}
	a.srv.StartTLS()
	t.Cleanup(a.srv.Close)
	return a
}

func (a *toolAPI) host() string { return strings.TrimPrefix(a.srv.URL, "https://") }

func (a *toolAPI) requests() []http.Header {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]http.Header(nil), a.got...)
}

// TestEndToEndSessionIdentity runs the daemon with the real data plane and a
// session minted the way `scrim run` mints it, and sends traffic the way an
// agent under `scrim run` does: tool traffic through
// HTTPS_PROXY=http://<session>:<token>@host:port and provider requests to
// the base URL with `x-scrim-session: <token>`.
//
//   - An ask rule on the agent is answered by the control plane with the
//     session's identity (the approval names the session's agent and session).
//   - The session header and the proxy credentials reach neither the fake
//     provider nor the fake tool API, and the token is in no log.
//   - With the default configuration (policy.default deny, no inject rule),
//     the built-in rule injects toward the bound host for the session, and
//     refuses an unbound host and an unidentified caller.
func TestEndToEndSessionIdentity(t *testing.T) {
	bin := realDataPlane(t)
	fake := fakeprovider.New(fakeprovider.Options{})
	up := httptest.NewServer(fake)
	defer up.Close()
	pki := newTestPKI(t)
	bound, unbound := newToolAPI(t, pki), newToolAPI(t, pki)

	credential := seed(t, "sk-e2e-")
	h := newHarness(t, credential)
	// Rules: only the agent ask on provider requests. Injection is left to
	// the built-in rule and policy.default (deny).
	if err := os.WriteFile(filepath.Join(h.dir, "rules.yaml"), []byte(`default: deny
rules:
  - name: ask-e2e-agent
    decision: ask
    when: op == "llm.forward" && agent.known && agent.labels.session_name == "e2e-agent"
    reason: provider request from the e2e agent
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(h.dir, "config.yaml")
	cfg, err := os.ReadFile(cfgPath) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	cfg = []byte(strings.Replace(string(cfg), "hosts: [api.acme.test]", "hosts: ["+bound.host()+"]", 1))
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	// The data plane trusts the fake tool APIs' certificate upstream.
	caFile := filepath.Join(h.dir, "tool-api-ca.pem")
	if err := os.WriteFile(caFile, pki.caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	h.opts.DataPlaneEnv = []string{"SCRIM_DP_EXTRA_CA_FILE=" + caFile}
	h.opts.Config.Environ = append(h.opts.Config.Environ, "SCRIM_DATAPLANE_PATH="+bin,
		"SCRIM_PROXY_UPSTREAM_ANTHROPIC="+up.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	d, err := Start(ctx, h.opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Shutdown(context.Background()) }()
	eventually(t, "daemon ready", func() bool { return d.Ready(ctx) })

	// Mint a session as `scrim run` does, from this process.
	mc := localapi.NewClient(d.Addrs().AgentAPI, secret.Value{})
	m, err := mc.Mint(ctx, localapi.MintInput{Name: "e2e-agent"})
	mc.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Token.Wipe()
	var token string
	_ = m.Token.Expose(func(b []byte) error { token = string(b); return nil })
	sid := m.Session.ID
	eventually(t, "session token in the snapshot", func() bool {
		st, err := d.Supervisor().Status(ctx)
		return err == nil && st.GetValueCount() >= 2
	})

	// The environment scrim run would give the agent.
	plan, err := run.Build(run.Input{
		Command: []string{"claude"}, Environ: []string{"PATH=/usr/bin"}, SessionDir: h.dir, SessionID: sid, Token: true,
		Endpoints: run.Endpoints{LLMBaseURL: d.Addrs().BaseURL, ForwardProxy: "http://" + d.Addrs().ForwardProxy, CACertPEM: []byte(d.TrustBundlePEM())},
	})
	if err != nil {
		t.Fatal(err)
	}
	env, err := plan.Environ(nil, m.Token)
	if err != nil {
		t.Fatal(err)
	}
	agentEnv := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		agentEnv[k] = v
	}
	proxyURL, err := url.Parse(agentEnv["HTTPS_PROXY"])
	if err != nil || proxyURL.User.Username() != sid {
		t.Fatalf("HTTPS_PROXY does not name the session (%v)", err)
	}
	headers := agentEnv["ANTHROPIC_CUSTOM_HEADERS"]
	hname, hvalue, _ := strings.Cut(headers, ": ")
	if hname != run.SessionHeader || hvalue != token {
		t.Fatal("ANTHROPIC_CUSTOM_HEADERS does not carry the session header")
	}

	// 1. A provider request from the session: the ask rule on the agent is
	// answered by the control plane with the session's identity.
	approved := make(chan error, 1)
	go func() {
		apps := d.App().PolicyParts.Approvals
		for ctx.Err() == nil {
			pending, err := apps.List(ctx, state.ApprovalFilter{Status: state.ApprovalPending})
			if err == nil && len(pending) > 0 {
				a := pending[0]
				if a.Rule != "ask-e2e-agent" || a.Request.Agent.Session != sid || a.Request.Agent.ID != m.Session.Agent {
					approved <- &unexpected{a}
					return
				}
				_, err := apps.Decide(ctx, a.ID, approval.Decision{Approve: true, By: "e2e", Via: "api"})
				approved <- err
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	status, reply := postMessages(t, ctx, d.Addrs().BaseURL, map[string]string{hname: hvalue}, "hello from the session")
	if status != http.StatusOK {
		t.Fatalf("session request: %d %s\n%s", status, reply, h.logs.String())
	}
	select {
	case err := <-approved:
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("the session's provider request was not asked about")
	}
	// An anonymous provider request: the default does not stop it, and
	// the ask rule (agent.known) does not apply.
	if status, reply := postMessages(t, ctx, d.Addrs().BaseURL, nil, "hello from nobody"); status != http.StatusOK {
		t.Fatalf("anonymous request: %d %s", status, reply)
	}
	// A bare session id proves nothing: evaluated as unknown, so the ask
	// rule does not apply and the default does not stop it; the refusal is
	// audited.
	if status, reply := postMessages(t, ctx, d.Addrs().BaseURL, map[string]string{run.SessionHeader: sid}, "bare id"); status != http.StatusOK {
		t.Fatalf("bare session id: %d %s", status, reply)
	}
	for _, ex := range fake.Exchanges() {
		for k, vs := range ex.Header {
			if strings.EqualFold(k, run.SessionHeader) || strings.EqualFold(k, "proxy-authorization") {
				t.Errorf("the provider received %s", k)
			}
			for _, v := range vs {
				if strings.Contains(v, token[len(token)-20:]) {
					t.Errorf("the provider received the token in %s", k)
				}
			}
		}
		if strings.Contains(string(ex.Body), token[len(token)-20:]) {
			t.Error("the provider received the token in a body")
		}
	}

	// 2. Injection with the default configuration, through the proxy URL
	// scrim run sets.
	client := proxyClient(t, proxyURL, d.TrustBundlePEM())
	if code, _ := toolGet(t, ctx, client, "https://"+bound.host()+"/v1/thing"); code != http.StatusOK {
		t.Fatalf("injection toward the bound host refused: %d\n%s", code, h.logs.String())
	}
	// An agent that also sends the session header to a tool API (as it
	// does to the LLM proxy) does not leak it there.
	if code, _ := toolGet(t, ctx, client, "https://"+bound.host()+"/v1/thing", run.SessionHeader, token); code != http.StatusOK {
		t.Fatalf("second injection refused: %d", code)
	}
	got := bound.requests()
	if len(got) != 2 || got[0].Get("Authorization") != "Bearer "+credential || got[1].Get("Authorization") != "Bearer "+credential {
		t.Fatalf("the bound host did not receive the credential: %d requests", len(got))
	}
	for k, vs := range mergeHeaders(got) {
		if strings.EqualFold(k, run.SessionHeader) || strings.EqualFold(k, "proxy-authorization") {
			t.Errorf("the tool API received %s", k)
		}
		for _, v := range vs {
			if strings.Contains(v, token[len(token)-20:]) {
				t.Errorf("the tool API received the token in %s", k)
			}
		}
	}
	// An unbound host never sees the request.
	if code, body := toolGet(t, ctx, client, "https://"+unbound.host()+"/v1/thing"); code != http.StatusForbidden || !strings.Contains(body, "unbound") {
		t.Fatalf("unbound host: %d %s", code, body)
	}
	if n := len(unbound.requests()); n != 0 {
		t.Fatalf("the unbound host received %d requests", n)
	}
	// Without the session the caller is unknown: no injection.
	anon := proxyClient(t, &url.URL{Scheme: "http", Host: d.Addrs().ForwardProxy}, d.TrustBundlePEM())
	if code, body := toolGet(t, ctx, anon, "https://"+bound.host()+"/v1/thing"); code != http.StatusForbidden || !strings.Contains(body, "policy_denied") {
		t.Fatalf("anonymous injection: %d %s", code, body)
	}
	if n := len(bound.requests()); n != 2 {
		t.Fatalf("the bound host received %d requests", n)
	}

	// The decisions name the caller; nothing logged or audited holds the
	// token.
	var callers []string
	_ = d.App().State.View(ctx, func(tx state.Tx) error {
		es, err := tx.QueryAudit(ctx, state.AuditQuery{Action: gate.ActionDecision})
		for _, e := range es {
			callers = append(callers, e.Attrs["action"]+"/"+e.Attrs["caller"]+"/"+e.Attrs["caller_reason"])
			if strings.Contains(e.Reason, token[len(token)-20:]) {
				t.Error("an audit entry holds the token")
			}
		}
		return err
	})
	all := strings.Join(callers, " ")
	for _, want := range []string{"llm.forward/session/", "llm.forward/refused/no proof of the session token", "inject/session/"} {
		if !strings.Contains(all, want) {
			t.Errorf("no %q decision: %s", want, all)
		}
	}
	if strings.Contains(h.logs.String(), token[len(token)-20:]) || strings.Contains(h.logs.String(), credential) {
		t.Fatal("the token or the credential reached the log")
	}
}

type unexpected struct{ a state.Approval }

func (u *unexpected) Error() string {
	return "unexpected approval: rule " + u.a.Rule + " agent " + u.a.Request.Agent.ID + " session " + u.a.Request.Agent.Session
}

func postMessages(t *testing.T, ctx context.Context, base string, hdr map[string]string, text string) (int, string) {
	t.Helper()
	body := `{"model":"claude-sonnet-4-5","max_tokens":64,"messages":[{"role":"user","content":"` + text + `"}]}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+"/anthropic/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "agent-own-key")
	req.Header.Set("anthropic-version", "2023-06-01")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// proxyClient is an HTTP client configured the way HTTPS_PROXY configures
// one: Go sends the URL's user info as Proxy-Authorization on CONNECT.
func proxyClient(t *testing.T, proxy *url.URL, caPEM string) *http.Client {
	t.Helper()
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = http.ProxyURL(proxy)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		t.Fatal("no CA certificate")
	}
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}

func toolGet(t *testing.T, ctx context.Context, c *http.Client, u string, extra ...string) (int, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("Authorization", "Bearer SCRIM_ACME_KEY")
	for i := 0; i+1 < len(extra); i += 2 {
		req.Header.Set(extra[i], extra[i+1])
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func mergeHeaders(hs []http.Header) http.Header {
	out := http.Header{}
	for _, h := range hs {
		for k, vs := range h {
			out[k] = append(out[k], vs...)
		}
	}
	return out
}
