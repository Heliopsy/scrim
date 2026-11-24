// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/gate"
	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/run"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/testing/certtest"
	"github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// certClient is an HTTPS client that trusts scrim's CA and presents cert
// (none when cert has no certificate). With proxy set it uses it as an
// HTTPS proxy: Go presents the same client certificate to the proxy.
func certClient(t *testing.T, caPEM string, cert *certtest.Issued, proxy string) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		t.Fatal("no CA certificate")
	}
	tc := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if cert != nil {
		tc.Certificates = []tls.Certificate{cert.TLS}
	}
	tr := &http.Transport{TLSClientConfig: tc, DisableKeepAlives: true, ForceAttemptHTTP2: false}
	if proxy != "" {
		tr.Proxy = http.ProxyURL(&url.URL{Scheme: "https", Host: proxy})
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}

// certMessages posts an Anthropic Messages request to the TLS base URL and
// returns the status code, or 0 and the error when no connection was made.
func certMessages(ctx context.Context, c *http.Client, base string, hdr map[string]string, text string) (int, error) {
	body := `{"model":"claude-sonnet-4-5","max_tokens":64,"messages":[{"role":"user","content":"` + text + `"}]}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+"/anthropic/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "agent-own-key")
	req.Header.Set("anthropic-version", "2023-06-01")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// TestEndToEndClientCertificateIdentity runs the daemon with the real data
// plane and client certificate identity, and sends traffic the way an agent
// with an X.509 identity does: provider requests to the base URL over TLS
// and tool traffic through the forward proxy over TLS, each with its client
// certificate.
//
//   - Two mapped certificates get different outcomes from rules on agent.id,
//     for provider requests and for injection, and each decision is audited
//     as that agent with caller=certificate.
//   - Redaction applies to a certificate caller's provider requests (checked
//     with the leak checker).
//   - Certificates from another CA, expired or revoked, and a client with no
//     certificate, get no connection; each refusal is audited with its reason.
//   - An unmapped certificate is an unknown caller: its injection is refused
//     and audited as caller=unmapped.
//   - A new CRL revokes a certificate without a restart.
func TestEndToEndClientCertificateIdentity(t *testing.T) {
	bin := realDataPlane(t)
	fake := fakeprovider.New(fakeprovider.Options{})
	up := httptest.NewServer(fake)
	defer up.Close()
	pki := newTestPKI(t)
	bound := newToolAPI(t, pki)

	credential := seed(t, "sk-e2e-")
	h := newHarness(t, credential)
	if err := os.WriteFile(filepath.Join(h.dir, "rules.yaml"), []byte(`default: deny
rules:
  - name: no-inject-for-reviewer
    decision: deny
    when: op == "inject" && agent.kind == "mtls" && agent.id == "reviewer"
  - name: no-llm-for-reviewer
    decision: deny
    when: op == "llm.forward" && agent.id == "reviewer"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	ca := certtest.NewCA(t, "agents CA")
	other := certtest.NewCA(t, "someone else's CA")
	old := ca.Issue(t, certtest.Leaf{CN: "builder-old", SPIFFE: "spiffe://example.org/agents/builder"})
	builder := ca.Issue(t, certtest.Leaf{CN: "builder-1", SPIFFE: "spiffe://example.org/agents/builder"})
	reviewer := ca.Issue(t, certtest.Leaf{CN: "reviewer-1", SPIFFE: "spiffe://example.org/agents/reviewer"})
	stranger := ca.Issue(t, certtest.Leaf{CN: "stranger", SPIFFE: "spiffe://example.org/agents/stranger"})
	caFile, crlFile := filepath.Join(h.dir, "agents-ca.pem"), filepath.Join(h.dir, "agents.crl")
	if err := os.WriteFile(caFile, ca.PEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(crlFile, ca.CRL(t, time.Time{}, old.Cert), 0o600); err != nil {
		t.Fatal(err)
	}
	h.editConfig(t, "hosts: [api.acme.test]", "hosts: ["+bound.host()+"]")
	h.editConfig(t, "  forward-listen: 127.0.0.1:0\n", "  forward-listen: 127.0.0.1:0\n  tls-listen: 127.0.0.1:0\n  forward-tls-listen: 127.0.0.1:0\n")
	h.editConfig(t, "catalog:\n", `identity:
  client-certificates:
    enabled: true
    ca: file:`+caFile+`
    crl-files: [`+crlFile+`]
    refresh: 200ms
    agents:
      builder: "spiffe:spiffe://example.org/agents/builder"
      reviewer: "spiffe:spiffe://example.org/agents/reviewer"
catalog:
`)
	toolCA := filepath.Join(h.dir, "tool-api-ca.pem")
	if err := os.WriteFile(toolCA, pki.caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	h.opts.Config.Environ = append(h.opts.Config.Environ, "SCRIM_DATAPLANE_UPSTREAM_CA_FILE="+toolCA)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	d := h.startReal(t, ctx, bin, up.URL)
	addrs := d.Addrs()
	if !strings.HasPrefix(addrs.BaseURLTLS, "https://127.0.0.1:") || addrs.ForwardProxyTLS == "" {
		t.Fatalf("TLS listeners: %+v", addrs)
	}
	scrimCA := d.TrustBundlePEM()
	direct := func(c *certtest.Issued) *http.Client { return certClient(t, scrimCA, c, "") }
	via := func(c *certtest.Issued) *http.Client { return certClient(t, scrimCA, c, addrs.ForwardProxyTLS) }

	// Provider requests: builder is redacted and forwarded, reviewer is
	// denied by its rule. A session header on a certificate connection is
	// ignored and not forwarded.
	checker := leak.NewChecker([]leak.Seed{leak.NewSeed("credential", leak.KindPassword, credential)})
	before := len(fake.Exchanges())
	code, err := certMessages(ctx, direct(&builder), addrs.BaseURLTLS,
		map[string]string{run.SessionHeader: "scrim_st_aaaaaaaaaaaaaaaa_" + strings.Repeat("b", 43)}, "deploy with key "+credential+" please")
	if err != nil || code != http.StatusOK {
		t.Fatalf("builder provider request: %d %v\n%s", code, err, h.logs.String())
	}
	ex := fake.Exchanges()
	if len(ex) != before+1 {
		t.Fatalf("the provider saw %d new requests", len(ex)-before)
	}
	if f := checker.CheckText(1, string(ex[len(ex)-1].Body)); len(f) > 0 {
		t.Fatalf("the credential reached the provider: %+v", f)
	}
	if !strings.Contains(string(ex[len(ex)-1].Body), "⟦scrim:acme:") {
		t.Fatalf("no placeholder in what the provider saw: %s", ex[len(ex)-1].Body)
	}
	for k := range ex[len(ex)-1].Header {
		if strings.EqualFold(k, run.SessionHeader) {
			t.Error("the provider received the session header")
		}
	}
	if code, err := certMessages(ctx, direct(&reviewer), addrs.BaseURLTLS, nil, "hello from reviewer"); err != nil || code == http.StatusOK {
		t.Fatalf("reviewer provider request: %d %v", code, err)
	}

	// Injection through the forward proxy over TLS.
	if code, body := toolGet(t, ctx, via(&builder), "https://"+bound.host()+"/v1/thing"); code != http.StatusOK {
		t.Fatalf("builder injection: %d %s\n%s", code, body, h.logs.String())
	}
	for name, c := range map[string]*certtest.Issued{"reviewer": &reviewer, "unmapped": &stranger} {
		if code, body := toolGet(t, ctx, via(c), "https://"+bound.host()+"/v1/thing"); code != http.StatusForbidden || !strings.Contains(body, "policy_denied") {
			t.Fatalf("%s injection: %d %s", name, code, body)
		}
	}
	got := bound.requests()
	if len(got) != 1 || got[0].Get("Authorization") != "Bearer "+credential {
		t.Fatalf("the bound host got %d requests", len(got))
	}

	// Refused in the handshake: no connection, nothing forwarded.
	expired := ca.Issue(t, certtest.Leaf{CN: "builder-2", SPIFFE: "spiffe://example.org/agents/builder",
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Minute)})
	untrusted := other.Issue(t, certtest.Leaf{CN: "builder-3", SPIFFE: "spiffe://example.org/agents/builder"})
	before = len(fake.Exchanges())
	for name, c := range map[string]*certtest.Issued{"untrusted": &untrusted, "expired": &expired, "revoked": &old, "no certificate": nil} {
		if code, err := certMessages(ctx, direct(c), addrs.BaseURLTLS, nil, "hello"); err == nil {
			t.Errorf("%s: provider request answered %d", name, code)
		}
		if _, err := via(c).Get("https://" + bound.host() + "/v1/thing"); err == nil {
			t.Errorf("%s: the forward proxy accepted the connection", name)
		}
	}
	if n := len(fake.Exchanges()) - before; n != 0 {
		t.Fatalf("the provider saw %d requests from refused certificates", n)
	}

	// A new CRL revokes builder's certificate without a restart.
	if err := os.WriteFile(crlFile, ca.CRL(t, time.Time{}, old.Cert, builder.Cert), 0o600); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the new CRL in force", func() bool {
		_, err := certMessages(ctx, direct(&builder), addrs.BaseURLTLS, nil, "hello")
		return err != nil
	})

	var decisions []string
	refusals := map[string]bool{}
	eventually(t, "the refusals audited", func() bool {
		decisions, refusals = nil, map[string]bool{}
		_ = d.App().State.View(ctx, func(tx state.Tx) error {
			es, err := tx.QueryAudit(ctx, state.AuditQuery{})
			for _, e := range es {
				b, _ := json.Marshal(e)
				if strings.Contains(string(b), credential) {
					t.Fatal("the credential reached the audit log")
				}
				switch e.Action {
				case gate.ActionDecision:
					decisions = append(decisions, e.Attrs["action"]+"/"+e.Attrs["caller"]+"/"+e.Agent.ID+"/"+e.Attrs["status"])
				case "dataplane.client_certificate_refused":
					refusals[e.Reason] = true
				}
			}
			return err
		})
		return refusals["untrusted"] && refusals["expired"] && refusals["revoked"] && refusals["no certificate"]
	})
	all := strings.Join(decisions, " ")
	for _, want := range []string{
		"llm.forward/certificate/builder/allowed", "llm.forward/certificate/reviewer/denied",
		"inject/certificate/builder/allowed", "inject/certificate/reviewer/denied", "inject/unmapped//denied",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("no %q decision: %s", want, all)
		}
	}
	if strings.Contains(h.logs.String(), credential) {
		t.Fatal("the credential reached the log")
	}
}
