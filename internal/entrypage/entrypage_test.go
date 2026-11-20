// SPDX-License-Identifier: AGPL-3.0-only

package entrypage

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/agenttools/agenttoolstest"
)

// Generated test value, never a real secret.
const entered = "ask-test-value-90ab78cd56ef"

type harness struct {
	env    *agenttoolstest.Env
	base   string
	client *http.Client
}

// start serves a real page on loopback, wired to a Service over fakes.
func start(t *testing.T) *harness {
	t.Helper()
	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	links := Links{Addr: ln.Addr().String()}
	e := agenttoolstest.NewEnv(t)
	svc, err := agenttools.New(agenttools.Deps{Policy: e.Policy, Approvals: e.Approvals, Catalog: e.Store,
		Store: e.Store, Auditor: e.Audit, Notifier: e.Notifier, Links: links})
	if err != nil {
		t.Fatal(err)
	}
	e.Service = svc
	p := New(svc, links.Addr, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &harness{env: e, base: links.Base(), client: c}
}

// ask opens an ask as agent dev, waiting for the answer in the background,
// and returns the entry link and a function that returns the agent's result.
func (p *harness) ask(t *testing.T, ref string) (string, func() agenttools.AskOutput) {
	t.Helper()
	notices := p.env.Notifier.Chan()
	var (
		out agenttools.AskOutput
		wg  sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		var err error
		out, err = p.env.Service.Ask(context.Background(), agenttoolstest.Agent("dev", 1000),
			agenttools.AskInput{Ref: ref, Prompt: "Hetzner API token <b>for</b> project web", WaitSeconds: 10})
		if err != nil {
			t.Error(err)
		}
	}()
	n := <-notices
	return n.URL, func() agenttools.AskOutput { wg.Wait(); return out }
}

func (p *harness) get(t *testing.T, u string) (*http.Response, string) {
	t.Helper()
	resp, err := p.client.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (p *harness) post(t *testing.T, u string, form url.Values, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, u, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", p.base)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := p.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

// TestHumanEntersAValue is the 8.4 verification: the human submits a value,
// it is stored, and the agent receives only "stored" with the reference.
func TestHumanEntersAValue(t *testing.T) {
	p := start(t)
	link, result := p.ask(t, "bao://kv/agents/hcloud")
	resp, body := p.get(t, link)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET: %d", resp.StatusCode)
	}
	for _, want := range []string{"dev", "bao://kv/agents/hcloud", `type="password"`, `<label for="value">`, `lang="en"`,
		"Hetzner API token &lt;b&gt;for&lt;/b&gt; project web"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(body, "<script") || regexp.MustCompile(`(?i)(src|href)="?https?:`).MatchString(body) {
		t.Error("page loads scripts or external assets")
	}

	resp, body = p.post(t, link, url.Values{"value": {entered}, "action": {"store"}}, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Stored") {
		t.Fatalf("POST: %d %s", resp.StatusCode, body)
	}
	out := result()
	if out.Status != agenttools.AskStored || out.Ref != "bao://kv/agents/hcloud" {
		t.Fatalf("agent got %+v", out)
	}
	if v, _ := p.env.Store.Value("bao://kv/agents/hcloud"); string(v) != entered {
		t.Fatal("value not stored exactly")
	}
	agenttoolstest.AssertNoValues(t, "confirmation page", []byte(body), []byte(entered))

	// The link is single use.
	resp, _ = p.get(t, link)
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("reused link: %d", resp.StatusCode)
	}
	resp, _ = p.post(t, link, url.Values{"value": {"second-value"}, "action": {"store"}}, nil)
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("second POST: %d", resp.StatusCode)
	}
	if v, _ := p.env.Store.Value("bao://kv/agents/hcloud"); string(v) != entered {
		t.Fatal("second POST changed the value")
	}
}

func TestHumanDeclines(t *testing.T) {
	p := start(t)
	link, result := p.ask(t, "bao://kv/agents/x")
	resp, body := p.post(t, link, url.Values{"action": {"decline"}}, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Declined") {
		t.Fatalf("decline: %d", resp.StatusCode)
	}
	if out := result(); out.Status != agenttools.AskDeclined {
		t.Fatalf("agent got %+v", out)
	}
	if _, ok := p.env.Store.Value("bao://kv/agents/x"); ok {
		t.Fatal("declined ask stored a value")
	}
}

func TestEmptyValueKeepsTheFormOpen(t *testing.T) {
	p := start(t)
	link, result := p.ask(t, "bao://kv/agents/x")
	resp, body := p.post(t, link, url.Values{"value": {""}, "action": {"store"}}, nil)
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, `role="alert"`) {
		t.Fatalf("empty: %d", resp.StatusCode)
	}
	resp, _ = p.post(t, link, url.Values{"value": {"x y+z%"}, "action": {"store"}}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("after empty: %d", resp.StatusCode)
	}
	if v, _ := p.env.Store.Value("bao://kv/agents/x"); string(v) != "x y+z%" {
		t.Fatalf("form decoding: got %d bytes", len(v))
	}
	_ = result()
}

func TestRequestsFromElsewhereAreRefused(t *testing.T) {
	p := start(t)
	link, result := p.ask(t, "bao://kv/agents/x")
	cases := []map[string]string{
		{"Origin": "http://evil.example"},
		{"Origin": ""},
		{"Sec-Fetch-Site": "cross-site"},
		{"Content-Type": "multipart/form-data; boundary=x"},
	}
	for _, hdr := range cases {
		resp, _ := p.post(t, link, url.Values{"value": {entered}, "action": {"store"}}, hdr)
		if resp.StatusCode < 400 || resp.StatusCode == http.StatusGone {
			t.Errorf("%v: status %d", hdr, resp.StatusCode)
		}
	}
	// DNS rebinding: the right address under another Host name.
	req, _ := http.NewRequest(http.MethodGet, link, nil)
	req.Host = "attacker.example"
	resp, err := p.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Errorf("foreign Host: %d", resp.StatusCode)
	}
	if _, ok := p.env.Store.Value("bao://kv/agents/x"); ok {
		t.Fatal("a refused request stored a value")
	}
	// The link still works for the real page.
	resp, _ = p.post(t, link, url.Values{"action": {"decline"}}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("decline after refusals: %d", resp.StatusCode)
	}
	_ = result()
}

func TestSecurityHeaders(t *testing.T) {
	p := start(t)
	link, result := p.ask(t, "bao://kv/agents/x")
	for _, u := range []string{link, p.base + "/entry/unknown-token", p.base + "/"} {
		resp, body := p.get(t, u)
		h := resp.Header
		csp := h.Get("Content-Security-Policy")
		if !strings.HasPrefix(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") || !strings.Contains(csp, "form-action 'self'") {
			t.Errorf("%s: CSP %q", u, csp)
		}
		for k, want := range map[string]string{"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
			"Referrer-Policy": "no-referrer", "Cache-Control": "no-store"} {
			if h.Get(k) != want {
				t.Errorf("%s: %s = %q", u, k, h.Get(k))
			}
		}
		// The inline stylesheet is the one the CSP hash allows.
		m := regexp.MustCompile(`(?s)<style>(.*?)</style>`).FindStringSubmatch(body)
		if m == nil {
			t.Fatalf("%s: no stylesheet", u)
		}
		sum := sha256.Sum256([]byte(m[1]))
		if !strings.Contains(csp, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'") {
			t.Errorf("%s: stylesheet does not match the CSP hash", u)
		}
	}
	resp, _ := p.get(t, p.base+"/entry/unknown-token")
	if resp.StatusCode != http.StatusGone {
		t.Errorf("unknown token: %d", resp.StatusCode)
	}
	_, _ = p.post(t, link, url.Values{"action": {"decline"}}, nil)
	_ = result()
}

func TestTooLargeIsRefused(t *testing.T) {
	p := start(t)
	link, result := p.ask(t, "bao://kv/agents/x")
	big := strings.Repeat("%41", agenttools.MaxValueSize+10)
	req, _ := http.NewRequest(http.MethodPost, link, strings.NewReader("action=store&value="+big))
	req.Close = true
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", p.base)
	resp, err := p.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge && resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("too large: %d", resp.StatusCode)
	}
	if _, ok := p.env.Store.Value("bao://kv/agents/x"); ok {
		t.Fatal("oversized value stored")
	}
	_, _ = p.post(t, link, url.Values{"action": {"decline"}}, nil)
	_ = result()
}

func TestListenRefusesNonLoopback(t *testing.T) {
	for _, a := range []string{"0.0.0.0:0", "[::]:0", "example.com:80", "nonsense"} {
		if ln, err := Listen(a); err == nil {
			_ = ln.Close()
			t.Errorf("%s accepted", a)
		}
	}
	ln, err := Listen("[::1]:0")
	if err == nil {
		_ = ln.Close()
	}
}

func TestParseForm(t *testing.T) {
	f := parseForm([]byte("action=store&value=a%2Bb+c%zz%4&value=second&=x&k"))
	if string(f["action"]) != "store" || string(f["value"]) != "a+b c%zz%4" || len(f["k"]) != 0 {
		t.Fatalf("parsed %q", f)
	}
	if _, ok := f[""]; ok {
		t.Fatal("empty key kept")
	}
}

func TestLinks(t *testing.T) {
	l := Links{Addr: "127.0.0.1:4242"}
	u, err := l.EntryURL("abc_DEF-123")
	if err != nil || u != "http://127.0.0.1:4242/entry/abc_DEF-123" {
		t.Fatalf("%q %v", u, err)
	}
	for _, bad := range []string{"", "a/b", "a?b", "a#b", "a%2f"} {
		if _, err := l.EntryURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
