// SPDX-License-Identifier: AGPL-3.0-only

package run

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/leak/stub"
	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/localapi/localapitest"
	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// envAgent selects the test binary's agent mode (see TestMain).
const envAgent = "SCRIM_RUN_TEST_AGENT"

func TestMain(m *testing.M) {
	if mode := os.Getenv(envAgent); mode != "" {
		os.Exit(testAgent(mode))
	}
	os.Exit(m.Run())
}

// testAgent is a tiny agent: it does what a coding agent does with scrim's
// environment and reports what it saw on stdout, never a value.
func testAgent(mode string) int {
	switch mode {
	case "llm":
		return agentLLM()
	case "sleep":
		time.Sleep(time.Minute)
		return 0
	case "env":
		tok := os.Getenv(localapi.EnvToken)
		for _, kv := range os.Environ() {
			k, v, _ := strings.Cut(kv, "=")
			if tok != "" && k != localapi.EnvToken {
				v = strings.ReplaceAll(v, tok, TokenMarker)
			}
			if k == localapi.EnvToken {
				v = fmt.Sprintf("<%d bytes>", len(v))
			}
			_, _ = fmt.Fprintf(os.Stdout, "%s=%s\n", k, v)
		}
		return 0
	}
	return 2
}

func agentLLM() int {
	data, err := os.ReadFile("notes.txt")
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "read:", err)
		return 2
	}
	ctx := context.Background()
	text := string(data)
	post := func(u string, body any, hdr map[string]string) error {
		// Like real clients, do not escape < > & as \u003c.
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(body)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, u, &b)
		req.Header.Set("Content-Type", "application/json")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s: status %d", u, resp.StatusCode)
		}
		return nil
	}
	if err := post(os.Getenv("ANTHROPIC_BASE_URL")+"/v1/messages", map[string]any{
		"model": "claude-test", "max_tokens": 64,
		"messages": []any{map[string]any{"role": "user", "content": "Read this file:\n" + text}},
	}, map[string]string{"X-Api-Key": "fake-provider-key-not-a-seed", "Anthropic-Version": "2023-06-01"}); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "anthropic:", err)
		return 3
	}
	if err := post(os.Getenv("OPENAI_BASE_URL")+"/chat/completions", map[string]any{
		"model":    "gpt-test",
		"messages": []any{map[string]any{"role": "user", "content": "Read this file:\n" + text}},
	}, map[string]string{"Authorization": "Bearer fake-provider-key-not-a-seed"}); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "openai:", err)
		return 3
	}
	c := localapi.FromEnv()
	defer c.Close()
	id, err := c.WhoAmI(ctx)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "whoami:", err)
		return 4
	}
	_, _ = fmt.Fprintf(os.Stdout, "session=%s agent=%s\n", id.SessionID, id.Agent)
	if u := os.Getenv("TEST_TOOL_URL"); u != "" {
		// A tool call: the default client honours HTTPS_PROXY and
		// SSL_CERT_FILE, as curl, git and most SDKs do.
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "tool:", err)
			return 5
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		_, _ = fmt.Fprintf(os.Stdout, "tool=%s\n", b)
	}
	return 7
}

// harness is a scrim stand-in: a real local API, a fake provider behind a
// verbatim redactor on the LLM base URL, and optionally a forward proxy
// with its own CA in front of a TLS "tool" server.
type harness struct {
	api    *localapitest.Server
	fake   *fp.Server
	seeds  []leak.Seed
	llm    *httptest.Server
	ep     Endpoints
	ready  error
	mu     sync.Mutex
	tunnel []string // CONNECT targets seen by the forward proxy
	tool   *httptest.Server
}

func newHarness(t *testing.T, forward bool) *harness {
	t.Helper()
	fake := fp.New(fp.Options{})
	h := newHarnessUpstream(t, forward, fake)
	h.fake = fake
	return h
}

// newHarnessUpstream is newHarness with another model behind the redactor.
func newHarnessUpstream(t *testing.T, forward bool, model http.Handler) *harness {
	t.Helper()
	h := &harness{api: localapitest.Start(t),
		seeds: leak.GenerateSet(leak.KindAPIKey, leak.KindGitHubToken, leak.KindPassword)}
	up := httptest.NewServer(model)
	t.Cleanup(up.Close)
	upURL, _ := url.Parse(up.URL)
	naive := stub.Naive(upURL, h.seeds)
	mux := http.NewServeMux()
	mux.Handle("/anthropic/", http.StripPrefix("/anthropic", naive))
	mux.Handle("/openai/", http.StripPrefix("/openai", naive))
	h.llm = httptest.NewServer(mux)
	t.Cleanup(h.llm.Close)
	h.ep = Endpoints{APISocket: h.api.Socket, LLMBaseURL: h.llm.URL}
	if forward {
		caPEM, cert := testCA(t, "tool.test")
		h.tool = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "tool-ok")
		}))
		h.tool.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		// Agents also tunnel to their own hosts (update checks, telemetry);
		// those fail the handshake against the tool certificate, as they
		// should, and need not be logged.
		h.tool.Config.ErrorLog = log.New(io.Discard, "", 0)
		h.tool.StartTLS()
		t.Cleanup(h.tool.Close)
		px := httptest.NewServer(http.HandlerFunc(h.connect))
		t.Cleanup(px.Close)
		h.ep.ForwardProxy = px.URL
		h.ep.CACertPEM = caPEM
	}
	return h
}

// connect is a CONNECT tunnel that sends every target to the tool server,
// the way scrim's forward proxy terminates every connection itself.
func (h *harness) connect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
		return
	}
	h.mu.Lock()
	h.tunnel = append(h.tunnel, r.Host)
	h.mu.Unlock()
	dst, err := net.Dial("tcp", h.tool.Listener.Addr().String())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hj, _ := w.(http.Hijacker)
	src, buf, err := hj.Hijack()
	if err != nil {
		_ = dst.Close()
		return
	}
	_, _ = src.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	go func() { _, _ = io.Copy(dst, bufio.NewReader(buf)); _ = dst.Close() }()
	_, _ = io.Copy(src, dst)
	_ = src.Close()
}

func (h *harness) tunnels() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.tunnel...)
}

func (h *harness) daemon() Daemon {
	return Fixed{Instance: &Static{EP: h.ep, ReadyFn: func(context.Context) error { return h.ready }}}
}

// testCA makes a CA and a leaf for host signed by it.
func testCA(t *testing.T, host string) ([]byte, tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "scrim test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: key}
}

// syncBuf is a goroutine-safe buffer for the agent's streams.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// baseEnv is a minimal environment for a child: no inherited proxy or
// provider settings from the developer's shell.
func baseEnv(t *testing.T, extra ...string) []string {
	t.Helper()
	return append(isolatedEnv(t), extra...)
}

// isolatedEnv keeps a child, and any scrim it starts, away from the real
// home, config, state, cache and runtime directories.
func isolatedEnv(t *testing.T) []string {
	t.Helper()
	home := t.TempDir()
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + home + "/.config",
		"XDG_STATE_HOME=" + home + "/.local/state",
		"XDG_CACHE_HOME=" + home + "/.cache",
		"XDG_RUNTIME_DIR=" + home + "/run",
	}
}
