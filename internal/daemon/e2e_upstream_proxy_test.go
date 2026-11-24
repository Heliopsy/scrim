// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// recordingProxy is an HTTP CONNECT proxy that requires Basic credentials,
// sends every tunnel to dest and keeps the targets asked for and every byte
// the client sent through a tunnel.
type recordingProxy struct {
	addr, auth, dest string

	mu      sync.Mutex
	targets []string
	denied  int
	relayed []byte
}

func startRecordingProxy(t *testing.T, auth, dest string) *recordingProxy {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	p := &recordingProxy{addr: l.Addr().String(), auth: auth, dest: dest}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go p.serve(c)
		}
	}()
	return p
}

func (p *recordingProxy) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil || req.Method != http.MethodConnect {
		return
	}
	if req.Header.Get("Proxy-Authorization") != p.auth {
		p.mu.Lock()
		p.denied++
		p.mu.Unlock()
		_, _ = io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
		return
	}
	up, err := net.Dial("tcp", p.dest)
	if err != nil {
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer func() { _ = up.Close() }()
	p.mu.Lock()
	p.targets = append(p.targets, req.Host)
	p.mu.Unlock()
	_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	go func() { _, _ = io.Copy(c, up) }()
	buf := make([]byte, 32<<10)
	for {
		n, err := br.Read(buf)
		if n > 0 {
			p.mu.Lock()
			p.relayed = append(p.relayed, buf[:n]...)
			p.mu.Unlock()
			if _, werr := up.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (p *recordingProxy) seen() (targets []string, denied int, relayed []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.targets), p.denied, slices.Clone(p.relayed)
}

// providerCert is a CA (PEM) and a certificate for name it issued.
func providerCert(t *testing.T, name string) ([]byte, tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "upstream proxy test provider CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestUpstreamProxyChainRealDataPlane: scrim started with
// HTTPS_PROXY=http://user:password@proxy (as `scrim run` starts it from a
// corporate shell) sends a provider request through that proxy after
// redaction, with TLS to the provider verified inside the tunnel. The secret
// and the proxy password pasted into the request reach the provider only as
// placeholders, and the leak checker finds neither in what the provider
// received, in what crossed the proxy or in the log.
func TestUpstreamProxyChainRealDataPlane(t *testing.T) {
	bin := realDataPlane(t)
	fake := fakeprovider.New(fakeprovider.Options{})
	caPEM, leaf := providerCert(t, "example.com")
	up := httptest.NewUnstartedServer(fake)
	up.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12}
	up.StartTLS()
	defer up.Close()
	_, port, _ := net.SplitHostPort(up.Listener.Addr().String())

	token := seed(t, "sk-chain-")
	proxyPW := credValue()
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("corp-user:"+proxyPW))
	proxy := startRecordingProxy(t, auth, up.Listener.Addr().String())

	h := newHarness(t, token)
	h.opts.DataPlaneEnv = nil
	caFile := filepath.Join(h.dir, "provider-ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	// example.com resolves nowhere useful here: only the proxy, which sends every tunnel to the fake, reaches it.
	h.opts.Config.Environ = append(h.opts.Config.Environ, "SCRIM_DATAPLANE_PATH="+bin,
		"SCRIM_PROXY_UPSTREAM_ANTHROPIC=https://example.com:"+port,
		"SCRIM_DATAPLANE_UPSTREAM_CA_FILE="+caFile,
		"HTTPS_PROXY=http://corp-user:"+proxyPW+"@"+proxy.addr,
		"NO_PROXY=internal.corp.test")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	d, err := Start(ctx, h.opts)
	if err != nil {
		t.Fatalf("start: %v\n%s", err, h.logs.String())
	}
	defer func() { _ = d.Shutdown(context.Background()) }()
	deadline := time.Now().Add(30 * time.Second)
	for !d.Ready(ctx) {
		if time.Now().After(deadline) {
			t.Fatalf("daemon not ready: %+v\n%s", d.Info().Problems, h.logs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got := d.Info().UpstreamProxy; got != "http://"+proxy.addr {
		t.Errorf("Info().UpstreamProxy = %q", got)
	}
	// The proxy password is one of scrim's own credentials.
	eventually(t, "proxy password in the redaction set", func() bool {
		red, err := d.redact(ctx, []byte("x "+proxyPW+" y"))
		return err == nil && strings.Contains(string(red.Text), scrimCredPlaceholder)
	})

	content, _ := json.Marshal("deploy with " + token + " through the proxy as corp-user:" + proxyPW)
	body := `{"model":"claude-sonnet-4-5","max_tokens":64,"messages":[{"role":"user","content":` + string(content) + `}]}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, d.Addrs().BaseURL+"/anthropic/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "agent-own-key")
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	reply, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s\n%s", resp.StatusCode, reply, h.logs.String())
	}

	ex := fake.Exchanges()
	if len(ex) != 1 {
		t.Fatalf("provider saw %d requests", len(ex))
	}
	if !slices.ContainsFunc(ex[0].Placeholders, func(p string) bool { return strings.HasPrefix(p, "⟦scrim:acme:") }) ||
		!slices.ContainsFunc(ex[0].Placeholders, func(p string) bool { return strings.HasPrefix(p, scrimCredPlaceholder) }) {
		t.Errorf("placeholders %v: want the secret's and the proxy password's", ex[0].Placeholders)
	}
	targets, denied, relayed := proxy.seen()
	if len(targets) != 1 || targets[0] != "example.com:"+port || denied != 0 {
		t.Fatalf("proxy saw %v (denied %d)", targets, denied)
	}

	checker := leak.NewChecker([]leak.Seed{
		leak.NewSeed("secret", leak.KindPassword, token),
		credSeed("upstream proxy password", proxyPW),
	})
	if f := checker.Check(ex[0].Capture); len(f) > 0 {
		t.Errorf("a value reached the provider: %v", f)
	}
	if f := checker.CheckText(0, string(relayed)); len(f) > 0 {
		t.Errorf("a value crossed the upstream proxy in clear: %v", f)
	}
	if f := checker.CheckText(0, h.logs.String()); len(f) > 0 {
		t.Errorf("a value reached the log: %v", f)
	}
	if !strings.Contains(h.logs.String(), "outbound connections go through the upstream proxy") {
		t.Errorf("the upstream proxy is not logged:\n%s", h.logs.String())
	}
}
