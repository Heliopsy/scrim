// SPDX-License-Identifier: AGPL-3.0-only

package netproxy

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
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
)

func build(t *testing.T, env ...string) *config.Config {
	t.Helper()
	cfg, err := config.Build(config.Options{Environ: append([]string{"HOME=" + t.TempDir()}, env...), SystemDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func resolve(t *testing.T, env ...string) *Proxy {
	t.Helper()
	p, err := Resolve(build(t, env...))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Wipe)
	return p
}

func TestResolveSources(t *testing.T) {
	if p := resolve(t); p.Enabled() || p.String() != Direct {
		t.Errorf("no proxy anywhere: %v", p)
	}
	p := resolve(t, "HTTPS_PROXY=http://alice:s3cr%40t-pw-91@proxy.corp.test:3128", "NO_PROXY=corp.test, <local>,10.0.0.0/8")
	if p.String() != "http://proxy.corp.test:3128" || p.Source != SourceEnvironment || p.Username != "alice" {
		t.Errorf("environment proxy: %s %s %q", p, p.Source, p.Username)
	}
	_ = p.Password().Expose(func(b []byte) error {
		if string(b) != "s3cr@t-pw-91" {
			t.Errorf("password not decoded from the URL")
		}
		return nil
	})
	if strings.Join(p.NoProxy, ",") != "localhost,127.0.0.0/8,::1,corp.test,10.0.0.0/8" || len(p.Skipped) != 1 || p.Skipped[0] != "<local>" {
		t.Errorf("no-proxy %v skipped %v", p.NoProxy, p.Skipped)
	}
	// Order of the variables, and host:port alone.
	if p := resolve(t, "http_proxy=proxy-b:8080", "HTTP_PROXY=proxy-a:8080"); p.String() != "http://proxy-a:8080" {
		t.Errorf("HTTP_PROXY before http_proxy: %s", p)
	}
	if p := resolve(t, "HTTP_PROXY=http://proxy-a:8080", "https_proxy=https://proxy-b"); p.String() != "https://proxy-b:443" {
		t.Errorf("https_proxy before HTTP_PROXY: %s", p)
	}
	// The setting wins over the environment, and its no-proxy list replaces NO_PROXY.
	p = resolve(t, "HTTPS_PROXY=http://env-proxy:3128", "NO_PROXY=env.test",
		"SCRIM_NETWORK_UPSTREAM_PROXY_URL=https://cfg-proxy.corp.test:8443",
		"SCRIM_NETWORK_UPSTREAM_PROXY_NO_PROXY=corp.test",
		"SCRIM_NETWORK_UPSTREAM_PROXY_USERNAME=scrim", "SCRIM_NETWORK_UPSTREAM_PROXY_PASSWORD=env:PROXY_PW", "PROXY_PW=cfg-pw-0123456")
	if p.String() != "https://cfg-proxy.corp.test:8443" || p.Source != SourceConfig || p.Username != "scrim" ||
		strings.Join(p.NoProxy, ",") != "localhost,127.0.0.0/8,::1,corp.test" {
		t.Errorf("configured proxy: %s %s %q %v", p, p.Source, p.Username, p.NoProxy)
	}
	// direct overrides the environment.
	if p := resolve(t, "HTTPS_PROXY=http://env-proxy:3128", "SCRIM_NETWORK_UPSTREAM_PROXY_URL=direct"); p.Enabled() {
		t.Errorf("direct: %s", p)
	}
	// The password setting replaces the environment URL's.
	p = resolve(t, "HTTPS_PROXY=http://alice:env-pw-77777@proxy:3128", "SCRIM_NETWORK_UPSTREAM_PROXY_PASSWORD=env:PROXY_PW", "PROXY_PW=cfg-pw-0123456")
	_ = p.Password().Expose(func(b []byte) error {
		if string(b) != "cfg-pw-0123456" || p.Username != "alice" {
			t.Errorf("password setting did not win")
		}
		return nil
	})
}

func TestResolveErrors(t *testing.T) {
	for _, env := range [][]string{
		{"HTTPS_PROXY=socks5://proxy:1080"},
		{"SCRIM_NETWORK_UPSTREAM_PROXY_PASSWORD=env:PW", "PW=no-user-password", "SCRIM_NETWORK_UPSTREAM_PROXY_URL=http://proxy:3128"},
	} {
		cfg := build(t, env...)
		if _, err := Resolve(cfg); err == nil {
			t.Errorf("%v: no error", env)
		} else if strings.Contains(err.Error(), "no-user-password") {
			t.Errorf("error shows the password: %v", err)
		}
	}
	for _, env := range []string{
		"SCRIM_NETWORK_UPSTREAM_PROXY_URL=http://u:p@proxy:3128",
		"SCRIM_NETWORK_UPSTREAM_PROXY_URL=socks5://proxy:1080",
		"SCRIM_NETWORK_UPSTREAM_PROXY_URL=http://proxy:3128/path",
		"SCRIM_NETWORK_UPSTREAM_PROXY_NO_PROXY=<local>",
		"SCRIM_NETWORK_UPSTREAM_PROXY_NO_PROXY=10.0.0.0/33",
		"SCRIM_NETWORK_UPSTREAM_PROXY_USERNAME=a:b",
	} {
		_, err := config.Build(config.Options{Environ: []string{"HOME=" + t.TempDir(), env}, SystemDir: t.TempDir()})
		if err == nil {
			t.Errorf("%s accepted", env)
		} else if strings.Contains(env, "u:p@") && strings.Contains(err.Error(), "u:p") {
			t.Errorf("error repeats the credentials: %v", err)
		}
	}
}

type vectors struct {
	Groups []struct {
		NoProxy string `json:"no_proxy"`
		Cases   []struct {
			Host    string `json:"host"`
			Port    int    `json:"port"`
			Proxied bool   `json:"proxied"`
		} `json:"cases"`
	} `json:"groups"`
}

// TestSharedVectors runs the NO_PROXY cases the data plane runs too
// (scrim-upstream-proxy, noproxy.rs), so both planes send the same
// destinations to the proxy, and checks every entry passes validation.
func TestSharedVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/no_proxy_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, g := range v.Groups {
		var list []string
		for e := range strings.SplitSeq(g.NoProxy, ",") {
			if err := ValidNoProxyEntry(e); err != nil {
				t.Errorf("vector entry rejected: %v", err)
			}
			list = append(list, strings.TrimSpace(e))
		}
		p := &Proxy{URL: &url.URL{Scheme: "http", Host: "proxy.test:3128"}, NoProxy: append(append([]string{}, Loopback...), list...)}
		p.compile()
		for _, c := range g.Cases {
			for _, scheme := range []string{"https", "http"} {
				target := &url.URL{Scheme: scheme, Host: net.JoinHostPort(strings.Trim(c.Host, "[]"), strconv.Itoa(c.Port))}
				got, err := p.ProxyURL(target)
				if err != nil {
					t.Fatal(err)
				}
				if (got != nil) != c.Proxied {
					t.Errorf("NO_PROXY=%q %s: proxied=%v, want %v", g.NoProxy, target, got != nil, c.Proxied)
				}
				n++
			}
		}
	}
	if n < 40 {
		t.Fatalf("only %d cases", n)
	}
}

func TestLoopbackAlwaysDirect(t *testing.T) {
	p := resolve(t, "HTTPS_PROXY=http://proxy:3128")
	for _, h := range []string{"localhost:9790", "127.0.0.1:9791", "127.9.9.9:1", "[::1]:443"} {
		if got, _ := p.ProxyURL(&url.URL{Scheme: "https", Host: h}); got != nil {
			t.Errorf("%s goes through the proxy", h)
		}
	}
	if pb := p.Proto(); pb.GetNoProxy()[0] != "localhost" || pb.GetNoProxy()[1] != "127.0.0.0/8" || pb.GetNoProxy()[2] != "::1" {
		t.Errorf("data plane list %v", pb.GetNoProxy())
	}
}

func TestProtoCopiesPassword(t *testing.T) {
	p := resolve(t, "HTTPS_PROXY=http://alice:proto-pw-123456@proxy:3128")
	m := p.Proto()
	if m.GetUrl() != "http://proxy:3128" || m.GetUsername() != "alice" || string(m.GetPassword()) != "proto-pw-123456" {
		t.Fatalf("proto %v %v", m.GetUrl(), m.GetUsername())
	}
	clear(m.Password)
	if p.Password().Len() != len("proto-pw-123456") || p.Password().Wiped() {
		t.Error("wiping the snapshot copy wiped the Proxy's")
	}
	if resolve(t).Proto() != nil {
		t.Error("direct has a proto")
	}
	if strings.Contains(p.String(), "proto-pw") || strings.Contains(m.GetUrl(), "alice") {
		t.Error("URL shows credentials")
	}
}

// connectProxy is a CONNECT proxy for tests: it requires auth when set,
// records targets and sends every tunnel to dest.
type connectProxy struct {
	addr    string
	auth    string
	dest    string
	mu      sync.Mutex
	targets []string
	denied  int
}

func startConnectProxy(t *testing.T, auth, dest string) *connectProxy {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	cp := &connectProxy{addr: l.Addr().String(), auth: auth, dest: dest}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go cp.serve(c)
		}
	}()
	return cp
}

func (cp *connectProxy) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	req, err := http.ReadRequest(bufio.NewReader(c))
	if err != nil || req.Method != http.MethodConnect {
		return
	}
	if cp.auth != "" && req.Header.Get("Proxy-Authorization") != cp.auth {
		cp.mu.Lock()
		cp.denied++
		cp.mu.Unlock()
		_, _ = io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n")
		return
	}
	cp.mu.Lock()
	cp.targets = append(cp.targets, req.Host)
	cp.mu.Unlock()
	up, err := net.Dial("tcp", cp.dest)
	if err != nil {
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer func() { _ = up.Close() }()
	_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	go func() { _, _ = io.Copy(up, c) }()
	_, _ = io.Copy(c, up)
}

func (cp *connectProxy) seen() ([]string, int) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return append([]string(nil), cp.targets...), cp.denied
}

// TestGoClientsThroughConnectProxy: a transport cloned from
// http.DefaultTransport (as every store, notifier and audit sink client is)
// goes through the installed proxy with its credentials, verifies the
// destination's certificate inside the tunnel, and reaches NO_PROXY hosts
// directly.
func TestGoClientsThroughConnectProxy(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello "+r.Host)
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	const pw = "go-client-proxy-pw-5521"
	cp := startConnectProxy(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("scrim:"+pw)), srv.Listener.Addr().String())
	client := func() *http.Client {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		// The dialler stands in for DNS: every name reaches the test server,
		// so a request that skipped the proxy still answers.
		d := net.Dialer{}
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if strings.HasPrefix(addr, "example.com:") || strings.HasPrefix(addr, "direct.example.com:") {
				addr = srv.Listener.Addr().String()
			}
			return d.DialContext(ctx, network, addr)
		}
		return &http.Client{Transport: tr}
	}
	get := func(host string) (string, error) {
		resp, err := client().Get("https://" + host + ":" + port + "/")
		if err != nil {
			return "", err
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return string(b), nil
	}

	set := func(env ...string) {
		p := resolve(t, env...)
		t.Cleanup(Install(p))
	}
	// With credentials, through the proxy; example.com is in the test certificate.
	set("HTTPS_PROXY=http://scrim:"+pw+"@"+cp.addr, "NO_PROXY=direct.example.com")
	if got, err := get("example.com"); err != nil || !strings.HasPrefix(got, "hello example.com") {
		t.Fatalf("through the proxy: %q %v", got, err)
	}
	if targets, _ := cp.seen(); len(targets) != 1 || targets[0] != "example.com:"+port {
		t.Fatalf("proxy saw %v", targets)
	}
	// NO_PROXY: direct (the certificate does not name direct.example.com, so
	// skip verification of the name only for this request).
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if u, _ := tr.Proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: "direct.example.com:" + port}}); u != nil {
		t.Errorf("NO_PROXY host proxied via %v", u)
	}
	// Wrong password: the proxy refuses and nothing is fetched.
	set("HTTPS_PROXY=http://scrim:wrong-pw-000@" + cp.addr)
	if _, err := get("example.com"); err == nil {
		t.Fatal("request succeeded with a refused proxy password")
	} else if strings.Contains(err.Error(), "wrong-pw") || strings.Contains(err.Error(), pw) {
		t.Errorf("error shows the password: %v", err)
	}
	// Without credentials, against a proxy that needs none.
	open := startConnectProxy(t, "", srv.Listener.Addr().String())
	set("SCRIM_NETWORK_UPSTREAM_PROXY_URL=http://" + open.addr)
	if got, err := get("example.com"); err != nil || !strings.HasPrefix(got, "hello") {
		t.Fatalf("without credentials: %q %v", got, err)
	}
	if targets, _ := open.seen(); len(targets) != 1 {
		t.Fatalf("open proxy saw %v", targets)
	}
	// A proxy that sends the tunnel somewhere with another certificate is
	// refused by TLS verification.
	other := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	other.TLS = &tls.Config{Certificates: []tls.Certificate{selfSigned(t, "example.com")}, MinVersion: tls.VersionTLS12}
	other.StartTLS()
	defer other.Close()
	mitm := startConnectProxy(t, "", other.Listener.Addr().String())
	set("SCRIM_NETWORK_UPSTREAM_PROXY_URL=http://" + mitm.addr)
	if _, err := get("example.com"); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("intercepting proxy not refused: %v", err)
	}
	// Direct overrides everything.
	set("HTTPS_PROXY=http://"+cp.addr, "SCRIM_NETWORK_UPSTREAM_PROXY_URL=direct")
	before, _ := cp.seen()
	if _, err := get("example.com"); err != nil {
		t.Fatal(err)
	}
	if after, _ := cp.seen(); len(after) != len(before) {
		t.Error("direct went through the proxy")
	}
}

// selfSigned is a certificate for name that no test trusts.
func selfSigned(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestFuncFallsBackToEnvironment(t *testing.T) {
	uninstall := Install(nil)
	defer uninstall()
	if http.DefaultTransport.(*http.Transport).Proxy == nil {
		t.Fatal("default transport has no proxy function")
	}
	// Without an installed Proxy, Func is ProxyFromEnvironment; loopback is
	// never proxied either way.
	u, err := Func(&http.Request{URL: &url.URL{Scheme: "https", Host: "127.0.0.1:1"}})
	if u != nil || err != nil {
		t.Errorf("loopback: %v %v", u, err)
	}
}
