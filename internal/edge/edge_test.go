// SPDX-License-Identifier: AGPL-3.0-only

package edge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/localapi"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/sshagent"
)

// testCA is a throwaway CA in the shape scrim's CA manager hands out.
type testCA struct {
	certPEM string
	keyPEM  []byte
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "edge test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		keyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})}
}

func (c testCA) source() (string, secret.Value, error) { return c.certPEM, secret.New(c.keyPEM), nil }

// fakeToken returns a random JWT-shaped token, as the cluster would mint.
func fakeToken(t *testing.T, sub string) string {
	t.Helper()
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	enc := base64.RawURLEncoding
	return "eyJhbGciOiJSUzI1NiJ9." + enc.EncodeToString([]byte(`{"sub":"`+sub+`"}`)) + "." + enc.EncodeToString(b)
}

// fakeKube accepts the tokens it was given, as TokenReview would.
type fakeKube struct {
	mu     sync.Mutex
	tokens map[string]identity.Identity
	down   bool
}

func (k *fakeKube) identify(_ context.Context, tok []byte) (identity.Identity, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.down {
		return identity.Identity{}, errors.New("tokenreview: connection refused")
	}
	id, ok := k.tokens[string(tok)]
	if !ok {
		return identity.Unknown(identity.Peer{}), &identity.RefusedError{Reason: "token not authenticated"}
	}
	return id, nil
}

func kubeID(agent string) identity.Identity {
	return identity.Identity{Agent: agent, Source: identity.SourceKubernetes, Scopes: identity.AgentScopes,
		Labels: map[string]string{identity.LabelNamespace: "agents", identity.LabelServiceAccount: "default"}}
}

// fakeKeyring signs with one key for agent "agents/default" only and
// records who asked.
type fakeKeyring struct {
	signer ssh.Signer
	mu     sync.Mutex
	asked  []string
}

func (k *fakeKeyring) Keys(_ context.Context, id identity.Identity, _ []sshagent.Binding) ([]sshagent.Key, error) {
	k.mu.Lock()
	k.asked = append(k.asked, "keys:"+id.Principal())
	k.mu.Unlock()
	return []sshagent.Key{{Blob: k.signer.PublicKey().Marshal(), Comment: "scrim:deploy"}}, nil
}

func (k *fakeKeyring) Sign(_ context.Context, id identity.Identity, req sshagent.SignRequest) (sshagent.Signature, error) {
	k.mu.Lock()
	k.asked = append(k.asked, "sign:"+id.Principal())
	k.mu.Unlock()
	if id.Agent != "agents/default" {
		return sshagent.Signature{}, agenttools.Errorf(agenttools.CodeDenied, "denied by policy")
	}
	sig, err := k.signer.Sign(rand.Reader, req.Data)
	if err != nil {
		return sshagent.Signature{}, err
	}
	return sshagent.Signature{Format: sig.Format, Blob: sig.Blob}, nil
}

type memAudit struct {
	mu      sync.Mutex
	entries []agenttools.AuditEntry
}

func (a *memAudit) Record(_ context.Context, e agenttools.AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
	return nil
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type harness struct {
	t        *testing.T
	ca       testCA
	kube     *fakeKube
	keyring  *fakeKeyring
	audit    *memAudit
	logs     *syncBuf
	addr     string
	stop     func()
	token    string
	other    string
	dir      string
	dbCalled chan identity.Identity
	// certs, when set, makes the listener take client certificates.
	certs *identity.CertResolver
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, ca: newTestCA(t), keyring: &fakeKeyring{signer: signer}, audit: &memAudit{}, logs: &syncBuf{},
		token: fakeToken(t, "system:serviceaccount:agents:default"), other: fakeToken(t, "system:serviceaccount:agents:other"),
		dir: t.TempDir(), dbCalled: make(chan identity.Identity, 4)}
	h.kube = &fakeKube{tokens: map[string]identity.Identity{h.token: kubeID("agents/default"), h.other: kubeID("agents/other")}}
	h.start()
	return h
}

func (h *harness) logger(component string) *slog.Logger {
	return slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})).With("component", component)
}

// start runs the edge listener on a fresh loopback port (or the previous
// one after a stop).
func (h *harness) start() {
	t := h.t
	addr := h.addr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	h.addr = ln.Addr().String()
	api := &localapi.Server{Logger: h.logger("api")}
	srv := &Server{Identify: h.kube.identify, Certificates: h.certs, API: api.Handler(), SSH: h.keyring, Auditor: h.audit, Log: h.logger("edge"),
		Database: func(name string) (func(context.Context, net.Conn), bool) {
			if name != "app" {
				return nil, false
			}
			return func(_ context.Context, c net.Conn) {
				id, ok := IdentityOf(c)
				if !ok {
					_, _ = c.Write([]byte("no identity\n"))
					return
				}
				h.dbCalled <- id
				_, _ = c.Write([]byte("hello " + id.Agent + "\n"))
				_, _ = io.Copy(c, c)
			}, true
		}}
	certs := &Certs{CA: h.ca.source, Names: []string{"scrim.scrim.svc", "127.0.0.1"}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		cfg := TLSConfig(certs.GetCertificate)
		if h.certs != nil {
			cfg.ClientAuth = tls.RequestClientCert
		}
		_ = srv.Serve(ctx, ln, cfg)
	}()
	h.stop = func() { cancel(); <-done }
	t.Cleanup(h.stop)
}

func (h *harness) forwarder(token, caPEM string) *Forwarder {
	tc, err := NewTLSConfig([]byte(caPEM), "scrim.scrim.svc")
	if err != nil {
		h.t.Fatal(err)
	}
	path := filepath.Join(h.t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		h.t.Fatal(err)
	}
	return &Forwarder{Central: h.addr, TLS: tc, Token: TokenFile(path), DialTimeout: 2 * time.Second, Log: h.logger("forwarder")}
}

// serveLocal runs the forwarder's endpoints in a temporary directory.
func (h *harness) serveLocal(f *Forwarder) (sshSock, apiSock, dbAddr string) {
	t := h.t
	dir, err := os.MkdirTemp("", "edge") // short: Unix socket paths are limited
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sshSock, apiSock = filepath.Join(dir, "ssh.sock"), filepath.Join(dir, "api.sock")
	sl, err := localapi.Listen(sshSock, localapi.ListenOptions{Mode: 0o666})
	if err != nil {
		t.Fatal(err)
	}
	al, err := localapi.Listen(apiSock, localapi.ListenOptions{Mode: 0o666})
	if err != nil {
		t.Fatal(err)
	}
	dl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { _ = f.ServeTunnel(ctx, sl, PathSSHAgent) })
	wg.Go(func() { _ = f.ServeAPI(ctx, al) })
	wg.Go(func() { _ = f.ServeTunnel(ctx, dl, PathDatabase+"/app") })
	t.Cleanup(func() { cancel(); wg.Wait() })
	return sshSock, apiSock, dl.Addr().String()
}

func apiGet(t *testing.T, sock, path, auth string) (int, []byte) {
	t.Helper()
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}, Timeout: 10 * time.Second}
	req, _ := http.NewRequest(http.MethodGet, "http://local"+path, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func TestSSHAgentThroughTheForwarder(t *testing.T) {
	h := newHarness(t)
	sshSock, _, _ := h.serveLocal(h.forwarder(h.token, h.ca.certPEM))
	c, err := net.Dial("unix", sshSock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	ag := agent.NewClient(c)
	keys, err := ag.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].Comment != "scrim:deploy" {
		t.Fatalf("keys = %v", keys)
	}
	data := []byte("data to sign")
	sig, err := ag.Sign(keys[0], data)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.keyring.signer.PublicKey().Verify(data, sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
	// Key material never reaches the pod: the agent cannot add or export.
	if err := ag.Add(agent.AddedKey{PrivateKey: ed25519.NewKeyFromSeed(make([]byte, 32))}); err == nil {
		t.Error("adding a key through the forwarder succeeded")
	}
	h.keyring.mu.Lock()
	asked := strings.Join(h.keyring.asked, ",")
	h.keyring.mu.Unlock()
	if asked != "keys:k8s:agents/default,sign:k8s:agents/default" {
		t.Errorf("keyring calls = %s, want the pod's agent for each", asked)
	}
}

func TestSSHSignatureDeniedForAnotherAgent(t *testing.T) {
	h := newHarness(t)
	sshSock, _, _ := h.serveLocal(h.forwarder(h.other, h.ca.certPEM))
	c, err := net.Dial("unix", sshSock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	ag := agent.NewClient(c)
	keys, err := ag.List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("list: %v %v", keys, err)
	}
	if _, err := ag.Sign(keys[0], []byte("x")); err == nil {
		t.Fatal("a signature the keyring denied was returned")
	}
}

func TestDatabaseTunnelCarriesTheAgent(t *testing.T) {
	h := newHarness(t)
	_, _, dbAddr := h.serveLocal(h.forwarder(h.token, h.ca.certPEM))
	c, err := net.Dial("tcp", dbAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "hello agents/default\n" {
		t.Fatalf("greeting = %q", line)
	}
	if _, err := c.Write([]byte("ping\n")); err != nil {
		t.Fatal(err)
	}
	if echo, _ := br.ReadString('\n'); echo != "ping\n" {
		t.Fatalf("echo = %q", echo)
	}
	if id := <-h.dbCalled; id.Source != identity.SourceKubernetes {
		t.Errorf("source = %s", id.Source)
	}
}

func TestAPIForwardedAsThePod(t *testing.T) {
	h := newHarness(t)
	_, apiSock, _ := h.serveLocal(h.forwarder(h.token, h.ca.certPEM))
	// A client's own Authorization is replaced by the pod's token.
	status, body := apiGet(t, apiSock, "/v1/whoami", "Bearer scrim_st_somethingelse")
	if status != http.StatusOK {
		t.Fatalf("whoami: %d %s", status, body)
	}
	var id identity.Identity
	if err := json.Unmarshal(body, &id); err != nil {
		t.Fatal(err)
	}
	if id.Agent != "agents/default" || id.Source != identity.SourceKubernetes {
		t.Errorf("whoami = %+v", id)
	}
	for _, p := range []string{"/v1/sessions", "/v1/endpoints", "/healthz"} {
		if status, _ := apiGet(t, apiSock, p, ""); status != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", p, status)
		}
	}
}

func TestCheck(t *testing.T) {
	h := newHarness(t)
	id, err := h.forwarder(h.token, h.ca.certPEM).Check(context.Background())
	if err != nil || id.Agent != "agents/default" {
		t.Fatalf("check = %+v, %v", id, err)
	}
	_, err = h.forwarder(fakeToken(t, "nobody"), h.ca.certPEM).Check(context.Background())
	var re *RefusedError
	if !errors.As(err, &re) || re.Status != http.StatusUnauthorized {
		t.Fatalf("check with an unknown token: %v", err)
	}
}

// expectClosed checks that the server side closes c without sending
// anything.
func expectClosed(t *testing.T, c net.Conn, what string) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.Read(make([]byte, 64))
	if n != 0 || err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("%s: read %d bytes, err %v; want the connection closed", what, n, err)
	}
}

func TestFailsClosedWhenCentralIsDown(t *testing.T) {
	h := newHarness(t)
	sshSock, apiSock, dbAddr := h.serveLocal(h.forwarder(h.token, h.ca.certPEM))
	h.stop()

	c, err := net.Dial("tcp", dbAddr)
	if err != nil {
		t.Fatal(err)
	}
	expectClosed(t, c, "database")
	_ = c.Close()

	s, err := net.Dial("unix", sshSock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agent.NewClient(s).List(); err == nil {
		t.Error("ssh-agent listed keys with the central scrim down")
	}
	_ = s.Close()

	status, body := apiGet(t, apiSock, "/v1/whoami", "")
	if status != http.StatusServiceUnavailable || !strings.Contains(string(body), `"unavailable"`) {
		t.Errorf("api with central down: %d %s", status, body)
	}

	// Back up on the same address: the forwarder recovers without a restart.
	h.start()
	if _, err := h.forwarder(h.token, h.ca.certPEM).Check(context.Background()); err != nil {
		t.Fatalf("after restart: %v", err)
	}
	if status, _ := apiGet(t, apiSock, "/v1/whoami", ""); status != http.StatusOK {
		t.Errorf("api after restart: %d", status)
	}
}

func TestFailsClosedWhenIdentityCannotBeChecked(t *testing.T) {
	h := newHarness(t)
	_, apiSock, dbAddr := h.serveLocal(h.forwarder(h.token, h.ca.certPEM))
	h.kube.mu.Lock()
	h.kube.down = true
	h.kube.mu.Unlock()
	c, err := net.Dial("tcp", dbAddr)
	if err != nil {
		t.Fatal(err)
	}
	expectClosed(t, c, "database")
	_ = c.Close()
	if status, _ := apiGet(t, apiSock, "/v1/whoami", ""); status != http.StatusServiceUnavailable {
		t.Errorf("api: %d, want 503", status)
	}
	select {
	case <-h.dbCalled:
		t.Error("the database was served without a verified caller")
	default:
	}
}

func TestRefusedTokens(t *testing.T) {
	h := newHarness(t)
	unknown := fakeToken(t, "system:serviceaccount:agents:stranger")
	for name, tok := range map[string]string{
		"unknown":       unknown,
		"session token": "scrim_st_aaaaaaaaaaaaaaaa_" + strings.Repeat("b", 43),
	} {
		f := h.forwarder(tok, h.ca.certPEM)
		if _, err := f.Dial(context.Background(), PathDatabase+"/app"); err == nil {
			t.Errorf("%s: tunnel opened", name)
		}
		_, apiSock, dbAddr := h.serveLocal(f)
		if status, _ := apiGet(t, apiSock, "/v1/secrets", ""); status != http.StatusUnauthorized {
			t.Errorf("%s: api %d, want 401", name, status)
		}
		c, err := net.Dial("tcp", dbAddr)
		if err != nil {
			t.Fatal(err)
		}
		expectClosed(t, c, name)
		_ = c.Close()
	}
	select {
	case <-h.dbCalled:
		t.Error("a database was served for a refused token")
	default:
	}
	h.audit.mu.Lock()
	entries := h.audit.entries
	h.audit.mu.Unlock()
	if len(entries) == 0 {
		t.Fatal("refusals were not audited")
	}
	raw, _ := json.Marshal(entries)
	for _, tok := range []string{unknown, h.token} {
		if strings.Contains(string(raw), tok) || strings.Contains(h.logs.String(), tok) {
			t.Error("a token reached the audit log or a log line")
		}
	}
	for _, e := range entries {
		if e.Tool != ToolEdge || e.Outcome != agenttools.OutcomeRefused {
			t.Errorf("entry %+v", e)
		}
	}
}

func TestUnknownDatabaseAndBadUpgrade(t *testing.T) {
	h := newHarness(t)
	f := h.forwarder(h.token, h.ca.certPEM)
	_, err := f.Dial(context.Background(), PathDatabase+"/other")
	var re *RefusedError
	if !errors.As(err, &re) || re.Status != http.StatusNotFound {
		t.Fatalf("unknown database: %v", err)
	}
	// A plain GET without the Upgrade is not a tunnel.
	c, err := f.dialTLS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, _ = c.Write([]byte("GET " + PathSSHAgent + " HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + h.token + "\r\n\r\n"))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("GET without upgrade: %d", resp.StatusCode)
	}
}

func TestCentralCertificateMustChainToScrimsCA(t *testing.T) {
	h := newHarness(t)
	other := newTestCA(t)
	f := h.forwarder(h.token, other.certPEM)
	if _, err := f.Dial(context.Background(), PathSSHAgent); err == nil {
		t.Fatal("connected to a server whose certificate another CA signed")
	}
	// Nothing was sent before the handshake failed, so the token never left.
	select {
	case <-h.dbCalled:
		t.Error("unexpected database call")
	default:
	}
	tc, _ := NewTLSConfig([]byte(h.ca.certPEM), "wrong.name")
	f = &Forwarder{Central: h.addr, TLS: tc, Token: func() ([]byte, error) { return []byte(h.token), nil }, DialTimeout: time.Second}
	if _, err := f.Dial(context.Background(), PathSSHAgent); err == nil {
		t.Fatal("connected to a server for a name its certificate does not carry")
	}
}

func TestSettingsValidation(t *testing.T) {
	for _, bad := range []string{"0.0.0.0:5432", "10.0.0.1:5432", "localhost", "127.0.0.1:x"} {
		if loopbackAddr(bad) == nil {
			t.Errorf("%q accepted as a loopback database address", bad)
		}
	}
	for _, good := range []string{"127.0.0.1:5432", "[::1]:3306"} {
		if err := loopbackAddr(good); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}
	if err := validDatabases(map[string]string{"app\r\nX: y": "127.0.0.1:5432"}); err == nil {
		t.Error("a database name with a line break accepted")
	}
	if err := validDatabases(map[string]string{"app-db": "127.0.0.1:5432"}); err != nil {
		t.Errorf("app-db: %v", err)
	}
	if m, err := ParseMode("0660"); err != nil || m != 0o660 {
		t.Errorf("ParseMode = %o, %v", m, err)
	}
	if _, err := ParseMode("999"); err == nil {
		t.Error("999 accepted")
	}
}

func TestAPIRoutes(t *testing.T) {
	for p, want := range map[string]bool{
		"/v1/secrets": true, "/v1/secrets/request": true, "/v1/ssh/sign": true, "/v1/exec": true,
		"/v1/databases/query": true, "/v1/status/abc": true, "/v1/whoami": true,
		"/v1/sessions": false, "/v1/sessions/self": false, "/v1/endpoints": false, "/v1/execx": false, "/v1/": false,
	} {
		if apiRoute(p) != want {
			t.Errorf("apiRoute(%s) = %v, want %v", p, !want, want)
		}
	}
}
