// SPDX-License-Identifier: AGPL-3.0-only

package issuer

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/secret"
)

// Key generation is slow under -race; tests draw distinct keys from a pool
// made once.
var (
	poolOnce sync.Once
	pool     []*rsa.PrivateKey
)

func keyPool(t *testing.T) []*rsa.PrivateKey {
	t.Helper()
	poolOnce.Do(func() {
		for range 8 {
			k, err := rsa.GenerateKey(rand.Reader, KeyBits)
			if err != nil {
				panic(err)
			}
			pool = append(pool, k)
		}
	})
	return pool
}

// gen hands out the pool's keys in order, each once.
func gen(t *testing.T) func() (*rsa.PrivateKey, error) {
	keys := keyPool(t)
	n := 0
	var mu sync.Mutex
	return func() (*rsa.PrivateKey, error) {
		mu.Lock()
		defer mu.Unlock()
		if n == len(keys) {
			return nil, fmt.Errorf("test key pool exhausted")
		}
		n++
		return keys[n-1], nil
	}
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

const testURL = "https://scrim.example.test/idp"

type minted struct {
	mu   sync.Mutex
	toks []string
	exps []time.Time
}

func (m *minted) on(v secret.Value, exp time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_ = v.Expose(func(b []byte) error { m.toks = append(m.toks, string(b)); return nil })
	m.exps = append(m.exps, exp)
	v.Wipe()
}

func (m *minted) count() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.toks) }

func newTest(t *testing.T, c *clock, m *minted, logw io.Writer) (*Issuer, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "issuer")
	if logw == nil {
		logw = io.Discard
	}
	o := Options{URL: testURL, TokenTTL: 10 * time.Minute, RotateEvery: 24 * time.Hour, KeyDir: dir,
		Profile: "laptop", Host: "build-01", Now: c.now, Generate: gen(t), Log: slog.New(slog.NewJSONHandler(logw, nil))}
	if m != nil {
		o.OnMint = m.on
	}
	i, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(i.Close)
	return i, dir
}

func sessionID() identity.Identity {
	return identity.Identity{Agent: "claude-laptop", Source: identity.SourceSession, SessionID: "s1", SessionName: "review",
		ExpiresAt: time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC), Scopes: identity.AgentScopes}
}

func kubeID() identity.Identity {
	return identity.Identity{Agent: "agents/agent-a", Source: identity.SourceKubernetes, Labels: map[string]string{
		identity.LabelNamespace: "agents", identity.LabelServiceAccount: "agent-a", identity.LabelPod: "agent-a-0"}}
}

func expose(t *testing.T, v secret.Value) string {
	t.Helper()
	var s string
	_ = v.Expose(func(b []byte) error { s = string(b); return nil })
	v.Wipe()
	return s
}

func TestMintClaims(t *testing.T) {
	c := &clock{t: time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)}
	i, _ := newTest(t, c, nil, nil)
	tok, exp, err := i.Mint(sessionID(), "openbao")
	if err != nil {
		t.Fatal(err)
	}
	if !exp.Equal(c.now().Add(10 * time.Minute)) {
		t.Fatalf("expiry %s", exp)
	}
	cl, err := Verify(expose(t, tok), testURL, "openbao", i.PublicKeys(), c.now(), 0)
	if err != nil {
		t.Fatal(err)
	}
	want := Claims{Issuer: testURL, Subject: "agent:claude-laptop", Audience: "openbao", Agent: "claude-laptop", AgentKind: "session",
		Session: "s1", SessionName: "review", Host: "build-01", Profile: "laptop",
		IssuedAt: c.now().Unix(), NotBefore: c.now().Unix(), Expiry: exp.Unix(), ID: cl.ID}
	if cl != want || len(cl.ID) != 32 {
		t.Fatalf("claims\n got %+v\nwant %+v", cl, want)
	}

	tok, _, err = i.Mint(kubeID(), "sts.amazonaws.com")
	if err != nil {
		t.Fatal(err)
	}
	cl, err = Verify(expose(t, tok), testURL, "sts.amazonaws.com", i.PublicKeys(), c.now(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if cl.Subject != "k8s:agents/agent-a" || cl.AgentKind != "k8s" || cl.Namespace != "agents" || cl.ServiceAccount != "agent-a" ||
		cl.Pod != "agent-a-0" || cl.Host != "" || cl.Session != "" {
		t.Fatalf("kubernetes claims %+v", cl)
	}

	// The subject is the agent, the same for every session of it.
	other := sessionID()
	other.SessionID = "s2"
	if Subject(other) != Subject(sessionID()) {
		t.Fatal("subject depends on the session")
	}
}

func TestMintRefusals(t *testing.T) {
	c := &clock{t: time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)}
	i, _ := newTest(t, c, nil, nil)
	if _, _, err := i.Mint(identity.Unknown(identity.Peer{UID: 1000}), "openbao"); err != ErrUnknownCaller {
		t.Fatalf("unknown caller: %v", err)
	}
	if _, _, err := i.Mint(sessionID(), ""); err != ErrNoAudience {
		t.Fatalf("no audience: %v", err)
	}
	// A session ending in five minutes caps the token there.
	s := sessionID()
	s.ExpiresAt = c.now().Add(5 * time.Minute)
	tok, exp, err := i.Mint(s, "openbao")
	if err != nil || !exp.Equal(s.ExpiresAt) {
		t.Fatalf("capped expiry %s %v", exp, err)
	}
	tok.Wipe()
	s.ExpiresAt = c.now()
	if _, _, err := i.Mint(s, "openbao"); err != ErrSessionEnded {
		t.Fatalf("ended session: %v", err)
	}
}

func TestMintCacheAndRedactionHook(t *testing.T) {
	c := &clock{t: time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)}
	m := &minted{}
	i, _ := newTest(t, c, m, nil)
	a, _, _ := i.Mint(sessionID(), "openbao")
	c.add(6 * time.Minute)
	b, _, _ := i.Mint(sessionID(), "openbao")
	if expose(t, a) != expose(t, b) || m.count() != 1 {
		t.Fatalf("token not reused within two thirds of its life (%d minted)", m.count())
	}
	c.add(time.Minute)
	d, exp, _ := i.Mint(sessionID(), "openbao")
	e, _, _ := i.Mint(sessionID(), "vault")
	if m.count() != 3 {
		t.Fatalf("minted %d, want a new token after two thirds and one per audience", m.count())
	}
	if got := expose(t, d); got != m.toks[1] || !m.exps[1].Equal(exp) {
		t.Fatal("OnMint did not receive the token handed out")
	}
	e.Wipe()
	// Another pod of the same service account has its own claims and token.
	p := kubeID()
	x, _, _ := i.Mint(p, "openbao")
	p.Labels[identity.LabelPod] = "agent-a-1"
	y, _, _ := i.Mint(p, "openbao")
	if expose(t, x) == expose(t, y) {
		t.Fatal("two pods share a token")
	}
	// An ended session's token is never handed out again.
	before := m.count()
	i.Forget("s1")
	z, _, _ := i.Mint(sessionID(), "openbao")
	z.Wipe()
	if m.count() != before+1 {
		t.Fatal("Forget kept the session's token")
	}
}

func TestRotation(t *testing.T) {
	c := &clock{t: time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)}
	i, dir := newTest(t, c, nil, nil)
	srv := httptest.NewServer(i.Handler())
	defer srv.Close()

	first, pub := i.KeyIDs()
	if len(pub) != 2 || pub[0] != first {
		t.Fatalf("published %v, want the signing key and the next one", pub)
	}
	next := pub[1]

	// Nothing happens before the period is over.
	c.add(23*time.Hour + 55*time.Minute)
	if err := i.Tick(); err != nil {
		t.Fatal(err)
	}
	if s, _ := i.KeyIDs(); s != first {
		t.Fatal("rotated early")
	}
	old, _, _ := i.Mint(sessionID(), "openbao")
	oldTok := expose(t, old)
	c.add(5 * time.Minute)
	if err := i.Tick(); err != nil {
		t.Fatal(err)
	}
	signing, pub := i.KeyIDs()
	if signing != next || !slices.Contains(pub, first) || len(pub) != 3 {
		t.Fatalf("after rotation: signing %s published %v; want the pre-published key signing and the old one still published", signing, pub)
	}
	// The JWKS a verifier fetches still verifies the token the old key
	// signed, and the new key's tokens.
	keys := fetchJWKS(t, srv.URL+"/idp"+JWKSPath)
	if _, err := Verify(oldTok, testURL, "openbao", keys, c.now(), 0); err != nil {
		t.Fatalf("token from before the rotation: %v", err)
	}
	// The old token is still cached and reused only while valid; a new
	// audience gets the new key.
	nt, _, _ := i.Mint(sessionID(), "vault")
	if h := tokenKid(t, expose(t, nt)); h != next {
		t.Fatalf("new token signed by %s, want %s", h, next)
	}

	// Restart: the same keys come back from disk.
	j, err := New(Options{URL: testURL, KeyDir: dir, Now: c.now, Generate: gen(t)})
	if err != nil {
		t.Fatal(err)
	}
	if s, p := j.KeyIDs(); s != signing || !slices.Equal(p, pub) {
		t.Fatalf("after restart %s %v, want %s %v", s, p, signing, pub)
	}

	// Once its last token has expired (plus leeway) the old key goes, its
	// file with it.
	c.add(10*time.Minute + RetireLeeway)
	if err := i.Tick(); err != nil {
		t.Fatal(err)
	}
	if _, pub := i.KeyIDs(); slices.Contains(pub, first) || len(pub) != 2 {
		t.Fatalf("retired key still published: %v", pub)
	}
	if _, err := os.Stat(filepath.Join(dir, first+".pem")); !os.IsNotExist(err) {
		t.Fatalf("retired key file still on disk: %v", err)
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		fi, _ := e.Info()
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %04o", e.Name(), fi.Mode().Perm())
		}
	}
	if _, err := Verify(oldTok, testURL, "openbao", fetchJWKS(t, srv.URL+"/idp"+JWKSPath), c.now(), 0); err == nil {
		t.Fatal("expired token from a retired key verified")
	}
}

func TestRotateOverdueOnStart(t *testing.T) {
	c := &clock{t: time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)}
	g := gen(t)
	dir := filepath.Join(t.TempDir(), "k")
	i, err := New(Options{URL: testURL, KeyDir: dir, Now: c.now, Generate: g})
	if err != nil {
		t.Fatal(err)
	}
	_, pub := i.KeyIDs()
	c.add(30 * 24 * time.Hour)
	j, err := New(Options{URL: testURL, KeyDir: dir, Now: c.now, Generate: g})
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := j.KeyIDs(); s != pub[1] {
		t.Fatalf("an overdue key set was not rotated on start: signing %s", s)
	}
}

func TestKeyDirChecks(t *testing.T) {
	c := &clock{t: time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)}
	dir := filepath.Join(t.TempDir(), "k")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{URL: testURL, KeyDir: dir, Now: c.now, Generate: gen(t)}); err == nil || !strings.Contains(err.Error(), "group or others") {
		t.Fatalf("open key directory accepted: %v", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{URL: testURL, KeyDir: dir, Now: c.now, Generate: gen(t)}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, stateFile), []byte(`{"version":1,"current":"../../etc/passwd"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{URL: testURL, KeyDir: dir, Now: c.now, Generate: gen(t)}); err == nil {
		t.Fatal("tampered keys.json accepted")
	}
	if _, err := New(Options{URL: testURL, KeyDir: dir, TokenTTL: time.Hour, RotateEvery: time.Hour}); err == nil {
		t.Fatal("rotation period shorter than a token's life accepted")
	}
}

func pemKeys(t *testing.T, keys ...*rsa.PrivateKey) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, k := range keys {
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		_ = pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	return buf.Bytes()
}

func TestOperatorKeys(t *testing.T) {
	keys := keyPool(t)
	c := &clock{t: time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)}
	v := secret.New(pemKeys(t, keys[6], keys[7]))
	defer v.Wipe()
	i, err := New(Options{URL: testURL, Keys: v, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	s, pub := i.KeyIDs()
	if s != thumbprint(&keys[6].PublicKey) || len(pub) != 2 || pub[1] != thumbprint(&keys[7].PublicKey) {
		t.Fatalf("operator keys: signing %s published %v", s, pub)
	}
	if err := i.Rotate(); err == nil {
		t.Fatal("scrim rotated operator keys")
	}
	tok, _, _ := i.Mint(sessionID(), "openbao")
	if _, err := Verify(expose(t, tok), testURL, "openbao", map[string]*rsa.PublicKey{pub[0]: &keys[6].PublicKey}, c.now(), 0); err != nil {
		t.Fatal(err)
	}

	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(keys[6])
	for name, b := range map[string][]byte{
		"empty":       []byte("not a key"),
		"small":       pemKeys(t, small),
		"pkcs1":       pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}),
		"duplicate":   pemKeys(t, keys[6], keys[6]),
		"bad pkcs8":   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}),
		"public only": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1}}),
	} {
		v := secret.New(b)
		_, err := New(Options{URL: testURL, Keys: v})
		v.Wipe()
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestKeysNeverPrinted formats the issuer and its keys every way a log,
// error or response could, and checks no private key material appears;
// the issuer's own log lines carry key IDs only.
func TestKeysNeverPrinted(t *testing.T) {
	c := &clock{t: time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)}
	var logs bytes.Buffer
	i, _ := newTest(t, c, nil, &logs)
	c.add(25 * time.Hour)
	if err := i.Tick(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	l := slog.New(slog.NewJSONHandler(&out, nil))
	i.mu.Lock()
	keys := make([]signingKey, 0, len(i.keys))
	for _, k := range i.keys {
		keys = append(keys, k)
	}
	i.mu.Unlock()
	for _, k := range keys {
		fmt.Fprintf(&out, "%v %+v %#v %s %q\n", k, k, k, k, k)
		l.Info("key", "k", k, "ptr", &k)
		b, _ := json.Marshal(map[string]any{"k": k})
		out.Write(b)
		err := fmt.Errorf("wrapped %v", k)
		out.WriteString(err.Error())
	}
	fmt.Fprintf(&out, "%v %+v %#v %s\n", i, i, i, i)
	l.Info("issuer", "i", i)
	b, _ := json.Marshal(i)
	out.Write(b)
	out.Write(logs.Bytes())
	got := out.String()
	for _, k := range keys {
		d := k.priv.D.Bytes()
		p := k.priv.Primes[0].Bytes()
		der, _ := x509.MarshalPKCS8PrivateKey(k.priv)
		for _, needle := range []string{
			hex.EncodeToString(d[:16]), base64.RawURLEncoding.EncodeToString(d[:16]), base64.StdEncoding.EncodeToString(der[30:60]),
			k.priv.D.String()[:24], new(big.Int).SetBytes(p).String()[:24], hex.EncodeToString(p[:16]),
		} {
			if strings.Contains(got, needle) {
				t.Fatalf("private key material printed (%q)", needle)
			}
		}
		if !strings.Contains(got, k.kid) {
			t.Fatalf("key id %s missing from the formatted output", k.kid)
		}
	}
	if !strings.Contains(logs.String(), "rotated") {
		t.Fatalf("rotation not logged: %s", logs.String())
	}
}

func TestHandler(t *testing.T) {
	c := &clock{t: time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)}
	i, _ := newTest(t, c, nil, nil)
	srv := httptest.NewServer(i.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/idp" + DiscoveryPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || doc["issuer"] != testURL || doc["jwks_uri"] != testURL+JWKSPath ||
		fmt.Sprint(doc["id_token_signing_alg_values_supported"]) != "[RS256]" || resp.Header.Get("Cache-Control") == "" {
		t.Fatalf("discovery %d %v", resp.StatusCode, doc)
	}
	for _, p := range []string{"/", DiscoveryPath, "/idp/.well-known/other", "/idp/keys.json"} {
		r, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Body.Close()
		if r.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s: %d", p, r.StatusCode)
		}
	}
	r, err := http.Post(srv.URL+"/idp"+JWKSPath, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Body.Close()
	if r.StatusCode == http.StatusOK {
		t.Errorf("POST jwks: %d", r.StatusCode)
	}
	keys := fetchJWKS(t, srv.URL+"/idp"+JWKSPath)
	if len(keys) != 2 {
		t.Fatalf("jwks has %d keys", len(keys))
	}
}

func TestFromConfig(t *testing.T) {
	dir := t.TempDir()
	build := func(t *testing.T, yaml string) (*Issuer, error) {
		t.Helper()
		p := filepath.Join(dir, "scrim.yaml")
		if err := os.WriteFile(p, []byte("apiVersion: scrim.dev/v1\nkind: Config\n"+yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Build(config.Options{ConfigPaths: []string{p}, Environ: []string{}, SystemDir: dir})
		if err != nil {
			return nil, err
		}
		return FromConfig(cfg, func(k string) string {
			if k == "XDG_STATE_HOME" {
				return filepath.Join(dir, "state")
			}
			return ""
		}, nil, nil)
	}
	if i, err := build(t, "identity: {}\n"); i != nil || err != nil {
		t.Fatalf("off by default: %v %v", i, err)
	}
	for name, y := range map[string]string{
		"listen only":    "identity: {issuer: {listen: 127.0.0.1:0}}\n",
		"url only":       "identity: {issuer: {url: https://scrim.example.test}}\n",
		"http remote":    "identity: {issuer: {url: http://scrim.example.test, listen: 127.0.0.1:0}}\n",
		"trailing slash": "identity: {issuer: {url: https://scrim.example.test/, listen: 127.0.0.1:0}}\n",
		"query":          "identity: {issuer: {url: https://scrim.example.test?a=b, listen: 127.0.0.1:0}}\n",
		"ttl too long":   "identity: {issuer: {url: https://scrim.example.test, listen: 127.0.0.1:0, token-ttl: 2h}}\n",
		"literal keys":   "identity: {issuer: {url: https://scrim.example.test, listen: 127.0.0.1:0, signing-keys: abc}}\n",
	} {
		if _, err := build(t, y); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	i, err := build(t, "identity: {issuer: {url: http://127.0.0.1:8200, listen: 127.0.0.1:0}}\n")
	if err != nil || i == nil {
		t.Fatalf("loopback http: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "state", "scrim", "issuer", stateFile)); err != nil {
		t.Fatalf("default key directory: %v", err)
	}
	if i, err := build(t, "identity: {issuer: {url: http://scrim.scrim.svc:9792, listen: 127.0.0.1:0, insecure-http: true}}\n"); err != nil || i == nil {
		t.Fatalf("insecure-http: %v", err)
	}
	keyFile := filepath.Join(dir, "keys.pem")
	if err := os.WriteFile(keyFile, pemKeys(t, keyPool(t)[5]), 0o600); err != nil {
		t.Fatal(err)
	}
	i, err = build(t, "identity: {issuer: {url: https://scrim.example.test, listen: 127.0.0.1:0, signing-keys: \"file:"+keyFile+"\"}}\n")
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := i.KeyIDs(); s != thumbprint(&keyPool(t)[5].PublicKey) {
		t.Fatal("operator key not used")
	}
}

func fetchJWKS(t *testing.T, u string) map[string]*rsa.PublicKey {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		t.Fatal(err)
	}
	out := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		n, _ := base64.RawURLEncoding.DecodeString(k.N)
		e, _ := base64.RawURLEncoding.DecodeString(k.E)
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if thumbprint(pub) != k.Kid || k.Alg != Alg || k.Use != "sig" {
			t.Fatalf("jwk %s does not match its key", k.Kid)
		}
		out[k.Kid] = pub
	}
	return out
}

func tokenKid(t *testing.T, tok string) string {
	t.Helper()
	h, _ := base64.RawURLEncoding.DecodeString(strings.SplitN(tok, ".", 2)[0])
	var hd header
	_ = json.Unmarshal(h, &hd)
	return hd.Kid
}
