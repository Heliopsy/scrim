// SPDX-License-Identifier: AGPL-3.0-only

package ca

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/obs"
	"github.com/heliopsy/scrim/internal/secret"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Now().UTC().Truncate(time.Second)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func testConfig(t *testing.T, environ ...string) *config.Config {
	t.Helper()
	cfg, err := config.Build(config.Options{Registry: config.Default, SystemDir: t.TempDir(),
		Environ: append([]string{"HOME=" + t.TempDir()}, environ...)})
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// logBuffer is a scrubbing-free logger, so a leak shows up as written.
func logBuffer() (*slog.Logger, *syncBuffer) {
	var b syncBuffer
	return obs.NewLogger(&b, obs.LogOptions{Level: slog.LevelDebug}), &b
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func openTest(t *testing.T, dir string, c *clock, environ ...string) (*Manager, *syncBuffer) {
	t.Helper()
	log, buf := logBuffer()
	m, err := OpenWith(context.Background(), testConfig(t, environ...), log, Options{Dir: dir, Now: c.Now, PollInterval: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m, buf
}

func privateDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "ca")
	return d
}

func TestGenerationShape(t *testing.T) {
	now := time.Now()
	g, err := newGeneration(now, 17520*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer g.wipe()
	c, err := parseCert([]byte(g.certPEM))
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsCA || !c.BasicConstraintsValid || c.MaxPathLen != 1 {
		t.Errorf("basic constraints: ca=%v valid=%v pathlen=%d", c.IsCA, c.BasicConstraintsValid, c.MaxPathLen)
	}
	if want := x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature; c.KeyUsage != want {
		t.Errorf("key usage %v, want %v", c.KeyUsage, want)
	}
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		t.Fatalf("public key %T, want P-256", c.PublicKey)
	}
	if c.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("signature %v", c.SignatureAlgorithm)
	}
	if c.SerialNumber.Sign() <= 0 || c.SerialNumber.BitLen() > 127 {
		t.Errorf("serial %v", c.SerialNumber)
	}
	pk, _ := pub.Bytes()
	sum := sha256.Sum256(pk)
	if !bytes.Equal(c.SubjectKeyId, sum[:20]) {
		t.Errorf("subject key id is not the truncated SHA-256 rcgen uses")
	}
	if !strings.HasPrefix(c.Subject.CommonName, CommonName+" ") || len(c.Subject.Organization) != 1 || c.Subject.Organization[0] != Organization {
		t.Errorf("subject %s", c.Subject)
	}
	if got := c.NotAfter.Sub(now); got < 17519*time.Hour || got > 17521*time.Hour {
		t.Errorf("validity %s", got)
	}
	// The key is PKCS#8 PEM, the only form CertificateAuthority::from_pem reads.
	_ = g.key.Expose(func(b []byte) error {
		block, rest := pem.Decode(b)
		if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
			t.Fatalf("key PEM block %v", block)
		}
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := k.(*ecdsa.PrivateKey); !ok {
			t.Fatalf("key %T", k)
		}
		return nil
	})
	if err := checkKey(c, g.key); err != nil {
		t.Fatal(err)
	}
	other, err := newGeneration(now, time.Hour*48)
	if err != nil {
		t.Fatal(err)
	}
	defer other.wipe()
	if err := checkKey(c, other.key); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched key: %v", err)
	}
	if other.cert.Subject.CommonName == c.Subject.CommonName {
		t.Fatal("two generations created in the same second share a name")
	}
}

// signingKey reads the private key of a generation, for tests that sign
// like the data plane does.
func signingKey(t *testing.T, g Generation) *ecdsa.PrivateKey {
	t.Helper()
	var k *ecdsa.PrivateKey
	_ = g.Key.Expose(func(b []byte) error {
		block, _ := pem.Decode(b)
		pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		k = pk.(*ecdsa.PrivateKey)
		return nil
	})
	return k
}

func mustCert(t *testing.T, s string) *x509.Certificate {
	t.Helper()
	c, err := parseCert([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// During an overlap the data plane serves leaf + cross certificate (the new
// CA's name and key, signed by the previous CA, path length 0). A client
// that trusts only the previous CA must accept that chain, which needs the
// previous CA's path length to allow one intermediate.
func TestCrossCertificateChainVerifies(t *testing.T) {
	c := newClock()
	m, _ := openTest(t, privateDir(t), c)
	if err := m.Rotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	gens := m.Generations()
	defer func() {
		for _, g := range gens {
			g.Key.Wipe()
		}
	}()
	if len(gens) != 2 || !gens[0].Current || gens[1].Current {
		t.Fatalf("generations %+v", gens)
	}
	cur, prev := mustCert(t, gens[0].CertPEM), mustCert(t, gens[1].CertPEM)
	curKey, prevKey := signingKey(t, gens[0]), signingKey(t, gens[1])

	cross := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: cur.Subject, NotBefore: c.Now().Add(-time.Minute),
		NotAfter: prev.NotAfter, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	crossDER, err := x509.CreateCertificate(rand.Reader, cross, prev, &curKey.PublicKey, prevKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafT := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "api.example.test"},
		DNSNames: []string{"api.example.test"}, NotBefore: c.Now().Add(-time.Minute), NotAfter: c.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafT, cur, &leafKey.PublicKey, curKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	crossCert, _ := x509.ParseCertificate(crossDER)
	for name, root := range map[string]*x509.Certificate{"previous": prev, "current": cur} {
		roots, inter := x509.NewCertPool(), x509.NewCertPool()
		roots.AddCert(root)
		inter.AddCert(crossCert)
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "api.example.test", Roots: roots, Intermediates: inter,
			CurrentTime: c.Now()}); err != nil {
			t.Errorf("client trusting only the %s CA: %v", name, err)
		}
	}
}

func TestPersistenceAndPermissions(t *testing.T) {
	c := newClock()
	state := t.TempDir()
	cfg := testConfig(t)
	m, err := OpenWith(context.Background(), cfg, nil, Options{Getenv: func(k string) string {
		return map[string]string{"XDG_STATE_HOME": state}[k]
	}, Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(state, "scrim", "ca")
	if m.Dir() != dir {
		t.Fatalf("dir %s, want %s", m.Dir(), dir)
	}
	first := m.TrustBundlePEM()
	id := m.Certificates()[0].ID
	m.Close()
	for p, want := range map[string]os.FileMode{
		dir:                           0o700,
		filepath.Join(dir, stateFile): 0o600,
		genPath(dir, id, keyFile):     0o600,
		genPath(dir, id, certFile):    0o644,
	} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s mode %04o, want %04o", p, fi.Mode().Perm(), want)
		}
	}
	m2, err := OpenWith(context.Background(), cfg, nil, Options{Dir: dir, Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	if m2.TrustBundlePEM() != first {
		t.Fatal("reopening generated a new CA")
	}
	m2.Close()

	if err := os.Chmod(genPath(dir, id, keyFile), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWith(context.Background(), cfg, nil, Options{Dir: dir, Now: c.Now}); err == nil ||
		!strings.Contains(err.Error(), "readable by group or others") {
		t.Fatalf("group-readable key: %v", err)
	}
	_ = os.Chmod(genPath(dir, id, keyFile), 0o600)
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWith(context.Background(), cfg, nil, Options{Dir: dir, Now: c.Now}); err == nil ||
		!strings.Contains(err.Error(), "accessible to group or others") {
		t.Fatalf("group-accessible dir: %v", err)
	}
	_ = os.Chmod(dir, 0o700)

	// A key that does not belong to the certificate is refused.
	other, _ := newGeneration(c.Now(), 48*time.Hour)
	_ = other.key.Expose(func(b []byte) error { return os.WriteFile(genPath(dir, id, keyFile), b, 0o600) })
	other.wipe()
	if _, err := OpenWith(context.Background(), cfg, nil, Options{Dir: dir, Now: c.Now}); err == nil ||
		!strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched key: %v", err)
	}
}

func TestDefaultDir(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if d, _ := DefaultDir(env(map[string]string{"XDG_STATE_HOME": "/x/state", "HOME": "/h"})); d != "/x/state/scrim/ca" {
		t.Error(d)
	}
	if d, _ := DefaultDir(env(map[string]string{"XDG_STATE_HOME": "relative", "HOME": "/h"})); d != "/h/.local/state/scrim/ca" {
		t.Error(d)
	}
	if _, err := DefaultDir(env(nil)); err == nil {
		t.Error("no HOME and no XDG_STATE_HOME accepted")
	}
}

func TestRotationAndOverlapExpiry(t *testing.T) {
	c := newClock()
	dir := privateDir(t)
	m, _ := openTest(t, dir, c)
	first := m.Certificates()[0]
	if len(m.Certificates()) != 1 {
		t.Fatal("new CA has a previous generation")
	}
	c.Add(time.Hour)
	if err := m.Rotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	certs := m.Certificates()
	if len(certs) != 2 || certs[1].ID != first.ID || certs[0].ID == first.ID {
		t.Fatalf("after rotation %+v", certs)
	}
	if n := strings.Count(m.TrustBundlePEM(), "BEGIN CERTIFICATE"); n != 2 {
		t.Fatalf("bundle has %d certificates during the overlap", n)
	}
	gens := m.Generations()
	if want := c.Now().Add(7 * 24 * time.Hour); !gens[1].OverlapUntil.Equal(want) {
		t.Fatalf("overlap until %s, want %s", gens[1].OverlapUntil, want)
	}
	if !gens[0].OverlapUntil.IsZero() || gens[0].Key.IsZero() || gens[1].Key.IsZero() {
		t.Fatal("generation fields")
	}
	// Copies: wiping one does not touch the manager's key.
	gens[0].Key.Wipe()
	gens[1].Key.Wipe()
	if g := m.Generations(); g[0].Key.IsZero() {
		t.Fatal("wiping a returned key wiped the manager's")
	}

	c.Add(7*24*time.Hour - time.Minute)
	m.maintain()
	if len(m.Certificates()) != 2 {
		t.Fatal("overlap ended early")
	}
	c.Add(time.Minute)
	if len(m.Certificates()) != 1 {
		t.Fatal("previous generation still served after its overlap ended")
	}
	m.maintain()
	if _, err := os.Stat(filepath.Join(dir, genDir, first.ID)); !os.IsNotExist(err) {
		t.Fatalf("previous generation not removed from disk: %v", err)
	}
	if n := strings.Count(m.TrustBundlePEM(), "BEGIN CERTIFICATE"); n != 1 {
		t.Fatalf("bundle has %d certificates after the overlap", n)
	}

	// Automatic rotation when less than rotate-before remains.
	cur := m.Certificates()[0]
	c.t = cur.NotAfter.Add(-30*24*time.Hour - time.Minute)
	m.maintain()
	if m.Certificates()[0].ID != cur.ID {
		t.Fatal("rotated before it was due")
	}
	c.Add(time.Minute)
	if d := m.nextCheck(); d != time.Second {
		t.Fatalf("next check in %s when due", d)
	}
	m.maintain()
	if got := m.Certificates(); len(got) != 2 || got[1].ID != cur.ID {
		t.Fatalf("not rotated when due: %+v", got)
	}
}

func TestOverlapCappedAtPreviousExpiry(t *testing.T) {
	c := newClock()
	m, _ := openTest(t, privateDir(t), c, "SCRIM_TOOL_PROXY_CA_OVERLAP=720h")
	notAfter := m.Certificates()[0].NotAfter
	c.t = notAfter.Add(-24 * time.Hour)
	m.maintain() // due: rotates with the overlap capped
	g := m.Generations()
	if len(g) != 2 || !g[1].OverlapUntil.Equal(notAfter) {
		t.Fatalf("overlap until %v, want the previous expiry %s", g, notAfter)
	}
}

func TestRestartKeepsPreviousGeneration(t *testing.T) {
	c := newClock()
	dir := privateDir(t)
	m, _ := openTest(t, dir, c)
	if err := m.Rotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := m.TrustBundlePEM()
	until := m.Generations()[1].OverlapUntil
	m.Close()

	m2, _ := openTest(t, dir, c)
	if m2.TrustBundlePEM() != want || !m2.Generations()[1].OverlapUntil.Equal(until) {
		t.Fatal("restart lost the previous generation or its overlap end")
	}
	m2.Close()

	c.t = until
	m3, _ := openTest(t, dir, c)
	if len(m3.Certificates()) != 1 {
		t.Fatal("restart after the overlap kept the previous generation")
	}
}

func TestRunPicksUpRotationFromAnotherProcess(t *testing.T) {
	c := newClock()
	dir := privateDir(t)
	daemon, _ := openTest(t, dir, c)
	changes := make(chan struct{}, 8)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		daemon.Run(ctx, func() { changes <- struct{}{} })
		close(done)
	}()
	defer func() { cancel(); <-done }()

	cli, _ := openTest(t, dir, c)
	if err := cli.Rotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changes:
	case <-time.After(10 * time.Second):
		t.Fatal("rotation by another process not picked up")
	}
	if daemon.TrustBundlePEM() != cli.TrustBundlePEM() {
		t.Fatal("daemon and CLI disagree after reload")
	}
	// Rotate in this process also notifies.
	if err := daemon.Rotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changes:
	case <-time.After(10 * time.Second):
		t.Fatal("in-process rotation did not call onChange")
	}
}

func writeOperatorCA(t *testing.T, validity time.Duration) (certPath, keyPath string, g *generation) {
	t.Helper()
	g, err := newGeneration(time.Now(), validity)
	if err != nil {
		t.Fatal(err)
	}
	d := t.TempDir()
	certPath, keyPath = filepath.Join(d, "ca.crt"), filepath.Join(d, "ca.key")
	if err := os.WriteFile(certPath, []byte(g.certPEM), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = g.key.Expose(func(b []byte) error { return os.WriteFile(keyPath, b, 0o600) })
	return certPath, keyPath, g
}

// sameKey compares PEM keys ignoring the trailing newline a file: reference
// drops.
func sameKey(a, b secret.Value) bool {
	eq := false
	_ = a.Expose(func(x []byte) error {
		return b.Expose(func(y []byte) error {
			eq = bytes.Equal(bytes.TrimSpace(x), bytes.TrimSpace(y))
			return nil
		})
	})
	return eq
}

func TestOperatorCA(t *testing.T) {
	certPath, keyPath, g := writeOperatorCA(t, 10*24*time.Hour)
	defer g.wipe()
	log, buf := logBuffer()
	cfg := testConfig(t, "SCRIM_TOOL_PROXY_CA_CERT_FILE="+certPath, "SCRIM_TOOL_PROXY_CA_KEY=file:"+keyPath)
	m, err := OpenWith(context.Background(), cfg, log, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if !m.Operator() || m.Dir() != "" {
		t.Fatal("not in operator mode")
	}
	gens := m.Generations()
	if len(gens) != 1 || gens[0].ID != OperatorID || gens[0].CertPEM != g.certPEM || !sameKey(gens[0].Key, g.key) {
		t.Fatalf("generations %+v", gens)
	}
	gens[0].Key.Wipe()
	if err := m.Rotate(context.Background()); err == nil || !strings.Contains(err.Error(), "does not rotate") {
		t.Fatalf("rotate: %v", err)
	}
	if !strings.Contains(buf.String(), "expires soon") {
		t.Fatalf("no expiry warning: %s", buf.String())
	}

	// Public only: no key needed.
	pub, err := OpenWith(context.Background(), testConfig(t, "SCRIM_TOOL_PROXY_CA_CERT_FILE="+certPath,
		"SCRIM_TOOL_PROXY_CA_KEY=bao://kv/ca#key"), nil, Options{PublicOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if pub.TrustBundlePEM() != g.certPEM {
		t.Fatal("public-only bundle")
	}
	// An unresolved store reference is an error when the key is needed.
	if _, err := OpenWith(context.Background(), testConfig(t, "SCRIM_TOOL_PROXY_CA_CERT_FILE="+certPath,
		"SCRIM_TOOL_PROXY_CA_KEY=bao://kv/ca#key"), nil, Options{}); err == nil || !strings.Contains(err.Error(), "could not be resolved") {
		t.Fatalf("unresolved key: %v", err)
	}
	if _, err := OpenWith(context.Background(), testConfig(t, "SCRIM_TOOL_PROXY_CA_CERT_FILE="+certPath), nil, Options{}); err == nil ||
		!strings.Contains(err.Error(), "set together") {
		t.Fatalf("cert without key: %v", err)
	}
	_, otherKey, other := writeOperatorCA(t, 48*time.Hour)
	other.wipe()
	if _, err := OpenWith(context.Background(), testConfig(t, "SCRIM_TOOL_PROXY_CA_CERT_FILE="+certPath,
		"SCRIM_TOOL_PROXY_CA_KEY=file:"+otherKey), nil, Options{}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched key: %v", err)
	}
	// A literal key is refused by the configuration.
	if _, err := config.Build(config.Options{Registry: config.Default, SystemDir: t.TempDir(), Environ: []string{
		"SCRIM_TOOL_PROXY_CA_KEY=-----BEGIN PRIVATE KEY-----"}}); err == nil {
		t.Fatal("literal key accepted")
	}
}

func TestPolicyValidation(t *testing.T) {
	if _, err := OpenWith(context.Background(), testConfig(t, "SCRIM_TOOL_PROXY_CA_VALIDITY=1000h",
		"SCRIM_TOOL_PROXY_CA_ROTATE_BEFORE=600h"), nil, Options{Dir: privateDir(t)}); err == nil {
		t.Fatal("rotate-before above half the validity accepted")
	}
}

// keyMaterial returns the base64 body lines of every key file in dir.
func keyMaterial(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	matches, _ := filepath.Glob(filepath.Join(dir, genDir, "*", keyFile))
	for _, p := range matches {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range strings.Split(string(b), "\n") {
			if l != "" && !strings.HasPrefix(l, "-----") {
				out = append(out, l)
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("no key material found")
	}
	return out
}

func TestKeyNeverLogged(t *testing.T) {
	c := newClock()
	dir := privateDir(t)
	m, buf := openTest(t, dir, c)
	if err := m.Rotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	keys := keyMaterial(t, dir)
	c.Add(8 * 24 * time.Hour)
	m.maintain()
	keys = append(keys, keyMaterial(t, dir)...)
	var errs strings.Builder
	_ = os.Chmod(genPath(dir, m.Certificates()[0].ID, keyFile), 0o644)
	if _, err := OpenWith(context.Background(), testConfig(t), nil, Options{Dir: dir}); err != nil {
		errs.WriteString(err.Error())
	}
	gens := m.Generations()
	out := buf.String() + errs.String() + m.TrustBundlePEM()
	for _, g := range gens {
		out += g.CertPEM + g.Key.String() + g.ID
		g.Key.Wipe()
	}
	if !strings.Contains(buf.String(), "rotated the interception CA") {
		t.Fatalf("expected rotation log, got %s", buf.String())
	}
	for _, k := range keys {
		if strings.Contains(out, k) {
			t.Fatal("key material appears in logs, errors or public output")
		}
	}
	if strings.Contains(out, "PRIVATE KEY") {
		t.Fatal("a private key block appears in output")
	}
}
