// SPDX-License-Identifier: AGPL-3.0-only

package ca

import (
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var edgeNames = []string{"scrim.scrim.svc.cluster.local", "scrim.scrim.svc", "10.0.0.7"}

func openEdgeTest(t *testing.T, dir string, c *clock, names []string, environ ...string) (*Manager, *syncBuffer) {
	t.Helper()
	log, buf := logBuffer()
	m, err := OpenEdge(context.Background(), testConfig(t, environ...), log, names, Options{Dir: dir, Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m, buf
}

// verifyLeaf issues a leaf for names from m's current generation and
// verifies it against m's trust bundle alone.
func verifyLeaf(t *testing.T, m *Manager, now time.Time, names ...string) error {
	t.Helper()
	g := m.Generations()[0]
	defer g.Key.Wipe()
	leaf, err := IssueServer(g.CertPEM, g.Key, names, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(m.TrustBundlePEM()))
	_, err = leaf.Leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	return err
}

func TestEdgeCAIsNameConstrained(t *testing.T) {
	c := newClock()
	m, _ := openEdgeTest(t, privateDir(t), c, edgeNames)
	cert := mustCert(t, m.Certificates()[0].PEM)
	if !strings.HasPrefix(cert.Subject.CommonName, EdgeCommonName+" ") || !cert.IsCA || !cert.MaxPathLenZero || cert.MaxPathLen != 0 {
		t.Fatalf("edge CA shape: cn %q ca %v pathlen %d", cert.Subject.CommonName, cert.IsCA, cert.MaxPathLen)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("edge CA extended key usage %v", cert.ExtKeyUsage)
	}
	if !constrainedTo(cert, edgeNames) {
		t.Fatalf("constraints dns %v ip %v", cert.PermittedDNSDomains, cert.PermittedIPRanges)
	}
	if err := verifyLeaf(t, m, c.Now(), edgeNames...); err != nil {
		t.Fatalf("leaf for the edge names: %v", err)
	}
	// The edge CA's key cannot sign for anything else: not a provider host,
	// not another address.
	for _, other := range []string{"api.anthropic.com", "10.0.0.8", "scrim.other.svc"} {
		if err := verifyLeaf(t, m, c.Now(), other); err == nil {
			t.Fatalf("a certificate for %s verified against the edge CA", other)
		}
	}
	// Only names: no address at all is permitted when none is configured.
	m2, _ := openEdgeTest(t, privateDir(t), c, []string{"scrim.scrim.svc"})
	if err := verifyLeaf(t, m2, c.Now(), "127.0.0.1"); err == nil {
		t.Fatal("an address verified against an edge CA constrained to names only")
	}
	// Only addresses: no DNS name is permitted.
	m3, _ := openEdgeTest(t, privateDir(t), c, []string{"10.0.0.7"})
	if err := verifyLeaf(t, m3, c.Now(), "10.0.0.7"); err != nil {
		t.Fatalf("leaf for the edge address: %v", err)
	}
	if err := verifyLeaf(t, m3, c.Now(), "api.anthropic.com"); err == nil {
		t.Fatal("a DNS name verified against an edge CA constrained to an address only")
	}
}

func TestEdgeCARotatesWhenNamesChange(t *testing.T) {
	c := newClock()
	dir := privateDir(t)
	m, _ := openEdgeTest(t, dir, c, edgeNames)
	first := m.Certificates()[0].ID
	// Same names in another order: the same CA.
	again, _ := openEdgeTest(t, dir, c, []string{edgeNames[2], edgeNames[0], edgeNames[1]})
	if again.Certificates()[0].ID != first {
		t.Fatal("reordered names rotated the edge CA")
	}
	c.Add(time.Minute)
	renamed, buf := openEdgeTest(t, dir, c, []string{"edge.example.internal"})
	certs := renamed.Certificates()
	if certs[0].ID == first || len(certs) != 2 || certs[1].ID != first {
		t.Fatalf("after a rename: %+v", certs)
	}
	if !strings.Contains(buf.String(), "rotating it") {
		t.Fatalf("no log of the rename: %s", buf.String())
	}
	if err := verifyLeaf(t, renamed, c.Now(), "edge.example.internal"); err != nil {
		t.Fatal(err)
	}
}

func TestEdgeCANeverInTheInterceptionDir(t *testing.T) {
	dir := privateDir(t)
	cfg := testConfig(t, "SCRIM_TOOL_PROXY_CA_DIR="+dir, "SCRIM_EDGE_CA_DIR="+dir)
	if _, err := OpenEdge(context.Background(), cfg, nil, edgeNames, Options{}); err == nil ||
		!strings.Contains(err.Error(), "interception CA's directory") {
		t.Fatalf("edge CA in the interception CA's directory: %v", err)
	}
	// The default is a directory of its own.
	home := t.TempDir()
	getenv := func(k string) string {
		if k == "HOME" {
			return home
		}
		return ""
	}
	m, err := OpenEdge(context.Background(), testConfig(t), nil, edgeNames, Options{Getenv: getenv})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if m.Dir() != filepath.Join(home, ".local", "state", "scrim", "edge-ca") {
		t.Fatalf("default edge CA directory %s", m.Dir())
	}
	if _, err := OpenEdge(context.Background(), testConfig(t), nil, nil, Options{Getenv: getenv}); err == nil {
		t.Fatal("an edge CA without names")
	}
}

func TestOperatorEdgeCA(t *testing.T) {
	// An unconstrained operator CA works for any names, with a note.
	certPath, keyPath, g := writeOperatorCA(t, 10*24*time.Hour)
	defer g.wipe()
	log, buf := logBuffer()
	cfg := testConfig(t, "SCRIM_EDGE_CA_CERT_FILE="+certPath, "SCRIM_EDGE_CA_KEY=file:"+keyPath)
	m, err := OpenEdge(context.Background(), cfg, log, edgeNames, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if !m.Operator() || m.TrustBundlePEM() != g.certPEM {
		t.Fatal("not the operator's edge CA")
	}
	if !strings.Contains(buf.String(), "no name constraints") {
		t.Fatalf("no note about the missing constraints: %s", buf.String())
	}
	if err := m.Rotate(context.Background()); err == nil || !strings.Contains(err.Error(), "edge.ca.cert-file") {
		t.Fatalf("rotate: %v", err)
	}

	// A constrained operator CA must allow the configured names.
	prof := edgeProfile
	prof.names = []string{"scrim.scrim.svc"}
	cg, err := generate(time.Now(), 48*time.Hour, &prof)
	if err != nil {
		t.Fatal(err)
	}
	defer cg.wipe()
	d := t.TempDir()
	cPath, kPath := filepath.Join(d, "edge.crt"), filepath.Join(d, "edge.key")
	if err := os.WriteFile(cPath, []byte(cg.certPEM), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = cg.key.Expose(func(b []byte) error { return os.WriteFile(kPath, b, 0o600) })
	ccfg := testConfig(t, "SCRIM_EDGE_CA_CERT_FILE="+cPath, "SCRIM_EDGE_CA_KEY=file:"+kPath)
	ok, err := OpenEdge(context.Background(), ccfg, nil, []string{"scrim.scrim.svc"}, Options{})
	if err != nil {
		t.Fatalf("constrained edge CA for its own name: %v", err)
	}
	ok.Close()
	if _, err := OpenEdge(context.Background(), ccfg, nil, []string{"scrim.scrim.svc", "scrim.other.svc"}, Options{}); err == nil ||
		!strings.Contains(err.Error(), "cannot issue a certificate") {
		t.Fatalf("constrained edge CA for a name it does not permit: %v", err)
	}
}

func TestSharesKey(t *testing.T) {
	a, err := newGeneration(time.Now(), 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer a.wipe()
	b, err := newGeneration(time.Now(), 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer b.wipe()
	if !SharesKey([]string{a.certPEM}, []string{b.certPEM + a.certPEM}) {
		t.Fatal("the same certificate in a bundle was not found")
	}
	if SharesKey([]string{a.certPEM}, []string{b.certPEM}) {
		t.Fatal("two keys reported as one")
	}
}
