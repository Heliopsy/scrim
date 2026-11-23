// SPDX-License-Identifier: AGPL-3.0-only

package ca

import (
	"crypto/x509"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
)

func TestIssueServerVerifiesAgainstTheCA(t *testing.T) {
	now := time.Now()
	g, err := newGeneration(now, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer g.wipe()
	cert, err := IssueServer(g.certPEM, g.key, []string{"scrim.scrim.svc", "10.0.0.7"}, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(g.cert)
	for _, name := range []string{"scrim.scrim.svc", "10.0.0.7"} {
		if _, err := cert.Leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			t.Errorf("verify for %s: %v", name, err)
		}
	}
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{DNSName: "other.example", Roots: roots}); err == nil {
		t.Error("the certificate verified for a name it does not carry")
	}
	if !cert.Leaf.IPAddresses[0].Equal(net.ParseIP("10.0.0.7")) {
		t.Errorf("IP SAN = %v", cert.Leaf.IPAddresses)
	}
	if cert.Leaf.IsCA {
		t.Error("the server certificate is a CA")
	}
	if got := cert.Leaf.NotAfter.Sub(now); got > 24*time.Hour+time.Second {
		t.Errorf("valid for %v, want at most 24h", got)
	}
}

func TestIssueServerNeverOutlivesTheCA(t *testing.T) {
	now := time.Now()
	g, err := newGeneration(now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer g.wipe()
	cert, err := IssueServer(g.certPEM, g.key, []string{"scrim"}, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Leaf.NotAfter.After(g.cert.NotAfter) {
		t.Errorf("leaf expires %v, after the CA %v", cert.Leaf.NotAfter, g.cert.NotAfter)
	}
}

func TestIssueServerRefusals(t *testing.T) {
	now := time.Now()
	g, err := newGeneration(now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer g.wipe()
	keyText := ""
	_ = g.key.Expose(func(b []byte) error { keyText = string(b); return nil })
	cases := map[string]struct {
		cert  string
		key   secret.Value
		names []string
	}{
		"no names":    {g.certPEM, g.key, nil},
		"bad cert":    {"not pem", g.key, []string{"a"}},
		"bad key":     {g.certPEM, secret.FromString("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), []string{"a"}},
		"not pkcs8":   {g.certPEM, secret.FromString("garbage"), []string{"a"}},
		"wrong block": {g.certPEM, secret.FromString(strings.Replace(keyText, "PRIVATE KEY", "EC PRIVATE KEY", 2)), []string{"a"}},
	}
	for name, c := range cases {
		_, err := IssueServer(c.cert, c.key, c.names, now, time.Hour)
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		if strings.Contains(err.Error(), "PRIVATE KEY") || (len(keyText) > 80 && strings.Contains(err.Error(), keyText[40:80])) {
			t.Errorf("%s: the error quotes key material: %v", name, err)
		}
	}
}
