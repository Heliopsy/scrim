// SPDX-License-Identifier: AGPL-3.0-only

package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/testing/certtest"
)

// certHarness runs the edge listener with client certificate identity:
// certificates from ca map cn:builder to the agent builder.
func certHarness(t *testing.T, ca *certtest.CA, crls ...[]byte) *harness {
	t.Helper()
	h := newHarness(t)
	trust, err := identity.ParseCertTrust(ca.PEM, crls)
	if err != nil {
		t.Fatal(err)
	}
	h.stop()
	h.certs = &identity.CertResolver{Trust: func() *identity.CertTrust { return trust },
		Rules: []identity.CertRule{{Agent: "builder", CN: []string{"builder"}}}}
	h.start()
	return h
}

// certForwarder is a forwarder that presents a client certificate from
// files and sends no token.
func (h *harness) certForwarder(c certtest.Issued) *Forwarder {
	h.t.Helper()
	dir := h.t.TempDir()
	cf, kf := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(cf, c.CertPEM, 0o600); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(kf, c.KeyPEM, 0o600); err != nil {
		h.t.Fatal(err)
	}
	tc, err := NewTLSConfig([]byte(h.ca.certPEM), "scrim.scrim.svc")
	if err != nil {
		h.t.Fatal(err)
	}
	tc.GetClientCertificate = ClientCertificateFiles(cf, kf)
	return &Forwarder{Central: h.addr, TLS: tc, DialTimeout: 2 * time.Second, Log: h.logger("forwarder")}
}

func TestClientCertificateOnTheEdge(t *testing.T) {
	ca := certtest.NewCA(t, "agents CA")
	revoked := ca.Issue(t, certtest.Leaf{CN: "builder"})
	h := certHarness(t, ca, ca.CRL(t, time.Time{}, revoked.Cert))

	good := h.certForwarder(ca.Issue(t, certtest.Leaf{CN: "builder"}))
	id, err := good.Check(context.Background())
	if err != nil || id.Agent != "builder" || id.Source != identity.SourceCertificate {
		t.Fatalf("check = %+v, %v", id, err)
	}
	c, err := good.Dial(context.Background(), PathDatabase+"/app")
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if got := <-h.dbCalled; got.Agent != "builder" || got.Source != identity.SourceCertificate {
		t.Fatalf("database tunnel identity %+v", got)
	}

	// A token the forwarder adds does not override the certificate.
	both := h.certForwarder(ca.Issue(t, certtest.Leaf{CN: "builder"}))
	both.Token = func() ([]byte, error) { return []byte(h.other), nil }
	if id, err := both.Check(context.Background()); err != nil || id.Agent != "builder" {
		t.Fatalf("certificate and token: %+v, %v", id, err)
	}

	other := certtest.NewCA(t, "someone else's CA")
	for name, tc := range map[string]struct {
		cert certtest.Issued
		want string
	}{
		"untrusted": {other.Issue(t, certtest.Leaf{CN: "builder"}), "client certificate untrusted"},
		"expired": {ca.Issue(t, certtest.Leaf{CN: "builder", NotBefore: time.Now().Add(-2 * time.Hour),
			NotAfter: time.Now().Add(-time.Minute)}), "client certificate expired"},
		"revoked":  {revoked, "client certificate revoked"},
		"unmapped": {ca.Issue(t, certtest.Leaf{CN: "stranger"}), "client certificate not mapped to an agent"},
	} {
		f := h.certForwarder(tc.cert)
		_, err := f.Check(context.Background())
		var re *RefusedError
		if !errors.As(err, &re) || re.Status != http.StatusUnauthorized {
			t.Errorf("%s: check %v", name, err)
		}
		if _, err := f.Dial(context.Background(), PathSSHAgent); err == nil {
			t.Errorf("%s: tunnel opened", name)
		}
		if !h.audited(tc.want) {
			t.Errorf("%s: no audit entry %q", name, tc.want)
		}
	}

	// Without client certificates configured, the token still works and a
	// certificate is ignored.
	h2 := newHarness(t)
	f := h2.forwarder(h2.token, h2.ca.certPEM)
	f.TLS.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		c := ca.Issue(t, certtest.Leaf{CN: "builder"}).TLS
		return &c, nil
	}
	if id, err := f.Check(context.Background()); err != nil || id.Source != identity.SourceKubernetes {
		t.Fatalf("token with certificates off: %+v %v", id, err)
	}
}

func (h *harness) audited(detail string) bool {
	h.audit.mu.Lock()
	defer h.audit.mu.Unlock()
	for _, e := range h.audit.entries {
		if e.Tool == ToolEdge && e.Outcome == agenttools.OutcomeRefused && e.Detail == detail &&
			e.Source == string(identity.SourceCertificate) {
			return true
		}
	}
	return false
}
