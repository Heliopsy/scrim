// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/testing/certtest"
)

func TestParseListenerCert(t *testing.T) {
	ca := certtest.NewCA(t, "operator")
	server := ca.Issue(t, certtest.Leaf{CN: "scrim.example.test", DNS: []string{"scrim.example.test"}, ServerOnly: true})
	other := ca.Issue(t, certtest.Leaf{CN: "other", ServerOnly: true})
	client := ca.Issue(t, certtest.Leaf{CN: "agent"})
	expired := ca.Issue(t, certtest.Leaf{CN: "old", ServerOnly: true,
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour)})
	chain := append(append([]byte(nil), server.CertPEM...), ca.PEM...)
	now := time.Now()

	c, err := ParseListenerCert(chain, secret.New(server.KeyPEM), now)
	if err != nil {
		t.Fatal(err)
	}
	if c.Leaf.Subject.CommonName != "scrim.example.test" || strings.Count(string(c.ChainPEM), "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("leaf %s, chain %q", c.Leaf.Subject, c.ChainPEM)
	}

	cases := []struct {
		name  string
		chain []byte
		key   []byte
		want  string
	}{
		{"no certificate", []byte("nothing"), server.KeyPEM, "no certificate"},
		{"other key", server.CertPEM, other.KeyPEM, "does not match"},
		{"no key", server.CertPEM, []byte("not a key"), "does not match"},
		{"a CA", ca.PEM, ca.KeyPEM(t), "is a CA certificate"},
		{"client only", client.CertPEM, client.KeyPEM, "does not allow server authentication"},
		{"expired", expired.CertPEM, expired.KeyPEM, "expired at"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseListenerCert(tc.chain, secret.New(tc.key), now)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want one containing %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "PRIVATE KEY") {
				t.Fatalf("the error quotes the key: %v", err)
			}
		})
	}
}

func TestListenerCertSourceReload(t *testing.T) {
	ca := certtest.NewCA(t, "operator")
	first := ca.Issue(t, certtest.Leaf{CN: "one", ServerOnly: true})
	cur := first
	fail := false
	s := &ListenerCertSource{
		Read: func() ([]byte, secret.Value, error) {
			if fail {
				return nil, secret.Value{}, errors.New("gone")
			}
			return cur.CertPEM, secret.New(cur.KeyPEM), nil
		},
		RetireAfter: time.Millisecond,
	}
	if s.Current() != nil || (*ListenerCertSource)(nil).Current() != nil {
		t.Fatal("certificate before the first load")
	}
	if changed, err := s.Reload(); err != nil || !changed {
		t.Fatalf("first load: %v %v", changed, err)
	}
	if changed, err := s.Reload(); err != nil || changed {
		t.Fatalf("unchanged reload: %v %v", changed, err)
	}
	before := s.Current()

	// A renewal half written (the new certificate with the old key) keeps the one in force.
	renewed := ca.Issue(t, certtest.Leaf{CN: "two", ServerOnly: true})
	cur.CertPEM = renewed.CertPEM
	if _, err := s.Reload(); err == nil || s.Current() != before {
		t.Fatal("a mismatched pair replaced the certificate")
	}
	fail = true
	if _, err := s.Reload(); err == nil || s.Current() != before {
		t.Fatal("a failed read replaced the certificate")
	}

	fail = false
	cur = renewed
	if changed, err := s.Reload(); err != nil || !changed {
		t.Fatalf("renewal: %v %v", changed, err)
	}
	if s.Current().Leaf.Subject.CommonName != "two" {
		t.Fatalf("in force: %s", s.Current().Leaf.Subject)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !before.Key.Wiped() {
		if time.Now().After(deadline) {
			t.Fatal("the replaced key was not wiped")
		}
		time.Sleep(time.Millisecond)
	}
}
