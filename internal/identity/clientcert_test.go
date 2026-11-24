// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/testing/certtest"
)

func certResolver(t *testing.T, ca *certtest.CA, crls [][]byte, agents map[string]string, unmapped string) *CertResolver {
	t.Helper()
	trust, err := ParseCertTrust(ca.PEM, crls)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := CertRulesFromMap(agents)
	if err != nil {
		t.Fatal(err)
	}
	return &CertResolver{Trust: func() *CertTrust { return trust }, Rules: rules, Unmapped: unmapped}
}

func chainOf(i certtest.Issued) [][]byte { return [][]byte{i.Cert.Raw} }

func certRefusal(t *testing.T, err error) RefusalReason {
	t.Helper()
	re, ok := IsRefused(err)
	if !ok {
		t.Fatalf("want a refusal, got %v", err)
	}
	return re.Reason
}

func TestCertResolverMapsAndRefuses(t *testing.T) {
	ca := certtest.NewCA(t, "agents CA")
	other := certtest.NewCA(t, "someone else's CA")
	builder := ca.Issue(t, certtest.Leaf{CN: "builder-1", SPIFFE: "spiffe://example.org/agents/builder"})
	ci := ca.Issue(t, certtest.Leaf{CN: "ci-runner-7"})
	revoked := ca.Issue(t, certtest.Leaf{CN: "ci-runner-8"})
	stranger := ca.Issue(t, certtest.Leaf{CN: "stranger", SPIFFE: "spiffe://example.org/other/x"})
	agents := map[string]string{
		"builder": "spiffe:spiffe://example.org/agents/* label:team=platform",
		"ci":      "cn:ci-runner-* scope:secrets:list",
	}
	r := certResolver(t, ca, [][]byte{ca.CRL(t, time.Time{}, revoked.Cert)}, agents, "")

	id, err := r.Resolve(chainOf(builder))
	if err != nil {
		t.Fatal(err)
	}
	if id.Agent != "builder" || id.Source != SourceCertificate || id.Principal() != "mtls:builder" ||
		id.Labels[LabelSPIFFEID] != "spiffe://example.org/agents/builder" || id.Labels["team"] != "platform" ||
		id.Labels[LabelCertCN] != "builder-1" || len(id.Labels[LabelCertSHA256]) != 64 || !id.ExpiresAt.Equal(builder.Cert.NotAfter) {
		t.Fatalf("builder: %+v", id)
	}
	a := id.PolicyAgent()
	if a.Kind != policy.IdentityMTLS || a.ID != "builder" || a.Labels["uid"] != "" {
		t.Fatalf("policy agent: %+v", a)
	}
	id, err = r.Resolve(chainOf(ci))
	if err != nil || id.Agent != "ci" || len(id.Scopes) != 1 || id.Scopes[0] != ScopeSecretsList {
		t.Fatalf("ci: %+v %v", id, err)
	}

	// Unmapped: unknown by default, the SPIFFE ID under derive.
	id, err = r.Resolve(chainOf(stranger))
	if err != nil || id.Known() {
		t.Fatalf("unmapped: %+v %v", id, err)
	}
	r.Unmapped = UnmappedDerive
	id, err = r.Resolve(chainOf(stranger))
	if err != nil || id.Agent != "example.org/other/x" || id.Principal() != "mtls:example.org/other/x" {
		t.Fatalf("derived: %+v %v", id, err)
	}
	if id, err := r.Resolve(chainOf(ca.Issue(t, certtest.Leaf{CN: "no-spiffe"}))); err != nil || id.Known() {
		t.Fatalf("derive without a SPIFFE ID: %+v %v", id, err)
	}
	r.Unmapped = ""

	for name, tc := range map[string]struct {
		chain [][]byte
		want  RefusalReason
	}{
		"untrusted":   {chainOf(other.Issue(t, certtest.Leaf{CN: "ci-runner-1"})), RefusedCertUntrusted},
		"expired":     {chainOf(ca.Issue(t, certtest.Leaf{CN: "ci-runner-2", NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Minute)})), RefusedCertExpired},
		"not yet":     {chainOf(ca.Issue(t, certtest.Leaf{CN: "ci-runner-3", NotBefore: time.Now().Add(time.Hour), NotAfter: time.Now().Add(2 * time.Hour)})), RefusedCertNotYetValid},
		"server only": {chainOf(ca.Issue(t, certtest.Leaf{CN: "ci-runner-4", ServerOnly: true})), RefusedCertUsage},
		"revoked":     {chainOf(revoked), RefusedCertRevoked},
		"malformed":   {[][]byte{[]byte("not a certificate")}, RefusedCertMalformed},
		"empty":       {nil, RefusedCertMalformed},
	} {
		id, err := r.Resolve(tc.chain)
		if got := certRefusal(t, err); got != tc.want || id.Known() {
			t.Errorf("%s: refused as %q (want %q), identity %+v", name, got, tc.want, id)
		}
	}
}

func TestCertRevocationLists(t *testing.T) {
	ca := certtest.NewCA(t, "agents CA")
	other := certtest.NewCA(t, "other CA")
	leaf := ca.Issue(t, certtest.Leaf{CN: "a"})
	agents := map[string]string{"a": "cn:a"}

	// No CRL configured: revocation is not checked.
	if id, err := certResolver(t, ca, nil, agents, "").Resolve(chainOf(leaf)); err != nil || id.Agent != "a" {
		t.Fatalf("no CRL: %+v %v", id, err)
	}
	// A CRL for another issuer only: the leaf's status is unknown.
	trust, err := ParseCertTrust(append(append([]byte{}, ca.PEM...), other.PEM...), [][]byte{other.CRL(t, time.Time{})})
	if err != nil {
		t.Fatal(err)
	}
	r := &CertResolver{Trust: func() *CertTrust { return trust }, Rules: []CertRule{{Agent: "a", CN: []string{"a"}}}}
	if got := certRefusal(t, func() error { _, err := r.Resolve(chainOf(leaf)); return err }()); got != RefusedCertRevocationUnknown {
		t.Fatalf("CRL of another issuer: %q", got)
	}
	// A CRL with the right issuer name but signed by another key does not count.
	imposter := certtest.NewCA(t, "agents CA")
	if got := certRefusal(t, func() error {
		_, err := certResolver(t, ca, [][]byte{imposter.CRL(t, time.Time{})}, agents, "").Resolve(chainOf(leaf))
		return err
	}()); got != RefusedCertRevocationUnknown {
		t.Fatalf("forged CRL: %q", got)
	}
	// A CRL past its next update refuses every certificate of its issuer.
	stale := ca.CRL(t, time.Now().Add(-time.Minute))
	if got := certRefusal(t, func() error {
		_, err := certResolver(t, ca, [][]byte{stale}, agents, "").Resolve(chainOf(leaf))
		return err
	}()); got != RefusedCertCRLExpired {
		t.Fatalf("stale CRL: %q", got)
	}
	// A current CRL that does not list the leaf.
	if id, err := certResolver(t, ca, [][]byte{ca.CRL(t, time.Time{})}, agents, "").Resolve(chainOf(leaf)); err != nil || id.Agent != "a" {
		t.Fatalf("current CRL: %+v %v", id, err)
	}
}

func TestParseCertTrust(t *testing.T) {
	ca := certtest.NewCA(t, "c")
	leaf := ca.Issue(t, certtest.Leaf{CN: "x"})
	for name, tc := range map[string]struct {
		ca   []byte
		crls [][]byte
		want string
	}{
		"empty":        {nil, nil, "no CA certificate"},
		"not a CA":     {leaf.CertPEM, nil, "not a CA certificate"},
		"bad CRL":      {ca.PEM, [][]byte{[]byte("garbage")}, "CRL 1"},
		"PEM, no CRL":  {ca.PEM, [][]byte{ca.PEM}, "no X509 CRL block"},
		"broken block": {[]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), nil, "trust anchor 1"},
	} {
		if _, err := ParseCertTrust(tc.ca, tc.crls); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestCertRulesFromMap(t *testing.T) {
	for name, m := range map[string]map[string]string{
		"bad agent name": {"Bad Name": "cn:x"},
		"no matcher":     {"a": "scope:secrets:list"},
		"bad spiffe":     {"a": "spiffe:https://x"},
		"bad scope":      {"a": "cn:x scope:sessions:mint"},
		"reserved label": {"a": "cn:x label:spiffe_id=y"},
		"unknown kind":   {"a": "sa:x/y"},
		"bad glob":       {"a": "cn:[x"},
	} {
		if _, err := CertRulesFromMap(m); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCertTrustSourceReload(t *testing.T) {
	ca := certtest.NewCA(t, "c")
	crl := ca.CRL(t, time.Time{})
	fail := false
	s := &CertTrustSource{
		ReadCA: func() ([]byte, error) {
			if fail {
				return nil, errors.New("gone")
			}
			return ca.PEM, nil
		},
		ReadCRLs: func() ([][]byte, error) { return [][]byte{crl}, nil },
	}
	if s.Current() != nil {
		t.Fatal("trust before the first load")
	}
	if changed, err := s.Reload(); err != nil || !changed {
		t.Fatalf("first load: %v %v", changed, err)
	}
	if changed, err := s.Reload(); err != nil || changed {
		t.Fatalf("unchanged reload: %v %v", changed, err)
	}
	crl = ca.CRL(t, time.Time{}, ca.Issue(t, certtest.Leaf{CN: "r"}).Cert)
	if changed, err := s.Reload(); err != nil || !changed {
		t.Fatalf("new CRL: %v %v", changed, err)
	}
	before := s.Current()
	fail = true
	if _, err := s.Reload(); err == nil || s.Current() != before {
		t.Fatal("a failed reload replaced the trust")
	}
}

func TestResolveClaimCertificate(t *testing.T) {
	ca := certtest.NewCA(t, "c")
	leaf := ca.Issue(t, certtest.Leaf{CN: "a"})
	r := Resolver{Certificates: certResolver(t, ca, nil, map[string]string{"a": "cn:a"}, "")}
	id, err := r.ResolveClaim(context.Background(), TransportClaim{ClientCertificateChain: chainOf(leaf)})
	if err != nil || id.Agent != "a" {
		t.Fatalf("%+v %v", id, err)
	}
	// Without a certificate resolver the chain is refused, not ignored.
	_, err = Resolver{}.ResolveClaim(context.Background(), TransportClaim{ClientCertificateChain: chainOf(leaf)})
	if got := certRefusal(t, err); got != RefusedCertDisabled {
		t.Fatalf("disabled: %q", got)
	}
}
