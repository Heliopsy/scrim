// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"crypto/x509"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/heliopsy/scrim/internal/testing/certtest"
)

// ocspResolver checks against ca (and its CRLs) with OCSP on.
func ocspResolver(t *testing.T, ca *certtest.CA, crls [][]byte, o *OCSPChecker) *CertResolver {
	t.Helper()
	r := certResolver(t, ca, crls, map[string]string{"a": "cn:a"}, "")
	r.OCSP = o
	return r
}

func reason(t *testing.T, r *CertResolver, chain ...*x509.Certificate) RefusalReason {
	t.Helper()
	ders := make([][]byte, 0, len(chain))
	for _, c := range chain {
		ders = append(ders, c.Raw)
	}
	return r.Check(context.Background(), ders)
}

func TestOCSPStatuses(t *testing.T) {
	ca := certtest.NewCA(t, "agents CA")
	resp := ca.Responder(t)
	good := ca.Issue(t, certtest.Leaf{CN: "a", OCSP: []string{resp.URL}})
	revoked := ca.Issue(t, certtest.Leaf{CN: "a", OCSP: []string{resp.URL}})
	unknown := ca.Issue(t, certtest.Leaf{CN: "a", OCSP: []string{resp.URL}})
	noAIA := ca.Issue(t, certtest.Leaf{CN: "a"})
	resp.Set(revoked.Cert, ocsp.Revoked)
	resp.Set(unknown.Cert, ocsp.Unknown)
	r := ocspResolver(t, ca, nil, &OCSPChecker{Timeout: time.Second})

	if got := reason(t, r, good.Cert); got != "" {
		t.Fatalf("good: %q", got)
	}
	if id, err := r.Resolve(chainOf(good)); err != nil || id.Agent != "a" {
		t.Fatalf("good resolves: %+v %v", id, err)
	}
	for name, c := range map[RefusalReason]*x509.Certificate{
		RefusedCertRevoked:           revoked.Cert,
		RefusedCertRevocationUnknown: unknown.Cert,
	} {
		if got := reason(t, r, c); got != name {
			t.Fatalf("want %q, got %q", name, got)
		}
	}
	// No responder and no CRL: nothing can tell its status.
	if got := reason(t, r, noAIA.Cert); got != RefusedCertRevocationUnknown {
		t.Fatalf("no responder: %q", got)
	}
	// A configured responder is asked instead of the certificate's own.
	o := &OCSPChecker{Responder: resp.URL, Timeout: time.Second}
	if got := reason(t, ocspResolver(t, ca, nil, o), noAIA.Cert); got != "" {
		t.Fatalf("configured responder: %q", got)
	}
	// A current CRL covers a certificate the responder does not know.
	if got := reason(t, ocspResolver(t, ca, [][]byte{ca.CRL(t, time.Time{})}, &OCSPChecker{Timeout: time.Second}), unknown.Cert); got != "" {
		t.Fatalf("unknown, covered by a CRL: %q", got)
	}
	// A CRL that lists a certificate wins over a good answer.
	if got := reason(t, ocspResolver(t, ca, [][]byte{ca.CRL(t, time.Time{}, good.Cert)}, &OCSPChecker{Timeout: time.Second}), good.Cert); got != RefusedCertRevoked {
		t.Fatalf("listed in a CRL: %q", got)
	}
}

func TestOCSPUnreachable(t *testing.T) {
	ca := certtest.NewCA(t, "agents CA")
	resp := ca.Responder(t)
	leaf := ca.Issue(t, certtest.Leaf{CN: "a", OCSP: []string{resp.URL}})
	resp.Close()

	if got := reason(t, ocspResolver(t, ca, nil, &OCSPChecker{Timeout: time.Second}), leaf.Cert); got != RefusedCertOCSPUnavailable {
		t.Fatalf("fail-closed: %q", got)
	}
	if got := reason(t, ocspResolver(t, ca, nil, &OCSPChecker{Timeout: time.Second, SoftFail: true}), leaf.Cert); got != "" {
		t.Fatalf("soft-fail: %q", got)
	}
	// A current CRL still answers while the responder is down.
	if got := reason(t, ocspResolver(t, ca, [][]byte{ca.CRL(t, time.Time{})}, &OCSPChecker{Timeout: time.Second}), leaf.Cert); got != "" {
		t.Fatalf("covered by a CRL: %q", got)
	}
	// Soft-fail never accepts a revoked answer.
	up := ca.Responder(t)
	revoked := ca.Issue(t, certtest.Leaf{CN: "a", OCSP: []string{up.URL}})
	up.Set(revoked.Cert, ocsp.Revoked)
	if got := reason(t, ocspResolver(t, ca, nil, &OCSPChecker{Timeout: time.Second, SoftFail: true}), revoked.Cert); got != RefusedCertRevoked {
		t.Fatalf("soft-fail, revoked: %q", got)
	}
}

func TestOCSPResponsesMustVerify(t *testing.T) {
	ca := certtest.NewCA(t, "agents CA")
	other := certtest.NewCA(t, "agents CA")
	resp := ca.Responder(t)
	leaf := ca.Issue(t, certtest.Leaf{CN: "a", OCSP: []string{resp.URL}})
	check := func() RefusalReason {
		return reason(t, ocspResolver(t, ca, nil, &OCSPChecker{Timeout: time.Second}), leaf.Cert)
	}

	cert, key := ca.Delegate(t, true)
	resp.SignWith(cert, key)
	if got := check(); got != "" {
		t.Fatalf("delegated responder: %q", got)
	}
	cert, key = ca.Delegate(t, false)
	resp.SignWith(cert, key)
	if got := check(); got != RefusedCertOCSPUnavailable {
		t.Fatalf("delegate without OCSP signing: %q", got)
	}
	cert, key = other.Delegate(t, true)
	resp.SignWith(cert, key)
	if got := check(); got != RefusedCertOCSPUnavailable {
		t.Fatalf("delegate of another CA: %q", got)
	}
	resp.SignWith(nil, nil)
	resp.NextUpdate(-time.Minute)
	if got := check(); got != RefusedCertOCSPUnavailable {
		t.Fatalf("stale answer: %q", got)
	}
	resp.NextUpdate(time.Hour)
	resp.Broken(true)
	if got := check(); got != RefusedCertOCSPUnavailable {
		t.Fatalf("HTTP 500: %q", got)
	}
}

func TestOCSPCache(t *testing.T) {
	ca := certtest.NewCA(t, "agents CA")
	resp := ca.Responder(t)
	a := ca.Issue(t, certtest.Leaf{CN: "a", OCSP: []string{resp.URL}})
	b := ca.Issue(t, certtest.Leaf{CN: "a", OCSP: []string{resp.URL}})
	now := time.Now()
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	o := &OCSPChecker{Timeout: time.Second, CacheSize: 1, Now: clock}
	ctx := context.Background()

	// Concurrent checks of one certificate share one request.
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if s := o.Check(ctx, a.Cert, ca.Cert); s != OCSPGood {
				t.Errorf("concurrent check: %v", s)
			}
		})
	}
	wg.Wait()
	if h := resp.Hits(); h != 1 {
		t.Fatalf("%d requests for one certificate", h)
	}
	// Kept until its next update.
	resp.Set(a.Cert, ocsp.Revoked)
	if s := o.Check(ctx, a.Cert, ca.Cert); s != OCSPGood || resp.Hits() != 1 {
		t.Fatalf("cached: %v after %d requests", s, resp.Hits())
	}
	mu.Lock()
	now = now.Add(2 * time.Hour)
	mu.Unlock()
	// Past its next update (the responder's clock is real, so its fresh
	// answer is older than this clock's now: allowed within the hour).
	resp.NextUpdate(4 * time.Hour)
	if s := o.Check(ctx, a.Cert, ca.Cert); s != OCSPRevoked || resp.Hits() != 2 {
		t.Fatalf("after next update: %v after %d requests", s, resp.Hits())
	}
	// The cache holds one answer: a second certificate evicts the first.
	if s := o.Check(ctx, b.Cert, ca.Cert); s != OCSPGood || o.CacheLen() != 1 {
		t.Fatalf("second certificate: %v, cache %d", s, o.CacheLen())
	}
	if o.Check(ctx, a.Cert, ca.Cert); resp.Hits() != 4 {
		t.Fatalf("evicted answer was not fetched again: %d requests", resp.Hits())
	}
	// Failures are not kept.
	resp.Broken(true)
	c := ca.Issue(t, certtest.Leaf{CN: "a", OCSP: []string{resp.URL}})
	o.Check(ctx, c.Cert, ca.Cert)
	resp.Broken(false)
	if s := o.Check(ctx, c.Cert, ca.Cert); s != OCSPGood {
		t.Fatalf("after a failure: %v", s)
	}
}

func TestRevocationChainScope(t *testing.T) {
	root := certtest.NewCA(t, "agents root")
	rootResp := root.Responder(t)
	inter := root.Sub(t, "agents intermediate", rootResp.URL)
	interResp := inter.Responder(t)
	leaf := inter.Issue(t, certtest.Leaf{CN: "a", OCSP: []string{interResp.URL}})
	rootResp.Set(inter.Cert, ocsp.Revoked)
	resolver := func(chain bool, crls [][]byte, o *OCSPChecker) *CertResolver {
		r := ocspResolver(t, root, crls, o)
		r.Chain = chain
		return r
	}

	// OCSP: the end entity alone is good, its issuer is revoked.
	if got := reason(t, resolver(false, nil, &OCSPChecker{Timeout: time.Second}), leaf.Cert, inter.Cert); got != "" {
		t.Fatalf("end entity: %q", got)
	}
	if got := reason(t, resolver(true, nil, &OCSPChecker{Timeout: time.Second}), leaf.Cert, inter.Cert); got != RefusedCertRevoked {
		t.Fatalf("chain, OCSP: %q", got)
	}
	// CRLs: the root's list revokes the intermediate.
	crls := [][]byte{root.CRL(t, time.Time{}, inter.Cert), inter.CRL(t, time.Time{})}
	if got := reason(t, resolver(false, crls, nil), leaf.Cert, inter.Cert); got != "" {
		t.Fatalf("end entity, CRLs: %q", got)
	}
	if got := reason(t, resolver(true, crls, nil), leaf.Cert, inter.Cert); got != RefusedCertRevoked {
		t.Fatalf("chain, CRLs: %q", got)
	}
	// Chain scope needs a CRL for every issuer when OCSP is off.
	if got := reason(t, resolver(true, crls[1:], nil), leaf.Cert, inter.Cert); got != RefusedCertRevocationUnknown {
		t.Fatalf("chain, no root CRL: %q", got)
	}
}
