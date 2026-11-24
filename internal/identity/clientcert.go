// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// SourceCertificate is a caller that presented a client certificate on a
// TLS listener, verified against the configured trust anchors and
// revocation lists (agent-identity spec, "Optional mutual TLS identity").
const SourceCertificate Source = "certificate"

// Labels a client certificate identity carries, as policy sees them
// (`agent.labels.spiffe_id` and so on). They are set from the certificate
// and cannot be configured.
const (
	// LabelSPIFFEID is the certificate's SPIFFE ID, its one URI SAN with the
	// spiffe scheme.
	LabelSPIFFEID = "spiffe_id"
	// LabelCertCN is the subject common name.
	LabelCertCN = "cert_cn"
	// LabelCertSHA256 is the hex SHA-256 of the leaf certificate (DER).
	LabelCertSHA256 = "cert_sha256"
	// LabelCertIssuerCN is the issuer's common name.
	LabelCertIssuerCN = "cert_issuer_cn"
)

// Reasons a client certificate is refused, as audited. The caller is only
// told the certificate was refused.
const (
	RefusedCertDisabled          RefusalReason = "client certificate identity is not enabled"
	RefusedCertMalformed         RefusalReason = "malformed certificate"
	RefusedCertUntrusted         RefusalReason = "untrusted"
	RefusedCertExpired           RefusalReason = "expired"
	RefusedCertNotYetValid       RefusalReason = "not yet valid"
	RefusedCertUsage             RefusalReason = "not a client certificate"
	RefusedCertRevoked           RefusalReason = "revoked"
	RefusedCertRevocationUnknown RefusalReason = "revocation status unknown"
	RefusedCertCRLExpired        RefusalReason = "crl expired"
)

// maxChain bounds the chain a caller may present.
const maxChain = 8

// CertTrust is what a client certificate is checked against: trust anchors
// and, optionally, certificate revocation lists. Everything in it is public.
type CertTrust struct {
	// Roots are the trust anchors; no system roots are used.
	Roots *x509.CertPool
	// RootsPEM is the bundle Roots was parsed from, sent to the data plane.
	RootsPEM []byte
	// CRLs are the parsed revocation lists; CRLsDER their DER, for the data
	// plane. Empty means revocation is not checked.
	CRLs    []*x509.RevocationList
	CRLsDER [][]byte
}

// ParseCertTrust parses a PEM bundle of CA certificates and CRLs, each PEM
// or DER. It refuses a bundle without a certificate and a CRL that cannot
// be parsed, so a typo never turns revocation off.
func ParseCertTrust(caPEM []byte, crls [][]byte) (*CertTrust, error) {
	t := &CertTrust{Roots: x509.NewCertPool()}
	rest, n := caPEM, 0
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("trust anchor %d: %w", n+1, err)
		}
		if !c.IsCA {
			return nil, fmt.Errorf("trust anchor %d (%s) is not a CA certificate", n+1, c.Subject.CommonName)
		}
		t.Roots.AddCert(c)
		t.RootsPEM = append(t.RootsPEM, pem.EncodeToMemory(b)...)
		n++
	}
	if n == 0 {
		return nil, errors.New("no CA certificate in the trust anchor bundle")
	}
	for i, raw := range crls {
		ders := [][]byte{raw}
		if bytes.Contains(raw, []byte("-----BEGIN")) {
			ders = nil
			r := raw
			for {
				var b *pem.Block
				b, r = pem.Decode(r)
				if b == nil {
					break
				}
				if b.Type == "X509 CRL" {
					ders = append(ders, b.Bytes)
				}
			}
			if len(ders) == 0 {
				return nil, fmt.Errorf("CRL %d: no X509 CRL block", i+1)
			}
		}
		for _, der := range ders {
			l, err := x509.ParseRevocationList(der)
			if err != nil {
				return nil, fmt.Errorf("CRL %d: %w", i+1, err)
			}
			t.CRLs = append(t.CRLs, l)
			t.CRLsDER = append(t.CRLsDER, slices.Clone(der))
		}
	}
	return t, nil
}

// CertRule maps client certificates to one agent. A certificate matches
// when any of its patterns matches; patterns are [path.Match] globs, so `*`
// does not cross a `/`.
type CertRule struct {
	Agent  string
	SPIFFE []string
	CN     []string
	DNS    []string
	URI    []string
	Email  []string
	Scopes []Scope
	Labels map[string]string
}

// CertRulesFromMap turns identity.client-certificates.agents into rules.
// Each key is an agent name and each value a space-separated list of
// selectors: spiffe:<id>, cn:<name>, dns:<name>, uri:<uri>, email:<address>
// (globs allowed), scope:<scope> and label:<key>=<value>. For example
//
//	identity.client-certificates.agents:
//	  builder: "spiffe:spiffe://example.org/agents/builder"
//	  ci: "cn:ci-runner-* scope:secrets:list label:team=infra"
func CertRulesFromMap(m map[string]string) ([]CertRule, error) {
	names := slices.Sorted(maps.Keys(m))
	rules := make([]CertRule, 0, len(m))
	var errs []error
	for _, agent := range names {
		where := "identity.client-certificates.agents." + agent
		if !ValidAgentName(agent) {
			errs = append(errs, fmt.Errorf("%s: agent name must match %s", where, agentName))
			continue
		}
		r := CertRule{Agent: agent}
		matchers := 0
		for sel := range strings.FieldsSeq(m[agent]) {
			kind, val, ok := strings.Cut(sel, ":")
			if !ok || val == "" {
				errs = append(errs, fmt.Errorf("%s: selector %q is not kind:value", where, sel))
				continue
			}
			if _, err := path.Match(val, ""); err != nil && kind != "scope" && kind != "label" {
				errs = append(errs, fmt.Errorf("%s: pattern %q: %w", where, val, err))
				continue
			}
			switch kind {
			case "spiffe":
				if !strings.HasPrefix(val, "spiffe://") {
					errs = append(errs, fmt.Errorf("%s: spiffe %q does not start with spiffe://", where, val))
					continue
				}
				r.SPIFFE = append(r.SPIFFE, val)
			case "cn":
				r.CN = append(r.CN, val)
			case "dns":
				r.DNS = append(r.DNS, val)
			case "uri":
				r.URI = append(r.URI, val)
			case "email":
				r.Email = append(r.Email, val)
			case "scope":
				s := Scope(val)
				if !ValidScope(s) || s == ScopeSessionsMint {
					errs = append(errs, fmt.Errorf("%s: scope %q is not an agent scope", where, val))
					continue
				}
				r.Scopes = append(r.Scopes, s)
				continue
			case "label":
				k, v, ok := strings.Cut(val, "=")
				if !ok || k == "" {
					errs = append(errs, fmt.Errorf("%s: label %q is not key=value", where, val))
					continue
				}
				if isCertLabel(k) {
					errs = append(errs, fmt.Errorf("%s: label %q is set from the certificate and cannot be configured", where, k))
					continue
				}
				if r.Labels == nil {
					r.Labels = map[string]string{}
				}
				r.Labels[k] = v
				continue
			default:
				errs = append(errs, fmt.Errorf("%s: unknown selector kind %q", where, kind))
				continue
			}
			matchers++
		}
		if matchers == 0 {
			errs = append(errs, fmt.Errorf("%s: no spiffe:, cn:, dns:, uri: or email: selector", where))
		}
		rules = append(rules, r)
	}
	return rules, errors.Join(errs...)
}

func isCertLabel(k string) bool {
	switch k {
	case LabelSPIFFEID, LabelCertCN, LabelCertSHA256, LabelCertIssuerCN:
		return true
	}
	return false
}

func anyMatch(patterns []string, values ...string) bool {
	for _, p := range patterns {
		for _, v := range values {
			if ok, _ := path.Match(p, v); ok && v != "" {
				return true
			}
		}
	}
	return false
}

func (r CertRule) matches(c *x509.Certificate, spiffe string) bool {
	uris := make([]string, 0, len(c.URIs))
	for _, u := range c.URIs {
		uris = append(uris, u.String())
	}
	return anyMatch(r.SPIFFE, spiffe) || anyMatch(r.CN, c.Subject.CommonName) ||
		anyMatch(r.DNS, c.DNSNames...) || anyMatch(r.URI, uris...) || anyMatch(r.Email, c.EmailAddresses...)
}

// SPIFFEID returns the certificate's SPIFFE ID: its URI SAN with the
// spiffe scheme, when it has exactly one URI SAN (the X.509-SVID rule), else
// "".
func SPIFFEID(c *x509.Certificate) string {
	if len(c.URIs) != 1 || c.URIs[0].Scheme != "spiffe" || c.URIs[0].Host == "" {
		return ""
	}
	return c.URIs[0].String()
}

// CertResolver identifies callers by client certificates.
type CertResolver struct {
	// Trust returns the trust anchors and CRLs in force; nil refuses every
	// certificate.
	Trust func() *CertTrust
	Rules []CertRule
	// Unmapped is UnmappedUnknown (the default) or UnmappedDerive, which
	// names the agent after the SPIFFE ID without its scheme.
	Unmapped string
	Now      func() time.Time
}

// Resolve verifies a certificate chain, leaf first, DER, and returns the
// caller. A certificate that fails verification is a [RefusedError].
func (r *CertResolver) Resolve(chain [][]byte) (Identity, error) {
	if len(chain) == 0 || len(chain) > maxChain {
		return Unknown(Peer{}), &RefusedError{Reason: RefusedCertMalformed}
	}
	certs := make([]*x509.Certificate, 0, len(chain))
	for _, der := range chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return Unknown(Peer{}), &RefusedError{Reason: RefusedCertMalformed}
		}
		certs = append(certs, c)
	}
	return r.ResolveCertificates(certs)
}

// ResolveCertificates is [CertResolver.Resolve] for parsed certificates, as
// crypto/tls reports them (tls.ConnectionState.PeerCertificates).
func (r *CertResolver) ResolveCertificates(certs []*x509.Certificate) (Identity, error) {
	if r == nil || r.Trust == nil {
		return Unknown(Peer{}), &RefusedError{Reason: RefusedCertDisabled}
	}
	if len(certs) == 0 || len(certs) > maxChain {
		return Unknown(Peer{}), &RefusedError{Reason: RefusedCertMalformed}
	}
	t := r.Trust()
	if t == nil || t.Roots == nil {
		return Unknown(Peer{}), &RefusedError{Reason: RefusedCertUntrusted}
	}
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	leaf := certs[0]
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: t.Roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return Unknown(Peer{}), &RefusedError{Reason: verifyReason(err, leaf, now)}
	}
	if why := checkRevocation(t, leaf, chains, now); why != "" {
		return Unknown(Peer{}), &RefusedError{Reason: why}
	}
	return r.identityOf(leaf), nil
}

func verifyReason(err error, leaf *x509.Certificate, now time.Time) RefusalReason {
	var inv x509.CertificateInvalidError
	if errors.As(err, &inv) {
		switch inv.Reason {
		case x509.Expired:
			if now.Before(leaf.NotBefore) {
				return RefusedCertNotYetValid
			}
			return RefusedCertExpired
		case x509.IncompatibleUsage:
			return RefusedCertUsage
		default:
		}
	}
	return RefusedCertUntrusted
}

// checkRevocation applies the CRLs: with none configured revocation is not
// checked (short-lived certificates). Otherwise the leaf's issuer must have a
// CRL it signed, that CRL must be current, and it must not list the leaf.
// Only the end entity is checked, as the data plane does.
func checkRevocation(t *CertTrust, leaf *x509.Certificate, chains [][]*x509.Certificate, now time.Time) RefusalReason {
	if len(t.CRLs) == 0 {
		return ""
	}
	var issuers []*x509.Certificate
	for _, ch := range chains {
		if len(ch) > 1 {
			issuers = append(issuers, ch[1])
		}
	}
	var crl *x509.RevocationList
	for _, l := range t.CRLs {
		if !bytes.Equal(l.RawIssuer, leaf.RawIssuer) {
			continue
		}
		for _, is := range issuers {
			if l.CheckSignatureFrom(is) == nil {
				crl = l
				break
			}
		}
		if crl != nil {
			break
		}
	}
	if crl == nil {
		return RefusedCertRevocationUnknown
	}
	if !crl.NextUpdate.IsZero() && now.After(crl.NextUpdate) {
		return RefusedCertCRLExpired
	}
	for _, e := range crl.RevokedCertificateEntries {
		if e.SerialNumber != nil && e.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
			return RefusedCertRevoked
		}
	}
	return ""
}

func (r *CertResolver) identityOf(leaf *x509.Certificate) Identity {
	spiffe := SPIFFEID(leaf)
	labels := map[string]string{}
	agent, scopes := "", AgentScopes
	for _, rule := range r.Rules {
		if rule.matches(leaf, spiffe) {
			agent = rule.Agent
			if len(rule.Scopes) > 0 {
				scopes = rule.Scopes
			}
			maps.Copy(labels, rule.Labels)
			break
		}
	}
	if agent == "" {
		if r.Unmapped != UnmappedDerive || spiffe == "" {
			return Unknown(Peer{})
		}
		agent = strings.TrimPrefix(spiffe, "spiffe://")
	}
	sum := sha256.Sum256(leaf.Raw)
	labels[LabelCertSHA256] = hex.EncodeToString(sum[:])
	if spiffe != "" {
		labels[LabelSPIFFEID] = spiffe
	}
	if cn := leaf.Subject.CommonName; cn != "" {
		labels[LabelCertCN] = cn
	}
	if cn := leaf.Issuer.CommonName; cn != "" {
		labels[LabelCertIssuerCN] = cn
	}
	return Identity{Agent: agent, Source: SourceCertificate, ExpiresAt: leaf.NotAfter,
		Scopes: slices.Clone(scopes), Labels: labels}
}

// CertTrustSource holds the trust in force and reloads it: the trust anchor
// bundle from its reference and the CRL files, read again on every Reload.
type CertTrustSource struct {
	// ReadCA returns the trust anchor bundle (PEM).
	ReadCA func() ([]byte, error)
	// ReadCRLs returns the revocation lists, each PEM or DER.
	ReadCRLs func() ([][]byte, error)

	cur atomic.Pointer[CertTrust]
}

// Current is the trust in force, nil before the first successful Reload.
func (s *CertTrustSource) Current() *CertTrust {
	if s == nil {
		return nil
	}
	return s.cur.Load()
}

// Reload reads the bundle and the CRLs again. It reports whether the trust
// changed. On an error the trust in force is kept: a CRL that cannot be read
// again still expires at its next update, which then refuses certificates.
func (s *CertTrustSource) Reload() (bool, error) {
	ca, err := s.ReadCA()
	if err != nil {
		return false, fmt.Errorf("reading the trust anchors: %w", err)
	}
	var crls [][]byte
	if s.ReadCRLs != nil {
		if crls, err = s.ReadCRLs(); err != nil {
			return false, fmt.Errorf("reading the CRLs: %w", err)
		}
	}
	t, err := ParseCertTrust(ca, crls)
	if err != nil {
		return false, err
	}
	old := s.cur.Load()
	if old != nil && bytes.Equal(old.RootsPEM, t.RootsPEM) && slices.EqualFunc(old.CRLsDER, t.CRLsDER, bytes.Equal) {
		return false, nil
	}
	s.cur.Store(t)
	return true, nil
}
