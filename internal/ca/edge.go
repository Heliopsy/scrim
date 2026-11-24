// SPDX-License-Identifier: AGPL-3.0-only

package ca

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/config"
)

// EdgeCommonName is the start of every generated edge CA's common name.
const EdgeCommonName = "scrim edge CA"

// profile is what differs between the CAs a [Manager] holds: the
// interception CA and the edge CA.
type profile struct {
	// what names the CA in logs and errors.
	what       string
	commonName string
	// dirName is the default directory under $XDG_STATE_HOME/scrim.
	dirName  string
	dir      config.Key[string]
	certFile config.Key[string]
	key      config.Key[config.SecretRef]
	// names, for the edge CA, are the names it is constrained to. Nil for
	// the interception CA, which signs for any host.
	names []string
	// trustFiles: rotations rewrite the bundle files `scrim ca install`
	// recorded.
	trustFiles bool
	// rotated and expired finish the log lines of a rotation and of an
	// expired operator-supplied CA.
	rotated, expired string
}

var interceptionProfile = profile{
	what:       "interception CA",
	commonName: CommonName,
	dirName:    "ca",
	dir:        DirSetting,
	certFile:   CertFileSetting,
	key:        KeySetting,
	trustFiles: true,
	rotated: "clients must trust the new CA before the overlap ends " +
		"(run `scrim ca install --user` again, or export the bundle with `scrim ca export`)",
	expired: "clients will refuse the tool proxy until it is replaced",
}

var edgeProfile = profile{
	what:       "edge CA",
	commonName: EdgeCommonName,
	dirName:    "edge-ca",
	dir:        EdgeDirSetting,
	certFile:   EdgeCertFileSetting,
	key:        EdgeKeySetting,
	rotated: "edge forwarders must trust the new edge CA before the overlap ends " +
		"(give them the bundle from `scrim ca export --edge`)",
	expired: "edge forwarders will refuse the edge listener until it is replaced",
}

// OpenEdge loads the edge CA: the CA that issues only the edge listener's
// certificate, kept apart from the interception CA so that the key which
// signs certificates for intercepted hosts cannot authenticate scrim to the
// edge forwarders. names are edge.server-names.
//
// A generated edge CA lives in edge.ca.dir, rotates like the interception
// CA, and is name-constrained to exactly names (and the names below them):
// when names change it is rotated at once. An operator-supplied one
// (edge.ca.cert-file, edge.ca.key) is used as given, after checking that a
// certificate for names chains to it.
func OpenEdge(_ context.Context, cfg *config.Config, log *slog.Logger, names []string, o Options) (*Manager, error) {
	if len(names) == 0 {
		return nil, errors.New("ca: the edge CA needs the names it issues for (edge.server-names)")
	}
	prof := edgeProfile
	prof.names = slices.Clone(names)
	m, err := open(cfg, log, o, &prof)
	if err != nil {
		return nil, err
	}
	if m.dir != "" && m.dir == interceptionDir(cfg, o) {
		m.Close()
		return nil, fmt.Errorf("ca: %s is the interception CA's directory; the edge CA needs its own", EdgeDirSetting.Name())
	}
	return m, nil
}

// interceptionDir is the interception CA's directory as [Open] would pick
// it, or "" when it is operator-supplied or cannot be known.
func interceptionDir(cfg *config.Config, o Options) string {
	if CertFileSetting.Get(cfg) != "" {
		return ""
	}
	if d := DirSetting.Get(cfg); d != "" {
		return d
	}
	d, err := DefaultDir(o.Getenv)
	if err != nil {
		return ""
	}
	return d
}

// constrain adds name constraints for exactly names to a CA template: DNS
// names (each permits itself and the names below it) and IP addresses
// (each a single address). A kind of name the list has none of is
// excluded outright, so the CA can sign for nothing else.
func constrain(tmpl *x509.Certificate, names []string) {
	tmpl.PermittedDNSDomainsCritical = true
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.PermittedIPRanges = append(tmpl.PermittedIPRanges, hostRange(ip))
			continue
		}
		tmpl.PermittedDNSDomains = append(tmpl.PermittedDNSDomains, strings.ToLower(n))
	}
	if len(tmpl.PermittedIPRanges) == 0 {
		tmpl.ExcludedIPRanges = []*net.IPNet{
			{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
			{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		}
	}
	if len(tmpl.PermittedDNSDomains) == 0 {
		// An empty constraint matches every DNS name.
		tmpl.ExcludedDNSDomains = []string{""}
	}
}

func hostRange(ip net.IP) *net.IPNet {
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip.To16(), Mask: net.CIDRMask(128, 128)}
}

// constrainedTo reports whether c carries exactly the constraints
// [constrain] would give it for names.
func constrainedTo(c *x509.Certificate, names []string) bool {
	var want x509.Certificate
	constrain(&want, names)
	ipStrings := func(r []*net.IPNet) []string {
		out := make([]string, 0, len(r))
		for _, n := range r {
			out = append(out, n.String())
		}
		slices.Sort(out)
		return out
	}
	sorted := func(s []string) []string {
		s = slices.Clone(s)
		slices.Sort(s)
		return s
	}
	return c.PermittedDNSDomainsCritical &&
		slices.Equal(sorted(c.PermittedDNSDomains), sorted(want.PermittedDNSDomains)) &&
		slices.Equal(sorted(c.ExcludedDNSDomains), sorted(want.ExcludedDNSDomains)) &&
		slices.Equal(ipStrings(c.PermittedIPRanges), ipStrings(want.PermittedIPRanges)) &&
		slices.Equal(ipStrings(c.ExcludedIPRanges), ipStrings(want.ExcludedIPRanges))
}

// checkOperatorNames checks that an operator-supplied edge CA can issue the
// listener's certificate: a trial certificate for the configured names must
// verify against it alone, its name constraints, key usage and path length
// included.
func (m *Manager) checkOperatorNames(g *generation) error {
	now := m.now()
	leaf, err := IssueServer(g.certPEM, g.key, m.prof.names, now, time.Hour)
	if err != nil {
		return fmt.Errorf("ca: %s: %w", m.prof.certFile.Name(), err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(g.cert)
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return fmt.Errorf("ca: the edge CA in %s cannot issue a certificate for %s (%s): %w",
			m.certFile, strings.Join(m.prof.names, ", "), m.prof.certFile.Name(), err)
	}
	if !hasNameConstraints(g.cert) {
		m.log.Info("the operator-supplied edge CA has no name constraints; it is trusted only by edge forwarders, "+
			"but a CA constrained to the edge names limits what its key can sign anywhere else", "cert_file", m.certFile)
	}
	return nil
}

// parseAll parses every PEM certificate in s, skipping what does not parse.
func parseAll(s string) []*x509.Certificate {
	var out []*x509.Certificate
	rest := []byte(s)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			out = append(out, c)
		}
	}
}

func hasNameConstraints(c *x509.Certificate) bool {
	return len(c.PermittedDNSDomains)+len(c.ExcludedDNSDomains)+len(c.PermittedIPRanges)+len(c.ExcludedIPRanges)+
		len(c.PermittedEmailAddresses)+len(c.ExcludedEmailAddresses)+len(c.PermittedURIDomains)+len(c.ExcludedURIDomains) > 0
}

// SharesKey reports whether any certificate in a shares a public key with
// any certificate in b, all PEM. The edge CA must never have the
// interception CA's key.
func SharesKey(a, b []string) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	keys := func(pems []string) []crypto.PublicKey {
		var out []crypto.PublicKey
		for _, p := range pems {
			for _, c := range parseAll(p) {
				out = append(out, c.PublicKey)
			}
		}
		return out
	}
	kb := keys(b)
	for _, ka := range keys(a) {
		e, ok := ka.(equaler)
		if !ok {
			continue
		}
		for _, k := range kb {
			if e.Equal(k) {
				return true
			}
		}
	}
	return false
}
