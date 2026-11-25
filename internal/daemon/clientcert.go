// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/agentapi"
	"github.com/heliopsy/scrim/internal/dataplane"
	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
	"github.com/heliopsy/scrim/internal/identity"
)

// checkTLSListeners refuses TLS listeners without client certificate
// identity: they exist to identify callers by their certificates.
func checkTLSListeners(ls []*pb.Listener, trust *identity.CertTrustSource) error {
	if trust != nil {
		return nil
	}
	for _, l := range ls {
		if l.GetTls() {
			return fmt.Errorf("listener %s (%s) needs %s", l.GetName(), l.GetAddress(), agentapi.CertEnabled.Name())
		}
	}
	return nil
}

// checkSnapshotTLS refuses a snapshot the data plane would reject over its
// TLS listeners and client certificate trust, so the error names the setting
// here instead of the data plane keeping the previous snapshot: tls only on
// listeners that serve HTTP to agents, a trust whenever a listener has tls,
// and a trust that has at least one anchor, one server name and CRLs that
// parse.
func checkSnapshotTLS(s *pb.Snapshot) error {
	anyTLS := false
	for _, l := range s.GetListeners() {
		if !l.GetTls() {
			continue
		}
		anyTLS = true
		switch l.GetKind() {
		case pb.ListenerKind_LISTENER_KIND_BASE_URL, pb.ListenerKind_LISTENER_KIND_FORWARD_PROXY,
			pb.ListenerKind_LISTENER_KIND_TOOL_PROXY:
		default:
			return fmt.Errorf("snapshot: listener %s: tls is only for base URL, forward proxy and tool proxy listeners", l.GetName())
		}
	}
	t := s.GetClientCertificates()
	if t == nil {
		if anyTLS {
			return fmt.Errorf("snapshot: a TLS listener needs %s", agentapi.CertEnabled.Name())
		}
		return nil
	}
	anchors := 0
	rest := []byte(t.GetTrustAnchorsPem())
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(b.Bytes); err != nil {
			return fmt.Errorf("snapshot: %s: trust anchor %d does not parse", agentapi.CertCA.Name(), anchors+1)
		}
		anchors++
	}
	if anchors == 0 {
		return fmt.Errorf("snapshot: %s has no trust anchors", agentapi.CertCA.Name())
	}
	if (t.GetListenerChainPem() == "") != (len(t.GetListenerKeyPem()) == 0) {
		return fmt.Errorf("snapshot: %s and %s go together", agentapi.CertListenerCertFile.Name(), agentapi.CertListenerKey.Name())
	}
	named := t.GetListenerChainPem() != ""
	for _, n := range t.GetServerNames() {
		if strings.TrimSuffix(strings.TrimSpace(n), ".") != "" {
			named = true
			break
		}
	}
	if !named {
		return fmt.Errorf("snapshot: %s is empty", agentapi.CertServerNames.Name())
	}
	for i, d := range t.GetCrlsDer() {
		if _, err := x509.ParseRevocationList(d); err != nil {
			return errors.Join(fmt.Errorf("snapshot: %s: CRL %d does not parse", agentapi.CertCRLFiles.Name(), i+1), err)
		}
	}
	return nil
}

// clientCertificatesPB is the snapshot's trust for the TLS listeners, nil
// before the trust was loaded, with the operator's listener certificate
// when lc is set.
func clientCertificatesPB(t *identity.CertTrust, names []string, lc *identity.ListenerCert) *pb.ClientCertificateTrust {
	if t == nil {
		return nil
	}
	out := &pb.ClientCertificateTrust{TrustAnchorsPem: string(t.RootsPEM), CrlsDer: t.CRLsDER, ServerNames: names}
	if lc != nil {
		var key []byte
		if err := lc.Key.Expose(func(b []byte) error { key = slices.Clone(b); return nil }); err == nil && len(key) > 0 {
			out.ListenerChainPem = string(lc.ChainPEM)
			out.ListenerKeyPem = key
		}
	}
	return out
}

// watchCertTrust reads the trust anchors and CRLs, and the operator's
// listener certificate, again every period and pushes a snapshot when they
// changed, so the data plane checks new connections against the new lists
// and presents the new certificate. A read that fails keeps the trust in
// force: a CRL that is not replaced still expires at its next update.
func (d *Daemon) watchCertTrust(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		changed, err := d.certTrust.Reload()
		switch {
		case err != nil:
			d.log.Warn("could not reload the client certificate trust anchors or CRLs; keeping the ones in force", "err", err)
		case changed:
			d.log.Info("client certificate trust anchors or CRLs changed")
			d.pusher.Trigger()
		}
		if d.listenerCert == nil {
			continue
		}
		changed, err = d.listenerCert.Reload()
		switch {
		case err != nil:
			d.log.Warn("could not reload the listener certificate; keeping the one in force", "err", err)
		case changed:
			c := d.listenerCert.Current()
			d.log.Info("listener certificate changed", "subject", c.Leaf.Subject.String(), "not_after", c.Leaf.NotAfter)
			d.pusher.Trigger()
		}
	}
}

// certificateCheck answers the data plane's certificate checks while OCSP
// is on: the chain is verified again and checked against the CRLs and OCSP,
// as for an ask.
func certificateCheck(r *identity.CertResolver, log *slog.Logger) dataplane.CertificateCheckFunc {
	return func(ctx context.Context, chain [][]byte) string {
		why := r.Check(ctx, chain)
		if why != "" {
			log.Debug("client certificate refused by the revocation check", "reason", string(why))
		}
		return string(why)
	}
}
