// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"fmt"
	"time"

	"github.com/heliopsy/scrim/internal/agentapi"
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

// clientCertificatesPB is the snapshot's trust for the TLS listeners, nil
// before the trust was loaded.
func clientCertificatesPB(t *identity.CertTrust, names []string) *pb.ClientCertificateTrust {
	if t == nil {
		return nil
	}
	return &pb.ClientCertificateTrust{TrustAnchorsPem: string(t.RootsPEM), CrlsDer: t.CRLsDER, ServerNames: names}
}

// watchCertTrust reads the trust anchors and CRLs again every period and
// pushes a snapshot when they changed, so the data plane checks new
// connections against the new lists. A read that fails keeps the trust in
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
	}
}
