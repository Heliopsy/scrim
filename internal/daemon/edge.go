// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/heliopsy/scrim/internal/agentapi"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/edge"
	"github.com/heliopsy/scrim/internal/obs"
	"github.com/heliopsy/scrim/internal/secret"
)

// startEdge binds edge.listen, the listener the forwarders in agent pods
// connect to (specs/credential-injection "Edge forwarder for local
// sockets"). Callers are identified by their Kubernetes service account
// token only, through the agent API's resolver, so policy, approvals and
// audit see them as on the proxy. The certificate is issued from scrim's
// CA, which the pods already trust.
func (d *Daemon) startEdge(ctx context.Context, cfg *config.Config, caFn func() []CAGeneration) error {
	addr := edge.ListenAddr.Get(cfg)
	if addr == "" {
		return nil
	}
	kr := d.runtime.Resolver.Kubernetes
	if kr == nil {
		return fmt.Errorf("%s needs identity.kubernetes.enabled: the edge listener identifies agent pods by their service account token",
			edge.ListenAddr.Name())
	}
	names := edge.ServerNames.Get(cfg)
	if len(names) == 0 {
		return fmt.Errorf("%s needs %s: the names forwarders reach scrim by, for its certificate",
			edge.ListenAddr.Name(), edge.ServerNames.Name())
	}
	if caFn == nil {
		return fmt.Errorf("%s needs scrim's CA to issue its certificate", edge.ListenAddr.Name())
	}
	certs := &edge.Certs{Names: names, CA: func() (string, secret.Value, error) {
		var (
			pem string
			key secret.Value
		)
		for _, g := range caFn() {
			if g.Current && pem == "" {
				pem, key = g.CertPEM, g.Key
				continue
			}
			g.Key.Wipe()
		}
		if pem == "" {
			return "", secret.Value{}, errors.New("no current CA generation")
		}
		return pem, key, nil
	}}
	// Issue once now, so a CA that cannot sign stops start-up instead of
	// every handshake.
	if _, err := certs.GetCertificate(nil); err != nil {
		return fmt.Errorf("%s: issuing the listener's certificate: %w", edge.ListenAddr.Name(), err)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("%s: %w", edge.ListenAddr.Name(), err)
	}
	srv := &edge.Server{
		Identify: kr.Resolve,
		API:      d.runtime.Handler(),
		SSH:      d.runtime.SSHAgent(),
		Database: d.edgeDatabase,
		Auditor:  agentapi.Audit{State: d.app.State},
		Log:      obs.WithComponent(d.app.Log, "edge"),
	}
	d.addrs.Edge = ln.Addr().String()
	d.goRun("edge", func() error { return ignoreCanceled(srv.Serve(ctx, ln, edge.TLSConfig(certs.GetCertificate))) })
	d.log.Info("edge listener started", "listen", d.addrs.Edge, "names", names)
	return nil
}

// edgeDatabase serves a tunnelled connection with the database's auth proxy;
// the proxy's authorizer reads the caller from the tunnel.
func (d *Daemon) edgeDatabase(name string) (func(context.Context, net.Conn), bool) {
	if d.dbs == nil {
		return nil, false
	}
	e := d.dbs.specs[name]
	if e == nil {
		return nil, false
	}
	return e.proxy.ServeConn, true
}
