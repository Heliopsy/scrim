// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/heliopsy/scrim/internal/agentapi"
	"github.com/heliopsy/scrim/internal/ca"
	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/edge"
	"github.com/heliopsy/scrim/internal/obs"
	"github.com/heliopsy/scrim/internal/secret"
)

// startEdge binds edge.listen, the listener the forwarders in agent pods
// connect to (specs/credential-injection "Edge forwarder for local
// sockets"). Callers are identified by their Kubernetes service account
// token only, through the agent API's resolver, so policy, approvals and
// audit see them as on the proxy. The certificate is issued from the edge
// CA (edge.ca.*), which is never the interception CA: the key that signs
// certificates for intercepted hosts cannot impersonate scrim to the
// forwarders. With edge.legacy-interception-certificate, forwarders from
// before the edge CA get a certificate from the interception CA (caFn).
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
	m, err := ca.OpenEdge(ctx, cfg, obs.WithComponent(d.app.Log, "edge-ca"), names, ca.Options{})
	if err != nil {
		return fmt.Errorf("%s: %w", edge.ListenAddr.Name(), err)
	}
	d.cleanup = append(d.cleanup, m.Close)
	if caFn != nil && ca.SharesKey(certPEMs(m.Certificates()), interceptionPEMs(caFn)) {
		return fmt.Errorf("%s: the edge CA has the interception CA's key; give it its own (edge.ca.cert-file and edge.ca.key, or a generated one)",
			edge.ListenAddr.Name())
	}
	d.edgeTrust = m.TrustBundlePEM
	certs := &edge.Certs{Names: names, CA: currentCA(caGenerations(m))}
	if edge.LegacyInterceptionCertificate.Get(cfg) {
		if caFn == nil {
			return fmt.Errorf("%s needs the interception CA", edge.LegacyInterceptionCertificate.Name())
		}
		certs.Legacy = currentCA(caFn)
		if _, err := certs.LegacyCertificate(); err != nil {
			return fmt.Errorf("%s: issuing the legacy certificate: %w", edge.LegacyInterceptionCertificate.Name(), err)
		}
		d.log.Warn(edge.LegacyInterceptionCertificate.Name() + " is on: forwarders that do not announce the edge CA get a " +
			"certificate from the interception CA; turn it off once every agent pod runs the new forwarder")
	}
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
	// Rotations of a generated edge CA; the next handshake issues from the
	// new generation.
	d.goRun("edge CA", func() error { m.Run(ctx, nil); return nil })
	d.goRun("edge", func() error { return ignoreCanceled(srv.Serve(ctx, ln, edge.TLSConfig(certs.GetCertificate))) })
	d.log.Info("edge listener started", "listen", d.addrs.Edge, "names", names)
	return nil
}

// currentCA returns the current generation of the CA caFn supplies, with a
// key the caller wipes; the other generations' keys are wiped here.
func currentCA(caFn func() []CAGeneration) edge.CASource {
	return func() (string, secret.Value, error) {
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
	}
}

func certPEMs(cs []ca.Certificate) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.PEM
	}
	return out
}

func interceptionPEMs(caFn func() []CAGeneration) []string {
	gens := caFn()
	out := make([]string, len(gens))
	for i, g := range gens {
		out[i] = g.CertPEM
		g.Key.Wipe()
	}
	return out
}

// EdgeTrustBundlePEM returns the edge CA certificates the forwarders must
// trust (the current one and, during an overlap, the previous one), or ""
// without an edge listener. Public material.
func (d *Daemon) EdgeTrustBundlePEM() string {
	if d.edgeTrust == nil {
		return ""
	}
	return d.edgeTrust()
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
