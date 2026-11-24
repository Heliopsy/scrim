// SPDX-License-Identifier: AGPL-3.0-only

package app

import (
	"fmt"
	"log/slog"

	"github.com/heliopsy/scrim/internal/config"
	"github.com/heliopsy/scrim/internal/netproxy"
)

// installProxy makes cfg's upstream proxy the one the control plane's HTTP
// clients use (netproxy.Func) and logs it, without credentials. The data
// plane gets the same proxy in its snapshot.
func (a *App) installProxy(cfg *config.Config) error {
	p, err := netproxy.Resolve(cfg)
	if err != nil {
		return err
	}
	if a.uninstallProxy != nil {
		a.uninstallProxy()
	}
	a.uninstallProxy = netproxy.Install(p)
	desc := fmt.Sprint(p.String(), p.Source, p.HasCredentials(), p.NoProxy, p.Skipped)
	if desc != a.proxyDesc {
		a.proxyDesc = desc
		logProxy(a.Log, p)
	}
	return nil
}

func logProxy(log *slog.Logger, p *netproxy.Proxy) {
	if !p.Enabled() {
		return
	}
	log.Info("outbound connections go through the upstream proxy", "proxy", p.String(), "source", p.Source,
		"credentials", p.HasCredentials(), "no_proxy", p.NoProxy)
	for _, e := range p.Skipped {
		log.Warn("NO_PROXY entry from scrim's environment ignored: neither a host, an address nor a CIDR range; "+
			"connections it names go through the upstream proxy", "entry", e)
	}
}
