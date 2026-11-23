// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/obs"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/sshkeys"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/stores"
)

// sshKeyring is the control plane's side of scrim's ssh-agent: the
// catalog's ssh_key entries, read through the store refreshers, decided by
// the policy gate and audited in the state backend.
func (d *Daemon) sshKeyring() *sshkeys.Keyring {
	a := d.app
	pp := a.PolicyParts
	return &sshkeys.Keyring{
		Catalog: d.catalog.Current,
		Resolve: func(ctx context.Context, ref stores.Ref) (secret.Value, error) {
			r, err := d.refresherFor(ref)
			if err != nil {
				return secret.Value{}, err
			}
			return r.Resolve(ctx, ref)
		},
		Gate:       pp.Gate,
		Offer:      pp.Rules,
		DenyAll:    pp.BreakGlass.Active,
		Labels:     a.SecretLabels,
		KnownHosts: func() []string { return sshkeys.KnownHosts.Get(a.Config.Current()) },
		Record: func(ctx context.Context, e audit.Entry) error {
			return state.Apply(ctx, a.State, func(state.Tx) (state.Change, error) { return state.Change{Audit: e}, nil })
		},
		Log: obs.WithComponent(a.Log, "ssh-agent"),
	}
}
