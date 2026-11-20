// SPDX-License-Identifier: AGPL-3.0-only

package vaultwarden

import (
	"context"
	"errors"
	"strings"

	"github.com/heliopsy/scrim/internal/status"
	"github.com/heliopsy/scrim/internal/stores"
)

var _ status.CheckSource = (*Adapter)(nil)

// DoctorChecks implements status.CheckSource: whether the store unlocks, and
// the dedicated-account recommendation of design D6.
func (a *Adapter) DoctorChecks() []status.Check {
	name := "store " + a.name + " (vaultwarden)"
	return []status.Check{{
		Name: name,
		Run: func(ctx context.Context) []status.Finding {
			advice, err := a.Advice(ctx)
			if err != nil {
				fix := "check " + OptURL + " and that the server is reachable"
				switch {
				case errors.Is(err, stores.ErrLocked):
					fix = "make " + OptUnlock + " point at the account's master password, readable only by scrim"
				case errors.Is(err, stores.ErrPermission):
					fix = "check " + OptClientID + " and " + OptClientSecret + " (Settings > Security > Keys > API key)"
				}
				return []status.Finding{{Check: name, Outcome: status.Fail, Message: err.Error(), Fix: fix}}
			}
			var out []status.Finding
			for _, m := range advice {
				f := status.Finding{Check: name, Outcome: status.Warn, Message: m}
				if strings.Contains(m, "dedicated agent account") {
					f.Fix = "use a Vaultwarden account or organisation that holds only agent secrets, or set " + OptScope
				}
				out = append(out, f)
			}
			return out
		},
	}}
}
