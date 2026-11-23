// SPDX-License-Identifier: AGPL-3.0-only

package grant

import (
	"context"
	"errors"
	"time"

	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/stores"
)

// LeaseHolderPrefix starts the lease holder ID of a grant.
const LeaseHolderPrefix = "grant:"

// LeaseHolder is the holder of dynamic secrets issued under grant id
// (specs/secret-stores "HashiCorp Vault adapter"): active while the grant
// is usable, until its expiry. A revoked, expired, used-up or deleted
// grant, and deny-all, end it, and the store revokes the leases. Like
// every grant check it reads the state backend, so a revocation on any
// replica ends the leases held on every replica at its next check.
func (s *Service) LeaseHolder(id string) stores.LeaseHolder {
	return stores.LeaseHolder{
		ID: LeaseHolderPrefix + id,
		Active: func(ctx context.Context) (time.Time, bool, error) {
			if s.bg != nil && s.bg.Active() {
				return time.Time{}, false, nil
			}
			var g *state.Grant
			err := s.st.View(ctx, func(tx state.Tx) error {
				var err error
				g, err = tx.GetGrant(ctx, id)
				return err
			})
			if errors.Is(err, state.ErrNotFound) {
				return time.Time{}, false, nil
			}
			if err != nil {
				return time.Time{}, false, err
			}
			return g.ExpiresAt, g.Usable(s.now()), nil
		},
	}
}
