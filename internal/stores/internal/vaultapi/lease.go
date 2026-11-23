// SPDX-License-Identifier: AGPL-3.0-only

package vaultapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/stores"
	"github.com/heliopsy/scrim/internal/stores/internal/wire"
)

// Lease operations on dynamic secrets (sys/leases). Lease IDs name the
// secrets engine path and a random suffix; they are not credentials (using
// one needs a token with the sys/leases capability), so they appear in
// errors and logs.

// RenewLease extends leaseID by increment (zero lets the store choose) and
// returns the lease the store granted and whether it can be renewed again.
func (c *Client) RenewLease(ctx context.Context, op stores.Op, ref stores.Ref, leaseID string, increment time.Duration) (ttl time.Duration, renewable bool, err error) {
	body := map[string]any{"lease_id": leaseID}
	if increment > 0 {
		body["increment"] = int64(increment / time.Second)
	}
	resp, err := c.leaseCall(ctx, op, ref, "sys/leases/renew", body)
	defer resp.Wipe()
	if err != nil {
		return 0, false, err
	}
	var lr struct {
		LeaseDuration int64 `json:"lease_duration"`
		Renewable     bool  `json:"renewable"`
	}
	if err := json.Unmarshal(resp.Body, &lr); err != nil {
		return 0, false, c.StoreErr(Request{Op: op, Ref: ref}, stores.ErrUnavailable, "lease renewal: malformed response", nil)
	}
	return time.Duration(lr.LeaseDuration) * time.Second, lr.Renewable, nil
}

// RevokeLease revokes leaseID at once. A lease the store no longer knows
// (expired or already revoked) counts as revoked.
func (c *Client) RevokeLease(ctx context.Context, op stores.Op, ref stores.Ref, leaseID string) error {
	resp, err := c.leaseCall(ctx, op, ref, "sys/leases/revoke", map[string]any{"lease_id": leaseID})
	resp.Wipe()
	return err
}

func (c *Client) leaseCall(ctx context.Context, op stores.Op, ref stores.Ref, path string, body map[string]any) (*Response, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, c.StoreErr(Request{Op: op, Ref: ref}, stores.ErrInvalidRef, "cannot encode the lease request", err)
	}
	resp, err := c.Do(ctx, Request{Op: op, Ref: ref, Method: http.MethodPut, Path: path, Body: wire.NewBody(b)})
	if err != nil {
		var se *stores.Error
		if errors.As(err, &se) {
			what := strings.TrimPrefix(path, "sys/leases/")
			se.Detail = strings.TrimSpace("lease " + what + " failed: " + se.Detail)
		}
	}
	return resp, err
}
