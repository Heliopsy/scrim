// SPDX-License-Identifier: AGPL-3.0-only

package statetest

import (
	"fmt"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/stores"
)

// LeakTraffic writes every kind of state row through s, each with one of
// leaks smuggled into every free-text field (reasons, targets, hosts,
// paths, labels, attributes, decided-by, session names, scopes and end
// reasons), as a careless caller might. A leak test then dumps the backend
// and checks no leak survived, which holds only when the backend is built
// with a scrubber that knows them
// (specs/state-and-scaling "No secret value in any backend").
func LeakTraffic(t *testing.T, s state.Store, leaks []string) {
	t.Helper()
	ctx := t.Context()
	for i, v := range leaks {
		ag := policy.Agent{ID: fmt.Sprintf("agent-%d", i), Kind: policy.IdentitySession, Labels: map[string]string{"note": v}}
		ref := stores.MustParseRef("bao://kv/app#token")
		err := state.Apply(ctx, s, func(tx state.Tx) (state.Change, error) {
			a := &state.Approval{
				Request: policy.Request{Agent: ag, Action: policy.ActionInject, Ref: ref, Host: "api." + v, Path: "/x/" + v,
					Tool: v, Command: v, Name: v},
				Rule: "r", Reason: "agent pasted " + v, CreatedAt: t0, ExpiresAt: t0.Add(time.Minute),
			}
			if err := tx.CreateApproval(ctx, a); err != nil {
				return state.Change{}, err
			}
			if err := tx.DecideApproval(ctx, a.ID, state.ApprovalApproved, "op "+v, t0); err != nil {
				return state.Change{}, err
			}
			g := &state.Grant{Agent: ag, Ref: ref, Scope: state.Scope{Hosts: []string{v}, Tools: []string{v}},
				ApprovalID: a.ID, Rule: "r", CreatedAt: t0, ExpiresAt: t0.Add(time.Hour)}
			if err := tx.CreateGrant(ctx, g); err != nil {
				return state.Change{}, err
			}
			if err := tx.RevokeGrant(ctx, g.ID, "op "+v, t0); err != nil {
				return state.Change{}, err
			}
			sess := &state.Session{Agent: ag, Name: "run " + v, TokenHash: fmt.Sprintf("sha256:%d", i),
				Scopes: []string{v}, CreatedAt: t0, Labels: map[string]string{"cwd": "/home/" + v}}
			if err := tx.CreateSession(ctx, sess); err != nil {
				return state.Change{}, err
			}
			if err := tx.EndSession(ctx, sess.ID, t0, "killed by "+v); err != nil {
				return state.Change{}, err
			}
			return state.Change{
				Audit: audit.Entry{Action: "store.write", Actor: "op " + v, Agent: ag, Ref: ref, Effect: policy.Allow,
					Outcome: audit.OutcomeOK, Target: v, Subject: g.ID, RequestID: v, Reason: "echo " + v,
					Attrs: map[string]string{"upstream_error": "bad key " + v}, Time: t0},
				Events: []state.Event{{Kind: "grant.revoked", Subject: v, Time: t0}},
			}, nil
		})
		if err != nil {
			t.Fatalf("leak traffic %d: %v", i, err)
		}
	}
}
