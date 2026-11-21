// SPDX-License-Identifier: AGPL-3.0-only

// Package statetest is the contract suite every state backend passes:
//
//	func TestContract(t *testing.T) {
//		statetest.Run(t, func(t *testing.T) state.Store { return openTestDB(t) })
//	}
//
// Each case gets a fresh, migrated store from the factory.
package statetest

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/stores"
)

// Factory returns a fresh, empty store. The suite migrates and closes it.
type Factory func(t *testing.T) state.Store

// Run runs every case as a subtest.
func Run(t *testing.T, f Factory) {
	t.Helper()
	cases := []struct {
		name string
		run  func(t *testing.T, s state.Store)
	}{
		{"ApprovalLifecycle", approvalLifecycle},
		{"GrantUseAndRevoke", grantUseAndRevoke},
		{"Sessions", sessions},
		{"SessionsByAgent", sessionsByAgent},
		{"ApplyIsAtomic", applyIsAtomic},
		{"ApplyNeedsAudit", applyNeedsAudit},
		{"AuditQuery", auditQuery},
		{"EventsInOrder", eventsInOrder},
		{"LastEventID", lastEventID},
		{"EventCommitHook", eventCommitHook},
		{"AuditTap", auditTap},
		{"ViewIsReadOnly", viewIsReadOnly},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := f(t)
			t.Cleanup(func() { _ = s.Close() })
			if err := s.Migrate(t.Context()); err != nil {
				t.Fatalf("Migrate: %v", err)
			}
			if err := s.Health(t.Context()); err != nil {
				t.Fatalf("Health: %v", err)
			}
			c.run(t, s)
		})
	}
}

var t0 = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func agent(id string) policy.Agent {
	return policy.Agent{ID: id, Kind: policy.IdentitySession, Labels: map[string]string{"profile": "test"}}
}

func update(t *testing.T, s state.Store, fn func(tx state.Tx) error) {
	t.Helper()
	if err := s.Update(t.Context(), fn); err != nil {
		t.Fatalf("Update: %v", err)
	}
}

func approvalLifecycle(t *testing.T, s state.Store) {
	ctx := t.Context()
	a := &state.Approval{
		Request:   policy.Request{Agent: agent("a1"), Action: policy.ActionInject, Ref: stores.MustParseRef("bao://kv/gh#token"), Host: "api.github.com"},
		Rule:      "gh-push",
		Reason:    "push to a protected branch",
		GrantTTL:  30 * time.Minute,
		CreatedAt: t0,
		ExpiresAt: t0.Add(2 * time.Minute),
	}
	update(t, s, func(tx state.Tx) error { return tx.CreateApproval(ctx, a) })
	if a.ID == "" {
		t.Fatal("CreateApproval did not assign an ID")
	}
	err := s.View(ctx, func(tx state.Tx) error {
		got, err := tx.GetApproval(ctx, a.ID)
		if err != nil {
			return err
		}
		if got.Status != state.ApprovalPending || got.Request.Ref != a.Request.Ref || got.Request.Agent.Labels["profile"] != "test" || !got.ExpiresAt.Equal(a.ExpiresAt) {
			t.Errorf("stored approval differs: %+v", got)
		}
		list, err := tx.ListApprovals(ctx, state.ApprovalFilter{Status: state.ApprovalPending, AgentID: "a1"})
		if err != nil || len(list) != 1 {
			t.Errorf("ListApprovals = %v, %v", list, err)
		}
		_, err = tx.GetApproval(ctx, "missing")
		if !errors.Is(err, state.ErrNotFound) {
			t.Errorf("GetApproval missing: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	update(t, s, func(tx state.Tx) error {
		return tx.DecideApproval(ctx, a.ID, state.ApprovalApproved, "operator", t0.Add(time.Minute))
	})
	err = s.Update(ctx, func(tx state.Tx) error {
		return tx.DecideApproval(ctx, a.ID, state.ApprovalDenied, "operator", t0.Add(time.Minute))
	})
	if !errors.Is(err, state.ErrConflict) {
		t.Fatalf("deciding twice: %v, want ErrConflict", err)
	}
	_ = s.View(ctx, func(tx state.Tx) error {
		got, _ := tx.GetApproval(ctx, a.ID)
		if got.Status != state.ApprovalApproved || got.DecidedBy != "operator" {
			t.Errorf("decision not kept: %+v", got)
		}
		return nil
	})
}

func grantUseAndRevoke(t *testing.T, s state.Store) {
	ctx := t.Context()
	ref := stores.MustParseRef("bao://kv/gh#token")
	g := &state.Grant{Agent: agent("a1"), Ref: ref, Scope: state.Scope{Hosts: []string{"api.github.com"}}, MaxUses: 2, CreatedAt: t0, ExpiresAt: t0.Add(time.Hour)}
	other := &state.Grant{Agent: agent("a2"), Ref: ref, CreatedAt: t0, ExpiresAt: t0.Add(time.Minute)}
	update(t, s, func(tx state.Tx) error {
		if err := tx.CreateGrant(ctx, g); err != nil {
			return err
		}
		return tx.CreateGrant(ctx, other)
	})
	for i := range 2 {
		update(t, s, func(tx state.Tx) error {
			got, err := tx.UseGrant(ctx, g.ID, t0.Add(time.Minute))
			if err == nil && got.Uses != i+1 {
				t.Errorf("Uses = %d after %d uses", got.Uses, i+1)
			}
			return err
		})
	}
	err := s.Update(ctx, func(tx state.Tx) error { _, err := tx.UseGrant(ctx, g.ID, t0.Add(time.Minute)); return err })
	if !errors.Is(err, state.ErrGrantUnusable) {
		t.Fatalf("third use of a two-use grant: %v", err)
	}
	err = s.Update(ctx, func(tx state.Tx) error { _, err := tx.UseGrant(ctx, other.ID, t0.Add(2*time.Minute)); return err })
	if !errors.Is(err, state.ErrGrantUnusable) {
		t.Fatalf("use after expiry: %v", err)
	}
	_ = s.View(ctx, func(tx state.Tx) error {
		list, _ := tx.ListGrants(ctx, state.GrantFilter{Ref: ref, UsableAt: t0.Add(30 * time.Second)})
		if len(list) != 1 || list[0].ID != other.ID {
			t.Errorf("usable grants = %+v", list)
		}
		list, _ = tx.ListGrants(ctx, state.GrantFilter{AgentID: "a1"})
		if len(list) != 1 || list[0].Scope.Hosts[0] != "api.github.com" {
			t.Errorf("grants of a1 = %+v", list)
		}
		return nil
	})
	update(t, s, func(tx state.Tx) error { return tx.RevokeGrant(ctx, other.ID, "operator", t0.Add(time.Second)) })
	err = s.Update(ctx, func(tx state.Tx) error { _, err := tx.UseGrant(ctx, other.ID, t0.Add(2*time.Second)); return err })
	if !errors.Is(err, state.ErrGrantUnusable) {
		t.Fatalf("use after revoke: %v", err)
	}
	err = s.Update(ctx, func(tx state.Tx) error { return tx.RevokeGrant(ctx, other.ID, "operator", t0) })
	if !errors.Is(err, state.ErrConflict) {
		t.Fatalf("revoking twice: %v", err)
	}
}

func sessions(t *testing.T, s state.Store) {
	ctx := t.Context()
	sess := &state.Session{Agent: agent("a1"), Name: "claude", TokenHash: "sha256:abc", UID: 1000,
		RootPID: 4242, RootPPID: 41, RootStart: 1<<62 + 7, Scopes: []string{"secrets:list", "secrets:request"},
		CreatedAt: t0, ExpiresAt: t0.Add(time.Hour), Labels: map[string]string{"cwd": "/w"}}
	update(t, s, func(tx state.Tx) error { return tx.CreateSession(ctx, sess) })
	err := s.Update(ctx, func(tx state.Tx) error {
		return tx.CreateSession(ctx, &state.Session{Agent: agent("a2"), TokenHash: "sha256:abc", CreatedAt: t0})
	})
	if !errors.Is(err, state.ErrConflict) {
		t.Fatalf("duplicate token hash: %v", err)
	}
	err = s.Update(ctx, func(tx state.Tx) error {
		return tx.CreateSession(ctx, &state.Session{ID: sess.ID, Agent: agent("a2"), CreatedAt: t0})
	})
	if !errors.Is(err, state.ErrConflict) {
		t.Fatalf("duplicate session ID: %v", err)
	}
	_ = s.View(ctx, func(tx state.Tx) error {
		got, err := tx.SessionByTokenHash(ctx, "sha256:abc")
		if err != nil || got.ID != sess.ID || got.Agent.ID != "a1" {
			t.Errorf("SessionByTokenHash = %+v, %v", got, err)
		}
		if _, err := tx.SessionByTokenHash(ctx, "sha256:nope"); !errors.Is(err, state.ErrNotFound) {
			t.Errorf("unknown hash: %v", err)
		}
		got, err = tx.GetSession(ctx, sess.ID)
		if err != nil || got.Name != "claude" || got.UID != 1000 || got.RootPID != 4242 || got.RootPPID != 41 || got.RootStart != 1<<62+7 ||
			len(got.Scopes) != 2 || got.Scopes[1] != "secrets:request" || got.Labels["cwd"] != "/w" ||
			!got.CreatedAt.Equal(t0) || !got.ExpiresAt.Equal(t0.Add(time.Hour)) || !got.EndedAt.IsZero() || got.EndReason != "" {
			t.Errorf("stored session differs: %+v, %v", got, err)
		}
		if _, err := tx.GetSession(ctx, "missing"); !errors.Is(err, state.ErrNotFound) {
			t.Errorf("GetSession missing: %v", err)
		}
		return nil
	})
	update(t, s, func(tx state.Tx) error { return tx.EndSession(ctx, sess.ID, t0.Add(time.Minute), "ended") })
	_ = s.View(ctx, func(tx state.Tx) error {
		got, _ := tx.GetSession(ctx, sess.ID)
		if !got.EndedAt.Equal(t0.Add(time.Minute)) || got.EndReason != "ended" {
			t.Errorf("EndSession not kept: %+v", got)
		}
		return nil
	})
	err = s.Update(ctx, func(tx state.Tx) error { return tx.EndSession(ctx, sess.ID, t0.Add(2*time.Minute), "operator") })
	if !errors.Is(err, state.ErrConflict) {
		t.Fatalf("ending twice: %v", err)
	}
	err = s.Update(ctx, func(tx state.Tx) error { return tx.EndSession(ctx, "missing", t0, "operator") })
	if !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("ending a missing session: %v", err)
	}
	_ = s.View(ctx, func(tx state.Tx) error {
		got, _ := tx.GetSession(ctx, sess.ID)
		if got.EndReason != "ended" || !got.EndedAt.Equal(t0.Add(time.Minute)) {
			t.Errorf("second end overwrote the first: %+v", got)
		}
		return nil
	})
}

func sessionsByAgent(t *testing.T, s state.Store) {
	ctx := t.Context()
	// Created out of order, so listing has to sort.
	mk := []struct {
		id, agent string
		at        time.Duration
	}{{"s3", "a1", 3}, {"s1", "a1", 1}, {"s2", "a2", 2}, {"s4", "a1", 4}}
	update(t, s, func(tx state.Tx) error {
		for _, m := range mk {
			if err := tx.CreateSession(ctx, &state.Session{ID: m.id, Agent: agent(m.agent), TokenHash: "h" + m.id,
				CreatedAt: t0.Add(m.at * time.Second), ExpiresAt: t0.Add(time.Hour)}); err != nil {
				return err
			}
		}
		return tx.EndSession(ctx, "s4", t0.Add(time.Minute), "ended")
	})
	ids := func(ss []state.Session) []string {
		out := make([]string, len(ss))
		for i, x := range ss {
			out[i] = x.ID
		}
		return out
	}
	list := func(f state.SessionFilter) []string {
		t.Helper()
		var out []string
		if err := s.View(ctx, func(tx state.Tx) error {
			ss, err := tx.ListSessions(ctx, f)
			out = ids(ss)
			return err
		}); err != nil {
			t.Fatalf("ListSessions(%+v): %v", f, err)
		}
		return out
	}
	eq := func(what string, got []string, want ...string) {
		t.Helper()
		if len(got) != len(want) {
			t.Errorf("%s = %v, want %v", what, got, want)
			return
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("%s = %v, want %v", what, got, want)
				return
			}
		}
	}
	eq("all", list(state.SessionFilter{}), "s1", "s2", "s3", "s4")
	eq("a1", list(state.SessionFilter{AgentID: "a1"}), "s1", "s3", "s4")
	eq("a1 open", list(state.SessionFilter{AgentID: "a1", Open: true}), "s1", "s3")
	eq("limit", list(state.SessionFilter{Limit: 2}), "s1", "s2")

	var ended []string
	update(t, s, func(tx state.Tx) error {
		var err error
		ended, err = tx.EndAgentSessions(ctx, "a1", t0.Add(2*time.Minute), "operator")
		return err
	})
	eq("ended", ended, "s1", "s3")
	eq("a1 open after", list(state.SessionFilter{AgentID: "a1", Open: true}))
	eq("a2 untouched", list(state.SessionFilter{AgentID: "a2", Open: true}), "s2")
	_ = s.View(ctx, func(tx state.Tx) error {
		for id, want := range map[string]string{"s1": "operator", "s3": "operator", "s4": "ended"} {
			got, err := tx.GetSession(ctx, id)
			if err != nil || got.EndReason != want {
				t.Errorf("%s ended for %q, want %q (%v)", id, got.EndReason, want, err)
			}
		}
		return nil
	})
	update(t, s, func(tx state.Tx) error {
		var err error
		ended, err = tx.EndAgentSessions(ctx, "a1", t0.Add(3*time.Minute), "operator")
		if err == nil && len(ended) != 0 {
			t.Errorf("ending again ended %v", ended)
		}
		if again, err := tx.EndAgentSessions(ctx, "", t0, "operator"); err != nil || len(again) != 0 {
			t.Errorf("empty agent ended %v, %v", again, err)
		}
		return err
	})
	eq("a2 still open", list(state.SessionFilter{Open: true}), "s2")

	// A rolled-back EndAgentSessions ends nothing.
	boom := errors.New("roll back")
	err := s.Update(ctx, func(tx state.Tx) error {
		if _, err := tx.EndAgentSessions(ctx, "a2", t0, "operator"); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	eq("a2 after rollback", list(state.SessionFilter{AgentID: "a2", Open: true}), "s2")
	err = s.View(ctx, func(tx state.Tx) error { _, err := tx.EndAgentSessions(ctx, "a2", t0, "operator"); return err })
	if err == nil {
		t.Fatal("EndAgentSessions inside View succeeded")
	}
}

func applyIsAtomic(t *testing.T, s state.Store) {
	ctx := t.Context()
	boom := errors.New("fail after writing")
	err := state.Apply(ctx, s, func(tx state.Tx) (state.Change, error) {
		if err := tx.CreateGrant(ctx, &state.Grant{ID: "g1", Agent: agent("a1"), CreatedAt: t0, ExpiresAt: t0.Add(time.Hour)}); err != nil {
			return state.Change{}, err
		}
		if err := tx.AppendAudit(ctx, &audit.Entry{Action: "early", Time: t0}); err != nil {
			return state.Change{}, err
		}
		if err := tx.Emit(ctx, &state.Event{Kind: "grant.created", Subject: "g1", Time: t0}); err != nil {
			return state.Change{}, err
		}
		return state.Change{}, boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Apply = %v", err)
	}
	assertEmpty(t, s, "g1")

	// A panic inside the transaction also rolls back.
	func() {
		defer func() { _ = recover() }()
		_ = state.Apply(ctx, s, func(tx state.Tx) (state.Change, error) {
			_ = tx.CreateGrant(ctx, &state.Grant{ID: "g1", Agent: agent("a1"), CreatedAt: t0, ExpiresAt: t0.Add(time.Hour)})
			panic("boom")
		})
	}()
	assertEmpty(t, s, "g1")

	err = state.Apply(ctx, s, func(tx state.Tx) (state.Change, error) {
		g := &state.Grant{ID: "g1", Agent: agent("a1"), CreatedAt: t0, ExpiresAt: t0.Add(time.Hour)}
		return state.Change{
			Audit:  audit.Entry{Action: "grant.created", Actor: "operator", Subject: g.ID, Time: t0},
			Events: []state.Event{{Kind: "grant.created", Subject: g.ID, Time: t0}},
		}, tx.CreateGrant(ctx, g)
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = s.View(ctx, func(tx state.Tx) error {
		if _, err := tx.GetGrant(ctx, "g1"); err != nil {
			t.Errorf("grant missing after Apply: %v", err)
		}
		entries, _ := tx.QueryAudit(ctx, state.AuditQuery{})
		events, _ := tx.EventsAfter(ctx, 0, 0)
		if len(entries) != 1 || entries[0].Subject != "g1" || entries[0].ID == 0 || len(events) != 1 || events[0].ID == 0 {
			t.Errorf("after Apply: audit %+v events %+v", entries, events)
		}
		return nil
	})
}

func assertEmpty(t *testing.T, s state.Store, grantID string) {
	t.Helper()
	_ = s.View(t.Context(), func(tx state.Tx) error {
		if _, err := tx.GetGrant(t.Context(), grantID); !errors.Is(err, state.ErrNotFound) {
			t.Errorf("rolled-back grant visible: %v", err)
		}
		entries, _ := tx.QueryAudit(t.Context(), state.AuditQuery{})
		events, _ := tx.EventsAfter(t.Context(), 0, 0)
		if len(entries) != 0 || len(events) != 0 {
			t.Errorf("rolled-back audit %v or events %v visible", entries, events)
		}
		return nil
	})
}

func applyNeedsAudit(t *testing.T, s state.Store) {
	err := state.Apply(t.Context(), s, func(tx state.Tx) (state.Change, error) {
		return state.Change{}, tx.CreateGrant(t.Context(), &state.Grant{ID: "g1", CreatedAt: t0, ExpiresAt: t0})
	})
	if !errors.Is(err, state.ErrNoAudit) {
		t.Fatalf("Apply without audit = %v", err)
	}
	assertEmpty(t, s, "g1")
}

func auditQuery(t *testing.T, s state.Store) {
	ctx := t.Context()
	ref := stores.MustParseRef("inf://proj/prod/DB")
	update(t, s, func(tx state.Tx) error {
		for i, e := range []audit.Entry{
			{Action: "decision", Agent: agent("a1"), Ref: ref, Effect: policy.Deny, Outcome: audit.OutcomeRefused, Time: t0},
			{Action: "decision", Agent: agent("a2"), Ref: ref, Effect: policy.Allow, Outcome: audit.OutcomeOK, Time: t0.Add(time.Minute)},
			{Action: "store.write", Agent: agent("a1"), Effect: policy.Allow, Outcome: audit.OutcomeOK, Time: t0.Add(2 * time.Minute),
				Target: "bao", Attrs: map[string]string{"method": "put"}},
		} {
			e.RequestID = string(rune('a' + i))
			if err := tx.AppendAudit(ctx, &e); err != nil {
				return err
			}
		}
		return nil
	})
	_ = s.View(ctx, func(tx state.Tx) error {
		check := func(q state.AuditQuery, want int) {
			t.Helper()
			got, err := tx.QueryAudit(ctx, q)
			if err != nil || len(got) != want {
				t.Errorf("QueryAudit(%+v) = %d entries (%v), want %d", q, len(got), err, want)
			}
		}
		check(state.AuditQuery{}, 3)
		check(state.AuditQuery{AgentID: "a1"}, 2)
		check(state.AuditQuery{Ref: ref}, 2)
		check(state.AuditQuery{Action: "decision", AgentID: "a2"}, 1)
		check(state.AuditQuery{Since: t0.Add(time.Minute)}, 2)
		check(state.AuditQuery{Until: t0.Add(time.Minute)}, 1)
		check(state.AuditQuery{Limit: 2}, 2)
		all, _ := tx.QueryAudit(ctx, state.AuditQuery{})
		check(state.AuditQuery{AfterID: all[0].ID}, 2)
		if all[0].Effect != policy.Deny || all[1].Effect != policy.Allow || all[0].Outcome != audit.OutcomeRefused {
			t.Errorf("effects or outcomes not kept: %+v", all)
		}
		if all[2].Target != "bao" || all[2].Attrs["method"] != "put" || all[2].RequestID != "c" || !all[2].Time.Equal(t0.Add(2*time.Minute)) {
			t.Errorf("entry fields not kept: %+v", all[2])
		}
		check(state.AuditQuery{Effect: "allow"}, 2)
		check(state.AuditQuery{Effect: "deny", AgentID: "a1"}, 1)
		check(state.AuditQuery{Outcome: audit.OutcomeOK}, 2)
		check(state.AuditQuery{BeforeID: all[2].ID}, 2)
		newest, _ := tx.QueryAudit(ctx, state.AuditQuery{Newest: true, Limit: 2})
		if len(newest) != 2 || newest[0].ID != all[2].ID || newest[1].ID != all[1].ID {
			t.Errorf("newest first with limit = %+v", newest)
		}
		// The spec scenario: one agent's asks in a time window, newest first.
		page, _ := tx.QueryAudit(ctx, state.AuditQuery{AgentID: "a1", Since: t0, Until: t0.Add(time.Hour), Newest: true})
		if len(page) != 2 || page[0].Action != "store.write" {
			t.Errorf("a1 in the window, newest first = %+v", page)
		}
		return nil
	})
}

func eventsInOrder(t *testing.T, s state.Store) {
	ctx := t.Context()
	update(t, s, func(tx state.Tx) error {
		for _, k := range []string{"a", "b", "c"} {
			if err := tx.Emit(ctx, &state.Event{Kind: k, Time: t0}); err != nil {
				return err
			}
		}
		return nil
	})
	_ = s.View(ctx, func(tx state.Tx) error {
		ev, _ := tx.EventsAfter(ctx, 0, 0)
		if len(ev) != 3 || ev[0].Kind != "a" || ev[2].Kind != "c" || ev[0].ID >= ev[1].ID {
			t.Errorf("events = %+v", ev)
			return nil
		}
		rest, _ := tx.EventsAfter(ctx, ev[0].ID, 1)
		if len(rest) != 1 || rest[0].Kind != "b" {
			t.Errorf("EventsAfter(first, 1) = %+v", rest)
		}
		return nil
	})
}

func lastEventID(t *testing.T, s state.Store) {
	ctx := t.Context()
	last := func() int64 {
		t.Helper()
		var id int64
		if err := s.View(ctx, func(tx state.Tx) error {
			var err error
			id, err = tx.LastEventID(ctx)
			return err
		}); err != nil {
			t.Fatalf("LastEventID: %v", err)
		}
		return id
	}
	if id := last(); id != 0 {
		t.Fatalf("LastEventID on an empty outbox = %d", id)
	}
	var ids []int64
	update(t, s, func(tx state.Tx) error {
		for _, k := range []string{"a", "b"} {
			e := &state.Event{Kind: k, Time: t0}
			if err := tx.Emit(ctx, e); err != nil {
				return err
			}
			ids = append(ids, e.ID)
		}
		return nil
	})
	if id := last(); id != ids[1] {
		t.Fatalf("LastEventID = %d, want %d", id, ids[1])
	}
	// A rolled-back event does not move it.
	_ = s.Update(ctx, func(tx state.Tx) error {
		_ = tx.Emit(ctx, &state.Event{Kind: "c", Time: t0})
		return errors.New("roll back")
	})
	if id := last(); id != ids[1] {
		t.Fatalf("LastEventID after a rollback = %d, want %d", id, ids[1])
	}
}

func eventCommitHook(t *testing.T, s state.Store) {
	ctx := t.Context()
	h, ok := s.(state.CommitHook)
	if !ok {
		t.Fatal("backend does not implement state.CommitHook")
	}
	var n atomic.Int32
	h.OnEventCommit(func() { n.Add(1) })
	// No event, a rolled-back event: no call.
	update(t, s, func(tx state.Tx) error {
		return tx.AppendAudit(ctx, &audit.Entry{Time: t0, Action: "x"})
	})
	_ = s.Update(ctx, func(tx state.Tx) error {
		_ = tx.Emit(ctx, &state.Event{Kind: "a", Time: t0})
		return errors.New("roll back")
	})
	if got := n.Load(); got != 0 {
		t.Fatalf("hook ran %d times without a committed event", got)
	}
	update(t, s, func(tx state.Tx) error {
		if err := tx.Emit(ctx, &state.Event{Kind: "a", Time: t0}); err != nil {
			return err
		}
		return tx.Emit(ctx, &state.Event{Kind: "b", Time: t0})
	})
	if got := n.Load(); got != 1 {
		t.Fatalf("hook ran %d times for one committed transaction", got)
	}
}

// auditTap: the tap sees each transaction's entries, with IDs, before the
// commit; its error rolls the change back; done reports the outcome; a
// transaction without audit entries does not call it.
func auditTap(t *testing.T, s state.Store) {
	ctx := t.Context()
	tp, ok := s.(state.AuditTap)
	if !ok {
		t.Fatal("backend does not implement state.AuditTap")
	}
	var (
		seen     [][]audit.Entry
		outcomes []bool
		refuse   error
	)
	tp.SetAuditTap(func(_ context.Context, es []audit.Entry) (func(bool), error) {
		seen = append(seen, es)
		if refuse != nil {
			return nil, refuse
		}
		return func(c bool) { outcomes = append(outcomes, c) }, nil
	})
	err := state.Apply(ctx, s, func(tx state.Tx) (state.Change, error) {
		return state.Change{Audit: audit.Entry{Time: t0, Action: "tap.one", Attrs: map[string]string{"k": "v"}}}, tx.CreateGrant(ctx, &state.Grant{ID: "tg1", CreatedAt: t0, ExpiresAt: t0.Add(time.Hour)})
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || len(seen[0]) != 1 || seen[0][0].Action != "tap.one" || seen[0][0].ID == 0 || seen[0][0].Attrs["k"] != "v" {
		t.Fatalf("tap saw %+v", seen)
	}
	if len(outcomes) != 1 || !outcomes[0] {
		t.Fatalf("done outcomes %v, want [true]", outcomes)
	}
	update(t, s, func(tx state.Tx) error { return tx.Emit(ctx, &state.Event{Kind: "no.audit", Time: t0}) })
	if len(seen) != 1 {
		t.Fatalf("tap ran for a transaction without audit entries")
	}
	refuse = errors.New("sink full")
	err = state.Apply(ctx, s, func(tx state.Tx) (state.Change, error) {
		return state.Change{Audit: audit.Entry{Time: t0, Action: "tap.two"}}, tx.CreateGrant(ctx, &state.Grant{ID: "tg2", CreatedAt: t0, ExpiresAt: t0.Add(time.Hour)})
	})
	if !errors.Is(err, refuse) {
		t.Fatalf("Apply with a refusing tap = %v", err)
	}
	err = s.View(ctx, func(tx state.Tx) error {
		if _, err := tx.GetGrant(ctx, "tg2"); !errors.Is(err, state.ErrNotFound) {
			t.Errorf("the refused change was kept: %v", err)
		}
		es, err := tx.QueryAudit(ctx, state.AuditQuery{Action: "tap.two"})
		if err != nil || len(es) != 0 {
			t.Errorf("the refused audit entry was kept: %v %v", es, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	refuse = nil
	tp.SetAuditTap(nil)
	update(t, s, func(tx state.Tx) error { return tx.AppendAudit(ctx, &audit.Entry{Time: t0, Action: "untapped"}) })
	if len(seen) != 2 {
		t.Fatalf("tap ran after it was removed (%d calls)", len(seen))
	}
}

func viewIsReadOnly(t *testing.T, s state.Store) {
	ctx := t.Context()
	err := s.View(ctx, func(tx state.Tx) error {
		return tx.CreateGrant(ctx, &state.Grant{ID: "g1", CreatedAt: t0, ExpiresAt: t0})
	})
	if err == nil {
		t.Fatal("write inside View succeeded")
	}
	assertEmpty(t, s, "g1")
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.Update(cctx, func(state.Tx) error { return nil }); err == nil {
		t.Fatal("Update with a cancelled context succeeded")
	}
}
