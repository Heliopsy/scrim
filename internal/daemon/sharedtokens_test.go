// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/leak"
	"github.com/heliopsy/scrim/internal/placeholder"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/secret"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/memstate"
	"github.com/heliopsy/scrim/internal/stores/refresh"
	"github.com/heliopsy/scrim/internal/testing/pgtest"
	"github.com/heliopsy/scrim/internal/testing/podtest"
)

// eventsEnv selects an events backend for replicas sharing PostgreSQL
// state: postgres, valkey or nats in rootless podman.
func eventsEnv(t *testing.T, backend string) []string {
	t.Helper()
	switch backend {
	case "valkey":
		return []string{"SCRIM_EVENTS_BACKEND=valkey", "SCRIM_VALKEY_ADDRESSES=" + valkeySvc.Addr(t),
			"SCRIM_EVENTS_VALKEY_CHANNEL=scrim:tokens:" + podtest.RandHex(4)}
	case "nats":
		url := natsSvc.Addr(t)
		if !strings.Contains(url, "://") {
			url = "nats://" + url
		}
		return []string{"SCRIM_EVENTS_BACKEND=nats", "SCRIM_NATS_SERVERS=" + url,
			"SCRIM_EVENTS_NATS_SUBJECT=scrim.tokens." + podtest.RandHex(4)}
	}
	return []string{"SCRIM_EVENTS_BACKEND=postgres"}
}

// snapshotHolds reports whether h's last snapshot holds value in store.
func snapshotHolds(t *testing.T, h *harness, store, value string) bool {
	t.Helper()
	for _, v := range h.snapshot(t).GetValues() {
		if v.GetStore() == store && string(v.GetValue()) == value {
			return true
		}
	}
	return false
}

// TestReplicasShareTokens is the fake-data-plane half of
// specs/state-and-scaling "Every replica redacts scrim's own tokens" and
// "Shared tokens expire and fail safe", for each events backend: a session
// minted, a service account token verified and an identity token signed on
// replica A reach replica B's snapshot within the delivery bound; a replica
// started afterwards has all three in its first snapshot; a revocation on B
// takes the session out of A's redaction scopes and leaves its token; an
// expired token leaves B's set and its row; and no token, in any encoding,
// is in a dump of the state database.
func TestReplicasShareTokens(t *testing.T) {
	for _, backend := range []string{"postgres", "valkey", "nats"} {
		t.Run(backend, func(t *testing.T) { replicasShareTokens(t, backend) })
	}
}

func replicasShareTokens(t *testing.T, backend string) {
	dsn := pgtest.FreshDSN(t)
	env := append(eventsEnv(t, backend), "SCRIM_DEPLOYMENT_REPLICAS=3")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	token := seed(t, "tok-")
	start := func() (*Daemon, *harness) {
		t.Helper()
		h := newHarness(t, token)
		h.opts.Config.Environ = append(append(h.opts.Config.Environ, replicaEnv(dsn)...), env...)
		d, err := Start(ctx, h.opts)
		if err != nil {
			t.Fatalf("start replica: %v", err)
		}
		t.Cleanup(func() { _ = d.Shutdown(context.Background()) })
		if err := d.WaitReady(ctx); err != nil {
			t.Fatalf("%v\n%s", err, h.logs.String())
		}
		return d, h
	}
	a, ha := start()
	b, hb := start()
	if a.shared == nil || b.shared == nil {
		t.Fatal("token sharing is off with PostgreSQL state and placeholder keys")
	}
	within(t, "both events subscriptions", 15*time.Second, func() bool {
		return a.App().Events.Listening() && b.App().Events.Listening()
	})

	// A session minted on A.
	peer := identity.Peer{UID: uint32(os.Getuid()), PID: int32(os.Getpid())} //nolint:gosec // ids fit
	m, err := a.runtime.Sessions.Mint(ctx, identity.Identity{Agent: "dev", Source: identity.SourcePeer, Peer: peer,
		Scopes: []identity.Scope{identity.ScopeSessionsMint}}, identity.MintRequest{Name: "shared"})
	if err != nil {
		t.Fatal(err)
	}
	var sessTok string
	_ = m.Token.Expose(func(b []byte) error { sessTok = string(b); return nil })
	m.Token.Wipe()
	took := within(t, "the session token on B", fast, func() bool { return snapshotHolds(t, hb, sessionTokenStore, sessTok) })
	t.Logf("%s: a session minted on A reached B's snapshot in %s", backend, took)
	if ids := b.tokens.sessionsByAgent()["dev"]; !slices.Contains(ids, m.Session.ID) {
		t.Fatalf("B does not list the session for redaction scopes: %v", ids)
	}

	// A service account token verified and an identity token signed on A.
	kube, issued := "eyJ"+seed(t, "kube-"), "eyJ"+seed(t, "iss-")
	a.kubeTokens.addKube([]byte(kube), time.Now().Add(time.Hour))
	a.issued.addValue(secret.FromString(issued), time.Now().Add(10*time.Minute))
	within(t, "the service account and identity tokens on B", fast, func() bool {
		return snapshotHolds(t, hb, kubeTokenStore, kube) && snapshotHolds(t, hb, issuedTokenStore, issued)
	})

	// A replica started now has all three in its first snapshot.
	_, hc := start()
	for store, v := range map[string]string{sessionTokenStore: sessTok, kubeTokenStore: kube, issuedTokenStore: issued} {
		if !snapshotHolds(t, hc, store, v) {
			t.Fatalf("the replica started later lacks a %s token in its first snapshot", store)
		}
	}

	// Revoked on B: A drops the session from the redaction scopes and keeps
	// redacting its token.
	if err := b.runtime.Sessions.Revoke(ctx, m.Session.ID, "test"); err != nil {
		t.Fatal(err)
	}
	within(t, "the revocation on A", fast, func() bool { return len(a.tokens.sessionsByAgent()["dev"]) == 0 })
	if !snapshotHolds(t, ha, sessionTokenStore, sessTok) {
		t.Fatal("A dropped a revoked session's token before it expired")
	}

	// No token in the state database, in any encoding the checker decodes.
	sid := m.Session.ID
	checker := leak.NewChecker([]leak.Seed{
		leak.NewSeed("session", leak.KindAPIKey, sessTok, identity.TokenPrefix+sid+"_"),
		leak.NewSeed("kube", leak.KindJWT, kube, "eyJ"), leak.NewSeed("issued", leak.KindJWT, issued, "eyJ"),
	})
	dump := dumpState(t, dsn)
	if !strings.Contains(dump, "redaction.token") || !strings.Contains(dump, sid) {
		t.Fatal("the dump lacks the shared rows; the check below would prove nothing")
	}
	if f := checker.CheckText(1, dump); len(f) > 0 {
		t.Fatalf("the state database holds a token: %v", f)
	}

	// Expiry: B prunes the tokens and the rows go.
	later := time.Now().Add(2 * time.Hour)
	for _, set := range []*sessionTokens{b.kubeTokens, b.issued} {
		set.mu.Lock()
		set.now = func() time.Time { return later }
		set.mu.Unlock()
		if !set.prune() {
			t.Fatalf("%s: nothing expired", set.store)
		}
	}
	b.shared.mu.Lock()
	b.shared.now = func() time.Time { return later }
	b.shared.mu.Unlock()
	b.shared.deleteExpired(ctx)
	var left []state.RedactionToken
	_ = b.App().State.View(ctx, func(tx state.Tx) error {
		left, err = tx.ListRedactionTokens(ctx, time.Now().Add(-time.Hour))
		return err
	})
	if len(left) != 1 || left[0].Kind != state.TokenSession {
		t.Fatalf("rows left after the hour: %+v", left)
	}
	for _, l := range []string{ha.logs.String(), hb.logs.String(), hc.logs.String()} {
		if f := checker.CheckText(1, l); len(f) > 0 {
			t.Fatalf("a token reached a log: %v", f)
		}
	}
}

// dumpState returns every row of every scrim table as text.
func dumpState(t *testing.T, dsn string) string {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var out strings.Builder
	for _, table := range []string{"approvals", "grants", "sessions", "audit_log", "events", "redaction_tokens"} {
		rows, err := db.Query(`SELECT t::text FROM ` + table + ` t`) //nolint:gosec // fixed table names
		if err != nil {
			t.Fatalf("dump %s: %v", table, err)
		}
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			out.WriteString(s + "\n")
		}
		_ = rows.Close()
	}
	return out.String()
}

// flakyState fails every Update while fail is set.
type flakyState struct {
	state.Store
	fail atomic.Bool
}

func (f *flakyState) Update(ctx context.Context, fn func(state.Tx) error) error {
	if f.fail.Load() {
		return errors.New("database unreachable")
	}
	return f.Store.Update(ctx, fn)
}

func keyRing(t *testing.T, version int, key []byte) *placeholder.Ring {
	t.Helper()
	r := &placeholder.Ring{Keys: []placeholder.Key{{Version: version, Key: secret.New(key)}}}
	t.Cleanup(r.Wipe)
	return r
}

// A write that fails is retried until it lands; the token stays redacted on
// the replica that has it meanwhile. A row sealed under a key version this
// replica lacks is logged and skipped.
func TestSharedTokensRetryAndUnreadable(t *testing.T) {
	st := &flakyState{Store: memstate.New()}
	key := []byte(seed(t, "pk-"))
	var logs syncBuffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	sessions := newSessionTokens(sessionTokenStore, nil)
	s, err := newSharedTokens(st, keyRing(t, 1, key), log, sessions)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go s.run(ctx)

	st.fail.Store(true)
	tok := identity.TokenPrefix + "aaaaaaaaaaaaaaaa_" + seed(t, "")
	sessions.add(identity.Session{ID: "aaaaaaaaaaaaaaaa", Agent: "dev", ExpiresAt: time.Now().Add(time.Hour)}, secret.FromString(tok))
	rows := func() int {
		var n int
		_ = st.View(ctx, func(tx state.Tx) error {
			r, _ := tx.ListRedactionTokens(ctx, time.Now())
			n = len(r)
			return nil
		})
		return n
	}
	eventually(t, "the failure logged", func() bool { return strings.Contains(logs.String(), "sharing tokens with the other replicas failed") })
	if rows() != 0 || len(sessions.sessionsByAgent()["dev"]) != 1 {
		t.Fatal("unexpected state while the database fails")
	}
	st.fail.Store(false)
	eventually(t, "the retried write", func() bool { return rows() == 1 })

	// The row opens in another replica with the same key.
	other := newSessionTokens(sessionTokenStore, nil)
	o, err := newSharedTokens(st, keyRing(t, 1, key), log, other)
	if err != nil {
		t.Fatal(err)
	}
	defer o.close()
	_ = st.Update(ctx, func(tx state.Tx) error {
		return tx.CreateSession(ctx, &state.Session{ID: "aaaaaaaaaaaaaaaa", Agent: policy.Agent{ID: "dev"}, CreatedAt: time.Now()})
	})
	if err := o.load(ctx); err != nil {
		t.Fatal(err)
	}
	held := func(set *sessionTokens) bool {
		found := false
		set.EachValue(func(_ refresh.Source, v secret.Value) {
			_ = v.Expose(func(b []byte) error { found = found || bytes.Equal(b, []byte(tok)); return nil })
		})
		return found
	}
	if !held(other) {
		t.Fatal("the other replica did not load the shared token")
	}

	// A replica whose ring lacks version 1 skips the row and says so.
	third := newSessionTokens(sessionTokenStore, nil)
	x, err := newSharedTokens(st, keyRing(t, 2, []byte(seed(t, "pk2-"))), log, third)
	if err != nil {
		t.Fatal(err)
	}
	defer x.close()
	if err := x.load(ctx); err != nil {
		t.Fatal(err)
	}
	if held(third) || !strings.Contains(logs.String(), "cannot be opened") || strings.Contains(logs.String(), tok) {
		t.Fatal("an unreadable row was not skipped and logged by ID")
	}
}
