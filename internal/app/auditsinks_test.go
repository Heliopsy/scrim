// SPDX-License-Identifier: AGPL-3.0-only

package app_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/app"
	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/state"
)

// pushes is a Loki push endpoint that records bodies, or hangs while held.
type pushes struct {
	mu     sync.Mutex
	bodies []string
	hold   chan struct{}
}

func (p *pushes) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	hold := p.hold
	p.mu.Unlock()
	if hold != nil {
		select {
		case <-hold:
		case <-r.Context().Done():
			return
		}
	}
	b, _ := io.ReadAll(r.Body)
	p.mu.Lock()
	p.bodies = append(p.bodies, string(b))
	p.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (p *pushes) all() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.Join(p.bodies, "\n")
}

func change(ctx context.Context, a *app.App, action, grant string) error {
	return state.Apply(ctx, a.State, func(tx state.Tx) (state.Change, error) {
		return state.Change{Audit: audit.Entry{Time: time.Now(), Action: action, Actor: "test"}},
			tx.CreateGrant(ctx, &state.Grant{ID: grant, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	})
}

// TestAuditSinksFromStateChanges: with audit.sinks db,loki every state
// change's audit entry also reaches Loki; with policy block and Loki not
// answering, a change past the queue is refused and not stored.
func TestAuditSinksFromStateChanges(t *testing.T) {
	p := &pushes{}
	srv := httptest.NewServer(p)
	defer srv.Close()
	var logs bytes.Buffer
	a, err := app.New(context.Background(), isolated(t, "SCRIM_AUDIT_SINKS=db,loki", "SCRIM_AUDIT_LOKI_URL="+srv.URL,
		"SCRIM_AUDIT_LOKI_POLICY=block", "SCRIM_AUDIT_LOKI_QUEUE_SIZE=2", "SCRIM_AUDIT_LOKI_TIMEOUT=200ms",
		"SCRIM_AUDIT_LOKI_WRITE_TIMEOUT=100ms"), &logs)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	ctx := context.Background()
	if err := change(ctx, a, "grant.created", "g1"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(p.all(), `\"action\":\"grant.created\"`) {
		if time.Now().After(deadline) {
			t.Fatalf("the entry never reached Loki: %q", p.all())
		}
		time.Sleep(10 * time.Millisecond)
	}

	p.mu.Lock()
	p.hold = make(chan struct{})
	p.mu.Unlock()
	for i, g := range []string{"g2", "g3"} {
		if err := change(ctx, a, "grant.created", g); err != nil {
			t.Fatalf("change %d within the queue: %v", i, err)
		}
	}
	err = change(ctx, a, "grant.created", "g4")
	if !errors.Is(err, audit.ErrNotAudited) {
		t.Fatalf("change past a full blocking sink = %v", err)
	}
	_ = a.State.View(ctx, func(tx state.Tx) error {
		if _, err := tx.GetGrant(ctx, "g4"); !errors.Is(err, state.ErrNotFound) {
			t.Errorf("the refused change was stored: %v", err)
		}
		return nil
	})
	st := a.AuditSinks.Status()
	if len(st) != 1 || st[0].Refused != 1 {
		t.Fatalf("sink status %+v", st)
	}
	p.mu.Lock()
	close(p.hold)
	p.hold = nil
	p.mu.Unlock()
}
