// SPDX-License-Identifier: AGPL-3.0-only

package auditlog_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/auditlog"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/state/memstate"
	"github.com/heliopsy/scrim/internal/stores"
)

var now = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

func seeded(t *testing.T) state.Store {
	s := memstate.New()
	ref := stores.MustParseRef("bao://kv/gh#token")
	err := s.Update(context.Background(), func(tx state.Tx) error {
		for i := range 5 {
			e := audit.Entry{Action: "inject", Agent: policy.Agent{ID: "a1"}, Ref: ref, Effect: policy.Allow,
				Outcome: audit.OutcomeOK, Target: "api.github.com", Time: now.Add(time.Duration(i-5) * time.Minute)}
			if err := tx.AppendAudit(context.Background(), &e); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestHandlerPagesNewestFirst(t *testing.T) {
	h := auditlog.Handler(seeded(t), func() time.Time { return now })
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/audit?agent=a1&ref=bao://kv/gh%23token&decision=allow&limit=3", nil))
	var p auditlog.Page
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil || rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if len(p.Entries) != 3 || p.Entries[0].ID != 5 || p.NextBefore != 3 || p.Entries[0].Ref != "bao://kv/gh#token" {
		t.Fatalf("page = %+v", p)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/audit?limit=3&before=3", nil))
	p = auditlog.Page{}
	_ = json.Unmarshal(rec.Body.Bytes(), &p)
	if len(p.Entries) != 2 || p.Entries[0].ID != 2 || p.NextBefore != 0 {
		t.Fatalf("second page = %+v", p)
	}
}

func TestHandlerRejectsBadQueries(t *testing.T) {
	h := auditlog.Handler(seeded(t), nil)
	for _, q := range []string{"decision=maybe", "since=yesterday", "limit=x", "limit=5000", "limit=-1", "before=x", "ref=nope",
		"since=1h&until=2h"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/audit?"+q, nil))
		if rec.Code != 400 {
			t.Errorf("%s: %d", q, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/audit", nil))
	if rec.Code != 405 {
		t.Errorf("POST: %d", rec.Code)
	}
}

func TestParseTime(t *testing.T) {
	if got, _ := auditlog.ParseTime("1h", now); !got.Equal(now.Add(-time.Hour)) {
		t.Errorf("1h = %v", got)
	}
	if got, _ := auditlog.ParseTime("2026-11-20T10:00:00Z", now); got.Hour() != 10 {
		t.Errorf("rfc3339 = %v", got)
	}
	if _, err := auditlog.ParseTime("-1h", now); err == nil {
		t.Error("accepted a negative duration")
	}
}
