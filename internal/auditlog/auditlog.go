// SPDX-License-Identifier: AGPL-3.0-only

// Package auditlog queries the audit log for operators, through
// `scrim audit log` and the admin API (specs/policy-approvals "Querying the
// audit log"): by agent, reference, action, decision, outcome and time
// range, newest first, in human and machine-readable form. Entries are
// metadata only; nothing here can carry a value.
package auditlog

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/stores"
)

// DefaultLimit and MaxLimit bound one page.
const (
	DefaultLimit = 50
	MaxLimit     = 1000
)

// Filter is an operator's query. Zero fields match anything.
type Filter struct {
	Agent    string
	Ref      string
	Action   string
	Decision string // allow, deny or ask
	Outcome  string
	Since    time.Time
	Until    time.Time
	// Before is the paging cursor: only entries with a smaller ID.
	Before int64
	Limit  int
}

// Query converts f to a state query, newest first.
func (f Filter) Query() (state.AuditQuery, error) {
	q := state.AuditQuery{
		AgentID: f.Agent, Action: f.Action, Outcome: f.Outcome,
		Since: f.Since, Until: f.Until, BeforeID: f.Before, Newest: true, Limit: f.Limit,
	}
	if f.Ref != "" {
		r, err := stores.ParseRef(f.Ref)
		if err != nil {
			return q, fmt.Errorf("ref: %w", err)
		}
		q.Ref = r
	}
	if f.Decision != "" {
		e, err := policy.ParseEffect(f.Decision)
		if err != nil {
			return q, fmt.Errorf("decision: %w", err)
		}
		q.Effect = e.String()
	}
	switch {
	case q.Limit == 0:
		q.Limit = DefaultLimit
	case q.Limit < 0 || q.Limit > MaxLimit:
		return q, fmt.Errorf("limit %d must be between 1 and %d", q.Limit, MaxLimit)
	}
	if !f.Since.IsZero() && !f.Until.IsZero() && !f.Until.After(f.Since) {
		return q, fmt.Errorf("until must be after since")
	}
	return q, nil
}

// ParseTime reads a --since or --until value: an RFC 3339 time, or a
// duration ago such as 1h or 30m.
func ParseTime(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		if d < 0 {
			return time.Time{}, fmt.Errorf("%q: use a positive duration for a time in the past", s)
		}
		return now.Add(-d), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q is neither an RFC 3339 time nor a duration such as 1h", s)
	}
	return t, nil
}

// Record is the machine-readable form of one entry.
type Record struct {
	ID        int64             `json:"id"`
	Time      time.Time         `json:"time"`
	Action    string            `json:"action"`
	Actor     string            `json:"actor,omitempty"`
	Agent     string            `json:"agent,omitempty"`
	AgentKind string            `json:"agent_kind,omitempty"`
	Ref       string            `json:"ref,omitempty"`
	Decision  string            `json:"decision"`
	Rule      string            `json:"rule,omitempty"`
	Outcome   string            `json:"outcome,omitempty"`
	Target    string            `json:"target,omitempty"`
	Subject   string            `json:"subject,omitempty"`
	RequestID string            `json:"request_id,omitempty"`
	Reason    string            `json:"reason,omitempty"`
	Attrs     map[string]string `json:"attrs,omitempty"`
}

// FromEntry converts an entry.
func FromEntry(e audit.Entry) Record {
	r := Record{
		ID: e.ID, Time: e.Time.UTC(), Action: e.Action, Actor: e.Actor, Agent: e.Agent.ID,
		AgentKind: string(e.Agent.Kind), Decision: e.Effect.String(), Rule: e.Rule, Outcome: e.Outcome,
		Target: e.Target, Subject: e.Subject, RequestID: e.RequestID, Reason: e.Reason, Attrs: e.Attrs,
	}
	if !e.Ref.IsZero() {
		r.Ref = e.Ref.String()
	}
	return r
}

// Page is one query result. NextBefore, when non-zero, is the Before
// cursor of the next (older) page.
type Page struct {
	Entries    []Record `json:"entries"`
	NextBefore int64    `json:"next_before,omitempty"`
}

// Run executes f against s.
func Run(ctx context.Context, s state.Store, f Filter) (Page, error) {
	q, err := f.Query()
	if err != nil {
		return Page{}, err
	}
	var entries []audit.Entry
	if err := s.View(ctx, func(tx state.Tx) error {
		var err error
		entries, err = tx.QueryAudit(ctx, q)
		return err
	}); err != nil {
		return Page{}, err
	}
	p := Page{Entries: make([]Record, 0, len(entries))}
	for _, e := range entries {
		p.Entries = append(p.Entries, FromEntry(e))
	}
	if len(entries) == q.Limit && len(entries) > 0 {
		p.NextBefore = entries[len(entries)-1].ID
	}
	return p, nil
}

// WriteHuman writes p as a table, newest first.
func WriteHuman(w io.Writer, p Page) error {
	if len(p.Entries) == 0 {
		_, err := fmt.Fprintln(w, "no matching audit entries")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tTIME\tACTION\tAGENT\tREF\tTARGET\tDECISION\tOUTCOME\tRULE")
	for _, r := range p.Entries {
		_, _ = fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Time.Format(time.RFC3339), r.Action,
			dash(r.Agent), dash(r.Ref), dash(r.Target), r.Decision, dash(r.Outcome), dash(r.Rule))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if p.NextBefore != 0 {
		_, err := fmt.Fprintf(w, "more: --before %d\n", p.NextBefore)
		return err
	}
	return nil
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// FromValues reads a filter from URL query parameters: agent, ref, action,
// decision, outcome, since, until, before, limit.
func FromValues(v url.Values, now time.Time) (Filter, error) {
	f := Filter{Agent: v.Get("agent"), Ref: v.Get("ref"), Action: v.Get("action"),
		Decision: v.Get("decision"), Outcome: v.Get("outcome")}
	var err error
	if f.Since, err = ParseTime(v.Get("since"), now); err != nil {
		return f, fmt.Errorf("since: %w", err)
	}
	if f.Until, err = ParseTime(v.Get("until"), now); err != nil {
		return f, fmt.Errorf("until: %w", err)
	}
	if s := v.Get("before"); s != "" {
		if f.Before, err = strconv.ParseInt(s, 10, 64); err != nil {
			return f, fmt.Errorf("before: %q is not an integer", s)
		}
	}
	if s := v.Get("limit"); s != "" {
		if f.Limit, err = strconv.Atoi(s); err != nil {
			return f, fmt.Errorf("limit: %q is not an integer", s)
		}
	}
	return f, nil
}

// Handler serves GET requests with the filter in the query string and a
// [Page] as JSON, for mounting on the admin API behind its authentication.
func Handler(s state.Store, now func() time.Time) http.Handler {
	if now == nil {
		now = time.Now
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "use GET"})
			return
		}
		f, err := FromValues(r.URL.Query(), now())
		if err == nil {
			_, err = f.Query()
		}
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		p, err := Run(r.Context(), s, f)
		if err != nil {
			// Backend errors stay in the server log, not in the response.
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "audit query failed"})
			return
		}
		_ = json.NewEncoder(w).Encode(p)
	})
}
