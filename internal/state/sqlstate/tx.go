// SPDX-License-Identifier: AGPL-3.0-only

package sqlstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/audit"
	"github.com/heliopsy/scrim/internal/state"
	"github.com/heliopsy/scrim/internal/stores"
)

// Tx implements [state.Tx] on one database/sql transaction.
type Tx struct {
	db       *DB
	tx       *sql.Tx
	readOnly bool
	emitted  bool
	// audited holds copies of the entries appended, for the audit tap.
	audited []audit.Entry
}

var _ state.Tx = (*Tx)(nil)

func (t *Tx) begin(op string, write bool) error {
	if write && t.readOnly {
		return ErrReadOnly
	}
	return t.db.fault(op)
}

func (t *Tx) exec(ctx context.Context, op, q string, args ...any) (sql.Result, error) {
	res, err := t.tx.ExecContext(ctx, t.db.rebind(q), t.scrub(args)...)
	return res, t.db.mapErr(err, op)
}

func (t *Tx) query(ctx context.Context, op, q string, args ...any) (*sql.Rows, error) {
	rows, err := t.tx.QueryContext(ctx, t.db.rebind(q), t.scrub(args)...)
	return rows, t.db.mapErr(err, op)
}

func (t *Tx) row(ctx context.Context, q string, args ...any) *sql.Row {
	return t.tx.QueryRowContext(ctx, t.db.rebind(q), t.scrub(args)...)
}

// scrub passes every string argument through the configured scrubber.
func (t *Tx) scrub(args []any) []any {
	sc := t.db.cfg.Scrubber
	if sc == nil {
		return args
	}
	out := make([]any, len(args))
	for i, a := range args {
		if s, ok := a.(string); ok {
			a = sc.Scrub(s)
		}
		out[i] = a
	}
	return out
}

// exists reports whether table has a row with id, to tell ErrNotFound from
// ErrConflict after a conditional update matched nothing.
func (t *Tx) exists(ctx context.Context, op, table, id string) (bool, error) {
	var one int
	err := t.row(ctx, "SELECT 1 FROM "+table+" WHERE id = ?", id).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, t.db.mapErr(err, op)
}

func affected(res sql.Result) int64 {
	n, err := res.RowsAffected()
	if err != nil {
		return 0
	}
	return n
}

// --- approvals

const approvalCols = `id, status, agent_id, request, rule, reason, grant_ttl_ns, created_at, expires_at, decided_at, decided_by`

// CreateApproval implements [state.Tx].
func (t *Tx) CreateApproval(ctx context.Context, a *state.Approval) error {
	if err := t.begin("CreateApproval", true); err != nil {
		return err
	}
	if a.ID == "" {
		a.ID = state.NewID()
	}
	if a.Status == "" {
		a.Status = state.ApprovalPending
	}
	req, err := encode(a.Request)
	if err != nil {
		return err
	}
	_, err = t.exec(ctx, "create approval",
		`INSERT INTO approvals (`+approvalCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, string(a.Status), a.Request.Agent.ID, req, a.Rule, a.Reason, int64(a.GrantTTL),
		ts(a.CreatedAt), ts(a.ExpiresAt), ts(a.DecidedAt), a.DecidedBy)
	return err
}

func scanApproval(s interface{ Scan(...any) error }) (state.Approval, error) {
	var (
		a                         state.Approval
		status, agentID, req      string
		ttl                       int64
		created, expires, decided sql.NullInt64
	)
	if err := s.Scan(&a.ID, &status, &agentID, &req, &a.Rule, &a.Reason, &ttl, &created, &expires, &decided, &a.DecidedBy); err != nil {
		return a, err
	}
	a.Status = state.ApprovalStatus(status)
	a.GrantTTL = time.Duration(ttl)
	a.CreatedAt, a.ExpiresAt, a.DecidedAt = fromTS(created), fromTS(expires), fromTS(decided)
	if err := decode(req, &a.Request); err != nil {
		return a, err
	}
	return a, nil
}

// GetApproval implements [state.Tx].
func (t *Tx) GetApproval(ctx context.Context, id string) (*state.Approval, error) {
	if err := t.begin("GetApproval", false); err != nil {
		return nil, err
	}
	a, err := scanApproval(t.row(ctx, `SELECT `+approvalCols+` FROM approvals WHERE id = ?`, id))
	if err != nil {
		return nil, t.db.mapErr(err, "get approval")
	}
	return &a, nil
}

// ListApprovals implements [state.Tx].
func (t *Tx) ListApprovals(ctx context.Context, f state.ApprovalFilter) ([]state.Approval, error) {
	if err := t.begin("ListApprovals", false); err != nil {
		return nil, err
	}
	var w where
	if f.Status != "" {
		w.add("status = ?", string(f.Status))
	}
	if f.AgentID != "" {
		w.add("agent_id = ?", f.AgentID)
	}
	rows, err := t.query(ctx, "list approvals",
		`SELECT `+approvalCols+` FROM approvals`+w.sql()+` ORDER BY created_at, id`+limitSQL(f.Limit), w.args...)
	if err != nil {
		return nil, err
	}
	return collect(t.db, rows, "list approvals", scanApproval)
}

// DecideApproval implements [state.Tx].
func (t *Tx) DecideApproval(ctx context.Context, id string, status state.ApprovalStatus, by string, at time.Time) error {
	if err := t.begin("DecideApproval", true); err != nil {
		return err
	}
	if status == state.ApprovalPending {
		if ok, err := t.exists(ctx, "decide approval", "approvals", id); err != nil || !ok {
			return notFoundOr(err)
		}
		return state.ErrConflict
	}
	res, err := t.exec(ctx, "decide approval",
		`UPDATE approvals SET status = ?, decided_by = ?, decided_at = ? WHERE id = ? AND status = ?`,
		string(status), by, ts(at), id, string(state.ApprovalPending))
	if err != nil {
		return err
	}
	if affected(res) == 1 {
		return nil
	}
	if ok, err := t.exists(ctx, "decide approval", "approvals", id); err != nil || !ok {
		return notFoundOr(err)
	}
	return state.ErrConflict
}

// --- grants

const grantCols = `id, agent_id, agent, ref, scope, max_uses, uses, approval_id, rule, created_at, expires_at, revoked_at, revoked_by`

// CreateGrant implements [state.Tx].
func (t *Tx) CreateGrant(ctx context.Context, g *state.Grant) error {
	if err := t.begin("CreateGrant", true); err != nil {
		return err
	}
	if g.ID == "" {
		g.ID = state.NewID()
	}
	agent, err := encode(g.Agent)
	if err != nil {
		return err
	}
	scope, err := encode(g.Scope)
	if err != nil {
		return err
	}
	_, err = t.exec(ctx, "create grant",
		`INSERT INTO grants (`+grantCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		g.ID, g.Agent.ID, agent, refString(g.Ref), scope, g.MaxUses, g.Uses, g.ApprovalID, g.Rule,
		ts(g.CreatedAt), ts(g.ExpiresAt), ts(g.RevokedAt), g.RevokedBy)
	return err
}

func scanGrant(s interface{ Scan(...any) error }) (state.Grant, error) {
	var (
		g                          state.Grant
		agentID, agent, ref, scope string
		created, expires, revoked  sql.NullInt64
	)
	if err := s.Scan(&g.ID, &agentID, &agent, &ref, &scope, &g.MaxUses, &g.Uses, &g.ApprovalID, &g.Rule,
		&created, &expires, &revoked, &g.RevokedBy); err != nil {
		return g, err
	}
	g.CreatedAt, g.ExpiresAt, g.RevokedAt = fromTS(created), fromTS(expires), fromTS(revoked)
	var err error
	if g.Ref, err = parseRef(ref); err != nil {
		return g, err
	}
	if err := decode(agent, &g.Agent); err != nil {
		return g, err
	}
	return g, decode(scope, &g.Scope)
}

// GetGrant implements [state.Tx].
func (t *Tx) GetGrant(ctx context.Context, id string) (*state.Grant, error) {
	if err := t.begin("GetGrant", false); err != nil {
		return nil, err
	}
	g, err := scanGrant(t.row(ctx, `SELECT `+grantCols+` FROM grants WHERE id = ?`, id))
	if err != nil {
		return nil, t.db.mapErr(err, "get grant")
	}
	return &g, nil
}

// usableSQL is Grant.Usable as a predicate; its one argument is the time.
const usableSQL = `revoked_at IS NULL AND expires_at > ? AND (max_uses = 0 OR uses < max_uses)`

// ListGrants implements [state.Tx].
func (t *Tx) ListGrants(ctx context.Context, f state.GrantFilter) ([]state.Grant, error) {
	if err := t.begin("ListGrants", false); err != nil {
		return nil, err
	}
	var w where
	if f.AgentID != "" {
		w.add("agent_id = ?", f.AgentID)
	}
	if !f.Ref.IsZero() {
		w.add("ref = ?", refString(f.Ref))
	}
	if !f.UsableAt.IsZero() {
		w.add(usableSQL, ts(f.UsableAt))
	}
	rows, err := t.query(ctx, "list grants",
		`SELECT `+grantCols+` FROM grants`+w.sql()+` ORDER BY created_at, id`+limitSQL(f.Limit), w.args...)
	if err != nil {
		return nil, err
	}
	return collect(t.db, rows, "list grants", scanGrant)
}

// UseGrant implements [state.Tx]. The usability check and the increment are
// one conditional UPDATE, so two replicas cannot both take a grant's last
// use.
func (t *Tx) UseGrant(ctx context.Context, id string, at time.Time) (*state.Grant, error) {
	if err := t.begin("UseGrant", true); err != nil {
		return nil, err
	}
	res, err := t.exec(ctx, "use grant", `UPDATE grants SET uses = uses + 1 WHERE id = ? AND `+usableSQL, id, ts(at))
	if err != nil {
		return nil, err
	}
	if affected(res) == 0 {
		if ok, err := t.exists(ctx, "use grant", "grants", id); err != nil || !ok {
			return nil, notFoundOr(err)
		}
		return nil, state.ErrGrantUnusable
	}
	g, err := scanGrant(t.row(ctx, `SELECT `+grantCols+` FROM grants WHERE id = ?`, id))
	if err != nil {
		return nil, t.db.mapErr(err, "use grant")
	}
	return &g, nil
}

// RevokeGrant implements [state.Tx].
func (t *Tx) RevokeGrant(ctx context.Context, id, by string, at time.Time) error {
	if err := t.begin("RevokeGrant", true); err != nil {
		return err
	}
	res, err := t.exec(ctx, "revoke grant",
		`UPDATE grants SET revoked_at = ?, revoked_by = ? WHERE id = ? AND revoked_at IS NULL`, ts(at), by, id)
	if err != nil {
		return err
	}
	if affected(res) == 1 {
		return nil
	}
	if ok, err := t.exists(ctx, "revoke grant", "grants", id); err != nil || !ok {
		return notFoundOr(err)
	}
	return state.ErrConflict
}

// --- sessions

const sessionCols = `id, agent_id, agent, name, token_hash, uid, root_pid, root_ppid, root_start, scopes, ` +
	`created_at, expires_at, ended_at, end_reason, labels`

// CreateSession implements [state.Tx]. An empty token hash is stored as
// NULL, so many sessions may lack one while a set hash stays unique.
func (t *Tx) CreateSession(ctx context.Context, s *state.Session) error {
	if err := t.begin("CreateSession", true); err != nil {
		return err
	}
	if s.ID == "" {
		s.ID = state.NewID()
	}
	agent, err := encode(s.Agent)
	if err != nil {
		return err
	}
	labels, err := encode(s.Labels)
	if err != nil {
		return err
	}
	scopes := "[]"
	if len(s.Scopes) > 0 {
		if scopes, err = encode(s.Scopes); err != nil {
			return err
		}
	}
	var hash any
	if s.TokenHash != "" {
		hash = s.TokenHash
	}
	// Process start times are clock ticks or microseconds since an epoch;
	// one that does not fit a signed column is refused, never wrapped.
	if s.RootStart > math.MaxInt64 {
		return fmt.Errorf("create session: root process start time %d out of range", s.RootStart)
	}
	rootStart := int64(s.RootStart)
	_, err = t.exec(ctx, "create session",
		`INSERT INTO sessions (`+sessionCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.Agent.ID, agent, s.Name, hash, int64(s.UID), int64(s.RootPID), int64(s.RootPPID), rootStart,
		scopes, ts(s.CreatedAt), ts(s.ExpiresAt), ts(s.EndedAt), s.EndReason, labels)
	return err
}

func scanSession(sc interface{ Scan(...any) error }) (state.Session, error) {
	var (
		s                                 state.Session
		agentID, agent, scopes, labels    string
		hash                              sql.NullString
		uid, rootPID, rootPPID, rootStart int64
		created, expires, ended           sql.NullInt64
	)
	if err := sc.Scan(&s.ID, &agentID, &agent, &s.Name, &hash, &uid, &rootPID, &rootPPID, &rootStart, &scopes,
		&created, &expires, &ended, &s.EndReason, &labels); err != nil {
		return s, err
	}
	s.TokenHash = hash.String
	if uid < 0 || uid > math.MaxUint32 || rootPID < math.MinInt32 || rootPID > math.MaxInt32 ||
		rootPPID < math.MinInt32 || rootPPID > math.MaxInt32 || rootStart < 0 {
		return s, fmt.Errorf("session %s: stored process binding out of range", s.ID)
	}
	s.UID, s.RootPID, s.RootPPID, s.RootStart = uint32(uid), int32(rootPID), int32(rootPPID), uint64(rootStart)
	s.CreatedAt, s.ExpiresAt, s.EndedAt = fromTS(created), fromTS(expires), fromTS(ended)
	if err := decode(agent, &s.Agent); err != nil {
		return s, err
	}
	if err := decode(scopes, &s.Scopes); err != nil {
		return s, err
	}
	if len(s.Scopes) == 0 {
		s.Scopes = nil
	}
	return s, decode(labels, &s.Labels)
}

// GetSession implements [state.Tx].
func (t *Tx) GetSession(ctx context.Context, id string) (*state.Session, error) {
	if err := t.begin("GetSession", false); err != nil {
		return nil, err
	}
	s, err := scanSession(t.row(ctx, `SELECT `+sessionCols+` FROM sessions WHERE id = ?`, id))
	if err != nil {
		return nil, t.db.mapErr(err, "get session")
	}
	return &s, nil
}

// SessionByTokenHash implements [state.Tx].
func (t *Tx) SessionByTokenHash(ctx context.Context, hash string) (*state.Session, error) {
	if err := t.begin("SessionByTokenHash", false); err != nil {
		return nil, err
	}
	if hash == "" {
		return nil, state.ErrNotFound
	}
	s, err := scanSession(t.row(ctx, `SELECT `+sessionCols+` FROM sessions WHERE token_hash = ?`, hash))
	if err != nil {
		return nil, t.db.mapErr(err, "session by token hash")
	}
	return &s, nil
}

// ListSessions implements [state.Tx].
func (t *Tx) ListSessions(ctx context.Context, f state.SessionFilter) ([]state.Session, error) {
	if err := t.begin("ListSessions", false); err != nil {
		return nil, err
	}
	var w where
	if f.AgentID != "" {
		w.add("agent_id = ?", f.AgentID)
	}
	if f.Open {
		w.add("ended_at IS NULL")
	}
	rows, err := t.query(ctx, "list sessions",
		`SELECT `+sessionCols+` FROM sessions`+w.sql()+` ORDER BY created_at, id`+limitSQL(f.Limit), w.args...)
	if err != nil {
		return nil, err
	}
	return collect(t.db, rows, "list sessions", scanSession)
}

// EndSession implements [state.Tx].
func (t *Tx) EndSession(ctx context.Context, id string, at time.Time, reason string) error {
	if err := t.begin("EndSession", true); err != nil {
		return err
	}
	res, err := t.exec(ctx, "end session",
		`UPDATE sessions SET ended_at = ?, end_reason = ? WHERE id = ? AND ended_at IS NULL`, ts(at), reason, id)
	if err != nil {
		return err
	}
	if affected(res) == 1 {
		return nil
	}
	if ok, err := t.exists(ctx, "end session", "sessions", id); err != nil || !ok {
		return notFoundOr(err)
	}
	return state.ErrConflict
}

// EndAgentSessions implements [state.Tx]. The check and the update are one
// statement, so two replicas cannot both end the same session.
func (t *Tx) EndAgentSessions(ctx context.Context, agentID string, at time.Time, reason string) ([]string, error) {
	if err := t.begin("EndAgentSessions", true); err != nil {
		return nil, err
	}
	if agentID == "" {
		return nil, nil
	}
	rows, err := t.query(ctx, "end agent sessions",
		`UPDATE sessions SET ended_at = ?, end_reason = ? WHERE agent_id = ? AND ended_at IS NULL RETURNING id, created_at`,
		ts(at), reason, agentID)
	if err != nil {
		return nil, err
	}
	type ended struct {
		id      string
		created sql.NullInt64
	}
	all, err := collect(t.db, rows, "end agent sessions", func(s interface{ Scan(...any) error }) (ended, error) {
		var e ended
		return e, s.Scan(&e.id, &e.created)
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].created.Int64 != all[j].created.Int64 {
			return all[i].created.Int64 < all[j].created.Int64
		}
		return all[i].id < all[j].id
	})
	ids := make([]string, len(all))
	for i, e := range all {
		ids[i] = e.id
	}
	return ids, nil
}

// --- audit

const auditCols = `time, action, actor, agent_id, agent, ref, effect, outcome, rule, target, subject, request_id, reason, attrs`

// AppendAudit implements [state.Tx]. It writes in the caller's transaction,
// so the entry commits or rolls back with the change it records.
func (t *Tx) AppendAudit(ctx context.Context, e *audit.Entry) error {
	if err := t.begin("AppendAudit", true); err != nil {
		return err
	}
	agent, err := encode(e.Agent)
	if err != nil {
		return err
	}
	attrs, err := encode(e.Attrs)
	if err != nil {
		return err
	}
	effect, _ := e.Effect.MarshalText()
	args := []any{ts(e.Time), e.Action, e.Actor, e.Agent.ID, agent, refString(e.Ref), string(effect), e.Outcome, e.Rule,
		e.Target, e.Subject, e.RequestID, e.Reason, attrs}
	id, err := t.insertID(ctx, "append audit", `INSERT INTO audit_log (`+auditCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, args...)
	if err != nil {
		return err
	}
	e.ID = id
	if t.db.tapped() {
		t.audited = append(t.audited, audit.Clone(*e))
	}
	return nil
}

func scanAudit(s interface{ Scan(...any) error }) (audit.Entry, error) {
	var (
		e                           audit.Entry
		at                          sql.NullInt64
		agentID, agent, ref, effect string
		attrs                       string
	)
	if err := s.Scan(&e.ID, &at, &e.Action, &e.Actor, &agentID, &agent, &ref, &effect, &e.Outcome, &e.Rule, &e.Target,
		&e.Subject, &e.RequestID, &e.Reason, &attrs); err != nil {
		return e, err
	}
	e.Time = fromTS(at)
	var err error
	if e.Ref, err = parseRef(ref); err != nil {
		return e, err
	}
	if err := e.Effect.UnmarshalText([]byte(effect)); err != nil {
		return e, fmt.Errorf("state: audit entry %d: %w", e.ID, err)
	}
	if err := decode(agent, &e.Agent); err != nil {
		return e, err
	}
	return e, decode(attrs, &e.Attrs)
}

// QueryAudit implements [state.Tx].
func (t *Tx) QueryAudit(ctx context.Context, q state.AuditQuery) ([]audit.Entry, error) {
	if err := t.begin("QueryAudit", false); err != nil {
		return nil, err
	}
	var w where
	if q.AfterID > 0 {
		w.add("id > ?", q.AfterID)
	}
	if q.BeforeID > 0 {
		w.add("id < ?", q.BeforeID)
	}
	if q.AgentID != "" {
		w.add("agent_id = ?", q.AgentID)
	}
	if !q.Ref.IsZero() {
		w.add("ref = ?", refString(q.Ref))
	}
	if q.Effect != "" {
		w.add("effect = ?", q.Effect)
	}
	if q.Outcome != "" {
		w.add("outcome = ?", q.Outcome)
	}
	if q.Action != "" {
		w.add("action = ?", q.Action)
	}
	if !q.Since.IsZero() {
		w.add("time >= ?", ts(q.Since))
	}
	if !q.Until.IsZero() {
		w.add("time < ?", ts(q.Until))
	}
	rows, err := t.query(ctx, "query audit",
		`SELECT id, `+auditCols+` FROM audit_log`+w.sql()+` ORDER BY id`+desc(q.Newest)+limitSQL(q.Limit), w.args...)
	if err != nil {
		return nil, err
	}
	return collect(t.db, rows, "query audit", scanAudit)
}

// --- redaction tokens

const redactionTokenCols = `id, kind, key_version, sealed, created_at, expires_at`

// PutRedactionToken implements [state.Tx]. One statement on both engines,
// so two replicas sharing the same token at once both succeed.
func (t *Tx) PutRedactionToken(ctx context.Context, r *state.RedactionToken) error {
	if err := t.begin("PutRedactionToken", true); err != nil {
		return err
	}
	if r.ID == "" || r.ExpiresAt.IsZero() || len(r.Sealed) == 0 {
		return fmt.Errorf("put redaction token: id, expiry and sealed bytes are required")
	}
	// The sealed bytes go in as []byte, which the scrubber leaves alone:
	// they are ciphertext, and a scrubbed copy could not be opened.
	_, err := t.exec(ctx, "put redaction token",
		`INSERT INTO redaction_tokens (`+redactionTokenCols+`) VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT (id) DO UPDATE SET sealed = excluded.sealed, key_version = excluded.key_version,
		   expires_at = CASE WHEN excluded.expires_at > redaction_tokens.expires_at
		                     THEN excluded.expires_at ELSE redaction_tokens.expires_at END`,
		r.ID, r.Kind, int64(r.KeyVersion), r.Sealed, ts(r.CreatedAt), ts(r.ExpiresAt))
	return err
}

func scanRedactionToken(sc interface{ Scan(...any) error }) (state.RedactionToken, error) {
	var (
		r                state.RedactionToken
		version          int64
		created, expires sql.NullInt64
	)
	if err := sc.Scan(&r.ID, &r.Kind, &version, &r.Sealed, &created, &expires); err != nil {
		return r, err
	}
	if version < 1 || version > 255 {
		return r, fmt.Errorf("redaction token %s: stored key version out of range", r.ID)
	}
	r.KeyVersion = int(version)
	r.CreatedAt, r.ExpiresAt = fromTS(created), fromTS(expires)
	return r, nil
}

// GetRedactionToken implements [state.Tx].
func (t *Tx) GetRedactionToken(ctx context.Context, id string) (*state.RedactionToken, error) {
	if err := t.begin("GetRedactionToken", false); err != nil {
		return nil, err
	}
	r, err := scanRedactionToken(t.row(ctx, `SELECT `+redactionTokenCols+` FROM redaction_tokens WHERE id = ?`, id))
	if err != nil {
		return nil, t.db.mapErr(err, "get redaction token")
	}
	return &r, nil
}

// ListRedactionTokens implements [state.Tx].
func (t *Tx) ListRedactionTokens(ctx context.Context, liveAt time.Time) ([]state.RedactionToken, error) {
	if err := t.begin("ListRedactionTokens", false); err != nil {
		return nil, err
	}
	rows, err := t.query(ctx, "list redaction tokens",
		`SELECT `+redactionTokenCols+` FROM redaction_tokens WHERE expires_at > ? ORDER BY id`, liveAt.UnixNano())
	if err != nil {
		return nil, err
	}
	return collect(t.db, rows, "list redaction tokens", scanRedactionToken)
}

// DeleteRedactionTokens implements [state.Tx].
func (t *Tx) DeleteRedactionTokens(ctx context.Context, expiredAt time.Time) (int, error) {
	if err := t.begin("DeleteRedactionTokens", true); err != nil {
		return 0, err
	}
	res, err := t.exec(ctx, "delete redaction tokens", `DELETE FROM redaction_tokens WHERE expires_at <= ?`, expiredAt.UnixNano())
	if err != nil {
		return 0, err
	}
	return int(affected(res)), nil
}

// --- events

// Emit implements [state.Tx].
func (t *Tx) Emit(ctx context.Context, e *state.Event) error {
	if err := t.begin("Emit", true); err != nil {
		return err
	}
	if !t.emitted && t.db.cfg.BeforeEmit != nil {
		if err := t.db.cfg.BeforeEmit(ctx, t.tx); err != nil {
			return t.db.mapErr(err, "emit")
		}
	}
	t.emitted = true
	id, err := t.insertID(ctx, "emit", `INSERT INTO events (kind, subject, time) VALUES (?, ?, ?)`, e.Kind, e.Subject, ts(e.Time))
	if err != nil {
		return err
	}
	e.ID = id
	return nil
}

// EventsAfter implements [state.Tx].
func (t *Tx) EventsAfter(ctx context.Context, after int64, n int) ([]state.Event, error) {
	if err := t.begin("EventsAfter", false); err != nil {
		return nil, err
	}
	rows, err := t.query(ctx, "events after",
		`SELECT id, kind, subject, time FROM events WHERE id > ? ORDER BY id`+limitSQL(n), after)
	if err != nil {
		return nil, err
	}
	return collect(t.db, rows, "events after", func(s interface{ Scan(...any) error }) (state.Event, error) {
		var (
			e  state.Event
			at sql.NullInt64
		)
		err := s.Scan(&e.ID, &e.Kind, &e.Subject, &at)
		e.Time = fromTS(at)
		return e, err
	})
}

// LastEventID implements [state.Tx].
func (t *Tx) LastEventID(ctx context.Context) (int64, error) {
	if err := t.begin("LastEventID", false); err != nil {
		return 0, err
	}
	var id sql.NullInt64
	if err := t.row(ctx, `SELECT MAX(id) FROM events`).Scan(&id); err != nil {
		return 0, t.db.mapErr(err, "last event id")
	}
	return id.Int64, nil
}

// insertID runs an INSERT and returns the new row's integer id. SQLite and
// PostgreSQL both support RETURNING.
func (t *Tx) insertID(ctx context.Context, op, q string, args ...any) (int64, error) {
	var id int64
	if err := t.row(ctx, q+` RETURNING id`, args...).Scan(&id); err != nil {
		return 0, t.db.mapErr(err, op)
	}
	return id, nil
}

// --- helpers

type where struct {
	parts []string
	args  []any
}

func (w *where) add(cond string, args ...any) {
	w.parts = append(w.parts, cond)
	w.args = append(w.args, args...)
}

func (w *where) sql() string {
	if len(w.parts) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(w.parts, " AND ")
}

func desc(newest bool) string {
	if newest {
		return " DESC"
	}
	return ""
}

func limitSQL(n int) string {
	if n <= 0 {
		return ""
	}
	return fmt.Sprintf(" LIMIT %d", n)
}

func collect[T any](db *DB, rows *sql.Rows, op string, scan func(interface{ Scan(...any) error }) (T, error)) ([]T, error) {
	defer func() { _ = rows.Close() }()
	var out []T
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, db.mapErr(err, op)
		}
		out = append(out, v)
	}
	return out, db.mapErr(rows.Err(), op)
}

func notFoundOr(err error) error {
	if err != nil {
		return err
	}
	return state.ErrNotFound
}

// ts encodes t as UTC Unix nanoseconds, nil for the zero time.
func ts(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UnixNano()
}

func fromTS(n sql.NullInt64) time.Time {
	if !n.Valid {
		return time.Time{}
	}
	return time.Unix(0, n.Int64).UTC()
}

func encode(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("state: encoding %T: %w", v, err)
	}
	return string(b), nil
}

func decode(s string, v any) error {
	if s == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(s), v); err != nil {
		return fmt.Errorf("state: decoding %T: %w", v, err)
	}
	return nil
}

func refString(r stores.Ref) string {
	if r.IsZero() {
		return ""
	}
	return r.String()
}

func parseRef(s string) (stores.Ref, error) {
	if s == "" {
		return stores.Ref{}, nil
	}
	r, err := stores.ParseRef(s)
	if err != nil {
		return stores.Ref{}, fmt.Errorf("state: stored reference does not parse: %w", err)
	}
	return r, nil
}
