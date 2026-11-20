// SPDX-License-Identifier: AGPL-3.0-only

package approval

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"time"

	"github.com/heliopsy/scrim/internal/breakglass"
	"github.com/heliopsy/scrim/internal/grant"
	"github.com/heliopsy/scrim/internal/state"
)

// The HTTP surface has two halves:
//
//   - [Service.DecisionHandler] serves the decision links. It is meant to be
//     reachable from approvers' phones (approvals.public-url) and needs no
//     other authentication: the token in the link is the authority. GET
//     only shows the request and a confirm button, so link previews and
//     scanners cannot decide anything; POST decides.
//   - [AdminHandler] serves operators (`scrim approve`, `scrim approvals
//     list`, `scrim grants`, `scrim deny-all`) and must only be mounted on
//     the authenticated admin listener. It refuses every call for which the
//     Operator function names nobody.

// ApprovalView is the API form of an approval.
type ApprovalView struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	Agent     string    `json:"agent"`
	Action    string    `json:"action,omitempty"`
	Ref       string    `json:"ref,omitempty"`
	Name      string    `json:"name,omitempty"`
	Provider  string    `json:"provider,omitempty"`
	Host      string    `json:"host,omitempty"`
	Method    string    `json:"method,omitempty"`
	Path      string    `json:"path,omitempty"`
	Tool      string    `json:"tool,omitempty"`
	Command   string    `json:"command,omitempty"`
	Rule      string    `json:"rule"`
	Reason    string    `json:"reason,omitempty"`
	GrantTTL  string    `json:"grant_ttl,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	DecidedAt time.Time `json:"decided_at,omitzero"`
	DecidedBy string    `json:"decided_by,omitempty"`
}

// ViewOf converts an approval for the API.
func ViewOf(a *state.Approval) ApprovalView {
	v := ApprovalView{
		ID: a.ID, Status: string(a.Status), Agent: a.Request.Agent.ID, Action: string(a.Request.Action),
		Name: a.Request.Name, Provider: a.Request.Provider, Host: a.Request.Host, Method: a.Request.Method,
		Path: a.Request.Path, Tool: a.Request.Tool, Command: a.Request.Command, Rule: a.Rule, Reason: a.Reason,
		CreatedAt: a.CreatedAt, ExpiresAt: a.ExpiresAt, DecidedAt: a.DecidedAt, DecidedBy: a.DecidedBy,
	}
	if !a.Request.Ref.IsZero() {
		v.Ref = a.Request.Ref.String()
	}
	if a.GrantTTL > 0 {
		v.GrantTTL = a.GrantTTL.String()
	}
	return v
}

// GrantView is the API form of a grant.
type GrantView struct {
	ID         string    `json:"id"`
	Agent      string    `json:"agent"`
	Ref        string    `json:"ref"`
	Hosts      []string  `json:"hosts,omitempty"`
	Tools      []string  `json:"tools,omitempty"`
	MaxUses    int       `json:"max_uses,omitempty"`
	Uses       int       `json:"uses"`
	Rule       string    `json:"rule,omitempty"`
	ApprovalID string    `json:"approval_id,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	RevokedAt  time.Time `json:"revoked_at,omitzero"`
	RevokedBy  string    `json:"revoked_by,omitempty"`
	Active     bool      `json:"active"`
}

// GrantViewOf converts a grant for the API.
func GrantViewOf(g *state.Grant, now time.Time) GrantView {
	return GrantView{
		ID: g.ID, Agent: g.Agent.ID, Ref: g.Ref.String(), Hosts: g.Scope.Hosts, Tools: g.Scope.Tools,
		MaxUses: g.MaxUses, Uses: g.Uses, Rule: g.Rule, ApprovalID: g.ApprovalID, CreatedAt: g.CreatedAt,
		ExpiresAt: g.ExpiresAt, RevokedAt: g.RevokedAt, RevokedBy: g.RevokedBy, Active: g.Usable(now),
	}
}

// DecisionResult is the body of a decision response.
type DecisionResult struct {
	Approval ApprovalView `json:"approval"`
	GrantID  string       `json:"grant_id,omitempty"`
	GrantTTL string       `json:"grant_ttl,omitempty"`
	Capped   bool         `json:"ttl_capped,omitempty"`
}

// ErrorBody is the body of every error response.
type ErrorBody struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

const maxBody = 64 << 10

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr maps service errors to statuses. Messages are fixed strings or
// error texts that carry no value.
func writeErr(w http.ResponseWriter, err error) {
	status, code := http.StatusInternalServerError, "internal"
	switch {
	case errors.Is(err, ErrTokenInvalid), errors.Is(err, ErrTokenMismatch):
		status, code = http.StatusForbidden, "token_invalid"
	case errors.Is(err, ErrTokenExpired):
		status, code = http.StatusGone, "token_expired"
	case errors.Is(err, ErrSettled):
		status, code = http.StatusConflict, "already_decided"
	case errors.Is(err, ErrExpired):
		status, code = http.StatusGone, "expired"
	case errors.Is(err, state.ErrNotFound):
		status, code = http.StatusNotFound, "not_found"
	case errors.Is(err, state.ErrConflict):
		status, code = http.StatusConflict, "conflict"
	case errors.Is(err, breakglass.ErrActive):
		status, code = http.StatusForbidden, "deny_all"
	case errors.Is(err, breakglass.ErrConfigured):
		status, code = http.StatusConflict, "deny_all_configured"
	case errors.Is(err, errBadRequest):
		status, code = http.StatusBadRequest, "bad_request"
	case errors.Is(err, errUnauthenticated):
		status, code = http.StatusUnauthorized, "unauthenticated"
	}
	msg := err.Error()
	if status == http.StatusInternalServerError {
		msg = "internal error"
	}
	writeJSON(w, status, ErrorBody{Error: msg, Code: code})
}

var (
	errBadRequest      = errors.New("bad request")
	errUnauthenticated = errors.New("no operator identity on this request")
)

// DecisionHandler serves GET and POST on [DecidePath].
func (s *Service) DecisionHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/approvals/{id}/decide", s.confirmPage)
	mux.HandleFunc("POST /v1/approvals/{id}/decide", s.decideByToken)
	return mux
}

var page = template.Must(template.New("decide").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>scrim approval</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:36rem;margin:2rem auto;padding:0 1rem}
dt{font-weight:600}dd{margin:0 0 .5rem;word-break:break-all}button{font-size:1.1rem;padding:.6rem 1.4rem}</style></head>
<body><h1>{{if eq .Action "approve"}}Approve{{else}}Deny{{end}} this request?</h1>
{{if .Err}}<p><strong>{{.Err}}</strong></p>{{end}}
<dl>
<dt>Agent</dt><dd>{{.A.Agent}}</dd>
{{if .A.Ref}}<dt>Secret</dt><dd>{{.A.Ref}}</dd>{{end}}
{{if .A.Host}}<dt>Destination</dt><dd>{{.A.Method}} {{.A.Host}}{{.A.Path}}</dd>{{end}}
{{if .A.Tool}}<dt>Tool</dt><dd>{{.A.Tool}} {{.A.Command}}</dd>{{end}}
<dt>Rule</dt><dd>{{.A.Rule}}</dd>
{{if .A.Reason}}<dt>Reason</dt><dd>{{.A.Reason}}</dd>{{end}}
<dt>Status</dt><dd>{{.A.Status}}, expires {{.A.ExpiresAt.Format "2006-01-02 15:04:05 MST"}}</dd>
</dl>
{{if eq .A.Status "pending"}}{{if not .Err}}<form method="post"><input type="hidden" name="t" value="{{.Token}}">
<button type="submit">{{if eq .Action "approve"}}Approve{{else}}Deny{{end}}</button></form>{{end}}{{end}}
</body></html>`))

// confirmPage shows what the link would decide. It changes nothing.
func (s *Service) confirmPage(w http.ResponseWriter, r *http.Request) {
	id, tok := r.PathValue("id"), r.URL.Query().Get("t")
	c, err := s.o.Signer.Verify(tok, id, s.o.Now())
	if err != nil {
		writeErr(w, err)
		return
	}
	a, err := s.get(r.Context(), id)
	if err != nil {
		writeErr(w, err)
		return
	}
	data := struct {
		A      ApprovalView
		Action Action
		Token  string
		Err    string
	}{A: ViewOf(a), Action: c.Action, Token: tok}
	if a.Status != state.ApprovalPending {
		data.Err = "This request is already " + string(a.Status) + "."
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
	w.Header().Set("X-Frame-Options", "DENY")
	_ = page.Execute(w, data)
}

func (s *Service) decideByToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	tok := r.URL.Query().Get("t")
	if tok == "" {
		_ = r.ParseForm()
		tok = r.PostForm.Get("t")
	}
	out, err := s.DecideToken(r.Context(), r.PathValue("id"), tok)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result(out))
}

func result(out Outcome) DecisionResult {
	res := DecisionResult{Approval: ViewOf(&out.Approval), Capped: out.Capped}
	if out.Grant != nil {
		res.GrantID = out.Grant.ID
		res.GrantTTL = out.Grant.ExpiresAt.Sub(out.Grant.CreatedAt).String()
	}
	return res
}

// DecideBody is the body of the admin approve and deny calls.
type DecideBody struct {
	// TTL is a Go duration; empty means the rule's default.
	TTL    string `json:"ttl,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// ReasonBody is the body of revoke and deny-all calls.
type ReasonBody struct {
	Reason string `json:"reason,omitempty"`
}

// DenyAllBody is the body of POST /v1/deny-all.
type DenyAllBody struct {
	Active bool   `json:"active"`
	Reason string `json:"reason,omitempty"`
}

// AdminHandler serves the operator API. operator returns the authenticated
// operator's name for a request, or false; it is the admin listener's job.
func AdminHandler(s *Service, g *grant.Service, bg *breakglass.Switch, operator func(*http.Request) (string, bool)) http.Handler {
	h := &admin{s: s, g: g, bg: bg}
	mux := http.NewServeMux()
	auth := func(fn func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			name, ok := "", false
			if operator != nil {
				name, ok = operator(r)
			}
			if !ok || name == "" {
				writeErr(w, errUnauthenticated)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBody)
			fn(w, r, name)
		}
	}
	mux.HandleFunc("GET /v1/approvals", auth(h.list))
	mux.HandleFunc("GET /v1/approvals/{id}", auth(h.get))
	mux.HandleFunc("POST /v1/approvals/{id}/approve", auth(h.decide(true)))
	mux.HandleFunc("POST /v1/approvals/{id}/deny", auth(h.decide(false)))
	mux.HandleFunc("GET /v1/grants", auth(h.grants))
	mux.HandleFunc("POST /v1/grants/{id}/revoke", auth(h.revoke))
	mux.HandleFunc("GET /v1/deny-all", auth(h.denyAllStatus))
	mux.HandleFunc("POST /v1/deny-all", auth(h.denyAll))
	return mux
}

type admin struct {
	s  *Service
	g  *grant.Service
	bg *breakglass.Switch
}

func decodeBody(r *http.Request, v any) error {
	if r.ContentLength == 0 {
		return nil
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", errBadRequest, err)
	}
	return nil
}

func (h *admin) list(w http.ResponseWriter, r *http.Request, _ string) {
	q := r.URL.Query()
	f := state.ApprovalFilter{Status: state.ApprovalStatus(q.Get("status")), AgentID: q.Get("agent")}
	switch f.Status {
	case "", state.ApprovalPending, state.ApprovalApproved, state.ApprovalDenied, state.ApprovalExpired:
	default:
		writeErr(w, fmt.Errorf("%w: unknown status", errBadRequest))
		return
	}
	if l := q.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 0 {
			writeErr(w, fmt.Errorf("%w: limit", errBadRequest))
			return
		}
		f.Limit = n
	}
	as, err := h.s.List(r.Context(), f)
	if err != nil {
		writeErr(w, err)
		return
	}
	out := make([]ApprovalView, 0, len(as))
	for i := range as {
		out = append(out, ViewOf(&as[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *admin) get(w http.ResponseWriter, r *http.Request, _ string) {
	a, err := h.s.Get(r.Context(), r.PathValue("id"), "")
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ViewOf(a))
}

func (h *admin) decide(approve bool) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, r *http.Request, op string) {
		var body DecideBody
		if err := decodeBody(r, &body); err != nil {
			writeErr(w, err)
			return
		}
		var ttl time.Duration
		if body.TTL != "" {
			var err error
			if ttl, err = time.ParseDuration(body.TTL); err != nil || ttl <= 0 {
				writeErr(w, fmt.Errorf("%w: ttl must be a positive duration", errBadRequest))
				return
			}
		}
		out, err := h.s.Decide(r.Context(), r.PathValue("id"), Decision{Approve: approve, By: op, Via: "api", TTL: ttl, Reason: body.Reason})
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, result(out))
	}
}

func (h *admin) grants(w http.ResponseWriter, r *http.Request, _ string) {
	if h.g == nil {
		writeErr(w, state.ErrNotFound)
		return
	}
	q := r.URL.Query()
	gs, err := h.g.List(r.Context(), q.Get("agent"), q.Get("active") != "false")
	if err != nil {
		writeErr(w, err)
		return
	}
	now := h.s.o.Now()
	out := make([]GrantView, 0, len(gs))
	for i := range gs {
		out = append(out, GrantViewOf(&gs[i], now))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *admin) revoke(w http.ResponseWriter, r *http.Request, op string) {
	var body ReasonBody
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, err)
		return
	}
	if h.g == nil {
		writeErr(w, state.ErrNotFound)
		return
	}
	id := r.PathValue("id")
	if err := h.g.Revoke(r.Context(), id, op, body.Reason); err != nil {
		writeErr(w, err)
		return
	}
	g, err := h.g.Get(r.Context(), id, "")
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, GrantViewOf(g, h.s.o.Now()))
}

func (h *admin) denyAllStatus(w http.ResponseWriter, _ *http.Request, _ string) {
	if h.bg == nil {
		writeErr(w, state.ErrNotFound)
		return
	}
	writeJSON(w, http.StatusOK, h.bg.Status())
}

func (h *admin) denyAll(w http.ResponseWriter, r *http.Request, op string) {
	var body DenyAllBody
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, err)
		return
	}
	if h.bg == nil {
		writeErr(w, state.ErrNotFound)
		return
	}
	var err error
	if body.Active {
		err = h.bg.Engage(r.Context(), op, body.Reason)
		if err == nil {
			_, err = h.s.DenyAllPending(r.Context(), op)
		}
	} else {
		err = h.bg.Release(r.Context(), op, body.Reason)
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h.bg.Status())
}
