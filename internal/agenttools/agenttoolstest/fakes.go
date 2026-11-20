// SPDX-License-Identifier: AGPL-3.0-only

// Package agenttoolstest holds in-memory fakes of the services the agent
// tools depend on, and a leak checker, for tests across the local API, the
// MCP server, the CLI and the entry page. Values in these fakes are
// generated test values, never real secrets.
package agenttoolstest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/agenttools"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/secret"
)

// Rule is one fake policy rule: the first rule whose agent (empty matches
// any), tool (empty matches any) and ref prefix match decides.
type Rule struct {
	Agent  string
	Tool   string
	Prefix string
	Effect agenttools.Effect
}

// Policy is a fake policy over a rule list. No match denies.
type Policy struct {
	mu    sync.Mutex
	Rules []Rule
	// Grants, when set, turns an ask into allow for a principal holding an
	// active grant on the ref.
	Grants *Approvals
	Err    error
}

// Decide implements agenttools.Policy.
func (p *Policy) Decide(_ context.Context, id identity.Identity, op agenttools.Operation) (agenttools.Decision, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Err != nil {
		return agenttools.Decision{}, p.Err
	}
	for i, r := range p.Rules {
		if (r.Agent == "" || r.Agent == id.Agent) && (r.Tool == "" || r.Tool == op.Tool) && strings.HasPrefix(op.Ref, r.Prefix) {
			eff := r.Effect
			if eff == agenttools.EffectAsk && p.Grants != nil && p.Grants.holds(id.Principal(), op.Ref) {
				eff = agenttools.EffectAllow
			}
			return agenttools.Decision{Effect: eff, Rule: fmt.Sprintf("rule-%d", i), Reason: "test rule"}, nil
		}
	}
	return agenttools.Decision{Effect: agenttools.EffectDeny, Rule: "default", Reason: "no rule matches"}, nil
}

// SetRules replaces the rules.
func (p *Policy) SetRules(r ...Rule) { p.mu.Lock(); p.Rules = r; p.mu.Unlock() }

type approval struct {
	owner string
	ref   string
	dur   time.Duration
	state agenttools.ApprovalState
}

// Approvals is a fake approval service: refs under AskPrefix go pending,
// refs under DenyPrefix are denied, everything else is granted. Durations
// above Max are capped.
type Approvals struct {
	mu         sync.Mutex
	AskPrefix  string
	DenyPrefix string
	Max        time.Duration
	Now        func() time.Time
	n          int
	approvals  map[string]*approval
	grants     map[string][]agenttools.Grant // by principal
}

func (a *Approvals) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Approvals) init() {
	if a.approvals == nil {
		a.approvals, a.grants = map[string]*approval{}, map[string][]agenttools.Grant{}
	}
}

// Request implements agenttools.Approvals.
func (a *Approvals) Request(_ context.Context, id identity.Identity, r agenttools.GrantRequest) (agenttools.GrantResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.init()
	dur, capped := r.Duration, false
	if dur == 0 {
		dur = 15 * time.Minute
	}
	if a.Max > 0 && dur > a.Max {
		dur, capped = a.Max, true
	}
	a.n++
	switch {
	case a.DenyPrefix != "" && strings.HasPrefix(r.Ref, a.DenyPrefix):
		return agenttools.GrantResult{Status: agenttools.StatusDenied, Reason: "denied by test rule"}, nil
	case a.AskPrefix != "" && strings.HasPrefix(r.Ref, a.AskPrefix):
		aid := fmt.Sprintf("apr_%04d", a.n)
		a.approvals[aid] = &approval{owner: id.Principal(), ref: r.Ref, dur: dur,
			state: agenttools.ApprovalState{Status: agenttools.ApprovalPending, Ref: r.Ref}}
		return agenttools.GrantResult{Status: agenttools.StatusPending, ApprovalID: aid, Duration: dur, Capped: capped}, nil
	default:
		g := a.grant(id.Principal(), r.Ref, dur)
		return agenttools.GrantResult{Status: agenttools.StatusGranted, GrantID: g.ID, ExpiresAt: g.ExpiresAt,
			Duration: dur, Capped: capped}, nil
	}
}

func (a *Approvals) grant(owner, ref string, dur time.Duration) agenttools.Grant {
	one := 3
	g := agenttools.Grant{ID: fmt.Sprintf("grt_%04d", a.n), Ref: ref, Scope: []string{"api.example.test"},
		ExpiresAt: a.now().Add(dur), RemainingUses: &one}
	a.grants[owner] = append(a.grants[owner], g)
	return g
}

// Settle approves or denies a pending approval, as a human would.
func (a *Approvals) Settle(aid string, approve bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.init()
	ap, ok := a.approvals[aid]
	if !ok || ap.state.Status != agenttools.ApprovalPending {
		return errors.New("no pending approval")
	}
	if !approve {
		ap.state.Status = agenttools.ApprovalDenied
		return nil
	}
	a.n++
	g := a.grant(ap.owner, ap.ref, ap.dur)
	ap.state = agenttools.ApprovalState{Status: agenttools.ApprovalApproved, Ref: ap.ref, GrantID: g.ID, ExpiresAt: g.ExpiresAt}
	return nil
}

// Approval implements agenttools.Approvals.
func (a *Approvals) Approval(_ context.Context, id identity.Identity, aid string) (agenttools.ApprovalState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.init()
	ap, ok := a.approvals[aid]
	if !ok || ap.owner != id.Principal() {
		return agenttools.ApprovalState{}, agenttools.ErrNotFound
	}
	return ap.state, nil
}

// Grants implements agenttools.Approvals.
func (a *Approvals) Grants(_ context.Context, id identity.Identity) ([]agenttools.Grant, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.init()
	return slices.Clone(a.grants[id.Principal()]), nil
}

func (a *Approvals) holds(principal, ref string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.init()
	for _, g := range a.grants[principal] {
		if g.Ref == ref && a.now().Before(g.ExpiresAt) {
			return true
		}
	}
	return false
}

// Store is a fake store and catalog. It keeps values so tests can check what
// was written; nothing in the tools can read them back.
type Store struct {
	mu      sync.Mutex
	Default string
	values  map[string][]byte
	info    map[string]agenttools.SecretInfo
	// WriteErr, when set, fails every write with this error.
	WriteErr error
	// Writers records the principal of every write.
	Writers []string
}

// NewStore returns a store whose default store name is "bao".
func NewStore() *Store {
	return &Store{Default: "bao", values: map[string][]byte{}, info: map[string]agenttools.SecretInfo{}}
}

// Seed puts a value and its metadata in the store, as if it already existed.
func (s *Store) Seed(info agenttools.SecretInfo, value []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if info.Store == "" {
		info.Store = s.Default
	}
	info.Placeholder = Placeholder(info.Ref)
	s.values[info.Ref] = bytes.Clone(value)
	s.info[info.Ref] = info
}

// Value returns what was stored at ref, for test assertions only.
func (s *Store) Value(ref string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.values[ref]
	return bytes.Clone(v), ok
}

// Placeholder is the fake placeholder for a ref.
func Placeholder(ref string) string {
	slug := strings.NewReplacer("://", "-", "/", "-", "#", "-").Replace(ref)
	return "⟦scrim:" + slug + ":test⟧"
}

// Write implements agenttools.Store.
func (s *Store) Write(_ context.Context, id identity.Identity, w agenttools.Write) (agenttools.Written, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.WriteErr != nil {
		return agenttools.Written{}, s.WriteErr
	}
	if _, ok := s.values[w.Ref]; ok && !w.Overwrite {
		return agenttools.Written{}, agenttools.ErrExists
	}
	store := w.Store
	if store == "" {
		store = s.Default
	}
	var v []byte
	if err := w.Value.Expose(func(b []byte) error { v = bytes.Clone(b); return nil }); err != nil {
		return agenttools.Written{}, err
	}
	s.values[w.Ref] = v
	s.info[w.Ref] = agenttools.SecretInfo{Ref: w.Ref, Store: store, Placeholder: Placeholder(w.Ref)}
	s.Writers = append(s.Writers, id.Principal())
	return agenttools.Written{Ref: w.Ref, Store: store, Placeholder: Placeholder(w.Ref)}, nil
}

// List implements agenttools.Catalog.
func (s *Store) List(context.Context, identity.Identity, agenttools.ListInput) ([]agenttools.SecretInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]agenttools.SecretInfo, 0, len(s.info))
	for _, i := range s.info {
		out = append(out, i)
	}
	slices.SortFunc(out, func(a, b agenttools.SecretInfo) int { return strings.Compare(a.Ref, b.Ref) })
	return out, nil
}

// Audit records entries.
type Audit struct {
	mu      sync.Mutex
	Entries []agenttools.AuditEntry
	Err     error
}

// Record implements agenttools.Auditor.
func (a *Audit) Record(_ context.Context, e agenttools.AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.Err != nil {
		return a.Err
	}
	a.Entries = append(a.Entries, e)
	return nil
}

// All returns a copy of the entries.
func (a *Audit) All() []agenttools.AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.Entries)
}

// Last returns the last entry.
func (a *Audit) Last() agenttools.AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.Entries) == 0 {
		return agenttools.AuditEntry{}
	}
	return a.Entries[len(a.Entries)-1]
}

// Notifier captures notices.
type Notifier struct {
	mu      sync.Mutex
	Notices []agenttools.Notice
	Err     error
	ch      chan agenttools.Notice
}

// NotifyAsk implements agenttools.Notifier.
func (n *Notifier) NotifyAsk(_ context.Context, x agenttools.Notice) error {
	n.mu.Lock()
	if n.Err != nil {
		n.mu.Unlock()
		return n.Err
	}
	n.Notices = append(n.Notices, x)
	ch := n.ch
	n.mu.Unlock()
	if ch != nil {
		ch <- x
	}
	return nil
}

// Chan returns a channel that receives every later notice.
func (n *Notifier) Chan() <-chan agenttools.Notice {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.ch == nil {
		n.ch = make(chan agenttools.Notice, 16)
	}
	return n.ch
}

// Links builds entry URLs on a fixed base.
type Links struct{ Base string }

// EntryURL implements agenttools.EntryLinks.
func (l Links) EntryURL(tok string) (string, error) { return l.Base + "/entry/" + tok, nil }

// TokenOf returns the token at the end of an entry URL.
func TokenOf(url string) string { return url[strings.LastIndexByte(url, '/')+1:] }

// Env is a Service wired to fakes.
type Env struct {
	Service   *agenttools.Service
	Policy    *Policy
	Approvals *Approvals
	Store     *Store
	Audit     *Audit
	Notifier  *Notifier
}

// NewEnv returns a Service over fresh fakes. Policy allows everything under
// bao://kv/agents/ and denies the rest; Approvals asks under
// bao://kv/agents/ask/ and denies under bao://kv/agents/deny/.
func NewEnv(t testing.TB) *Env {
	t.Helper()
	ap := &Approvals{AskPrefix: "bao://kv/agents/ask/", DenyPrefix: "bao://kv/agents/deny/", Max: 2 * time.Hour}
	e := &Env{
		Policy:    &Policy{Rules: []Rule{{Prefix: "bao://kv/agents/", Effect: agenttools.EffectAllow}}, Grants: ap},
		Approvals: ap,
		Store:     NewStore(),
		Audit:     &Audit{},
		Notifier:  &Notifier{},
	}
	svc, err := agenttools.New(agenttools.Deps{Policy: e.Policy, Approvals: ap, Catalog: e.Store, Store: e.Store,
		Auditor: e.Audit, Notifier: e.Notifier, Links: Links{Base: "http://127.0.0.1:1"}})
	if err != nil {
		t.Fatal(err)
	}
	e.Service = svc
	return e
}

// Agent returns a peer identity with every agent scope.
func Agent(name string, uid uint32) identity.Identity {
	return identity.Identity{Agent: name, Source: identity.SourcePeer, Peer: identity.Peer{UID: uid, GID: uid, PID: 4242},
		Scopes: slices.Clone(identity.AgentScopes)}
}

// Session returns a session identity.
func Session(name, sessionID string, uid uint32) identity.Identity {
	id := Agent(name, uid)
	id.Source, id.SessionID = identity.SourceSession, sessionID
	return id
}

// Variants returns v as it could appear in output: raw, JSON-escaped,
// base64 (standard and URL, padded and not) and hex in both cases.
func Variants(v []byte) [][]byte {
	js, _ := json.Marshal(string(v))
	out := [][]byte{
		bytes.Clone(v),
		js[1 : len(js)-1],
		[]byte(base64.StdEncoding.EncodeToString(v)),
		[]byte(base64.RawStdEncoding.EncodeToString(v)),
		[]byte(base64.URLEncoding.EncodeToString(v)),
		[]byte(base64.RawURLEncoding.EncodeToString(v)),
		[]byte(hex.EncodeToString(v)),
		[]byte(strings.ToUpper(hex.EncodeToString(v))),
	}
	return out
}

// AssertNoValues fails t if data contains any of values in any variant.
func AssertNoValues(t testing.TB, where string, data []byte, values ...[]byte) {
	t.Helper()
	for _, v := range values {
		for _, x := range Variants(v) {
			if len(x) > 0 && bytes.Contains(data, x) {
				t.Errorf("%s contains a seeded value (variant of %d bytes)", where, len(x))
			}
		}
	}
}

// Value returns a fresh secret.Value of s.
func Value(s string) secret.Value { return secret.FromString(s) }
