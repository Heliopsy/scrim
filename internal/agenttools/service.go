// SPDX-License-Identifier: AGPL-3.0-only

package agenttools

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/secret"
)

// MaxRequestDuration bounds the duration a caller can ask for. The approval
// service caps grants further per rule.
const MaxRequestDuration = 31 * 24 * time.Hour

// Deps are what a Service is built from. Policy, Approvals, Catalog, Store
// and Auditor are required; Notifier and Links are needed for
// secret_ask_human only.
type Deps struct {
	Policy    Policy
	Approvals Approvals
	Catalog   Catalog
	Store     Store
	Auditor   Auditor
	Notifier  Notifier
	Links     EntryLinks
	Logger    *slog.Logger
	Now       func() time.Time
	Rand      io.Reader
}

// Service implements every agent tool.
type Service struct {
	d    Deps
	asks *asks
}

// New returns a Service.
func New(d Deps) (*Service, error) {
	var missing []string
	for name, dep := range map[string]any{"policy": d.Policy, "approvals": d.Approvals,
		"catalog": d.Catalog, "store": d.Store, "auditor": d.Auditor} {
		if dep == nil {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return nil, errors.New("agenttools: missing dependencies: " + strings.Join(missing, ", "))
	}
	if d.Logger == nil {
		d.Logger = slog.New(slog.DiscardHandler)
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	s := &Service{d: d}
	s.asks = newAsks(d.Now, d.Rand)
	return s, nil
}

// scopeFor is the scope each tool needs.
var scopeFor = map[string]identity.Scope{
	ToolSecretsList:    identity.ScopeSecretsList,
	ToolSecretRequest:  identity.ScopeSecretsRequest,
	ToolApprovalStatus: identity.ScopeSecretsRequest,
	ToolGrantsList:     identity.ScopeSecretsRequest,
	ToolSecretGen:      identity.ScopeSecretsWrite,
	ToolSecretCapture:  identity.ScopeSecretsWrite,
	ToolSecretAskHuman: identity.ScopeSecretsWrite,
	ToolSecretPut:      identity.ScopeSecretsWrite,
}

// call is one tool invocation being audited.
type call struct {
	s     *Service
	id    identity.Identity
	entry AuditEntry
}

func (s *Service) begin(id identity.Identity, tool, ref, store string) *call {
	return &call{s: s, id: id, entry: AuditEntry{
		Agent: id.Agent, Principal: id.Principal(), Source: string(id.Source),
		SessionID: id.SessionID, UID: id.Peer.UID, PID: id.Peer.PID,
		Tool: tool, Ref: ref, Store: store,
	}}
}

// authorize checks identity and scope.
func (c *call) authorize() error {
	if !c.id.Known() {
		return Errorf(CodeUnauthenticated, "the caller has no agent identity")
	}
	if !c.id.Has(scopeFor[c.entry.Tool]) {
		return Errorf(CodeForbidden, "the caller's identity lacks scope %s", scopeFor[c.entry.Tool])
	}
	return nil
}

// decide evaluates policy for the call's operation.
func (c *call) decide(ctx context.Context) error {
	d, err := c.s.d.Policy.Decide(ctx, c.id, Operation{Tool: c.entry.Tool, Ref: c.entry.Ref, Store: c.entry.Store})
	if err != nil {
		c.s.d.Logger.Warn("policy evaluation failed", "tool", c.entry.Tool, "ref", c.entry.Ref, "error", err)
		return Errorf(CodeUnavailable, "policy could not be evaluated")
	}
	c.entry.Decision, c.entry.Rule = string(d.Effect), d.Rule
	switch d.Effect {
	case EffectAllow:
		return nil
	case EffectAsk:
		return Errorf(CodeNeedsApproval, "policy requires approval for %s on %s; call secret_request for it first", c.entry.Tool, c.entry.Ref)
	default:
		if d.Reason != "" {
			return Errorf(CodeDenied, "denied by policy: %s", d.Reason)
		}
		return Errorf(CodeDenied, "denied by policy")
	}
}

// finish records the audit entry. A call whose audit entry cannot be written
// fails, so nothing an agent does goes unrecorded.
func (c *call) finish(ctx context.Context, err error) error {
	c.entry.Time = c.s.d.Now().UTC()
	if c.entry.Outcome == "" {
		switch CodeOf(err) {
		case "":
		case CodeDenied, CodeForbidden, CodeNeedsApproval:
			c.entry.Outcome = OutcomeDenied
		case CodeUnauthenticated:
			c.entry.Outcome = OutcomeRefused
		default:
			c.entry.Outcome = OutcomeError
		}
		if err == nil {
			c.entry.Outcome = OutcomeOK
		}
	}
	if err != nil && c.entry.Detail == "" {
		c.entry.Detail = string(CodeOf(err))
	}
	if aerr := c.s.d.Auditor.Record(ctx, c.entry); aerr != nil {
		c.s.d.Logger.Error("audit write failed", "tool", c.entry.Tool, "ref", c.entry.Ref, "error", aerr)
		if err == nil {
			return Errorf(CodeUnavailable, "the audit log is unavailable")
		}
	}
	if err != nil {
		return Public(err)
	}
	return nil
}

// List implements secrets_list.
func (s *Service) List(ctx context.Context, id identity.Identity, in ListInput) (ListOutput, error) {
	c := s.begin(id, ToolSecretsList, in.Prefix, in.Store)
	out, err := s.list(ctx, c, in)
	return out, c.finish(ctx, err)
}

func (s *Service) list(ctx context.Context, c *call, in ListInput) (ListOutput, error) {
	if err := c.authorize(); err != nil {
		return ListOutput{}, err
	}
	if err := checkStore(in.Store); err != nil {
		return ListOutput{}, err
	}
	if len(in.Prefix) > maxRefLen || len(in.Binding) > 255 {
		return ListOutput{}, Errorf(CodeInvalid, "prefix or binding is too long")
	}
	all, err := s.d.Catalog.List(ctx, c.id, in)
	if err != nil {
		s.d.Logger.Warn("listing secrets failed", "error", err)
		return ListOutput{}, Errorf(CodeUnavailable, "the secret catalog is unavailable")
	}
	out := ListOutput{Secrets: []SecretInfo{}}
	for _, info := range all {
		if in.Store != "" && info.Store != in.Store ||
			in.Prefix != "" && !strings.HasPrefix(info.Ref, in.Prefix) ||
			in.Binding != "" && !contains(info.Bindings, in.Binding) {
			continue
		}
		d, err := s.d.Policy.Decide(ctx, c.id, Operation{Tool: ToolSecretsList, Ref: info.Ref, Store: info.Store})
		if err != nil {
			s.d.Logger.Warn("policy evaluation failed", "tool", ToolSecretsList, "ref", info.Ref, "error", err)
			return ListOutput{}, Errorf(CodeUnavailable, "policy could not be evaluated")
		}
		if d.Effect == EffectDeny {
			continue
		}
		out.Secrets = append(out.Secrets, info)
	}
	c.entry.Detail = "listed"
	return out, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// Request implements secret_request.
func (s *Service) Request(ctx context.Context, id identity.Identity, in RequestInput) (RequestOutput, error) {
	c := s.begin(id, ToolSecretRequest, in.Ref, "")
	out, err := s.request(ctx, c, in)
	return out, c.finish(ctx, err)
}

func (s *Service) request(ctx context.Context, c *call, in RequestInput) (RequestOutput, error) {
	if err := c.authorize(); err != nil {
		return RequestOutput{}, err
	}
	if err := checkRef(in.Ref); err != nil {
		return RequestOutput{}, err
	}
	var dur time.Duration
	if in.Duration != "" {
		d, err := time.ParseDuration(in.Duration)
		if err != nil || d <= 0 || d > MaxRequestDuration {
			return RequestOutput{}, Errorf(CodeInvalid, "duration must be a positive Go duration up to %s, such as 30m", MaxRequestDuration)
		}
		dur = d
	}
	reason := strings.TrimSpace(in.Reason)
	if reason == "" {
		return RequestOutput{}, Errorf(CodeInvalid, "reason is required")
	}
	if len(reason) > 1024 {
		return RequestOutput{}, Errorf(CodeInvalid, "reason is longer than 1024 bytes")
	}
	r, err := s.d.Approvals.Request(ctx, c.id, GrantRequest{Ref: in.Ref, Duration: dur, Reason: reason})
	if err != nil {
		s.d.Logger.Warn("grant request failed", "ref", in.Ref, "error", err)
		return RequestOutput{}, Errorf(CodeUnavailable, "the approval service is unavailable")
	}
	out := RequestOutput{Status: r.Status, Ref: in.Ref, ApprovalID: r.ApprovalID, GrantID: r.GrantID,
		ExpiresAt: r.ExpiresAt.UTC(), Capped: r.Capped}
	if r.Duration > 0 {
		out.Duration = r.Duration.String()
	}
	c.entry.ApprovalID, c.entry.GrantID, c.entry.Decision = r.ApprovalID, r.GrantID, r.Status
	switch r.Status {
	case StatusGranted:
		c.entry.Outcome = OutcomeOK
	case StatusPending:
		c.entry.Outcome = OutcomePending
	case StatusDenied:
		c.entry.Outcome = OutcomeDenied
		out.Reason = r.Reason
	default:
		s.d.Logger.Error("approval service returned an unknown status", "status", r.Status)
		return RequestOutput{}, Errorf(CodeInternal, "the approval service returned an unknown status")
	}
	return out, nil
}

// Status implements approval_status for both approvals and asks.
func (s *Service) Status(ctx context.Context, id identity.Identity, in StatusInput) (StatusOutput, error) {
	c := s.begin(id, ToolApprovalStatus, "", "")
	out, err := s.status(ctx, c, in)
	return out, c.finish(ctx, err)
}

func (s *Service) status(ctx context.Context, c *call, in StatusInput) (StatusOutput, error) {
	if err := c.authorize(); err != nil {
		return StatusOutput{}, err
	}
	if in.ID == "" || len(in.ID) > 128 {
		return StatusOutput{}, Errorf(CodeInvalid, "id is required")
	}
	if isAskID(in.ID) {
		c.entry.Tool = ToolApprovalStatus
		a, err := s.asks.status(c.id.Principal(), in.ID)
		if err != nil {
			return StatusOutput{}, err
		}
		c.entry.Ref, c.entry.Detail = a.Ref, "ask "+a.Status
		return StatusOutput{ID: a.ID, Kind: "ask", Status: a.Status, Ref: a.Ref, ExpiresAt: a.ExpiresAt}, nil
	}
	c.entry.ApprovalID = in.ID
	st, err := s.d.Approvals.Approval(ctx, c.id, in.ID)
	if errors.Is(err, ErrNotFound) {
		return StatusOutput{}, Errorf(CodeNotFound, "no approval %s", in.ID)
	}
	if err != nil {
		s.d.Logger.Warn("approval lookup failed", "approval", in.ID, "error", err)
		return StatusOutput{}, Errorf(CodeUnavailable, "the approval service is unavailable")
	}
	c.entry.Ref, c.entry.GrantID, c.entry.Detail = st.Ref, st.GrantID, "approval "+st.Status
	return StatusOutput{ID: in.ID, Kind: "approval", Status: st.Status, Ref: st.Ref, GrantID: st.GrantID,
		ExpiresAt: st.ExpiresAt.UTC()}, nil
}

// Grants implements grants_list.
func (s *Service) Grants(ctx context.Context, id identity.Identity) (GrantsOutput, error) {
	c := s.begin(id, ToolGrantsList, "", "")
	out, err := s.grants(ctx, c)
	return out, c.finish(ctx, err)
}

func (s *Service) grants(ctx context.Context, c *call) (GrantsOutput, error) {
	if err := c.authorize(); err != nil {
		return GrantsOutput{}, err
	}
	gs, err := s.d.Approvals.Grants(ctx, c.id)
	if err != nil {
		s.d.Logger.Warn("listing grants failed", "error", err)
		return GrantsOutput{}, Errorf(CodeUnavailable, "the approval service is unavailable")
	}
	if gs == nil {
		gs = []Grant{}
	}
	for i := range gs {
		gs[i].ExpiresAt = gs[i].ExpiresAt.UTC()
	}
	return GrantsOutput{Grants: gs}, nil
}

// Check reports whether a write would be allowed, without writing. The
// capture path calls it before running the command, so a token-creating
// command is not run only to have its output refused.
func (s *Service) Check(ctx context.Context, id identity.Identity, in CheckInput) (CheckOutput, error) {
	switch in.Tool {
	case ToolSecretCapture, ToolSecretPut, ToolSecretGen, ToolSecretAskHuman:
	default:
		return CheckOutput{}, Errorf(CodeInvalid, "check applies to secret_capture, secret_put, secret_gen and secret_ask_human")
	}
	c := s.begin(id, in.Tool, in.Ref, in.Store)
	c.entry.Detail = "check"
	err := c.authorize()
	if err == nil {
		err = checkRef(in.Ref)
	}
	if err == nil {
		err = checkStore(in.Store)
	}
	if err == nil {
		err = c.decide(ctx)
	}
	switch CodeOf(err) {
	case CodeDenied, CodeNeedsApproval, CodeForbidden:
		c.entry.Outcome = OutcomeDenied
		if ferr := c.finish(ctx, nil); ferr != nil {
			return CheckOutput{}, ferr
		}
		return CheckOutput{Allowed: false, Reason: Public(err).Message}, nil
	}
	if err != nil {
		return CheckOutput{}, c.finish(ctx, err)
	}
	return CheckOutput{Allowed: true}, c.finish(ctx, nil)
}

// Generate implements secret_gen. The value is made here, stored, and wiped;
// only where it went is returned.
func (s *Service) Generate(ctx context.Context, id identity.Identity, in GenInput) (WriteOutput, error) {
	c := s.begin(id, ToolSecretGen, in.Ref, in.Store)
	out, err := s.generate(ctx, c, in)
	return out, c.finish(ctx, err)
}

func (s *Service) generate(ctx context.Context, c *call, in GenInput) (WriteOutput, error) {
	if err := c.authorize(); err != nil {
		return WriteOutput{}, err
	}
	if err := checkRef(in.Ref); err != nil {
		return WriteOutput{}, err
	}
	if err := checkStore(in.Store); err != nil {
		return WriteOutput{}, err
	}
	spec, err := NormalizeGen(in)
	if err != nil {
		return WriteOutput{}, err
	}
	if err := c.decide(ctx); err != nil {
		return WriteOutput{}, err
	}
	v, err := Generate(spec, s.d.Rand)
	if err != nil {
		s.d.Logger.Error("generating a value failed", "error", err)
		return WriteOutput{}, Errorf(CodeInternal, "generating the value failed")
	}
	defer v.Wipe()
	c.entry.Detail = "format " + spec.Format
	return s.write(ctx, c, Write{Ref: in.Ref, Store: in.Store, Value: v, Overwrite: in.Overwrite})
}

// Put stores a value that arrived on standard input (`scrim secret put`) or
// was extracted by secret_capture in the tool process. The value is wiped
// before Put returns, whatever the outcome.
func (s *Service) Put(ctx context.Context, id identity.Identity, in PutInput, v secret.Value) (WriteOutput, error) {
	defer v.Wipe()
	tool := ToolSecretPut
	if in.Origin == ToolSecretCapture {
		tool = ToolSecretCapture
	}
	c := s.begin(id, tool, in.Ref, in.Store)
	out, err := s.put(ctx, c, in, v)
	return out, c.finish(ctx, err)
}

func (s *Service) put(ctx context.Context, c *call, in PutInput, v secret.Value) (WriteOutput, error) {
	if err := c.authorize(); err != nil {
		return WriteOutput{}, err
	}
	if in.Origin != "" && in.Origin != ToolSecretPut && in.Origin != ToolSecretCapture {
		return WriteOutput{}, Errorf(CodeInvalid, "origin must be secret_put or secret_capture")
	}
	if err := checkRef(in.Ref); err != nil {
		return WriteOutput{}, err
	}
	if err := checkStore(in.Store); err != nil {
		return WriteOutput{}, err
	}
	if v.IsZero() {
		return WriteOutput{}, Errorf(CodeInvalid, "the value is empty")
	}
	if v.Len() > MaxValueSize {
		return WriteOutput{}, Errorf(CodeInvalid, "the value is larger than %d bytes", MaxValueSize)
	}
	if err := c.decide(ctx); err != nil {
		return WriteOutput{}, err
	}
	return s.write(ctx, c, Write{Ref: in.Ref, Store: in.Store, Value: v, Overwrite: in.Overwrite})
}

// write stores a value through the Store and shapes the result. A store
// error whose text contains the value is withheld even from the log.
func (s *Service) write(ctx context.Context, c *call, w Write) (WriteOutput, error) {
	got, err := s.d.Store.Write(ctx, c.id, w)
	if errors.Is(err, ErrExists) {
		return WriteOutput{}, Errorf(CodeConflict, "a secret already exists at %s; pass overwrite to replace it", w.Ref)
	}
	if err != nil {
		s.d.Logger.Warn("store write failed", "ref", w.Ref, "store", w.Store, "error", withheld(err, w.Value))
		return WriteOutput{}, Errorf(CodeUnavailable, "the store write failed; nothing about the value is returned")
	}
	c.entry.Ref, c.entry.Store = got.Ref, got.Store
	return WriteOutput{Status: StatusStored, Ref: got.Ref, Store: got.Store,
		Placeholder: got.Placeholder, Length: w.Value.Len()}, nil
}

// withheld returns err unless its text contains v, in which case it returns
// a marker error instead.
func withheld(err error, v secret.Value) error {
	msg := err.Error()
	leak := false
	_ = v.Expose(func(b []byte) error {
		leak = len(b) > 0 && bytes.Contains([]byte(msg), b)
		return nil
	})
	if leak {
		return errors.New("error text withheld: it contained the value")
	}
	return err
}
