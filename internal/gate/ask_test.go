// SPDX-License-Identifier: AGPL-3.0-only

package gate

import (
	"context"
	"fmt"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/heliopsy/scrim/internal/audit"
	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
	"github.com/heliopsy/scrim/internal/identity"
	"github.com/heliopsy/scrim/internal/policy"
	"github.com/heliopsy/scrim/internal/state"
)

// procs is a fake process table: init(1) -> scrim run (200) -> agent (201);
// init(1) -> other process of the same user (300).
type procs map[int32]identity.Proc

func (p procs) Lookup(pid int32) (identity.Proc, error) {
	if pr, ok := p[pid]; ok {
		return pr, nil
	}
	return identity.Proc{}, fmt.Errorf("no process %d", pid)
}

var machine = procs{
	1:   {PID: 1, Start: 1},
	200: {PID: 200, PPID: 1, Start: 20},
	201: {PID: 201, PPID: 200, Start: 21},
	300: {PID: 300, PPID: 1, Start: 30},
}

// withSessions gives the rig an identity resolver: uid 1000 maps to agent
// "dev", and one `scrim run` session (root pid 200) exists.
func withSessions(t *testing.T, r *rig) identity.Session {
	t.Helper()
	peers, err := identity.NewPeerMap([]identity.PeerRule{{Agent: "dev", UIDs: []uint32{1000}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	mgr := identity.NewManager(identity.NewMemorySessions(), identity.ManagerOptions{Procs: machine})
	r.g.Callers = &identity.Resolver{Peers: peers, Sessions: mgr}
	minter, _ := peers.Lookup(identity.Peer{UID: 1000, PID: 200})
	m, err := mgr.Mint(context.Background(), minter, identity.MintRequest{Name: "claude"})
	if err != nil {
		t.Fatal(err)
	}
	m.Token.Wipe()
	return m.Session
}

// proven is the caller the data plane sends for a request that carried s's
// token.
func proven(s identity.Session, a *pb.AskRequest) *pb.AskCaller {
	return &pb.AskCaller{SessionId: s.ID, SessionProof: identity.SessionProof(s.Hash, s.ID, a.GetId(), a.GetDeadlineUnixNano())}
}

func injectAsk(id uint64, method string) *pb.AskRequest {
	return &pb.AskRequest{Protocol: uint32(pb.ProtocolVersion_PROTOCOL_VERSION_CURRENT), Id: id, Request: &pb.PolicyRequest{
		Action: "inject", Ref: "bao://kv/agents/github", Host: "api.github.com", Method: method,
	}, DeadlineUnixNano: time.Now().Add(5 * time.Second).UnixNano()}
}

func TestAnswerDataPlaneAsk(t *testing.T) {
	r := newRig(t, rules)
	s := withSessions(t, r)
	ctx := context.Background()
	ask := func(id uint64, method string) *pb.AskRequest {
		a := injectAsk(id, method)
		a.Caller = proven(s, a)
		return a
	}
	if a := r.g.Answer(ctx, ask(7, "GET")); a.Effect != pb.Effect_EFFECT_ALLOW || a.Id != 7 {
		t.Fatalf("GET: %+v", a)
	}
	r.approveNext(t, 1, true)
	if a := r.g.Answer(ctx, ask(8, "POST")); a.Effect != pb.Effect_EFFECT_ALLOW || a.GrantId == "" || a.GrantExpiresUnixNano == 0 {
		t.Fatalf("approved POST: %+v", a)
	}
	// The approval and its grant belong to the session's principal.
	_ = r.st.View(ctx, func(tx state.Tx) error {
		as, err := tx.ListApprovals(ctx, state.ApprovalFilter{})
		if err != nil || len(as) != 1 || as[0].Request.Agent.ID != "dev" || as[0].Request.Agent.Session != s.ID {
			t.Errorf("approval owner: %+v %v", as, err)
		}
		return nil
	})
	bad := ask(9, "GET")
	bad.Protocol = 99
	if a := r.g.Answer(ctx, bad); a.Effect != pb.Effect_EFFECT_DENY {
		t.Fatalf("protocol mismatch allowed: %+v", a)
	}
	bad = ask(10, "GET")
	bad.Request.Ref = "not a ref"
	if a := r.g.Answer(ctx, bad); a.Effect != pb.Effect_EFFECT_DENY {
		t.Fatalf("bad ref allowed: %+v", a)
	}
	// A past deadline denies without waiting for a human.
	late := injectAsk(11, "PUT")
	late.Request.Ref = "bao://kv/agents/hetzner"
	late.DeadlineUnixNano = time.Now().Add(20 * time.Millisecond).UnixNano()
	late.Caller = proven(s, late)
	if a := r.g.Answer(ctx, late); a.Effect != pb.Effect_EFFECT_DENY {
		t.Fatalf("deadline: %+v", a)
	}
}

// TestAnswerResolvesTheCaller: the rules see the verified identity, and a
// caller that cannot be verified is evaluated as unknown (rule no-unknown
// denies) with the reason in the decision's audit entry.
func TestAnswerResolvesTheCaller(t *testing.T) {
	r := newRig(t, rules)
	s := withSessions(t, r)
	ctx := context.Background()
	var id uint64 = 100
	cases := []struct {
		name   string
		caller func(a *pb.AskRequest) *pb.AskCaller
		spoof  bool
		allow  bool
		attr   string
		reason string
	}{
		{name: "proven session", caller: func(a *pb.AskRequest) *pb.AskCaller { return proven(s, a) }, allow: true, attr: CallerSession},
		{name: "bare session id", caller: func(*pb.AskRequest) *pb.AskCaller { return &pb.AskCaller{SessionId: s.ID} },
			attr: CallerRefused, reason: string(identity.RefusedNoProof)},
		{name: "proof for another ask", caller: func(a *pb.AskRequest) *pb.AskCaller {
			c := proven(s, a)
			c.SessionProof = identity.SessionProof(s.Hash, s.ID, a.GetId()+1, a.GetDeadlineUnixNano())
			return c
		}, attr: CallerRefused, reason: string(identity.RefusedUnknown)},
		{name: "session from outside its tree", caller: func(a *pb.AskRequest) *pb.AskCaller {
			c := proven(s, a)
			c.UnixPeer, c.PeerUid, c.PeerPid = true, 1000, 300
			return c
		}, attr: CallerRefused, reason: string(identity.RefusedWrongTree)},
		{name: "unix peer in the session tree", caller: func(*pb.AskRequest) *pb.AskCaller {
			return &pb.AskCaller{UnixPeer: true, PeerUid: 1000, PeerPid: 201}
		}, allow: true, attr: CallerSession},
		{name: "mapped unix peer", caller: func(*pb.AskRequest) *pb.AskCaller {
			return &pb.AskCaller{UnixPeer: true, PeerUid: 1000, PeerPid: 300}
		}, allow: true, attr: CallerPeer},
		{name: "unmapped unix peer", caller: func(*pb.AskRequest) *pb.AskCaller {
			return &pb.AskCaller{UnixPeer: true, PeerUid: 4242, PeerPid: 300}
		}, attr: CallerUnmapped},
		{name: "no caller, agent fields claimed in the request", caller: func(*pb.AskRequest) *pb.AskCaller { return nil },
			spoof: true, attr: CallerNone},
	}
	for _, c := range cases {
		id++
		a := injectAsk(id, "GET")
		a.Caller = c.caller(a)
		if c.spoof {
			a.Request.AgentId, a.Request.AgentKind, a.Request.Session = "dev", "session", s.ID
		}
		ans := r.g.Answer(ctx, a)
		if (ans.Effect == pb.Effect_EFFECT_ALLOW) != c.allow {
			t.Errorf("%s: %+v", c.name, ans)
		}
		_ = r.st.View(ctx, func(tx state.Tx) error {
			all, err := tx.QueryAudit(ctx, state.AuditQuery{Action: ActionDecision})
			var es []audit.Entry
			for _, e := range all {
				if e.RequestID == fmt.Sprintf("dp-%d", id) {
					es = append(es, e)
				}
			}
			if err != nil || len(es) != 1 {
				t.Fatalf("%s: audit %v %v", c.name, es, err)
			}
			e := es[0]
			if e.Attrs["caller"] != c.attr || e.Attrs["caller_reason"] != c.reason {
				t.Errorf("%s: audit attrs %v", c.name, e.Attrs)
			}
			if c.allow != (e.Agent.ID == "dev") {
				t.Errorf("%s: audited agent %+v", c.name, e.Agent)
			}
			return nil
		})
	}
	// Without a resolver every caller is unknown.
	r.g.Callers = nil
	a := injectAsk(999, "GET")
	a.Caller = proven(s, a)
	if ans := r.g.Answer(ctx, a); ans.Effect != pb.Effect_EFFECT_DENY {
		t.Fatalf("no resolver: %+v", ans)
	}
}

// TestForwardConformance checks, conformance style, that a provider request
// ends the same whether the data plane decides it alone or asks: for random
// llm.forward requests over a rule set with deny, ask, allow and residual
// (time-based) rules under default deny, the data plane's local step
// (decide_forward in dataplane/crates/scrim-dataplane/src/policy.rs,
// emulated over the reference table) followed by Gate.Answer for what it
// sends on equals the forward semantics of the full evaluation: only a
// matching deny rule refuses, an ask rule needs an approval (none comes:
// denied), and the default never refuses.
func TestForwardConformance(t *testing.T) {
	cfg := policy.Config{Default: "deny", Rules: []policy.RuleSpec{
		{Name: "unknown-callers", Decision: "deny", When: `op == "llm.forward" && !agent.known && provider == "gemini"`},
		{Name: "no-openai-for-ci", Decision: "deny", When: `provider == "openai" && agent.labels.team == "ci"`},
		{Name: "night-anthropic", Decision: "deny", When: `provider == "anthropic" && now.getHours() >= 25`},
		{Name: "ask-mistral", Decision: "ask", When: `provider == "mistral"`},
		{Name: "allow-dev", Decision: "allow", When: `agent.id == "dev" && now.getHours() < 25`},
		{Name: "allow-openai", Decision: "allow", When: `provider == "openai"`},
	}}
	r := newRig(t, cfg)
	r.g.Approvals = nil // an ask is never approved here
	s := withSessions(t, r)
	snap := r.live.RuleSet().Snapshot(1, false)
	ctx := context.Background()
	rnd := rand.New(rand.NewPCG(5, 6))
	providers := []string{"anthropic", "openai", "gemini", "mistral", ""}
	kinds := map[string]int{}
	for i := range 400 {
		req := policy.Request{Action: policy.ActionForward, Provider: providers[rnd.IntN(len(providers))]}
		session := rnd.IntN(2) == 0
		if session {
			// What the data plane knows about a session caller: nothing
			// about the agent (its fields are unknown to the table).
			req.Agent = policy.Agent{ID: "dev", Kind: policy.IdentitySession, Session: s.ID, Labels: map[string]string{"uid": "1000", "session_name": "claude"}}
		}
		// The reference: full evaluation with forward semantics.
		full := r.live.Evaluate(req)
		want := full.Effect == policy.Allow || full.Default
		// The data plane's local step.
		var local policy.LocalResult
		if session {
			local = snap.EvaluateUnknownAgent(req)
		} else {
			local = snap.Evaluate(req)
		}
		var got bool
		switch {
		case local.Default:
			got, kinds["local default"] = true, kinds["local default"]+1
		case local.Outcome == policy.OutcomeControlPlane && local.Ask == policy.AskResidual && ruleEffect(cfg, local.Rule) == policy.Allow:
			got, kinds["local residual allow"] = true, kinds["local residual allow"]+1
		case local.Outcome == policy.OutcomeAllow:
			got, kinds["local allow"] = true, kinds["local allow"]+1
		case local.Outcome == policy.OutcomeDeny:
			got, kinds["local deny"] = false, kinds["local deny"]+1
		default:
			kinds["asked"]++
			a := &pb.AskRequest{Protocol: uint32(pb.ProtocolVersion_PROTOCOL_VERSION_CURRENT), Id: uint64(i + 1), //nolint:gosec // small
				Request: &pb.PolicyRequest{Action: string(req.Action), Provider: req.Provider}, Rule: local.Rule,
				DeadlineUnixNano: time.Now().Add(time.Minute).UnixNano()}
			if session {
				a.Caller = proven(s, a)
			}
			got = r.g.Answer(ctx, a).GetEffect() == pb.Effect_EFFECT_ALLOW
		}
		if got != want {
			t.Fatalf("%+v (session %v): data plane %+v then %v, reference %+v", req, session, local, got, full)
		}
	}
	for _, k := range []string{"local default", "local deny", "asked"} {
		if kinds[k] == 0 {
			t.Errorf("no %s case: %v", k, kinds)
		}
	}
	// Break-glass stops neither path.
	if err := r.bg.Engage(ctx, "oncall", "drill"); err != nil {
		t.Fatal(err)
	}
	a := &pb.AskRequest{Protocol: uint32(pb.ProtocolVersion_PROTOCOL_VERSION_CURRENT), Id: 9999,
		Request: &pb.PolicyRequest{Action: "llm.forward", Provider: "mistral"}, DeadlineUnixNano: time.Now().Add(time.Minute).UnixNano()}
	if ans := r.g.Answer(ctx, a); ans.Effect != pb.Effect_EFFECT_ALLOW || ans.Reason != ReasonForwardBreakGlass {
		t.Fatalf("break-glass: %+v", ans)
	}
}

func ruleEffect(cfg policy.Config, name string) policy.Effect {
	for _, r := range cfg.Rules {
		if r.Name == name {
			e, _ := policy.ParseEffect(r.Decision)
			return e
		}
	}
	return policy.Deny
}
