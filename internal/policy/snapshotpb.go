// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"fmt"

	pb "github.com/heliopsy/scrim/internal/dataplane/dataplanev1"
	"github.com/heliopsy/scrim/internal/stores"
)

var opToPB = map[CondOp]pb.ConditionOp{
	OpIn: pb.ConditionOp_CONDITION_OP_IN, OpPrefix: pb.ConditionOp_CONDITION_OP_PREFIX,
	OpSuffix: pb.ConditionOp_CONDITION_OP_SUFFIX, OpContains: pb.ConditionOp_CONDITION_OP_CONTAINS,
	OpGlob: pb.ConditionOp_CONDITION_OP_GLOB, OpHasKey: pb.ConditionOp_CONDITION_OP_HAS_KEY,
}

// EffectToPB converts an effect to its wire form.
func EffectToPB(e Effect) pb.Effect {
	switch e {
	case Allow:
		return pb.Effect_EFFECT_ALLOW
	case Ask:
		return pb.Effect_EFFECT_ASK
	}
	return pb.Effect_EFFECT_DENY
}

// EffectFromPB converts a wire effect; unspecified is deny.
func EffectFromPB(e pb.Effect) Effect {
	switch e {
	case pb.Effect_EFFECT_ALLOW:
		return Allow
	case pb.Effect_EFFECT_ASK:
		return Ask
	}
	return Deny
}

// Proto returns the snapshot as the Policy message the data plane receives.
func (s *Snapshot) Proto() *pb.Policy {
	p := &pb.Policy{
		Version:       s.Version,
		DefaultEffect: EffectToPB(s.Default),
		BreakGlass:    s.DenyAll,
		TableFormat:   uint32(s.Format),
		Table:         make([]*pb.TableRule, 0, len(s.Rules)),
	}
	for _, r := range s.Rules {
		tr := &pb.TableRule{Name: r.Name, Effect: EffectToPB(r.Decision), ControlPlane: r.ControlPlane, Reason: r.Reason,
			Clauses: make([]*pb.Clause, 0, len(r.Clauses))}
		for _, c := range r.Clauses {
			pc := &pb.Clause{Residual: c.Residual}
			for _, cond := range c.Conditions {
				pc.Conditions = append(pc.Conditions, &pb.Condition{
					Field: cond.Field, Key: cond.Key, Op: opToPB[cond.Op], Values: cond.Values, Negate: cond.Negate,
				})
			}
			tr.Clauses = append(tr.Clauses, pc)
		}
		p.Table = append(p.Table, tr)
	}
	return p
}

// SnapshotFromProto validates and converts a Policy message, as the data
// plane must before applying it. It rejects unknown formats, operators and
// fields, so a data plane never guesses.
func SnapshotFromProto(p *pb.Policy) (Snapshot, error) {
	if p.GetTableFormat() != SnapshotFormat {
		return Snapshot{}, fmt.Errorf("policy: table format %d is not %d", p.GetTableFormat(), SnapshotFormat)
	}
	s := Snapshot{Format: SnapshotFormat, Version: p.GetVersion(), DenyAll: p.GetBreakGlass(), Default: EffectFromPB(p.GetDefaultEffect())}
	fromPB := map[pb.ConditionOp]CondOp{}
	for k, v := range opToPB {
		fromPB[v] = k
	}
	for _, tr := range p.GetTable() {
		r := SnapshotRule{Name: tr.GetName(), Decision: EffectFromPB(tr.GetEffect()), ControlPlane: tr.GetControlPlane(),
			Reason: tr.GetReason(), Clauses: []Clause{}}
		for _, pc := range tr.GetClauses() {
			c := Clause{Residual: pc.GetResidual()}
			for _, cond := range pc.GetConditions() {
				op, ok := fromPB[cond.GetOp()]
				if !ok {
					return Snapshot{}, fmt.Errorf("policy: rule %s: unknown condition operator %v", r.Name, cond.GetOp())
				}
				kind, ok := SnapshotFields[cond.GetField()]
				if !ok {
					return Snapshot{}, fmt.Errorf("policy: rule %s: unknown field %q", r.Name, cond.GetField())
				}
				if (kind == kindMap) != (cond.GetKey() != "") {
					return Snapshot{}, fmt.Errorf("policy: rule %s: field %q and key disagree", r.Name, cond.GetField())
				}
				if op == OpHasKey && kind != kindMap {
					return Snapshot{}, fmt.Errorf("policy: rule %s: has_key on a non-map field", r.Name)
				}
				if op != OpIn && op != OpHasKey && len(cond.GetValues()) != 1 {
					return Snapshot{}, fmt.Errorf("policy: rule %s: %s needs exactly one value", r.Name, op)
				}
				if op == OpGlob {
					if err := ValidateGlob(cond.GetValues()[0]); err != nil {
						return Snapshot{}, fmt.Errorf("policy: rule %s: %w", r.Name, err)
					}
				}
				vals := cond.GetValues()
				if vals == nil {
					vals = []string{}
				}
				c.Conditions = append(c.Conditions, Condition{Field: cond.GetField(), Key: cond.GetKey(), Op: op, Values: vals, Negate: cond.GetNegate()})
			}
			r.Clauses = append(r.Clauses, c)
		}
		s.Rules = append(s.Rules, r)
	}
	if s.Rules == nil {
		s.Rules = []SnapshotRule{}
	}
	return s, nil
}

// RequestFromProto converts the request of a data-plane ask.
func RequestFromProto(p *pb.PolicyRequest) (Request, error) {
	r := Request{
		Agent:  Agent{ID: p.GetAgentId(), Kind: IdentityKind(p.GetAgentKind()), Session: p.GetSession(), Labels: p.GetAgentLabels()},
		Action: Action(p.GetAction()), Name: p.GetName(), Store: p.GetStore(), SecretClass: p.GetSecretClass(),
		SecretLabels: p.GetSecretLabels(), Provider: p.GetProvider(), Host: p.GetHost(), Method: p.GetMethod(),
		Path: p.GetPath(), Tool: p.GetTool(), Command: p.GetCommand(),
	}
	if p.GetRef() != "" {
		ref, err := stores.ParseRef(p.GetRef())
		if err != nil {
			return Request{}, err
		}
		r.Ref = ref
	}
	switch r.Agent.Kind {
	case IdentityUnknown, IdentityPeer, IdentitySession, IdentityK8s, IdentityMTLS:
	default:
		return Request{}, fmt.Errorf("policy: unknown agent kind %q", r.Agent.Kind)
	}
	if r.Agent.Kind == IdentityUnknown {
		r.Agent.ID = ""
	}
	return r, nil
}
