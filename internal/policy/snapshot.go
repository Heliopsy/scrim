// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"fmt"
	"slices"
	"strconv"

	"cel.dev/cel-go/cel"
	celast "cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/operators"
	"cel.dev/cel-go/common/overloads"
	"cel.dev/cel-go/common/types"
)

// The data plane decides allow and deny locally (design D7) without a CEL
// interpreter. [RuleSet.Snapshot] lowers every rule into a decision table the
// data plane can evaluate with string comparisons and the glob matcher, and
// marks the parts it cannot lower as residual: when a residual part could
// change the outcome, the data plane sends the request to the control plane,
// which evaluates the full CEL rule. The reference evaluator is
// [Snapshot.Evaluate]; the Rust data plane must agree with it on every
// conformance vector.

// SnapshotFormat is the version of the snapshot semantics. A data plane that
// does not implement this version refuses the snapshot.
const SnapshotFormat = 1

// maxClauses bounds the disjunctive normal form of one rule. A rule that
// expands further is shipped as a single residual clause.
const maxClauses = 64

// Snapshot is the compiled rule set pushed to the data plane.
type Snapshot struct {
	// Format is [SnapshotFormat].
	Format int `json:"format"`
	// Version increases with every rule-set or deny-all change; the data
	// plane acknowledges the version it applied.
	Version uint64 `json:"version"`
	// DenyAll is the break-glass switch: while set, every operation the
	// snapshot governs is denied without evaluating rules.
	DenyAll bool `json:"deny_all,omitempty"`
	// Default is the decision when no rule matches.
	Default Effect `json:"default"`
	// Rules in configuration order.
	Rules []SnapshotRule `json:"rules"`
}

// SnapshotRule is one rule in disjunctive normal form: it matches when any
// clause matches.
type SnapshotRule struct {
	Name     string `json:"name"`
	Decision Effect `json:"decision"`
	// ControlPlane is set on allow rules with side effects (an allow rule
	// with a grant TTL leaves a grant behind). When such a rule decides, the
	// data plane forwards the request to the control plane instead of
	// allowing it locally.
	ControlPlane bool `json:"control_plane,omitempty"`
	// Clauses are alternatives; no clauses means the rule never matches.
	Clauses []Clause `json:"clauses"`
	// Reason is the rule's reason, for audit events.
	Reason string `json:"reason,omitempty"`
}

// Clause is a conjunction of conditions.
type Clause struct {
	// Conditions must all hold. An empty list holds.
	Conditions []Condition `json:"conditions,omitempty"`
	// Residual is set when the clause also has parts only the control plane
	// can evaluate. If every condition holds, the clause's result is unknown
	// to the data plane.
	Residual bool `json:"residual,omitempty"`
}

// CondOp is a condition operator.
type CondOp string

// Condition operators. The operand is the field's value as a string (ports
// in decimal, booleans as true or false).
const (
	// OpIn holds when the operand equals one of Values.
	OpIn CondOp = "in"
	// OpPrefix holds when the operand starts with Values[0].
	OpPrefix CondOp = "prefix"
	// OpSuffix holds when the operand ends with Values[0].
	OpSuffix CondOp = "suffix"
	// OpContains holds when the operand contains Values[0].
	OpContains CondOp = "contains"
	// OpGlob holds when the operand matches the glob pattern Values[0].
	OpGlob CondOp = "glob"
	// OpHasKey holds when the map field has Key. It never errors.
	OpHasKey CondOp = "has_key"
)

// Condition tests one request field.
type Condition struct {
	// Field is a dotted field name from [SnapshotFields].
	Field string `json:"field"`
	// Key selects an entry of a map field (agent.labels, secret.labels). A
	// condition other than has_key on a missing key is an error, as in CEL.
	Key string `json:"key,omitempty"`
	// Op is the operator.
	Op CondOp `json:"op"`
	// Values are the literal operands.
	Values []string `json:"values"`
	// Negate inverts the result. An error stays an error.
	Negate bool `json:"negate,omitempty"`
}

// fieldKind is how a snapshot field is typed.
type fieldKind int

const (
	kindString fieldKind = iota
	kindInt
	kindBool
	kindMap
)

// SnapshotFields lists the request fields the data plane evaluates, with
// their kinds. Every other attribute (now) is residual.
var SnapshotFields = map[string]fieldKind{
	"op":            kindString,
	"provider":      kindString,
	"agent.id":      kindString,
	"agent.kind":    kindString,
	"agent.known":   kindBool,
	"agent.session": kindString,
	"agent.labels":  kindMap,
	"secret.ref":    kindString,
	"secret.name":   kindString,
	"secret.store":  kindString,
	"secret.class":  kindString,
	"secret.labels": kindMap,
	"dest.host":     kindString,
	"dest.method":   kindString,
	"dest.path":     kindString,
	"tool.name":     kindString,
	"tool.command":  kindString,
}

// Snapshot lowers the rule set into the data-plane decision table.
func (rs *RuleSet) Snapshot(version uint64, denyAll bool) Snapshot {
	s := Snapshot{
		Format:  SnapshotFormat,
		Version: version,
		DenyAll: denyAll,
		Default: rs.def,
		Rules:   make([]SnapshotRule, 0, len(rs.rules)),
	}
	for _, cr := range rs.rules {
		sr := SnapshotRule{
			Name:         cr.rule.Name,
			Decision:     cr.effect,
			ControlPlane: cr.effect == Allow && cr.rule.Grant.TTL > 0,
			Reason:       cr.rule.Reason,
		}
		if cr.ast == nil {
			sr.Clauses = []Clause{{}}
		} else {
			cl, ok := lower(cr.ast.NativeRep().Expr(), false)
			if !ok || len(cl) > maxClauses {
				cl = []Clause{{Residual: true}}
			}
			sr.Clauses = cl
		}
		if sr.Clauses == nil {
			sr.Clauses = []Clause{}
		}
		s.Rules = append(s.Rules, sr)
	}
	return s
}

// lower converts e (negated when neg) into DNF clauses. ok is false only when
// the expansion exceeds maxClauses.
func lower(e celast.Expr, neg bool) ([]Clause, bool) {
	if e.Kind() == celast.LiteralKind {
		if b, isBool := e.AsLiteral().(types.Bool); isBool {
			if bool(b) != neg {
				return []Clause{{}}, true
			}
			return nil, true
		}
		return []Clause{{Residual: true}}, true
	}
	if e.Kind() == celast.CallKind {
		call := e.AsCall()
		switch call.FunctionName() {
		case operators.LogicalNot:
			return lower(call.Args()[0], !neg)
		case operators.LogicalAnd, operators.LogicalOr:
			and := (call.FunctionName() == operators.LogicalAnd) != neg
			var out []Clause
			for i, a := range call.Args() {
				cl, ok := lower(a, neg)
				if !ok {
					return nil, false
				}
				switch {
				case and && i == 0:
					out = cl
				case and:
					out = product(out, cl)
				default:
					out = append(out, cl...)
				}
				if len(out) > maxClauses {
					return nil, false
				}
			}
			return out, true
		}
	}
	c, ok := atom(e)
	if !ok {
		return []Clause{{Residual: true}}, true
	}
	c.Negate = c.Negate != neg
	return []Clause{{Conditions: []Condition{c}}}, true
}

func product(a, b []Clause) []Clause {
	out := make([]Clause, 0, len(a)*len(b))
	for _, x := range a {
		for _, y := range b {
			out = append(out, Clause{
				Conditions: append(slices.Clone(x.Conditions), y.Conditions...),
				Residual:   x.Residual || y.Residual,
			})
		}
	}
	return out
}

// atom recognises one condition the data plane can evaluate.
func atom(e celast.Expr) (Condition, bool) {
	switch e.Kind() {
	case celast.SelectKind, celast.IdentKind:
		// A bare bool field: agent.known.
		f, key, ok := field(e)
		if ok && key == "" && SnapshotFields[f] == kindBool {
			return Condition{Field: f, Op: OpIn, Values: []string{"true"}}, true
		}
		if sel := e; sel.Kind() == celast.SelectKind && sel.AsSelect().IsTestOnly() {
			// has(agent.labels.team)
			s := sel.AsSelect()
			f, k, ok := field(s.Operand())
			if ok && k == "" && SnapshotFields[f] == kindMap {
				return Condition{Field: f, Key: s.FieldName(), Op: OpHasKey, Values: []string{}}, true
			}
		}
		return Condition{}, false
	case celast.CallKind:
	default:
		return Condition{}, false
	}
	call := e.AsCall()
	args := call.Args()
	switch fn := call.FunctionName(); fn {
	case operators.Equals, operators.NotEquals:
		f, key, lit, ok := fieldAndLiteral(args[0], args[1])
		if !ok {
			f, key, lit, ok = fieldAndLiteral(args[1], args[0])
		}
		if !ok {
			return Condition{}, false
		}
		return Condition{Field: f, Key: key, Op: OpIn, Values: []string{lit}, Negate: fn == operators.NotEquals}, true
	case operators.In:
		// "team" in agent.labels
		if f, key, ok := field(args[1]); ok && key == "" && SnapshotFields[f] == kindMap {
			if k, ok := stringLiteral(args[0]); ok {
				return Condition{Field: f, Key: k, Op: OpHasKey, Values: []string{}}, true
			}
			return Condition{}, false
		}
		f, key, ok := field(args[0])
		if !ok || args[1].Kind() != celast.ListKind {
			return Condition{}, false
		}
		kind := scalarKind(f, key)
		elems := args[1].AsList().Elements()
		vals := make([]string, 0, len(elems))
		for i, el := range elems {
			if args[1].AsList().IsOptional(int32(i)) {
				return Condition{}, false
			}
			v, ok := literalOf(el, kind)
			if !ok {
				return Condition{}, false
			}
			vals = append(vals, v)
		}
		return Condition{Field: f, Key: key, Op: OpIn, Values: vals}, true
	case overloads.StartsWith, overloads.EndsWith, "contains", "glob":
		if !call.IsMemberFunction() || len(args) != 1 {
			return Condition{}, false
		}
		f, key, ok := field(call.Target())
		if !ok || scalarKind(f, key) != kindString {
			return Condition{}, false
		}
		lit, ok := stringLiteral(args[0])
		if !ok {
			return Condition{}, false
		}
		op := map[string]CondOp{
			overloads.StartsWith: OpPrefix, overloads.EndsWith: OpSuffix,
			"contains": OpContains, "glob": OpGlob,
		}[fn]
		return Condition{Field: f, Key: key, Op: op, Values: []string{lit}}, true
	}
	return Condition{}, false
}

// field resolves a variable or field selection, or a map index on a map
// field, to a snapshot field name and optional map key.
func field(e celast.Expr) (name, key string, ok bool) {
	switch e.Kind() {
	case celast.IdentKind:
		n := e.AsIdent()
		if _, known := SnapshotFields[n]; known {
			return n, "", true
		}
	case celast.SelectKind:
		s := e.AsSelect()
		if s.IsTestOnly() {
			return "", "", false
		}
		op := s.Operand()
		if op.Kind() == celast.IdentKind {
			n := op.AsIdent() + "." + s.FieldName()
			if _, known := SnapshotFields[n]; known {
				return n, "", true
			}
			return "", "", false
		}
		// agent.labels.team
		if f, k, ok := field(op); ok && k == "" && SnapshotFields[f] == kindMap {
			return f, s.FieldName(), true
		}
	case celast.CallKind:
		c := e.AsCall()
		if c.FunctionName() != operators.Index {
			return "", "", false
		}
		f, k, ok := field(c.Args()[0])
		if !ok || k != "" || SnapshotFields[f] != kindMap {
			return "", "", false
		}
		key, ok := stringLiteral(c.Args()[1])
		if !ok {
			return "", "", false
		}
		return f, key, true
	}
	return "", "", false
}

// scalarKind is the kind of the value a (field, key) pair yields.
func scalarKind(f, key string) fieldKind {
	k := SnapshotFields[f]
	if k == kindMap && key != "" {
		return kindString
	}
	return k
}

func fieldAndLiteral(fe, le celast.Expr) (f, key, lit string, ok bool) {
	f, key, ok = field(fe)
	if !ok {
		return "", "", "", false
	}
	kind := scalarKind(f, key)
	if kind == kindMap {
		return "", "", "", false
	}
	lit, ok = literalOf(le, kind)
	return f, key, lit, ok
}

func literalOf(e celast.Expr, kind fieldKind) (string, bool) {
	if e.Kind() != celast.LiteralKind {
		return "", false
	}
	switch v := e.AsLiteral().(type) {
	case types.String:
		return string(v), kind == kindString
	case types.Int:
		return strconv.FormatInt(int64(v), 10), kind == kindInt
	case types.Bool:
		return strconv.FormatBool(bool(v)), kind == kindBool
	}
	return "", false
}

func stringLiteral(e celast.Expr) (string, bool) { return literalOf(e, kindString) }

// checkLiteralGlobs rejects glob calls whose literal pattern is invalid, so a
// typo fails at load time rather than on a request.
func checkLiteralGlobs(a *cel.Ast) error {
	var err error
	celast.PostOrderVisit(a.NativeRep().Expr(), celast.NewExprVisitor(func(e celast.Expr) {
		if err != nil || e.Kind() != celast.CallKind {
			return
		}
		c := e.AsCall()
		if c.FunctionName() != "glob" || len(c.Args()) != 1 {
			return
		}
		if p, ok := stringLiteral(c.Args()[0]); ok {
			if gerr := ValidateGlob(p); gerr != nil {
				err = fmt.Errorf("invalid glob pattern %q: %w", p, gerr)
			}
		}
	}))
	return err
}
