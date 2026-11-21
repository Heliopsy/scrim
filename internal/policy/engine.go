// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"

	"cel.dev/cel-go/cel"
	celast "cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/ext"
)

// costLimit bounds the work one rule may do on one request. Rules over the
// request attributes cost a few hundred units; the limit only stops runaway
// comprehensions.
const costLimit = 100_000

// DefaultRule is the rule name reported when no rule matched.
const DefaultRule = "default"

// RuleSet is a compiled, immutable rule set. It implements [Engine] and is
// safe for concurrent use. Build one with [Compile]; swap rule sets on
// reload with [Live].
type RuleSet struct {
	cfg   Config
	rules []compiledRule
	def   Effect
}

type compiledRule struct {
	rule   RuleSpec
	effect Effect
	ast    *cel.Ast // nil when When is empty (always matches)
	prg    cel.Program
	// labels: the expression reads secret.labels (or the whole secret).
	labels bool
	// partial evaluates with secret.labels unknown; set when labels is.
	partial cel.Program
}

var (
	envOnce sync.Once
	envVal  *cel.Env
	envErr  error
)

// Env returns the CEL environment rules are compiled in. Its variables are
// documented in docs/policy.md:
//
//	op       string             the action (inject, store.write, ...)
//	agent    policy.RuleAgent   the transport identity
//	secret   policy.RuleSecret  the secret reference and metadata
//	provider string             the model provider, if any
//	dest     policy.RuleDest    host, method, path
//	tool     policy.RuleTool    tool name and command
//	now      timestamp          request time
//
// Besides the CEL standard library, optional types and the strings
// extension it adds `string.glob(pattern) -> bool` (see [Glob]).
func Env() (*cel.Env, error) {
	envOnce.Do(func() { envVal, envErr = newEnv() })
	return envVal, envErr
}

func newEnv() (*cel.Env, error) {
	return cel.NewEnv(
		ext.NativeTypes(
			reflect.TypeFor[RuleAgent](),
			reflect.TypeFor[RuleSecret](),
			reflect.TypeFor[RuleDest](),
			reflect.TypeFor[RuleTool](),
			ext.ParseStructTags(true),
		),
		ext.Strings(),
		cel.OptionalTypes(),
		cel.Variable("op", cel.StringType),
		cel.Variable("agent", cel.ObjectType("policy.RuleAgent")),
		cel.Variable("secret", cel.ObjectType("policy.RuleSecret")),
		cel.Variable("provider", cel.StringType),
		cel.Variable("dest", cel.ObjectType("policy.RuleDest")),
		cel.Variable("tool", cel.ObjectType("policy.RuleTool")),
		cel.Variable("now", cel.TimestampType),
		cel.Function("glob",
			cel.MemberOverload("string_glob_string",
				[]*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.BinaryBinding(func(s, p ref.Val) ref.Val {
					str, ok1 := s.(types.String)
					pat, ok2 := p.(types.String)
					if !ok1 || !ok2 {
						return types.NewErr("glob: string arguments required")
					}
					toks, err := compileGlob(string(pat))
					if err != nil {
						return types.NewErr("%s", err.Error())
					}
					return types.Bool(globMatch(toks, []rune(string(str))))
				}),
			),
		),
	)
}

// Compile validates cfg and compiles every rule. Any invalid rule rejects the
// whole configuration: there is no partial rule set. An empty cfg.Default
// means deny; callers that honour the policy.default setting fill it in
// first.
func Compile(cfg Config) (*RuleSet, error) {
	effects, err := cfg.validateShape()
	if err != nil {
		return nil, err
	}
	env, err := Env()
	if err != nil {
		return nil, fmt.Errorf("policy: building CEL environment: %w", err)
	}
	rs := &RuleSet{cfg: cfg, def: Deny, rules: make([]compiledRule, len(cfg.Rules))}
	if cfg.Default != "" {
		rs.def, _ = ParseEffect(cfg.Default)
	}
	var errs []error
	for i, r := range cfg.Rules {
		cr := compiledRule{rule: r, effect: effects[i]}
		if r.When != "" {
			ast, iss := env.Compile(r.When)
			if iss.Err() != nil {
				errs = append(errs, &RuleError{Index: i, Name: r.Name, Err: iss.Err()})
				continue
			}
			if !ast.OutputType().IsExactType(cel.BoolType) {
				errs = append(errs, &RuleError{Index: i, Name: r.Name,
					Err: fmt.Errorf("when must be a bool expression, got %s", ast.OutputType())})
				continue
			}
			if err := checkLiteralGlobs(ast); err != nil {
				errs = append(errs, &RuleError{Index: i, Name: r.Name, Err: err})
				continue
			}
			prg, err := env.Program(ast,
				cel.CostLimit(costLimit),
				cel.EvalOptions(cel.OptOptimize),
				cel.InterruptCheckFrequency(100),
			)
			if err != nil {
				errs = append(errs, &RuleError{Index: i, Name: r.Name, Err: err})
				continue
			}
			cr.ast, cr.prg, cr.labels = ast, prg, readsSecretLabels(ast)
			if cr.labels {
				if cr.partial, err = env.Program(ast,
					cel.CostLimit(costLimit),
					cel.EvalOptions(cel.OptPartialEval),
					cel.InterruptCheckFrequency(100),
				); err != nil {
					errs = append(errs, &RuleError{Index: i, Name: r.Name, Err: err})
					continue
				}
			}
		}
		rs.rules[i] = cr
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return rs, nil
}

// Config returns the configuration the rule set was compiled from.
func (rs *RuleSet) Config() Config { return rs.cfg }

// Default returns the effective default decision.
func (rs *RuleSet) Default() Effect { return rs.def }

// Rule returns the rule with the given name.
func (rs *RuleSet) Rule(name string) (RuleSpec, bool) {
	for _, r := range rs.rules {
		if r.rule.Name == name {
			return r.rule, true
		}
	}
	return RuleSpec{}, false
}

// Result is the outcome of evaluating a request, with the detail `scrim
// policy eval` shows.
type Result struct {
	// Effect is the final decision.
	Effect Effect `json:"effect"`
	// Rule names the deciding rule, or [DefaultRule].
	Rule string `json:"rule"`
	// Default is true when no rule matched and the default applied.
	Default bool `json:"default,omitempty"`
	// Reason is the deciding rule's reason.
	Reason string `json:"reason,omitempty"`
	// Matched lists every rule that matched, in rule order.
	Matched []string `json:"matched,omitempty"`
	// Errors lists rules whose expression failed on this request.
	Errors []EvalError `json:"errors,omitempty"`

	grant GrantSettings
}

// Grant returns the deciding rule's grant settings.
func (r Result) Grant() GrantSettings { return r.grant }

// EvalError records a rule that could not be evaluated for a request. A rule
// that errors counts as matching if it denies or asks and as not matching if
// it allows, so an error can only make the outcome stricter.
type EvalError struct {
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

// Evaluate decides req.
//
// Every rule is evaluated. Among the rules that match, the decision with the
// highest precedence wins (deny over ask over allow) and the first matching
// rule in configuration order with that decision is reported. When no rule
// matches, the default decision applies. A rule whose expression fails on the
// request (for example indexing a label the agent does not have) is treated
// as matching when it denies or asks and as not matching when it allows.
func (rs *RuleSet) Evaluate(req Request) Result {
	v := newView(&req)
	act := v.activation()
	res := Result{}
	var best *compiledRule
	for i := range rs.rules {
		cr := &rs.rules[i]
		var matched bool
		var err error
		if req.SecretLabelsUnknown && cr.labels {
			matched, err = cr.evalLabelsUnknown(act)
		} else {
			matched, err = cr.eval(act)
		}
		if err != nil {
			res.Errors = append(res.Errors, EvalError{Rule: cr.rule.Name, Message: err.Error()})
			matched = cr.effect != Allow
		}
		if !matched {
			continue
		}
		res.Matched = append(res.Matched, cr.rule.Name)
		if best == nil || cr.effect.strength() > best.effect.strength() {
			best = cr
		}
	}
	if best == nil {
		res.Effect, res.Rule, res.Default = rs.def, DefaultRule, true
		res.Reason = "no rule matched; default is " + rs.def.String()
		return res
	}
	res.Effect, res.Rule, res.Reason, res.grant = best.effect, best.rule.Name, best.rule.Reason, best.rule.Grant
	return res
}

// Decide implements [Engine]. It never returns an error: evaluation errors
// are folded into the decision as described on [RuleSet.Evaluate].
func (rs *RuleSet) Decide(_ context.Context, req Request) (Decision, error) {
	r := rs.Evaluate(req)
	d := Decision{Effect: r.Effect, Rule: r.Rule, Reason: r.Reason}
	if r.Effect != Deny {
		d.GrantTTL = r.grant.TTL.D()
	}
	return d, nil
}

// errLabelsUnknown is the evaluation error of a rule that reads
// secret.labels when the secret's store could not say what they are.
var errLabelsUnknown = errors.New("secret.labels unknown: the store's metadata could not be read")

// readsSecretLabels reports whether a rule reads secret.labels, directly or
// by using the secret variable as a whole.
func readsSecretLabels(a *cel.Ast) bool {
	idents, selects, labels := 0, 0, false
	celast.PreOrderVisit(a.NativeRep().Expr(), celast.NewExprVisitor(func(e celast.Expr) {
		switch e.Kind() {
		case celast.IdentKind:
			if e.AsIdent() == "secret" {
				idents++
			}
		case celast.SelectKind:
			s := e.AsSelect()
			if op := s.Operand(); op.Kind() == celast.IdentKind && op.AsIdent() == "secret" {
				selects++
				labels = labels || s.FieldName() == "labels"
			}
		}
	}))
	return labels || idents > selects
}

// evalLabelsUnknown evaluates the rule with secret.labels unknown. A rule
// whose outcome depends on them errors (errLabelsUnknown); one that is
// decided without them (op == "inject" && ... for a write) is not affected.
func (cr *compiledRule) evalLabelsUnknown(act map[string]any) (bool, error) {
	vars, err := cel.PartialVars(act, cel.AttributePattern("secret").QualString("labels"))
	if err != nil {
		return false, err
	}
	out, _, err := cr.partial.Eval(vars)
	if err != nil {
		return false, err
	}
	if types.IsUnknown(out) {
		return false, errLabelsUnknown
	}
	b, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("rule returned %s, not bool", out.Type())
	}
	return b, nil
}

func (cr *compiledRule) eval(act map[string]any) (bool, error) {
	if cr.prg == nil {
		return true, nil
	}
	out, _, err := cr.prg.Eval(act)
	if err != nil {
		return false, err
	}
	b, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("rule returned %s, not bool", out.Type())
	}
	return b, nil
}

// Live keeps the rule set in force and swaps it atomically on reload. A
// reload that fails to compile leaves the previous rules in force and records
// the error for health status. Live implements [Engine].
type Live struct {
	cur atomic.Pointer[RuleSet]

	mu      sync.Mutex
	version uint64
	lastErr error
	onSwap  []func(*RuleSet, uint64)
}

// NewLive compiles cfg. Start-up fails on an invalid configuration.
func NewLive(cfg Config) (*Live, error) {
	rs, err := Compile(cfg)
	if err != nil {
		return nil, err
	}
	l := &Live{version: 1}
	l.cur.Store(rs)
	return l, nil
}

// RuleSet returns the rule set in force.
func (l *Live) RuleSet() *RuleSet { return l.cur.Load() }

// Decide implements [Engine] with the rule set in force.
func (l *Live) Decide(ctx context.Context, req Request) (Decision, error) {
	return l.cur.Load().Decide(ctx, req)
}

// Rule returns the rule with the given name from the rule set in force.
func (l *Live) Rule(name string) (RuleSpec, bool) { return l.cur.Load().Rule(name) }

// Evaluate evaluates req against the rule set in force.
func (l *Live) Evaluate(req Request) Result { return l.cur.Load().Evaluate(req) }

// Reload compiles cfg and swaps it in. On error the previous rule set stays
// in force and the error is returned and kept for [Live.Health].
func (l *Live) Reload(cfg Config) error {
	rs, err := Compile(cfg)
	l.mu.Lock()
	defer l.mu.Unlock()
	if err != nil {
		l.lastErr = err
		return fmt.Errorf("policy: reload rejected, previous rules stay in force: %w", err)
	}
	l.cur.Store(rs)
	l.version++
	l.lastErr = nil
	for _, fn := range l.onSwap {
		fn(rs, l.version)
	}
	return nil
}

// OnSwap registers fn to run after every successful reload, for example to
// push a new snapshot to the data plane. fn runs with the holder locked, so
// swaps are delivered in order; it must not call Reload.
func (l *Live) OnSwap(fn func(*RuleSet, uint64)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.onSwap = append(l.onSwap, fn)
}

// Health returns the rule-set version in force and the error of the last
// rejected reload, if the last reload failed. It fits obs health checks.
func (l *Live) Health() (version uint64, lastErr error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.version, l.lastErr
}
