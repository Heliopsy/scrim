// SPDX-License-Identifier: AGPL-3.0-only

//! The decision table (design D7, `Policy.table`, `table_format` 1).
//!
//! The control plane lowers every CEL rule into disjunctive normal form over conditions this
//! module evaluates with string operations, and marks what it cannot lower as residual. The
//! semantics are exactly those of the Go reference evaluator, `policy.Snapshot.Evaluate`, and
//! [`Table::evaluate`] reproduces every vector in `internal/policy/testdata/conformance.json`.
//!
//! # Three-valued logic
//!
//! A condition is true, false, or an error (any operator but `has_key` on a missing map key),
//! and with [`Request::unknown`] also unknown. `negate` inverts true and false; an error stays
//! an error.
//!
//! * Clause (conjunction): false if any condition is false; otherwise unknown if residual or
//!   any condition is unknown; otherwise error if any condition errored; otherwise true.
//! * Rule (disjunction of clauses): true if any clause is true; otherwise unknown if any is
//!   unknown; otherwise error if any errored; otherwise false. No clauses is false.
//! * An erroring rule counts as a match when its effect is deny or ask and as no match for
//!   allow, so an error can only tighten the outcome.
//!
//! # Decision
//!
//! Break-glass denies without evaluating anything. Otherwise, for deny, then ask, then allow,
//! the first rule (in configuration order) at that level that is not a no-match decides: if it
//! is unknown the control plane decides ([`AskReason::Residual`]); deny denies; ask goes to the
//! control plane ([`AskReason::Rule`]); allow allows, unless the rule has side effects (a grant
//! TTL), which also goes to the control plane ([`AskReason::SideEffect`]). With no candidate the
//! default effect applies, and a default of ask goes to the control plane.

use std::fmt;
use std::sync::Arc;

use scrim_proto::v1 as pb;

use crate::glob::Glob;
use crate::request::{Field, Request};

/// The `table_format` this crate implements.
pub const TABLE_FORMAT: u32 = 1;

/// Rule name reported when no rule matched (the Go `policy.DefaultRule`).
pub const DEFAULT_RULE: &str = "default";

/// A rule effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Effect {
    /// Refuse.
    Deny,
    /// Hold for a human (or a grant), decided by the control plane.
    Ask,
    /// Permit.
    Allow,
}

impl Effect {
    /// Converts a wire effect. Unspecified and unknown values are deny, as in the control
    /// plane.
    pub fn from_proto(e: i32) -> Effect {
        match pb::Effect::try_from(e) {
            Ok(pb::Effect::Allow) => Effect::Allow,
            Ok(pb::Effect::Ask) => Effect::Ask,
            _ => Effect::Deny,
        }
    }

    /// The wire form.
    pub fn to_proto(self) -> pb::Effect {
        match self {
            Effect::Deny => pb::Effect::Deny,
            Effect::Ask => pb::Effect::Ask,
            Effect::Allow => pb::Effect::Allow,
        }
    }

    /// `deny`, `ask` or `allow`.
    pub fn as_str(self) -> &'static str {
        match self {
            Effect::Deny => "deny",
            Effect::Ask => "ask",
            Effect::Allow => "allow",
        }
    }
}

/// What the data plane does with a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// Refuse locally.
    Deny,
    /// Let it through locally.
    Allow,
    /// Send it to the control plane over the `Asks` call.
    ControlPlane,
}

impl Outcome {
    /// `deny`, `allow` or `control_plane`, as in the conformance vectors.
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Deny => "deny",
            Outcome::Allow => "allow",
            Outcome::ControlPlane => "control_plane",
        }
    }
}

/// Why a request goes to the control plane.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AskReason {
    /// A rule, or the default, decided ask.
    Rule,
    /// A rule the data plane cannot fully evaluate could decide the outcome.
    Residual,
    /// An allow rule with a grant TTL decided; the control plane records the grant.
    SideEffect,
}

impl AskReason {
    /// `ask`, `residual` or `side_effect`, as in the conformance vectors.
    pub fn as_str(self) -> &'static str {
        match self {
            AskReason::Rule => "ask",
            AskReason::Residual => "residual",
            AskReason::SideEffect => "side_effect",
        }
    }
}

/// Index of a rule in its [`Table`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RuleId(pub usize);

/// What decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DecidedBy {
    /// The rule with this id.
    Rule(RuleId),
    /// No rule matched; the default effect applied.
    Default,
    /// The break-glass switch is engaged.
    BreakGlass,
}

/// The data plane's decision for one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Decision {
    /// What to do.
    pub outcome: Outcome,
    /// Set when `outcome` is [`Outcome::ControlPlane`].
    pub ask: Option<AskReason>,
    /// The deciding rule, or the rule that forced the control-plane call.
    pub by: DecidedBy,
}

/// The operator of a [`Condition`], with its compiled operand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Matcher {
    /// The operand equals one of the values.
    In(Box<[String]>),
    /// The operand starts with the value.
    Prefix(String),
    /// The operand ends with the value.
    Suffix(String),
    /// The operand contains the value.
    Contains(String),
    /// The operand matches the glob.
    Glob(Glob),
    /// The map field has the key. Never errors.
    HasKey,
}

/// One test of a request field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Condition {
    /// The field tested.
    pub field: Field,
    /// Map key, for map fields; empty otherwise.
    pub key: String,
    /// Operator and operand.
    pub matcher: Matcher,
    /// Inverts the result; an error stays an error.
    pub negate: bool,
}

/// A conjunction of conditions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Clause {
    /// All must hold. Empty holds.
    pub conditions: Vec<Condition>,
    /// The clause also has parts only the control plane evaluates.
    pub residual: bool,
}

/// One rule in disjunctive normal form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// Rule name, for audit and asks.
    pub name: Arc<str>,
    /// Effect when the rule decides.
    pub effect: Effect,
    /// An allow rule with side effects: when it decides, ask the control plane.
    pub control_plane: bool,
    /// Alternatives; none means the rule never matches.
    pub clauses: Vec<Clause>,
    /// Shown in approvals and audit.
    pub reason: Arc<str>,
}

/// Why a `Policy` message was rejected. Messages name rules and fields, never request data.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TableError {
    /// `table_format` is not [`TABLE_FORMAT`].
    #[error("policy: table format {0} is not {TABLE_FORMAT}")]
    Format(u32),
    /// The snapshot uses the legacy rule list or an opaque engine, which this data plane does
    /// not implement.
    #[error("policy: unsupported policy form ({0}); only the decision table is implemented")]
    Unsupported(&'static str),
    /// A condition names an operator this data plane does not know.
    #[error("policy: rule {rule}: unknown condition operator {op}")]
    Operator {
        /// Rule name.
        rule: String,
        /// Raw operator value.
        op: i32,
    },
    /// A condition names a field this data plane does not know.
    #[error("policy: rule {rule}: unknown field {field:?}")]
    Field {
        /// Rule name.
        rule: String,
        /// The field name.
        field: String,
    },
    /// A map field without a key, or a scalar field with one.
    #[error("policy: rule {rule}: field {field:?} and key disagree")]
    Key {
        /// Rule name.
        rule: String,
        /// The field name.
        field: String,
    },
    /// `has_key` on a scalar field.
    #[error("policy: rule {rule}: has_key on a non-map field")]
    HasKeyScalar {
        /// Rule name.
        rule: String,
    },
    /// prefix, suffix, contains or glob without exactly one value.
    #[error("policy: rule {rule}: {op} needs exactly one value")]
    Arity {
        /// Rule name.
        rule: String,
        /// Operator name.
        op: &'static str,
    },
    /// An invalid glob pattern.
    #[error("policy: rule {rule}: glob: trailing backslash")]
    Glob {
        /// Rule name.
        rule: String,
    },
}

/// The compiled decision table.
#[derive(Clone, PartialEq, Eq)]
pub struct Table {
    version: u64,
    default: Effect,
    break_glass: bool,
    rules: Vec<Rule>,
    /// Rule indices per level, in order: deny, ask, allow.
    levels: [Vec<usize>; 3],
}

impl fmt::Debug for Table {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Table")
            .field("version", &self.version)
            .field("default", &self.default)
            .field("break_glass", &self.break_glass)
            .field("rules", &self.rules.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tri {
    False,
    True,
    Error,
    Unknown,
}

impl Tri {
    fn of(b: bool) -> Tri {
        if b { Tri::True } else { Tri::False }
    }
}

fn op_name(op: pb::ConditionOp) -> &'static str {
    match op {
        pb::ConditionOp::In => "in",
        pb::ConditionOp::Prefix => "prefix",
        pb::ConditionOp::Suffix => "suffix",
        pb::ConditionOp::Contains => "contains",
        pb::ConditionOp::Glob => "glob",
        pb::ConditionOp::HasKey => "has_key",
        pb::ConditionOp::Unspecified => "unspecified",
    }
}

impl Table {
    /// Validates and compiles a `Policy` message, as `policy.SnapshotFromProto` does: unknown
    /// formats, operators and fields are rejected, so the data plane never guesses.
    pub fn from_proto(p: &pb::Policy) -> Result<Table, TableError> {
        if p.table_format != TABLE_FORMAT {
            return Err(TableError::Format(p.table_format));
        }
        if !p.engine.is_empty() || !p.compiled.is_empty() {
            return Err(TableError::Unsupported("engine"));
        }
        if !p.rules.is_empty() {
            return Err(TableError::Unsupported("rules"));
        }
        let mut rules = Vec::with_capacity(p.table.len());
        for tr in &p.table {
            let mut clauses = Vec::with_capacity(tr.clauses.len());
            for pc in &tr.clauses {
                let mut conditions = Vec::with_capacity(pc.conditions.len());
                for c in &pc.conditions {
                    conditions.push(compile_condition(&tr.name, c)?);
                }
                clauses.push(Clause {
                    conditions,
                    residual: pc.residual,
                });
            }
            rules.push(Rule {
                name: tr.name.as_str().into(),
                effect: Effect::from_proto(tr.effect),
                control_plane: tr.control_plane,
                clauses,
                reason: tr.reason.as_str().into(),
            });
        }
        Ok(Table::new(
            p.version,
            Effect::from_proto(p.default_effect),
            p.break_glass,
            rules,
        ))
    }

    /// Builds a table from compiled rules.
    pub fn new(version: u64, default: Effect, break_glass: bool, rules: Vec<Rule>) -> Table {
        let mut levels: [Vec<usize>; 3] = Default::default();
        for (i, r) in rules.iter().enumerate() {
            let l = match r.effect {
                Effect::Deny => 0,
                Effect::Ask => 1,
                Effect::Allow => 2,
            };
            levels[l].push(i);
        }
        Table {
            version,
            default,
            break_glass,
            rules,
            levels,
        }
    }

    /// A table with no rules that denies everything by default: the state before the first
    /// snapshot.
    pub fn deny_all() -> Table {
        Table::new(0, Effect::Deny, false, Vec::new())
    }

    /// The policy version.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The default effect.
    pub fn default_effect(&self) -> Effect {
        self.default
    }

    /// Whether break-glass is engaged.
    pub fn break_glass(&self) -> bool {
        self.break_glass
    }

    /// The rules, in configuration order.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// The rule with `id`.
    ///
    /// # Panics
    ///
    /// When `id` does not come from this table.
    pub fn rule(&self, id: RuleId) -> &Rule {
        &self.rules[id.0]
    }

    /// The name a decision reports: the rule name, [`DEFAULT_RULE`], or empty for break-glass.
    pub fn rule_name(&self, by: DecidedBy) -> &str {
        match by {
            DecidedBy::Rule(id) => self.rules.get(id.0).map_or("", |r| &r.name),
            DecidedBy::Default => DEFAULT_RULE,
            DecidedBy::BreakGlass => "",
        }
    }

    /// The reason of the deciding rule, empty otherwise.
    pub fn reason(&self, by: DecidedBy) -> &str {
        match by {
            DecidedBy::Rule(id) => self.rules.get(id.0).map_or("", |r| &r.reason),
            _ => "",
        }
    }

    /// Decides `req` (see the module documentation).
    pub fn evaluate(&self, req: &Request) -> Decision {
        if self.break_glass {
            return Decision {
                outcome: Outcome::Deny,
                ask: None,
                by: DecidedBy::BreakGlass,
            };
        }
        for (level, ids) in self.levels.iter().enumerate() {
            for &i in ids {
                let r = &self.rules[i];
                let st = match rule_eval(r, req) {
                    Tri::Error if r.effect == Effect::Allow => Tri::False,
                    Tri::Error => Tri::True,
                    s => s,
                };
                let by = DecidedBy::Rule(RuleId(i));
                match st {
                    Tri::False => {}
                    Tri::Unknown => {
                        return Decision {
                            outcome: Outcome::ControlPlane,
                            ask: Some(AskReason::Residual),
                            by,
                        };
                    }
                    _ => {
                        return match (level, r.control_plane) {
                            (0, _) => Decision {
                                outcome: Outcome::Deny,
                                ask: None,
                                by,
                            },
                            (1, _) => Decision {
                                outcome: Outcome::ControlPlane,
                                ask: Some(AskReason::Rule),
                                by,
                            },
                            (_, true) => Decision {
                                outcome: Outcome::ControlPlane,
                                ask: Some(AskReason::SideEffect),
                                by,
                            },
                            (_, false) => Decision {
                                outcome: Outcome::Allow,
                                ask: None,
                                by,
                            },
                        };
                    }
                }
            }
        }
        let (outcome, ask) = match self.default {
            Effect::Allow => (Outcome::Allow, None),
            Effect::Ask => (Outcome::ControlPlane, Some(AskReason::Rule)),
            Effect::Deny => (Outcome::Deny, None),
        };
        Decision {
            outcome,
            ask,
            by: DecidedBy::Default,
        }
    }

    /// Whether a deny or ask rule matches, could match (unknown) or errors on `req`, or
    /// break-glass is engaged. The default effect and allow rules are not consulted.
    ///
    /// This is how restore uses the table: the tool policy is restore's default, and rules can
    /// only take a restore away (redaction spec "Resolution follows tool policy"). Returns what
    /// restricted it.
    pub fn restricts(&self, req: &Request) -> Option<DecidedBy> {
        if self.break_glass {
            return Some(DecidedBy::BreakGlass);
        }
        self.levels[..2]
            .iter()
            .flatten()
            .find(|&&i| rule_eval(&self.rules[i], req) != Tri::False)
            .map(|&i| DecidedBy::Rule(RuleId(i)))
    }
}

fn compile_condition(rule: &str, c: &pb::Condition) -> Result<Condition, TableError> {
    let op = pb::ConditionOp::try_from(c.op).unwrap_or(pb::ConditionOp::Unspecified);
    if op == pb::ConditionOp::Unspecified {
        return Err(TableError::Operator {
            rule: rule.into(),
            op: c.op,
        });
    }
    let Some(field) = Field::from_name(&c.field) else {
        return Err(TableError::Field {
            rule: rule.into(),
            field: c.field.clone(),
        });
    };
    if field.is_map() == c.key.is_empty() {
        return Err(TableError::Key {
            rule: rule.into(),
            field: c.field.clone(),
        });
    }
    if op == pb::ConditionOp::HasKey && !field.is_map() {
        return Err(TableError::HasKeyScalar { rule: rule.into() });
    }
    let one = || -> Result<String, TableError> {
        match c.values.as_slice() {
            [v] => Ok(v.clone()),
            _ => Err(TableError::Arity {
                rule: rule.into(),
                op: op_name(op),
            }),
        }
    };
    let matcher = match op {
        pb::ConditionOp::In => Matcher::In(c.values.clone().into()),
        pb::ConditionOp::Prefix => Matcher::Prefix(one()?),
        pb::ConditionOp::Suffix => Matcher::Suffix(one()?),
        pb::ConditionOp::Contains => Matcher::Contains(one()?),
        pb::ConditionOp::Glob => {
            Matcher::Glob(Glob::new(&one()?).map_err(|_| TableError::Glob { rule: rule.into() })?)
        }
        pb::ConditionOp::HasKey | pb::ConditionOp::Unspecified => Matcher::HasKey,
    };
    Ok(Condition {
        field,
        key: c.key.clone(),
        matcher,
        negate: c.negate,
    })
}

fn rule_eval(r: &Rule, req: &Request) -> Tri {
    let mut out = Tri::False;
    for c in &r.clauses {
        match clause_eval(c, req) {
            Tri::True => return Tri::True,
            Tri::Unknown => out = Tri::Unknown,
            Tri::Error if out != Tri::Unknown => out = Tri::Error,
            _ => {}
        }
    }
    out
}

fn clause_eval(c: &Clause, req: &Request) -> Tri {
    let mut out = Tri::True;
    for cond in &c.conditions {
        match cond_eval(cond, req) {
            Tri::False => return Tri::False,
            Tri::Unknown => out = Tri::Unknown,
            Tri::Error if out != Tri::Unknown => out = Tri::Error,
            _ => {}
        }
    }
    if c.residual { Tri::Unknown } else { out }
}

fn cond_eval(c: &Condition, req: &Request) -> Tri {
    if req.unknown.contains(c.field) {
        return Tri::Unknown;
    }
    let v: &str = match req.map(c.field) {
        Some(m) => {
            let val = m.get(&c.key);
            if c.matcher == Matcher::HasKey {
                return Tri::of(val.is_some() != c.negate);
            }
            match val {
                Some(v) => v,
                None => return Tri::Error,
            }
        }
        None => req.scalar(c.field),
    };
    let b = match &c.matcher {
        Matcher::In(vals) => vals.iter().any(|x| x == v),
        Matcher::Prefix(p) => v.starts_with(p.as_str()),
        Matcher::Suffix(s) => v.ends_with(s.as_str()),
        Matcher::Contains(s) => v.contains(s.as_str()),
        Matcher::Glob(g) => g.matches(v),
        // has_key on a scalar field is rejected at load; evaluate it as the control plane
        // would, as an error.
        Matcher::HasKey => return Tri::Error,
    };
    Tri::of(b != c.negate)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]
mod tests {
    use super::*;
    use crate::request::FieldSet;

    fn cond(
        field: &str,
        key: &str,
        op: pb::ConditionOp,
        values: &[&str],
        negate: bool,
    ) -> pb::Condition {
        pb::Condition {
            field: field.into(),
            key: key.into(),
            op: op as i32,
            values: values.iter().map(|s| (*s).to_string()).collect(),
            negate,
        }
    }

    fn rule(name: &str, effect: pb::Effect, clauses: Vec<pb::Clause>) -> pb::TableRule {
        pb::TableRule {
            name: name.into(),
            effect: effect as i32,
            control_plane: false,
            clauses,
            reason: String::new(),
        }
    }

    fn clause(conditions: Vec<pb::Condition>, residual: bool) -> pb::Clause {
        pb::Clause {
            conditions,
            residual,
        }
    }

    fn policy(table: Vec<pb::TableRule>) -> pb::Policy {
        pb::Policy {
            version: 7,
            default_effect: pb::Effect::Deny as i32,
            table_format: 1,
            table,
            ..Default::default()
        }
    }

    #[test]
    fn rejects_what_go_rejects() {
        let ok = policy(vec![rule(
            "r",
            pb::Effect::Deny,
            vec![clause(
                vec![cond("op", "", pb::ConditionOp::In, &["x"], false)],
                false,
            )],
        )]);
        Table::from_proto(&ok).unwrap();

        let mut bad = ok.clone();
        bad.table_format = 2;
        assert_eq!(Table::from_proto(&bad), Err(TableError::Format(2)));
        bad.table_format = 0;
        assert_eq!(Table::from_proto(&bad), Err(TableError::Format(0)));

        let mut bad = ok.clone();
        bad.table[0].clauses[0].conditions[0].field = "agent.nmae".into();
        assert!(matches!(
            Table::from_proto(&bad),
            Err(TableError::Field { .. })
        ));

        let mut bad = ok.clone();
        bad.table[0].clauses[0].conditions[0].op = 0;
        assert!(matches!(
            Table::from_proto(&bad),
            Err(TableError::Operator { .. })
        ));
        bad.table[0].clauses[0].conditions[0].op = 99;
        assert!(matches!(
            Table::from_proto(&bad),
            Err(TableError::Operator { .. })
        ));

        let mut bad = ok.clone();
        bad.table[0].clauses[0].conditions[0] =
            cond("agent.labels", "", pb::ConditionOp::In, &["x"], false);
        assert!(matches!(
            Table::from_proto(&bad),
            Err(TableError::Key { .. })
        ));
        bad.table[0].clauses[0].conditions[0] = cond("op", "k", pb::ConditionOp::In, &["x"], false);
        assert!(matches!(
            Table::from_proto(&bad),
            Err(TableError::Key { .. })
        ));

        let mut bad = ok.clone();
        bad.table[0].clauses[0].conditions[0] = cond("op", "", pb::ConditionOp::HasKey, &[], false);
        assert!(matches!(
            Table::from_proto(&bad),
            Err(TableError::Key { .. }) | Err(TableError::HasKeyScalar { .. })
        ));

        for op in [
            pb::ConditionOp::Prefix,
            pb::ConditionOp::Suffix,
            pb::ConditionOp::Contains,
            pb::ConditionOp::Glob,
        ] {
            let mut bad = ok.clone();
            bad.table[0].clauses[0].conditions[0] = cond("op", "", op, &[], false);
            assert!(
                matches!(Table::from_proto(&bad), Err(TableError::Arity { .. })),
                "{op:?}"
            );
            bad.table[0].clauses[0].conditions[0] = cond("op", "", op, &["a", "b"], false);
            assert!(
                matches!(Table::from_proto(&bad), Err(TableError::Arity { .. })),
                "{op:?}"
            );
        }

        let mut bad = ok.clone();
        bad.table[0].clauses[0].conditions[0] =
            cond("op", "", pb::ConditionOp::Glob, &["a\\"], false);
        assert!(matches!(
            Table::from_proto(&bad),
            Err(TableError::Glob { .. })
        ));

        let mut bad = ok.clone();
        bad.engine = "cel/v1".into();
        assert_eq!(
            Table::from_proto(&bad),
            Err(TableError::Unsupported("engine"))
        );
        let mut bad = ok.clone();
        bad.rules.push(pb::PolicyRule::default());
        assert_eq!(
            Table::from_proto(&bad),
            Err(TableError::Unsupported("rules"))
        );

        // IN with no values and has_key with values are accepted, as in Go.
        let mut fine = ok.clone();
        fine.table[0].clauses[0].conditions = vec![
            cond("op", "", pb::ConditionOp::In, &[], false),
            cond(
                "agent.labels",
                "team",
                pb::ConditionOp::HasKey,
                &["ignored"],
                false,
            ),
        ];
        Table::from_proto(&fine).unwrap();
    }

    #[test]
    fn errors_tighten_and_unknown_dominates() {
        // deny when agent.labels.team != "infra"; a missing label errors, so it denies.
        let t = Table::from_proto(&policy(vec![
            rule(
                "deny-team",
                pb::Effect::Deny,
                vec![clause(
                    vec![cond(
                        "agent.labels",
                        "team",
                        pb::ConditionOp::In,
                        &["infra"],
                        true,
                    )],
                    false,
                )],
            ),
            rule(
                "allow-team",
                pb::Effect::Allow,
                vec![clause(
                    vec![cond(
                        "agent.labels",
                        "team",
                        pb::ConditionOp::In,
                        &["infra"],
                        false,
                    )],
                    false,
                )],
            ),
        ]))
        .unwrap();
        let mut req = Request::default();
        let d = t.evaluate(&req);
        assert_eq!(d.outcome, Outcome::Deny);
        assert_eq!(t.rule_name(d.by), "deny-team");
        req.agent.labels.insert("team".into(), "infra".into());
        let d = t.evaluate(&req);
        assert_eq!(
            (d.outcome, t.rule_name(d.by)),
            (Outcome::Allow, "allow-team")
        );
        // Unknown labels: the deny rule could match, so the control plane decides.
        req.unknown = FieldSet::AGENT;
        let d = t.evaluate(&req);
        assert_eq!(d.outcome, Outcome::ControlPlane);
        assert_eq!(d.ask, Some(AskReason::Residual));
        assert_eq!(t.rule_name(d.by), "deny-team");
        // has_key on an unknown map is unknown too.
        let t = Table::from_proto(&policy(vec![rule(
            "has",
            pb::Effect::Deny,
            vec![clause(
                vec![cond(
                    "agent.labels",
                    "team",
                    pb::ConditionOp::HasKey,
                    &[],
                    true,
                )],
                false,
            )],
        )]))
        .unwrap();
        assert_eq!(t.evaluate(&req).outcome, Outcome::ControlPlane);
        req.unknown = FieldSet::EMPTY;
        assert_eq!(t.evaluate(&req).by, DecidedBy::Default);
        req.agent.labels.clear();
        assert_eq!(t.rule_name(t.evaluate(&req).by), "has");
    }

    #[test]
    fn unknown_beats_error_within_a_clause() {
        // (labels.team == "x" [error: missing] && agent.id == ... [unknown]) on a deny rule:
        // the unknown part could be false, so this must not deny locally.
        let t = Table::from_proto(&policy(vec![rule(
            "r",
            pb::Effect::Deny,
            vec![clause(
                vec![
                    cond("agent.labels", "team", pb::ConditionOp::In, &["x"], false),
                    cond("op", "", pb::ConditionOp::In, &["restore"], false),
                ],
                false,
            )],
        )]))
        .unwrap();
        let req = Request {
            unknown: FieldSet::EMPTY.with(Field::Op),
            ..Request::default()
        };
        assert_eq!(t.evaluate(&req).ask, Some(AskReason::Residual));
    }

    #[test]
    fn break_glass_denies_without_evaluating() {
        let mut p = policy(vec![rule(
            "allow",
            pb::Effect::Allow,
            vec![clause(vec![], false)],
        )]);
        p.break_glass = true;
        let t = Table::from_proto(&p).unwrap();
        let d = t.evaluate(&Request::default());
        assert_eq!(
            d,
            Decision {
                outcome: Outcome::Deny,
                ask: None,
                by: DecidedBy::BreakGlass
            }
        );
        assert_eq!(t.rule_name(d.by), "");
        assert_eq!(
            t.restricts(&Request::default()),
            Some(DecidedBy::BreakGlass)
        );
    }

    #[test]
    fn defaults_and_side_effects() {
        let mut p = policy(vec![]);
        for (eff, want) in [
            (pb::Effect::Allow, (Outcome::Allow, None)),
            (
                pb::Effect::Ask,
                (Outcome::ControlPlane, Some(AskReason::Rule)),
            ),
            (pb::Effect::Deny, (Outcome::Deny, None)),
            (pb::Effect::Unspecified, (Outcome::Deny, None)),
        ] {
            p.default_effect = eff as i32;
            let t = Table::from_proto(&p).unwrap();
            let d = t.evaluate(&Request::default());
            assert_eq!((d.outcome, d.ask), want);
            assert_eq!(t.rule_name(d.by), DEFAULT_RULE);
        }
        p.default_effect = 42;
        assert_eq!(
            Table::from_proto(&p).unwrap().default_effect(),
            Effect::Deny
        );
        let mut r = rule("grant", pb::Effect::Allow, vec![clause(vec![], false)]);
        r.control_plane = true;
        r.reason = "because".into();
        let t = Table::from_proto(&policy(vec![r])).unwrap();
        let d = t.evaluate(&Request::default());
        assert_eq!(d.ask, Some(AskReason::SideEffect));
        assert_eq!(t.reason(d.by), "because");
        // A rule with no clauses never matches.
        let t = Table::from_proto(&policy(vec![rule("never", pb::Effect::Deny, vec![])])).unwrap();
        assert_eq!(t.evaluate(&Request::default()).by, DecidedBy::Default);
    }

    #[test]
    fn restricts_ignores_allow_and_default() {
        let t = Table::from_proto(&policy(vec![
            rule("allow", pb::Effect::Allow, vec![clause(vec![], false)]),
            rule(
                "no-restore-prod",
                pb::Effect::Deny,
                vec![clause(
                    vec![
                        cond("op", "", pb::ConditionOp::In, &["restore"], false),
                        cond(
                            "secret.ref",
                            "",
                            pb::ConditionOp::Glob,
                            &["bao://kv/prod/**"],
                            false,
                        ),
                    ],
                    false,
                )],
            ),
            rule(
                "ask-night",
                pb::Effect::Ask,
                vec![clause(
                    vec![cond("tool.name", "", pb::ConditionOp::In, &["Bash"], false)],
                    true,
                )],
            ),
        ]))
        .unwrap();
        let mut req = Request {
            op: "restore".into(),
            ..Request::default()
        };
        req.secret.reference = "bao://kv/dev/x".into();
        assert_eq!(t.restricts(&req), None);
        req.secret.reference = "bao://kv/prod/x".into();
        assert_eq!(t.rule_name(t.restricts(&req).unwrap()), "no-restore-prod");
        req.secret.reference = "bao://kv/dev/x".into();
        req.tool.name = "Bash".into();
        assert_eq!(t.rule_name(t.restricts(&req).unwrap()), "ask-night");
        assert!(format!("{t:?}").contains("rules: 3, .."));
        assert_eq!(Table::deny_all().evaluate(&req).outcome, Outcome::Deny);
    }

    #[test]
    fn names() {
        assert_eq!(Outcome::ControlPlane.as_str(), "control_plane");
        assert_eq!(AskReason::SideEffect.as_str(), "side_effect");
        assert_eq!(Effect::Ask.as_str(), "ask");
        for e in [Effect::Deny, Effect::Ask, Effect::Allow] {
            assert_eq!(Effect::from_proto(e.to_proto() as i32), e);
        }
    }
}
