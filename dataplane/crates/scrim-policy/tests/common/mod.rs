// SPDX-License-Identifier: AGPL-3.0-only

//! Shared test helpers: the Go snapshot JSON form, its conversion to the wire `Policy`, and an
//! independent reference evaluator ported line by line from `policy.Snapshot.Evaluate`.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

pub mod reference;

use std::collections::HashMap;

use scrim_policy::{Request, Table};
use scrim_proto::v1 as pb;
use serde::Deserialize;

/// `policy.Snapshot` as JSON.
#[derive(Clone, Debug, Deserialize)]
pub struct GoSnapshot {
    pub format: u32,
    pub version: u64,
    #[serde(default)]
    pub deny_all: bool,
    pub default: String,
    pub rules: Vec<GoRule>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct GoRule {
    pub name: String,
    pub decision: String,
    #[serde(default)]
    pub control_plane: bool,
    pub clauses: Vec<GoClause>,
    #[serde(default)]
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct GoClause {
    #[serde(default)]
    pub conditions: Vec<GoCondition>,
    #[serde(default)]
    pub residual: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct GoCondition {
    pub field: String,
    #[serde(default)]
    pub key: String,
    pub op: String,
    pub values: Vec<String>,
    #[serde(default)]
    pub negate: bool,
}

/// `vectorRequest`.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct GoRequest {
    #[serde(default)]
    pub op: String,
    pub agent: GoAgent,
    pub secret: GoSecret,
    #[serde(default)]
    pub provider: String,
    pub dest: GoDest,
    pub tool: GoTool,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct GoAgent {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub known: bool,
    #[serde(default)]
    pub session: String,
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct GoSecret {
    #[serde(default, rename = "ref")]
    pub reference: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub store: String,
    #[serde(default)]
    pub class: String,
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct GoDest {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub path: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct GoTool {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub command: String,
}

/// `LocalResult`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct GoResult {
    pub outcome: String,
    #[serde(default)]
    pub rule: String,
    #[serde(default)]
    pub default: bool,
    #[serde(default)]
    pub ask: String,
    #[serde(default)]
    pub deny_all: bool,
}

#[derive(Debug, Deserialize)]
pub struct Conformance {
    pub snapshot: GoSnapshot,
    pub cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
pub struct Case {
    pub request: GoRequest,
    pub want: GoResult,
}

pub fn effect(s: &str) -> pb::Effect {
    match s {
        "allow" => pb::Effect::Allow,
        "ask" => pb::Effect::Ask,
        _ => pb::Effect::Deny,
    }
}

pub fn op(s: &str) -> pb::ConditionOp {
    match s {
        "in" => pb::ConditionOp::In,
        "prefix" => pb::ConditionOp::Prefix,
        "suffix" => pb::ConditionOp::Suffix,
        "contains" => pb::ConditionOp::Contains,
        "glob" => pb::ConditionOp::Glob,
        "has_key" => pb::ConditionOp::HasKey,
        _ => pb::ConditionOp::Unspecified,
    }
}

/// `Snapshot.Proto()`.
pub fn to_proto(s: &GoSnapshot) -> pb::Policy {
    pb::Policy {
        version: s.version,
        default_effect: effect(&s.default) as i32,
        break_glass: s.deny_all,
        table_format: s.format,
        table: s
            .rules
            .iter()
            .map(|r| pb::TableRule {
                name: r.name.clone(),
                effect: effect(&r.decision) as i32,
                control_plane: r.control_plane,
                reason: r.reason.clone(),
                clauses: r
                    .clauses
                    .iter()
                    .map(|c| pb::Clause {
                        residual: c.residual,
                        conditions: c
                            .conditions
                            .iter()
                            .map(|x| pb::Condition {
                                field: x.field.clone(),
                                key: x.key.clone(),
                                op: op(&x.op) as i32,
                                values: x.values.clone(),
                                negate: x.negate,
                            })
                            .collect(),
                    })
                    .collect(),
            })
            .collect(),
        ..Default::default()
    }
}

pub fn to_request(v: &GoRequest) -> Request {
    let mut r = Request {
        op: v.op.clone(),
        provider: v.provider.clone(),
        ..Request::default()
    };
    r.agent.id = v.agent.id.clone();
    r.agent.kind = v.agent.kind.clone();
    r.agent.session = v.agent.session.clone();
    r.agent.labels = v.agent.labels.clone();
    r.secret.reference = v.secret.reference.clone();
    r.secret.name = v.secret.name.clone();
    r.secret.store = v.secret.store.clone();
    r.secret.class = v.secret.class.clone();
    r.secret.labels = v.secret.labels.clone();
    r.dest.host = v.dest.host.clone();
    r.dest.method = v.dest.method.clone();
    r.dest.path = v.dest.path.clone();
    r.tool.name = v.tool.name.clone();
    r.tool.command = v.tool.command.clone();
    r
}

/// The Rust decision in the Go `LocalResult` form.
pub fn result(t: &Table, r: &Request) -> GoResult {
    let d = t.evaluate(r);
    GoResult {
        outcome: d.outcome.as_str().into(),
        rule: t.rule_name(d.by).into(),
        default: d.by == scrim_policy::DecidedBy::Default,
        ask: d.ask.map(|a| a.as_str().to_string()).unwrap_or_default(),
        deny_all: d.by == scrim_policy::DecidedBy::BreakGlass,
    }
}

pub fn load_conformance() -> Conformance {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../internal/policy/testdata/conformance.json"
    );
    let data = std::fs::read(path).expect("conformance vectors");
    serde_json::from_slice(&data).expect("conformance json")
}
