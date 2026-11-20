// SPDX-License-Identifier: AGPL-3.0-only

//! A naive, independent port of `policy.Snapshot.Evaluate` over the Go JSON form, for
//! differential testing. It evaluates every rule up front, as Go does, and matches globs with a
//! regular expression built the way Go's `globRegexp` oracle builds it, so it shares no code
//! with the crate.

use super::{GoCondition, GoRequest, GoResult, GoRule, GoSnapshot};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tri {
    F,
    T,
    E,
    U,
}

fn glob_regex(p: &str) -> Option<regex::Regex> {
    let mut b = String::from("^");
    let rs: Vec<char> = p.chars().collect();
    let mut i = 0;
    while i < rs.len() {
        match rs[i] {
            '\\' => {
                if i + 1 >= rs.len() {
                    return None;
                }
                i += 1;
                b.push_str(&regex::escape(&rs[i].to_string()));
            }
            '?' => b.push_str("[^/]"),
            '*' => {
                if i + 1 < rs.len() && rs[i + 1] == '*' {
                    while i + 1 < rs.len() && rs[i + 1] == '*' {
                        i += 1;
                    }
                    b.push_str("(?s:.*)");
                } else {
                    b.push_str("[^/]*");
                }
            }
            c => b.push_str(&regex::escape(&c.to_string())),
        }
        i += 1;
    }
    b.push('$');
    Some(regex::Regex::new(&b).unwrap())
}

/// Go-oracle glob.
pub fn glob(p: &str, s: &str) -> Option<bool> {
    glob_regex(p).map(|re| re.is_match(s))
}

fn scalar(r: &GoRequest, f: &str) -> Option<String> {
    Some(match f {
        "op" => r.op.clone(),
        "provider" => r.provider.clone(),
        "agent.id" => r.agent.id.clone(),
        "agent.kind" => r.agent.kind.clone(),
        "agent.known" => (!r.agent.kind.is_empty()).to_string(),
        "agent.session" => r.agent.session.clone(),
        "secret.ref" => r.secret.reference.clone(),
        "secret.name" => r.secret.name.clone(),
        "secret.store" => r.secret.store.clone(),
        "secret.class" => r.secret.class.clone(),
        "dest.host" => r.dest.host.clone(),
        "dest.method" => r.dest.method.clone(),
        "dest.path" => r.dest.path.clone(),
        "tool.name" => r.tool.name.clone(),
        "tool.command" => r.tool.command.clone(),
        _ => return None,
    })
}

fn cond(c: &GoCondition, r: &GoRequest) -> Tri {
    let bt = |b: bool| if b { Tri::T } else { Tri::F };
    let v = match c.field.as_str() {
        "agent.labels" | "secret.labels" => {
            let m = if c.field == "agent.labels" {
                &r.agent.labels
            } else {
                &r.secret.labels
            };
            let val = m.get(&c.key);
            if c.op == "has_key" {
                return bt(val.is_some() != c.negate);
            }
            match val {
                Some(v) => v.clone(),
                None => return Tri::E,
            }
        }
        f => match scalar(r, f) {
            Some(v) => v,
            None => return Tri::E,
        },
    };
    let b = match c.op.as_str() {
        "in" => c.values.contains(&v),
        "prefix" | "suffix" | "contains" | "glob" => {
            if c.values.len() != 1 {
                return Tri::E;
            }
            let x = &c.values[0];
            match c.op.as_str() {
                "prefix" => v.starts_with(x.as_str()),
                "suffix" => v.ends_with(x.as_str()),
                "contains" => v.contains(x.as_str()),
                _ => match glob(x, &v) {
                    Some(b) => b,
                    None => return Tri::E,
                },
            }
        }
        _ => return Tri::E,
    };
    bt(b != c.negate)
}

fn rule(r: &GoRule, req: &GoRequest) -> Tri {
    let mut out = Tri::F;
    for cl in &r.clauses {
        let mut c_out = Tri::T;
        let mut false_seen = false;
        for c in &cl.conditions {
            match cond(c, req) {
                Tri::F => {
                    false_seen = true;
                    break;
                }
                Tri::E => c_out = Tri::E,
                _ => {}
            }
        }
        let st = if false_seen {
            Tri::F
        } else if cl.residual {
            Tri::U
        } else {
            c_out
        };
        match st {
            Tri::T => return Tri::T,
            Tri::U => out = Tri::U,
            Tri::E => {
                if out != Tri::U {
                    out = Tri::E;
                }
            }
            Tri::F => {}
        }
    }
    out
}

/// `Snapshot.Evaluate`.
pub fn evaluate(s: &GoSnapshot, req: &GoRequest) -> GoResult {
    if s.deny_all {
        return GoResult {
            outcome: "deny".into(),
            deny_all: true,
            ..GoResult::default()
        };
    }
    let status: Vec<Tri> = s
        .rules
        .iter()
        .map(|r| match rule(r, req) {
            Tri::E if r.decision == "allow" => Tri::F,
            Tri::E => Tri::T,
            st => st,
        })
        .collect();
    let level = |d: &str| match d {
        "allow" => "allow",
        "ask" => "ask",
        _ => "deny",
    };
    for lv in ["deny", "ask", "allow"] {
        for (i, r) in s.rules.iter().enumerate() {
            if level(&r.decision) != lv || status[i] == Tri::F {
                continue;
            }
            let rule = r.name.clone();
            if status[i] == Tri::U {
                return GoResult {
                    outcome: "control_plane".into(),
                    rule,
                    ask: "residual".into(),
                    ..GoResult::default()
                };
            }
            return match lv {
                "deny" => GoResult {
                    outcome: "deny".into(),
                    rule,
                    ..GoResult::default()
                },
                "ask" => GoResult {
                    outcome: "control_plane".into(),
                    rule,
                    ask: "ask".into(),
                    ..GoResult::default()
                },
                _ if r.control_plane => GoResult {
                    outcome: "control_plane".into(),
                    rule,
                    ask: "side_effect".into(),
                    ..GoResult::default()
                },
                _ => GoResult {
                    outcome: "allow".into(),
                    rule,
                    ..GoResult::default()
                },
            };
        }
    }
    let rule = "default".to_string();
    match s.default.as_str() {
        "allow" => GoResult {
            outcome: "allow".into(),
            rule,
            default: true,
            ..GoResult::default()
        },
        "ask" => GoResult {
            outcome: "control_plane".into(),
            rule,
            default: true,
            ask: "ask".into(),
            ..GoResult::default()
        },
        _ => GoResult {
            outcome: "deny".into(),
            rule,
            default: true,
            ..GoResult::default()
        },
    }
}
