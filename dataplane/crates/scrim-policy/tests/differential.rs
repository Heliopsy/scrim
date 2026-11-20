// SPDX-License-Identifier: AGPL-3.0-only

//! Differential property tests: the crate's evaluator and glob matcher against an independent
//! port of the Go reference (`tests/common/reference.rs`) on random tables and requests.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

mod common;

use std::collections::HashMap;

use common::{
    GoAgent, GoClause, GoCondition, GoDest, GoRequest, GoRule, GoSecret, GoSnapshot, GoTool,
    reference, result, to_proto, to_request,
};
use proptest::prelude::*;
use scrim_policy::{Glob, Table};

const WORDS: &[&str] = &[
    "", "a", "ab", "b", "a/b", "ab/c", "x.y", "é", "a*", "*", "**",
];
const KEYS: &[&str] = &["team", "env"];
const SCALARS: &[&str] = &[
    "op",
    "provider",
    "agent.id",
    "agent.kind",
    "agent.known",
    "agent.session",
    "secret.ref",
    "secret.name",
    "secret.store",
    "secret.class",
    "dest.host",
    "dest.method",
    "dest.path",
    "tool.name",
    "tool.command",
];

fn word() -> impl Strategy<Value = String> {
    prop::sample::select(WORDS).prop_map(str::to_string)
}

fn pattern() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop::sample::select(&["a", "b", "/", "*", "?", "\\*", "\\\\", "é"][..]),
        0..6,
    )
    .prop_map(|v| v.concat())
}

fn condition() -> impl Strategy<Value = GoCondition> {
    let field = prop_oneof![
        prop::sample::select(SCALARS).prop_map(|f| (f.to_string(), String::new())),
        (
            prop::sample::select(&["agent.labels", "secret.labels"][..]),
            prop::sample::select(KEYS)
        )
            .prop_map(|(f, k)| (f.to_string(), k.to_string())),
    ];
    (
        field,
        0..6usize,
        prop::collection::vec(word(), 0..3),
        pattern(),
        any::<bool>(),
    )
        .prop_map(|((field, key), op, mut values, pat, negate)| {
            let map = !key.is_empty();
            let op = match op {
                0 => "in",
                1 => "prefix",
                2 => "suffix",
                3 => "contains",
                4 => "glob",
                _ if map => "has_key",
                _ => "in",
            };
            if field == "agent.known" && op == "in" {
                values = vec!["true".into()];
            }
            match op {
                "prefix" | "suffix" | "contains" => {
                    values.truncate(1);
                    if values.is_empty() {
                        values.push("a".into());
                    }
                }
                "glob" => values = vec![pat],
                _ => {}
            }
            GoCondition {
                field,
                key,
                op: op.into(),
                values,
                negate,
            }
        })
}

fn snapshot() -> impl Strategy<Value = GoSnapshot> {
    let clause = (
        prop::collection::vec(condition(), 0..4),
        prop::bool::weighted(0.2),
    )
        .prop_map(|(conditions, residual)| GoClause {
            conditions,
            residual,
        });
    let rule = (
        prop::collection::vec(clause, 0..4),
        prop::sample::select(&["deny", "ask", "allow"][..]),
        any::<bool>(),
        0..1000u32,
    )
        .prop_map(|(clauses, d, cp, n)| GoRule {
            name: format!("r{n}"),
            decision: d.into(),
            control_plane: cp && d == "allow",
            clauses,
            reason: String::new(),
        });
    (
        prop::collection::vec(rule, 0..7),
        prop::sample::select(&["deny", "ask", "allow"][..]),
        prop::bool::weighted(0.05),
    )
        .prop_map(|(rules, d, deny_all)| GoSnapshot {
            format: 1,
            version: 1,
            deny_all,
            default: d.into(),
            rules,
        })
}

fn labels() -> impl Strategy<Value = HashMap<String, String>> {
    prop::collection::hash_map(
        prop::sample::select(KEYS).prop_map(str::to_string),
        word(),
        0..3,
    )
}

fn request() -> impl Strategy<Value = GoRequest> {
    (
        (
            word(),
            word(),
            word(),
            prop::sample::select(&["", "peer", "session"][..]),
            word(),
            labels(),
        ),
        (word(), word(), word(), word(), labels()),
        (word(), word(), word(), word(), word()),
    )
        .prop_map(
            |(
                (op, provider, id, kind, session, al),
                (r, name, store, class, sl),
                (host, method, path, tn, tc),
            )| GoRequest {
                op,
                provider,
                agent: GoAgent {
                    id,
                    kind: kind.into(),
                    known: !kind.is_empty(),
                    session,
                    labels: al,
                },
                secret: GoSecret {
                    reference: r,
                    name,
                    store,
                    class,
                    labels: sl,
                },
                dest: GoDest { host, method, path },
                tool: GoTool {
                    name: tn,
                    command: tc,
                },
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 4000, ..ProptestConfig::default() })]

    #[test]
    fn evaluator_matches_reference(s in snapshot(), reqs in prop::collection::vec(request(), 1..8)) {
        let table = Table::from_proto(&to_proto(&s));
        let valid_globs = s.rules.iter().flat_map(|r| &r.clauses).flat_map(|c| &c.conditions)
            .filter(|c| c.op == "glob").all(|c| Glob::new(&c.values[0]).is_ok());
        prop_assert_eq!(table.is_ok(), valid_globs);
        let Ok(table) = table else { return Ok(()) };
        for req in &reqs {
            prop_assert_eq!(result(&table, &to_request(req)), reference::evaluate(&s, req));
        }
    }

    #[test]
    fn glob_matches_go_oracle(p in pattern(), s in prop::collection::vec(prop::sample::select(&["a", "b", "/", "*", "?", "\\", "é", ""][..]), 0..8)) {
        let s = s.concat();
        match reference::glob(&p, &s) {
            None => prop_assert!(Glob::new(&p).is_err()),
            Some(want) => prop_assert_eq!(Glob::new(&p).unwrap().matches(&s), want),
        }
    }

    #[test]
    fn glob_arbitrary_text(p in "[a-c/*?\\\\]{0,12}", s in "[a-c/*?]{0,24}") {
        match reference::glob(&p, &s) {
            None => prop_assert!(Glob::new(&p).is_err()),
            Some(want) => prop_assert_eq!(Glob::new(&p).unwrap().matches(&s), want),
        }
    }
}
