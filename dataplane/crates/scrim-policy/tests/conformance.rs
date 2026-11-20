// SPDX-License-Identifier: AGPL-3.0-only

//! The Rust evaluator reproduces every vector the Go reference evaluator generated
//! (`internal/policy/testdata/conformance.json`, design D7).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

mod common;

use std::collections::BTreeMap;

use common::{load_conformance, reference, result, to_proto, to_request};
use scrim_policy::Table;

#[test]
fn every_conformance_vector() {
    let c = load_conformance();
    let table = Table::from_proto(&to_proto(&c.snapshot)).expect("snapshot accepted");
    assert_eq!(table.rules().len(), c.snapshot.rules.len());
    assert!(c.cases.len() >= 140, "only {} vectors", c.cases.len());
    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    for (i, case) in c.cases.iter().enumerate() {
        assert_eq!(
            case.request.agent.known,
            !case.request.agent.kind.is_empty(),
            "vector {i}: agent.known inconsistent with kind"
        );
        let req = to_request(&case.request);
        let got = result(&table, &req);
        assert_eq!(got, case.want, "vector {i}: {:?}", case.request);
        assert_eq!(
            reference::evaluate(&c.snapshot, &case.request),
            case.want,
            "reference port disagrees on vector {i}"
        );
        *kinds
            .entry(format!("{}/{}", got.outcome, got.ask))
            .or_default() += 1;
    }
    for k in [
        "allow/",
        "deny/",
        "control_plane/ask",
        "control_plane/residual",
        "control_plane/side_effect",
    ] {
        assert!(kinds.contains_key(k), "vectors do not cover {k}: {kinds:?}");
    }
}

#[test]
fn conformance_snapshot_under_break_glass() {
    let c = load_conformance();
    let mut p = to_proto(&c.snapshot);
    p.break_glass = true;
    let table = Table::from_proto(&p).unwrap();
    for case in &c.cases {
        let got = result(&table, &to_request(&case.request));
        assert_eq!(got.outcome, "deny");
        assert!(got.deny_all);
        assert_eq!(got.rule, "");
    }
}

#[test]
fn conformance_snapshot_rejections() {
    let c = load_conformance();
    let good = to_proto(&c.snapshot);
    let mut bad = good.clone();
    bad.table_format = 2;
    assert!(Table::from_proto(&bad).is_err(), "unknown format accepted");
    let mut bad = good.clone();
    bad.table[0].clauses[0].conditions[0].field = "agent.nmae".into();
    assert!(Table::from_proto(&bad).is_err(), "unknown field accepted");
    let mut bad = good.clone();
    bad.table[0].clauses[0].conditions[0].op = 0;
    assert!(
        Table::from_proto(&bad).is_err(),
        "unspecified operator accepted"
    );
}
