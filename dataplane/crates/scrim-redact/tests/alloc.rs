//! The hot path does not allocate once buffers have grown.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    unreachable_pub,
    missing_docs
)]

mod common;

use std::alloc::System;

use common::fixtures::{gen_body, gen_secrets};
use scrim_redact::*;
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn redact_and_guard_do_not_allocate_when_warm() {
    let secrets = gen_secrets(11, 300);
    let refs: Vec<&[u8]> = secrets.iter().map(|s| s.as_bytes()).collect();
    for kind in [EngineKind::AhoCorasick, EngineKind::HashWindow] {
        let cfg = Config {
            engine: EngineChoice::Fixed(kind),
            ..Config::default()
        };
        let s = common::snapshot_with(&refs, ValueClass::Credential, &cfg);
        let (body, _) = gen_body(5, 200_000, &secrets);
        let mut ws = Workspace::new();
        let mut out = Vec::new();
        // Warm up: buffers grow, regex caches fill.
        for _ in 0..3 {
            s.redactor().redact(&body, &mut out).unwrap();
            s.protect(&body, &mut ws).unwrap();
        }
        let region = Region::new(GLOBAL);
        for _ in 0..5 {
            let st = s.redactor().redact(&body, &mut out).unwrap();
            assert!(st.credential > 10);
            let p = s.protect(&body, &mut ws).unwrap();
            assert_eq!(p.guard, GuardOutcome::Clean);
        }
        let ch = region.change();
        assert_eq!(ch.allocations + ch.reallocations, 0, "{kind:?}: {ch:?}");
    }
}
