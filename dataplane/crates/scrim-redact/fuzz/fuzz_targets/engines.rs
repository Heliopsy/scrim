//! Aho-Corasick and hash-window engines produce identical output, and `protect` on several
//! threads (tiny regions) produces exactly what it produces on one.
#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use scrim_redact::*;

fuzz_target!(|data: &[u8]| {
    let (vals, hay) = common::split(data);
    if vals.is_empty() {
        return;
    }
    let min_len = 4 + usize::from(data[0] % 8);
    let ac = common::snapshot(
        &vals,
        min_len,
        EngineChoice::Fixed(EngineKind::AhoCorasick),
        ValueClass::Display,
    );
    let hw = common::snapshot(
        &vals,
        min_len,
        EngineChoice::Fixed(EngineKind::HashWindow),
        ValueClass::Display,
    );
    let (Some(ac), Some(hw)) = (ac, hw) else {
        return;
    };
    let (mut a, mut h) = (Vec::new(), Vec::new());
    ac.redactor().redact(hay, &mut a).unwrap();
    hw.redactor().redact(hay, &mut h).unwrap();
    assert_eq!(a, h, "engines disagree");

    let threads = 2 + usize::from(data[0] % 5);
    for (one, kind) in [(&ac, EngineKind::AhoCorasick), (&hw, EngineKind::HashWindow)] {
        let Some(par) =
            common::snapshot_threads(&vals, min_len, EngineChoice::Fixed(kind), ValueClass::Display, threads)
        else {
            return;
        };
        let (mut w1, mut w2) = (Workspace::new(), Workspace::new());
        let r1 = one
            .protect(hay, &mut w1)
            .map(|p| (p.bytes.to_vec(), p.stats, p.guard, p.findings.to_vec()));
        let r2 = par
            .protect(hay, &mut w2)
            .map(|p| (p.bytes.to_vec(), p.stats, p.guard, p.findings.to_vec()));
        assert_eq!(r1, r2, "parallel protect differs");
    }
});
