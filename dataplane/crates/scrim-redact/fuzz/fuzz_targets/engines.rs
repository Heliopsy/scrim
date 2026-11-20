//! Aho-Corasick and hash-window engines produce identical output.
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
});
