//! The guard never panics, and a repair leaves nothing it can find.
#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use scrim_redact::*;

fuzz_target!(|data: &[u8]| {
    let (vals, body) = common::split(data);
    if vals.is_empty() {
        return;
    }
    let Some(s) = common::snapshot(&vals, 8, EngineChoice::Auto, ValueClass::Credential) else {
        return;
    };
    let mut gs = GuardScratch::new();
    let repaired = match s.guard().check(body, &mut gs) {
        Verdict::Clean | Verdict::Withhold(_) => return,
        Verdict::Repaired { bytes, findings } => {
            assert!(!findings.is_empty());
            bytes.to_vec()
        }
    };
    let mut gs2 = GuardScratch::new();
    assert_eq!(s.guard().check(&repaired, &mut gs2), Verdict::Clean);
    for v in vals.iter().filter(|v| v.len() >= 8) {
        assert!(!common::contains_outside(&s, &repaired, v));
    }
});
