//! The guard never panics, a repair leaves nothing it can find, a value JSON-escaped up to the
//! configured depth in any mix of styles is found, the guard reaches the same verdict as the
//! pre-optimisation guard kept as an oracle, on one thread and split over several, and a value
//! reversed, spaced, one character per line or written as decimal bytes is found.
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
    // With a marker byte, embed the first long value nested in JSON strings: the guard alone (no
    // redactor) must find it at every depth up to the default.
    if let Some((&0xFD, rest)) = body.split_first()
        && let Some(v) = vals.iter().find(|v| v.len() >= 8)
        && let Some((&sel, rest)) = rest.split_first()
    {
        let depth = 1 + usize::from(sel % 3);
        let styles: Vec<u8> = (0..depth).map(|i| (sel >> (2 + 2 * i)) % 6).collect();
        let form = common::json_nested(v, &styles);
        let mid = rest.len() / 2;
        let embedded = [&rest[..mid], b" ", &form, b" ", &rest[mid..]].concat();
        let mut gs = GuardScratch::new();
        assert!(
            !matches!(s.guard().check(&embedded, &mut gs), Verdict::Clean),
            "nested form at depth {depth} missed"
        );
        assert!(s.guard().agrees_with_oracle(&embedded));
    }
    assert!(s.guard().agrees_with_oracle(body));
    if let Some(p) =
        common::snapshot_threads(&vals, 8, EngineChoice::Auto, ValueClass::Credential, 3)
    {
        assert!(p.guard().agrees_with_oracle(body));
    }
    // With another marker, embed the first long value in a tool transform (reversed, spaced,
    // one per line, or as decimal bytes): the guard alone must find it.
    if let Some((&0xFC, rest)) = body.split_first()
        && let Some(v) = vals.iter().find(|v| v.len() >= 8)
        && let Some((&sel, rest)) = rest.split_first()
        // Separated forms are text tools' output: printable ASCII, not starting with a space.
        && (sel % 4 == 0 || sel % 4 == 3 || (v[0] != b' ' && v.iter().all(|c| (0x20..0x7f).contains(c))))
    {
        let form: Vec<u8> = match sel % 4 {
            0 => v.iter().rev().copied().collect(),
            1 => v.iter().flat_map(|&c| [c, b' ']).collect(),
            2 => v.iter().flat_map(|&c| [c, b'\n']).collect(),
            _ => v
                .iter()
                .flat_map(|&c| format!("{c} ").into_bytes())
                .collect(),
        };
        let mid = rest.len() / 2;
        let embedded = [&rest[..mid], b"\n", &form, b"\n", &rest[mid..]].concat();
        let mut gs = GuardScratch::new();
        assert!(
            !matches!(s.guard().check(&embedded, &mut gs), Verdict::Clean),
            "transform {} missed",
            sel % 4
        );
    }
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
