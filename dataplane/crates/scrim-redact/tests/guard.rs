//! The guard catches values the redactor is made to miss.
//!
//! Each test bypasses the redactor (the guard runs on the raw input, or the redactor is built
//! without the value) and checks the guard finds, repairs or withholds.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    unreachable_pub,
    missing_docs
)]

mod common;

use std::sync::Arc;

use common::fixtures::{b64, gen_body, gen_secrets, hex, json_escape, url_encode};
use common::*;
use scrim_redact::*;

const V: &str = "Gu4rd/Value+42 \"q\" é tail";

fn guard_snapshot(values: &[&[u8]]) -> Snapshot {
    snapshot_with(values, ValueClass::Credential, &no_detectors())
}

/// Runs the guard directly over `body`, as if the redactor had missed everything.
fn bypass(s: &Snapshot, body: &[u8]) -> (Option<Vec<u8>>, Vec<GuardFinding>) {
    let mut gs = GuardScratch::new();
    match s.guard().check(body, &mut gs) {
        Verdict::Clean => (None, vec![]),
        Verdict::Repaired { bytes, findings } => (Some(bytes.to_vec()), findings.to_vec()),
        Verdict::Withhold(r) => panic!("withheld: {r:?}"),
    }
}

fn decodes_to_value(out: &[u8], v: &[u8]) -> bool {
    decoded_views(out).iter().any(|d| contains(d, v))
        || contains(&out.to_ascii_lowercase(), &v.to_ascii_lowercase())
}

/// Strict independent decoding of an output: base64 at every alignment of every run.
fn decoded_views(out: &[u8]) -> Vec<Vec<u8>> {
    let mut views = Vec::new();
    let alpha = |c: u8| c.is_ascii_alphanumeric() || b"+/-_".contains(&c);
    for run in out.split(|&c| !alpha(c)) {
        for a in 0..4.min(run.len()) {
            let dec: Vec<u8> = run[a..]
                .chunks(4)
                .flat_map(|q| {
                    let val = |c: u8| match c {
                        b'A'..=b'Z' => c - b'A',
                        b'a'..=b'z' => c - b'a' + 26,
                        b'0'..=b'9' => c - b'0' + 52,
                        b'+' | b'-' => 62,
                        _ => 63,
                    };
                    let mut acc = 0u32;
                    for (k, &c) in q.iter().enumerate() {
                        acc |= u32::from(val(c)) << (18 - 6 * k);
                    }
                    (0..(q.len() * 6) / 8).map(move |k| (acc >> (16 - 8 * k)) as u8)
                })
                .collect();
            views.push(dec);
        }
    }
    views
}

#[test]
fn guard_catches_every_form() {
    let v = V.as_bytes();
    let s = guard_snapshot(&[v]);
    let mut forms: Vec<(&str, Vec<u8>, GuardView)> = vec![
        ("raw", v.to_vec(), GuardView::Raw),
        ("upper", V.to_ascii_uppercase().into_bytes(), GuardView::Raw),
        (
            "json",
            json_escape(V, false, false).into_bytes(),
            GuardView::Json,
        ),
        (
            "json-slash",
            json_escape(V, true, false).into_bytes(),
            GuardView::Json,
        ),
        (
            "json-ascii",
            json_escape(V, false, true).into_bytes(),
            GuardView::Json,
        ),
        (
            "json-double",
            json_escape(&json_escape(V, false, false), false, false).into_bytes(),
            GuardView::JsonTwice,
        ),
        ("url", url_encode(V).into_bytes(), GuardView::Url),
        (
            "url-lower",
            url_encode(V).to_lowercase().into_bytes(),
            GuardView::Url,
        ),
        ("hex", hex(v).into_bytes(), GuardView::Hex),
        (
            "hex-upper",
            hex(v).to_uppercase().into_bytes(),
            GuardView::Hex,
        ),
    ];
    for pre in 0..4 {
        for url in [false, true] {
            let stream = [vec![b'#'; pre], v.to_vec(), b"~~".to_vec()].concat();
            forms.push((
                "base64",
                b64(&stream, url, true).into_bytes(),
                GuardView::Base64,
            ));
            // Glued to other base64 characters, so the run starts at every alignment.
            for glue in ["Q", "Qx", "Qx7"] {
                let glued = format!("{glue}{}", b64(&stream, url, true));
                forms.push(("base64-glued", glued.into_bytes(), GuardView::Base64));
            }
        }
    }
    // Wrapped base64 (76 columns, like `base64` without -w0) inside JSON.
    let long = [b"prefix-bytes-".as_slice(), v, b"-suffix"].concat();
    let wrapped: String = b64(&[long.as_slice(); 3].concat(), false, true)
        .as_bytes()
        .chunks(20)
        .map(|c| std::str::from_utf8(c).unwrap().to_string() + "\\n")
        .collect();
    forms.push((
        "base64-wrapped-json",
        wrapped.into_bytes(),
        GuardView::Base64,
    ));
    // base64 inside JSON with escaped slashes.
    let b = b64(&[b"xx".as_slice(), v].concat(), false, true).replace('/', "\\/");
    forms.push(("base64-json-slash", b.into_bytes(), GuardView::Base64));

    for (name, form, view) in forms {
        let body = [b"{\"content\":\"start ".as_slice(), &form, b" end\"}"].concat();
        let (rep, findings) = bypass(&s, &body);
        let rep = rep.unwrap_or_else(|| panic!("{name}: not caught"));
        assert!(
            findings
                .iter()
                .any(|f| f.view == view && f.entry == EntryId(1)),
            "{name}: {findings:?}"
        );
        assert!(!decodes_to_value(&rep, v), "{name}: value survived repair");
        assert!(contains(&rep, "\u{27e6}scrim:s1:".as_bytes()), "{name}");
        assert!(
            rep.starts_with(b"{\"content\":\"start ") && rep.ends_with(b" end\"}"),
            "{name}: context damaged"
        );
    }
}

#[test]
fn redactor_missing_a_value_is_caught_by_protect() {
    // The redactor knows only `a`; the guard is given both. Simulate by building two snapshots and
    // feeding the redactor's output of the first to the guard of the second.
    let a: &[u8] = b"value-the-redactor-knows";
    let b: &[u8] = b"value-the-redactor-misses";
    let partial = guard_snapshot(&[a]);
    let full = guard_snapshot(&[a, b]);
    let body = [b"x ".as_slice(), a, b" y ", b, b" z"].concat();
    let redacted = redact(&partial, &body);
    assert!(contains(&redacted, b));
    let mut gs = GuardScratch::new();
    match full.guard().check(&redacted, &mut gs) {
        Verdict::Repaired { bytes, findings } => {
            assert!(!contains(bytes, b) && !contains(bytes, a));
            assert_eq!(
                findings,
                &[GuardFinding {
                    entry: EntryId(2),
                    view: GuardView::Raw
                }]
            );
        }
        v => panic!("{v:?}"),
    }
}

#[test]
fn clean_redactor_output_is_clean() {
    let secrets = gen_secrets(7, 150);
    let refs: Vec<&[u8]> = secrets.iter().map(|s| s.as_bytes()).collect();
    let s = guard_snapshot(&refs);
    let (body, n) = gen_body(99, 200_000, &secrets);
    assert!(n > 25);
    let mut ws = Workspace::new();
    let p = s.protect(&body, &mut ws).unwrap();
    assert_eq!(p.guard, GuardOutcome::Clean, "{:?}", p.findings);
    // And the guard alone over the unredacted body finds and repairs every one.
    let lenient = snapshot_with(
        &refs,
        ValueClass::Credential,
        &Config {
            guard_max_repairs: 10_000,
            ..no_detectors()
        },
    );
    let mut gs = GuardScratch::new();
    match lenient.guard().check(&body, &mut gs) {
        Verdict::Repaired { bytes, findings } => {
            assert!(
                findings.len() >= n,
                "{} findings for {n} hits",
                findings.len()
            );
            let views = decoded_views(bytes);
            let lower = bytes.to_ascii_lowercase();
            for v in &refs {
                assert!(!contains(&lower, &v.to_ascii_lowercase()));
                assert!(!views.iter().any(|d| contains(d, v)));
            }
        }
        v => panic!("{v:?}"),
    }
    let strict = snapshot_with(
        &refs,
        ValueClass::Credential,
        &Config {
            guard_max_repairs: 5,
            ..no_detectors()
        },
    );
    let mut gs = GuardScratch::new();
    assert_eq!(
        strict.guard().check(&body, &mut gs),
        Verdict::Withhold(WithholdReason::TooManyInterventions)
    );
}

#[test]
fn short_values_exact_only() {
    let s = guard_snapshot(&[b"pw42x"]);
    assert!(bypass(&s, b"the pw42x here").0.is_some());
    assert!(
        bypass(&s, b"the PW42X here").0.is_none(),
        "short values are case-sensitive"
    );
    assert!(
        bypass(&s, hex(b"pw42x").as_bytes()).0.is_none(),
        "short values are not decoded"
    );
}

#[test]
fn genuine_placeholders_are_left_alone() {
    // A short numeric value that occurs inside a placeholder's hex tag is not a leak.
    let long: &[u8] = b"long-display-value-1";
    let s0 = guard_snapshot(&[long]);
    let ph = redact(&s0, long);
    let tag = &ph[ph.len() - 3 - 16..ph.len() - 3];
    let short = &tag[..5];
    let s = Snapshot::build(
        vec![
            Entry::new(
                1,
                RefSlug::new("s1").unwrap(),
                ValueClass::Credential,
                SecretValue::from_slice(long),
            ),
            Entry::new(
                2,
                RefSlug::new("s2").unwrap(),
                ValueClass::Credential,
                SecretValue::from_slice(short),
            ),
        ],
        keyring(),
        &no_detectors(),
    )
    .unwrap();
    let body = [b"history: ".as_slice(), &ph, b" now ", short].concat();
    let out = redact(&s, &body);
    assert!(
        out.starts_with(&[b"history: ".as_slice(), &ph].concat()),
        "genuine placeholder kept"
    );
    assert!(!out.ends_with(short));
    let mut ws = Workspace::new();
    assert_eq!(
        s.protect(&body, &mut ws).unwrap().guard,
        GuardOutcome::Clean
    );
    // A fake placeholder wrapping the value protects nothing.
    let fake = format!(
        "\u{27e6}scrim:{}:01aaaaaaaaaaaaaaaa\u{27e7}",
        "long-display-value-1"
    );
    let out = redact(&s, fake.as_bytes());
    assert!(!contains(&out, long));
}

#[test]
fn withhold_when_too_many() {
    let s = Snapshot::build(
        entries(&[b"repeat-me-123"], ValueClass::Credential),
        keyring(),
        &Config {
            guard_max_repairs: 3,
            ..no_detectors()
        },
    )
    .unwrap();
    let body = b"REPEAT-ME-123 ".repeat(4);
    let mut gs = GuardScratch::new();
    assert_eq!(
        s.guard().check(&body, &mut gs),
        Verdict::Withhold(WithholdReason::TooManyInterventions)
    );
    let mut ws = Workspace::new();
    assert_eq!(
        s.protect(&body, &mut ws).unwrap_err(),
        Error::Withheld(WithholdReason::TooManyInterventions)
    );
    assert!(s.protect(&b"REPEAT-ME-123 ".repeat(3), &mut ws).is_ok());
}

#[test]
fn overlapping_findings_merge() {
    let s = Snapshot::build(
        vec![
            Entry::new(
                1,
                RefSlug::new("a").unwrap(),
                ValueClass::Credential,
                SecretValue::from_slice(b"OUTER-VALUE-XYZ"),
            ),
            Entry::new(
                2,
                RefSlug::new("b").unwrap(),
                ValueClass::Credential,
                SecretValue::from_slice(b"value-xyzinner"),
            ),
        ],
        Arc::new(Keyring::new(PlaceholderKey::new(1, &[9; 32]).unwrap())),
        &no_detectors(),
    )
    .unwrap();
    let mut gs = GuardScratch::new();
    match s.guard().check(b"[OUTER-VALUE-XYZinner]", &mut gs) {
        Verdict::Repaired { bytes, findings } => {
            assert_eq!(findings.len(), 2);
            assert!(!contains(&bytes.to_ascii_lowercase(), b"outer-value-xyz"));
            assert!(!contains(&bytes.to_ascii_lowercase(), b"value-xyzinner"));
            assert!(bytes.starts_with(b"[") && bytes.ends_with(b"]"));
        }
        v => panic!("{v:?}"),
    }
}
