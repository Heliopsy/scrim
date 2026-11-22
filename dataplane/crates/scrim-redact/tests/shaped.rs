//! Format-preserving placeholders through the redactor, guard and resolver (redaction spec
//! "Format-preserving placeholders").
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

use std::sync::Arc;

use scrim_redact::*;

// Generated-looking test values, never real tokens.
const GH: &str = "ghp_TeStV4lu3N0tR34l0123456789abcdefABCD";
const AKID: &str = "AKIATESTVALUE7Q2W4E6";
const AWS_SECRET: &str = "tEsTsEcReT/0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c";
const DISPLAY: &str = "display-value-0a1b2c3d4e5f6a7b";

fn key() -> PlaceholderKey {
    PlaceholderKey::new(1, &[9u8; 32]).unwrap()
}

fn snap_with(keys: Keyring, shape: bool) -> Snapshot {
    let entries = vec![
        Entry::new(
            1,
            RefSlug::new("github").unwrap(),
            ValueClass::Credential,
            SecretValue::from_slice(GH.as_bytes()),
        )
        .with_shape(shape),
        Entry::new(
            2,
            RefSlug::new("aws-akid").unwrap(),
            ValueClass::Credential,
            SecretValue::from_slice(AKID.as_bytes()),
        )
        .with_shape(shape),
        Entry::new(
            3,
            RefSlug::new("aws-secret").unwrap(),
            ValueClass::Credential,
            SecretValue::from_slice(AWS_SECRET.as_bytes()),
        )
        .with_shape(shape),
        Entry::new(
            4,
            RefSlug::new("shown").unwrap(),
            ValueClass::Display,
            SecretValue::from_slice(DISPLAY.as_bytes()),
        )
        .with_shape(shape),
    ];
    Snapshot::build(entries, Arc::new(keys), &Config::default()).unwrap()
}

fn snap() -> Snapshot {
    snap_with(Keyring::new(key()), true)
}

fn shaped(slug: &str, v: &str) -> String {
    shaped_placeholder_for(&key(), &RefSlug::new(slug).unwrap(), v.as_bytes()).unwrap()
}

#[test]
fn redactor_writes_the_shaped_placeholder_and_the_guard_passes() {
    let s = snap();
    let mut ws = Workspace::new();
    let body = format!(
        r#"{{"env":"GH_TOKEN={GH} AWS_ACCESS_KEY_ID={AKID} AWS_SECRET_ACCESS_KEY={AWS_SECRET} shown={DISPLAY}"}}"#
    );
    let out = s.protect(body.as_bytes(), &mut ws).unwrap();
    let text = String::from_utf8(out.bytes.to_vec()).unwrap();
    for v in [GH, AKID, AWS_SECRET, DISPLAY] {
        assert!(!text.contains(v), "{text}");
    }
    assert!(text.contains(&shaped("github", GH)), "{text}");
    assert!(text.contains(&shaped("aws-akid", AKID)), "{text}");
    assert!(text.contains(&shaped("aws-secret", AWS_SECRET)), "{text}");
    // Display values keep the bracket form: the restorer needs its delimiters.
    assert!(text.contains("\u{27e6}scrim:shown:"), "{text}");
    assert_eq!(s.report().shape_fallback, vec![EntryId(4)]);
}

#[test]
fn a_shaped_placeholder_in_the_input_is_kept_byte_for_byte() {
    // A client that checks the `ghp_` prefix accepted the placeholder and the agent pasted it back:
    // the GitHub token detector must not take it for a token, and redaction must not change it.
    let s = snap();
    let mut ws = Workspace::new();
    let ph = shaped("github", GH);
    let body = format!(
        "gh auth status shows token {ph} and ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa is unknown"
    );
    let out = s.protect(body.as_bytes(), &mut ws).unwrap();
    let text = String::from_utf8(out.bytes.to_vec()).unwrap();
    assert!(text.contains(&ph), "{text}");
    // The unknown look-alike token is still caught by the detector.
    assert!(!text.contains("ghp_aaaa"), "{text}");
    assert_eq!(out.stats.detected, 1);
}

#[test]
fn guard_catches_the_value_even_when_redaction_is_skipped() {
    // The guard checks the outgoing bytes independently: a raw value next to a shaped placeholder
    // is still found (here through the guard alone).
    let s = snap();
    let mut scratch = GuardScratch::new();
    let ph = shaped("github", GH);
    let bytes = format!("{ph} {GH}");
    assert!(
        s.guard().check(bytes.as_bytes(), &mut scratch) != Verdict::Clean,
        "the guard missed the value"
    );
    let clean = format!("{ph} and nothing else");
    assert!(matches!(
        s.guard().check(clean.as_bytes(), &mut scratch),
        Verdict::Clean
    ));
}

#[test]
fn resolver_recognises_shaped_placeholders_of_every_retained_key() {
    let old = PlaceholderKey::new(1, &[9u8; 32]).unwrap();
    let new = PlaceholderKey::new(2, &[8u8; 32]).unwrap();
    let ring = Keyring::new(new).retain(old).unwrap();
    let s = snap_with(ring, true);
    let before = shaped("github", GH);
    let r = s
        .resolver()
        .resolve(before.as_bytes())
        .expect("old-key placeholder resolves");
    assert_eq!(r.meta.id, EntryId(1));
    assert_eq!(r.expose(), GH.as_bytes());
    let new_ph = shaped_placeholder_for(
        &PlaceholderKey::new(2, &[8u8; 32]).unwrap(),
        &RefSlug::new("github").unwrap(),
        GH.as_bytes(),
    )
    .unwrap();
    assert!(s.resolver().resolve(new_ph.as_bytes()).is_some());
    assert!(
        s.resolver()
            .resolve(b"ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .is_none()
    );
    // Credentials are never restored into text, whatever their form.
    let mut out = String::new();
    let mut b = BlockRestorer::new();
    b.push(
        s.resolver(),
        &RestoreDisplay,
        &format!("token {before}"),
        &mut out,
    );
    b.finish(&mut out);
    assert!(out.contains(&before) && !out.contains(GH));
}

#[test]
fn without_the_opt_in_the_bracket_form_is_used() {
    let s = snap_with(Keyring::new(key()), false);
    let mut ws = Workspace::new();
    let out = s.protect(GH.as_bytes(), &mut ws).unwrap();
    let text = String::from_utf8(out.bytes.to_vec()).unwrap();
    assert!(text.starts_with("\u{27e6}scrim:github:"), "{text}");
    assert!(s.report().shape_fallback.is_empty());
}

#[test]
fn find_matches_reports_shaped_spans() {
    let s = snap();
    let body = format!("a {GH} b");
    let mut seen = Vec::new();
    s.redactor()
        .find_matches(body.as_bytes(), &mut |a, b, p| {
            seen.push((a, b, p.to_vec()))
        })
        .unwrap();
    assert_eq!(
        seen,
        vec![(2, 2 + GH.len(), shaped("github", GH).into_bytes())]
    );
}
