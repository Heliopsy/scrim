//! Stream restorer: split placeholders, policy, credentials, and the round-trip property.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    unreachable_pub,
    missing_docs
)]

mod common;

use common::*;
use proptest::prelude::*;
use scrim_redact::*;

fn restore_chunks(s: &Snapshot, policy: &dyn RestorePolicy, chunks: &[&str]) -> String {
    let mut b = BlockRestorer::new();
    let mut out = String::new();
    for c in chunks {
        b.push(s.resolver(), policy, c, &mut out);
        assert!(b.held_len() < MAX_PLACEHOLDER_LEN);
    }
    b.finish(&mut out);
    out
}

fn mixed() -> Snapshot {
    Snapshot::build(
        vec![
            Entry::new(
                1,
                RefSlug::new("hostname").unwrap(),
                ValueClass::Display,
                SecretValue::from_slice(b"db.internal.example"),
            ),
            Entry::new(
                2,
                RefSlug::new("api-token").unwrap(),
                ValueClass::Credential,
                SecretValue::from_slice(b"tok_credential_123456"),
            ),
        ],
        keyring(),
        &no_detectors(),
    )
    .unwrap()
}

fn ph(s: &Snapshot, v: &[u8]) -> String {
    String::from_utf8(redact(s, v)).unwrap()
}

#[test]
fn split_at_every_byte() {
    let s = mixed();
    let p = ph(&s, b"db.internal.example");
    let text = format!("connect to {p} now");
    let want = "connect to db.internal.example now";
    let idx: Vec<usize> = (0..=text.len())
        .filter(|&i| text.is_char_boundary(i))
        .collect();
    for &i in &idx {
        for &j in idx.iter().filter(|&&j| j >= i) {
            let got = restore_chunks(&s, &RestoreDisplay, &[&text[..i], &text[i..j], &text[j..]]);
            assert_eq!(got, want, "split {i}/{j}");
        }
    }
}

#[test]
fn credentials_are_never_restored() {
    let s = mixed();
    let p = ph(&s, b"tok_credential_123456");
    let text = format!("curl -H 'Authorization: Bearer {p}' https://x");
    let allow_all = |_: &EntryMeta| true;
    assert_eq!(restore_chunks(&s, &allow_all, &[&text]), text);
    let mut out = String::new();
    let st = restore_text(s.resolver(), &allow_all, &text, &mut out);
    assert_eq!(
        st,
        RestoreStats {
            restored: 0,
            kept: 1
        }
    );
    // The injection primitive does see it, when asked explicitly.
    let mut bytes = Vec::new();
    assert_eq!(
        s.resolver()
            .substitute_into(text.as_bytes(), &mut bytes, &|m| m.class
                == ValueClass::Credential),
        1
    );
    assert!(contains(&bytes, b"tok_credential_123456"));
}

#[test]
fn policy_decides_display_values() {
    let s = mixed();
    let p = ph(&s, b"db.internal.example");
    assert_eq!(restore_chunks(&s, &KeepAll, &[&p]), p);
    let only_other = |m: &EntryMeta| m.slug.as_str() == "other";
    assert_eq!(restore_chunks(&s, &only_other, &[&p]), p);
    let by_slug = |m: &EntryMeta| m.slug.as_str() == "hostname";
    assert_eq!(restore_chunks(&s, &by_slug, &[&p]), "db.internal.example");
}

#[test]
fn unresolvable_fragments_pass_unchanged() {
    let s = mixed();
    let p = ph(&s, b"db.internal.example");
    // Truncated at the end of the block: emitted as is, never partially resolved.
    let cut = &p[..p.len() - 4];
    assert_eq!(
        restore_chunks(&s, &RestoreDisplay, &["x ", cut]),
        format!("x {cut}")
    );
    // Unknown placeholder with a valid shape.
    let unknown = "\u{27e6}scrim:hostname:01ffffffffffffffff\u{27e7}";
    assert_eq!(restore_chunks(&s, &RestoreDisplay, &[unknown]), unknown);
    // Junk that starts like one.
    let junk = "\u{27e6}scrim:Hostname \u{27e6}\u{27e6}scrim:";
    assert_eq!(restore_chunks(&s, &RestoreDisplay, &[junk]), junk);
    // Plain text with no lead byte is not held back at all.
    let mut b = BlockRestorer::new();
    let mut out = String::new();
    b.push(s.resolver(), &RestoreDisplay, "plain text", &mut out);
    assert_eq!(out, "plain text");
    assert_eq!(b.held_len(), 0);
}

#[test]
fn holdback_is_bounded() {
    let s = mixed();
    let long_prefix = format!("\u{27e6}scrim:{}", "a".repeat(RefSlug::MAX_LEN));
    let mut b = BlockRestorer::new();
    let mut out = String::new();
    b.push(s.resolver(), &RestoreDisplay, &long_prefix, &mut out);
    assert!(b.held_len() < MAX_PLACEHOLDER_LEN);
    b.push(s.resolver(), &RestoreDisplay, "a", &mut out);
    // 49 slug characters cannot be a placeholder: released.
    assert_eq!(b.held_len(), 0);
    b.finish(&mut out);
    assert_eq!(out, format!("{long_prefix}a"));
}

#[test]
fn restored_value_reencodes_as_json() {
    let s = Snapshot::build(
        vec![Entry::new(
            1,
            RefSlug::new("q").unwrap(),
            ValueClass::Display,
            SecretValue::from_slice(b"say \"hi\"\n\\o/"),
        )],
        keyring(),
        &no_detectors(),
    )
    .unwrap();
    let p = ph(&s, b"say \"hi\"\n\\o/");
    let text = restore_chunks(&s, &RestoreDisplay, &[&p]);
    let mut enc = Vec::new();
    json_escape_into(&mut enc, text.as_bytes());
    assert_eq!(enc, br#"say \"hi\"\n\\o/"#);
}

fn value() -> impl Strategy<Value = String> {
    "[A-Za-z0-9_./+-]{8,24}"
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// restore(redact(x)) == x when every value is display and policy allows all, for any chunking.
    #[test]
    fn round_trip(
        values in prop::collection::hash_set(value(), 1..6),
        filler in prop::collection::vec("[ a-z,.\n]{0,12}", 1..12),
        picks in prop::collection::vec(any::<prop::sample::Index>(), 1..12),
        cuts in prop::collection::vec(any::<prop::sample::Index>(), 0..6),
    ) {
        let values: Vec<String> = values.into_iter().collect();
        let refs: Vec<&[u8]> = values.iter().map(|v| v.as_bytes()).collect();
        let s = snapshot_with(&refs, ValueClass::Display, &no_detectors());
        let mut x = String::new();
        for (f, p) in filler.iter().zip(picks.iter().cycle()) {
            x.push_str(f);
            x.push_str(p.get(&values));
        }
        let red = String::from_utf8(redact(&s, x.as_bytes())).unwrap();
        // Values could overlap one another; only check the property when the redacted text
        // holds no raw value (the usual case).
        prop_assume!(values.iter().all(|v| !red.contains(v.as_str())));
        let mut points: Vec<usize> = cuts.iter().map(|c| c.index(red.len() + 1)).filter(|&i| red.is_char_boundary(i)).collect();
        points.sort_unstable();
        let mut chunks = Vec::new();
        let mut last = 0;
        for p in points {
            chunks.push(&red[last..p]);
            last = p;
        }
        chunks.push(&red[last..]);
        let back = restore_chunks(&s, &RestoreDisplay, &chunks);
        // Overlapping values can make the redactor pick a different but equivalent split; the
        // restored text must still equal the input whenever every match was a whole value.
        let mut whole = String::new();
        restore_text(s.resolver(), &RestoreDisplay, &red, &mut whole);
        prop_assert_eq!(&back, &whole);
        prop_assert_eq!(back, x);
    }
}

#[test]
fn next_placeholder_and_meta() {
    let s = mixed();
    let p = ph(&s, b"db.internal.example");
    let text = format!("ab {p} cd");
    assert_eq!(
        next_placeholder(text.as_bytes()),
        Some(PlaceholderAt::Complete {
            start: 3,
            end: 3 + p.len()
        })
    );
    assert_eq!(
        next_placeholder(&text.as_bytes()[..10]),
        Some(PlaceholderAt::Partial { start: 3 })
    );
    assert_eq!(next_placeholder(b"no placeholder \xe2\x9f\xa6x"), None);
    assert_eq!(
        s.resolver().meta(EntryId(2)).unwrap().slug.as_str(),
        "api-token"
    );
    assert!(s.resolver().meta(EntryId(9)).is_none());
}
