//! Redactor behaviour: variants, minimum length, determinism, rotation, detectors, leaks.
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

use common::fixtures::{b64, hex, json_escape, url_encode};
use common::*;
use scrim_redact::*;

const V: &str = "S3cr3t/Value+with \"quotes\" é and spaces";

fn both_engines(values: &[&[u8]], f: impl Fn(&Snapshot)) {
    for kind in [EngineKind::AhoCorasick, EngineKind::HashWindow] {
        let s = snapshot_with(values, ValueClass::Display, &engine(kind));
        assert_eq!(s.redactor().engine(), kind);
        f(&s);
    }
}

/// Every encoded form, embedded in surrounding text, is replaced and no form survives.
#[test]
fn each_variant_is_replaced() {
    let v = V.as_bytes();
    let mut forms: Vec<(&str, Vec<u8>)> = vec![
        ("raw", v.to_vec()),
        ("json", json_escape(V, false, false).into_bytes()),
        ("json-slash", json_escape(V, true, false).into_bytes()),
        ("json-ascii", json_escape(V, false, true).into_bytes()),
        ("json-ascii-slash", json_escape(V, true, true).into_bytes()),
        (
            "json-ascii-upper",
            json_escape(V, false, true)
                .replace("\\u00e9", "\\u00E9")
                .into_bytes(),
        ),
        (
            "json-double",
            json_escape(&json_escape(V, false, false), false, false).into_bytes(),
        ),
        ("hex", hex(v).into_bytes()),
        ("hex-upper", hex(v).to_uppercase().into_bytes()),
        ("url", url_encode(V).into_bytes()),
        (
            "url-lower",
            url_encode(V)
                .replace("%2F", "%2f")
                .replace("%2B", "%2b")
                .replace("%C3%A9", "%c3%a9")
                .into_bytes(),
        ),
        ("url-form", url_encode(V).replace("%20", "+").into_bytes()),
    ];
    // Base64 of the value inside longer streams, at every byte offset, both alphabets.
    for pre in 0..6 {
        for url in [false, true] {
            let mut stream = vec![b'#'; pre];
            stream.extend_from_slice(v);
            stream.extend_from_slice(b"~tail");
            forms.push(("base64", b64(&stream, url, true).into_bytes()));
        }
    }
    both_engines(&[v], |s| {
        for (name, form) in &forms {
            let mut body = b"{\"text\":\"before ".to_vec();
            body.extend_from_slice(form);
            body.extend_from_slice(b" after\"}");
            let out = redact(s, &body);
            assert!(!contains(&out, form), "{name}: form survived");
            assert!(
                contains(&out, "\u{27e6}scrim:s1:".as_bytes()),
                "{name}: no placeholder"
            );
            if *name == "base64" {
                // Decoding the remains at any alignment never yields the value.
                assert!(!contains(&out, v));
            }
        }
    });
}

#[test]
fn variant_is_reported() {
    let s = snapshot_with(&[V.as_bytes()], ValueClass::Credential, &no_detectors());
    let body = format!("x {} y {}", hex(V.as_bytes()), url_encode(V));
    let mut seen = Vec::new();
    let mut out = Vec::new();
    let st = s
        .redactor()
        .redact_with(body.as_bytes(), &mut out, &mut |h| {
            if let Hit::Known { meta, variant, .. } = h {
                seen.push((meta.id, variant));
            }
        })
        .unwrap();
    assert_eq!(
        st,
        Stats {
            credential: 2,
            display: 0,
            detected: 0
        }
    );
    assert_eq!(
        seen,
        vec![
            (EntryId(1), Variant::HexLower),
            (EntryId(1), Variant::UrlUpper)
        ]
    );
}

/// Values at and around the minimum length, with the default and a custom minimum.
#[test]
fn minimum_length_rule() {
    for min_len in [8usize, 12] {
        let cfg = Config {
            min_len,
            ..no_detectors()
        };
        for len in 4..=min_len + 2 {
            let v: Vec<u8> = (0..len).map(|i| b"Qx7#kLm9pZ2&vB4!"[i % 16]).collect();
            let s = snapshot_with(&[&v], ValueClass::Display, &cfg);
            assert_eq!(s.report().short, usize::from(len < min_len), "len {len}");
            // Whole value: replaced.
            let out = redact(&s, &[b"a ", v.as_slice(), b" b"].concat());
            assert!(!contains(&out, &v), "len {len} min {min_len}");
            // Whole base64 encoding: replaced for short and long values.
            let whole = b64(&v, false, true);
            assert!(
                !contains(&redact(&s, whole.as_bytes()), whole.as_bytes()),
                "b64 whole len {len}"
            );
            // Hex: replaced.
            assert!(!contains(
                &redact(&s, hex(&v).as_bytes()),
                hex(&v).as_bytes()
            ));
            // An inner base64 fragment (value at offset 1 of a stream): only long values.
            let frag = b64(&[b"#".as_slice(), &v, b"~~~"].concat(), false, true);
            let out = redact(&s, frag.as_bytes());
            assert_eq!(
                out == frag.as_bytes(),
                len < min_len,
                "fragment len {len} min {min_len}"
            );
        }
    }
}

#[test]
fn below_floor_is_rejected_and_reported() {
    let s = Snapshot::build(
        entries(&[b"abc", b"long enough value"], ValueClass::Display),
        keyring(),
        &no_detectors(),
    )
    .unwrap();
    assert_eq!(s.report().rejected, vec![EntryId(1)]);
    assert_eq!(s.report().values, 1);
    assert!(
        Snapshot::build(
            vec![],
            keyring(),
            &Config {
                short_floor: 3,
                ..Config::default()
            }
        )
        .is_err()
    );
    assert!(
        Snapshot::build(
            vec![],
            keyring(),
            &Config {
                min_len: 5,
                short_floor: 6,
                ..Config::default()
            }
        )
        .is_err()
    );
}

#[test]
fn not_ready_until_stored() {
    let h = SnapshotHandle::new();
    assert!(!h.is_ready());
    assert_eq!(h.load().unwrap_err(), Error::NotReady);
    assert_eq!(
        Error::NotReady.to_string(),
        "redaction is not ready: known values have not loaded"
    );
    h.store(Arc::new(snapshot(&[b"value-12345678"])));
    assert!(h.load().is_ok());
}

#[test]
fn input_size_limit() {
    let s = snapshot_with(
        &[b"value-12345678"],
        ValueClass::Display,
        &Config {
            max_input: 10,
            ..no_detectors()
        },
    );
    let mut out = Vec::new();
    assert_eq!(
        s.redactor().redact(b"12345678901", &mut out),
        Err(Error::InputTooLarge)
    );
    let mut ws = Workspace::new();
    assert_eq!(
        s.protect(b"12345678901", &mut ws).unwrap_err(),
        Error::InputTooLarge
    );
}

#[test]
fn deterministic_and_cache_stable() {
    let vals: Vec<Vec<u8>> = (0..50)
        .map(|i| format!("secret-number-{i:04}-xyz").into_bytes())
        .collect();
    let refs: Vec<&[u8]> = vals.iter().map(Vec::as_slice).collect();
    let a = snapshot(&refs);
    // Same entries in another order: same output.
    let mut e = entries(&refs, ValueClass::Display);
    e.reverse();
    let b = Snapshot::build(e, keyring(), &Config::default()).unwrap();
    let prefix = format!(
        "system prompt {} more {}",
        "secret-number-0007-xyz", "secret-number-0042-xyz"
    );
    let r1 = redact(&a, format!("{prefix} turn one").as_bytes());
    let r2 = redact(
        &b,
        format!("{prefix} turn two, secret-number-0001-xyz").as_bytes(),
    );
    let p = redact(&a, prefix.as_bytes());
    assert!(r1.starts_with(&p) && r2.starts_with(&p));
}

#[test]
fn duplicate_values_lowest_id_wins() {
    let e = vec![
        Entry::new(
            9,
            RefSlug::new("later").unwrap(),
            ValueClass::Display,
            SecretValue::from_slice(b"same-value-123"),
        ),
        Entry::new(
            3,
            RefSlug::new("first").unwrap(),
            ValueClass::Display,
            SecretValue::from_slice(b"same-value-123"),
        ),
    ];
    let s = Snapshot::build(e, keyring(), &Config::default()).unwrap();
    assert_eq!(s.report().duplicates, 1);
    assert!(contains(&redact(&s, b"same-value-123"), b"scrim:first:"));
}

#[test]
fn rotation_keeps_old_placeholders_resolving() {
    let v: &[u8] = b"rotating-display-value";
    let k1 = Arc::new(Keyring::new(PlaceholderKey::new(1, &[1; 32]).unwrap()));
    let old = Snapshot::build(entries(&[v], ValueClass::Display), k1, &Config::default()).unwrap();
    let old_ph = redact(&old, v);

    let k2 = Arc::new(
        Keyring::new(PlaceholderKey::new(2, &[2; 32]).unwrap())
            .retain(PlaceholderKey::new(1, &[1; 32]).unwrap())
            .unwrap(),
    );
    let new = Snapshot::build(entries(&[v], ValueClass::Display), k2, &Config::default()).unwrap();
    let new_ph = redact(&new, v);
    assert_ne!(old_ph, new_ph);
    assert!(contains(&new_ph, b":02"));
    assert_eq!(new.resolver().resolve(&old_ph).unwrap().expose(), v);
    assert_eq!(new.resolver().resolve(&new_ph).unwrap().expose(), v);

    // Once retired, the old key's placeholders no longer resolve.
    let k3 = Arc::new(Keyring::new(PlaceholderKey::new(2, &[2; 32]).unwrap()));
    let retired =
        Snapshot::build(entries(&[v], ValueClass::Display), k3, &Config::default()).unwrap();
    assert!(retired.resolver().resolve(&old_ph).is_none());
    assert!(
        Keyring::new(PlaceholderKey::new(2, &[2; 32]).unwrap())
            .retain(PlaceholderKey::new(2, &[3; 32]).unwrap())
            .is_err()
    );
    assert!(PlaceholderKey::new(0, &[0; 32]).is_err());
}

#[test]
fn resolver_checks_slug_and_tag() {
    let s = snapshot(&[b"resolvable-value-1"]);
    let p = String::from_utf8(redact(&s, b"resolvable-value-1")).unwrap();
    assert_eq!(
        s.resolver().resolve(p.as_bytes()).unwrap().meta.id,
        EntryId(1)
    );
    assert!(
        s.resolver()
            .resolve(p.replace("s1", "s2").as_bytes())
            .is_none()
    );
    let mut bad = p.clone().into_bytes();
    let n = bad.len();
    bad[n - 4] = if bad[n - 4] == b'0' { b'1' } else { b'0' };
    assert!(s.resolver().resolve(&bad).is_none());
    assert!(s.resolver().resolve(format!("{p} ").as_bytes()).is_none());
}

#[test]
fn detectors_replace_unknown_tokens() {
    let s = snapshot(&[b"known-value-0001"]);
    let body = br#"{"t":"aws AKIAIOSFODNN7EXAMPLE and ghp_abcdefghijklmnopqrstuvwxyz0123456789 known-value-0001"}"#;
    let mut rules = Vec::new();
    let mut out = Vec::new();
    let st = s
        .redactor()
        .redact_with(body, &mut out, &mut |h| {
            if let Hit::Detected { rule, .. } = h {
                rules.push(rule);
            }
        })
        .unwrap();
    assert_eq!(st.detected, 2);
    assert_eq!(st.display, 1);
    assert_eq!(rules, vec!["aws-access-key-id", "github-token"]);
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("\u{27e6}scrim:det-aws-access-key-id:01"));
    assert!(!text.contains("AKIAIOSFODNN7EXAMPLE"));
    // Detector placeholders are deterministic and never resolve.
    assert_eq!(redact(&s, body), text.as_bytes());
    for (at, p) in find_placeholders(text.as_bytes()) {
        let ph = &text.as_bytes()[at..at + p.len];
        assert_eq!(s.resolver().resolve(ph).is_some(), p.slug == b"s1");
    }
}

#[test]
fn protect_runs_both_checks() {
    let s = snapshot(&[b"protect-me-please"]);
    let mut ws = Workspace::new();
    let p = s.protect(b"say protect-me-please", &mut ws).unwrap();
    assert_eq!(p.guard, GuardOutcome::Clean);
    assert_eq!(p.stats.display, 1);
    assert!(!contains(p.bytes, b"protect-me-please"));
    // Uppercased: the redactor has no variant for it, the guard catches it.
    let p = s.protect(b"say PROTECT-ME-PLEASE", &mut ws).unwrap();
    assert_eq!(p.guard, GuardOutcome::Repaired);
    assert_eq!(
        p.findings,
        &[GuardFinding {
            entry: EntryId(1),
            view: GuardView::Raw
        }]
    );
    assert!(!contains(
        &p.bytes.to_ascii_lowercase(),
        b"protect-me-please"
    ));
}

/// Nothing this crate prints contains a value, its encodings or the key.
#[test]
fn no_value_in_debug_or_errors() {
    let v: &[u8] = b"LeakCanary-9f8e7d6c5b4a";
    let key = PlaceholderKey::new(1, b"KeyCanary-0123456789abcdef").unwrap();
    let kr = Arc::new(Keyring::new(key));
    let s = Snapshot::build(
        entries(&[v], ValueClass::Credential),
        kr.clone(),
        &Config::default(),
    )
    .unwrap();
    let mut ws = Workspace::new();
    let body = [b"x ".as_slice(), v].concat();
    let prot = format!("{:?}", s.protect(&body, &mut ws).unwrap());
    let mut gs = GuardScratch::new();
    let verdict = format!("{:?}", s.guard().check(&body, &mut gs));
    let resolved = {
        let p = redact(&s, v);
        format!("{:?}", s.resolver().resolve(&p).unwrap())
    };
    let printed = [
        format!("{:?}", SecretValue::from_slice(v)),
        format!("{:?}", entries(&[v], ValueClass::Credential)),
        format!(
            "{s:?} {:?} {:?} {:?}",
            s.redactor(),
            s.guard(),
            s.resolver()
        ),
        format!("{kr:?} {ws:?} {gs:?}"),
        prot,
        verdict,
        resolved,
        format!("{:?}", BlockRestorer::new()),
        Error::Withheld(WithholdReason::RepairIncomplete).to_string(),
        BuildError::InvalidSlug.to_string(),
    ]
    .join("\n");
    let canaries = [
        "LeakCanary".to_string(),
        "KeyCanary".to_string(),
        hex(v),
        b64(v, false, false)[..12].to_string(),
        String::from_utf8_lossy(&v[..8]).to_string(),
    ];
    for c in canaries {
        assert!(!printed.contains(&c), "{c} printed");
        assert!(
            !printed.to_lowercase().contains(&c.to_lowercase()),
            "{c} printed"
        );
    }
    // Spot check that the dump is not empty.
    assert!(printed.contains("SecretValue(<redacted>)"));
}

#[test]
fn placeholder_for_matches_redactor() {
    let kr = keyring();
    let s = Snapshot::build(
        entries(&[b"same-bytes-everywhere"], ValueClass::Display),
        kr.clone(),
        &Config::default(),
    )
    .unwrap();
    let p = placeholder_for(
        kr.current(),
        &RefSlug::new("s1").unwrap(),
        b"same-bytes-everywhere",
    );
    assert_eq!(redact(&s, b"same-bytes-everywhere"), p.as_bytes());
}

#[test]
fn slugs() {
    assert!(RefSlug::new("github-token").is_ok());
    for bad in ["", "-a", "a-", "A", "a_b", "a b", &"x".repeat(49)] {
        assert!(RefSlug::new(bad).is_err(), "{bad}");
    }
    assert_eq!(
        RefSlug::from_alias("GitHub Token (prod)").as_str(),
        "github-token-prod"
    );
    assert_eq!(RefSlug::from_alias("___").as_str(), "ref");
    assert_eq!(RefSlug::from_alias(&"ab-".repeat(40)).as_str().len(), 47);
}

/// Placeholders are inert in the contexts they land in.
#[test]
fn placeholder_is_unambiguous() {
    let p = placeholder_for(
        keyring().current(),
        &RefSlug::new("db-password").unwrap(),
        b"x",
    );
    for c in p.chars() {
        assert!(
            !c.is_whitespace() && !"\"'`$\\;&|<>(){}[]*?!#~=%^,".contains(c),
            "{c}"
        );
    }
    assert_eq!(json_escape(&p, false, false), p);
    assert_eq!(json_escape(&p, true, false), p);
}
