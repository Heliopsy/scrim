//! The guard's optional transform decoders (`TransformConfig`): look-alike Unicode, base85,
//! compressed documents, spelled-out values and short split fragments. Each form is caught with
//! its transform on and passes with it off; the redactor is bypassed so only the guard decides.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    unreachable_pub,
    missing_docs
)]

mod common;

use std::io::Write as _;

use common::fixtures::{BASE62, Rng, b64};
use common::*;
use scrim_redact::*;

fn snap(v: &[u8], tx: TransformConfig) -> Snapshot {
    snapshot_with(
        &[v],
        ValueClass::Credential,
        &Config {
            transforms: tx,
            ..no_detectors()
        },
    )
}

fn all_on() -> TransformConfig {
    TransformConfig {
        compressed: true,
        base85: true,
        ..TransformConfig::default()
    }
}

/// The guard alone over `body`: the views it found the value in, or none.
fn guard_views(s: &Snapshot, body: &[u8]) -> (Vec<GuardView>, Vec<u8>) {
    let mut gs = GuardScratch::new();
    match s.guard().check(body, &mut gs) {
        Verdict::Clean => (vec![], body.to_vec()),
        Verdict::Repaired { bytes, findings } => {
            (findings.iter().map(|f| f.view).collect(), bytes.to_vec())
        }
        Verdict::Withhold(r) => panic!("withheld: {r:?}"),
    }
}

/// A value with letters that have look-alikes and the digits `0` and `1`.
fn value(r: &mut Rng) -> String {
    format!("aePoc{}x0Kp1M{}", r.string(BASE62, 8), r.string(BASE62, 7))
}

fn homoglyphs(v: &str) -> String {
    v.chars()
        .map(|c| match c {
            'a' => 'а',
            'e' => 'е',
            'o' => 'о',
            'p' => 'р',
            'c' => 'с',
            'x' => 'х',
            'K' => 'К',
            'M' => 'М',
            'P' => 'Р',
            c => c,
        })
        .collect()
}

fn fullwidth(v: &str) -> String {
    v.chars()
        .map(|c| char::from_u32(c as u32 + 0xFEE0).unwrap())
        .collect()
}

fn math_bold(v: &str) -> String {
    v.chars()
        .map(|c| match c {
            'A'..='Z' => char::from_u32(0x1D400 + (c as u32 - 'A' as u32)).unwrap(),
            'a'..='z' => char::from_u32(0x1D41A + (c as u32 - 'a' as u32)).unwrap(),
            '0'..='9' => char::from_u32(0x1D7CE + (c as u32 - '0' as u32)).unwrap(),
            c => c,
        })
        .collect()
}

/// Zero-width characters at uneven places, as an agent hiding a value would put them.
fn invisible(v: &str) -> String {
    let mut out = String::new();
    for (i, c) in v.chars().enumerate() {
        out.push(c);
        match i % 5 {
            1 => out.push('\u{200B}'),
            3 => out.push_str("\u{2060}\u{00AD}"),
            _ => {}
        }
    }
    out
}

fn b85(v: &[u8], alphabet: &[u8]) -> String {
    let mut out = String::new();
    for g in v.chunks(4) {
        let mut q = [0u8; 4];
        q[..g.len()].copy_from_slice(g);
        let mut n = u32::from_be_bytes(q);
        let mut d = [0u8; 5];
        for x in d.iter_mut().rev() {
            *x = alphabet[(n % 85) as usize];
            n /= 85;
        }
        out.push_str(std::str::from_utf8(&d[..g.len() + 1]).unwrap());
    }
    out
}

const A85: &[u8] =
    b"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu";
const Z85: &[u8] =
    b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";
const RFC1924: &[u8] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";

fn spelled(v: &str, sep: &str) -> String {
    const NATO: [&str; 26] = [
        "alfa", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india",
        "juliett", "kilo", "lima", "mike", "november", "oscar", "papa", "quebec", "romeo",
        "sierra", "tango", "uniform", "victor", "whiskey", "xray", "yankee", "zulu",
    ];
    const DIGITS: [&str; 10] = [
        "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine",
    ];
    v.chars()
        .map(|c| match c {
            'a'..='z' => NATO[(c as u8 - b'a') as usize].to_string(),
            'A'..='Z' => format!("capital {}", NATO[(c as u8 - b'A') as usize]),
            '0'..='9' => DIGITS[(c as u8 - b'0') as usize].to_string(),
            '-' => "dash".to_string(),
            '_' => "underscore".to_string(),
            _ => c.to_string(),
        })
        .collect::<Vec<_>>()
        .join(sep)
}

fn gzip(d: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(d).unwrap();
    e.finish().unwrap()
}

fn zlib(d: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(d).unwrap();
    e.finish().unwrap()
}

fn deflate(d: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(d).unwrap();
    e.finish().unwrap()
}

fn brotli(d: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut w = brotli::CompressorWriter::new(&mut out, 4096, 9, 22);
        w.write_all(d).unwrap();
    }
    out
}

/// `base64` wrapped at 76 columns, as coreutils writes it.
fn wrapped(s: &str) -> String {
    s.as_bytes()
        .chunks(76)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every form, the transform that catches it and the view it is found in.
fn forms(v: &str) -> Vec<(&'static str, String, &'static str, GuardView)> {
    let env = format!("SERVICE=billing\nAPI_TOKEN={v}\nLOG_LEVEL=debug\nREGION=eu-west-1\n");
    let vb = v.as_bytes();
    let mut doc = b"prefix-".to_vec();
    doc.extend_from_slice(vb);
    doc.extend_from_slice(b"-and a longer suffix");
    vec![
        (
            "homoglyphs",
            homoglyphs(v),
            "confusables",
            GuardView::Confusable,
        ),
        (
            "fullwidth",
            fullwidth(v),
            "confusables",
            GuardView::Confusable,
        ),
        (
            "math-bold",
            math_bold(v),
            "confusables",
            GuardView::Confusable,
        ),
        (
            "zero-width",
            invisible(v),
            "confusables",
            GuardView::Confusable,
        ),
        (
            "unicode-tags",
            format!(
                "see{}{}{} here",
                "\u{E0001}",
                v.chars()
                    .map(|c| char::from_u32(0xE0000 + c as u32).unwrap())
                    .collect::<String>(),
                "\u{E007F}",
            ),
            "confusables",
            GuardView::Confusable,
        ),
        (
            "homoglyphs-in-json",
            format!(r#"{{"content":"token: {}\n"}}"#, homoglyphs(v)),
            "confusables",
            GuardView::Confusable,
        ),
        ("ascii85", b85(vb, A85), "base85", GuardView::Raw),
        ("z85-in-doc", b85(&doc, Z85), "base85", GuardView::Raw),
        (
            "rfc1924-in-doc",
            b85(&doc, RFC1924),
            "base85",
            GuardView::Raw,
        ),
        (
            "gzip-base64",
            b64(&gzip(env.as_bytes()), false, true),
            "compressed",
            GuardView::Compressed,
        ),
        (
            "gzip-base64-wrapped",
            wrapped(&b64(&gzip(env.repeat(4).as_bytes()), false, true)),
            "compressed",
            GuardView::Compressed,
        ),
        (
            "zlib-base64",
            b64(&zlib(env.as_bytes()), false, true),
            "compressed",
            GuardView::Compressed,
        ),
        (
            "zstd-base64",
            b64(&zstd::encode_all(env.as_bytes(), 3).unwrap(), false, true),
            "compressed",
            GuardView::Compressed,
        ),
        (
            "brotli-base64",
            b64(&brotli(env.as_bytes()), false, true),
            "compressed",
            GuardView::Compressed,
        ),
        (
            "deflate-base64",
            b64(&deflate(env.as_bytes()), false, true),
            "compressed",
            GuardView::Compressed,
        ),
        ("nato", spelled(v, " "), "spelled-out", GuardView::Spelled),
        (
            "nato-commas",
            spelled(v, ", "),
            "spelled-out",
            GuardView::Spelled,
        ),
        (
            "nato-lines",
            spelled(v, "\n"),
            "spelled-out",
            GuardView::Spelled,
        ),
        (
            "nato-in-json",
            format!(r#"{{"content":"{}"}}"#, spelled(v, " ")),
            "spelled-out",
            GuardView::Spelled,
        ),
        (
            "split-3-fields",
            format!(
                r#"{{"a":"{}","b":"{}","c":"{}"}}"#,
                &v[..9],
                &v[9..18],
                &v[18..]
            ),
            "split-fragments",
            GuardView::Fragment,
        ),
        (
            "split-3-blocks",
            format!(
                "first part {} then {} and {}.",
                &v[..8],
                &v[8..18],
                &v[18..]
            ),
            "split-fragments",
            GuardView::Fragment,
        ),
    ]
}

#[test]
fn each_transform_catches_its_forms_and_only_when_on() {
    let mut r = Rng::new(77);
    let v = value(&mut r);
    assert_eq!(v.len(), 26);
    let on = snap(v.as_bytes(), all_on());
    for (name, text, transform, view) in forms(&v) {
        // The form does not hold the value, case aside: only the transform can find it.
        assert!(
            !text.to_lowercase().contains(&v.to_lowercase()),
            "{name} holds the value"
        );
        let (views, repaired) = guard_views(&on, text.as_bytes());
        assert!(views.contains(&view), "{name}: {views:?} {text}");
        // The repair leaves nothing the guard finds.
        assert_eq!(guard_views(&on, &repaired).0, vec![], "{name}: repair");
        let mut off = all_on();
        assert!(off.set(transform, false));
        let (views, _) = guard_views(&snap(v.as_bytes(), off), text.as_bytes());
        assert!(
            !views.contains(&view),
            "{name} with {transform} off: {views:?}"
        );
    }
}

/// Prose, code and agent bodies hold none of the forms: no finding with every transform on.
#[test]
fn transforms_stay_quiet_on_ordinary_text() {
    let mut r = Rng::new(3);
    let secrets: Vec<String> = (0..50).map(|_| value(&mut r)).collect();
    let refs: Vec<&[u8]> = secrets.iter().map(|s| s.as_bytes()).collect();
    let s = snapshot_with(
        &refs,
        ValueClass::Credential,
        &Config {
            transforms: all_on(),
            ..no_detectors()
        },
    );
    let (body, _) = common::fixtures::gen_body(11, 400_000, &[]);
    let text = [
        "The pilot read back: alpha bravo charlie, over. One two three four, testing.",
        "Ünïcödé prose — with “quotes”, emoji 🎉, ﬁligree, ² and Ⓐ; Привет, мир. Καλημέρα.",
        "Le café coûte 3 €; naïve façade; ẞtraße.",
        include_str!("../src/guard_tx.rs"),
        include_str!("../README.md"),
    ]
    .concat();
    for b in [&body[..], text.as_bytes()] {
        let (views, _) = guard_views(&s, b);
        assert!(views.is_empty(), "{views:?}");
    }
}

/// A password with quotes, a backslash and symbols, the leak suite's kind, in look-alikes
/// with invisible characters and spelled with its symbols as they are.
#[test]
fn values_with_symbols() {
    let mut r = Rng::new(21);
    let v = format!("pA\"{}\\x%M-{}_q", r.string(BASE62, 6), r.string(BASE62, 6));
    let s = snap(v.as_bytes(), TransformConfig::default());
    for (name, text, view) in [
        (
            "homoglyphs",
            invisible(&homoglyphs(&v)),
            GuardView::Confusable,
        ),
        ("spelled", spelled(&v, " "), GuardView::Spelled),
        (
            "spelled-json",
            format!(r#"{{"c":"{}"}}"#, spelled(&v, ", ")),
            GuardView::Spelled,
        ),
    ] {
        let (views, _) = guard_views(&s, text.as_bytes());
        assert!(views.contains(&view), "{name}: {views:?} {text}");
    }
}

/// Fragments shorter than half a value count only together: one alone, or pieces that leave
/// too much of the value out, are not findings.
#[test]
fn split_fragments_need_to_cover_the_value() {
    let mut r = Rng::new(12);
    let v = value(&mut r);
    let s = snap(v.as_bytes(), all_on());
    for text in [
        format!(r#"{{"a":"{}"}}"#, &v[..9]),
        format!(r#"{{"a":"{}","b":"{}"}}"#, &v[..9], &v[9..18]),
    ] {
        assert_eq!(guard_views(&s, text.as_bytes()).0, vec![], "{text}");
    }
}

/// The control plane validates `redaction.guard.*` against `internal/daemon/guard_transforms.json`:
/// the same names, in the same order, with the same defaults.
#[test]
fn transform_list_shared_with_the_control_plane() {
    let v: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../internal/daemon/guard_transforms.json"
    )))
    .unwrap();
    let theirs: Vec<(String, bool)> = v["transforms"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| {
            (
                t["name"].as_str().unwrap().to_string(),
                t["default"].as_bool().unwrap(),
            )
        })
        .collect();
    let ours: Vec<(String, bool)> = TRANSFORM_NAMES
        .iter()
        .map(|&n| {
            let mut on = TransformConfig::default();
            assert!(on.set(n, true));
            (n.to_string(), on == TransformConfig::default())
        })
        .collect();
    assert_eq!(theirs, ours);
}
