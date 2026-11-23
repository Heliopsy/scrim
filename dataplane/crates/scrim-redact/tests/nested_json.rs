//! JSON text nested in JSON strings: tool-call `arguments`, tool results wrapping
//! `JSON.stringify` output, MCP text blocks holding JSON. A value with characters JSON escapes is
//! escaped once per level, so each level is a different byte string.
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
use scrim_redact::*;
use serde_json::{Value, json};

/// A password like the leak suite's: letters, digits and the symbols every escaping layer treats
/// differently, generated from `seed`.
fn password(seed: u64, non_ascii: bool) -> String {
    const SYMS: &[u8] = b"\"\\/<>&='";
    let mut x = seed | 1;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut s: String = (0..14)
        .map(|_| (b'a' + (next() % 26) as u8) as char)
        .collect();
    for &c in SYMS {
        let at = (next() as usize) % (s.len() + 1);
        s.insert(at, c as char);
    }
    if non_ascii {
        s.insert(3, 'é');
    }
    s
}

#[derive(Clone, Copy, Debug)]
enum Style {
    /// serde_json, JavaScript `JSON.stringify`.
    Min,
    /// Go `encoding/json`.
    Html,
    /// Python `json.dumps`.
    Ascii,
    /// Escaped slashes (PHP, some Java).
    Slash,
    /// Every character as a `\u` escape.
    All,
}

const STYLES: [Style; 5] = [
    Style::Min,
    Style::Html,
    Style::Ascii,
    Style::Slash,
    Style::All,
];

fn u4(o: &mut String, c: char) {
    let mut b = [0u16; 2];
    for x in c.encode_utf16(&mut b) {
        o.push_str(&format!("\\u{x:04x}"));
    }
}

/// `s` as JSON string content (no quotes) in `st`.
fn esc(s: &str, st: Style) -> String {
    let mut o = String::new();
    for c in s.chars() {
        match (st, c) {
            (Style::All, c) => u4(&mut o, c),
            (_, '"') => o.push_str("\\\""),
            (_, '\\') => o.push_str("\\\\"),
            (_, '\n') => o.push_str("\\n"),
            (Style::Slash, '/') => o.push_str("\\/"),
            (Style::Html, '<' | '>' | '&') => u4(&mut o, c),
            (Style::Ascii, c) if !c.is_ascii() => u4(&mut o, c),
            (_, c) if (c as u32) < 0x20 => u4(&mut o, c),
            (_, c) => o.push(c),
        }
    }
    o
}

/// The value inside `{"command":"..."}` objects nested `styles.len()` levels deep, the innermost
/// level first, inside a request body.
fn nested_body(v: &str, styles: &[Style]) -> String {
    let mut t = format!("printf '%s' '{v}' > .env");
    for &st in styles {
        t = format!("{{\"command\":\"{}\"}}", esc(&t, st));
    }
    format!("{{\"messages\":[{{\"role\":\"tool\",\"content\":{t}}}]}}")
}

/// Every string in `v`, and every string of every string that is itself JSON, at any depth.
fn strings_deep(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => {
            out.push(s.clone());
            if let Ok(inner) = serde_json::from_str::<Value>(s)
                && (inner.is_object() || inner.is_array() || inner.is_string())
            {
                strings_deep(&inner, out);
            }
        }
        Value::Array(a) => a.iter().for_each(|x| strings_deep(x, out)),
        Value::Object(m) => m.iter().for_each(|(k, x)| {
            out.push(k.clone());
            strings_deep(x, out);
        }),
        _ => {}
    }
}

/// Whether `body` parses and none of its strings, at any nesting, holds `v`.
fn deep_clean(body: &[u8], v: &str) -> bool {
    let doc: Value = serde_json::from_slice(body).expect("body is JSON");
    let mut all = Vec::new();
    strings_deep(&doc, &mut all);
    all.iter().all(|s| !s.contains(v))
}

fn deep_holds(body: &[u8], v: &str) -> bool {
    !deep_clean(body, v)
}

fn serde_inner(s: &str) -> String {
    let q = serde_json::to_string(s).unwrap();
    q[1..q.len() - 1].to_string()
}

/// An OpenAI Chat request a Codex-style agent sends after a tool call: the call's `arguments`
/// (JSON in a JSON string) carry the value, and the tool result is `JSON.stringify` of an object
/// whose `output` field is the tool's own JSON (three levels).
fn openai_chat_request(v: &str) -> Value {
    let arguments = serde_json::to_string(&json!({
        "command": format!("printf '%s' '{v}' > .env"),
    }))
    .unwrap();
    let tool_json = serde_json::to_string(&json!({ "stdout": v, "exit_code": 0 })).unwrap();
    let result = serde_json::to_string(&json!({ "output": tool_json, "ok": true })).unwrap();
    json!({
        "model": "gpt-test",
        "messages": [
            { "role": "user", "content": "Write the password to .env." },
            { "role": "assistant", "content": null, "tool_calls": [{
                "id": "call_1", "type": "function",
                "function": { "name": "shell", "arguments": arguments },
            }]},
            { "role": "tool", "tool_call_id": "call_1", "content": result },
        ],
    })
}

/// Rewrites a body the way Go's `encoding/json` would have written it.
fn go_html(body: &str) -> String {
    body.replace('<', &esc("<", Style::Html))
        .replace('>', &esc(">", Style::Html))
        .replace('&', &esc("&", Style::Html))
}

/// Rewrites a body the way Python's `json.dumps` would have written it.
fn py_ascii(body: &str) -> String {
    body.chars()
        .map(|c| {
            if c.is_ascii() {
                c.to_string()
            } else {
                esc(&c.to_string(), Style::Ascii)
            }
        })
        .collect()
}

#[test]
fn openai_chat_tool_call_arguments_are_redacted() {
    for (seed, non_ascii) in [(7, false), (11, true), (19, true)] {
        let v = password(seed, non_ascii);
        let body = serde_json::to_string(&openai_chat_request(&v)).unwrap();
        assert!(deep_holds(body.as_bytes(), &v));
        for outer in ["serde", "go", "python"] {
            let body = match outer {
                "go" => go_html(&body),
                "python" => py_ascii(&body),
                _ => body.clone(),
            };
            for kind in [EngineKind::AhoCorasick, EngineKind::HashWindow] {
                let s = snapshot_with(&[v.as_bytes()], ValueClass::Credential, &engine(kind));
                let mut ws = Workspace::new();
                let p = s.protect(body.as_bytes(), &mut ws).unwrap();
                // The redactor alone gets every level; the guard has nothing to repair.
                assert_eq!(p.guard, GuardOutcome::Clean, "{outer} {kind:?}");
                assert_eq!(p.stats.credential, 2, "{outer} {kind:?}");
                assert!(deep_clean(p.bytes, &v), "{outer} {kind:?}");
                assert!(contains(p.bytes, &ph(&s, v.as_bytes())));
            }
        }
    }
}

#[test]
fn redactor_covers_same_style_outer_levels_to_the_configured_depth() {
    let v = password(23, true);
    for depth in 2..=MAX_JSON_DEPTH {
        let cfg = Config {
            json_depth: depth,
            ..no_detectors()
        };
        let s = snapshot_with(&[v.as_bytes()], ValueClass::Credential, &cfg);
        // Every-character escaping is left to the guard.
        for inner in [Style::Min, Style::Html, Style::Ascii, Style::Slash] {
            for outer in [Style::Min, Style::Html, Style::Ascii] {
                for d in 1..=MAX_JSON_DEPTH {
                    for k in 1..=d.saturating_sub(1).max(1) {
                        let mut styles = vec![inner; k];
                        styles.extend(std::iter::repeat_n(outer, d - k));
                        let body = nested_body(&v, &styles);
                        let out = redact(&s, body.as_bytes());
                        assert_eq!(
                            deep_clean(&out, &v),
                            d <= depth,
                            "config {depth}, {styles:?}"
                        );
                    }
                }
            }
        }
    }
}

/// The guard alone, as if the redactor had missed everything, over every mix of styles.
#[test]
fn guard_unescapes_nested_json_to_the_configured_depth() {
    let v = password(29, true);
    let s = snapshot_with(&[v.as_bytes()], ValueClass::Credential, &no_detectors());
    let deep = snapshot_with(
        &[v.as_bytes()],
        ValueClass::Credential,
        &Config {
            json_depth: 4,
            ..no_detectors()
        },
    );
    let mut combos: Vec<Vec<Style>> = vec![vec![]];
    for _ in 0..4 {
        combos = combos
            .iter()
            .flat_map(|c| {
                STYLES.iter().map(move |&st| {
                    let mut c = c.clone();
                    c.push(st);
                    c
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .chain(combos.clone())
            .collect();
        combos.sort_by_key(|c| format!("{c:?}"));
        combos.dedup_by_key(|c| format!("{c:?}"));
    }
    let mut checked = 0;
    for styles in combos.iter().filter(|c| !c.is_empty()) {
        let body = nested_body(&v, styles);
        assert!(deep_holds(body.as_bytes(), &v));
        let want = match styles.len() {
            1 => GuardView::Json,
            2 => GuardView::JsonTwice,
            _ => GuardView::JsonDeep,
        };
        for (snap, depth) in [(&s, DEFAULT_JSON_DEPTH), (&deep, 4)] {
            let mut gs = GuardScratch::new();
            match snap.guard().check(body.as_bytes(), &mut gs) {
                Verdict::Repaired { bytes, findings } if styles.len() > depth => {
                    // Past the depth only a fragment left verbatim by the inner escaping (at
                    // least half the value, readable after fewer rounds) may be found.
                    assert!(
                        findings.iter().all(|f| f.view == GuardView::Fragment),
                        "{styles:?} caught past depth {depth}: {findings:?}"
                    );
                    assert!(deep_clean(bytes, &v), "{styles:?}");
                }
                Verdict::Repaired { bytes, findings } => {
                    assert!(findings.iter().any(|f| f.view == want), "{styles:?}");
                    // The repair maps back onto the escaped bytes: the body stays JSON at
                    // every level and no level holds the value.
                    assert!(deep_clean(bytes, &v), "{styles:?}");
                    checked += 1;
                }
                Verdict::Clean => assert!(styles.len() > depth, "{styles:?} missed"),
                Verdict::Withhold(r) => panic!("{styles:?}: {r:?}"),
            }
        }
    }
    assert!(checked > 700, "{checked}");
}

/// What the redactor leaves (a mixed-style nesting it does not compile) the guard catches.
#[test]
fn protect_catches_mixed_styles_the_redactor_leaves() {
    let v = password(31, true);
    let s = snapshot_with(&[v.as_bytes()], ValueClass::Credential, &no_detectors());
    let body = nested_body(&v, &[Style::Min, Style::Ascii, Style::Html]);
    assert!(deep_holds(&redact(&s, body.as_bytes()), &v));
    let mut ws = Workspace::new();
    let p = s.protect(body.as_bytes(), &mut ws).unwrap();
    assert_eq!(p.guard, GuardOutcome::Repaired);
    assert!(p.findings.iter().all(|f| f.view == GuardView::JsonDeep));
    assert!(deep_clean(p.bytes, &v));
}

#[test]
fn serde_json_at_every_level_matches_the_compiled_forms() {
    let v = password(37, true);
    let s = snapshot_with(&[v.as_bytes()], ValueClass::Credential, &no_detectors());
    let mut form = v.clone();
    for depth in 1..=DEFAULT_JSON_DEPTH {
        form = serde_inner(&form);
        let out = redact(&s, form.as_bytes());
        assert!(out == ph(&s, v.as_bytes()), "depth {depth}");
    }
}

#[test]
fn plain_values_add_no_nested_patterns() {
    let plain: &[u8] = b"Zyxwvu0123456789abcdef";
    let quoted = password(41, false);
    let count = |values: &[&[u8]], depth| {
        let cfg = Config {
            json_depth: depth,
            ..no_detectors()
        };
        snapshot_with(values, ValueClass::Credential, &cfg)
            .report()
            .patterns
    };
    assert_eq!(count(&[plain], 2), count(&[plain], 4));
    assert!(count(&[quoted.as_bytes()], 3) > count(&[quoted.as_bytes()], 2));
}

#[test]
fn json_depth_is_validated() {
    for depth in [0, 1, MAX_JSON_DEPTH + 1] {
        let cfg = Config {
            json_depth: depth,
            ..Config::default()
        };
        assert!(matches!(
            Snapshot::build(
                entries(&[b"some-value"], ValueClass::Display),
                keyring(),
                &cfg
            ),
            Err(BuildError::InvalidConfig(_))
        ));
    }
    assert_eq!(Config::default().json_depth, DEFAULT_JSON_DEPTH);
}

/// The guard's check of `body` (a value escaped `styles` times inside one JSON string, nothing
/// else escaped) with JSON unescaping to `depth` rounds: the value is found in the deepest view
/// and the repaired body is clean.
fn guard_finds_deep(v: &[u8], form: &[u8], depth: usize) {
    let s = snapshot_with(
        &[v],
        ValueClass::Credential,
        &Config {
            json_depth: depth,
            ..no_detectors()
        },
    );
    let body = [&b"{\"content\":\""[..], form, b"\"}"].concat();
    let mut gs = GuardScratch::new();
    match s.guard().check(&body, &mut gs) {
        Verdict::Repaired { bytes, findings } => {
            assert!(
                findings.iter().any(|f| f.view == GuardView::JsonDeep),
                "{findings:?}"
            );
            let repaired = bytes.to_vec();
            let mut gs = GuardScratch::new();
            assert_eq!(s.guard().check(&repaired, &mut gs), Verdict::Clean);
        }
        other => panic!("missed at depth {depth}: {other:?}"),
    }
}

/// A value made only of characters the first level escapes, then every character escaped: the
/// second level's escapes decode to `\`, `u` and hex digits, none of them in the value, yet they
/// spell the escapes the third round decodes into the value. The guard must not skip the second
/// view because its escapes decode to bytes no value holds.
#[test]
fn guard_unescapes_escapes_that_spell_escapes() {
    for (v, styles) in [
        (
            ">\t>\t>\t\u{2}\u{8}",
            &[Style::Html, Style::All, Style::All][..],
        ),
        (
            "\u{8}\u{1}\u{1}\n\n\u{1}\t\u{1}",
            &[Style::Min, Style::All, Style::Ascii],
        ),
        (
            "\t\n\u{1}\t\n\u{8}\u{1}\n\u{8}\u{8}\n\n",
            &[Style::Min, Style::All, Style::Min],
        ),
    ] {
        let form = styles.iter().fold(v.to_string(), |acc, &st| esc(&acc, st));
        guard_finds_deep(v.as_bytes(), form.as_bytes(), DEFAULT_JSON_DEPTH);
        // One more outer level, with the guard unescaping four times: the third round's parent
        // must not be skipped either.
        let form4 = esc(&form, Style::Min);
        guard_finds_deep(v.as_bytes(), form4.as_bytes(), 4);
    }
}

/// The `guard` fuzz target's finding (release fuzzing, 600 s): eight bytes that are not UTF-8,
/// with NULs, escaped in Go, every-character and Python style, bytes from 0x80 copied as they are.
#[test]
fn guard_unescapes_escapes_that_spell_escapes_in_binary_values() {
    let v: &[u8] = b"\xef\xf7\xf7\x92\xf7\x00\x00\xbf";
    let level = |s: &[u8], f: &dyn Fn(u8) -> Option<String>| -> Vec<u8> {
        s.iter()
            .flat_map(|&b| f(b).map_or_else(|| vec![b], String::into_bytes))
            .collect()
    };
    let go = level(v, &|b| (b < 0x20).then(|| format!("\\u{b:04x}")));
    let all = level(&go, &|b| (b < 0x80).then(|| format!("\\u{b:04x}")));
    let py = level(&all, &|b| (b == b'\\').then(|| "\\\\".to_string()));
    guard_finds_deep(v, &py, DEFAULT_JSON_DEPTH);
}

/// The `variants` fuzz target's finding (release fuzzing, 600 s): a value with control characters
/// nested three levels deep (Go, Go, minimal), right after four raw backslashes.
///
/// As the serialisers write it (`\n` and `\r` short), the form is one the redactor compiles and it
/// is replaced whatever precedes it. The target had written `\n` as `\u000a`, a form no
/// serialiser it names writes, so only the guard could find it; and the four backslashes before
/// it pair with its own, so the value only appears after a fourth round of unescaping, past the
/// default depth. With `json_depth` 4 the guard finds that form too.
#[test]
fn compiled_nested_form_is_redacted_after_backslashes() {
    let v: &[u8] = b"\x0b\x0a\x0d\x0f\x17\xaa\xd9\x01\x00\x00\x00\xfe";
    let level = |s: &[u8], short: bool| -> Vec<u8> {
        s.iter()
            .flat_map(|&b| match b {
                b'\\' => b"\\\\".to_vec(),
                b'\n' if short => b"\\n".to_vec(),
                b'\r' if short => b"\\r".to_vec(),
                0..0x20 => format!("\\u{b:04x}").into_bytes(),
                _ => vec![b],
            })
            .collect()
    };
    let nest = |short| level(&level(&level(v, short), short), short);
    let pre: &[u8] = b"#=s\\\\\\\\";
    let post: &[u8] = b"\xcb#<#\x94\xd4\x94";

    let s = snapshot_with(&[v], ValueClass::Credential, &no_detectors());
    let compiled = nest(true);
    let body = [pre, &compiled, post].concat();
    let mut ws = Workspace::new();
    let p = s.protect(&body, &mut ws).unwrap();
    assert_eq!(p.bytes, [pre, &ph(&s, v), post].concat());
    assert_eq!(p.guard, GuardOutcome::Clean);

    let other = nest(false);
    let body = [pre, &other, post].concat();
    let deep = snapshot_with(
        &[v],
        ValueClass::Credential,
        &Config {
            json_depth: 4,
            ..no_detectors()
        },
    );
    let mut gs = GuardScratch::new();
    assert!(matches!(
        deep.guard().check(&body, &mut gs),
        Verdict::Repaired { findings, .. } if findings.iter().any(|f| f.view == GuardView::JsonDeep)
    ));
}
