//! Fallback detectors: rule fixtures and the false-positive corpus.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    unreachable_pub,
    missing_docs
)]

mod common;

use common::fixtures::{Rng, b64, gen_body, hex};
use scrim_redact::*;

fn detector_snapshot(entropy: bool) -> Snapshot {
    let cfg = Config {
        detectors: DetectorConfig {
            entropy: entropy.then(EntropyConfig::default),
            ..Default::default()
        },
        ..Config::default()
    };
    Snapshot::build(vec![], common::keyring(), &cfg).unwrap()
}

fn rules_hit(s: &Snapshot, text: &str) -> Vec<&'static str> {
    let mut v = Vec::new();
    let mut out = Vec::new();
    s.redactor()
        .redact_with(text.as_bytes(), &mut out, &mut |h| {
            if let Hit::Detected { rule, .. } = h {
                v.push(rule);
            }
        })
        .unwrap();
    v
}

/// Generated tokens in each format (never real ones).
fn fixtures() -> Vec<(&'static str, String)> {
    let mut r = Rng::new(42);
    let b62 = common::fixtures::BASE62;
    let b32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    vec![
        ("aws-access-key-id", format!("AKIA{}", r.string(b32, 16))),
        ("aws-access-key-id", format!("ASIA{}", r.string(b32, 16))),
        ("github-token", format!("ghp_{}", r.string(b62, 36))),
        ("github-token", format!("ghs_{}", r.string(b62, 36))),
        (
            "github-fine-grained-token",
            format!("github_pat_{}_{}", r.string(b62, 22), r.string(b62, 59)),
        ),
        (
            "anthropic-api-key",
            format!("sk-ant-api03-{}AA", r.string(url, 93)),
        ),
        ("openai-api-key", format!("sk-proj-{}", r.string(url, 64))),
        (
            "openai-api-key",
            format!("sk-{}T3BlbkFJ{}", r.string(b62, 20), r.string(b62, 20)),
        ),
        ("gitlab-token", format!("glpat-{}", r.string(url, 20))),
        (
            "slack-token",
            format!("xoxb-{}-{}", r.string("0123456789", 12), r.string(b62, 24)),
        ),
        ("stripe-key", format!("sk_live_{}", r.string(b62, 24))),
        ("google-api-key", format!("AIza{}", r.string(url, 35))),
        ("npm-token", format!("npm_{}", r.string(b62, 36))),
        (
            "jwt",
            format!(
                "{}.{}.{}",
                b64(br#"{"alg":"HS256","typ":"JWT"}"#, true, false),
                b64(br#"{"sub":"1234567890","iat":1516239022}"#, true, false),
                b64(&r.bytes(32), true, false)
            ),
        ),
        (
            "private-key",
            format!(
                "-----BEGIN EC PRIVATE KEY-----\n{}\n-----END EC PRIVATE KEY-----",
                b64(&r.bytes(90), false, true)
            ),
        ),
    ]
}

#[test]
fn every_rule_fires_in_context() {
    let s = detector_snapshot(false);
    for (rule, tok) in fixtures() {
        for ctx in ["{}", "export TOKEN={}", "\"key\": \"{}\"", "Bearer {}\n"] {
            let text = ctx.replace("{}", &tok);
            assert_eq!(rules_hit(&s, &text), vec![rule], "{rule} in {ctx}");
            let mut out = Vec::new();
            s.redactor().redact(text.as_bytes(), &mut out).unwrap();
            assert!(!common::contains(&out, tok.as_bytes()), "{rule}");
        }
    }
}

#[test]
fn each_rule_can_be_disabled() {
    for (rule, tok) in fixtures() {
        let cfg = Config {
            detectors: DetectorConfig {
                disabled_rules: vec![rule.into()],
                ..Default::default()
            },
            ..Config::default()
        };
        let s = Snapshot::build(vec![], common::keyring(), &cfg).unwrap();
        assert!(!rules_hit(&s, &tok).contains(&rule), "{rule}");
    }
    assert!(builtin_rule_names().len() >= 12);
}

/// Text an agent sends all the time: prose, code, logs, hashes, UUIDs, base64 data, paths.
fn corpus() -> String {
    let mut r = Rng::new(7);
    let mut c = common::fixtures::gen_stream_text(3, 200_000, &[], 0);
    for _ in 0..2000 {
        let sha1 = hex(&r.bytes(20));
        let sha256 = hex(&r.bytes(32));
        let u = hex(&r.bytes(16));
        let uuid = format!(
            "{}-{}-{}-{}-{}",
            &u[..8],
            &u[8..12],
            &u[12..16],
            &u[16..20],
            &u[20..]
        );
        c.push_str(&format!("commit {sha1} sha256:{sha256} id={uuid} "));
        c.push_str(
            "/usr/lib/x86_64-linux-gnu/libssl.so.3 src/components/HTTPRequestHandlerFactory.ts ",
        );
        c.push_str(
            "AbstractSingletonProxyFactoryBean getElementsByClassName XMLHttpRequestEventTarget ",
        );
        c.push_str("ask-anything task-runner desk-lamp sk-learn AKIA-docs ghp_short eyJhbGc ");
    }
    c.push_str(include_str!("../src/restore.rs"));
    c.push_str(include_str!("../src/matcher.rs"));
    c.push_str(include_str!("../src/redactor.rs"));
    c
}

#[test]
fn false_positive_corpus() {
    let c = corpus();
    let body = String::from_utf8(gen_body(3, 400_000, &[]).0).unwrap();
    let rules = detector_snapshot(false);
    let hits = rules_hit(&rules, &format!("{c}{body}"));
    // Pattern rules: zero false positives on the corpus (source files included).
    assert!(hits.is_empty(), "pattern rules fired: {hits:?}");
    // Entropy (opt-in): silent on prose, code, hashes, UUIDs and paths.
    let ent = detector_snapshot(true);
    let mut quiet = Vec::new();
    let mut out = Vec::new();
    ent.redactor()
        .redact_with(c.as_bytes(), &mut out, &mut |h| {
            if let Hit::Detected { start, end, .. } = h {
                quiet.push(c[start..end].to_string());
            }
        })
        .unwrap();
    assert!(quiet.is_empty(), "entropy hits on the corpus: {quiet:?}");
    // Base64 data of random bytes does trip it, which is why entropy is off by default; the rate
    // on an agent request body with embedded blobs stays bounded.
    let n = rules_hit(&ent, &body).len();
    let per_mb = n as f64 / (body.len() as f64 / 1e6);
    assert!(per_mb < 2000.0, "{n} entropy hits ({per_mb:.0}/MB)");
}

#[test]
fn entropy_catches_random_tokens() {
    let s = detector_snapshot(true);
    let mut r = Rng::new(9);
    let tok = r.string(common::fixtures::BASE62, 40);
    assert_eq!(
        rules_hit(&s, &format!("secret = {tok};")),
        vec![ENTROPY_RULE]
    );
    assert!(rules_hit(&s, &format!("commit {}", hex(&r.bytes(20)))).is_empty());
}
