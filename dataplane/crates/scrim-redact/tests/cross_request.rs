//! The guard's `cross-request` transform: short fragments of a value sent in separate requests
//! of one session (one piece per request, or a provider keeping earlier turns through
//! `previous_response_id`) are joined, and the request that completes the value has its pieces
//! repaired. The redactor is bypassed so only the guard decides.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    unreachable_pub,
    missing_docs,
    clippy::print_stdout,
    reason = "test code; the measurement prints its numbers"
)]

mod common;

use common::fixtures::{BASE62, Rng};
use common::*;
use scrim_redact::*;

fn snap_with(values: &[&[u8]], tx: TransformConfig) -> Snapshot {
    snapshot_with(
        values,
        ValueClass::Credential,
        &Config {
            transforms: tx,
            ..no_detectors()
        },
    )
}

fn snap(v: &[u8]) -> Snapshot {
    snap_with(&[v], TransformConfig::default())
}

/// A 40-byte value: pieces of 13 to 19 bytes are below half of it, above the minimum length,
/// and two pieces of 19 cover it but its last two bytes.
fn value(r: &mut Rng) -> String {
    r.string(BASE62, 40)
}

const S1: SessionKey = [1u8; 32];
const S2: SessionKey = [2u8; 32];

/// The guard over one request of `session`: the views of its findings and the bytes to send.
fn send(s: &Snapshot, session: &SessionKey, body: &str) -> (Vec<GuardView>, String) {
    let mut gs = GuardScratch::new();
    match s.guard().check_in(body.as_bytes(), &mut gs, session) {
        Verdict::Clean => (vec![], body.to_string()),
        Verdict::Repaired { bytes, findings } => (
            findings.iter().map(|f| f.view).collect(),
            String::from_utf8(bytes.to_vec()).unwrap(),
        ),
        Verdict::Withhold(r) => panic!("withheld: {r:?}"),
    }
}

/// Whether the guard joined the request's pieces with earlier ones (one finding per indexed form
/// of the value that the pieces cover: the value, and its skeleton when it has one).
fn joined(views: &[GuardView]) -> bool {
    !views.is_empty() && views.iter().all(|&v| v == GuardView::CrossRequest)
}

/// An OpenAI Responses request continuing a stored conversation with one tool result.
fn turn(output: &str, previous: Option<&str>) -> String {
    let prev = previous.map_or(String::new(), |p| {
        format!(r#""previous_response_id":"{p}","#)
    });
    format!(
        r#"{{"model":"gpt-5",{prev}"input":[{{"type":"function_call_output","call_id":"call_1","output":"{output}"}}]}}"#
    )
}

#[test]
fn pieces_over_two_requests() {
    let mut r = Rng::new(1);
    let v = value(&mut r);
    let s = snap(v.as_bytes());
    // The first request holds the first and last pieces, in two places: not all of the value.
    let first = turn(&format!("head: {} tail: {}", &v[..13], &v[27..]), None);
    assert_eq!(send(&s, &S1, &first).0, vec![]);
    // The second one, chained by server-side state, holds the middle: it completes the value.
    let second = turn(&format!("middle: {}", &v[13..27]), Some("resp_1"));
    let (views, sent) = send(&s, &S1, &second);
    assert!(joined(&views));
    assert!(!sent.contains(&v[13..27]), "{sent}");
    // The repaired request is clean; checked alone, without the session, it was clean too.
    assert_eq!(send(&s, &S1, &sent).0, vec![]);
    let mut gs = GuardScratch::new();
    assert_eq!(
        s.guard().check(second.as_bytes(), &mut gs),
        Verdict::Clean,
        "one piece alone is no finding"
    );
}

#[test]
fn pieces_over_three_requests() {
    let mut r = Rng::new(2);
    let v = value(&mut r);
    let s = snap(v.as_bytes());
    assert_eq!(send(&s, &S1, &turn(&v[..13], None)).0, vec![]);
    assert_eq!(send(&s, &S1, &turn(&v[13..26], Some("resp_1"))).0, vec![]);
    let (views, sent) = send(&s, &S1, &turn(&v[26..], Some("resp_2")));
    assert!(joined(&views));
    assert!(!sent.contains(&v[26..]));
    // Any order.
    let s = snap(v.as_bytes());
    assert_eq!(send(&s, &S1, &turn(&v[26..], None)).0, vec![]);
    assert_eq!(send(&s, &S1, &turn(&v[..13], None)).0, vec![]);
    assert!(joined(&send(&s, &S1, &turn(&v[13..26], None)).0));
}

#[test]
fn a_value_sent_again_is_repaired_again() {
    let mut r = Rng::new(3);
    let v = value(&mut r);
    let s = snap(v.as_bytes());
    send(&s, &S1, &turn(&v[..19], None));
    for _ in 0..3 {
        assert!(joined(&send(&s, &S1, &turn(&v[19..38], None)).0));
    }
}

#[test]
fn other_sessions_never_combine() {
    let mut r = Rng::new(4);
    let v = value(&mut r);
    let s = snap(v.as_bytes());
    assert_eq!(send(&s, &S1, &turn(&v[..19], None)).0, vec![]);
    assert_eq!(send(&s, &S2, &turn(&v[19..38], None)).0, vec![]);
    // A check without a session neither joins nor remembers.
    let mut gs = GuardScratch::new();
    assert_eq!(
        s.guard().check(turn(&v[19..38], None).as_bytes(), &mut gs),
        Verdict::Clean
    );
    // Each session still completes its own.
    assert!(joined(&send(&s, &S1, &turn(&v[19..38], None)).0));
    assert!(joined(&send(&s, &S2, &turn(&v[..19], None)).0));
}

#[test]
fn other_values_never_combine() {
    let mut r = Rng::new(5);
    let (a, b) = (value(&mut r), value(&mut r));
    let s = snap_with(&[a.as_bytes(), b.as_bytes()], TransformConfig::default());
    assert_eq!(send(&s, &S1, &turn(&a[..19], None)).0, vec![]);
    assert_eq!(send(&s, &S1, &turn(&b[19..38], None)).0, vec![]);
}

/// The data plane gives every snapshot one memory: pieces join across a change to the
/// redaction set (a session token added, a value refreshed), and pieces of a value that left the
/// set are dropped.
#[test]
fn one_memory_across_snapshots() {
    let mut r = Rng::new(10);
    let (v, w) = (value(&mut r), value(&mut r));
    let mem = std::sync::Arc::new(CrossMemory::new());
    let with = |values: &[&[u8]]| {
        snap_with(
            values,
            TransformConfig {
                memory: Some(mem.clone()),
                ..TransformConfig::default()
            },
        )
    };
    let s = with(&[v.as_bytes()]);
    assert_eq!(send(&s, &S1, &turn(&v[..19], None)).0, vec![]);
    // A new snapshot with one more value: the first piece is still known.
    let s = with(&[v.as_bytes(), w.as_bytes()]);
    assert!(joined(&send(&s, &S1, &turn(&v[19..38], None)).0));
    // v leaves the set: the next check of the session drops its pieces.
    let s = with(&[w.as_bytes()]);
    let before = mem.pieces(&S1);
    assert_eq!(send(&s, &S1, &turn(&w[..19], None)).0, vec![]);
    assert!(mem.pieces(&S1) < before, "v's pieces kept");
    // Back in the set, its old pieces are gone: one piece alone is no finding.
    let s = with(&[v.as_bytes(), w.as_bytes()]);
    assert_eq!(send(&s, &S1, &turn(&v[19..38], None)).0, vec![]);
}

/// Without a shared memory each guard keeps its own.
#[test]
fn a_new_snapshot_starts_empty() {
    let mut r = Rng::new(6);
    let v = value(&mut r);
    let s = snap(v.as_bytes());
    send(&s, &S1, &turn(&v[..19], None));
    let s = snap(v.as_bytes());
    assert_eq!(send(&s, &S1, &turn(&v[19..38], None)).0, vec![]);
}

#[test]
fn off_by_name_and_independent_of_split_fragments() {
    let mut r = Rng::new(7);
    let v = value(&mut r);
    let mut off = TransformConfig::default();
    assert!(off.set("cross-request", false));
    let s = snap_with(&[v.as_bytes()], off);
    assert!(!s.guard().remembers());
    send(&s, &S1, &turn(&v[..19], None));
    assert_eq!(send(&s, &S1, &turn(&v[19..38], None)).0, vec![]);

    let mut only = TransformConfig::default();
    assert!(only.set("split-fragments", false));
    let s = snap_with(&[v.as_bytes()], only);
    assert!(s.guard().remembers());
    // Within one request nothing is joined...
    let both = turn(&format!("{} and {}", &v[..19], &v[19..38]), None);
    assert_eq!(send(&s, &S2, &both).0, vec![]);
    // ...across requests the pieces still are.
    send(&s, &S1, &turn(&v[..19], None));
    assert!(joined(&send(&s, &S1, &turn(&v[19..38], None)).0));
}

/// Bodies above the verdict cache's threshold: the conversation so far is cached clean, and a
/// piece in a later request is still joined with one sent earlier.
#[test]
fn works_with_the_verdict_cache() {
    let mut r = Rng::new(8);
    let v = value(&mut r);
    let s = snap(v.as_bytes());
    assert!(s.guard().caches());
    let (history, _) = common::fixtures::gen_body(5, 200_000, &[]);
    let history = String::from_utf8(history).unwrap();
    // Twice, so the history's segments are known clean.
    assert_eq!(send(&s, &S1, &history).0, vec![]);
    assert_eq!(send(&s, &S1, &history).0, vec![]);
    let with = |piece: &str| {
        let mut b = history.clone();
        b.truncate(b.rfind(']').unwrap());
        format!(
            r#"{b},{{"role":"user","content":[{{"type":"tool_result","tool_use_id":"t","content":"{piece}"}}]}}]}}"#
        )
    };
    assert_eq!(send(&s, &S1, &with(&v[..19])).0, vec![]);
    let (views, sent) = send(&s, &S1, &with(&v[19..38]));
    assert!(joined(&views));
    assert!(!sent.contains(&v[19..38]));
}

/// A conversation of ordinary agent requests, each a new piece of a long history, over many
/// values: no finding.
#[test]
fn stays_quiet_on_ordinary_conversations() {
    let mut r = Rng::new(9);
    let secrets: Vec<String> = (0..200).map(|_| value(&mut r)).collect();
    let refs: Vec<&[u8]> = secrets.iter().map(|s| s.as_bytes()).collect();
    let s = snap_with(&refs, TransformConfig::default());
    for i in 0..40 {
        let (body, _) = common::fixtures::gen_body(100 + i, 50_000, &[]);
        let body = String::from_utf8(body).unwrap();
        assert_eq!(send(&s, &S1, &body).0, vec![], "request {i}");
    }
}

/// Every file under `dir` with one of `exts`, read as text, in a stable order.
fn corpus(dir: &std::path::Path, exts: &[&str], out: &mut Vec<String>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            corpus(&p, exts, out);
        } else if p.extension().is_some_and(|e| exts.iter().any(|x| e == *x))
            && let Ok(t) = std::fs::read_to_string(&p)
        {
            out.push(t);
        }
    }
}

/// Requests with a within-request fragment finding (or refused), with a cross-request finding, and the
/// guard's time per request with a session and without, for one session sending `requests`.
fn fp_run(values: &[String], requests: &[String]) -> (usize, usize, f64, f64) {
    let refs: Vec<&[u8]> = values.iter().map(|s| s.as_bytes()).collect();
    let s = snap_with(&refs, TransformConfig::default());
    let (mut within, mut across) = (0usize, 0usize);
    let mut gs = GuardScratch::new();
    let t = std::time::Instant::now();
    for b in requests {
        match s.guard().check_in(b.as_bytes(), &mut gs, &S1) {
            Verdict::Repaired { findings, .. } => {
                within += usize::from(findings.iter().any(|f| f.view == GuardView::Fragment));
                across += usize::from(findings.iter().any(|f| f.view == GuardView::CrossRequest));
            }
            // Too many repairs: refused, which a false positive also is.
            Verdict::Withhold(_) => within += 1,
            Verdict::Clean => {}
        }
    }
    let with = t.elapsed();
    let s = snap_with(&refs, TransformConfig::default());
    let t = std::time::Instant::now();
    for b in requests {
        let _ = s.guard().check(b.as_bytes(), &mut gs);
    }
    let without = t.elapsed();
    let ms = |d: std::time::Duration| d.as_secs_f64() * 1e3 / requests.len() as f64;
    (within, across, ms(with), ms(without))
}

/// The false positive rate and the cost of `cross-request`, as `docs/configuration.md` quotes
/// them. Not a gate (it reads the repository and takes a while):
/// `cargo test --release -p scrim-redact --test cross_request -- --ignored --nocapture`.
///
/// One session sends the repository's documentation, OpenSpec and Go sources as JSON requests
/// of about 50 KB each. Value sets: 1,000 random tokens of 24 to 47 characters; 200 weak values
/// of three distinct words of that text (`billing-service-token`); 200 weak values of three
/// words drawn by how often they occur there (the worst case: `return-error-string`).
#[test]
#[ignore = "measurement, run by hand"]
fn measure_false_positives_and_cost() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut texts = Vec::new();
    corpus(&root.join("docs"), &["md"], &mut texts);
    corpus(&root.join("internal"), &["go"], &mut texts);
    corpus(&root.join("openspec"), &["md"], &mut texts);
    let all = texts.concat();
    let words: Vec<&str> = all
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| w.len() >= 4 && w.len() <= 10)
        .collect();
    let mut vocab = words.clone();
    vocab.sort_unstable();
    vocab.dedup();
    let mut requests = Vec::new();
    let mut cur = String::new();
    for t in &texts {
        cur.push_str(t);
        if cur.len() >= 50_000 {
            let body = serde_json::json!({"model": "m", "input": [{"type": "function_call_output", "call_id": "c", "output": cur}]});
            requests.push(body.to_string());
            cur.clear();
        }
    }
    let bytes: usize = requests.iter().map(String::len).sum();
    println!("requests={} bytes={bytes}", requests.len());
    let mut r = Rng::new(42);
    let random: Vec<String> = (0..1000)
        .map(|_| {
            let n = 24 + r.below(24);
            r.string(BASE62, n)
        })
        .collect();
    let mut weak = |from: &[&str]| -> Vec<String> {
        (0..200)
            .map(|i| {
                let w: Vec<&str> = (0..3).map(|_| *r.pick(from)).collect();
                w.join(["-", "_", ".", ""][i % 4])
            })
            .collect()
    };
    let distinct = weak(&vocab);
    let frequent = weak(&words);
    for (name, values) in [
        ("random tokens", &random),
        ("weak, distinct words", &distinct),
        ("weak, frequent words", &frequent),
    ] {
        let (within, across, with, without) = fp_run(values, &requests);
        println!(
            "{name} ({}): requests with a within-request fragment finding={within} with a \
             cross-request finding={across}; guard {with:.2} ms/request with a session, \
             {without:.2} without",
            values.len()
        );
    }
}

/// The words of a value made of words turn up in any long session: such pieces are not joined.
#[test]
fn pieces_that_read_as_words_are_not_joined() {
    let v = "Providence-Waterfall-Harmonica";
    let s = snap(v.as_bytes());
    for w in ["Providence", "Waterfall", "Harmonica"] {
        assert_eq!(send(&s, &S1, &turn(w, None)).0, vec![], "{w}");
    }
    // Within one request the split-fragments rule still joins them.
    let all = turn("Providence and Waterfall and Harmonica", None);
    assert!(send(&s, &S2, &all).0.contains(&GuardView::Fragment));
}
