//! The committed seed inputs of the fuzz targets (`fuzz/seeds/<target>`), built from the
//! repository's fixtures: the recorded provider requests and streams of scrim-llm and the leak
//! suite's scenario corpus, with generated test values in place of their secrets. Each seed is
//! encoded the way its target reads its input (`fuzz/fuzz_targets`), so fuzzing starts from real
//! request and stream shapes instead of empty input.
//!
//! The test fails when the committed seeds differ from what the fixtures give; after changing a
//! fixture or a target's input format, rewrite them with
//! `SCRIM_FUZZ_SEEDS=update cargo test -p scrim-redact --test fuzz_seeds`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Test values, never real tokens: each carries the TeSt or TEST marker (`.gitleaks.toml`) and
/// is between 8 and 64 bytes, the lengths the targets' value lists accept.
const VALUES: &[(&str, &str)] = &[
    ("github-token", "ghp_TeStFuzzSeed0a1b2c3d4e5f6a7b8c9d0e1f2"),
    (
        "api-key",
        "sk-ant-api03-TeStFuzzSeed-0a1b2c3d4e5f6a7b8c9dAA",
    ),
    ("password", "TeSt-pässw0rd!"),
    ("aws-access-key-id", "AKIATESTFUZZSEED7Q2W"),
    (
        "aws-secret-access-key",
        "TeStsEcReT/0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c",
    ),
    (
        "jwt",
        "eyJhbGciOiJIUzI1NiJ9.eyJUZVN0IjoxfQ.TeSt0a1b2c3d4e5f6a7b",
    ),
    ("db-password", "TeSt_db_pass_42"),
    ("short-password", "TeSt8chr"),
];

/// Bodies are cut to this many bytes: libFuzzer takes the longest seed as its length limit, and
/// the targets build a snapshot and protect the whole body on every run, so longer seeds cost
/// runs per second more than they add coverage.
const MAX_BODY: usize = 1024;

const TARGETS: &[&str] = &["engines", "guard", "restore", "shaped", "variants"];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn value(kind: &str) -> &'static str {
    VALUES
        .iter()
        .find(|(k, _)| *k == kind)
        .map(|(_, v)| *v)
        .unwrap_or_else(|| panic!("no test value for secret kind {kind}; add one to VALUES"))
}

/// One fixture: its text with every secret marked as `\u{1}<index>:<part>\u{2}`, and the values
/// those indexes stand for.
struct Fixture {
    name: String,
    text: String,
    values: Vec<&'static str>,
}

impl Fixture {
    /// The text with the values filled in.
    fn filled(&self) -> Vec<u8> {
        self.fill(|i| self.values[i].to_owned())
    }

    /// The text with `with(i)` in place of value `i`.
    fn fill(&self, with: impl Fn(usize) -> String) -> Vec<u8> {
        let mut out = String::new();
        let mut rest = self.text.as_str();
        while let Some(at) = rest.find('\u{1}') {
            out.push_str(&rest[..at]);
            let end = rest[at..].find('\u{2}').unwrap() + at;
            let (i, part) = rest[at + 1..end].split_once(':').unwrap();
            let whole = with(i.parse().unwrap());
            // A value split over two stream events: `a` is its first half, `b` the rest.
            let half = whole
                .char_indices()
                .map(|(i, _)| i)
                .nth(whole.chars().count() / 2)
                .unwrap_or(0);
            out.push_str(match part {
                "a" => &whole[..half],
                "b" => &whole[half..],
                _ => &whole,
            });
            rest = &rest[end + 1..];
        }
        out.push_str(rest);
        let mut b = out.into_bytes();
        b.truncate(MAX_BODY);
        b
    }
}

/// Replaces each `{{<open>...}}` marker in `s` with a value index, `kind` naming the value.
fn mark(
    s: &str,
    open: &str,
    kind: impl Fn(&str) -> &'static str,
    values: &mut Vec<&'static str>,
) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(at) = rest.find(open) {
        out.push_str(&rest[..at]);
        let end = rest[at..].find("}}").unwrap() + at;
        let inner = &rest[at + open.len()..end];
        // {{P0a}} and {{P0b}}: the two halves of one value.
        let (name, part) = match inner.strip_suffix(['a', 'b']) {
            Some(n) if n.bytes().all(|b| b.is_ascii_digit()) && !n.is_empty() => {
                (n, &inner[n.len()..])
            }
            _ => (inner, ""),
        };
        let v = kind(name);
        let i = values.iter().position(|x| *x == v).unwrap_or_else(|| {
            values.push(v);
            values.len() - 1
        });
        out.push_str(&format!("\u{1}{i}:{part}\u{2}"));
        rest = &rest[end + 2..];
    }
    out.push_str(rest);
    out
}

fn sorted_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    files
}

fn fixtures() -> Vec<Fixture> {
    let mut out = Vec::new();
    // Recorded provider requests and streams: {{S<n>}} is a secret in a request, {{P<n>}} a
    // placeholder in a response, which the agent sees restored to the value.
    let llm = manifest_dir().join("../scrim-llm/tests/fixtures");
    for provider in sorted_files(&llm) {
        for file in sorted_files(&provider) {
            let text = fs::read_to_string(&file).unwrap();
            let mut values = Vec::new();
            let pick = |n: &str| VALUES[n.parse::<usize>().unwrap() % VALUES.len()].1;
            let text = mark(&text, "{{S", pick, &mut values);
            let text = mark(&text, "{{P", pick, &mut values);
            out.push(Fixture {
                name: format!(
                    "llm-{}-{}",
                    provider.file_name().unwrap().to_str().unwrap(),
                    file.file_stem().unwrap().to_str().unwrap()
                ),
                text,
                values,
            });
        }
    }
    // The leak suite's scenarios: the prompt and every tool output, {{secret:<kind>}} a seeded
    // value of that kind.
    let leak = manifest_dir().join("../../../internal/leak/scenario/corpus");
    for file in sorted_files(&leak) {
        let doc: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
        let mut parts = vec![doc["prompt"].as_str().unwrap_or_default().to_owned()];
        for step in doc["steps"].as_array().unwrap() {
            if let Some(input) = step.get("input") {
                parts.push(input.to_string());
            }
            if let Some(output) = step.get("output").and_then(|o| o.as_str()) {
                parts.push(output.to_owned());
            }
        }
        let mut values = Vec::new();
        let text = mark(&parts.join("\n"), "{{secret:", value, &mut values);
        out.push(Fixture {
            name: format!("leak-{}", file.file_stem().unwrap().to_str().unwrap()),
            text,
            values,
        });
    }
    out
}

/// `values` separated by 0xFF, then 0xFF 0xFE and `rest`: `common::split` in the targets.
fn split_input(values: &[&str], rest: &[u8]) -> Vec<u8> {
    let mut b: Vec<u8> = values
        .iter()
        .enumerate()
        .flat_map(|(i, v)| {
            let mut x = if i == 0 { Vec::new() } else { vec![0xFF] };
            x.extend_from_slice(v.as_bytes());
            x
        })
        .collect();
    b.extend_from_slice(&[0xFF, 0xFE]);
    b.extend_from_slice(rest);
    b
}

/// Every seed, by target and file name.
fn seeds() -> BTreeMap<(&'static str, String), Vec<u8>> {
    let mut out = BTreeMap::new();
    for (i, f) in fixtures().iter().enumerate() {
        let values: Vec<&str> = if f.values.is_empty() {
            vec![VALUES[i % VALUES.len()].1]
        } else {
            f.values.clone()
        };
        let body = if f.values.is_empty() {
            f.text.as_bytes()[..f.text.len().min(MAX_BODY)].to_vec()
        } else {
            f.filled()
        };
        let sel = (i * 37 % 256) as u8;
        // engines: the values and a body that holds them.
        out.insert(("engines", f.name.clone()), split_input(&values, &body));
        // guard: every other fixture with the marker that also nests the first value in JSON.
        let mut rest = if i % 2 == 1 {
            vec![0xFD, sel]
        } else {
            Vec::new()
        };
        rest.extend_from_slice(&body);
        out.insert(("guard", f.name.clone()), split_input(&values, &rest));
        // variants: the first byte picks the encoding the value is embedded in, the second
        // its parameters.
        let mut rest = vec![(i % 6) as u8, sel];
        rest.extend_from_slice(&body);
        out.insert(("variants", f.name.clone()), split_input(&values, &rest));
        // restore: the first byte's low bit picks the class, and each `|` of the text is where
        // the target puts a value before redacting it.
        let mut rest = vec![(i % 2) as u8];
        rest.extend_from_slice(&f.fill(|_| "|".to_owned()));
        out.insert(("restore", f.name.clone()), split_input(&values, &rest));
        // shaped: a value, a NUL, then the text; a first byte divisible by 8 runs the
        // redactor, guard and resolver too.
        let mut b = values[0].as_bytes().to_vec();
        b.extend_from_slice(&[0, 0, (i % 2) as u8]);
        b.extend_from_slice(&body);
        out.insert(("shaped", f.name.clone()), b);
    }
    // shaped: every test value once more, alone and inside a short JSON body.
    for (kind, v) in VALUES {
        let mut b = v.as_bytes().to_vec();
        b.extend_from_slice(b"\0\0\0{\"token\":\"");
        b.extend_from_slice(v.as_bytes());
        b.extend_from_slice(b"\"}");
        out.insert(("shaped", format!("value-{kind}")), b);
    }
    out
}

#[test]
fn fuzz_seeds_match_the_fixtures() {
    let want = seeds();
    let dir = manifest_dir().join("fuzz/seeds");
    if std::env::var("SCRIM_FUZZ_SEEDS").as_deref() == Ok("update") {
        let _ = fs::remove_dir_all(&dir);
        for ((target, name), bytes) in &want {
            fs::create_dir_all(dir.join(target)).unwrap();
            fs::write(dir.join(target).join(name), bytes).unwrap();
        }
    }
    let mut problems = Vec::new();
    for target in TARGETS {
        let have: Vec<String> = sorted_files(&dir.join(target))
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_owned())
            .collect();
        for name in &have {
            match want.get(&(*target, name.clone())) {
                None => problems.push(format!("{target}/{name}: not built from any fixture")),
                Some(bytes) if *bytes != fs::read(dir.join(target).join(name)).unwrap() => {
                    problems.push(format!("{target}/{name}: differs from its fixture"));
                }
                Some(_) => {}
            }
        }
        for ((t, name), bytes) in &want {
            if t == target && !have.contains(name) {
                problems.push(format!("{target}/{name}: missing"));
            }
            assert!(
                bytes.len() <= 4096,
                "{t}/{name} is {} bytes, over 4096",
                bytes.len()
            );
        }
    }
    assert!(
        problems.is_empty(),
        "fuzz/seeds is out of date ({}); rewrite it with \
         SCRIM_FUZZ_SEEDS=update cargo test -p scrim-redact --test fuzz_seeds",
        problems.join("; ")
    );
}
