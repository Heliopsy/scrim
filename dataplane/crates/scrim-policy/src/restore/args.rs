// SPDX-License-Identifier: AGPL-3.0-only

//! Tool-call arguments: the JSON string literals in them, and for every placeholder what the
//! tool's role allows there.

use std::collections::HashSet;

use crate::escape::shell::{self, CommandSet};
use crate::escape::{Refusal, Site};
use crate::restore::KeepReason;
use crate::restore::tools::{ToolRole, ToolSpec};

/// One step of a JSON path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Seg {
    Key(String),
    Index(usize),
}

/// A string in the arguments: a JSON string literal (with its source span), or the whole
/// free-form input.
#[derive(Clone, Debug)]
pub(crate) struct Str {
    /// Byte range of the literal, quotes included; `None` for free-form input.
    pub span: Option<(usize, usize)>,
    pub decoded: String,
    pub path: Vec<Seg>,
    pub key: bool,
}

/// What may happen to one placeholder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Insert the value as is.
    Raw,
    /// Insert the value escaped for the site.
    Escape(Site),
    /// Keep the placeholder.
    Keep(KeepReason),
}

/// One placeholder occurrence.
#[derive(Clone, Debug)]
pub(crate) struct Occ {
    /// Index into [`Analysis::strings`].
    pub s: usize,
    /// Byte range in the decoded string.
    pub start: usize,
    pub end: usize,
    pub slug: String,
    pub verdict: Verdict,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Analysis {
    pub strings: Vec<Str>,
    pub occ: Vec<Occ>,
}

enum Frame {
    Obj {
        key: Option<String>,
        expect_key: bool,
    },
    Arr {
        idx: usize,
    },
}

/// Every string literal of a JSON document, in source order. `None` when `src` is not JSON.
pub(crate) fn json_strings(src: &str) -> Option<Vec<Str>> {
    serde_json::from_str::<serde_json::Value>(src).ok()?;
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut stack: Vec<Frame> = Vec::new();
    let mut i = 0;
    let path = |stack: &[Frame]| -> Vec<Seg> {
        stack
            .iter()
            .filter_map(|f| match f {
                Frame::Obj { key: Some(k), .. } => Some(Seg::Key(k.clone())),
                Frame::Obj { key: None, .. } => None,
                Frame::Arr { idx } => Some(Seg::Index(*idx)),
            })
            .collect()
    };
    while i < b.len() {
        match b[i] {
            b'{' => {
                stack.push(Frame::Obj {
                    key: None,
                    expect_key: true,
                });
                i += 1;
            }
            b'[' => {
                stack.push(Frame::Arr { idx: 0 });
                i += 1;
            }
            b'}' | b']' => {
                stack.pop();
                i += 1;
            }
            b':' => {
                if let Some(Frame::Obj { expect_key, .. }) = stack.last_mut() {
                    *expect_key = false;
                }
                i += 1;
            }
            b',' => {
                match stack.last_mut() {
                    Some(Frame::Obj { key, expect_key }) => {
                        *key = None;
                        *expect_key = true;
                    }
                    Some(Frame::Arr { idx }) => *idx += 1,
                    None => {}
                }
                i += 1;
            }
            b'"' => {
                let start = i;
                let mut j = i + 1;
                while j < b.len() {
                    match b[j] {
                        b'\\' => j += 2,
                        b'"' => break,
                        _ => j += 1,
                    }
                }
                let end = (j + 1).min(b.len());
                let decoded: String = serde_json::from_str(&src[start..end]).ok()?;
                let is_key = matches!(
                    stack.last(),
                    Some(Frame::Obj {
                        expect_key: true,
                        ..
                    })
                );
                if is_key {
                    let p = path(&stack);
                    if let Some(Frame::Obj { key, .. }) = stack.last_mut() {
                        *key = Some(decoded.clone());
                    }
                    out.push(Str {
                        span: Some((start, end)),
                        decoded,
                        path: p,
                        key: true,
                    });
                } else {
                    out.push(Str {
                        span: Some((start, end)),
                        decoded,
                        path: path(&stack),
                        key: false,
                    });
                }
                i = end;
            }
            _ => i += 1,
        }
    }
    Some(out)
}

fn placeholders(s: &str) -> Vec<(usize, usize, String)> {
    scrim_redact::find_placeholders(s.as_bytes())
        .map(|(at, p)| (at, at + p.len, String::from_utf8_lossy(p.slug).into_owned()))
        .collect()
}

fn context(r: Result<Site, Refusal>) -> Verdict {
    match r {
        Ok(site) if site.layers.is_empty() => Verdict::Raw,
        Ok(site) => Verdict::Escape(site),
        Err(r) => Verdict::Keep(KeepReason::Context(r)),
    }
}

const PATCH_BEGIN: &str = "*** Begin Patch";

/// Per-line verdicts of an `apply_patch` document: `+` lines may carry a placeholder only when
/// the same placeholder is on a context, removed or `@@` line of the same file.
fn patch_verdicts(text: &str, phs: &[(usize, usize, String)]) -> Vec<Verdict> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Line {
        Header,
        Known,
        Added,
        Other,
    }
    let mut lines = Vec::new();
    let mut section = 0usize;
    let mut pos = 0;
    for l in text.split_inclusive('\n') {
        let t = l.trim_end_matches(['\n', '\r']);
        let kind = if t.starts_with("*** Update File: ")
            || t.starts_with("*** Add File: ")
            || t.starts_with("*** Delete File: ")
        {
            section += 1;
            Line::Header
        } else if t.starts_with("*** Move to: ") {
            Line::Header
        } else if t.starts_with("@@") || t.starts_with(' ') || t.starts_with('-') {
            Line::Known
        } else if t.starts_with('+') {
            Line::Added
        } else {
            Line::Other
        };
        lines.push((pos, pos + l.len(), kind, section));
        pos += l.len();
    }
    let line_of = |at: usize| {
        lines
            .iter()
            .find(|&&(s, e, _, _)| at >= s && at < e)
            .copied()
    };
    let mut known: HashSet<(usize, &str)> = HashSet::new();
    for (s, e, _) in phs {
        if let Some((_, _, Line::Known, sec)) = line_of(*s) {
            known.insert((sec, &text[*s..*e]));
        }
    }
    phs.iter()
        .map(|(s, e, _)| match line_of(*s) {
            Some((_, _, Line::Header | Line::Known, _)) => Verdict::Raw,
            Some((_, _, Line::Added, sec)) if known.contains(&(sec, &text[*s..*e])) => Verdict::Raw,
            Some((_, _, Line::Added, _)) => Verdict::Keep(KeepReason::NewInFile),
            _ => Verdict::Keep(KeepReason::Context(Refusal::Position)),
        })
        .collect()
}

/// Analyses one tool call's complete arguments.
pub(crate) fn analyze(spec: &ToolSpec, input: &str, commands: &dyn CommandSet) -> Analysis {
    let (strings, json) = match json_strings(input) {
        Some(s) => (s, true),
        None => (
            vec![Str {
                span: None,
                decoded: input.to_owned(),
                path: Vec::new(),
                key: false,
            }],
            false,
        ),
    };
    let found: Vec<Vec<(usize, usize, String)>> =
        strings.iter().map(|s| placeholders(&s.decoded)).collect();
    let mut verdicts: Vec<Vec<Verdict>> = found
        .iter()
        .map(|f| vec![Verdict::Keep(KeepReason::Role(spec.role)); f.len()])
        .collect();
    let field_is = |s: &Str, names: &[std::sync::Arc<str>]| {
        s.path
            .iter()
            .rev()
            .find_map(|seg| match seg {
                Seg::Key(k) => Some(k),
                Seg::Index(_) => None,
            })
            .is_some_and(|k| names.iter().any(|n| n.as_ref() == k))
    };
    match spec.role {
        ToolRole::Read | ToolRole::Search => {
            for (i, s) in strings.iter().enumerate() {
                verdicts[i].fill(if s.key {
                    Verdict::Keep(KeepReason::Context(Refusal::Position))
                } else {
                    Verdict::Raw
                });
            }
        }
        ToolRole::Shell => {
            let cf = spec.command_field.as_ref();
            let mut argv: Vec<usize> = Vec::new();
            for (i, s) in strings.iter().enumerate() {
                if s.key {
                    verdicts[i].fill(Verdict::Keep(KeepReason::Context(Refusal::Position)));
                    continue;
                }
                let script = !json || s.path == [Seg::Key(cf.to_owned())];
                if script {
                    let spans: Vec<_> = found[i].iter().map(|&(a, b, _)| (a, b)).collect();
                    for (v, r) in verdicts[i]
                        .iter_mut()
                        .zip(shell::analyze_script(&s.decoded, &spans, commands))
                    {
                        *v = context(r);
                    }
                } else if matches!(s.path.as_slice(), [Seg::Key(k), Seg::Index(_)] if k == cf) {
                    argv.push(i);
                } else {
                    verdicts[i].fill(Verdict::Raw);
                }
            }
            if !argv.is_empty() {
                let contiguous = argv
                    .iter()
                    .enumerate()
                    .all(|(n, &i)| strings[i].path.get(1) == Some(&Seg::Index(n)));
                if contiguous {
                    let words: Vec<&str> =
                        argv.iter().map(|&i| strings[i].decoded.as_str()).collect();
                    let spans: Vec<Vec<_>> = argv
                        .iter()
                        .map(|&i| found[i].iter().map(|&(a, b, _)| (a, b)).collect())
                        .collect();
                    for (&i, rs) in argv
                        .iter()
                        .zip(shell::analyze_argv(&words, &spans, commands))
                    {
                        for (v, r) in verdicts[i].iter_mut().zip(rs) {
                            *v = context(r);
                        }
                    }
                } else {
                    for &i in &argv {
                        verdicts[i].fill(Verdict::Keep(KeepReason::Context(Refusal::Unsupported)));
                    }
                }
            }
        }
        ToolRole::Edit => {
            let mut known: HashSet<&str> = HashSet::new();
            for (i, s) in strings.iter().enumerate() {
                if !s.key && field_is(s, &spec.old_fields) {
                    for &(a, b, _) in &found[i] {
                        known.insert(&s.decoded[a..b]);
                    }
                }
            }
            for (i, s) in strings.iter().enumerate() {
                if s.key {
                    verdicts[i].fill(Verdict::Keep(KeepReason::Context(Refusal::Position)));
                } else if s.decoded.trim_start().starts_with(PATCH_BEGIN) {
                    verdicts[i] = patch_verdicts(&s.decoded, &found[i]);
                } else if !json {
                    // Free-form input that is not a patch: nothing to vouch for.
                } else if field_is(s, &spec.old_fields) {
                    verdicts[i].fill(Verdict::Raw);
                } else if field_is(s, &spec.new_fields) {
                    for (v, &(a, b, _)) in verdicts[i].iter_mut().zip(&found[i]) {
                        *v = if known.contains(&s.decoded[a..b]) {
                            Verdict::Raw
                        } else {
                            Verdict::Keep(KeepReason::NewInFile)
                        };
                    }
                } else {
                    // Paths and other plain arguments.
                    verdicts[i].fill(Verdict::Raw);
                }
            }
        }
        ToolRole::None | ToolRole::Write | ToolRole::Network => {}
    }
    let mut occ = Vec::new();
    for (i, (f, vs)) in found.into_iter().zip(verdicts).enumerate() {
        for ((start, end, slug), verdict) in f.into_iter().zip(vs) {
            occ.push(Occ {
                s: i,
                start,
                end,
                slug,
                verdict,
            });
        }
    }
    Analysis { strings, occ }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::pedantic)]
mod tests {
    use super::*;
    use crate::escape::Layer;
    use crate::restore::tools::Settings;

    #[test]
    fn json_paths() {
        let src = r#"{"a": "x", "b": [1, "y", {"c": "z\u0041"}], "d": {"e": ["w"]}}"#;
        let s = json_strings(src).unwrap();
        let got: Vec<_> = s
            .iter()
            .map(|s| (s.decoded.as_str(), s.key, s.path.clone()))
            .collect();
        use Seg::*;
        assert_eq!(
            got,
            vec![
                ("a", true, vec![]),
                ("x", false, vec![Key("a".into())]),
                ("b", true, vec![]),
                ("y", false, vec![Key("b".into()), Index(1)]),
                ("c", true, vec![Key("b".into()), Index(2)]),
                (
                    "zA",
                    false,
                    vec![Key("b".into()), Index(2), Key("c".into())]
                ),
                ("d", true, vec![]),
                ("e", true, vec![Key("d".into())]),
                ("w", false, vec![Key("d".into()), Key("e".into()), Index(0)]),
            ]
        );
        assert_eq!(
            &src[s[5].span.unwrap().0..s[5].span.unwrap().1],
            "\"z\\u0041\""
        );
        assert!(json_strings("{not json").is_none());
        assert!(json_strings("\"top\"").unwrap()[0].path.is_empty());
    }

    fn ph(slug: &str) -> String {
        format!("\u{27e6}scrim:{slug}:01{}\u{27e7}", "0123456789abcdef")
    }

    fn verdicts(spec: &ToolSpec, input: &str) -> Vec<Verdict> {
        analyze(spec, input, &Settings::standard())
            .occ
            .into_iter()
            .map(|o| o.verdict)
            .collect()
    }

    #[test]
    fn edit_roles() {
        let s = Settings::standard();
        let p = ph("a");
        let q = ph("b");
        let input = serde_json::json!({"file_path": format!("/x/{p}"), "old_string": format!("k={p}"), "new_string": format!("k2={p} {q}")}).to_string();
        assert_eq!(
            verdicts(&s.tool("Edit"), &input),
            vec![
                Verdict::Raw,
                Verdict::Raw,
                Verdict::Raw,
                Verdict::Keep(KeepReason::NewInFile)
            ]
        );
        let input = serde_json::json!({"file_path": "f", "edits": [{"old_string": p, "new_string": "x"}, {"old_string": "y", "new_string": format!("{p}{q}")}]}).to_string();
        assert_eq!(
            verdicts(&s.tool("MultiEdit"), &input),
            vec![
                Verdict::Raw,
                Verdict::Raw,
                Verdict::Keep(KeepReason::NewInFile)
            ]
        );
        let patch = format!(
            "*** Begin Patch\n*** Update File: {p}.txt\n@@ fn x\n-old {p}\n+new {p}\n+new {q}\n*** Add File: b.txt\n+{p}\n*** End Patch\n"
        );
        assert_eq!(
            verdicts(&s.tool("apply_patch"), &patch),
            vec![
                Verdict::Raw,
                Verdict::Raw,
                Verdict::Raw,
                Verdict::Keep(KeepReason::NewInFile),
                Verdict::Keep(KeepReason::NewInFile),
            ]
        );
        let wrapped = serde_json::json!({ "input": patch }).to_string();
        assert_eq!(verdicts(&s.tool("apply_patch"), &wrapped).len(), 5);
        let input = serde_json::json!({"file_path": "f", "content": p}).to_string();
        assert_eq!(
            verdicts(&s.tool("Write"), &input),
            vec![Verdict::Keep(KeepReason::Role(ToolRole::Write))]
        );
        assert_eq!(
            verdicts(&s.tool("Edit"), &format!("free {p}")),
            vec![Verdict::Keep(KeepReason::Role(ToolRole::Edit))]
        );
    }

    #[test]
    fn shell_roles() {
        let s = Settings::standard();
        let p = ph("a");
        let input =
            serde_json::json!({"command": format!("echo {p} | sh"), "description": p}).to_string();
        assert_eq!(
            verdicts(&s.tool("Bash"), &input),
            vec![
                Verdict::Keep(KeepReason::Context(Refusal::UnknownCommand)),
                Verdict::Raw
            ]
        );
        let input =
            serde_json::json!({"command": ["bash", "-lc", format!("cat '{p}'")], "workdir": p})
                .to_string();
        assert_eq!(
            verdicts(&s.tool("shell"), &input),
            vec![
                Verdict::Escape(Site {
                    layers: vec![
                        Layer::ShellSingle { word_start: true },
                        Layer::Argv { word_start: false }
                    ]
                }),
                Verdict::Raw
            ]
        );
        let input = serde_json::json!({"cmd": format!("cat {p}")}).to_string();
        assert!(matches!(
            verdicts(&s.tool("exec_command"), &input)[0],
            Verdict::Escape(_)
        ));
        assert!(matches!(
            verdicts(&s.tool("Bash"), &format!("echo {p}"))[0],
            Verdict::Escape(_)
        ));
        let input = serde_json::json!({"command": ["cat", 1, p]}).to_string();
        assert_eq!(
            verdicts(&s.tool("shell"), &input),
            vec![Verdict::Keep(KeepReason::Context(Refusal::Unsupported))]
        );
        let input = serde_json::json!({ p.clone(): "x" }).to_string();
        assert_eq!(
            verdicts(&s.tool("Read"), &input),
            vec![Verdict::Keep(KeepReason::Context(Refusal::Position))]
        );
    }
}
