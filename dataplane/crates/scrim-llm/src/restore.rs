// SPDX-License-Identifier: AGPL-3.0-only

//! Placeholder resolution in response text, with bounded holdback for streams.
//!
//! A [`StreamText`] restores one content block. It holds back at most
//! `Placeholders::max_len() - 1` bytes (the longest possible placeholder prefix at the end of the
//! text so far) and emits everything else at once. Each complete placeholder is resolved only when
//! the [`RestorePolicy`] says so and the value is not a credential; otherwise, and for unknown
//! placeholders, it is emitted unchanged.

use std::cell::Cell;

use crate::engine::{PlaceholderMatch, RestoreDecision, RestoreSite, Snapshot, ValueClass};
use crate::json;

/// How resolved values are written into the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TextKind {
    /// Plain decoded text (assistant text, free-form tool input). The value is inserted as is;
    /// the codec re-encodes the surrounding JSON string.
    Plain,
    /// JSON source text (streamed `partial_json`, function-call `arguments`). The value is
    /// resolved only inside a string literal, and JSON-escaped there.
    JsonText,
}

/// Counters for one response, reported to the audit sink.
#[derive(Debug, Default)]
pub(crate) struct RestoreStats {
    pub resolved: Cell<u64>,
    pub kept: Cell<u64>,
}

/// One request's view of the snapshot used for restore.
pub(crate) struct Ctx<'s> {
    pub snap: &'s Snapshot,
    pub stats: &'s RestoreStats,
}

impl Ctx<'_> {
    /// Returns the value to substitute for `placeholder` at `site`, or `None` to keep it.
    fn decide(
        &self,
        site: &RestoreSite<'_>,
        placeholder: &str,
    ) -> Option<std::sync::Arc<crate::engine::SecretValue>> {
        let Some(r) = self.snap.placeholders.resolve(placeholder) else {
            self.stats.kept.set(self.stats.kept.get() + 1);
            return None;
        };
        // Credentials are never restored, whatever the policy says (design D5).
        let ok = r.class != ValueClass::Credential
            && self.snap.policy.decide(site, &r.reference, r.class) == RestoreDecision::Resolve
            && std::str::from_utf8(r.value.expose()).is_ok();
        if ok {
            self.stats.resolved.set(self.stats.resolved.get() + 1);
            Some(r.value)
        } else {
            self.stats.kept.set(self.stats.kept.get() + 1);
            None
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct JsonLex {
    in_str: bool,
    esc: bool,
}

impl JsonLex {
    fn feed(&mut self, s: &str) {
        for b in s.bytes() {
            if self.in_str {
                if self.esc {
                    self.esc = false;
                } else if b == b'\\' {
                    self.esc = true;
                } else if b == b'"' {
                    self.in_str = false;
                }
            } else if b == b'"' {
                self.in_str = true;
            }
        }
    }
}

/// Restores one content block of a stream.
#[derive(Debug)]
pub(crate) struct StreamText {
    kind: TextKind,
    held: String,
    lex: JsonLex,
}

impl StreamText {
    pub(crate) fn new(kind: TextKind) -> Self {
        Self {
            kind,
            held: String::new(),
            lex: JsonLex::default(),
        }
    }

    /// How values are written into this block.
    pub(crate) fn kind(&self) -> TextKind {
        self.kind
    }

    /// Bytes currently held back.
    #[cfg(test)]
    pub(crate) fn held_len(&self) -> usize {
        self.held.len()
    }

    /// Feeds `chunk`, appends what can be emitted now to `out`. Returns `true` when `out` differs
    /// from `chunk` (something was resolved, held back or released).
    pub(crate) fn push(
        &mut self,
        ctx: &Ctx<'_>,
        site: &RestoreSite<'_>,
        chunk: &str,
        out: &mut String,
    ) -> bool {
        let had_held = !self.held.is_empty();
        let joined;
        let buf: &str = if had_held {
            let mut b = std::mem::take(&mut self.held);
            b.push_str(chunk);
            joined = b;
            &joined
        } else {
            chunk
        };
        let max = ctx.snap.placeholders.max_len();
        let mut changed = had_held;
        let mut i = 0;
        loop {
            match ctx.snap.placeholders.find(&buf[i..]) {
                None => {
                    self.emit(out, &buf[i..]);
                    break;
                }
                Some(PlaceholderMatch::Partial { start }) => {
                    let start = i + start;
                    self.emit(out, &buf[i..start]);
                    let tail = &buf[start..];
                    if tail.len() >= max || !buf.is_char_boundary(start) {
                        // A misbehaving matcher must not make us hold unbounded text.
                        self.emit(out, tail);
                    } else {
                        self.held.push_str(tail);
                        changed = true;
                    }
                    break;
                }
                Some(PlaceholderMatch::Complete { start, end }) => {
                    let (start, end) = (i + start, i + end);
                    if end <= start
                        || end > buf.len()
                        || !buf.is_char_boundary(start)
                        || !buf.is_char_boundary(end)
                    {
                        self.emit(out, &buf[i..]);
                        break;
                    }
                    self.emit(out, &buf[i..start]);
                    let ph = &buf[start..end];
                    let eligible = match self.kind {
                        TextKind::Plain => true,
                        TextKind::JsonText => self.lex.in_str && !self.lex.esc,
                    };
                    match eligible.then(|| ctx.decide(site, ph)).flatten() {
                        Some(v) => {
                            // decide() checked UTF-8.
                            let v = std::str::from_utf8(v.expose()).unwrap_or_default();
                            match self.kind {
                                TextKind::Plain => out.push_str(v),
                                TextKind::JsonText => {
                                    let mut esc = Vec::with_capacity(v.len() + 8);
                                    json::escape_into(&mut esc, v);
                                    out.push_str(std::str::from_utf8(&esc).unwrap_or_default());
                                }
                            }
                            changed = true;
                        }
                        None => self.emit(out, ph),
                    }
                    i = end;
                }
            }
        }
        changed
    }

    /// Releases held bytes unchanged (they never became a placeholder).
    pub(crate) fn finish(&mut self, out: &mut String) {
        let held = std::mem::take(&mut self.held);
        self.emit(out, &held);
    }

    fn emit(&mut self, out: &mut String, s: &str) {
        if self.kind == TextKind::JsonText {
            self.lex.feed(s);
        }
        out.push_str(s);
    }
}

/// Restores a complete text. Returns `None` when nothing was resolved.
pub(crate) fn restore_complete(
    ctx: &Ctx<'_>,
    site: &RestoreSite<'_>,
    kind: TextKind,
    text: &str,
) -> Option<String> {
    let before = ctx.stats.resolved.get();
    let mut st = StreamText::new(kind);
    let mut out = String::with_capacity(text.len());
    st.push(ctx, site, text, &mut out);
    st.finish(&mut out);
    (ctx.stats.resolved.get() != before).then_some(out)
}

#[cfg(all(test, feature = "test-util"))]
mod tests {
    use super::*;
    use crate::testing::{FakePolicy, Fixture};

    fn ctx_for(fx: &Fixture) -> (Snapshot, RestoreStats) {
        (fx.snapshot(), RestoreStats::default())
    }

    #[test]
    fn resolves_whole_placeholder_in_text() {
        let fx = Fixture::new(&[("api", "display-value-123")]);
        let (snap, stats) = ctx_for(&fx);
        let ctx = Ctx {
            snap: &snap,
            stats: &stats,
        };
        let ph = fx.placeholder("api");
        let text = format!("before {ph} after");
        let out = restore_complete(&ctx, &RestoreSite::Text, TextKind::Plain, &text).unwrap();
        assert_eq!(out, "before display-value-123 after");
        assert_eq!(stats.resolved.get(), 1);
    }

    #[test]
    fn credential_never_resolved_even_if_policy_allows() {
        let mut fx = Fixture::new(&[]);
        fx.add_credential("tok", "ghp_credential_value_0001");
        fx.policy = FakePolicy::resolve_all();
        let (snap, stats) = ctx_for(&fx);
        let ctx = Ctx {
            snap: &snap,
            stats: &stats,
        };
        let ph = fx.placeholder("tok");
        let site = RestoreSite::ToolInput {
            tool: "Bash",
            arguments: None,
        };
        assert!(restore_complete(&ctx, &site, TextKind::Plain, &format!("curl -H {ph}")).is_none());
        assert_eq!(stats.kept.get(), 1);
    }

    #[test]
    fn json_text_resolves_only_inside_strings_and_escapes() {
        let fx = Fixture::new(&[("q", "va\"l\\ue-with-quote")]);
        let (snap, stats) = ctx_for(&fx);
        let ctx = Ctx {
            snap: &snap,
            stats: &stats,
        };
        let ph = fx.placeholder("q");
        let site = RestoreSite::ToolInput {
            tool: "Read",
            arguments: None,
        };
        let src = format!("{{\"a\":\"x {ph} y\",\"b\":{ph}}}");
        let out = restore_complete(&ctx, &site, TextKind::JsonText, &src).unwrap();
        assert_eq!(
            out,
            format!("{{\"a\":\"x va\\\"l\\\\ue-with-quote y\",\"b\":{ph}}}")
        );
        let v: serde_json::Value = serde_json::from_str(&out.replace(&ph, "0")).unwrap();
        assert_eq!(v["a"], "x va\"l\\ue-with-quote y");
    }

    #[test]
    fn split_placeholder_held_and_released_once() {
        let fx = Fixture::new(&[("api", "display-value-123")]);
        let (snap, stats) = ctx_for(&fx);
        let ctx = Ctx {
            snap: &snap,
            stats: &stats,
        };
        let ph = fx.placeholder("api");
        let full = format!("x{ph}y");
        for cut in 1..full.len() {
            if !full.is_char_boundary(cut) {
                continue;
            }
            let mut st = StreamText::new(TextKind::Plain);
            let mut out = String::new();
            st.push(&ctx, &RestoreSite::Text, &full[..cut], &mut out);
            assert!(st.held_len() < fx.placeholders_max_len());
            st.push(&ctx, &RestoreSite::Text, &full[cut..], &mut out);
            st.finish(&mut out);
            assert_eq!(out, "xdisplay-value-123y", "cut at {cut}");
        }
    }

    #[test]
    fn unknown_placeholder_emitted_unchanged() {
        let fx = Fixture::new(&[("api", "display-value-123")]);
        let (snap, stats) = ctx_for(&fx);
        let ctx = Ctx {
            snap: &snap,
            stats: &stats,
        };
        let foreign = Fixture::new(&[("other", "another-value-456")]).placeholder("other");
        assert!(
            restore_complete(
                &ctx,
                &RestoreSite::Text,
                TextKind::Plain,
                &format!("a {foreign} b")
            )
            .is_none()
        );
    }

    #[test]
    fn dangling_prefix_flushed_verbatim() {
        let fx = Fixture::new(&[("api", "display-value-123")]);
        let (snap, stats) = ctx_for(&fx);
        let ctx = Ctx {
            snap: &snap,
            stats: &stats,
        };
        let ph = fx.placeholder("api");
        let prefix = &ph[..ph.len() - 4];
        let mut st = StreamText::new(TextKind::Plain);
        let mut out = String::new();
        assert!(st.push(&ctx, &RestoreSite::Text, &format!("t {prefix}"), &mut out));
        assert_eq!(out, "t ");
        st.finish(&mut out);
        assert_eq!(out, format!("t {prefix}"));
    }

    #[test]
    fn keep_policy_leaves_text() {
        let mut fx = Fixture::new(&[("api", "display-value-123")]);
        fx.policy = FakePolicy::keep_all();
        let (snap, stats) = ctx_for(&fx);
        let ctx = Ctx {
            snap: &snap,
            stats: &stats,
        };
        let ph = fx.placeholder("api");
        assert!(restore_complete(&ctx, &RestoreSite::Text, TextKind::Plain, &ph).is_none());
    }
}
