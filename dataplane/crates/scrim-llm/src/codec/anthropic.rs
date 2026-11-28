// SPDX-License-Identifier: AGPL-3.0-only

//! Anthropic Messages API.
//!
//! Request: allowlisted top-level configuration, `thinking`/`signature` of thinking blocks and
//! `data` of redacted thinking blocks stay byte-identical; base64 image and document sources are
//! unscannable binary. Everything else is redacted.
//!
//! Response: `text` blocks resolve under [`RestoreSite::Text`], `tool_use` input under
//! [`RestoreSite::ToolInput`]. Thinking, redacted thinking, signatures, server tool use and
//! citations are left alone. Streams follow the content-block protocol (`content_block_start`,
//! `content_block_delta`, `content_block_stop`) with one holdback per block index.

use std::collections::BTreeMap;

use super::{
    DeltaOut, Edits, Plan, PlanError, StreamBlock, StreamCodec, StreamLimits, feed_delta,
    flush_block, keep_allowlisted, restore_json_source, restore_string, synth_from_template,
};
use crate::engine::RestoreSite;
use crate::json::{self, Doc, Kind, Value};
use crate::remote::{Edit, Target};
use crate::restore::{Ctx, TextKind};
use crate::sse;

/// Top-level request members that are configuration, not content. Their values are forwarded
/// byte-identical. Every other member, known or not, is redacted.
pub(crate) const ALLOWLIST: &[&str] = &[
    "model",
    "max_tokens",
    "stream",
    "temperature",
    "top_p",
    "top_k",
    "tool_choice",
    "thinking",
    "service_tier",
    "anthropic_version",
];

pub(crate) fn plan(doc: &Doc<'_>) -> Result<Plan, PlanError> {
    let mut plan = Plan::default();
    let root = doc.root();
    keep_allowlisted(&mut plan, root, ALLOWLIST)?;
    if let Some(messages) = root.get("messages")? {
        if messages.kind() != Kind::Array {
            return Err(PlanError::Shape("messages is not an array"));
        }
        for m in messages.children() {
            if let Some(content) = m.get("content")? {
                plan_blocks(&mut plan, content, 0)?;
            }
        }
    }
    if let Some(system) = root.get("system")? {
        plan_blocks(&mut plan, system, 0)?;
    }
    Ok(plan)
}

fn plan_blocks(plan: &mut Plan, content: Value<'_, '_>, depth: usize) -> Result<(), PlanError> {
    if content.kind() != Kind::Array || depth > 4 {
        return Ok(());
    }
    for b in content.children() {
        if b.kind() != Kind::Object {
            continue;
        }
        let ty = b.get_str("type")?;
        match ty.as_deref() {
            Some("thinking") => {
                for f in ["thinking", "signature"] {
                    if let Some(v) = b.get(f)? {
                        plan.keep(v);
                    }
                }
            }
            Some("redacted_thinking") => {
                if let Some(v) = b.get("data")? {
                    plan.keep(v);
                }
            }
            Some("image" | "document") => {
                if let Some(src) = b.get("source")? {
                    plan_source(plan, src, depth)?;
                }
            }
            Some("container_upload") => {
                if let Some(id) = b.get_str("file_id")? {
                    plan.reference(Target::FileId(id.into_owned()), Edit::None);
                }
            }
            Some("tool_result" | "search_result") => {
                if let Some(c) = b.get("content")? {
                    plan_blocks(plan, c, depth + 1)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn plan_source(plan: &mut Plan, src: Value<'_, '_>, depth: usize) -> Result<(), PlanError> {
    match src.get_str("type")?.as_deref() {
        Some("base64") => {
            if let Some(data) = src.get("data")? {
                let mt = src.get_str("media_type")?.unwrap_or_default();
                plan.binary(data, &mt);
            }
        }
        Some("content") => {
            if let Some(c) = src.get("content")? {
                plan_blocks(plan, c, depth + 1)?;
            }
        }
        Some("url") => {
            if let Some(u) = src.get_str("url")? {
                plan.reference(
                    Target::Url(u.into_owned()),
                    Edit::AnthropicSource { span: src.span() },
                );
            }
        }
        Some("file") => {
            if let Some(id) = src.get_str("file_id")? {
                plan.reference(Target::FileId(id.into_owned()), Edit::None);
            }
        }
        _ => {}
    }
    Ok(())
}

/// Restores a non-streaming Messages response (`{"type":"message","content":[...]}`).
pub(crate) fn restore_message(ctx: &Ctx<'_>, root: Value<'_, '_>, edits: &mut Edits) {
    let Ok(Some(content)) = root.get("content") else {
        return;
    };
    for b in content.children() {
        restore_block(ctx, b, edits);
    }
}

fn restore_block(ctx: &Ctx<'_>, b: Value<'_, '_>, edits: &mut Edits) {
    let Ok(ty) = b.get_str("type") else { return };
    match ty.as_deref() {
        Some("text") => {
            if let Ok(Some(t)) = b.get("text") {
                restore_string(ctx, &RestoreSite::Text, TextKind::Plain, t, edits);
            }
        }
        Some("tool_use") => {
            let name = b.get_str("name").ok().flatten().unwrap_or_default();
            if let Ok(Some(input)) = b.get("input") {
                let args = std::str::from_utf8(input.raw()).unwrap_or_default();
                let site = RestoreSite::ToolInput {
                    tool: &name,
                    arguments: Some(args),
                };
                restore_json_source(ctx, &site, input, edits);
            }
        }
        _ => {}
    }
}

/// Streaming state for one Messages response.
pub(crate) struct Stream {
    blocks: BTreeMap<u64, StreamBlock>,
    budget: usize,
}

impl Stream {
    pub(crate) fn new(limits: StreamLimits) -> Self {
        Self {
            blocks: BTreeMap::new(),
            budget: limits.max_buffered_tool_input,
        }
    }

    fn flush(&mut self, ctx: &Ctx<'_>, index: u64, out: &mut Vec<u8>) {
        let Some(block) = self.blocks.get_mut(&index) else {
            return;
        };
        let text = flush_block(ctx, block);
        if text.is_empty() {
            return;
        }
        let field = if block.tool.is_some() {
            "partial_json"
        } else {
            "text"
        };
        if let Some(ev) = block
            .template
            .as_deref()
            .and_then(|t| synth_from_template(t, &["delta", field], &text))
        {
            out.extend_from_slice(&ev);
        } else {
            // No template (cannot happen for held text); build a minimal delta.
            let mut data = Vec::new();
            data.extend_from_slice(b"{\"type\":\"content_block_delta\",\"index\":");
            data.extend_from_slice(index.to_string().as_bytes());
            let ty = if block.tool.is_some() {
                "input_json_delta"
            } else {
                "text_delta"
            };
            data.extend_from_slice(
                format!(",\"delta\":{{\"type\":\"{ty}\",\"{field}\":").as_bytes(),
            );
            data.extend_from_slice(&json::quote(&text));
            data.extend_from_slice(b"}}");
            out.extend_from_slice(&sse::build(Some("content_block_delta"), &data));
        }
    }

    fn flush_all(&mut self, ctx: &Ctx<'_>, out: &mut Vec<u8>) {
        let keys: Vec<u64> = self.blocks.keys().copied().collect();
        for k in keys {
            self.flush(ctx, k, out);
        }
    }

    fn start(&mut self, ctx: &Ctx<'_>, root: Value<'_, '_>) {
        let Some(index) = index_of(root) else { return };
        let Ok(Some(cb)) = root.get("content_block") else {
            return;
        };
        let ty = cb.get_str("type").ok().flatten();
        let block = match ty.as_deref() {
            Some("text") => StreamBlock::text(),
            Some("tool_use") => {
                let name = cb.get_str("name").ok().flatten().unwrap_or_default();
                StreamBlock::tool(ctx, &name, TextKind::JsonText)
            }
            // thinking, redacted_thinking, server_tool_use, web search results, unknown kinds.
            _ => StreamBlock::verbatim(),
        };
        self.blocks.insert(index, block);
    }

    fn delta(
        &mut self,
        ctx: &Ctx<'_>,
        raw: &[u8],
        data: &str,
        root: Value<'_, '_>,
        out: &mut Vec<u8>,
    ) {
        let pass = |out: &mut Vec<u8>| out.extend_from_slice(raw);
        let (Some(index), Ok(Some(delta))) = (index_of(root), root.get("delta")) else {
            return pass(out);
        };
        let field = match delta.get_str("type").ok().flatten().as_deref() {
            Some("text_delta") => "text",
            Some("input_json_delta") => "partial_json",
            // thinking_delta and signature_delta stay byte-identical; citations pass through.
            _ => return pass(out),
        };
        let Ok(Some(v)) = delta.get(field) else {
            return pass(out);
        };
        let Some(s) = v.as_str() else {
            return pass(out);
        };
        let block = self.blocks.entry(index).or_insert_with(|| {
            // A delta without a start: treat as text, or as a tool the policy cannot name.
            if field == "text" {
                StreamBlock::text()
            } else {
                StreamBlock::tool(ctx, "", TextKind::JsonText)
            }
        });
        if (field == "text") != block.tool.is_none() && !block.passthrough {
            // Delta kind does not match the block kind; do not guess.
            return pass(out);
        }
        match feed_delta(ctx, block, &s, &mut self.budget) {
            DeltaOut::Unchanged => pass(out),
            DeltaOut::Drop => {
                block.template = Some(raw.to_vec());
            }
            DeltaOut::Replace(text) => {
                let new = json::splice(
                    data.as_bytes(),
                    &[(v.span().0, v.span().1, json::quote(&text))],
                );
                out.extend_from_slice(&sse::with_data(raw, &new));
                block.template = Some(raw.to_vec());
            }
        }
    }
}

fn index_of(root: Value<'_, '_>) -> Option<u64> {
    let v = root.get("index").ok()??;
    let n: u64 = std::str::from_utf8(v.raw()).ok()?.parse().ok()?;
    (n < 1 << 16).then_some(n)
}

impl StreamCodec for Stream {
    fn event(&mut self, ctx: &Ctx<'_>, raw: &[u8], out: &mut Vec<u8>) {
        let Some(ev) = sse::Event::parse(raw) else {
            return out.extend_from_slice(raw);
        };
        if !ev.has_data {
            return out.extend_from_slice(raw);
        }
        let Ok(doc) = Doc::parse(ev.data.as_bytes()) else {
            return out.extend_from_slice(raw);
        };
        let root = doc.root();
        let ty = root.get_str("type").ok().flatten();
        match ty.as_deref() {
            Some("content_block_start") => {
                self.start(ctx, root);
                out.extend_from_slice(raw);
            }
            Some("content_block_delta") => self.delta(ctx, raw, &ev.data, root, out),
            Some("content_block_stop") => {
                if let Some(i) = index_of(root) {
                    self.flush(ctx, i, out);
                    self.blocks.remove(&i);
                }
                out.extend_from_slice(raw);
            }
            Some("message_delta" | "message_stop") => {
                self.flush_all(ctx, out);
                out.extend_from_slice(raw);
            }
            _ => out.extend_from_slice(raw),
        }
    }

    fn finish(&mut self, ctx: &Ctx<'_>, out: &mut Vec<u8>) {
        self.flush_all(ctx, out);
        self.blocks.clear();
    }
}

/// Exposed for tests: whether `tool` would be buffered under the snapshot's policy.
#[cfg(test)]
pub(crate) fn is_buffered(ctx: &Ctx<'_>, tool: &str) -> bool {
    ctx.snap.policy.tool_mode(tool) == crate::engine::ToolMode::Buffered
}

#[cfg(all(test, feature = "test-util"))]
mod tests {
    use super::*;
    use crate::codec::{self, Api};
    use crate::restore::RestoreStats;
    use crate::testing::{FakePolicy, Fixture};

    fn planned(body: &str) -> Vec<String> {
        let p = codec::plan(Api::AnthropicMessages, body.as_bytes()).unwrap();
        p.verbatim
            .iter()
            .map(|(s, e)| body[*s..*e].to_string())
            .collect()
    }

    #[test]
    fn plan_keeps_config_and_signed_content() {
        let body = r#"{"model":"claude-x","max_tokens":10,"stream":true,"metadata":{"user_id":"u"},
            "messages":[{"role":"assistant","content":[
              {"type":"thinking","thinking":"hmm","signature":"c2ln"},
              {"type":"redacted_thinking","data":"ZW5j"},
              {"type":"text","text":"hi"}]},
              {"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":[
                {"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBO"}}]}]}],
            "thinking":{"type":"enabled","budget_tokens":1024},"unknown_field":"x"}"#;
        let kept = planned(body);
        assert_eq!(
            kept,
            vec![
                "claude-x",
                "10",
                "true",
                "hmm",
                "c2ln",
                "ZW5j",
                "iVBO",
                r#"{"type":"enabled","budget_tokens":1024}"#
            ]
        );
        let p = codec::plan(Api::AnthropicMessages, body.as_bytes()).unwrap();
        assert_eq!(p.binary, vec!["image/png"]);
    }

    #[test]
    fn plan_rejects_duplicate_type_and_bad_messages() {
        let dup = r#"{"messages":[{"role":"user","content":[{"type":"thinking","type":"text","thinking":"x"}]}]}"#;
        assert!(codec::plan(Api::AnthropicMessages, dup.as_bytes()).is_err());
        assert!(codec::plan(Api::AnthropicMessages, br#"{"messages":{}}"#).is_err());
        assert!(codec::plan(Api::AnthropicMessages, br#"{"model":"a","model":"b"}"#).is_ok());
    }

    #[test]
    fn restore_message_text_and_tool_use() {
        let fx = Fixture::new(&[("api", "display-value-123")]);
        let snap = fx.snapshot();
        let stats = RestoreStats::default();
        let ctx = Ctx {
            snap: &snap,
            stats: &stats,
        };
        let ph = fx.placeholder("api");
        let body = format!(
            r#"{{"type":"message","content":[{{"type":"thinking","thinking":"{ph}","signature":"s"}},{{"type":"text","text":"v={ph}"}},{{"type":"tool_use","id":"t","name":"Read","input":{{"path":"/x/{ph}"}}}}]}}"#
        );
        let out = codec::restore_json(Api::AnthropicMessages, &ctx, body.as_bytes()).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["content"][0]["thinking"], ph.as_str());
        assert_eq!(v["content"][1]["text"], "v=display-value-123");
        assert_eq!(v["content"][2]["input"]["path"], "/x/display-value-123");
    }

    #[test]
    fn buffered_mode_detected() {
        let mut fx = Fixture::new(&[]);
        fx.policy = FakePolicy {
            buffered: vec!["Write".into()],
            ..FakePolicy::resolve_all()
        };
        let snap = fx.snapshot();
        let stats = RestoreStats::default();
        let ctx = Ctx {
            snap: &snap,
            stats: &stats,
        };
        assert!(is_buffered(&ctx, "Write"));
        assert!(!is_buffered(&ctx, "Read"));
    }
}
