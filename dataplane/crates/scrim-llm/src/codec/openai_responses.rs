// SPDX-License-Identifier: AGPL-3.0-only

//! `OpenAI` Responses API.
//!
//! Request: allowlisted top-level configuration and every `encrypted_content` (reasoning and
//! compaction items) stay byte-identical, as do the summaries of reasoning items; `data:` URLs
//! in `input_image` and `file_data` in `input_file` are unscannable binary. Everything else is
//! redacted.
//!
//! Response: `output_text` and `refusal` parts resolve under [`RestoreSite::Text`];
//! `function_call.arguments` (JSON text) and `custom_tool_call.input` (free-form, as used by
//! Codex `apply_patch`) under [`RestoreSite::ToolInput`]. Reasoning is never touched. In a stream
//! the deltas, the matching `*.done` events, `output_item.done` and the final
//! `response.completed` snapshot are all restored with the same decisions, so an agent that
//! reads any of them sees the same text.

use std::collections::BTreeMap;

use super::{
    DeltaOut, Edits, Plan, PlanError, StreamBlock, StreamCodec, StreamLimits, block_site,
    data_url_media_type, feed_delta, flush_block, keep_allowlisted, restore_string,
    synth_from_template,
};
use crate::engine::{RestoreSite, ToolMode};
use crate::json::{self, Doc, Kind, Value};
use crate::restore::{Ctx, TextKind};
use crate::sse;

/// Top-level request members that are configuration, not content.
pub(crate) const ALLOWLIST: &[&str] = &[
    "model",
    "stream",
    "temperature",
    "top_p",
    "max_output_tokens",
    "max_tool_calls",
    "tool_choice",
    "parallel_tool_calls",
    "reasoning",
    "store",
    "service_tier",
    "truncation",
    "include",
    "previous_response_id",
    "prompt_cache_key",
    "background",
    "top_logprobs",
];

pub(crate) fn plan(doc: &Doc<'_>) -> Result<Plan, PlanError> {
    let mut plan = Plan::default();
    plan_body(&mut plan, doc.root())?;
    Ok(plan)
}

/// Members of a WebSocket-mode client event that are protocol, not content: the event type and
/// the `generate: false` warm-up flag.
const WS_ALLOWLIST: &[&str] = &["type", "generate"];

/// Plans one client event of the Responses API WebSocket mode (`GET /v1/responses` upgraded):
/// `{"type":"response.create", ...}` with the create body's members at the top level, as Codex
/// and the `OpenAI` SDKs send it, or nested under `response`. Either way it is planned as a
/// create body; every other event is redacted whole.
pub(crate) fn plan_ws(doc: &Doc<'_>) -> Result<Plan, PlanError> {
    let mut plan = Plan::default();
    let root = doc.root();
    keep_allowlisted(&mut plan, root, WS_ALLOWLIST)?;
    if root.get_str("type")?.as_deref() == Some("response.create") {
        plan_body(&mut plan, root)?;
        if let Some(r) = root.get("response")?
            && r.kind() == Kind::Object
        {
            plan_body(&mut plan, r)?;
        }
    }
    Ok(plan)
}

fn plan_body(plan: &mut Plan, root: Value<'_, '_>) -> Result<(), PlanError> {
    keep_allowlisted(plan, root, ALLOWLIST)?;
    if let Some(input) = root.get("input")?
        && input.kind() == Kind::Array
    {
        for item in input.children() {
            plan_item(plan, item)?;
        }
    }
    Ok(())
}

fn plan_item(plan: &mut Plan, item: Value<'_, '_>) -> Result<(), PlanError> {
    if item.kind() != Kind::Object {
        return Ok(());
    }
    if let Some(enc) = item.get("encrypted_content")? {
        plan.keep(enc);
    }
    match item.get_str("type")?.as_deref() {
        Some("reasoning") => {
            for f in ["summary", "content"] {
                if let Some(v) = item.get(f)? {
                    plan.keep(v);
                }
            }
        }
        // `message` items have no explicit type in the shorthand form.
        Some("message") | None => {
            if let Some(c) = item.get("content")? {
                plan_parts(plan, c)?;
            }
        }
        Some("function_call_output" | "custom_tool_call_output") => {
            if let Some(o) = item.get("output")? {
                plan_parts(plan, o)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn plan_parts(plan: &mut Plan, content: Value<'_, '_>) -> Result<(), PlanError> {
    if content.kind() != Kind::Array {
        return Ok(());
    }
    for part in content.children() {
        match part.get_str("type")?.as_deref() {
            Some("input_image") => {
                if let Some(u) = part.get("image_url")?
                    && let Some(mt) = u.as_str().as_deref().and_then(data_url_media_type)
                {
                    plan.binary(u, mt);
                }
            }
            Some("input_file") => {
                if let Some(d) = part.get("file_data")? {
                    let mt = d
                        .as_str()
                        .as_deref()
                        .and_then(data_url_media_type)
                        .unwrap_or("application/octet-stream")
                        .to_string();
                    plan.binary(d, &mt);
                }
            }
            Some("input_audio") => {
                if let Some(a) = part.get("input_audio")?
                    && let Some(d) = a.get("data")?
                {
                    let fmt = a.get_str("format")?.unwrap_or_default();
                    plan.binary(d, &format!("audio/{fmt}"));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Restores a Responses object (`{"object":"response","output":[...]}`). `full_args(tool)` says
/// whether the policy sees complete arguments for that tool (always for non-streaming bodies,
/// only in buffered mode for streams, matching how the deltas were decided).
pub(crate) fn restore_response(
    ctx: &Ctx<'_>,
    root: Value<'_, '_>,
    edits: &mut Edits,
    full_args: &dyn Fn(&str) -> bool,
) {
    let Ok(Some(output)) = root.get("output") else {
        return;
    };
    for item in output.children() {
        restore_item(ctx, item, edits, full_args);
    }
}

fn restore_item(
    ctx: &Ctx<'_>,
    item: Value<'_, '_>,
    edits: &mut Edits,
    full_args: &dyn Fn(&str) -> bool,
) {
    let Ok(ty) = item.get_str("type") else { return };
    match ty.as_deref() {
        Some("message") => {
            let Ok(Some(content)) = item.get("content") else {
                return;
            };
            for part in content.children() {
                restore_part(ctx, part, edits);
            }
        }
        Some(t @ ("function_call" | "custom_tool_call")) => {
            let (field, kind) = if t == "function_call" {
                ("arguments", TextKind::JsonText)
            } else {
                ("input", TextKind::Plain)
            };
            let name = item.get_str("name").ok().flatten().unwrap_or_default();
            if let Ok(Some(v)) = item.get(field) {
                let full = v.as_str().unwrap_or_default();
                let site = block_site(Some(&name), full_args(&name), &full);
                restore_string(ctx, &site, kind, v, edits);
            }
        }
        _ => {}
    }
}

fn restore_part(ctx: &Ctx<'_>, part: Value<'_, '_>, edits: &mut Edits) {
    let field = match part.get_str("type").ok().flatten().as_deref() {
        Some("output_text") => "text",
        Some("refusal") => "refusal",
        _ => return,
    };
    if let Ok(Some(v)) = part.get(field) {
        restore_string(ctx, &RestoreSite::Text, TextKind::Plain, v, edits);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Part(u64, u64),
    Args(u64),
}

impl Key {
    fn output(self) -> u64 {
        match self {
            Key::Part(o, _) | Key::Args(o) => o,
        }
    }
}

#[derive(Debug, Clone)]
enum Item {
    Function(String),
    Custom(String),
    Other,
}

/// Streaming state for one Responses stream.
pub(crate) struct Stream {
    items: BTreeMap<u64, Item>,
    blocks: BTreeMap<Key, StreamBlock>,
    budget: usize,
}

fn num(v: Option<Value<'_, '_>>) -> Option<u64> {
    let v = v?;
    let n: u64 = std::str::from_utf8(v.raw()).ok()?.parse().ok()?;
    (n < 1 << 20).then_some(n)
}

impl Stream {
    pub(crate) fn new(limits: StreamLimits) -> Self {
        Self {
            items: BTreeMap::new(),
            blocks: BTreeMap::new(),
            budget: limits.max_buffered_tool_input,
        }
    }

    fn flush(&mut self, ctx: &Ctx<'_>, key: Key, out: &mut Vec<u8>) {
        let Some(mut b) = self.blocks.remove(&key) else {
            return;
        };
        let text = flush_block(ctx, &mut b);
        if text.is_empty() {
            return;
        }
        if let Some(ev) = b
            .template
            .as_deref()
            .and_then(|t| synth_from_template(t, &["delta"], &text))
        {
            out.extend_from_slice(&ev);
        }
    }

    fn flush_where(&mut self, ctx: &Ctx<'_>, out: &mut Vec<u8>, pred: impl Fn(Key) -> bool) {
        let keys: Vec<Key> = self.blocks.keys().copied().filter(|k| pred(*k)).collect();
        for k in keys {
            self.flush(ctx, k, out);
        }
    }

    fn block_for(&mut self, ctx: &Ctx<'_>, key: Key) -> &mut StreamBlock {
        let item = match key {
            Key::Args(o) => self.items.get(&o).cloned().unwrap_or(Item::Other),
            Key::Part(..) => Item::Other,
        };
        self.blocks.entry(key).or_insert_with(|| match (key, item) {
            (Key::Part(..), _) => StreamBlock::text(),
            (Key::Args(_), Item::Function(n)) => StreamBlock::tool(ctx, &n, TextKind::JsonText),
            (Key::Args(_), Item::Custom(n)) => StreamBlock::tool(ctx, &n, TextKind::Plain),
            // Arguments for an item we never saw announced: the policy cannot name the tool.
            (Key::Args(_), Item::Other) => StreamBlock::tool(ctx, "", TextKind::JsonText),
        })
    }

    fn is_buffered(ctx: &Ctx<'_>, tool: &str) -> bool {
        ctx.snap.policy.tool_mode(tool) == ToolMode::Buffered
    }

    fn delta(
        &mut self,
        ctx: &Ctx<'_>,
        key: Key,
        raw: &[u8],
        data: &str,
        root: Value<'_, '_>,
        out: &mut Vec<u8>,
    ) {
        let Ok(Some(v)) = root.get("delta") else {
            return out.extend_from_slice(raw);
        };
        let Some(s) = v.as_str() else {
            return out.extend_from_slice(raw);
        };
        let mut budget = self.budget;
        let block = self.block_for(ctx, key);
        let res = feed_delta(ctx, block, &s, &mut budget);
        match res {
            DeltaOut::Unchanged => out.extend_from_slice(raw),
            DeltaOut::Drop => block.template = Some(raw.to_vec()),
            DeltaOut::Replace(text) => {
                let new = json::splice(
                    data.as_bytes(),
                    &[(v.span().0, v.span().1, json::quote(&text))],
                );
                out.extend_from_slice(&sse::with_data(raw, &new));
                block.template = Some(raw.to_vec());
            }
        }
        self.budget = budget;
    }

    /// Restores a complete field of a `*.done` event after flushing its block.
    #[allow(clippy::too_many_arguments)]
    fn done(
        &mut self,
        ctx: &Ctx<'_>,
        key: Key,
        field: &str,
        raw: &[u8],
        data: &str,
        root: Value<'_, '_>,
        out: &mut Vec<u8>,
    ) {
        self.flush(ctx, key, out);
        let (tool, kind) = match (key, self.items.get(&key.output())) {
            (Key::Args(_), Some(Item::Function(n))) => (Some(n.clone()), TextKind::JsonText),
            (Key::Args(_), Some(Item::Custom(n))) => (Some(n.clone()), TextKind::Plain),
            (Key::Args(_), _) => (Some(String::new()), TextKind::JsonText),
            (Key::Part(..), _) => (None, TextKind::Plain),
        };
        let mut edits = Edits::default();
        if let Ok(Some(v)) = root.get(field) {
            let full = v.as_str().unwrap_or_default();
            let buffered = tool.as_deref().is_some_and(|t| Self::is_buffered(ctx, t));
            let site = block_site(tool.as_deref(), buffered, &full);
            restore_string(ctx, &site, kind, v, &mut edits);
        }
        emit(raw, data, edits, out);
    }
}

fn emit(raw: &[u8], data: &str, edits: Edits, out: &mut Vec<u8>) {
    match edits.apply(data.as_bytes()) {
        Some(new) => out.extend_from_slice(&sse::with_data(raw, &new)),
        None => out.extend_from_slice(raw),
    }
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
        let ty = root
            .get_str("type")
            .ok()
            .flatten()
            .map(std::borrow::Cow::into_owned);
        let o = num(root.get("output_index").ok().flatten());
        let c = num(root.get("content_index").ok().flatten()).unwrap_or(0);
        let data = &ev.data;
        match (ty.as_deref(), o) {
            // A new response. Over HTTP it opens the stream; on a WebSocket in Responses mode
            // it follows the previous response, which may have ended with an `error` event and
            // no `response.completed`: whatever that one still holds is released before it, and
            // its output indexes are forgotten.
            (Some("response.created"), _) => {
                self.flush_where(ctx, out, |_| true);
                self.items.clear();
                out.extend_from_slice(raw);
            }
            (Some("response.output_item.added"), Some(o)) => {
                if let Ok(Some(item)) = root.get("item") {
                    let name = || {
                        item.get_str("name")
                            .ok()
                            .flatten()
                            .unwrap_or_default()
                            .into_owned()
                    };
                    let info = match item.get_str("type").ok().flatten().as_deref() {
                        Some("function_call") => Item::Function(name()),
                        Some("custom_tool_call") => Item::Custom(name()),
                        _ => Item::Other,
                    };
                    self.items.insert(o, info);
                }
                out.extend_from_slice(raw);
            }
            (Some("response.output_text.delta" | "response.refusal.delta"), Some(o)) => {
                self.delta(ctx, Key::Part(o, c), raw, data, root, out);
            }
            (
                Some(
                    "response.function_call_arguments.delta"
                    | "response.custom_tool_call_input.delta",
                ),
                Some(o),
            ) => {
                self.delta(ctx, Key::Args(o), raw, data, root, out);
            }
            (Some("response.output_text.done"), Some(o)) => {
                self.done(ctx, Key::Part(o, c), "text", raw, data, root, out);
            }
            (Some("response.refusal.done"), Some(o)) => {
                self.done(ctx, Key::Part(o, c), "refusal", raw, data, root, out);
            }
            (Some("response.function_call_arguments.done"), Some(o)) => {
                self.done(ctx, Key::Args(o), "arguments", raw, data, root, out);
            }
            (Some("response.custom_tool_call_input.done"), Some(o)) => {
                self.done(ctx, Key::Args(o), "input", raw, data, root, out);
            }
            (Some("response.content_part.done"), Some(o)) => {
                self.flush(ctx, Key::Part(o, c), out);
                let mut edits = Edits::default();
                if let Ok(Some(part)) = root.get("part") {
                    restore_part(ctx, part, &mut edits);
                }
                emit(raw, data, edits, out);
            }
            (Some("response.output_item.done"), Some(o)) => {
                self.flush_where(ctx, out, |k| k.output() == o);
                let mut edits = Edits::default();
                if let Ok(Some(item)) = root.get("item") {
                    restore_item(ctx, item, &mut edits, &|t| Self::is_buffered(ctx, t));
                }
                emit(raw, data, edits, out);
            }
            (Some("response.completed" | "response.incomplete" | "response.failed"), _) => {
                self.flush_where(ctx, out, |_| true);
                let mut edits = Edits::default();
                if let Ok(Some(resp)) = root.get("response") {
                    restore_response(ctx, resp, &mut edits, &|t| Self::is_buffered(ctx, t));
                }
                emit(raw, data, edits, out);
            }
            _ => out.extend_from_slice(raw),
        }
    }

    fn finish(&mut self, ctx: &Ctx<'_>, out: &mut Vec<u8>) {
        self.flush_where(ctx, out, |_| true);
    }
}
