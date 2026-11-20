// SPDX-License-Identifier: AGPL-3.0-only

//! `OpenAI` Chat Completions API.
//!
//! Request: allowlisted top-level configuration stays byte-identical; `data:` URLs in
//! `image_url` parts, `input_audio.data` and `file.file_data` are unscannable binary. Everything
//! else is redacted.
//!
//! Response: `message.content` and `message.refusal` resolve under [`RestoreSite::Text`],
//! `tool_calls[].function.arguments` (JSON text inside a string) under
//! [`RestoreSite::ToolInput`]. Streams are `data:` chunks with `choices[].delta`, one holdback
//! per (choice, content) and (choice, tool call), flushed at `finish_reason`, at the usage chunk
//! and at `[DONE]`.

use std::collections::BTreeMap;

use super::{
    DeltaOut, Edits, Plan, PlanError, StreamBlock, StreamCodec, StreamLimits, data_url_media_type,
    feed_delta, flush_block, keep_allowlisted, restore_string,
};
use crate::engine::RestoreSite;
use crate::json::{self, Doc, Kind, Value};
use crate::restore::{Ctx, TextKind};
use crate::sse;

/// Top-level request members that are configuration, not content.
pub(crate) const ALLOWLIST: &[&str] = &[
    "model",
    "stream",
    "stream_options",
    "temperature",
    "top_p",
    "n",
    "max_tokens",
    "max_completion_tokens",
    "presence_penalty",
    "frequency_penalty",
    "logprobs",
    "top_logprobs",
    "seed",
    "tool_choice",
    "parallel_tool_calls",
    "reasoning_effort",
    "service_tier",
    "store",
    "modalities",
    "verbosity",
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
                plan_parts(&mut plan, content)?;
            }
        }
    }
    Ok(plan)
}

pub(crate) fn plan_parts(plan: &mut Plan, content: Value<'_, '_>) -> Result<(), PlanError> {
    if content.kind() != Kind::Array {
        return Ok(());
    }
    for part in content.children() {
        match part.get_str("type")?.as_deref() {
            Some("image_url") => {
                if let Some(iu) = part.get("image_url")? {
                    let url = if iu.kind() == Kind::String {
                        Some(iu)
                    } else {
                        iu.get("url")?
                    };
                    if let Some(u) = url
                        && let Some(mt) = u.as_str().as_deref().and_then(data_url_media_type)
                    {
                        plan.binary(u, mt);
                    }
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
            Some("file") => {
                if let Some(f) = part.get("file")?
                    && let Some(d) = f.get("file_data")?
                {
                    let mt = d
                        .as_str()
                        .as_deref()
                        .and_then(data_url_media_type)
                        .unwrap_or("application/octet-stream")
                        .to_string();
                    plan.binary(d, &mt);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Restores a non-streaming chat completion.
pub(crate) fn restore_completion(ctx: &Ctx<'_>, root: Value<'_, '_>, edits: &mut Edits) {
    let Ok(Some(choices)) = root.get("choices") else {
        return;
    };
    for c in choices.children() {
        let Ok(Some(msg)) = c.get("message") else {
            continue;
        };
        for f in ["content", "refusal"] {
            if let Ok(Some(v)) = msg.get(f) {
                restore_string(ctx, &RestoreSite::Text, TextKind::Plain, v, edits);
            }
        }
        let Ok(Some(calls)) = msg.get("tool_calls") else {
            continue;
        };
        for call in calls.children() {
            let Ok(Some(func)) = call.get("function") else {
                continue;
            };
            let name = func.get_str("name").ok().flatten().unwrap_or_default();
            if let Ok(Some(args)) = func.get("arguments") {
                let full = args.as_str().unwrap_or_default();
                let site = RestoreSite::ToolInput {
                    tool: &name,
                    arguments: Some(&full),
                };
                restore_string(ctx, &site, TextKind::JsonText, args, edits);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Content(u64),
    Refusal(u64),
    Tool(u64, u64),
}

impl Key {
    fn choice(self) -> u64 {
        match self {
            Key::Content(c) | Key::Refusal(c) | Key::Tool(c, _) => c,
        }
    }
}

/// Streaming state for one chat completion.
pub(crate) struct Stream {
    blocks: BTreeMap<Key, StreamBlock>,
    budget: usize,
    /// Last chunk's envelope (id, object, created, model, ...), for synthesised chunks.
    envelope: Option<serde_json::Map<String, serde_json::Value>>,
}

fn num(v: Option<Value<'_, '_>>) -> Option<u64> {
    let v = v?;
    let n: u64 = std::str::from_utf8(v.raw()).ok()?.parse().ok()?;
    (n < 1 << 16).then_some(n)
}

impl Stream {
    pub(crate) fn new(limits: StreamLimits) -> Self {
        Self {
            blocks: BTreeMap::new(),
            budget: limits.max_buffered_tool_input,
            envelope: None,
        }
    }

    fn synth(&self, key: Key, text: &str) -> Vec<u8> {
        let mut obj = self.envelope.clone().unwrap_or_default();
        let delta = match key {
            Key::Content(_) => serde_json::json!({ "content": text }),
            Key::Refusal(_) => serde_json::json!({ "refusal": text }),
            Key::Tool(_, t) => {
                serde_json::json!({ "tool_calls": [{ "index": t, "function": { "arguments": text } }] })
            }
        };
        obj.insert(
            "choices".into(),
            serde_json::json!([{ "index": key.choice(), "delta": delta, "finish_reason": serde_json::Value::Null }]),
        );
        let data = serde_json::to_vec(&serde_json::Value::Object(obj)).unwrap_or_default();
        sse::build(None, &data)
    }

    fn flush_where(&mut self, ctx: &Ctx<'_>, out: &mut Vec<u8>, pred: impl Fn(Key) -> bool) {
        let keys: Vec<Key> = self.blocks.keys().copied().filter(|k| pred(*k)).collect();
        for k in keys {
            if let Some(mut b) = self.blocks.remove(&k) {
                let text = flush_block(ctx, &mut b);
                if !text.is_empty() {
                    let ev = self.synth(k, &text);
                    out.extend_from_slice(&ev);
                }
            }
        }
    }

    fn remember_envelope(&mut self, root: Value<'_, '_>) {
        let mut env = serde_json::Map::new();
        for (k, v) in root.members() {
            if matches!(
                k.as_ref(),
                "id" | "object" | "created" | "model" | "system_fingerprint" | "service_tier"
            ) && let Ok(val) = serde_json::from_slice(v.raw())
            {
                env.insert(k.into_owned(), val);
            }
        }
        self.envelope = Some(env);
    }

    fn chunk(
        &mut self,
        ctx: &Ctx<'_>,
        raw: &[u8],
        data: &str,
        root: Value<'_, '_>,
        out: &mut Vec<u8>,
    ) {
        self.remember_envelope(root);
        let Ok(Some(choices)) = root.get("choices") else {
            return out.extend_from_slice(raw);
        };
        if choices.kind() == Kind::Array && choices.children().next().is_none() {
            // Usage-only chunk at the end.
            self.flush_where(ctx, out, |_| true);
            return out.extend_from_slice(raw);
        }
        let mut fields: Vec<Field> = Vec::new();
        let mut finishing = Vec::new();
        for c in choices.children() {
            let Some(ci) = num(c.get("index").ok().flatten()) else {
                continue;
            };
            if let Ok(Some(fr)) = c.get("finish_reason")
                && fr.kind() != Kind::Null
            {
                finishing.push(ci);
            }
            let Ok(Some(delta)) = c.get("delta") else {
                continue;
            };
            for (name, key) in [("content", Key::Content(ci)), ("refusal", Key::Refusal(ci))] {
                if let Ok(Some(v)) = delta.get(name)
                    && v.kind() == Kind::String
                {
                    let b = self.blocks.entry(key).or_insert_with(StreamBlock::text);
                    fields.push(feed(ctx, key, b, v, &mut self.budget));
                }
            }
            let Ok(Some(calls)) = delta.get("tool_calls") else {
                continue;
            };
            for call in calls.children() {
                let Some(ti) = num(call.get("index").ok().flatten()) else {
                    continue;
                };
                let Ok(Some(func)) = call.get("function") else {
                    continue;
                };
                let key = Key::Tool(ci, ti);
                let b = self.blocks.entry(key).or_insert_with(|| {
                    let name = func.get_str("name").ok().flatten().unwrap_or_default();
                    StreamBlock::tool(ctx, &name, TextKind::JsonText)
                });
                if let Ok(Some(args)) = func.get("arguments")
                    && args.kind() == Kind::String
                {
                    fields.push(feed(ctx, key, b, args, &mut self.budget));
                }
            }
        }
        // A finishing choice releases what its blocks still hold: into the same field of this
        // chunk when it has one, otherwise as a chunk of its own just before this one, so no
        // text ever follows finish_reason.
        let keys: Vec<Key> = self
            .blocks
            .keys()
            .copied()
            .filter(|k| finishing.contains(&k.choice()))
            .collect();
        for key in keys {
            let Some(mut b) = self.blocks.remove(&key) else {
                continue;
            };
            let rest = flush_block(ctx, &mut b);
            if rest.is_empty() {
                continue;
            }
            if let Some(f) = fields.iter_mut().rev().find(|f| f.key == key) {
                f.text.push_str(&rest);
                f.changed = true;
            } else {
                let ev = self.synth(key, &rest);
                out.extend_from_slice(&ev);
            }
        }
        let mut edits = Edits::default();
        for f in fields.into_iter().filter(|f| f.changed) {
            edits.push(f.span, json::quote(&f.text));
        }
        match edits.apply(data.as_bytes()) {
            Some(new) => out.extend_from_slice(&sse::with_data(raw, &new)),
            None => out.extend_from_slice(raw),
        }
    }
}

/// One delta string in a chunk and what it becomes.
struct Field {
    key: Key,
    span: (usize, usize),
    text: String,
    changed: bool,
}

fn feed(
    ctx: &Ctx<'_>,
    key: Key,
    b: &mut StreamBlock,
    v: Value<'_, '_>,
    budget: &mut usize,
) -> Field {
    let s = v.as_str().unwrap_or_default();
    let (text, changed) = match feed_delta(ctx, b, &s, budget) {
        DeltaOut::Unchanged => (s.into_owned(), false),
        DeltaOut::Drop => (String::new(), true),
        DeltaOut::Replace(t) => (t, true),
    };
    Field {
        key,
        span: v.span(),
        text,
        changed,
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
        if ev.data.trim() == "[DONE]" {
            self.flush_where(ctx, out, |_| true);
            return out.extend_from_slice(raw);
        }
        let Ok(doc) = Doc::parse(ev.data.as_bytes()) else {
            return out.extend_from_slice(raw);
        };
        self.chunk(ctx, raw, &ev.data, doc.root(), out);
    }

    fn finish(&mut self, ctx: &Ctx<'_>, out: &mut Vec<u8>) {
        self.flush_where(ctx, out, |_| true);
    }
}
