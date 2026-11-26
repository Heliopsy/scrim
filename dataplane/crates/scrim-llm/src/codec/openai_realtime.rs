// SPDX-License-Identifier: AGPL-3.0-only

//! `OpenAI` Realtime API (`/v1/realtime`, WebSocket). Each message is one JSON event.
//!
//! Client events: the event `type` stays byte-identical, and base64 audio
//! (`input_audio_buffer.append.audio`, the `audio` of `input_audio` content parts) and `data:`
//! URLs in `input_image` parts are unscannable binary. Everything else, instructions, tool
//! definitions, conversation items and every field this codec does not know, is redacted.
//!
//! Server events (GA names, and the beta names where they differ): assistant text
//! (`response.output_text.*`, beta `response.text.*`), transcripts of the model's audio
//! (`response.output_audio_transcript.*`, beta `response.audio_transcript.*`) and transcripts of
//! the user's audio (`conversation.item.input_audio_transcription.delta`, `.completed` and the
//! diarized `.segment`) resolve under [`RestoreSite::Text`], function call arguments under
//! [`RestoreSite::ToolInput`]. Deltas are keyed by item and content index, so responses that
//! interleave (out-of-band responses) keep separate holdbacks. The matching `*.done` events,
//! `response.content_part.done`, `response.output_item.done`, `conversation.item.done` and
//! `.retrieved` (assistant and function call items, and the `transcript` of a user item's
//! `input_audio` parts) and the final `response.done` get the same decisions. Audio itself, MCP
//! calls (run by the provider, not the agent) and the rest of the echo of the client's own items
//! are passed through. A transcription session (`"type": "transcription"`) sends the same
//! transcription events. The same codec serves the protocols built on Realtime: Azure `OpenAI`
//! Realtime and Azure Voice Live (which keeps the beta names), and xAI's Voice Agent API, whose
//! cumulative `conversation.item.input_audio_transcription.updated` and
//! `conversation.item.truncated` transcripts are restored whole.

use std::collections::{BTreeMap, HashMap};

use super::{
    DeltaOut, Edits, Plan, PlanError, StreamBlock, StreamCodec, StreamLimits, block_site,
    data_url_media_type, feed_delta, flush_block, keep_allowlisted, restore_string,
    synth_from_template,
};
use crate::engine::{RestoreSite, ToolMode};
use crate::json::{self, Doc, Kind, Value};
use crate::restore::{Ctx, TextKind};
use crate::sse;

/// Client event members that are protocol, not content.
const ALLOWLIST: &[&str] = &["type"];

/// The media type reported for base64 audio: the event does not say which format the session
/// uses.
const AUDIO: &str = "audio/unknown";

/// Plans one client event.
pub(crate) fn plan(doc: &Doc<'_>) -> Result<Plan, PlanError> {
    let mut plan = Plan::default();
    let root = doc.root();
    keep_allowlisted(&mut plan, root, ALLOWLIST)?;
    match root.get_str("type")?.as_deref() {
        Some("input_audio_buffer.append") => {
            if let Some(a) = root.get("audio")? {
                plan.binary(a, AUDIO);
            }
        }
        Some("conversation.item.create") => {
            if let Some(item) = root.get("item")? {
                plan_item(&mut plan, item)?;
            }
        }
        Some("response.create") => {
            if let Some(r) = root.get("response")?
                && let Some(input) = r.get("input")?
                && input.kind() == Kind::Array
            {
                for item in input.children() {
                    plan_item(&mut plan, item)?;
                }
            }
        }
        _ => {}
    }
    Ok(plan)
}

fn plan_item(plan: &mut Plan, item: Value<'_, '_>) -> Result<(), PlanError> {
    if item.kind() != Kind::Object {
        return Ok(());
    }
    let Some(content) = item.get("content")? else {
        return Ok(());
    };
    if content.kind() != Kind::Array {
        return Ok(());
    }
    for part in content.children() {
        if part.kind() != Kind::Object {
            continue;
        }
        match part.get_str("type")?.as_deref() {
            Some("input_audio") => {
                if let Some(a) = part.get("audio")? {
                    plan.binary(a, AUDIO);
                }
            }
            Some("input_image") => {
                if let Some(u) = part.get("image_url")?
                    && let Some(mt) = u.as_str().as_deref().and_then(data_url_media_type)
                {
                    plan.binary(u, mt);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Part(String, u64),
    Args(String),
    /// The transcript of the user's audio in an input item.
    Input(String, u64),
}

impl Key {
    fn item(&self) -> &str {
        match self {
            Key::Part(i, _) | Key::Args(i) | Key::Input(i, _) => i,
        }
    }
}

/// Streaming state for one Realtime connection.
pub(crate) struct Stream {
    /// Function call names by item id.
    calls: HashMap<String, String>,
    blocks: BTreeMap<Key, StreamBlock>,
    budget: usize,
}

fn num(v: Option<Value<'_, '_>>) -> Option<u64> {
    let v = v?;
    let n: u64 = std::str::from_utf8(v.raw()).ok()?.parse().ok()?;
    (n < 1 << 20).then_some(n)
}

/// Bounds the call-name table: item ids come from the provider, one per call.
const MAX_CALLS: usize = 4096;

impl Stream {
    pub(crate) fn new(limits: StreamLimits) -> Self {
        Self {
            calls: HashMap::new(),
            blocks: BTreeMap::new(),
            budget: limits.max_buffered_tool_input,
        }
    }

    fn is_buffered(ctx: &Ctx<'_>, tool: &str) -> bool {
        ctx.snap.policy.tool_mode(tool) == ToolMode::Buffered
    }

    fn remember(&mut self, item: Value<'_, '_>) {
        if item.get_str("type").ok().flatten().as_deref() != Some("function_call") {
            return;
        }
        let (Some(id), Some(name)) = (
            item.get_str("id").ok().flatten(),
            item.get_str("name").ok().flatten(),
        ) else {
            return;
        };
        if self.calls.len() >= MAX_CALLS {
            self.calls.clear();
        }
        self.calls.insert(id.into_owned(), name.into_owned());
    }

    fn flush(&mut self, ctx: &Ctx<'_>, key: &Key, out: &mut Vec<u8>) {
        let Some(mut b) = self.blocks.remove(key) else {
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

    fn flush_where(&mut self, ctx: &Ctx<'_>, out: &mut Vec<u8>, pred: impl Fn(&Key) -> bool) {
        let keys: Vec<Key> = self.blocks.keys().filter(|k| pred(k)).cloned().collect();
        for k in keys {
            self.flush(ctx, &k, out);
        }
    }

    fn block_for(&mut self, ctx: &Ctx<'_>, key: &Key) -> &mut StreamBlock {
        let tool = match key {
            Key::Args(i) => Some(self.calls.get(i).cloned().unwrap_or_default()),
            Key::Part(..) | Key::Input(..) => None,
        };
        self.blocks
            .entry(key.clone())
            .or_insert_with(|| match tool {
                None => StreamBlock::text(),
                // An unknown item names no tool; the policy decides for "".
                Some(n) => StreamBlock::tool(ctx, &n, TextKind::JsonText),
            })
    }

    fn delta(
        &mut self,
        ctx: &Ctx<'_>,
        key: &Key,
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
        match feed_delta(ctx, block, &s, &mut budget) {
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

    /// Restores the complete `field` of a `*.done` event after flushing its block.
    #[allow(clippy::too_many_arguments)]
    fn done(
        &mut self,
        ctx: &Ctx<'_>,
        key: &Key,
        field: &str,
        raw: &[u8],
        data: &str,
        root: Value<'_, '_>,
        out: &mut Vec<u8>,
    ) {
        self.flush(ctx, key, out);
        let (tool, kind) = match key {
            Key::Args(i) => {
                let name = self
                    .calls
                    .get(i)
                    .cloned()
                    .or_else(|| {
                        root.get_str("name")
                            .ok()
                            .flatten()
                            .map(std::borrow::Cow::into_owned)
                    })
                    .unwrap_or_default();
                (Some(name), TextKind::JsonText)
            }
            Key::Part(..) | Key::Input(..) => (None, TextKind::Plain),
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

    /// A complete item (`response.output_item.done`, `conversation.item.done`, `...retrieved`)
    /// or the whole response (`response.done`): flushes the item's blocks and restores it with
    /// the decisions its deltas got.
    fn complete(
        &mut self,
        ctx: &Ctx<'_>,
        ty: &str,
        raw: &[u8],
        data: &str,
        root: Value<'_, '_>,
        out: &mut Vec<u8>,
    ) {
        let full_args = |t: &str| Self::is_buffered(ctx, t);
        let mut edits = Edits::default();
        let one = |s: &mut Self, item: Value<'_, '_>, edits: &mut Edits, out: &mut Vec<u8>| {
            s.remember(item);
            if let Some(id) = item.get_str("id").ok().flatten() {
                s.flush_where(ctx, out, |k| k.item() == id);
            }
            restore_item(ctx, item, edits, &full_args);
        };
        if ty == "response.done" {
            if let Ok(Some(resp)) = root.get("response")
                && let Ok(Some(output)) = resp.get("output")
            {
                for item in output.children() {
                    one(self, item, &mut edits, out);
                }
            }
        } else if let Ok(Some(item)) = root.get("item") {
            one(self, item, &mut edits, out);
        }
        emit(raw, data, edits, out);
    }
}

/// The text field of an assistant content part: `text` for text parts, `transcript` for audio.
fn part_field(part: Value<'_, '_>) -> Option<&'static str> {
    match part.get_str("type").ok().flatten().as_deref() {
        Some("output_text" | "text") => Some("text"),
        Some("output_audio" | "audio") => Some("transcript"),
        _ => None,
    }
}

fn restore_part(ctx: &Ctx<'_>, part: Value<'_, '_>, edits: &mut Edits) {
    let Some(field) = part_field(part) else {
        return;
    };
    if let Ok(Some(v)) = part.get(field) {
        restore_string(ctx, &RestoreSite::Text, TextKind::Plain, v, edits);
    }
}

/// The transcript of the user's audio in a user item's `input_audio` part, written by the
/// provider's transcription model.
fn restore_input_transcripts(ctx: &Ctx<'_>, item: Value<'_, '_>, edits: &mut Edits) {
    let Ok(Some(content)) = item.get("content") else {
        return;
    };
    for part in content.children() {
        if part.get_str("type").ok().flatten().as_deref() == Some("input_audio")
            && let Ok(Some(v)) = part.get("transcript")
        {
            restore_string(ctx, &RestoreSite::Text, TextKind::Plain, v, edits);
        }
    }
}

/// Restores an assistant message, a function call item, and the transcripts of the user's
/// audio. The rest of the client's own items (user and system messages, function call output)
/// is left as the provider echoed it.
fn restore_item(
    ctx: &Ctx<'_>,
    item: Value<'_, '_>,
    edits: &mut Edits,
    full_args: &dyn Fn(&str) -> bool,
) {
    match item.get_str("type").ok().flatten().as_deref() {
        Some("message") => {
            match item.get_str("role").ok().flatten().as_deref() {
                Some("assistant") => {}
                Some("user") => return restore_input_transcripts(ctx, item, edits),
                _ => return,
            }
            let Ok(Some(content)) = item.get("content") else {
                return;
            };
            for part in content.children() {
                restore_part(ctx, part, edits);
            }
        }
        Some("function_call") => {
            let name = item.get_str("name").ok().flatten().unwrap_or_default();
            if let Ok(Some(v)) = item.get("arguments") {
                let full = v.as_str().unwrap_or_default();
                let site = block_site(Some(&name), full_args(&name), &full);
                restore_string(ctx, &site, TextKind::JsonText, v, edits);
            }
        }
        _ => {}
    }
}

/// Restores an event carrying a complete text without deltas of its own: a diarized segment
/// (`text`), xAI's cumulative transcript so far and xAI's transcript of a truncated item
/// (`transcript`).
fn whole(ctx: &Ctx<'_>, ty: &str, raw: &[u8], data: &str, root: Value<'_, '_>, out: &mut Vec<u8>) {
    let field = if ty.ends_with(".segment") {
        "text"
    } else {
        "transcript"
    };
    let mut edits = Edits::default();
    if let Ok(Some(v)) = root.get(field) {
        restore_string(ctx, &RestoreSite::Text, TextKind::Plain, v, &mut edits);
    }
    emit(raw, data, edits, out);
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
        if root.kind() != Kind::Object {
            return out.extend_from_slice(raw);
        }
        let ty = root
            .get_str("type")
            .ok()
            .flatten()
            .map(std::borrow::Cow::into_owned);
        let item_id = root
            .get_str("item_id")
            .ok()
            .flatten()
            .map(std::borrow::Cow::into_owned);
        let c = num(root.get("content_index").ok().flatten()).unwrap_or(0);
        let data = &ev.data;
        match (ty.as_deref(), item_id) {
            (
                Some(
                    "response.output_item.added"
                    | "conversation.item.added"
                    | "conversation.item.created",
                ),
                _,
            ) => {
                if let Ok(Some(item)) = root.get("item") {
                    self.remember(item);
                }
                out.extend_from_slice(raw);
            }
            (
                Some(
                    "response.output_text.delta"
                    | "response.text.delta"
                    | "response.output_audio_transcript.delta"
                    | "response.audio_transcript.delta",
                ),
                Some(i),
            ) => self.delta(ctx, &Key::Part(i, c), raw, data, root, out),
            (Some("conversation.item.input_audio_transcription.delta"), Some(i)) => {
                self.delta(ctx, &Key::Input(i, c), raw, data, root, out);
            }
            (Some("conversation.item.input_audio_transcription.completed"), Some(i)) => {
                self.done(ctx, &Key::Input(i, c), "transcript", raw, data, root, out);
            }
            (
                Some(
                    t @ ("conversation.item.input_audio_transcription.segment"
                    | "conversation.item.input_audio_transcription.updated"
                    | "conversation.item.truncated"),
                ),
                Some(_),
            ) => whole(ctx, t, raw, data, root, out),
            (Some("response.function_call_arguments.delta"), Some(i)) => {
                self.delta(ctx, &Key::Args(i), raw, data, root, out);
            }
            (Some("response.output_text.done" | "response.text.done"), Some(i)) => {
                self.done(ctx, &Key::Part(i, c), "text", raw, data, root, out);
            }
            (
                Some("response.output_audio_transcript.done" | "response.audio_transcript.done"),
                Some(i),
            ) => {
                self.done(ctx, &Key::Part(i, c), "transcript", raw, data, root, out);
            }
            (Some("response.function_call_arguments.done"), Some(i)) => {
                self.done(ctx, &Key::Args(i), "arguments", raw, data, root, out);
            }
            (Some("response.content_part.done"), Some(i)) => {
                self.flush(ctx, &Key::Part(i, c), out);
                let mut edits = Edits::default();
                if let Ok(Some(part)) = root.get("part") {
                    restore_part(ctx, part, &mut edits);
                }
                emit(raw, data, edits, out);
            }
            (
                Some(
                    t @ ("response.output_item.done"
                    | "conversation.item.done"
                    | "conversation.item.retrieved"
                    | "response.done"),
                ),
                _,
            ) => self.complete(ctx, t, raw, data, root, out),
            _ => out.extend_from_slice(raw),
        }
    }

    fn finish(&mut self, ctx: &Ctx<'_>, out: &mut Vec<u8>) {
        self.flush_where(ctx, out, |_| true);
    }
}

#[cfg(all(test, feature = "test-util"))]
mod tests {
    use super::*;
    use crate::restore::RestoreStats;
    use crate::testing::Fixture;

    fn spans(body: &str) -> (Vec<String>, Vec<String>) {
        let doc = Doc::parse(body.as_bytes()).unwrap();
        let p = plan(&doc).unwrap().finish();
        (
            p.verbatim
                .iter()
                .map(|&(s, e)| body[s..e].to_string())
                .collect(),
            p.binary,
        )
    }

    #[test]
    fn plans_type_audio_and_images_only() {
        let (v, b) = spans(r#"{"type":"input_audio_buffer.append","audio":"AAAABBBB"}"#);
        assert_eq!(v, ["input_audio_buffer.append", "AAAABBBB"]);
        assert_eq!(b, [AUDIO]);
        let (v, b) = spans(
            r#"{"type":"conversation.item.create","event_id":"e1","item":{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"},{"type":"input_audio","audio":"UklGRg=="},{"type":"input_image","image_url":"data:image/png;base64,iVBO"}]}}"#,
        );
        assert_eq!(
            v,
            [
                "conversation.item.create",
                "UklGRg==",
                "data:image/png;base64,iVBO"
            ]
        );
        assert_eq!(b, [AUDIO, "image/png"]);
        let (v, _) = spans(
            r#"{"type":"response.create","response":{"instructions":"x","input":[{"type":"message","role":"user","content":[{"type":"input_audio","audio":"QUJD"}]}]}}"#,
        );
        assert_eq!(v, ["response.create", "QUJD"]);
        let (v, b) = spans(r#"{"type":"session.update","session":{"instructions":"be brief"}}"#);
        assert_eq!(v, ["session.update"]);
        assert_eq!(b, [] as [String; 0]);
        assert!(plan(&Doc::parse(b"[1]").unwrap()).is_err());
    }

    fn run(fx: &Fixture, events: &[String]) -> (Vec<String>, u64) {
        let snap = fx.snapshot();
        let stats = RestoreStats::default();
        let ctx = Ctx {
            snap: &snap,
            stats: &stats,
        };
        let mut s = Stream::new(StreamLimits {
            max_buffered_tool_input: 1 << 20,
        });
        let mut out = Vec::new();
        for e in events {
            s.event(&ctx, format!("data: {e}\n\n").as_bytes(), &mut out);
        }
        s.finish(&ctx, &mut out);
        let text = String::from_utf8(out).unwrap();
        let datas = text
            .split("\n\n")
            .filter(|e| !e.is_empty())
            .map(|e| e.strip_prefix("data: ").unwrap().to_string())
            .collect();
        (datas, stats.resolved.get())
    }

    fn deltas(datas: &[String], ty: &str) -> String {
        datas
            .iter()
            .map(|d| serde_json::from_str::<serde_json::Value>(d).unwrap())
            .filter(|v| v["type"] == ty)
            .map(|v| v["delta"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn restores_split_text_transcript_and_done_events() {
        let fx = Fixture::new(&[("a", "alpha-secret-value-01")]);
        let p = fx.placeholder("a");
        let v = fx.value("a");
        let (head, tail) = p.split_at(p.char_indices().nth(5).unwrap().0);
        let mut events = vec![
            r#"{"type":"response.output_item.added","item":{"id":"it1","type":"message","role":"assistant"}}"#.to_string(),
        ];
        for (ty, field) in [
            ("response.output_text", "text"),
            ("response.output_audio_transcript", "transcript"),
        ] {
            events.push(format!(
                r#"{{"type":"{ty}.delta","item_id":"it1","content_index":0,"delta":"pw {head}"}}"#
            ));
            events.push(format!(
                r#"{{"type":"{ty}.delta","item_id":"it1","content_index":0,"delta":"{tail} ok"}}"#
            ));
            events.push(format!(
                r#"{{"type":"{ty}.done","item_id":"it1","content_index":0,"{field}":"pw {p} ok"}}"#
            ));
        }
        events.push(format!(
            r#"{{"type":"response.done","response":{{"output":[{{"id":"it1","type":"message","role":"assistant","content":[{{"type":"output_text","text":"{p}"}},{{"type":"output_audio","transcript":"{p}"}}]}}]}}}}"#
        ));
        let (datas, resolved) = run(&fx, &events);
        assert_eq!(
            deltas(&datas, "response.output_text.delta"),
            format!("pw {v} ok")
        );
        assert_eq!(
            deltas(&datas, "response.output_audio_transcript.delta"),
            format!("pw {v} ok")
        );
        let all = datas.join("\n");
        assert!(!all.contains(&p), "{all}");
        assert_eq!(resolved, 6);
    }

    #[test]
    fn function_arguments_follow_the_tool_policy_and_user_items_are_left() {
        let fx = Fixture::new(&[("a", "alpha-secret-value-01")]);
        let p = fx.placeholder("a");
        let events = vec![
            r#"{"type":"response.output_item.added","item":{"id":"fc1","type":"function_call","name":"Bash","arguments":""}}"#.to_string(),
            format!(
                r#"{{"type":"response.function_call_arguments.delta","item_id":"fc1","delta":"{{\"cmd\":\"echo {p}\"}}"}}"#
            ),
            format!(
                r#"{{"type":"response.function_call_arguments.done","item_id":"fc1","arguments":"{{\"cmd\":\"echo {p}\"}}"}}"#
            ),
            format!(
                r#"{{"type":"conversation.item.done","item":{{"id":"u1","type":"message","role":"user","content":[{{"type":"input_text","text":"{p}"}}]}}}}"#
            ),
        ];
        let (datas, _) = run(&fx, &events);
        // The fixture policy resolves display values everywhere; the user's own item is never
        // restored.
        let user: serde_json::Value = serde_json::from_str(&datas[3]).unwrap();
        assert_eq!(user["item"]["content"][0]["text"], p);
        let args: serde_json::Value = serde_json::from_str(&datas[2]).unwrap();
        assert!(args["arguments"].as_str().unwrap().contains(&fx.value("a")));
    }

    #[test]
    fn transcripts_of_the_users_audio_are_restored() {
        let fx = Fixture::new(&[("a", "alpha-secret-value-01")]);
        let p = fx.placeholder("a");
        let v = fx.value("a");
        let (head, tail) = p.split_at(p.char_indices().nth(5).unwrap().0);
        let ty = "conversation.item.input_audio_transcription";
        let events = vec![
            format!(
                r#"{{"type":"{ty}.delta","item_id":"in1","content_index":0,"delta":"call {head}"}}"#
            ),
            format!(
                r#"{{"type":"{ty}.delta","item_id":"in1","content_index":0,"delta":"{tail} now"}}"#
            ),
            format!(
                r#"{{"type":"{ty}.completed","item_id":"in1","content_index":0,"transcript":"call {p} now"}}"#
            ),
            format!(
                r#"{{"type":"{ty}.segment","item_id":"in1","content_index":0,"id":"seg_1","speaker":"A","start":0.0,"end":1.2,"text":"call {p}"}}"#
            ),
            format!(
                r#"{{"type":"{ty}.updated","item_id":"in1","content_index":0,"transcript":"call {p}"}}"#
            ),
            format!(
                r#"{{"type":"conversation.item.done","item":{{"id":"in1","type":"message","role":"user","content":[{{"type":"input_audio","transcript":"call {p} now"}},{{"type":"input_text","text":"{p}"}}]}}}}"#
            ),
        ];
        let (datas, resolved) = run(&fx, &events);
        assert_eq!(
            deltas(&datas, &format!("{ty}.delta")),
            format!("call {v} now")
        );
        let completed: serde_json::Value = serde_json::from_str(&datas[2]).unwrap();
        assert_eq!(completed["transcript"], format!("call {v} now"));
        let segment: serde_json::Value = serde_json::from_str(&datas[3]).unwrap();
        assert_eq!(segment["text"], format!("call {v}"));
        let updated: serde_json::Value = serde_json::from_str(&datas[4]).unwrap();
        assert_eq!(updated["transcript"], format!("call {v}"));
        let item: serde_json::Value = serde_json::from_str(&datas[5]).unwrap();
        assert_eq!(
            item["item"]["content"][0]["transcript"],
            format!("call {v} now")
        );
        // The agent's own text in the same item stays as the provider echoed it.
        assert_eq!(item["item"]["content"][1]["text"], p);
        assert_eq!(resolved, 5);
    }

    #[test]
    fn unknown_and_audio_events_pass_byte_for_byte() {
        let fx = Fixture::new(&[("a", "alpha-secret-value-01")]);
        let events = vec![
            r#"{"type":"response.output_audio.delta","item_id":"it1","delta":"AAAA"}"#.to_string(),
            r#"{"type":"rate_limits.updated","rate_limits":[]}"#.to_string(),
            "not json".to_string(),
        ];
        let (datas, _) = run(&fx, &events);
        assert_eq!(datas, events);
    }
}
