// SPDX-License-Identifier: AGPL-3.0-only

//! Google Gemini `generateContent` API: `models/*:generateContent`, `:streamGenerateContent`
//! and `:countTokens` on the Gemini API (`generativelanguage.googleapis.com`). The same request
//! and response shapes serve Gemini models on Vertex AI
//! (`.../publishers/google/models/*:generateContent`), so a Vertex route reuses this codec with
//! [`is_gemini_method`] and only adds its own authentication.
//!
//! Request: the allowlisted top-level configuration (`model`, `toolConfig`, `safetySettings`,
//! `cachedContent`), the known scalar settings in `generationConfig`, the `text` of thought
//! parts and every `thoughtSignature` stay byte-identical; `inlineData.data` is unscannable
//! binary. Everything else, including `contents`, `systemInstruction`, `tools`, function calls
//! and responses, stop sequences and response schemas, is redacted. The API accepts both
//! `lowerCamelCase` and `snake_case` field names (proto JSON); a part or config that names one field
//! both ways is ambiguous and refused.
//!
//! Response: non-thought `text` parts resolve under [`RestoreSite::Text`], `functionCall.args`
//! (a JSON object) under [`RestoreSite::ToolInput`]. Thought parts, signatures, executable code,
//! grounding and citations are left alone. A stream is a sequence of complete
//! `GenerateContentResponse` chunks, as SSE (`alt=sse`) or as the elements of one JSON array
//! (the default); each candidate's text has one holdback, released before any other part of
//! that candidate, at `finishReason`, before the array closes and at the end of the stream.
//! Function calls arrive whole in one chunk and are restored in place.

use std::collections::BTreeMap;

use super::{
    DeltaOut, Edits, Plan, PlanError, StreamBlock, StreamCodec, StreamLimits, feed_delta,
    flush_block, keep_allowlisted, members_except, restore_json_source, restore_string,
};
use crate::engine::RestoreSite;
use crate::json::{self, Doc, Kind, Value};
use crate::remote::{Add, Edit, Target};
use crate::restore::{Ctx, TextKind};
use crate::sse;

/// Top-level request members that are configuration, not content.
pub(crate) const ALLOWLIST: &[&str] = &[
    "model",
    "toolConfig",
    "tool_config",
    "safetySettings",
    "safety_settings",
    "cachedContent",
    "cached_content",
];

/// Members of `generationConfig` that are plain settings. `stopSequences`, `responseSchema`,
/// `responseJsonSchema`, `speechConfig` and anything unknown are redacted.
pub(crate) const GENERATION_ALLOWLIST: &[&str] = &[
    "temperature",
    "topP",
    "top_p",
    "topK",
    "top_k",
    "candidateCount",
    "candidate_count",
    "maxOutputTokens",
    "max_output_tokens",
    "presencePenalty",
    "presence_penalty",
    "frequencyPenalty",
    "frequency_penalty",
    "seed",
    "responseMimeType",
    "response_mime_type",
    "responseLogprobs",
    "response_logprobs",
    "logprobs",
    "thinkingConfig",
    "thinking_config",
    "mediaResolution",
    "media_resolution",
    "responseModalities",
    "response_modalities",
    "enableEnhancedCivicAnswers",
    "enable_enhanced_civic_answers",
];

/// Method suffixes of the last path segment that speak this API.
const METHODS: &[&str] = &["generateContent", "streamGenerateContent", "countTokens"];

/// Whether `path` (after a route prefix, without the query) calls a Gemini `generateContent`,
/// `streamGenerateContent` or `countTokens` method: its last segment is `<resource>:<method>`,
/// with the colon literal or percent-encoded. Shared with Vertex AI routes.
pub fn is_gemini_method(path: &str) -> bool {
    let last = path
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or_default();
    let method = match last.rfind(':') {
        Some(i) => &last[i + 1..],
        None => match last.to_ascii_lowercase().rfind("%3a") {
            Some(i) => &last[i + 3..],
            None => return false,
        },
    };
    METHODS.contains(&method)
}

/// The member named `camel` or `snake`. Both present is ambiguous and refused.
pub(crate) fn member<'d, 'a>(
    v: Value<'d, 'a>,
    camel: &str,
    snake: &str,
) -> Result<Option<Value<'d, 'a>>, PlanError> {
    let a = v.get(camel)?;
    if camel == snake {
        return Ok(a);
    }
    match (a, v.get(snake)?) {
        (Some(_), Some(_)) => Err(PlanError::Shape(
            "a field is given both in camelCase and in snake_case",
        )),
        (a, b) => Ok(a.or(b)),
    }
}

/// Lenient lookup for responses: never fails, prefers lowerCamelCase.
pub(crate) fn field<'d, 'a>(v: Value<'d, 'a>, camel: &str, snake: &str) -> Option<Value<'d, 'a>> {
    v.get(camel)
        .ok()
        .flatten()
        .or_else(|| v.get(snake).ok().flatten())
}

pub(crate) fn plan(doc: &Doc<'_>) -> Result<Plan, PlanError> {
    let mut plan = Plan::default();
    plan_request(&mut plan, doc.root(), 0)?;
    Ok(plan)
}

fn plan_request(plan: &mut Plan, root: Value<'_, '_>, depth: usize) -> Result<(), PlanError> {
    keep_allowlisted(plan, root, ALLOWLIST)?;
    if let Some(gc) = member(root, "generationConfig", "generation_config")?
        && gc.kind() == Kind::Object
    {
        for (k, v) in gc.members() {
            if GENERATION_ALLOWLIST.contains(&k.as_ref()) {
                plan.keep(v);
            }
        }
    }
    if let Some(contents) = root.get("contents")? {
        if contents.kind() != Kind::Array {
            return Err(PlanError::Shape("contents is not an array"));
        }
        for c in contents.children() {
            plan_content(plan, c)?;
        }
    }
    if let Some(sys) = member(root, "systemInstruction", "system_instruction")? {
        plan_content(plan, sys)?;
    }
    // countTokens wraps a whole generateContent request.
    if depth == 0
        && let Some(inner) = member(root, "generateContentRequest", "generate_content_request")?
    {
        plan_request(plan, inner, depth + 1)?;
    }
    Ok(())
}

pub(crate) fn plan_content(plan: &mut Plan, content: Value<'_, '_>) -> Result<(), PlanError> {
    if content.kind() != Kind::Object {
        return Ok(());
    }
    let Some(parts) = content.get("parts")? else {
        return Ok(());
    };
    if parts.kind() != Kind::Array {
        return Err(PlanError::Shape("parts is not an array"));
    }
    for part in parts.children() {
        if part.kind() != Kind::Object {
            continue;
        }
        if let Some(sig) = member(part, "thoughtSignature", "thought_signature")? {
            plan.keep(sig);
        }
        let thought = part.get("thought")?.is_some_and(|t| t.raw() == b"true");
        if thought && let Some(t) = part.get("text")? {
            plan.keep(t);
        }
        if let Some(inline) = member(part, "inlineData", "inline_data")?
            && let Some(data) = inline.get("data")?
        {
            let mt = member(inline, "mimeType", "mime_type")?
                .and_then(|m| m.as_str())
                .unwrap_or_default();
            plan.binary(data, &mt);
        }
        // Refuse a part naming one field both ways even where nothing is kept, so scrim and
        // the provider never read different function calls or responses.
        member(part, "functionCall", "function_call")?;
        member(part, "functionResponse", "function_response")?;
        if let Some(fd) = member(part, "fileData", "file_data")? {
            plan_file_data(plan, part, fd)?;
        }
    }
    Ok(())
}

/// A `fileData` part: a Files API file, a Cloud Storage object, a `YouTube` video, or a URL
/// (Gemini fetches public `http(s)` URLs itself). URLs are inlined as an `inlineData` part.
fn plan_file_data(
    plan: &mut Plan,
    part: Value<'_, '_>,
    fd: Value<'_, '_>,
) -> Result<(), PlanError> {
    let Some(uri) = member(fd, "fileUri", "file_uri")?.and_then(|u| u.as_str()) else {
        return Ok(());
    };
    let declared = member(fd, "mimeType", "mime_type")?
        .and_then(|m| m.as_str())
        .map(std::borrow::Cow::into_owned);
    let lower = uri.to_ascii_lowercase();
    let host = lower.split_once("://").map_or("", |(_, r)| {
        r.split(['/', '?', '#']).next().unwrap_or_default()
    });
    let host = host.rsplit('@').next().unwrap_or_default();
    let target = if let Some(id) = crate::remote::files::gemini_file_id(&uri) {
        Target::FileId(id)
    } else if lower.starts_with("gs://") {
        Target::Unfetchable("Cloud Storage URI")
    } else if [
        "youtube.com",
        "www.youtube.com",
        "m.youtube.com",
        "youtu.be",
    ]
    .contains(&host)
    {
        Target::Unfetchable("YouTube URI")
    } else {
        Target::Url(uri.into_owned())
    };
    let edit = if matches!(target, Target::Url(_)) {
        Edit::Rebuild {
            span: part.span(),
            keep: members_except(part, &["fileData", "file_data"]),
            add: Add::GeminiInline {
                snake: part.get("file_data")?.is_some(),
                declared,
            },
        }
    } else {
        Edit::None
    };
    plan.reference(target, edit);
    Ok(())
}

/// Restores one `GenerateContentResponse`, or a JSON array of them (a buffered stream).
pub(crate) fn restore_response(ctx: &Ctx<'_>, root: Value<'_, '_>, edits: &mut Edits) {
    if root.kind() == Kind::Array {
        for r in root.children() {
            restore_response(ctx, r, edits);
        }
        return;
    }
    let Ok(Some(candidates)) = root.get("candidates") else {
        return;
    };
    for c in candidates.children() {
        let Some(parts) = field(c, "content", "content").and_then(|v| v.get("parts").ok()?) else {
            continue;
        };
        for p in parts.children() {
            if is_thought(p) {
                continue;
            }
            if let Ok(Some(t)) = p.get("text") {
                restore_string(ctx, &RestoreSite::Text, TextKind::Plain, t, edits);
            }
            if let Some(call) = field(p, "functionCall", "function_call") {
                restore_call(ctx, call, edits);
            }
        }
    }
}

pub(crate) fn is_thought(p: Value<'_, '_>) -> bool {
    p.get("thought")
        .ok()
        .flatten()
        .is_some_and(|t| t.raw() == b"true")
}

pub(crate) fn restore_call(ctx: &Ctx<'_>, call: Value<'_, '_>, edits: &mut Edits) {
    let name = call.get_str("name").ok().flatten().unwrap_or_default();
    let Ok(Some(args)) = call.get("args") else {
        return;
    };
    let full = std::str::from_utf8(args.raw()).unwrap_or_default();
    let site = RestoreSite::ToolInput {
        tool: &name,
        arguments: Some(full),
    };
    restore_json_source(ctx, &site, args, edits);
}

/// A text part of a chunk and what it becomes.
struct Field {
    candidate: u64,
    span: (usize, usize),
    text: String,
    changed: bool,
}

/// What one chunk turns into.
pub(crate) struct ChunkOut {
    /// Chunks (JSON) to send before this one: text a candidate still held when the chunk
    /// carried nothing of that candidate's text to attach it to.
    pub before: Vec<Vec<u8>>,
    /// The rebuilt chunk, `None` when it passes unchanged.
    pub chunk: Option<Vec<u8>>,
}

/// Streaming state for one `streamGenerateContent` response, independent of its framing.
pub(crate) struct Chunks {
    /// Text holdback per candidate index.
    texts: BTreeMap<u64, StreamBlock>,
    budget: usize,
    /// The last chunk's envelope (`responseId`, `modelVersion`, `createTime`), for synthesised
    /// chunks.
    envelope: serde_json::Map<String, serde_json::Value>,
}

fn candidate_index(c: Value<'_, '_>, pos: usize) -> Option<u64> {
    match c.get("index").ok().flatten() {
        Some(v) => {
            let n: u64 = std::str::from_utf8(v.raw()).ok()?.parse().ok()?;
            (n < 1 << 16).then_some(n)
        }
        // The API leaves out a zero index.
        None => u64::try_from(pos).ok(),
    }
}

impl Chunks {
    pub(crate) fn new(limits: StreamLimits) -> Self {
        Self {
            texts: BTreeMap::new(),
            budget: limits.max_buffered_tool_input,
            envelope: serde_json::Map::new(),
        }
    }

    /// A chunk carrying `text` as candidate `candidate`'s next text.
    fn synth(&self, candidate: u64, text: &str) -> Vec<u8> {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "candidates".into(),
            serde_json::json!([{
                "content": { "parts": [{ "text": text }], "role": "model" },
                "index": candidate,
            }]),
        );
        for (k, v) in &self.envelope {
            obj.insert(k.clone(), v.clone());
        }
        serde_json::to_vec(&serde_json::Value::Object(obj)).unwrap_or_default()
    }

    fn remember_envelope(&mut self, root: Value<'_, '_>) {
        for (k, v) in root.members() {
            if matches!(
                k.as_ref(),
                "responseId" | "response_id" | "modelVersion" | "model_version" | "createTime"
            ) && let Ok(val) = serde_json::from_slice(v.raw())
            {
                self.envelope.insert(k.into_owned(), val);
            }
        }
    }

    /// Releases what candidate `ci` still holds: into its last text field of this chunk when
    /// `attach`, otherwise as a chunk of its own sent first.
    fn release(
        &mut self,
        ctx: &Ctx<'_>,
        ci: u64,
        attach: bool,
        fields: &mut [Field],
        before: &mut Vec<Vec<u8>>,
    ) {
        let Some(mut b) = self.texts.remove(&ci) else {
            return;
        };
        let rest = flush_block(ctx, &mut b);
        if rest.is_empty() {
            return;
        }
        match fields.iter_mut().rev().find(|f| f.candidate == ci) {
            Some(f) if attach => {
                f.text.push_str(&rest);
                f.changed = true;
            }
            _ => before.push(self.synth(ci, &rest)),
        }
    }

    /// Handles one complete chunk (`GenerateContentResponse` JSON).
    pub(crate) fn chunk(&mut self, ctx: &Ctx<'_>, data: &[u8]) -> ChunkOut {
        let unchanged = ChunkOut {
            before: Vec::new(),
            chunk: None,
        };
        let Ok(doc) = Doc::parse(data) else {
            return unchanged;
        };
        let root = doc.root();
        self.remember_envelope(root);
        let Ok(Some(candidates)) = root.get("candidates") else {
            return unchanged;
        };
        let mut fields: Vec<Field> = Vec::new();
        let mut before = Vec::new();
        let mut edits = Edits::default();
        for (pos, c) in candidates.children().enumerate() {
            let Some(ci) = candidate_index(c, pos) else {
                continue;
            };
            // Whether the candidate's last part in this chunk is a text part, so held text can
            // join it without moving past anything.
            let mut last_text = false;
            if let Some(parts) = field(c, "content", "content").and_then(|v| v.get("parts").ok()?) {
                for p in parts.children() {
                    if is_thought(p) {
                        continue;
                    }
                    if let Ok(Some(t)) = p.get("text")
                        && let Some(s) = t.as_str()
                    {
                        let b = self.texts.entry(ci).or_insert_with(StreamBlock::text);
                        let (text, changed) = match feed_delta(ctx, b, &s, &mut self.budget) {
                            DeltaOut::Unchanged => (s.into_owned(), false),
                            DeltaOut::Drop => (String::new(), true),
                            DeltaOut::Replace(t) => (t, true),
                        };
                        fields.push(Field {
                            candidate: ci,
                            span: t.span(),
                            text,
                            changed,
                        });
                        last_text = true;
                        continue;
                    }
                    // Any other part ends the text before it.
                    self.release(ctx, ci, last_text, &mut fields, &mut before);
                    last_text = false;
                    if let Some(call) = field(p, "functionCall", "function_call") {
                        restore_call(ctx, call, &mut edits);
                    }
                }
            }
            let finishing =
                field(c, "finishReason", "finish_reason").is_some_and(|f| f.kind() != Kind::Null);
            if finishing {
                self.release(ctx, ci, last_text, &mut fields, &mut before);
            }
        }
        for f in fields.into_iter().filter(|f| f.changed) {
            edits.push(f.span, json::quote(&f.text));
        }
        ChunkOut {
            before,
            chunk: edits.apply(data),
        }
    }

    /// Releases everything still held, as chunks.
    pub(crate) fn finish(&mut self, ctx: &Ctx<'_>) -> Vec<Vec<u8>> {
        let keys: Vec<u64> = self.texts.keys().copied().collect();
        let mut out = Vec::new();
        for k in keys {
            if let Some(mut b) = self.texts.remove(&k) {
                let text = flush_block(ctx, &mut b);
                if !text.is_empty() {
                    out.push(self.synth(k, &text));
                }
            }
        }
        out
    }
}

/// `streamGenerateContent?alt=sse`: one chunk per `data:` event.
pub(crate) struct SseStream(Chunks);

impl SseStream {
    pub(crate) fn new(limits: StreamLimits) -> Self {
        Self(Chunks::new(limits))
    }
}

impl StreamCodec for SseStream {
    fn event(&mut self, ctx: &Ctx<'_>, raw: &[u8], out: &mut Vec<u8>) {
        let Some(ev) = sse::Event::parse(raw) else {
            return out.extend_from_slice(raw);
        };
        if !ev.has_data {
            return out.extend_from_slice(raw);
        }
        let r = self.0.chunk(ctx, ev.data.as_bytes());
        for b in r.before {
            out.extend_from_slice(&sse::build(None, &b));
        }
        match r.chunk {
            Some(new) => out.extend_from_slice(&sse::with_data(raw, &new)),
            None => out.extend_from_slice(raw),
        }
    }

    fn finish(&mut self, ctx: &Ctx<'_>, out: &mut Vec<u8>) {
        for b in self.0.finish(ctx) {
            out.extend_from_slice(&sse::build(None, &b));
        }
    }
}

/// `streamGenerateContent` without `alt=sse`: one chunk per element of a JSON array.
pub(crate) struct ArrayStream {
    chunks: Chunks,
    /// Elements written so far, so a synthesised element knows whether it needs a comma.
    written: usize,
}

impl ArrayStream {
    pub(crate) fn new(limits: StreamLimits) -> Self {
        Self {
            chunks: Chunks::new(limits),
            written: 0,
        }
    }

    fn extra(&mut self, out: &mut Vec<u8>, chunks: Vec<Vec<u8>>) {
        for c in chunks {
            if self.written > 0 {
                out.extend_from_slice(b",\r\n");
            }
            out.extend_from_slice(&c);
            self.written += 1;
        }
    }
}

impl super::ArrayCodec for ArrayStream {
    fn element(&mut self, ctx: &Ctx<'_>, raw: &[u8], out: &mut Vec<u8>) {
        let r = self.chunks.chunk(ctx, raw);
        // The separator before this element has been written already: each extra element
        // goes before it, followed by its own separator.
        for c in r.before {
            out.extend_from_slice(&c);
            out.extend_from_slice(b",\r\n");
            self.written += 1;
        }
        match r.chunk {
            Some(new) => out.extend_from_slice(&new),
            None => out.extend_from_slice(raw),
        }
        self.written += 1;
    }

    fn close(&mut self, ctx: &Ctx<'_>, out: &mut Vec<u8>) {
        let held = self.chunks.finish(ctx);
        self.extra(out, held);
    }

    fn finish(&mut self, ctx: &Ctx<'_>, out: &mut Vec<u8>) {
        let held = self.chunks.finish(ctx);
        self.extra(out, held);
    }
}

#[cfg(all(test, feature = "test-util"))]
mod tests {
    use super::*;
    use crate::codec::{self, Api};
    use crate::restore::RestoreStats;
    use crate::testing::Fixture;

    fn planned(body: &str) -> Vec<String> {
        let p = codec::plan(Api::Gemini, body.as_bytes()).unwrap();
        p.verbatim
            .iter()
            .map(|(s, e)| body[*s..*e].to_string())
            .collect()
    }

    #[test]
    fn methods() {
        for p in [
            "/v1beta/models/gemini-2.5-pro:generateContent",
            "/v1beta/models/gemini-2.5-flash:streamGenerateContent",
            "/v1/models/gemini-2.5-pro:countTokens",
            "/v1beta/tunedModels/my-model:generateContent",
            "/v1/projects/p/locations/us-central1/publishers/google/models/gemini-2.5-pro:streamGenerateContent",
            "/v1beta/models/gemini-2.5-pro%3AgenerateContent",
            "/v1beta/models/gemini-2.5-pro%3agenerateContent/",
        ] {
            assert!(is_gemini_method(p), "{p}");
        }
        for p in [
            "/v1beta/models/gemini-2.5-pro",
            "/v1beta/models/text-embedding-004:embedContent",
            "/v1beta/models/gemini-2.5-pro:batchGenerateContent",
            "/v1beta/files",
            "/v1beta/models/generateContent",
            "",
        ] {
            assert!(!is_gemini_method(p), "{p}");
        }
    }

    #[test]
    fn plan_keeps_config_signatures_thoughts_and_binary() {
        let body = r#"{"contents":[{"role":"user","parts":[{"text":"hi"},{"inlineData":{"mimeType":"image/png","data":"iVBO"}}]},
            {"role":"model","parts":[{"text":"plan","thought":true},{"functionCall":{"name":"run","args":{"c":"x"}},"thoughtSignature":"c2ln"}]}],
            "systemInstruction":{"parts":[{"text":"sys"}]},
            "generationConfig":{"temperature":0.2,"stopSequences":["END"],"thinkingConfig":{"thinkingBudget":1024},"responseSchema":{"type":"STRING"}},
            "toolConfig":{"functionCallingConfig":{"mode":"AUTO"}},"model":"models/gemini-2.5-pro","labels":{"a":"b"}}"#;
        assert_eq!(
            planned(body),
            vec![
                "iVBO",
                "plan",
                "c2ln",
                "0.2",
                r#"{"thinkingBudget":1024}"#,
                r#"{"functionCallingConfig":{"mode":"AUTO"}}"#,
                "models/gemini-2.5-pro",
            ]
        );
        let p = codec::plan(Api::Gemini, body.as_bytes()).unwrap();
        assert_eq!(p.binary, vec!["image/png"]);
    }

    #[test]
    fn plan_snake_case_and_count_tokens() {
        let body = r#"{"generate_content_request":{"model":"models/m","contents":[{"parts":[{"inline_data":{"mime_type":"audio/wav","data":"UklG"}},{"text":"t","thought":true,"thought_signature":"c2"}]}],"generation_config":{"max_output_tokens":5}}}"#;
        assert_eq!(planned(body), vec!["models/m", "UklG", "t", "c2", "5"]);
    }

    #[test]
    fn plan_refuses_ambiguity_and_bad_shapes() {
        for body in [
            r#"{"contents":{}}"#,
            r#"{"contents":[{"parts":{}}]}"#,
            r#"{"contents":[{"parts":[{"inlineData":{"data":"a"},"inline_data":{"data":"b"}}]}]}"#,
            r#"{"contents":[{"parts":[{"text":"a","thought":true,"thought":false}]}]}"#,
            r#"{"contents":[{"parts":[{"functionCall":{},"function_call":{}}]}]}"#,
            r#"{"generationConfig":{},"generation_config":{}}"#,
            r#"{"systemInstruction":{},"system_instruction":{}}"#,
            r"[]",
            "not json",
        ] {
            assert!(codec::plan(Api::Gemini, body.as_bytes()).is_err(), "{body}");
        }
        assert!(codec::plan(Api::Gemini, b"{}").is_ok());
    }

    #[test]
    fn plan_does_not_keep_non_thought_text() {
        // `thought` must be the literal true; anything else is ordinary text.
        let body = r#"{"contents":[{"parts":[{"text":"a","thought":"true"},{"text":"b","thought":false}]}]}"#;
        assert_eq!(planned(body), [] as [String; 0]);
    }

    #[test]
    fn restores_text_and_function_call_not_thoughts() {
        let fx = Fixture::new(&[("api", "display-value-123")]);
        let snap = fx.snapshot();
        let stats = RestoreStats::default();
        let ctx = Ctx {
            snap: &snap,
            stats: &stats,
        };
        let ph = fx.placeholder("api");
        let body = format!(
            r#"{{"candidates":[{{"content":{{"role":"model","parts":[{{"text":"{ph}","thought":true}},{{"text":"v={ph}"}},{{"functionCall":{{"name":"run","args":{{"cmd":"echo {ph}"}}}},"thoughtSignature":"{ph}"}}]}},"finishReason":"STOP"}}]}}"#
        );
        let out = codec::restore_json(Api::Gemini, &ctx, body.as_bytes()).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let parts = &v["candidates"][0]["content"]["parts"];
        assert_eq!(parts[0]["text"], ph.as_str());
        assert_eq!(parts[1]["text"], "v=display-value-123");
        assert_eq!(
            parts[2]["functionCall"]["args"]["cmd"],
            "echo display-value-123"
        );
        assert_eq!(parts[2]["thoughtSignature"], ph.as_str());

        let arr = format!("[{body},\r\n{body}]");
        let out = codec::restore_json(Api::Gemini, &ctx, arr.as_bytes()).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(
            v[1]["candidates"][0]["content"]["parts"][1]["text"],
            "v=display-value-123"
        );
    }

    #[test]
    fn held_text_released_before_function_call_and_at_finish() {
        let fx = Fixture::new(&[("api", "display-value-123")]);
        let snap = fx.snapshot();
        let stats = RestoreStats::default();
        let ctx = Ctx {
            snap: &snap,
            stats: &stats,
        };
        let ph = fx.placeholder("api");
        let (head, tail) = ph.split_at(4);
        let mut st = Chunks::new(StreamLimits {
            max_buffered_tool_input: 1 << 20,
        });
        let first = format!(
            r#"{{"candidates":[{{"content":{{"parts":[{{"text":"x {head}"}}],"role":"model"}}}}],"responseId":"r1","modelVersion":"gemini-2.5-pro"}}"#
        );
        let out = st.chunk(&ctx, first.as_bytes());
        assert_eq!(out.before, [] as [Vec<u8>; 0]);
        let v: serde_json::Value = serde_json::from_slice(&out.chunk.unwrap()).unwrap();
        assert_eq!(v["candidates"][0]["content"]["parts"][0]["text"], "x ");

        // The rest of the placeholder, then a function call in the same chunk.
        let second = format!(
            r#"{{"candidates":[{{"content":{{"parts":[{{"text":"{tail} y"}},{{"functionCall":{{"name":"run","args":{{}}}}}}],"role":"model"}},"finishReason":"STOP","index":0}}]}}"#
        );
        let out = st.chunk(&ctx, second.as_bytes());
        assert_eq!(out.before, [] as [Vec<u8>; 0]);
        let v: serde_json::Value = serde_json::from_slice(&out.chunk.unwrap()).unwrap();
        assert_eq!(
            v["candidates"][0]["content"]["parts"][0]["text"],
            "display-value-123 y"
        );

        // Held text and a chunk with only a function call: released as its own chunk first.
        let mut st = Chunks::new(StreamLimits {
            max_buffered_tool_input: 1 << 20,
        });
        st.chunk(&ctx, first.as_bytes());
        let call = r#"{"candidates":[{"content":{"parts":[{"functionCall":{"name":"run","args":{}}}],"role":"model"}}]}"#;
        let out = st.chunk(&ctx, call.as_bytes());
        assert!(out.chunk.is_none());
        assert_eq!(out.before.len(), 1);
        let v: serde_json::Value = serde_json::from_slice(&out.before[0]).unwrap();
        assert_eq!(v["candidates"][0]["content"]["parts"][0]["text"], head);
        assert_eq!(v["responseId"], "r1");
        assert_eq!(v["modelVersion"], "gemini-2.5-pro");
        assert_eq!(st.finish(&ctx), [] as [Vec<u8>; 0]);
    }

    #[test]
    fn candidates_have_separate_holdbacks() {
        let fx = Fixture::new(&[("api", "display-value-123")]);
        let snap = fx.snapshot();
        let stats = RestoreStats::default();
        let ctx = Ctx {
            snap: &snap,
            stats: &stats,
        };
        let ph = fx.placeholder("api");
        let (head, tail) = ph.split_at(5);
        let mut st = Chunks::new(StreamLimits {
            max_buffered_tool_input: 1 << 20,
        });
        let one = format!(
            r#"{{"candidates":[{{"content":{{"parts":[{{"text":"{head}"}}]}}}},{{"content":{{"parts":[{{"text":"two "}}]}},"index":1}}]}}"#
        );
        st.chunk(&ctx, one.as_bytes());
        let two = format!(
            r#"{{"candidates":[{{"content":{{"parts":[{{"text":"{tail}"}}]}},"index":0}},{{"content":{{"parts":[{{"text":"{head}"}}]}},"index":1}}]}}"#
        );
        let out = st.chunk(&ctx, two.as_bytes());
        let v: serde_json::Value = serde_json::from_slice(&out.chunk.unwrap()).unwrap();
        assert_eq!(
            v["candidates"][0]["content"]["parts"][0]["text"],
            "display-value-123"
        );
        assert_eq!(v["candidates"][1]["content"]["parts"][0]["text"], "");
        let rest = st.finish(&ctx);
        assert_eq!(rest.len(), 1);
        let v: serde_json::Value = serde_json::from_slice(&rest[0]).unwrap();
        assert_eq!(v["candidates"][0]["index"], 1);
        assert_eq!(v["candidates"][0]["content"]["parts"][0]["text"], head);
    }
}
