// SPDX-License-Identifier: AGPL-3.0-only

//! Provider API codecs.
//!
//! On the request side a codec only *plans*: it parses the body with the span scanner and lists
//! the byte spans that must leave unchanged (allowlisted configuration, signed thinking, opaque
//! reasoning, unscannable binary data). Everything else, including every field the codec does
//! not know, is redacted on its raw bytes by the redactor (design D2, D4).
//!
//! On the response side a codec resolves placeholders where the restore policy allows: in a
//! buffered JSON body by splicing the changed strings, or in an SSE stream event by event with a
//! per-content-block holdback. Thinking, reasoning and signatures are never touched.

pub(crate) mod anthropic;
pub(crate) mod converse;
pub mod gemini;
pub(crate) mod openai_chat;
pub(crate) mod openai_realtime;
pub(crate) mod openai_responses;

use crate::engine::RestoreSite;
use crate::json::{self, Doc, Duplicate, JsonError, Kind, Value};
use crate::restore::{Ctx, StreamText, TextKind, restore_complete};

/// Which provider API a request speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Api {
    /// Anthropic Messages (`/v1/messages`, `/v1/messages/count_tokens`).
    AnthropicMessages,
    /// `OpenAI` Chat Completions (`/v1/chat/completions`).
    OpenAiChat,
    /// `OpenAI` Responses (`/v1/responses`, `/v1/responses/compact`).
    OpenAiResponses,
    /// Google Gemini `generateContent`, `streamGenerateContent` and `countTokens`, on the
    /// Gemini API and on Vertex AI.
    Gemini,
    /// Amazon Bedrock Converse (`/model/{modelId}/converse`, `/converse-stream`). Its stream is
    /// an event stream, restored by [`crate::eventstream::EventStreamRestorer`].
    BedrockConverse,
    /// Anything else on a provider route. The whole body is redacted, nothing is allowlisted,
    /// and responses pass through without resolution.
    Generic,
}

impl Api {
    /// Stable name.
    pub fn name(self) -> &'static str {
        match self {
            Self::AnthropicMessages => "anthropic-messages",
            Self::OpenAiChat => "openai-chat",
            Self::OpenAiResponses => "openai-responses",
            Self::Gemini => "gemini",
            Self::BedrockConverse => "bedrock-converse",
            Self::Generic => "generic",
        }
    }
}

/// A request body the codec could not plan; refused as malformed.
#[derive(Debug, Clone, thiserror::Error)]
pub(crate) enum PlanError {
    #[error(transparent)]
    Json(#[from] JsonError),
    #[error(transparent)]
    Duplicate(#[from] Duplicate),
    #[error("{0}")]
    Shape(&'static str),
}

/// What must leave unchanged.
#[derive(Debug, Default)]
pub(crate) struct Plan {
    /// Sorted, non-overlapping byte spans forwarded without redaction.
    pub verbatim: Vec<(usize, usize)>,
    /// Media types of unscannable parts (also listed in `verbatim`).
    pub binary: Vec<String>,
}

impl Plan {
    pub(crate) fn keep(&mut self, v: Value<'_, '_>) {
        let span = match v.kind() {
            // Keep the content only, so the quotes stay part of the redacted neighbourhood and
            // the spans of adjacent members never touch.
            Kind::String => v.str_content_span().unwrap_or(v.span()),
            _ => v.span(),
        };
        if span.1 > span.0 {
            self.verbatim.push(span);
        }
    }

    pub(crate) fn binary(&mut self, data: Value<'_, '_>, media_type: &str) {
        self.keep(data);
        self.binary.push(sanitize_media_type(media_type));
    }

    pub(crate) fn finish(mut self) -> Self {
        self.verbatim.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(self.verbatim.len());
        for (s, e) in self.verbatim {
            match merged.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        self.verbatim = merged;
        self
    }
}

/// Media types come from the agent's request. Only a plain `type/subtype` is reported; anything
/// else becomes `unknown`, so no request content reaches an error or audit entry.
pub(crate) fn sanitize_media_type(m: &str) -> String {
    let ok = m.len() <= 64
        && m.split_once('/').is_some_and(|(a, b)| {
            let good = |s: &str| {
                !s.is_empty()
                    && s.bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b".+-".contains(&c))
            };
            good(a) && good(b)
        });
    if ok {
        m.to_ascii_lowercase()
    } else {
        "unknown".to_string()
    }
}

/// Media type of a `data:` URL, or `None` when `url` is not one.
pub(crate) fn data_url_media_type(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("data:")?;
    let meta = rest.split_once(',')?.0;
    Some(meta.split(';').next().unwrap_or(""))
}

/// Plans a request body for `api`.
pub(crate) fn plan(api: Api, body: &[u8]) -> Result<Plan, PlanError> {
    let plan = match api {
        Api::Generic => return Ok(Plan::default()),
        Api::AnthropicMessages => anthropic::plan(&Doc::parse(body)?)?,
        Api::OpenAiChat => openai_chat::plan(&Doc::parse(body)?)?,
        Api::OpenAiResponses => openai_responses::plan(&Doc::parse(body)?)?,
        Api::Gemini => gemini::plan(&Doc::parse(body)?)?,
        Api::BedrockConverse => converse::plan(&Doc::parse(body)?)?,
    };
    Ok(plan.finish())
}

/// Keeps allowlisted top-level members verbatim; requires an object root.
pub(crate) fn keep_allowlisted(
    plan: &mut Plan,
    root: Value<'_, '_>,
    allow: &[&str],
) -> Result<(), PlanError> {
    if root.kind() != Kind::Object {
        return Err(PlanError::Shape("request body is not a JSON object"));
    }
    for (k, v) in root.members() {
        if allow.contains(&k.as_ref()) {
            plan.keep(v);
        }
    }
    Ok(())
}

/// Restores a non-streaming JSON response. `None` when nothing changed or the body is not JSON
/// the codec understands (it then passes through unchanged, which keeps placeholders).
pub(crate) fn restore_json(api: Api, ctx: &Ctx<'_>, body: &[u8]) -> Option<Vec<u8>> {
    let doc = Doc::parse(body).ok()?;
    let mut edits = Edits::default();
    match api {
        Api::AnthropicMessages => anthropic::restore_message(ctx, doc.root(), &mut edits),
        Api::OpenAiChat => openai_chat::restore_completion(ctx, doc.root(), &mut edits),
        Api::OpenAiResponses => {
            openai_responses::restore_response(ctx, doc.root(), &mut edits, &|_| true);
        }
        Api::Gemini => gemini::restore_response(ctx, doc.root(), &mut edits),
        Api::BedrockConverse => converse::restore_response(ctx, doc.root(), &mut edits),
        Api::Generic => return None,
    }
    edits.apply(body)
}

/// Byte edits against one JSON source.
#[derive(Debug, Default)]
pub(crate) struct Edits(Vec<(usize, usize, Vec<u8>)>);

impl Edits {
    pub(crate) fn push(&mut self, span: (usize, usize), bytes: Vec<u8>) {
        self.0.push((span.0, span.1, bytes));
    }

    /// Applies the edits, `None` when there are none.
    pub(crate) fn apply(mut self, src: &[u8]) -> Option<Vec<u8>> {
        if self.0.is_empty() {
            return None;
        }
        self.0.sort_by_key(|e| e.0);
        Some(json::splice(src, &self.0))
    }
}

/// Restores the string `v` in place: resolves placeholders and, when anything changed, records
/// an edit replacing the whole string literal.
pub(crate) fn restore_string(
    ctx: &Ctx<'_>,
    site: &RestoreSite<'_>,
    kind: TextKind,
    v: Value<'_, '_>,
    edits: &mut Edits,
) {
    let Some(s) = v.as_str() else { return };
    if let Some(new) = restore_complete(ctx, site, kind, &s) {
        edits.push(v.span(), json::quote(&new));
    }
}

/// Restores an embedded JSON value (such as an Anthropic `tool_use.input` object) as JSON
/// source text, resolving only inside string literals.
pub(crate) fn restore_json_source(
    ctx: &Ctx<'_>,
    site: &RestoreSite<'_>,
    v: Value<'_, '_>,
    edits: &mut Edits,
) {
    let Ok(src) = std::str::from_utf8(v.raw()) else {
        return;
    };
    if let Some(new) = restore_complete(ctx, site, TextKind::JsonText, src) {
        edits.push(v.span(), new.into_bytes());
    }
}

/// A streamed content block: restorer plus what is needed to emit held text later.
pub(crate) struct StreamBlock {
    pub text: StreamText,
    /// Tool name for tool-argument blocks; `None` for text.
    pub tool: Option<String>,
    /// Feed the whole arguments to the policy at the end (buffered mode).
    pub buffered: Option<String>,
    /// Never restore (verbatim kinds, or a buffered block that outgrew its limit).
    pub passthrough: bool,
    /// Raw bytes of the last delta event for this block, used to synthesise flush events.
    pub template: Option<Vec<u8>>,
}

impl StreamBlock {
    pub(crate) fn text() -> Self {
        Self {
            text: StreamText::new(TextKind::Plain),
            tool: None,
            buffered: None,
            passthrough: false,
            template: None,
        }
    }

    pub(crate) fn tool(ctx: &Ctx<'_>, name: &str, kind: TextKind) -> Self {
        let buffered = (ctx.snap.policy.tool_mode(name) == crate::engine::ToolMode::Buffered)
            .then(String::new);
        Self {
            text: StreamText::new(kind),
            tool: Some(name.to_string()),
            buffered,
            passthrough: false,
            template: None,
        }
    }

    pub(crate) fn verbatim() -> Self {
        Self {
            text: StreamText::new(TextKind::Plain),
            tool: None,
            buffered: None,
            passthrough: true,
            template: None,
        }
    }
}

/// Limits a stream codec works within.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StreamLimits {
    /// Total bytes of buffered tool arguments per stream.
    pub max_buffered_tool_input: usize,
}

/// Outcome of feeding one delta string to a block.
pub(crate) enum DeltaOut {
    /// Pass the event through unchanged.
    Unchanged,
    /// Drop the event (everything is held back).
    Drop,
    /// Replace the delta string with this text.
    Replace(String),
}

/// Feeds `delta` to `block`, honouring buffered mode and the stream-wide buffer budget.
pub(crate) fn feed_delta(
    ctx: &Ctx<'_>,
    block: &mut StreamBlock,
    delta: &str,
    budget: &mut usize,
) -> DeltaOut {
    if block.passthrough {
        return DeltaOut::Unchanged;
    }
    if let Some(buf) = block.buffered.as_mut() {
        if delta.len() <= *budget {
            *budget -= delta.len();
            buf.push_str(delta);
            return DeltaOut::Drop;
        }
        // Over budget: release what was buffered, unresolved, and pass the rest through.
        let mut out = std::mem::take(buf);
        out.push_str(delta);
        block.buffered = None;
        block.passthrough = true;
        return DeltaOut::Replace(out);
    }
    let site = match &block.tool {
        Some(t) => RestoreSite::ToolInput {
            tool: t,
            arguments: None,
        },
        None => RestoreSite::Text,
    };
    let mut out = String::with_capacity(delta.len());
    if !block.text.push(ctx, &site, delta, &mut out) {
        return DeltaOut::Unchanged;
    }
    if out.is_empty() {
        DeltaOut::Drop
    } else {
        DeltaOut::Replace(out)
    }
}

/// Text a block still owes the agent at its end: held bytes, or the whole buffered arguments
/// restored with the complete arguments in view.
pub(crate) fn flush_block(ctx: &Ctx<'_>, block: &mut StreamBlock) -> String {
    if let Some(buf) = block.buffered.take() {
        let tool = block.tool.clone().unwrap_or_default();
        let kind = block.text.kind();
        let site = RestoreSite::ToolInput {
            tool: &tool,
            arguments: Some(&buf),
        };
        return restore_complete(ctx, &site, kind, &buf).unwrap_or(buf);
    }
    let mut out = String::new();
    block.text.finish(&mut out);
    out
}

/// The restore site for a block's complete text (done events, final snapshots), consistent with
/// how its deltas were decided.
pub(crate) fn block_site<'a>(
    tool: Option<&'a str>,
    buffered: bool,
    full: &'a str,
) -> RestoreSite<'a> {
    match tool {
        None => RestoreSite::Text,
        Some(t) => RestoreSite::ToolInput {
            tool: t,
            arguments: buffered.then_some(full),
        },
    }
}

/// Re-parses `template` (a raw SSE event), sets the string at `path` in its data to `text`, and
/// returns the rebuilt event. `None` when the template does not have that shape.
pub(crate) fn synth_from_template(template: &[u8], path: &[&str], text: &str) -> Option<Vec<u8>> {
    let ev = crate::sse::Event::parse(template)?;
    let doc = Doc::parse(ev.data.as_bytes()).ok()?;
    let mut v = doc.root();
    for p in path {
        v = v.get(p).ok()??;
    }
    if v.kind() != Kind::String {
        return None;
    }
    let data = json::splice(
        ev.data.as_bytes(),
        &[(v.span().0, v.span().1, json::quote(text))],
    );
    Some(crate::sse::with_data(template, &data))
}

/// The per-stream restore state machine of one API.
pub(crate) trait StreamCodec: Send {
    /// Handles one complete raw SSE event, appending what the agent should receive.
    fn event(&mut self, ctx: &Ctx<'_>, raw: &[u8], out: &mut Vec<u8>);
    /// Releases everything still held at end of stream.
    fn finish(&mut self, ctx: &Ctx<'_>, out: &mut Vec<u8>);
}

/// Creates the stream codec for `api`, or `None` when the API's streams pass through.
pub(crate) fn stream_codec(api: Api, limits: StreamLimits) -> Option<Box<dyn StreamCodec>> {
    match api {
        Api::AnthropicMessages => Some(Box::new(anthropic::Stream::new(limits))),
        Api::OpenAiChat => Some(Box::new(openai_chat::Stream::new(limits))),
        Api::OpenAiResponses => Some(Box::new(openai_responses::Stream::new(limits))),
        Api::Gemini => Some(Box::new(gemini::SseStream::new(limits))),
        // Event streams, not SSE (crate::eventstream).
        Api::BedrockConverse | Api::Generic => None,
    }
}

/// The per-stream restore state machine of an API that streams the elements of one JSON array
/// (Gemini `streamGenerateContent` without `alt=sse`).
pub(crate) trait ArrayCodec: Send {
    /// Handles one complete top-level element, appending what the agent should receive. The
    /// separator before it has been written already.
    fn element(&mut self, ctx: &Ctx<'_>, raw: &[u8], out: &mut Vec<u8>);
    /// Called just before the closing `]` is written: releases everything still held, as
    /// further elements.
    fn close(&mut self, ctx: &Ctx<'_>, out: &mut Vec<u8>);
    /// Releases everything still held at the end of a stream that never closed its array.
    fn finish(&mut self, ctx: &Ctx<'_>, out: &mut Vec<u8>);
}

/// Whether `api` may stream as one JSON array of chunks (see [`array_codec`]).
pub(crate) fn streams_json_array(api: Api) -> bool {
    matches!(api, Api::Gemini)
}

/// Creates the JSON-array stream codec for `api`, or `None` when the API has no such stream.
pub(crate) fn array_codec(api: Api, limits: StreamLimits) -> Option<Box<dyn ArrayCodec>> {
    match api {
        Api::Gemini => Some(Box::new(gemini::ArrayStream::new(limits))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_types_sanitised() {
        assert_eq!(sanitize_media_type("image/PNG"), "image/png");
        assert_eq!(
            sanitize_media_type("application/vnd.openxmlformats+xml"),
            "application/vnd.openxmlformats+xml"
        );
        assert_eq!(sanitize_media_type("image/png; secret=abc"), "unknown");
        assert_eq!(sanitize_media_type(""), "unknown");
        assert_eq!(sanitize_media_type(&"a".repeat(80)), "unknown");
    }

    #[test]
    fn data_urls() {
        assert_eq!(
            data_url_media_type("data:image/png;base64,AAAA"),
            Some("image/png")
        );
        assert_eq!(data_url_media_type("data:,hello"), Some(""));
        assert_eq!(data_url_media_type("https://example.com/a.png"), None);
    }

    #[test]
    fn plan_merges_overlaps() {
        let p = Plan {
            verbatim: vec![(10, 20), (0, 5), (15, 30), (30, 31)],
            binary: vec![],
        }
        .finish();
        assert_eq!(p.verbatim, vec![(0, 5), (10, 31)]);
    }

    #[test]
    fn generic_plans_nothing_and_needs_no_json() {
        assert_eq!(
            plan(Api::Generic, b"not json").unwrap().verbatim,
            [] as [(usize, usize); 0]
        );
        assert!(plan(Api::AnthropicMessages, b"not json").is_err());
        assert!(plan(Api::AnthropicMessages, b"[]").is_err());
    }
}
