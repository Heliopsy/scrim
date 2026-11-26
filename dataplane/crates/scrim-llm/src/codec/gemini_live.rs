// SPDX-License-Identifier: AGPL-3.0-only

//! Gemini Live API (`BidiGenerateContent`, WebSocket), on the Gemini API
//! (`/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent`, `v1alpha`
//! and the ephemeral-token `BidiGenerateContentConstrained`) and on Vertex AI
//! (`/ws/google.cloud.aiplatform.v1.LlmBidiService/BidiGenerateContent`, `v1beta1`). Each
//! message is one JSON object; the Gemini API sends its server messages in binary frames.
//! Field names are accepted in `lowerCamelCase` and `snake_case`, as the APIs accept both.
//!
//! Client messages: in `setup`, the `model`, the plain settings of `generationConfig` (those
//! [`super::gemini`] keeps), and the session settings that hold no prompt text
//! (`realtimeInputConfig`, `sessionResumption` with its server-issued handle,
//! `contextWindowCompression`, `inputAudioTranscription`, `outputAudioTranscription`) stay
//! byte-identical; `systemInstruction` (also in Vertex AI's `contextUpdate`) and the `turns` of
//! `clientContent` are planned like `generateContent` contents (thought signatures kept,
//! `inlineData` binary). The `audio`,
//! `video` and `mediaChunks` blobs of `realtimeInput` are binary parts. Everything else, tools,
//! `realtimeInput.text`, tool responses and every field this codec does not know, is redacted.
//!
//! Server messages: the non-thought text parts of `serverContent.modelTurn` and the
//! `outputTranscription` and `inputTranscription` text (inside `serverContent`, or at the top
//! level as Vertex AI lists them) resolve under [`RestoreSite::Text`], each with its own
//! holdback across messages; `interimInputTranscription`, which the API rewrites while the user
//! speaks, is restored message by message without a holdback. `toolCall.functionCalls[].args`
//! (whole JSON objects) and `functionCall` parts resolve under [`RestoreSite::ToolInput`]. Held
//! model text is released before any other part and before a `toolCall`; model text and the
//! output transcription at `generationComplete` (the API sends the turn's last transcription
//! before it); everything at `turnComplete` and `interrupted`. Audio (`inlineData`), thoughts,
//! grounding and every other message pass byte for byte.

use super::gemini::{GENERATION_ALLOWLIST, field, is_thought, member, plan_content, restore_call};
use super::{
    DeltaOut, Edits, Plan, PlanError, StreamBlock, StreamCodec, StreamLimits, feed_delta,
    flush_block, restore_string,
};
use crate::engine::RestoreSite;
use crate::json::{self, Doc, Kind, Value};
use crate::restore::{Ctx, TextKind};
use crate::sse;

/// `setup` members that are session settings, not content.
const SETUP_ALLOWLIST: &[(&str, &str)] = &[
    ("model", "model"),
    ("realtimeInputConfig", "realtime_input_config"),
    ("sessionResumption", "session_resumption"),
    ("contextWindowCompression", "context_window_compression"),
    ("inputAudioTranscription", "input_audio_transcription"),
    ("outputAudioTranscription", "output_audio_transcription"),
];

/// Whether the last path segment names the Live API: `...BidiGenerateContent` or
/// `...BidiGenerateContentConstrained`.
pub(crate) fn is_live_path(path: &str) -> bool {
    let last = path
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or_default();
    last.ends_with("BidiGenerateContent") || last.ends_with("BidiGenerateContentConstrained")
}

/// Plans one client message.
pub(crate) fn plan(doc: &Doc<'_>) -> Result<Plan, PlanError> {
    let mut plan = Plan::default();
    let root = doc.root();
    if root.kind() != Kind::Object {
        return Err(PlanError::Shape("message is not a JSON object"));
    }
    if let Some(setup) = member(root, "setup", "setup")?
        && setup.kind() == Kind::Object
    {
        plan_setup(&mut plan, setup)?;
    }
    if let Some(cc) = member(root, "clientContent", "client_content")?
        && cc.kind() == Kind::Object
        && let Some(turns) = cc.get("turns")?
    {
        if turns.kind() != Kind::Array {
            return Err(PlanError::Shape("turns is not an array"));
        }
        for t in turns.children() {
            plan_content(&mut plan, t)?;
        }
    }
    if let Some(ri) = member(root, "realtimeInput", "realtime_input")?
        && ri.kind() == Kind::Object
    {
        for name in ["audio", "video"] {
            if let Some(b) = ri.get(name)? {
                plan_blob(&mut plan, b)?;
            }
        }
        if let Some(chunks) = member(ri, "mediaChunks", "media_chunks")?
            && chunks.kind() == Kind::Array
        {
            for b in chunks.children() {
                plan_blob(&mut plan, b)?;
            }
        }
    }
    // Vertex AI: replaces the instructions and tools mid-session.
    if let Some(cu) = member(root, "contextUpdate", "context_update")?
        && cu.kind() == Kind::Object
        && let Some(sys) = member(cu, "systemInstruction", "system_instruction")?
    {
        plan_content(&mut plan, sys)?;
    }
    // Refuse a message naming one field both ways, so scrim and the provider never read
    // different tool responses.
    member(root, "toolResponse", "tool_response")?;
    Ok(plan)
}

fn plan_setup(plan: &mut Plan, setup: Value<'_, '_>) -> Result<(), PlanError> {
    for (camel, snake) in SETUP_ALLOWLIST {
        if let Some(v) = member(setup, camel, snake)? {
            plan.keep(v);
        }
    }
    if let Some(gc) = member(setup, "generationConfig", "generation_config")?
        && gc.kind() == Kind::Object
    {
        for (k, v) in gc.members() {
            if GENERATION_ALLOWLIST.contains(&k.as_ref()) {
                plan.keep(v);
            }
        }
    }
    if let Some(sys) = member(setup, "systemInstruction", "system_instruction")? {
        plan_content(plan, sys)?;
    }
    Ok(())
}

/// A `Blob` (`mimeType`, base64 `data`): the data is a binary part.
fn plan_blob(plan: &mut Plan, blob: Value<'_, '_>) -> Result<(), PlanError> {
    if blob.kind() != Kind::Object {
        return Ok(());
    }
    if let Some(data) = blob.get("data")? {
        let mt = member(blob, "mimeType", "mime_type")?
            .and_then(|m| m.as_str())
            .unwrap_or_default();
        // `audio/pcm;rate=16000`: the parameters are not part of the media type reported.
        plan.binary(data, mt.split(';').next().unwrap_or_default().trim());
    }
    Ok(())
}

/// The three texts of a session that stream across messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Block {
    /// Text parts of `serverContent.modelTurn`.
    Model,
    /// `serverContent.outputTranscription.text`: what the model said.
    Output,
    /// `serverContent.inputTranscription.text`: what the user said.
    Input,
}

const BLOCKS: [Block; 3] = [Block::Model, Block::Output, Block::Input];

/// A text field of the current message and what it becomes.
struct Field {
    block: Block,
    span: (usize, usize),
    text: String,
    changed: bool,
}

/// Streaming state for one Live session.
pub(crate) struct Stream {
    model: Option<StreamBlock>,
    output: Option<StreamBlock>,
    input: Option<StreamBlock>,
    budget: usize,
    /// The provider writes `snake_case` names (seen on its last `serverContent`), so
    /// synthesised messages do too.
    snake: bool,
}

impl Stream {
    pub(crate) fn new(limits: StreamLimits) -> Self {
        Self {
            model: None,
            output: None,
            input: None,
            budget: limits.max_buffered_tool_input,
            snake: false,
        }
    }

    fn slot(&mut self, b: Block) -> &mut Option<StreamBlock> {
        match b {
            Block::Model => &mut self.model,
            Block::Output => &mut self.output,
            Block::Input => &mut self.input,
        }
    }

    /// Feeds one text field to its block.
    fn feed(&mut self, ctx: &Ctx<'_>, block: Block, t: Value<'_, '_>, fields: &mut Vec<Field>) {
        let Some(s) = t.as_str() else { return };
        let mut budget = self.budget;
        let b = self.slot(block).get_or_insert_with(StreamBlock::text);
        let (text, changed) = match feed_delta(ctx, b, &s, &mut budget) {
            DeltaOut::Unchanged => (s.into_owned(), false),
            DeltaOut::Drop => (String::new(), true),
            DeltaOut::Replace(t) => (t, true),
        };
        self.budget = budget;
        fields.push(Field {
            block,
            span: t.span(),
            text,
            changed,
        });
    }

    /// Releases what `block` still holds: into its last field of this message when `attach`,
    /// otherwise as a message of its own sent first.
    fn release(
        &mut self,
        ctx: &Ctx<'_>,
        block: Block,
        attach: bool,
        fields: &mut [Field],
        before: &mut Vec<Vec<u8>>,
    ) {
        let Some(mut b) = self.slot(block).take() else {
            return;
        };
        let rest = flush_block(ctx, &mut b);
        if rest.is_empty() {
            return;
        }
        match fields.iter_mut().rev().find(|f| f.block == block) {
            Some(f) if attach => {
                f.text.push_str(&rest);
                f.changed = true;
            }
            _ => before.push(self.synth(block, &rest)),
        }
    }

    /// A `serverContent` message carrying `text` as the next text of `block`.
    fn synth(&self, block: Block, text: &str) -> Vec<u8> {
        let n = |camel: &'static str, snake: &'static str| if self.snake { snake } else { camel };
        let inner = match block {
            Block::Model => {
                serde_json::json!({ n("modelTurn", "model_turn"): { "parts": [{ "text": text }] } })
            }
            Block::Output => {
                serde_json::json!({ n("outputTranscription", "output_transcription"): { "text": text } })
            }
            Block::Input => {
                serde_json::json!({ n("inputTranscription", "input_transcription"): { "text": text } })
            }
        };
        let msg = serde_json::json!({ n("serverContent", "server_content"): inner });
        serde_json::to_vec(&msg).unwrap_or_default()
    }

    /// Handles one server message; `None` when it passes unchanged. `before` receives messages
    /// to send ahead of it.
    fn message(
        &mut self,
        ctx: &Ctx<'_>,
        data: &[u8],
        before: &mut Vec<Vec<u8>>,
    ) -> Option<Vec<u8>> {
        let doc = Doc::parse(data).ok()?;
        let root = doc.root();
        if root.kind() != Kind::Object {
            return None;
        }
        let mut fields: Vec<Field> = Vec::new();
        let mut edits = Edits::default();
        if let Some(sc) = field(root, "serverContent", "server_content") {
            self.snake = root.get("server_content").ok().flatten().is_some();
            self.server_content(ctx, sc, &mut fields, &mut edits, before);
        } else if field(root, "inputTranscription", "input_transcription").is_some()
            || field(root, "outputTranscription", "output_transcription").is_some()
        {
            // Vertex AI lists the transcriptions as server messages of their own.
            self.server_content(ctx, root, &mut fields, &mut edits, before);
        } else if let Some(tc) = field(root, "toolCall", "tool_call") {
            // The model's text before a tool call ends there.
            self.release(ctx, Block::Model, false, &mut fields, before);
            if let Some(calls) = field(tc, "functionCalls", "function_calls") {
                for call in calls.children() {
                    restore_call(ctx, call, &mut edits);
                }
            }
        }
        for f in fields.into_iter().filter(|f| f.changed) {
            edits.push(f.span, json::quote(&f.text));
        }
        edits.apply(data)
    }

    fn server_content(
        &mut self,
        ctx: &Ctx<'_>,
        sc: Value<'_, '_>,
        fields: &mut Vec<Field>,
        edits: &mut Edits,
        before: &mut Vec<Vec<u8>>,
    ) {
        // Whether the last model part of this message is text, so held text can join it
        // without moving past anything.
        let mut last_text = false;
        if let Some(parts) =
            field(sc, "modelTurn", "model_turn").and_then(|t| t.get("parts").ok()?)
        {
            for p in parts.children() {
                if p.kind() != Kind::Object || is_thought(p) {
                    continue;
                }
                if let Ok(Some(t)) = p.get("text")
                    && t.kind() == Kind::String
                {
                    self.feed(ctx, Block::Model, t, fields);
                    last_text = true;
                    continue;
                }
                // Any other part (audio, code, a call) ends the text before it.
                self.release(ctx, Block::Model, last_text, fields, before);
                last_text = false;
                if let Some(call) = field(p, "functionCall", "function_call") {
                    restore_call(ctx, call, edits);
                }
            }
        }
        let has = |block: Block, camel: &str, snake: &str, s: &mut Self, f: &mut Vec<Field>| {
            if let Some(t) = field(sc, camel, snake).and_then(|v| v.get("text").ok()?)
                && t.kind() == Kind::String
            {
                s.feed(ctx, block, t, f);
                return true;
            }
            false
        };
        let out_here = has(
            Block::Output,
            "outputTranscription",
            "output_transcription",
            self,
            fields,
        );
        let in_here = has(
            Block::Input,
            "inputTranscription",
            "input_transcription",
            self,
            fields,
        );
        // Rewritten while the user speaks: each message stands alone.
        if let Some(t) = field(
            sc,
            "interimInputTranscription",
            "interim_input_transcription",
        )
        .and_then(|v| v.get("text").ok()?)
        {
            restore_string(ctx, &RestoreSite::Text, TextKind::Plain, t, edits);
        }
        let flag =
            |camel: &str, snake: &str| field(sc, camel, snake).is_some_and(|v| v.raw() == b"true");
        let turn_end = flag("turnComplete", "turn_complete") || flag("interrupted", "interrupted");
        if turn_end || flag("generationComplete", "generation_complete") {
            self.release(ctx, Block::Model, last_text, fields, before);
            self.release(ctx, Block::Output, out_here, fields, before);
        }
        if turn_end {
            self.release(ctx, Block::Input, in_here, fields, before);
        }
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
        let mut before = Vec::new();
        let msg = self.message(ctx, ev.data.as_bytes(), &mut before);
        for b in before {
            out.extend_from_slice(&sse::build(None, &b));
        }
        match msg {
            Some(new) => out.extend_from_slice(&sse::with_data(raw, &new)),
            None => out.extend_from_slice(raw),
        }
    }

    fn finish(&mut self, ctx: &Ctx<'_>, out: &mut Vec<u8>) {
        let mut before = Vec::new();
        for b in BLOCKS {
            self.release(ctx, b, false, &mut [], &mut before);
        }
        for b in before {
            out.extend_from_slice(&sse::build(None, &b));
        }
    }
}

#[cfg(all(test, feature = "test-util"))]
mod tests {
    use super::*;
    use crate::restore::RestoreStats;
    use crate::testing::Fixture;

    fn kept(body: &str) -> (Vec<String>, Vec<String>) {
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
    fn live_paths() {
        for p in [
            "/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent",
            "/ws/google.ai.generativelanguage.v1alpha.GenerativeService.BidiGenerateContentConstrained",
            "/ws/google.cloud.aiplatform.v1.LlmBidiService/BidiGenerateContent",
            "/ws/google.cloud.aiplatform.v1beta1.LlmBidiService/BidiGenerateContent/",
        ] {
            assert!(is_live_path(p), "{p}");
        }
        for p in [
            "/v1beta/models/gemini-2.5-flash:streamGenerateContent",
            "/ws/BidiGenerateContent/x",
            "",
        ] {
            assert!(!is_live_path(p), "{p}");
        }
    }

    #[test]
    fn plans_setup_settings_blobs_and_signatures() {
        let (v, b) = kept(
            r#"{"setup":{"model":"models/gemini-live-2.5-flash","generationConfig":{"responseModalities":["AUDIO"],"temperature":0.4,"speechConfig":{"voiceConfig":{"prebuiltVoiceConfig":{"voiceName":"Kore"}}}},"systemInstruction":{"parts":[{"text":"be brief"}]},"tools":[{"functionDeclarations":[{"name":"run"}]}],"sessionResumption":{"handle":"h-123"},"outputAudioTranscription":{}}}"#,
        );
        assert_eq!(
            v,
            [
                "models/gemini-live-2.5-flash",
                r#"["AUDIO"]"#,
                "0.4",
                r#"{"handle":"h-123"}"#,
                "{}",
            ]
        );
        assert_eq!(b, [] as [String; 0]);
        let (v, b) = kept(
            r#"{"realtimeInput":{"audio":{"mimeType":"audio/pcm;rate=16000","data":"AAAA"},"text":"hi","mediaChunks":[{"mime_type":"image/jpeg","data":"/9j/"}]}}"#,
        );
        assert_eq!(v, ["AAAA", "/9j/"]);
        assert_eq!(b, ["audio/pcm", "image/jpeg"]);
        let (v, b) = kept(
            r#"{"client_content":{"turns":[{"role":"model","parts":[{"text":"x","thought_signature":"c2ln"},{"inline_data":{"mime_type":"image/png","data":"iVBO"}}]}],"turn_complete":true}}"#,
        );
        assert_eq!(v, ["c2ln", "iVBO"]);
        assert_eq!(b, ["image/png"]);
        let (v, _) = kept(
            r#"{"toolResponse":{"functionResponses":[{"id":"c1","name":"run","response":{"out":"x"}}]}}"#,
        );
        assert_eq!(v, [] as [String; 0]);
        for bad in [
            r"[]",
            r#"{"setup":{"systemInstruction":{},"system_instruction":{}}}"#,
            r#"{"clientContent":{"turns":{}}}"#,
            r#"{"toolResponse":{},"tool_response":{}}"#,
            r#"{"realtimeInput":{"mediaChunks":[],"media_chunks":[]}}"#,
        ] {
            assert!(plan(&Doc::parse(bad.as_bytes()).unwrap()).is_err(), "{bad}");
        }
    }

    fn run(fx: &Fixture, msgs: &[String]) -> (Vec<serde_json::Value>, u64) {
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
        for m in msgs {
            s.event(&ctx, format!("data: {m}\n\n").as_bytes(), &mut out);
        }
        s.finish(&ctx, &mut out);
        let text = String::from_utf8(out).unwrap();
        let vals = text
            .split("\n\n")
            .filter(|e| !e.is_empty())
            .map(|e| serde_json::from_str(e.strip_prefix("data: ").unwrap()).unwrap())
            .collect();
        (vals, stats.resolved.get())
    }

    fn joined(
        vals: &[serde_json::Value],
        f: impl Fn(&serde_json::Value) -> Option<String>,
    ) -> String {
        vals.iter().filter_map(f).collect()
    }

    /// The non-thought text of a message's model turn.
    fn model_text(v: &serde_json::Value) -> Option<String> {
        let parts = v["serverContent"]["modelTurn"]["parts"].as_array()?;
        Some(
            parts
                .iter()
                .filter(|p| p["thought"] != true)
                .filter_map(|p| p["text"].as_str())
                .collect(),
        )
    }

    #[test]
    fn restores_split_model_text_and_transcripts() {
        let fx = Fixture::new(&[("a", "alpha-secret-value-01")]);
        let p = fx.placeholder("a");
        let v = fx.value("a");
        let (head, tail) = p.split_at(p.char_indices().nth(5).unwrap().0);
        let sc =
            |inner: serde_json::Value| serde_json::json!({ "serverContent": inner }).to_string();
        let msgs = vec![
            r#"{"setupComplete":{}}"#.to_string(),
            sc(serde_json::json!({"inputTranscription":{"text":format!("say {head}")}})),
            sc(serde_json::json!({"inputTranscription":{"text":format!("{tail} please")}})),
            sc(
                serde_json::json!({"modelTurn":{"parts":[{"text":"thinking","thought":true},{"text":format!("it is {head}")}]}}),
            ),
            sc(
                serde_json::json!({"modelTurn":{"parts":[{"text":format!("{tail}.")}]},"outputTranscription":{"text":format!("it is {head}")}}),
            ),
            sc(serde_json::json!({"outputTranscription":{"text":tail}})),
            sc(serde_json::json!({"generationComplete":true})),
            sc(serde_json::json!({"interimInputTranscription":{"text":format!("next {p}")}})),
            sc(serde_json::json!({"turnComplete":true})),
        ];
        let (vals, resolved) = run(&fx, &msgs);
        assert_eq!(vals[0], serde_json::json!({"setupComplete":{}}));
        assert_eq!(joined(&vals, model_text), format!("it is {v}."));
        assert_eq!(
            joined(&vals, |v| v["serverContent"]["outputTranscription"]["text"]
                .as_str()
                .map(str::to_string)),
            format!("it is {v}")
        );
        assert_eq!(
            joined(&vals, |v| v["serverContent"]["inputTranscription"]["text"]
                .as_str()
                .map(str::to_string)),
            format!("say {v} please")
        );
        // The thought part is left as sent.
        assert_eq!(
            vals[3]["serverContent"]["modelTurn"]["parts"][0]["text"],
            "thinking"
        );
        assert_eq!(
            joined(&vals, |v| {
                v["serverContent"]["interimInputTranscription"]["text"]
                    .as_str()
                    .map(str::to_string)
            }),
            format!("next {v}")
        );
        assert_eq!(resolved, 4);
        assert!(!serde_json::to_string(&vals).unwrap().contains(&p));
    }

    #[test]
    fn held_text_is_released_before_a_tool_call_whose_args_are_restored() {
        let fx = Fixture::new(&[("a", "alpha-secret-value-01")]);
        let p = fx.placeholder("a");
        let head = &p[..4];
        let msgs = vec![
            format!(r#"{{"serverContent":{{"modelTurn":{{"parts":[{{"text":"x {head}"}}]}}}}}}"#),
            format!(
                r#"{{"toolCall":{{"functionCalls":[{{"id":"c1","name":"run","args":{{"cmd":"echo {p}"}}}}]}}}}"#
            ),
        ];
        let (vals, _) = run(&fx, &msgs);
        assert_eq!(vals.len(), 3);
        assert_eq!(model_text(&vals[0]).as_deref(), Some("x "));
        // The held prefix never became a placeholder: released unchanged, before the call.
        assert_eq!(model_text(&vals[1]).as_deref(), Some(head));
        assert_eq!(
            vals[2]["toolCall"]["functionCalls"][0]["args"]["cmd"],
            format!("echo {}", fx.value("a"))
        );
    }

    #[test]
    fn audio_parts_and_snake_case() {
        let fx = Fixture::new(&[("a", "alpha-secret-value-01")]);
        let p = fx.placeholder("a");
        let head = &p[..4];
        let msgs = vec![
            format!(
                r#"{{"server_content":{{"model_turn":{{"parts":[{{"text":"{head}"}},{{"inline_data":{{"mime_type":"audio/pcm","data":"AAAA"}}}}]}}}}}}"#
            ),
            format!(r#"{{"server_content":{{"output_transcription":{{"text":"{head}"}}}}}}"#),
            r#"{"usageMetadata":{"totalTokenCount":3}}"#.to_string(),
        ];
        let (vals, _) = run(&fx, &msgs);
        // Held text joins the text part before the audio part.
        assert_eq!(
            vals[0]["server_content"]["model_turn"]["parts"][0]["text"],
            head
        );
        assert_eq!(
            vals[1]["server_content"]["output_transcription"]["text"],
            ""
        );
        assert_eq!(
            vals[2],
            serde_json::json!({"usageMetadata":{"totalTokenCount":3}})
        );
        // Released at the end, in the provider's naming.
        assert_eq!(
            vals[3]["server_content"]["output_transcription"]["text"],
            head
        );
        assert_eq!(vals.len(), 4);
    }

    #[test]
    fn vertex_top_level_transcriptions_and_context_update() {
        let fx = Fixture::new(&[("a", "alpha-secret-value-01")]);
        let p = fx.placeholder("a");
        let msgs = vec![format!(
            r#"{{"outputTranscription":{{"text":"is {p}","finished":true}}}}"#
        )];
        let (vals, _) = run(&fx, &msgs);
        assert_eq!(
            vals[0]["outputTranscription"]["text"],
            format!("is {}", fx.value("a"))
        );
        let (v, _) = kept(
            r#"{"contextUpdate":{"systemInstruction":{"parts":[{"text":"x","thoughtSignature":"c2ln"}]},"tools":[]}}"#,
        );
        assert_eq!(v, ["c2ln"]);
    }

    #[test]
    fn other_messages_pass_byte_for_byte() {
        let fx = Fixture::new(&[("a", "alpha-secret-value-01")]);
        let msgs = vec![
            r#"{"serverContent":{"modelTurn":{"parts":[{"inlineData":{"mimeType":"audio/pcm;rate=24000","data":"AAAA"}}]}}}"#.to_string(),
            r#"{"goAway":{"timeLeft":"10s"}}"#.to_string(),
            r#"{"sessionResumptionUpdate":{"newHandle":"h","resumable":true}}"#.to_string(),
            r#"{"toolCallCancellation":{"ids":["c1"]}}"#.to_string(),
        ];
        let snap = fx.snapshot();
        let stats = RestoreStats::default();
        let ctx = Ctx {
            snap: &snap,
            stats: &stats,
        };
        let mut s = Stream::new(StreamLimits {
            max_buffered_tool_input: 1 << 20,
        });
        for m in &msgs {
            let raw = format!("data: {m}\n\n");
            let mut out = Vec::new();
            s.event(&ctx, raw.as_bytes(), &mut out);
            assert_eq!(out, raw.as_bytes());
        }
    }
}
