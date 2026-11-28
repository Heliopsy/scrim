// SPDX-License-Identifier: AGPL-3.0-only

//! Amazon Bedrock Converse API (`/model/{modelId}/converse` and `/converse-stream`).
//!
//! Request: inference, guardrail and performance configuration and the tool choice stay
//! byte-identical, and so does signed reasoning (`reasoningContent.reasoningText` with its
//! signature, and `redactedContent`); image, document and video bytes are unscannable binary.
//! Everything else, including messages, system prompts, tool specifications and tool results, is
//! redacted.
//!
//! Response: `text` blocks resolve under [`RestoreSite::Text`], `toolUse.input` under
//! [`RestoreSite::ToolInput`]. Reasoning is left alone. The stream is an event stream
//! ([`crate::eventstream`]) whose `contentBlockDelta` events carry `delta.text` or
//! `delta.toolUse.input`; held text is released before `contentBlockStop`, `messageStop` and
//! `metadata`.

use std::collections::BTreeMap;

use super::{
    DeltaOut, Edits, Plan, PlanError, StreamBlock, StreamLimits, feed_delta, flush_block,
    keep_allowlisted, restore_json_source, restore_string,
};
use crate::engine::RestoreSite;
use crate::eventstream::{HeaderValue, Message};
use crate::json::{self, Doc, Kind, Value};
use crate::restore::{Ctx, TextKind};

/// Top-level request members that are configuration. Every other member is redacted.
pub(crate) const ALLOWLIST: &[&str] = &[
    "inferenceConfig",
    "guardrailConfig",
    "performanceConfig",
    "additionalModelResponseFieldPaths",
    "serviceTier",
];

pub(crate) fn plan(doc: &Doc<'_>) -> Result<Plan, PlanError> {
    let mut plan = Plan::default();
    let root = doc.root();
    keep_allowlisted(&mut plan, root, ALLOWLIST)?;
    if let Some(tc) = root.get("toolConfig")?
        && let Some(choice) = tc.get("toolChoice")?
    {
        plan.keep(choice);
    }
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
        if let Some(r) = b.get("reasoningContent")? {
            if let Some(t) = r.get("reasoningText")? {
                for f in ["text", "signature"] {
                    if let Some(v) = t.get(f)? {
                        plan.keep(v);
                    }
                }
            }
            if let Some(v) = r.get("redactedContent")? {
                plan.keep(v);
            }
        }
        for (kind, prefix) in [
            ("image", "image"),
            ("document", "application"),
            ("video", "video"),
        ] {
            if let Some(m) = b.get(kind)?
                && let Some(src) = m.get("source")?
            {
                if let Some(bytes) = src.get("bytes")? {
                    let format = m.get_str("format")?.unwrap_or_default();
                    plan.binary(bytes, &format!("{prefix}/{format}"));
                }
                if src.get("s3Location")?.is_some() {
                    plan.reference(
                        crate::remote::Target::Unfetchable("S3 location"),
                        crate::remote::Edit::None,
                    );
                }
            }
        }
        if let Some(tr) = b.get("toolResult")?
            && let Some(c) = tr.get("content")?
        {
            plan_blocks(plan, c, depth + 1)?;
        }
    }
    Ok(())
}

/// Restores a non-streaming Converse response (`{"output":{"message":{"content":[...]}}}`).
pub(crate) fn restore_response(ctx: &Ctx<'_>, root: Value<'_, '_>, edits: &mut Edits) {
    let Ok(Some(out)) = root.get("output") else {
        return;
    };
    let Ok(Some(msg)) = out.get("message") else {
        return;
    };
    let Ok(Some(content)) = msg.get("content") else {
        return;
    };
    for b in content.children() {
        if let Ok(Some(t)) = b.get("text") {
            restore_string(ctx, &RestoreSite::Text, TextKind::Plain, t, edits);
        }
        if let Ok(Some(tu)) = b.get("toolUse") {
            let name = tu.get_str("name").ok().flatten().unwrap_or_default();
            if let Ok(Some(input)) = tu.get("input") {
                let args = std::str::from_utf8(input.raw()).unwrap_or_default();
                let site = RestoreSite::ToolInput {
                    tool: &name,
                    arguments: Some(args),
                };
                restore_json_source(ctx, &site, input, edits);
            }
        }
    }
}

/// One open content block and the last delta frame seen for it.
struct Open {
    block: StreamBlock,
    template: Option<Message>,
}

/// Streaming state for one `ConverseStream` response.
pub(crate) struct Stream {
    blocks: BTreeMap<u64, Open>,
    budget: usize,
}

fn index_of(root: Value<'_, '_>) -> Option<u64> {
    let v = root.get("contentBlockIndex").ok()??;
    let n: u64 = std::str::from_utf8(v.raw()).ok()?.parse().ok()?;
    (n < 1 << 16).then_some(n)
}

impl Stream {
    pub(crate) fn new(limits: StreamLimits) -> Self {
        Self {
            blocks: BTreeMap::new(),
            budget: limits.max_buffered_tool_input,
        }
    }

    /// Handles one decoded message whose raw bytes are `raw`.
    pub(crate) fn message(&mut self, ctx: &Ctx<'_>, raw: &[u8], msg: &Message, out: &mut Vec<u8>) {
        if msg.header_str(":message-type") != Some("event") {
            return out.extend_from_slice(raw);
        }
        let Ok(doc) = Doc::parse(&msg.payload) else {
            return out.extend_from_slice(raw);
        };
        let root = doc.root();
        match msg.header_str(":event-type") {
            Some("contentBlockStart") => {
                if let Some(i) = index_of(root) {
                    let start = root.get("start").ok().flatten();
                    let tool = start.and_then(|s| s.get("toolUse").ok().flatten());
                    let block = match tool {
                        Some(t) => {
                            let name = t.get_str("name").ok().flatten().unwrap_or_default();
                            StreamBlock::tool(ctx, &name, TextKind::JsonText)
                        }
                        None => StreamBlock::verbatim(),
                    };
                    self.blocks.insert(
                        i,
                        Open {
                            block,
                            template: None,
                        },
                    );
                }
                out.extend_from_slice(raw);
            }
            Some("contentBlockDelta") => self.delta(ctx, raw, msg, root, out),
            Some("contentBlockStop") => {
                if let Some(i) = index_of(root) {
                    self.flush(ctx, i, out);
                    self.blocks.remove(&i);
                }
                out.extend_from_slice(raw);
            }
            Some("messageStop" | "metadata") => {
                self.flush_all(ctx, out);
                out.extend_from_slice(raw);
            }
            _ => out.extend_from_slice(raw),
        }
    }

    fn delta(
        &mut self,
        ctx: &Ctx<'_>,
        raw: &[u8],
        msg: &Message,
        root: Value<'_, '_>,
        out: &mut Vec<u8>,
    ) {
        let pass = |out: &mut Vec<u8>| out.extend_from_slice(raw);
        let (Some(index), Ok(Some(delta))) = (index_of(root), root.get("delta")) else {
            return pass(out);
        };
        let (is_text, v) = if let Ok(Some(t)) = delta.get("text") {
            (true, t)
        } else if let Ok(Some(tu)) = delta.get("toolUse")
            && let Ok(Some(input)) = tu.get("input")
        {
            (false, input)
        } else {
            // reasoningContent (text, signature, redactedContent) and citations pass unchanged.
            return pass(out);
        };
        let Some(s) = v.as_str() else {
            return pass(out);
        };
        let open = self.blocks.entry(index).or_insert_with(|| Open {
            // Text blocks have no start event in Converse.
            block: if is_text {
                StreamBlock::text()
            } else {
                StreamBlock::tool(ctx, "", TextKind::JsonText)
            },
            template: None,
        });
        if is_text != open.block.tool.is_none() && !open.block.passthrough {
            return pass(out);
        }
        match feed_delta(ctx, &mut open.block, &s, &mut self.budget) {
            DeltaOut::Unchanged => pass(out),
            DeltaOut::Drop => open.template = Some(msg.clone()),
            DeltaOut::Replace(text) => {
                let payload = json::splice(
                    &msg.payload,
                    &[(v.span().0, v.span().1, json::quote(&text))],
                );
                out.extend_from_slice(
                    &Message {
                        headers: msg.headers.clone(),
                        payload,
                    }
                    .encode(),
                );
                open.template = Some(msg.clone());
            }
        }
    }

    fn flush(&mut self, ctx: &Ctx<'_>, index: u64, out: &mut Vec<u8>) {
        let Some(open) = self.blocks.get_mut(&index) else {
            return;
        };
        let text = flush_block(ctx, &mut open.block);
        if text.is_empty() {
            return;
        }
        let tool = open.block.tool.is_some();
        let synth = open
            .template
            .as_ref()
            .and_then(|t| from_template(t, tool, &text));
        let msg = synth.unwrap_or_else(|| {
            let mut payload = Vec::new();
            payload.extend_from_slice(b"{\"contentBlockIndex\":");
            payload.extend_from_slice(index.to_string().as_bytes());
            payload.extend_from_slice(if tool {
                b",\"delta\":{\"toolUse\":{\"input\":".as_slice()
            } else {
                b",\"delta\":{\"text\":".as_slice()
            });
            payload.extend_from_slice(&json::quote(&text));
            payload.extend_from_slice(if tool { b"}}}".as_slice() } else { b"}}" });
            Message {
                headers: vec![
                    (
                        ":event-type".into(),
                        HeaderValue::String("contentBlockDelta".into()),
                    ),
                    (
                        ":content-type".into(),
                        HeaderValue::String("application/json".into()),
                    ),
                    (":message-type".into(), HeaderValue::String("event".into())),
                ],
                payload,
            }
        });
        out.extend_from_slice(&msg.encode());
    }

    fn flush_all(&mut self, ctx: &Ctx<'_>, out: &mut Vec<u8>) {
        let keys: Vec<u64> = self.blocks.keys().copied().collect();
        for k in keys {
            self.flush(ctx, k, out);
        }
    }

    pub(crate) fn finish(&mut self, ctx: &Ctx<'_>, out: &mut Vec<u8>) {
        self.flush_all(ctx, out);
        self.blocks.clear();
    }
}

/// The template delta with its string replaced by `text`.
fn from_template(t: &Message, tool: bool, text: &str) -> Option<Message> {
    let doc = Doc::parse(&t.payload).ok()?;
    let delta = doc.root().get("delta").ok()??;
    let v = if tool {
        delta.get("toolUse").ok()??.get("input").ok()??
    } else {
        delta.get("text").ok()??
    };
    if v.kind() != Kind::String {
        return None;
    }
    Some(Message {
        headers: t.headers.clone(),
        payload: json::splice(&t.payload, &[(v.span().0, v.span().1, json::quote(text))]),
    })
}

#[cfg(all(test, feature = "test-util"))]
mod tests {
    use crate::codec::{self, Api};

    fn planned(body: &str) -> Vec<String> {
        let p = codec::plan(Api::BedrockConverse, body.as_bytes()).unwrap();
        p.verbatim
            .iter()
            .map(|&(s, e)| body[s..e].to_string())
            .collect()
    }

    #[test]
    fn plan_keeps_config_signed_reasoning_and_binary() {
        let body = r#"{"messages":[{"role":"user","content":[{"text":"hi"},{"image":{"format":"png","source":{"bytes":"iVBORw0KGgo="}}},{"toolResult":{"toolUseId":"t1","content":[{"text":"out"},{"document":{"format":"pdf","name":"d","source":{"bytes":"JVBERi0="}}}]}}]},{"role":"assistant","content":[{"reasoningContent":{"reasoningText":{"text":"think","signature":"sig=="}}},{"reasoningContent":{"redactedContent":"cmVk"}}]}],"system":[{"text":"sys"}],"inferenceConfig":{"maxTokens":10},"toolConfig":{"tools":[{"toolSpec":{"name":"x"}}],"toolChoice":{"auto":{}}}}"#;
        let kept = planned(body);
        assert_eq!(
            kept,
            vec![
                "iVBORw0KGgo=",
                "JVBERi0=",
                "think",
                "sig==",
                "cmVk",
                r#"{"maxTokens":10}"#,
                r#"{"auto":{}}"#
            ]
        );
        let p = codec::plan(Api::BedrockConverse, body.as_bytes()).unwrap();
        assert_eq!(p.binary, vec!["image/png", "application/pdf"]);
        assert!(codec::plan(Api::BedrockConverse, br#"{"messages":{}}"#).is_err());
    }
}
