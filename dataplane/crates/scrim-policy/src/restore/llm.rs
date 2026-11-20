// SPDX-License-Identifier: AGPL-3.0-only

//! scrim-llm's `RestorePolicy` for the restore engine (feature `llm`).

use std::sync::Arc;

use scrim_llm::{RestoreDecision, RestoreSite, SecretRef, ToolMode};

use super::{At, Caller, RestoreEngine, ValueClass};

/// The restore engine bound to one caller, as scrim-llm's `RestorePolicy`.
///
/// scrim-llm inserts the raw value (JSON-escaped inside JSON strings), so this answers through
/// [`RestoreEngine::decide`]: a value that needs shell or other escaping at its site is kept.
/// Shell and edit tools are fed in `ToolMode::Buffered`, so their decisions see the complete
/// arguments. `SecretRef` must name the value's store reference (`ValueEntry.ref`) or its slug.
#[derive(Clone, Debug)]
pub struct LlmRestorePolicy {
    engine: Arc<RestoreEngine>,
    caller: Caller,
}

impl LlmRestorePolicy {
    /// Binds `engine` to `caller`. With [`Caller::default`] the agent identity is unknown to
    /// the decision table, so any deny or ask rule on it keeps placeholders.
    pub fn new(engine: Arc<RestoreEngine>, caller: Caller) -> LlmRestorePolicy {
        LlmRestorePolicy { engine, caller }
    }
}

fn class(c: scrim_llm::ValueClass) -> ValueClass {
    match c {
        scrim_llm::ValueClass::Display => ValueClass::Display,
        scrim_llm::ValueClass::Credential => ValueClass::Credential,
    }
}

fn decide(
    engine: &RestoreEngine,
    caller: &Caller,
    site: &RestoreSite<'_>,
    reference: &SecretRef,
    c: scrim_llm::ValueClass,
) -> RestoreDecision {
    let at = match *site {
        RestoreSite::Text => At::Text,
        RestoreSite::ToolInput { tool, arguments } => At::Tool {
            name: tool,
            arguments,
        },
    };
    if engine
        .decide(caller, at, reference.as_str(), class(c))
        .resolves()
    {
        RestoreDecision::Resolve
    } else {
        RestoreDecision::Keep
    }
}

fn mode(engine: &RestoreEngine, tool: &str) -> ToolMode {
    if engine.needs_arguments(tool) {
        ToolMode::Buffered
    } else {
        ToolMode::Stream
    }
}

impl scrim_llm::RestorePolicy for LlmRestorePolicy {
    fn decide(
        &self,
        site: &RestoreSite<'_>,
        reference: &SecretRef,
        class: scrim_llm::ValueClass,
    ) -> RestoreDecision {
        decide(&self.engine, &self.caller, site, reference, class)
    }

    fn tool_mode(&self, tool: &str) -> ToolMode {
        mode(&self.engine, tool)
    }
}

/// The engine with an unknown caller.
impl scrim_llm::RestorePolicy for RestoreEngine {
    fn decide(
        &self,
        site: &RestoreSite<'_>,
        reference: &SecretRef,
        class: scrim_llm::ValueClass,
    ) -> RestoreDecision {
        decide(self, &Caller::default(), site, reference, class)
    }

    fn tool_mode(&self, tool: &str) -> ToolMode {
        mode(self, tool)
    }
}
