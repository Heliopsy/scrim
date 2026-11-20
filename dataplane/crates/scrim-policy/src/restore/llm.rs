// SPDX-License-Identifier: AGPL-3.0-only

//! scrim-llm's `RestorePolicy` for the restore engine (feature `llm`).

use std::cell::RefCell;
use std::sync::Arc;

use scrim_llm::{
    Placeholders, Resolved, RestoreDecision, RestoreSite, SecretRef, ToolInputRestore, ToolMode,
};

use super::{At, Caller, ResolvedValue, RestoreEngine, ValueClass, ValueSource};

/// The restore engine bound to one caller, as scrim-llm's `RestorePolicy`.
///
/// Streamed placeholders are decided through [`RestoreEngine::decide`]: scrim-llm inserts the
/// raw value there (JSON-escaped inside JSON strings), so a value that needs shell or other
/// escaping at its site is kept. Complete tool calls (shell and edit tools are fed in
/// `ToolMode::Buffered`, and every call of a non-streamed response) go through
/// [`RestoreEngine::restore_tool_input`] instead, which restores such values escaped. `SecretRef` must name the value's store reference (`ValueEntry.ref`) or its slug.
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

/// Records the placeholders a restore pass asks for, resolving none.
#[derive(Default)]
struct Wanted(RefCell<Vec<String>>);

impl ValueSource for Wanted {
    fn resolve(&self, placeholder: &str) -> Option<ResolvedValue<'_>> {
        self.0.borrow_mut().push(placeholder.to_owned());
        None
    }
}

/// scrim-llm's placeholders, resolved up front for the placeholders one call needs, so their
/// values live as long as the restore pass.
struct Prefetched(Vec<(String, Resolved)>);

impl ValueSource for Prefetched {
    fn resolve(&self, placeholder: &str) -> Option<ResolvedValue<'_>> {
        let (_, r) = self.0.iter().find(|(p, _)| p == placeholder)?;
        Some(ResolvedValue {
            reference: r.reference.as_str(),
            class: class(r.class),
            value: r.value.expose(),
        })
    }
}

/// Restores a complete tool call escaped, through [`RestoreEngine::restore_tool_input`]. The
/// first pass finds which placeholders the call holds (the analysis is cached, so the second
/// pass reuses it); only those are resolved.
fn restore_tool_input(
    engine: &RestoreEngine,
    caller: &Caller,
    tool: &str,
    arguments: &str,
    values: &dyn Placeholders,
) -> ToolInputRestore {
    let wanted = Wanted::default();
    let _ = engine.restore_tool_input(caller, tool, arguments, &wanted);
    let mut found: Vec<(String, Resolved)> = Vec::new();
    for p in wanted.0.into_inner() {
        if found.iter().any(|(q, _)| *q == p) {
            continue;
        }
        if let Some(r) = values.resolve(&p) {
            found.push((p, r));
        }
    }
    let r = engine.restore_tool_input(caller, tool, arguments, &Prefetched(found));
    ToolInputRestore {
        text: r.text,
        resolved: u64::try_from(r.resolved.len()).unwrap_or(u64::MAX),
        kept: u64::try_from(r.kept.len()).unwrap_or(u64::MAX),
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

    fn restore_tool_input(
        &self,
        tool: &str,
        arguments: &str,
        values: &dyn Placeholders,
    ) -> Option<ToolInputRestore> {
        Some(restore_tool_input(
            &self.engine,
            &self.caller,
            tool,
            arguments,
            values,
        ))
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

    fn restore_tool_input(
        &self,
        tool: &str,
        arguments: &str,
        values: &dyn Placeholders,
    ) -> Option<ToolInputRestore> {
        Some(restore_tool_input(
            self,
            &Caller::default(),
            tool,
            arguments,
            values,
        ))
    }
}
