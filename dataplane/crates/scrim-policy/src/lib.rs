// SPDX-License-Identifier: AGPL-3.0-only

//! Data-plane policy for scrim.
//!
//! * [`Table`]: the decision table the control plane compiles from CEL rules (design D7,
//!   `Policy.table`, `table_format` 1). [`Table::evaluate`] decides allow, deny or "ask the
//!   control plane" locally, exactly as the Go reference `policy.Snapshot.Evaluate` does.
//! * [`RestoreEngine`]: the per-tool restore policy for placeholders in responses (redaction
//!   spec "Resolution follows tool policy"), with tool roles and aliases, display modes and the
//!   data-plane side of `scrim reveal`.
//! * [`escape`]: context-aware escaping of restored values (redaction spec "Context-aware
//!   escaping"): shell words, heredocs, interpreter `-c` strings, SQL, JSON and YAML, and
//!   refusal wherever a value would become code.
//!
//! The crate never holds a secret value. The restore engine keeps only metadata and
//! [`escape::ValueTraits`]; values pass through [`ValueSource`] for the length of one call.
//!
//! # Example
//!
//! ```
//! use scrim_policy::{At, Caller, RestoreEngine, Settings, ValueClass, ValueIndex, ValueInfo};
//! use scrim_policy::escape::ValueTraits;
//!
//! let mut values = ValueIndex::new();
//! values.push(ValueInfo {
//!     reference: "bao://kv/app#greeting".into(),
//!     slug: "greeting".into(),
//!     class: ValueClass::Display,
//!     name: "".into(),
//!     store: "bao".into(),
//!     traits: ValueTraits::of(b"hello world"),
//! });
//! let engine = RestoreEngine::new(Settings::standard(), None, values);
//! let ph = "\u{27e6}scrim:greeting:010123456789abcdef\u{27e7}";
//! let args = format!(r#"{{"command":"echo {ph}"}}"#);
//! let at = At::Tool { name: "Bash", arguments: Some(&args) };
//! // The value has a space: inserted raw it would be two words, so the streaming path keeps it.
//! assert!(!engine.decide(&Caller::default(), at, "bao://kv/app#greeting", ValueClass::Display).resolves());
//! ```

#![forbid(unsafe_code)]
// The lexers and analysers read best as one state machine per language, with short index names.
#![allow(clippy::too_many_lines, clippy::many_single_char_names)]

pub mod escape;
pub mod glob;
pub mod request;
pub mod restore;
pub mod table;

pub use glob::{Glob, GlobError, glob_match};
pub use request::{Agent, Dest, Field, FieldSet, Request, Secret, Tool};
#[cfg(feature = "llm")]
pub use restore::LlmRestorePolicy;
pub use restore::{
    At, BlockPolicy, Caller, DisplayMode, KeepReason, RedactValues, ResolvedValue, RestoreEngine,
    RestoreError, Restored, Settings, SettingsError, ToolRole, ToolSpec, ValueClass, ValueIndex,
    ValueInfo, ValueSource, Verdict,
};
pub use table::{
    AskReason, Clause, Condition, DEFAULT_RULE, DecidedBy, Decision, Effect, Matcher, Outcome,
    Rule, RuleId, TABLE_FORMAT, Table, TableError,
};
