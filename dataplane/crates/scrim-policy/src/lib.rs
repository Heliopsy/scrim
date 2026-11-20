// SPDX-License-Identifier: AGPL-3.0-only

//! Data-plane policy for scrim.

#![forbid(unsafe_code)]

pub mod glob;
pub mod request;
pub mod table;

pub use glob::{Glob, GlobError, glob_match};
pub use request::{Agent, Dest, Field, FieldSet, Request, Secret, Tool};
pub use table::{
    AskReason, Clause, Condition, DEFAULT_RULE, DecidedBy, Decision, Effect, Matcher, Outcome,
    Rule, RuleId, TABLE_FORMAT, Table, TableError,
};
