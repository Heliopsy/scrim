// SPDX-License-Identifier: AGPL-3.0-only

//! The restore policy (redaction spec "Resolution follows tool policy", "Credentials are never
//! restored into commands", "Tool aliases", "Display modes", "Share and reveal").
//!
//! A [`RestoreEngine`] is built once per snapshot from `Snapshot.restore`, `Snapshot.policy`
//! and the value dictionary's metadata. For every placeholder in a response it answers resolve
//! or keep:
//!
//! 1. Credentials are always kept. So is everything while break-glass is engaged.
//! 2. Displayed text (assistant text, refusals) follows the [`DisplayMode`].
//! 3. Tool-call arguments follow the tool's [`ToolRole`]: read and search tools get display
//!    values; shell tools get them where [`crate::escape::shell`] finds the value stays data;
//!    edit tools only where the call shows the value is already in the file (it appears in the
//!    replaced text, or on a context or removed line of the same file in a patch); write,
//!    network and unknown tools get nothing. Shell and edit decisions need the complete
//!    arguments ([`RestoreEngine::needs_arguments`]); without them the placeholder is kept.
//! 4. The decision table may take a restore away, never grant one: a deny or ask rule that
//!    matches (or could match) the request `op == "restore"` with the tool's name and the
//!    value's reference, name, store and class keeps the placeholder
//!    ([`crate::Table::restricts`]). The agent identity is taken from the [`Caller`]; when it
//!    is not known, conditions on it are unknown and a rule that depends on it keeps the
//!    placeholder. `secret.labels` are the value's labels from the snapshot
//!    (`ValueEntry.labels`); a snapshot without labels (an older control plane) leaves them
//!    unknown, so a rule on them keeps the placeholder.
//!
//! [`RestoreEngine::decide`] answers for one placeholder without seeing its value (it uses
//! [`crate::escape::ValueTraits`]), which is what the streaming proxy needs: it inserts the
//! raw value, so a value that would need escaping is kept. [`RestoreEngine::restore_tool_input`]
//! rewrites complete arguments with each value escaped for its site, so values that need
//! escaping are restored too.

mod args;
mod tools;
mod values;

#[cfg(feature = "llm")]
mod llm;

use std::sync::{Arc, Mutex};

use scrim_proto::v1 as pb;

use crate::escape::{self, Refusal};
use crate::request::{Field, FieldSet, Request};
use crate::table::{DecidedBy, Table, TableError};

pub use tools::{BUILTIN_TOOLS, DisplayMode, Settings, SettingsError, ToolRole, ToolSpec};
pub use values::{LabelInterner, Labels, ValueClass, ValueIndex, ValueInfo};

#[cfg(feature = "llm")]
pub use llm::LlmRestorePolicy;

/// Why a placeholder stays a placeholder. Value-free; safe to log and audit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeepReason {
    /// The value is a credential.
    Credential,
    /// Break-glass is engaged.
    BreakGlass,
    /// Displayed text in placeholder mode.
    DisplayMode,
    /// The tool's role restores nothing here.
    Role(ToolRole),
    /// The role needs the complete arguments and they are not available (streamed).
    Streaming,
    /// Where the placeholder sits (see [`Refusal`]).
    Context(Refusal),
    /// An edit would introduce a value the file does not already hold.
    NewInFile,
    /// The decision table restricts the restore; names the rule.
    Rule(Arc<str>),
    /// The placeholder does not resolve in this snapshot.
    UnknownValue,
    /// The value needs escaping at this site, which the streaming path cannot do.
    NeedsEscaping,
}

impl KeepReason {
    /// A short machine-readable name.
    pub fn as_str(&self) -> &'static str {
        match self {
            KeepReason::Credential => "credential",
            KeepReason::BreakGlass => "break_glass",
            KeepReason::DisplayMode => "display_mode",
            KeepReason::Role(_) => "role",
            KeepReason::Streaming => "streaming",
            KeepReason::Context(_) => "context",
            KeepReason::NewInFile => "new_in_file",
            KeepReason::Rule(_) => "rule",
            KeepReason::UnknownValue => "unknown_value",
            KeepReason::NeedsEscaping => "needs_escaping",
        }
    }
}

/// The decision for one placeholder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Replace the placeholder with the value.
    Resolve,
    /// Leave it.
    Keep(KeepReason),
}

impl Verdict {
    /// Whether the verdict resolves.
    pub fn resolves(&self) -> bool {
        *self == Verdict::Resolve
    }
}

/// Where a placeholder is being resolved.
#[derive(Clone, Copy, Debug)]
pub enum At<'a> {
    /// Text the agent displays.
    Text,
    /// A tool call's arguments.
    Tool {
        /// Tool name as the model called it.
        name: &'a str,
        /// The complete arguments (JSON, or free-form input), when available.
        arguments: Option<&'a str>,
    },
}

/// Who the response is for, as far as the caller knows. Unknown parts are unknown to the
/// decision table, which keeps placeholders a rule on them could affect.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Caller {
    /// The agent identity, if established.
    pub agent: Option<crate::request::Agent>,
    /// The provider, if known.
    pub provider: Option<String>,
}

/// A resolved placeholder handed to the restorer by a [`ValueSource`].
pub struct ResolvedValue<'a> {
    /// Store reference.
    pub reference: &'a str,
    /// Class.
    pub class: ValueClass,
    /// The value. Never logged or kept.
    pub value: &'a [u8],
}

impl std::fmt::Debug for ResolvedValue<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedValue")
            .field("reference", &self.reference)
            .field("class", &self.class)
            .finish_non_exhaustive()
    }
}

/// Resolves placeholders to values for [`RestoreEngine::restore_tool_input`] and friends.
pub trait ValueSource {
    /// Resolves one complete placeholder; `None` when it is unknown.
    fn resolve(&self, placeholder: &str) -> Option<ResolvedValue<'_>>;
}

/// scrim-redact's resolver, with the index that maps its entries to references.
///
/// An entry is matched to its [`ValueInfo`] by position (`EntryId(i)` for the `i`-th
/// `ValueEntry`) when the slug agrees, else by its slug when that is unique.
#[derive(Clone, Copy)]
pub struct RedactValues<'a> {
    /// The snapshot's resolver.
    pub resolver: &'a scrim_redact::Resolver,
    /// The value index of the same snapshot.
    pub index: &'a ValueIndex,
}

impl std::fmt::Debug for RedactValues<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedactValues").finish_non_exhaustive()
    }
}

impl ValueSource for RedactValues<'_> {
    fn resolve(&self, placeholder: &str) -> Option<ResolvedValue<'_>> {
        let r = self.resolver.resolve(placeholder.as_bytes())?;
        let info = meta_info(self.index, r.meta)?;
        let class = match r.meta.class {
            scrim_redact::ValueClass::Display if info.class == ValueClass::Display => {
                ValueClass::Display
            }
            _ => ValueClass::Credential,
        };
        Some(ResolvedValue {
            reference: &info.reference,
            class,
            value: r.expose(),
        })
    }
}

fn meta_info<'a>(index: &'a ValueIndex, meta: &scrim_redact::EntryMeta) -> Option<&'a ValueInfo> {
    let slug = meta.slug.as_str();
    if let Ok(pos) = usize::try_from(meta.id.0)
        && let Some(v) = index.by_position(pos)
        && v.slug.as_ref() == slug
    {
        return Some(v);
    }
    let mut it = index.with_slug(slug);
    match (it.next(), it.next()) {
        (Some(v), None) => Some(v),
        _ => None,
    }
}

/// What a restore pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Restored {
    /// The rewritten text; `None` when nothing was resolved.
    pub text: Option<String>,
    /// Placeholders resolved, by reference.
    pub resolved: Vec<Arc<str>>,
    /// Placeholders kept, with the reference when it resolved and why.
    pub kept: Vec<(Option<Arc<str>>, KeepReason)>,
}

/// Why a snapshot's restore inputs were rejected.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RestoreError {
    /// `Snapshot.policy` failed validation.
    #[error(transparent)]
    Table(#[from] TableError),
    /// `Snapshot.restore` failed validation.
    #[error(transparent)]
    Settings(#[from] SettingsError),
}

type Cached = (String, String, Arc<args::Analysis>);

/// The restore policy of one snapshot. Cheap to share (`Arc`); every method takes `&self`.
#[derive(Debug)]
pub struct RestoreEngine {
    settings: Settings,
    table: Option<Arc<Table>>,
    values: ValueIndex,
    cache: Mutex<Option<Cached>>,
}

impl RestoreEngine {
    /// Builds the engine from its parts. `table` is the snapshot's decision table, if any.
    pub fn new(settings: Settings, table: Option<Arc<Table>>, values: ValueIndex) -> RestoreEngine {
        RestoreEngine {
            settings,
            table,
            values,
            cache: Mutex::new(None),
        }
    }

    /// Builds the engine from a snapshot: `restore`, `policy` (when present) and the metadata
    /// of `values`.
    pub fn from_snapshot(s: &pb::Snapshot) -> Result<RestoreEngine, RestoreError> {
        let settings = Settings::from_proto(s.restore.as_ref())?;
        let table = s
            .policy
            .as_ref()
            .map(Table::from_proto)
            .transpose()?
            .map(Arc::new);
        Ok(RestoreEngine::new(
            settings,
            table,
            ValueIndex::from_entries(&s.values, s.value_labels),
        ))
    }

    /// Keeps every placeholder: the state before the first snapshot.
    pub fn keep_all() -> RestoreEngine {
        RestoreEngine::new(Settings::default(), None, ValueIndex::new())
    }

    /// The settings.
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// The value index.
    pub fn values(&self) -> &ValueIndex {
        &self.values
    }

    /// The role of `tool`.
    pub fn role(&self, tool: &str) -> ToolRole {
        self.settings.tool(tool).role
    }

    /// Whether decisions for `tool` need the complete arguments, so a streaming proxy should
    /// buffer them (scrim-llm's `ToolMode::Buffered`).
    pub fn needs_arguments(&self, tool: &str) -> bool {
        self.role(tool).needs_arguments()
    }

    fn break_glass(&self) -> bool {
        self.table.as_ref().is_some_and(|t| t.break_glass())
    }

    fn restricted(&self, caller: &Caller, tool: &str, info: &ValueInfo) -> Option<KeepReason> {
        let t = self.table.as_ref()?;
        let mut req = Request {
            op: "restore".into(),
            ..Request::default()
        };
        tool.clone_into(&mut req.tool.name);
        req.secret.reference = info.reference.to_string();
        req.secret.name = info.name.to_string();
        req.secret.store = info.store.to_string();
        info.class.as_str().clone_into(&mut req.secret.class);
        let mut unknown = match &caller.agent {
            Some(a) => {
                req.agent = a.clone();
                FieldSet::EMPTY
            }
            None => FieldSet::AGENT,
        };
        match &info.labels {
            Some(l) => req.secret.labels.clone_from(l),
            None => unknown = unknown.with(Field::SecretLabels),
        }
        match &caller.provider {
            Some(p) => req.provider.clone_from(p),
            None => unknown = unknown.with(Field::Provider),
        }
        req.unknown = unknown;
        t.restricts(&req).map(|by| match by {
            DecidedBy::BreakGlass => KeepReason::BreakGlass,
            by => KeepReason::Rule(t.rule_name(by).into()),
        })
    }

    /// The checks that do not depend on where the placeholder sits.
    fn gate(
        &self,
        caller: &Caller,
        at: At<'_>,
        info: &ValueInfo,
        class: ValueClass,
    ) -> Option<KeepReason> {
        if self.break_glass() {
            return Some(KeepReason::BreakGlass);
        }
        if class == ValueClass::Credential || info.class == ValueClass::Credential {
            return Some(KeepReason::Credential);
        }
        let tool = match at {
            At::Text => {
                if self.settings.display == DisplayMode::Placeholders {
                    return Some(KeepReason::DisplayMode);
                }
                ""
            }
            At::Tool { name, .. } => {
                let role = self.role(name);
                if matches!(role, ToolRole::None | ToolRole::Write | ToolRole::Network) {
                    return Some(KeepReason::Role(role));
                }
                name
            }
        };
        self.restricted(caller, tool, info)
    }

    fn analysis(&self, tool: &str, arguments: &str) -> Arc<args::Analysis> {
        if let Ok(guard) = self.cache.lock()
            && let Some((t, a, an)) = guard.as_ref()
            && t == tool
            && a == arguments
        {
            return an.clone();
        }
        let an = Arc::new(args::analyze(
            &self.settings.tool(tool),
            arguments,
            &self.settings,
        ));
        if let Ok(mut guard) = self.cache.lock() {
            *guard = Some((tool.to_owned(), arguments.to_owned(), an.clone()));
        }
        an
    }

    /// Decides one placeholder of `reference` at `at`, without its value. Resolving means the
    /// raw value may be inserted (JSON-escaped by the caller inside JSON strings): a value
    /// that would need shell or other escaping is kept ([`KeepReason::NeedsEscaping`]); use
    /// [`RestoreEngine::restore_tool_input`] to restore those escaped.
    ///
    /// `reference` is the store reference (`ValueEntry.ref`) or, when unique, the slug. With
    /// complete arguments every occurrence of the value's slug in them must be restorable.
    pub fn decide(
        &self,
        caller: &Caller,
        at: At<'_>,
        reference: &str,
        class: ValueClass,
    ) -> Verdict {
        let Some(info) = self.values.lookup(reference) else {
            return Verdict::Keep(KeepReason::UnknownValue);
        };
        if let Some(r) = self.gate(caller, at, info, class) {
            return Verdict::Keep(r);
        }
        let At::Tool { name, arguments } = at else {
            return Verdict::Resolve;
        };
        let role = self.role(name);
        if !role.needs_arguments() {
            return Verdict::Resolve;
        }
        let Some(arguments) = arguments else {
            return Verdict::Keep(KeepReason::Streaming);
        };
        let an = self.analysis(name, arguments);
        let mut seen = false;
        for o in an.occ.iter().filter(|o| *o.slug == *info.slug) {
            seen = true;
            match &o.verdict {
                args::Verdict::Raw => {}
                args::Verdict::Escape(site) => {
                    if !info.traits.raw_is_safe(site) {
                        return Verdict::Keep(KeepReason::NeedsEscaping);
                    }
                }
                args::Verdict::Keep(r) => return Verdict::Keep(r.clone()),
            }
        }
        if seen {
            Verdict::Resolve
        } else {
            // The caller asks about a placeholder these arguments do not show.
            Verdict::Keep(KeepReason::Context(Refusal::Unsupported))
        }
    }

    /// Restores the placeholders of one complete tool call's arguments, each escaped for where
    /// it lands. JSON arguments stay valid JSON: only string literals holding a resolved
    /// placeholder are re-encoded.
    pub fn restore_tool_input(
        &self,
        caller: &Caller,
        tool: &str,
        arguments: &str,
        values: &dyn ValueSource,
    ) -> Restored {
        let an = self.analysis(tool, arguments);
        let mut out = Restored::default();
        // New decoded text per string, built lazily.
        let mut rewritten: Vec<Option<String>> = vec![None; an.strings.len()];
        let mut cursor: Vec<usize> = vec![0; an.strings.len()];
        let at = At::Tool {
            name: tool,
            arguments: Some(arguments),
        };
        for o in &an.occ {
            let src = &an.strings[o.s].decoded;
            let ph = &src[o.start..o.end];
            let decision = match values.resolve(ph) {
                None => Err((None, KeepReason::UnknownValue)),
                Some(rv) => {
                    let info = self.values.lookup(rv.reference);
                    let reference: Arc<str> =
                        info.map_or_else(|| rv.reference.into(), |i| i.reference.clone());
                    match info {
                        None => Err((Some(reference), KeepReason::UnknownValue)),
                        Some(info) => match self.gate(caller, at, info, rv.class) {
                            Some(r) => Err((Some(reference), r)),
                            None => match &o.verdict {
                                args::Verdict::Keep(r) => Err((Some(reference), r.clone())),
                                args::Verdict::Raw => std::str::from_utf8(rv.value)
                                    .map(|v| (reference.clone(), v.to_owned()))
                                    .map_err(|_| {
                                        (
                                            Some(reference.clone()),
                                            KeepReason::Context(Refusal::NotText),
                                        )
                                    }),
                                args::Verdict::Escape(site) => escape::escape(site, rv.value)
                                    .map(|v| (reference.clone(), v))
                                    .map_err(|r| (Some(reference.clone()), KeepReason::Context(r))),
                            },
                        },
                    }
                }
            };
            let buf = rewritten[o.s].get_or_insert_with(String::new);
            buf.push_str(&src[cursor[o.s]..o.start]);
            match decision {
                Ok((reference, v)) => {
                    buf.push_str(&v);
                    out.resolved.push(reference);
                }
                Err(k) => {
                    buf.push_str(ph);
                    out.kept.push(k);
                }
            }
            cursor[o.s] = o.end;
        }
        if out.resolved.is_empty() {
            return out;
        }
        let json = an.strings.first().is_some_and(|s| s.span.is_some());
        if !json {
            let mut t = rewritten[0].take().unwrap_or_default();
            t.push_str(&an.strings[0].decoded[cursor[0]..]);
            out.text = Some(t);
            return out;
        }
        let mut text = String::with_capacity(arguments.len() + 64);
        let mut pos = 0;
        for (i, s) in an.strings.iter().enumerate() {
            let (Some(mut new), Some((a, b))) = (rewritten[i].take(), s.span) else {
                continue;
            };
            new.push_str(&s.decoded[cursor[i]..]);
            text.push_str(&arguments[pos..a]);
            text.push('"');
            text.push_str(
                &escape::escape(&escape::Site::of(escape::Layer::JsonString), new.as_bytes())
                    .unwrap_or_default(),
            );
            text.push('"');
            pos = b;
        }
        text.push_str(&arguments[pos..]);
        out.text = Some(text);
        out
    }

    fn restore_plain(
        &self,
        text: &str,
        values: &dyn ValueSource,
        mut allow: impl FnMut(&ValueInfo, ValueClass) -> Option<KeepReason>,
    ) -> Restored {
        let mut out = Restored::default();
        let mut t = String::with_capacity(text.len());
        let mut pos = 0;
        for (at, p) in scrim_redact::find_placeholders(text.as_bytes()) {
            let ph = &text[at..at + p.len];
            t.push_str(&text[pos..at]);
            pos = at + p.len;
            let Some(rv) = values.resolve(ph) else {
                t.push_str(ph);
                out.kept.push((None, KeepReason::UnknownValue));
                continue;
            };
            let Some(info) = self.values.lookup(rv.reference) else {
                t.push_str(ph);
                out.kept
                    .push((Some(rv.reference.into()), KeepReason::UnknownValue));
                continue;
            };
            let verdict = allow(info, rv.class).or_else(|| {
                std::str::from_utf8(rv.value)
                    .err()
                    .map(|_| KeepReason::Context(Refusal::NotText))
            });
            if let Some(r) = verdict {
                t.push_str(ph);
                out.kept.push((Some(info.reference.clone()), r));
            } else {
                t.push_str(std::str::from_utf8(rv.value).unwrap_or_default());
                out.resolved.push(info.reference.clone());
            }
        }
        if !out.resolved.is_empty() {
            t.push_str(&text[pos..]);
            out.text = Some(t);
        }
        out
    }

    /// Restores placeholders in text the agent displays, under the display mode.
    pub fn restore_text(&self, caller: &Caller, text: &str, values: &dyn ValueSource) -> Restored {
        self.restore_plain(text, values, |info, class| {
            self.gate(caller, At::Text, info, class)
        })
    }

    /// The data-plane side of `scrim reveal`: resolves placeholders in a text or file the user
    /// hands to the CLI. Display values are revealed; credentials only when their reference
    /// matches `reveal_credential_refs`. Nothing is revealed while break-glass is engaged. The
    /// display mode and tool roles do not apply: this is the user's own terminal.
    pub fn reveal(&self, text: &str, values: &dyn ValueSource) -> Restored {
        self.restore_plain(text, values, |info, class| {
            if self.break_glass() {
                return Some(KeepReason::BreakGlass);
            }
            let credential =
                class == ValueClass::Credential || info.class == ValueClass::Credential;
            (credential && !self.settings.reveal_credential(&info.reference))
                .then_some(KeepReason::Credential)
        })
    }

    /// A scrim-redact [`scrim_redact::RestorePolicy`] for one streamed content block at `at`.
    /// It allows display values only where no position analysis is needed: displayed text in
    /// values mode, and read and search tools. Shell and edit tools need the complete
    /// arguments; buffer them and use [`RestoreEngine::restore_tool_input`].
    pub fn block_policy<'a>(&'a self, caller: &'a Caller, at: At<'a>) -> BlockPolicy<'a> {
        BlockPolicy {
            engine: self,
            caller,
            at,
        }
    }
}

/// See [`RestoreEngine::block_policy`].
#[derive(Clone, Copy, Debug)]
pub struct BlockPolicy<'a> {
    engine: &'a RestoreEngine,
    caller: &'a Caller,
    at: At<'a>,
}

impl scrim_redact::RestorePolicy for BlockPolicy<'_> {
    fn allow(&self, meta: &scrim_redact::EntryMeta) -> bool {
        let Some(info) = meta_info(&self.engine.values, meta) else {
            return false;
        };
        let class = match meta.class {
            scrim_redact::ValueClass::Display => ValueClass::Display,
            scrim_redact::ValueClass::Credential => ValueClass::Credential,
        };
        if self
            .engine
            .gate(self.caller, self.at, info, class)
            .is_some()
        {
            return false;
        }
        match self.at {
            At::Text => true,
            At::Tool { name, .. } => !self.engine.role(name).needs_arguments(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::pedantic)]
mod tests;
