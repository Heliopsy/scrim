//! Redaction core of scrim.
//!
//! scrim sits between AI agents and model providers. Every outgoing request has every known
//! secret value replaced by a deterministic placeholder, an independent guard re-checks the exact
//! outgoing bytes, and streamed responses get placeholders restored where the tool policy allows.
//! This crate is that core. It knows nothing about HTTP, providers or policy files; the proxies
//! build on it.
//!
//! # Model
//!
//! * A [`Snapshot`] is built from the known values ([`Entry`]: id, [`RefSlug`], [`ValueClass`],
//!   [`SecretValue`]), a [`Keyring`] and a [`Config`]. It holds the [`Redactor`], the [`Guard`] and
//!   the [`Resolver`], all derived from the same values, and never changes after build.
//! * A [`SnapshotHandle`] holds the current snapshot. Rebuild off the request path and
//!   [`SnapshotHandle::store`] the result; requests [`SnapshotHandle::load`] once and keep their
//!   `Arc<Snapshot>` to the end. Until the first store, `load` returns [`Error::NotReady`] and the
//!   request must be refused.
//! * [`Snapshot::protect`] is the outbound check: redact, then guard. It returns the exact bytes to
//!   forward or an error; any error means refuse the request.
//! * Responses: one [`BlockRestorer`] per content block restores placeholders in decoded delta
//!   text, under a [`RestorePolicy`] the proxy supplies per tool call.
//!
//! # Invariants
//!
//! * No `Debug`, `Display`, error or panic message of this crate contains a value or request
//!   bytes. [`SecretValue`] prints as `<redacted>`; errors are fieldless enums.
//! * Redaction failure refuses the request; nothing here returns the unredacted input as a
//!   fallback.
//! * The redactor matches raw bytes against compiled encoded variants ([`Variant`]); it never
//!   decodes the request. The guard shares no matching code with it: it decodes the bytes into
//!   views and searches the raw values there (see [`guard`](crate::Guard)).
//! * Placeholders are `⟦scrim:<slug>:<vv><tag>⟧`, a keyed HMAC of the value, so the same value
//!   always yields the same bytes for a given key and slug, across processes and replicas.
//!   Redaction output is a pure function of input and snapshot, so prompt caches keep working.
//! * Matches are non-overlapping and leftmost-longest. Both engines ([`EngineKind`]) produce
//!   byte-identical output; the choice is only about speed.
//! * Values classed [`ValueClass::Credential`] are never restored by [`BlockRestorer`].
//! * Values shorter than [`Config::min_len`] are matched only whole (verbatim and in complete
//!   encodings). Values shorter than [`Config::short_floor`] are rejected and reported in
//!   [`BuildReport::rejected`]: they are not protected.
//!
//! # Thread safety
//!
//! [`Snapshot`], [`Redactor`], [`Guard`], [`Resolver`] and [`SnapshotHandle`] are `Send + Sync`
//! and used through `&self`. [`Workspace`], [`GuardScratch`] and [`BlockRestorer`] are per request
//! or per block and need `&mut self`; keep one per worker or stream, never share one.
//!
//! # Example
//!
//! ```
//! use std::sync::Arc;
//! use scrim_redact::*;
//!
//! let keyring = Arc::new(Keyring::new(PlaceholderKey::new(1, &[7u8; 32])?));
//! let entries = vec![Entry::new(
//!     1,
//!     RefSlug::new("db-password")?,
//!     ValueClass::Display,
//!     SecretValue::from_slice(b"hunter2-but-longer"),
//! )];
//! let handle = SnapshotHandle::new();
//! handle.store(Arc::new(Snapshot::build(entries, keyring, &Config::default())?));
//!
//! // Outbound.
//! let snap = handle.load()?;
//! let mut ws = Workspace::new();
//! let sent = snap.protect(br#"{"text":"pw is hunter2-but-longer"}"#, &mut ws)?;
//! let sent_text = std::str::from_utf8(sent.bytes)?.to_owned();
//! assert!(!sent_text.contains("hunter2"));
//! assert_eq!(sent.stats.display, 1);
//!
//! // Inbound: the model echoes the placeholder, split across two deltas.
//! let ph = &sent_text[sent_text.find('\u{27e6}').unwrap()..sent_text.rfind('\u{27e7}').unwrap() + 3];
//! let (a, b) = ph.split_at(10);
//! let mut block = BlockRestorer::new();
//! let mut shown = String::new();
//! block.push(snap.resolver(), &RestoreDisplay, &format!("it is {a}"), &mut shown);
//! block.push(snap.resolver(), &RestoreDisplay, &format!("{b}."), &mut shown);
//! block.finish(&mut shown);
//! assert_eq!(shown, "it is hunter2-but-longer.");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
// Offsets and indices are stored as u32 to keep tables small. Inputs are bounded by
// `Config::max_input`, which build rejects above u32::MAX, and pattern counts are far below it.
#![allow(clippy::cast_possible_truncation)]
// Decoders and matchers read best with short index names.
#![allow(
    clippy::many_single_char_names,
    clippy::too_many_lines,
    clippy::chunks_exact_to_as_chunks
)]

mod detect;
mod error;
mod guard;
mod guard_cache;
#[cfg(test)]
mod guard_cache_tests;
#[cfg(any(test, feature = "oracle"))]
mod guard_oracle;
#[cfg(test)]
mod guard_tests;
mod guard_tx;
mod matcher;
mod placeholder;
mod redactor;
mod restore;
mod secret;
mod shape;
mod variants;

pub use detect::{
    DetectorConfig, ENTROPY_RULE, EntropyConfig, builtin_rule_names, default_off_rule_names,
};
pub use error::{BuildError, Error, WithholdReason};
pub use guard::{Guard, GuardFinding, GuardScratch, GuardView, Verdict};
pub use matcher::{EngineChoice, EngineKind};
pub use placeholder::{
    Keyring, MAX_PERCENT_PLACEHOLDER_LEN, MAX_PLACEHOLDER_LEN, MIN_PLACEHOLDER_LEN,
    ParsedPlaceholder, PlaceholderAt, PlaceholderKey, find_placeholders, next_placeholder,
    percent_form, placeholder_for,
};
pub use redactor::{
    BuildReport, Config, GuardOutcome, Hit, Protected, Redactor, Snapshot, SnapshotHandle, Stats,
    Workspace,
};
pub use restore::{
    BlockRestorer, KeepAll, Resolved, Resolver, RestoreDisplay, RestorePolicy, RestoreStats,
    restore_text,
};
pub use secret::{Entry, EntryId, EntryMeta, RefSlug, SecretValue, ValueClass};
pub use shape::{MAX_SHAPED_LEN, MIN_SHAPED_LEN, PREFIXES, shaped_placeholder_for};
pub use variants::{B64Alphabet, DEFAULT_JSON_DEPTH, MAX_JSON_DEPTH, Variant, json_escape_into};

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]
mod tests {
    use super::*;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn shared_types_are_send_sync() {
        assert_send_sync::<Snapshot>();
        assert_send_sync::<SnapshotHandle>();
        assert_send_sync::<Redactor>();
        assert_send_sync::<Guard>();
        assert_send_sync::<Resolver>();
    }
}
