//! Placeholder resolution and the streaming restorer primitives.
//!
//! The proxy decodes each streamed delta string of a content block, passes the text through a
//! [`BlockRestorer`] (one per content block), and re-encodes what comes out. The restorer holds
//! back at most [`MAX_PLACEHOLDER_LEN`]` - 1` bytes: the tail of the text that could still become
//! a placeholder. Everything before it is emitted at once.
//!
//! What is restored is decided by a [`RestorePolicy`] the proxy supplies per tool call. Values
//! classed [`ValueClass::Credential`] are never offered to the policy and never restored by this
//! module; credentials reach their destination only through injection
//! ([`Resolver::substitute_into`]).

use std::collections::HashMap;
use std::sync::Arc;

use subtle::ConstantTimeEq;

use crate::placeholder::{
    LEAD, MAX_PLACEHOLDER_LEN, Parse, ParsedPlaceholder, find_placeholders, parse,
};
use crate::secret::{EntryMeta, SecretValue, ValueClass};

/// Decides, per resolved placeholder, whether its value may be restored.
///
/// Implementations see only [`ValueClass::Display`] entries from [`BlockRestorer`].
pub trait RestorePolicy {
    /// `true` to restore the value of `meta`, `false` to keep the placeholder.
    fn allow(&self, meta: &EntryMeta) -> bool;
}

impl<F: Fn(&EntryMeta) -> bool> RestorePolicy for F {
    fn allow(&self, meta: &EntryMeta) -> bool {
        self(meta)
    }
}

/// Keeps every placeholder (unknown tools, network-capable tools, placeholder display mode).
#[derive(Clone, Copy, Debug, Default)]
pub struct KeepAll;

impl RestorePolicy for KeepAll {
    fn allow(&self, _: &EntryMeta) -> bool {
        false
    }
}

/// Restores every display value.
#[derive(Clone, Copy, Debug, Default)]
pub struct RestoreDisplay;

impl RestorePolicy for RestoreDisplay {
    fn allow(&self, _: &EntryMeta) -> bool {
        true
    }
}

pub(crate) struct ResolverEntry {
    pub meta: EntryMeta,
    pub value: SecretValue,
}

/// A resolved placeholder: the entry's metadata and, behind [`Resolved::expose`], its value.
pub struct Resolved<'a> {
    /// Entry metadata.
    pub meta: &'a EntryMeta,
    value: &'a SecretValue,
}

impl<'a> Resolved<'a> {
    /// The secret bytes.
    pub fn expose(&self) -> &'a [u8] {
        self.value.expose()
    }
}

impl std::fmt::Debug for Resolved<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolved")
            .field("meta", self.meta)
            .finish_non_exhaustive()
    }
}

/// Maps placeholders made with any key in the keyring back to entries.
pub struct Resolver {
    map: HashMap<(u8, [u8; 8]), u32>,
    entries: Arc<[ResolverEntry]>,
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolver")
            .field("placeholders", &self.map.len())
            .finish_non_exhaustive()
    }
}

impl Resolver {
    pub(crate) fn new(map: HashMap<(u8, [u8; 8]), u32>, entries: Arc<[ResolverEntry]>) -> Self {
        Self { map, entries }
    }

    pub(crate) fn entries(&self) -> &[ResolverEntry] {
        &self.entries
    }

    /// Resolves one complete placeholder (exactly its bytes, nothing around it).
    pub fn resolve(&self, placeholder: &[u8]) -> Option<Resolved<'_>> {
        match parse(placeholder) {
            Parse::Complete(p) if p.len == placeholder.len() => self.resolve_parsed(&p),
            _ => None,
        }
    }

    fn resolve_parsed(&self, p: &ParsedPlaceholder<'_>) -> Option<Resolved<'_>> {
        let (&(ver, tag), &idx) = self.map.get_key_value(&(p.version, p.tag))?;
        let e = &self.entries[idx as usize];
        // The map lookup already matched; compare again in constant time so the acceptance
        // decision does not depend on how many tag bytes agree, and require the slug to match.
        let tag_ok = tag.ct_eq(&p.tag);
        let ver_ok = ver.ct_eq(&p.version);
        let slug_ok = e.meta.slug.as_str().as_bytes().ct_eq(p.slug);
        if bool::from(tag_ok & ver_ok & slug_ok) {
            Some(Resolved {
                meta: &e.meta,
                value: &e.value,
            })
        } else {
            None
        }
    }

    /// The span of a genuine placeholder (one that resolves with this keyring) in `bytes` that
    /// covers `[a, b)`, if any. Text inside such a placeholder is ours, not a leaked value, so the
    /// redactor and the guard leave it alone. A placeholder-shaped string that does not resolve
    /// gives no protection to what it contains.
    pub fn covering(&self, bytes: &[u8], a: usize, b: usize) -> Option<(usize, usize)> {
        let lo = a.saturating_sub(MAX_PLACEHOLDER_LEN);
        let hi = (a + 1).min(bytes.len());
        for p in memchr::memrchr_iter(LEAD, &bytes[lo..hi]) {
            let p = lo + p;
            if let Parse::Complete(ph) = parse(&bytes[p..]) {
                if p + ph.len >= b && self.resolve_parsed(&ph).is_some() {
                    return Some((p, p + ph.len));
                }
                return None;
            }
        }
        None
    }

    /// Copies `input` to `out` with every placeholder whose entry `allow` accepts replaced by its
    /// value. Unknown or refused placeholders are copied unchanged. Returns the number replaced.
    ///
    /// This sees credentials. It is the primitive for credential injection at the network edge
    /// (the tool proxy calls it with a predicate that checks the destination binding) and for the
    /// CLI `reveal`; never use it to restore text the model wrote into a tool call.
    pub fn substitute_into(
        &self,
        input: &[u8],
        out: &mut Vec<u8>,
        allow: &dyn Fn(&EntryMeta) -> bool,
    ) -> usize {
        let mut pos = 0;
        let mut n = 0;
        for (at, p) in find_placeholders(input) {
            if let Some(r) = self.resolve_parsed(&p)
                && allow(r.meta)
            {
                out.extend_from_slice(&input[pos..at]);
                out.extend_from_slice(r.expose());
                pos = at + p.len;
                n += 1;
            }
        }
        out.extend_from_slice(&input[pos..]);
        n
    }
}

/// Counts from one [`BlockRestorer::push`] or [`BlockRestorer::finish`] call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RestoreStats {
    /// Placeholders replaced by their value.
    pub restored: u32,
    /// Well-formed placeholders left in place (unknown, credential, policy refused, or a value
    /// that is not valid UTF-8 and so cannot be put in text).
    pub kept: u32,
}

/// Restores placeholders in the text of one content block, chunk by chunk.
///
/// Feed every decoded delta of the block to [`BlockRestorer::push`] in order and call
/// [`BlockRestorer::finish`] when the block ends. The concatenated output equals restoring the
/// whole text at once, whatever the chunk boundaries. Memory is bounded by
/// [`MAX_PLACEHOLDER_LEN`] bytes per block.
#[derive(Default)]
pub struct BlockRestorer {
    held: String,
}

impl std::fmt::Debug for BlockRestorer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockRestorer")
            .field("held_bytes", &self.held.len())
            .finish()
    }
}

impl BlockRestorer {
    /// A restorer with nothing held.
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes currently held back (never more than `MAX_PLACEHOLDER_LEN - 1`).
    pub fn held_len(&self) -> usize {
        self.held.len()
    }

    /// Processes the next delta, appending everything that can no longer be part of a
    /// placeholder to `out`.
    pub fn push(
        &mut self,
        resolver: &Resolver,
        policy: &dyn RestorePolicy,
        delta: &str,
        out: &mut String,
    ) -> RestoreStats {
        if self.held.is_empty() {
            let hold = process(resolver, policy, delta, out, false);
            self.held.push_str(&delta[hold.1..]);
            return hold.0;
        }
        self.held.push_str(delta);
        let held = std::mem::take(&mut self.held);
        let (st, h) = process(resolver, policy, &held, out, false);
        self.held = held;
        self.held.drain(..h);
        st
    }

    /// Ends the block: emits held bytes. An incomplete placeholder is emitted unchanged.
    pub fn finish(&mut self, out: &mut String) {
        out.push_str(&self.held);
        self.held.clear();
    }
}

/// Restores `text` into `out`. Returns stats and the offset from which bytes are held back
/// (`text.len()` if nothing is held, or always when `at_end`).
fn process(
    resolver: &Resolver,
    policy: &dyn RestorePolicy,
    text: &str,
    out: &mut String,
    at_end: bool,
) -> (RestoreStats, usize) {
    let b = text.as_bytes();
    let mut st = RestoreStats::default();
    let mut pos = 0;
    let mut i = 0;
    while let Some(off) = memchr::memchr(LEAD, &b[i..]) {
        let at = i + off;
        match parse(&b[at..]) {
            Parse::Complete(p) => {
                let end = at + p.len;
                let restored = resolver.resolve_parsed(&p).and_then(|r| {
                    if r.meta.class == ValueClass::Display && policy.allow(r.meta) {
                        std::str::from_utf8(r.expose()).ok()
                    } else {
                        None
                    }
                });
                if let Some(v) = restored {
                    out.push_str(&text[pos..at]);
                    out.push_str(v);
                    st.restored += 1;
                } else {
                    out.push_str(&text[pos..end]);
                    st.kept += 1;
                }
                pos = end;
                i = end;
            }
            Parse::Prefix if !at_end => {
                out.push_str(&text[pos..at]);
                return (st, at);
            }
            Parse::Prefix | Parse::Invalid => i = at + 1,
        }
    }
    out.push_str(&text[pos..]);
    (st, text.len())
}

/// Restores a complete text in one call (no streaming).
pub fn restore_text(
    resolver: &Resolver,
    policy: &dyn RestorePolicy,
    text: &str,
    out: &mut String,
) -> RestoreStats {
    process(resolver, policy, text, out, true).0
}

const _: () = assert!(MAX_PLACEHOLDER_LEN < 128);
