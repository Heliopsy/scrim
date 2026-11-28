// SPDX-License-Identifier: AGPL-3.0-only

//! The production engine: the `scrim-redact` core behind this crate's engine traits (feature
//! `redact`).
//!
//! One [`scrim_redact::Snapshot`] provides the redactor, the guard and the resolver; the
//! adapters here only translate types. The redactor and the guard stay independent: the
//! [`Redactor`] adapter calls the core's redactor, the [`Guard`] adapter the core's guard, which
//! shares no matching code with it.
//!
//! ```ignore
//! let core = Arc::new(scrim_redact::Snapshot::build(entries, keyring, &config)?);
//! let refs = vec![(EntryId(0), SecretRef::new("bao://kv/agents/github#token"))];
//! let engine = CoreEngine::new(core, refs);
//! cell.store(engine.snapshot(version, policy, BinaryPolicy::Pass));
//! ```

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use scrim_redact as rc;

use crate::codec::PlanCache;

use crate::engine::{
    BinaryPolicy, EngineError, Guard, GuardVerdict, PlaceholderMatch, Placeholders, RedactReport,
    Redactor, RemotePolicy, Resolved, RestorePolicy, ScopedRedaction, SecretRef, SecretValue,
    Snapshot, ValueClass,
};

struct Inner {
    snap: Arc<rc::Snapshot>,
    refs: HashMap<rc::EntryId, SecretRef>,
    /// Plans of conversation elements seen under this snapshot.
    plan_cache: Option<PlanCache>,
}

impl Inner {
    /// The reference an entry stands for. Every entry the data plane builds has one; the slug is
    /// a value-free fallback.
    fn reference(&self, meta: &rc::EntryMeta) -> SecretRef {
        self.refs
            .get(&meta.id)
            .cloned()
            .unwrap_or_else(|| SecretRef::new(meta.slug.as_str()))
    }

    fn reference_of(&self, id: rc::EntryId) -> SecretRef {
        match self.refs.get(&id) {
            Some(r) => r.clone(),
            None => self.snap.resolver().meta(id).map_or_else(
                || SecretRef::new("unknown"),
                |m| SecretRef::new(m.slug.as_str()),
            ),
        }
    }
}

fn class(c: rc::ValueClass) -> ValueClass {
    match c {
        rc::ValueClass::Credential => ValueClass::Credential,
        rc::ValueClass::Display => ValueClass::Display,
    }
}

/// A built `scrim-redact` snapshot plus the store reference of each entry, ready to hand out
/// the engine trait objects. Cheap to clone.
#[derive(Clone)]
pub struct CoreEngine {
    inner: Arc<Inner>,
}

impl fmt::Debug for CoreEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoreEngine")
            .field("report", self.inner.snap.report())
            .finish_non_exhaustive()
    }
}

impl CoreEngine {
    /// Wraps `snap`. `refs` names the secret reference of each entry id, for audit events.
    pub fn new(
        snap: Arc<rc::Snapshot>,
        refs: impl IntoIterator<Item = (rc::EntryId, SecretRef)>,
    ) -> Self {
        // The plan cache follows `redaction.redactor-cache`, a quarter of its size: it holds
        // whole messages, the redactor's segments are content blocks.
        let entries = snap.redactor().cache_entries();
        Self {
            inner: Arc::new(Inner {
                plan_cache: (entries > 0).then(|| PlanCache::new((entries / 4).max(1))),
                snap,
                refs: refs.into_iter().collect(),
            }),
        }
    }

    /// The core snapshot.
    pub fn core(&self) -> &Arc<rc::Snapshot> {
        &self.inner.snap
    }

    /// This core's redactor and guard, for a [`crate::Admission`] that narrows a caller's
    /// redaction to a core built from fewer values.
    pub fn redaction(&self) -> ScopedRedaction {
        ScopedRedaction {
            redactor: Arc::new(CoreRedactor(self.inner.clone())),
            guard: Arc::new(CoreGuard(self.inner.clone())),
        }
    }

    /// The engine snapshot for the proxy: this core's redactor, guard and placeholders with
    /// `policy` deciding restores. Set [`Snapshot::routes`] to ship routes with it.
    pub fn snapshot(
        &self,
        version: u64,
        policy: Arc<dyn RestorePolicy>,
        binary: BinaryPolicy,
    ) -> Snapshot {
        Snapshot {
            version,
            redactor: Arc::new(CoreRedactor(self.inner.clone())),
            guard: Arc::new(CoreGuard(self.inner.clone())),
            placeholders: Arc::new(CorePlaceholders(self.inner.clone())),
            policy,
            binary,
            remote: RemotePolicy::default(),
            routes: None,
            gate: None,
        }
    }
}

/// [`Redactor`] over the core's redactor.
struct CoreRedactor(Arc<Inner>);

impl Redactor for CoreRedactor {
    fn redact(&self, input: &[u8], out: &mut Vec<u8>) -> Result<RedactReport, EngineError> {
        let inner = &self.0;
        let mut ids: Vec<rc::EntryId> = Vec::new();
        let mut detectors: Vec<String> = Vec::new();
        let stats = inner
            .snap
            .redactor()
            .redact_append_with(input, out, &mut |hit| match hit {
                rc::Hit::Known { meta, .. } => {
                    if !ids.contains(&meta.id) {
                        ids.push(meta.id);
                    }
                }
                rc::Hit::Detected { rule, .. } => {
                    if !detectors.iter().any(|d| d == rule) {
                        detectors.push(rule.to_owned());
                    }
                }
            })
            .map_err(|e| EngineError::new(e.to_string()))?;
        Ok(RedactReport {
            replacements: usize::try_from(stats.total()).unwrap_or(usize::MAX),
            refs: ids.into_iter().map(|id| inner.reference_of(id)).collect(),
            detectors,
        })
    }

    fn plan_cache(&self) -> Option<&PlanCache> {
        self.0.plan_cache.as_ref()
    }
}

thread_local! {
    /// Guard buffers, reused per worker thread and wiped after every check.
    static SCRATCH: RefCell<rc::GuardScratch> = RefCell::new(rc::GuardScratch::new());
}

/// [`Guard`] over the core's guard.
struct CoreGuard(Arc<Inner>);

impl Guard for CoreGuard {
    fn check(&self, outgoing: &[u8]) -> Result<GuardVerdict, EngineError> {
        let inner = &self.0;
        let run = |scratch: &mut rc::GuardScratch| {
            let verdict = match inner.snap.guard().check(outgoing, scratch) {
                rc::Verdict::Clean => GuardVerdict::Clean,
                rc::Verdict::Repaired { bytes, findings } => GuardVerdict::Repaired {
                    bytes: bytes.to_vec(),
                    refs: refs_of(inner, findings),
                },
                rc::Verdict::Withhold(_) => GuardVerdict::Refused { refs: Vec::new() },
            };
            scratch.wipe();
            verdict
        };
        SCRATCH.with(|cell| match cell.try_borrow_mut() {
            Ok(mut scratch) => Ok(run(&mut scratch)),
            // Re-entered on the same thread (never expected): use fresh buffers.
            Err(_) => Ok(run(&mut rc::GuardScratch::new())),
        })
    }
}

fn refs_of(inner: &Inner, findings: &[rc::GuardFinding]) -> Vec<SecretRef> {
    let mut out: Vec<SecretRef> = Vec::new();
    for f in findings {
        let r = inner.reference_of(f.entry);
        if !out.contains(&r) {
            out.push(r);
        }
    }
    out
}

/// [`Placeholders`] over the core's placeholder syntax and resolver.
struct CorePlaceholders(Arc<Inner>);

impl Placeholders for CorePlaceholders {
    fn max_len(&self) -> usize {
        // Either form: the percent form (`%E2%9F%A6...%E2%9F%A7`) is the longer one.
        rc::MAX_PERCENT_PLACEHOLDER_LEN
    }

    fn find(&self, text: &str) -> Option<PlaceholderMatch> {
        rc::next_placeholder(text.as_bytes()).map(|at| match at {
            rc::PlaceholderAt::Complete { start, end } => PlaceholderMatch::Complete { start, end },
            rc::PlaceholderAt::Partial { start } => PlaceholderMatch::Partial { start },
        })
    }

    fn resolve(&self, placeholder: &str) -> Option<Resolved> {
        let inner = &self.0;
        let r = inner.snap.resolver().resolve(placeholder.as_bytes())?;
        // A percent-form placeholder sat in percent-encoded text; its value lands there encoded.
        let value = if placeholder.starts_with('%') {
            percent_encode(r.expose())
        } else {
            r.expose().to_vec()
        };
        Some(Resolved {
            reference: inner.reference(r.meta),
            class: class(r.meta.class),
            value: Arc::new(SecretValue::new(value)),
        })
    }
}

/// Percent-encodes every byte but RFC 3986 unreserved characters.
fn percent_encode(v: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Vec::with_capacity(v.len() * 3);
    for &b in v {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b);
        } else {
            out.extend_from_slice(&[b'%', HEX[usize::from(b >> 4)], HEX[usize::from(b & 15)]]);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::KeepAll;

    const VALUE: &str = "core-adapter-value-0123456789";

    fn engine() -> CoreEngine {
        let keyring = Arc::new(rc::Keyring::new(
            rc::PlaceholderKey::new(1, &[5u8; 32]).unwrap(),
        ));
        let entries = vec![rc::Entry::new(
            3,
            rc::RefSlug::new("db").unwrap(),
            rc::ValueClass::Display,
            rc::SecretValue::from_slice(VALUE.as_bytes()),
        )];
        let snap = rc::Snapshot::build(entries, keyring, &rc::Config::default()).unwrap();
        CoreEngine::new(
            Arc::new(snap),
            [(rc::EntryId(3), SecretRef::new("bao://kv/db#password"))],
        )
    }

    #[test]
    fn redacts_appends_and_names_the_reference() {
        let s = engine().snapshot(1, Arc::new(KeepAll), BinaryPolicy::Pass);
        let mut out = b"prefix:".to_vec();
        let r = s
            .redactor
            .redact(format!("x {VALUE} y").as_bytes(), &mut out)
            .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("prefix:x \u{27e6}scrim:db:01"), "{text}");
        assert!(!text.contains(VALUE));
        assert_eq!(r.replacements, 1);
        assert_eq!(r.refs, vec![SecretRef::new("bao://kv/db#password")]);
    }

    #[test]
    fn guard_repairs_and_placeholders_resolve() {
        let s = engine().snapshot(1, Arc::new(KeepAll), BinaryPolicy::Pass);
        assert!(matches!(
            s.guard.check(b"nothing here").unwrap(),
            GuardVerdict::Clean
        ));
        let GuardVerdict::Repaired { bytes, refs } =
            s.guard.check(format!("leak {VALUE}").as_bytes()).unwrap()
        else {
            panic!("guard did not repair");
        };
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains(VALUE));
        assert_eq!(refs, vec![SecretRef::new("bao://kv/db#password")]);

        let start = text.find('\u{27e6}').unwrap();
        let ph = &text[start..];
        assert_eq!(
            s.placeholders.find(&text),
            Some(PlaceholderMatch::Complete {
                start,
                end: text.len()
            })
        );
        assert_eq!(
            s.placeholders.find(&text[..text.len() - 3]),
            Some(PlaceholderMatch::Partial { start })
        );
        let r = s.placeholders.resolve(ph).unwrap();
        assert_eq!(r.value.expose(), VALUE.as_bytes());
        assert_eq!(r.class, ValueClass::Display);
        assert!(!format!("{r:?}").contains(VALUE));
        assert!(!format!("{:?}", engine()).contains(VALUE));
        assert!(
            s.placeholders
                .resolve("\u{27e6}scrim:db:01ffffffffffffffff\u{27e7}")
                .is_none()
        );
    }

    #[test]
    fn header_placeholders_are_ascii_and_resolve() {
        let s = engine().snapshot(1, Arc::new(KeepAll), BinaryPolicy::Pass);
        let mut h = http::HeaderMap::new();
        h.insert(
            "x-debug-context",
            http::HeaderValue::from_str(&format!("db=\"{VALUE}\"; q=1")).unwrap(),
        );
        let head =
            crate::head::prepare(&s, &http::Method::POST, "/v1/messages", None, &mut h).unwrap();
        assert_eq!(head.report.replacements, 1);
        let v = h["x-debug-context"].as_bytes();
        // RFC 9110 field-value: visible ASCII, space and tab only.
        assert!(
            v.iter()
                .all(|&b| b == b' ' || b == b'\t' || b.is_ascii_graphic()),
            "{}",
            String::from_utf8_lossy(v)
        );
        let v = std::str::from_utf8(v).unwrap();
        assert!(!v.contains(VALUE));
        let start = v.find("%E2%9F%A6scrim:db:01").unwrap();
        let Some(PlaceholderMatch::Complete { start: from, end }) = s.placeholders.find(v) else {
            panic!("percent form not found in {v}");
        };
        assert_eq!(from, start);
        assert_eq!(&v[end..], "\"; q=1");
        let r = s.placeholders.resolve(&v[from..end]).unwrap();
        assert_eq!(r.value.expose(), VALUE.as_bytes());
        // The same bytes pass the guard again unchanged.
        assert!(matches!(
            s.guard.check(v.as_bytes()).unwrap(),
            GuardVerdict::Clean
        ));
    }
}
