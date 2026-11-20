//! The redactor, the snapshot that bundles it with the guard and resolver, and the swap holder.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use arc_swap::ArcSwapOption;

use crate::detect::{DetectorConfig, Detectors};
use crate::error::{BuildError, Error};
use crate::guard::{Guard, GuardFinding, GuardInput, GuardScratch, Verdict};
use crate::matcher::{Cursor, Engine, EngineChoice, EngineKind, PatternSet, build_engine};
use crate::placeholder::{Keyring, MAX_PLACEHOLDER_LEN, write_placeholder};
use crate::restore::{Resolver, ResolverEntry};
use crate::secret::{Entry, EntryId, EntryMeta, RefSlug, ValueClass};
use crate::variants::{DEFAULT_JSON_DEPTH, MAX_JSON_DEPTH, Variant, variants};

/// Redaction settings. Canonical configuration keys are given per field.
#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    /// `redaction.min_length` (default 8): values shorter than this are short values, matched
    /// only verbatim and in whole encodings, never as base64 fragments, and listed by status.
    pub min_len: usize,
    /// `redaction.short_floor` (default 4, at least 4): values shorter than this cannot be matched
    /// without wrecking traffic; they are rejected at build and listed in the
    /// [`BuildReport::rejected`] ids.
    pub short_floor: usize,
    /// `redaction.engine` (default `auto`).
    pub engine: EngineChoice,
    /// `redaction.engine_threshold` (default 256 patterns): with `auto`, sets with more compiled
    /// patterns use the hash-window engine. Aho-Corasick is only faster while its SIMD (Teddy)
    /// prefilter applies, which is up to 64 patterns per automaton; the engine splits sets of up
    /// to 256 patterns into such automata. Above that the hash-window engine wins (measured, see
    /// the crate README).
    pub engine_threshold: usize,
    /// `redaction.max_body_bytes` (default 64 MiB): larger inputs are refused.
    pub max_input: usize,
    /// `redaction.guard.max_repairs` (default 64): more guard interventions than this in one
    /// body withhold the request instead of repairing it.
    pub guard_max_repairs: usize,
    /// `redaction.json_depth` (default 3, 2 to [`MAX_JSON_DEPTH`]): how many levels of JSON
    /// text inside JSON strings are covered. The redactor compiles each value escaped up to this
    /// many times and the guard unescapes the bytes as often. Two is a tool call's `arguments`
    /// (JSON in a JSON string); three is JSON inside those, such as a tool result holding
    /// `JSON.stringify` output that itself carries a JSON string.
    pub json_depth: usize,
    /// `redaction.detectors.*`.
    pub detectors: DetectorConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            min_len: 8,
            short_floor: 4,
            engine: EngineChoice::Auto,
            engine_threshold: 256,
            max_input: 64 << 20,
            guard_max_repairs: 64,
            json_depth: DEFAULT_JSON_DEPTH,
            detectors: DetectorConfig::default(),
        }
    }
}

/// What a build produced. Contains counts and ids only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildReport {
    /// Distinct values compiled.
    pub values: usize,
    /// Entries dropped because another entry with a lower id holds the same value.
    pub duplicates: usize,
    /// Values below [`Config::min_len`] (matched only whole).
    pub short: usize,
    /// Entries rejected for being below [`Config::short_floor`]. These values are NOT protected.
    pub rejected: Vec<EntryId>,
    /// Compiled patterns (values times distinct encoded variants).
    pub patterns: usize,
    /// Engine in use.
    pub engine: EngineKind,
}

/// Hit counts of one redaction. No values, no positions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Known credential values replaced.
    pub credential: u32,
    /// Known display values replaced.
    pub display: u32,
    /// Fallback detector matches replaced.
    pub detected: u32,
}

impl Stats {
    /// Total replacements.
    pub fn total(&self) -> u32 {
        self.credential + self.display + self.detected
    }
}

/// One replacement, reported through [`Redactor::redact_with`]. Positions refer to the input.
#[derive(Clone, Copy, Debug)]
pub enum Hit<'a> {
    /// A known value in one of its encoded forms.
    Known {
        /// Entry metadata.
        meta: &'a EntryMeta,
        /// Which encoding matched.
        variant: Variant,
        /// Start offset in the input.
        start: usize,
        /// End offset in the input.
        end: usize,
    },
    /// A fallback detector match.
    Detected {
        /// Rule name (`aws-access-key-id`, `high-entropy`, ...).
        rule: &'static str,
        /// Start offset in the input.
        start: usize,
        /// End offset in the input.
        end: usize,
    },
}

pub(crate) struct CompiledEntry {
    pub meta: EntryMeta,
    pub placeholder: Box<[u8]>,
}

/// Replaces known values and detector matches with placeholders. Immutable, `Send + Sync`.
pub struct Redactor {
    entries: Vec<CompiledEntry>,
    set: PatternSet,
    engine: Box<dyn Engine>,
    kind: EngineKind,
    detectors: Detectors,
    keyring: Arc<Keyring>,
    det_slugs: Vec<(&'static str, RefSlug)>,
    resolver: Arc<Resolver>,
    max_input: usize,
}

impl std::fmt::Debug for Redactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redactor")
            .field("values", &self.entries.len())
            .field("patterns", &self.set.len())
            .field("engine", &self.kind)
            .finish_non_exhaustive()
    }
}

impl Redactor {
    /// Writes `input` with every known value and detector match replaced into `out` (cleared
    /// first). Output is a pure function of the input and the snapshot, so an unchanged prefix
    /// redacts to identical bytes on every request.
    ///
    /// Does not allocate when `out` already has enough capacity.
    pub fn redact(&self, input: &[u8], out: &mut Vec<u8>) -> Result<Stats, Error> {
        self.redact_with(input, out, &mut |_| {})
    }

    /// Like [`Redactor::redact`], and reports each replacement to `on_hit` (for the audit log).
    pub fn redact_with(
        &self,
        input: &[u8],
        out: &mut Vec<u8>,
        on_hit: &mut dyn FnMut(Hit<'_>),
    ) -> Result<Stats, Error> {
        if input.len() > self.max_input {
            return Err(Error::InputTooLarge);
        }
        out.clear();
        out.reserve(input.len() + input.len() / 16 + MAX_PLACEHOLDER_LEN);
        let mut st = Stats::default();
        let mut cur = Cursor::default();
        let mut pos = 0;
        while let Some(m) = self.engine.next(&self.set, input, &mut cur) {
            if let Some((ps, pe)) = self.resolver.covering(input, m.start, m.end)
                && ps >= pos
            {
                // Inside a genuine placeholder from an earlier turn: keep it byte for byte.
                self.gap(input, pos, pe, out, &mut st, on_hit);
                pos = pe;
                cur.seek(pe);
                continue;
            }
            self.gap(input, pos, m.start, out, &mut st, on_hit);
            let info = self.set.info[m.pattern as usize];
            let e = &self.entries[info.owner as usize];
            out.extend_from_slice(&e.placeholder);
            match e.meta.class {
                ValueClass::Credential => st.credential += 1,
                ValueClass::Display => st.display += 1,
            }
            on_hit(Hit::Known {
                meta: &e.meta,
                variant: info.variant,
                start: m.start,
                end: m.end,
            });
            pos = m.end;
        }
        self.gap(input, pos, input.len(), out, &mut st, on_hit);
        Ok(st)
    }

    /// Reports every replacement [`Redactor::redact`] would make, in order, as
    /// `(start, end, placeholder)` over `input`, without producing the output for the caller.
    ///
    /// For callers that apply replacements themselves (the HTTPS tool proxy's streaming
    /// redactor). Allocates one scratch buffer per call.
    pub fn find_matches(
        &self,
        input: &[u8],
        f: &mut dyn FnMut(usize, usize, &[u8]),
    ) -> Result<(), Error> {
        let mut spans: Vec<(usize, usize)> = Vec::new();
        let mut out = Vec::new();
        self.redact_with(input, &mut out, &mut |h| match h {
            Hit::Known { start, end, .. } | Hit::Detected { start, end, .. } => {
                spans.push((start, end));
            }
        })?;
        // The output is the input with each span replaced by one placeholder: walk both.
        let (mut in_pos, mut out_pos) = (0, 0);
        for (start, end) in spans {
            out_pos += start - in_pos;
            let len = match crate::placeholder::parse(&out[out_pos..]) {
                crate::placeholder::Parse::Complete(p) => p.len,
                _ => unreachable!("redactor output holds a placeholder at every replacement"),
            };
            f(start, end, &out[out_pos..out_pos + len]);
            out_pos += len;
            in_pos = end;
        }
        zeroize::Zeroize::zeroize(&mut out);
        Ok(())
    }

    /// Longest input span one replacement can cover: the longest compiled pattern, or the
    /// longest a fallback detector matches. A streaming caller holds back this many bytes minus
    /// one.
    pub fn max_match_len(&self) -> usize {
        let pats = (0..self.set.len() as u32)
            .map(|i| self.set.get(i).len())
            .max()
            .unwrap_or(0);
        pats.max(self.detectors.max_match_len())
    }

    /// Copies `input[from..to]`, running the fallback detectors over it.
    fn gap(
        &self,
        input: &[u8],
        from: usize,
        to: usize,
        out: &mut Vec<u8>,
        st: &mut Stats,
        on_hit: &mut dyn FnMut(Hit<'_>),
    ) {
        if from >= to {
            return;
        }
        let gap = &input[from..to];
        if self.detectors.is_empty() {
            out.extend_from_slice(gap);
            return;
        }
        let mut pos = 0;
        let key = self.keyring.current();
        self.detectors.scan(gap, |d| {
            out.extend_from_slice(&gap[pos..d.start]);
            let fallback;
            let slug = if let Some((_, s)) = self.det_slugs.iter().find(|(r, _)| *r == d.rule) {
                s
            } else {
                fallback = detector_slug(d.rule);
                &fallback
            };
            write_placeholder(out, key, slug, &gap[d.start..d.end]);
            st.detected += 1;
            on_hit(Hit::Detected {
                rule: d.rule,
                start: from + d.start,
                end: from + d.end,
            });
            pos = d.end;
        });
        out.extend_from_slice(&gap[pos..]);
    }

    /// Engine in use.
    pub fn engine(&self) -> EngineKind {
        self.kind
    }
}

fn detector_slug(rule: &str) -> RefSlug {
    RefSlug::from_alias(&format!("det-{rule}"))
}

/// One immutable, consistent redaction state: redactor, guard and resolver built from the same
/// values and keyring. Share it as `Arc<Snapshot>`; it is `Send + Sync` and every method takes
/// `&self`. A request should load one snapshot and use it from start to end.
pub struct Snapshot {
    redactor: Redactor,
    guard: Guard,
    resolver: Arc<Resolver>,
    report: BuildReport,
}

impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snapshot")
            .field("report", &self.report)
            .finish_non_exhaustive()
    }
}

/// Reusable per-request buffers for [`Snapshot::protect`]. Not shared between threads; keep one
/// per worker and reuse it so the hot path does not allocate.
#[derive(Default)]
pub struct Workspace {
    out: Vec<u8>,
    guard: GuardScratch,
}

impl std::fmt::Debug for Workspace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Workspace(<redacted>)")
    }
}

impl Workspace {
    /// Empty workspace.
    pub fn new() -> Self {
        Self::default()
    }

    /// Wipes buffers that held request bytes, keeping their capacity.
    pub fn wipe(&mut self) {
        use zeroize::Zeroize;
        self.out.zeroize();
        self.guard.wipe();
    }
}

/// What the guard did in [`Snapshot::protect`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardOutcome {
    /// Nothing found.
    Clean,
    /// The guard repaired the redactor's output; audit each finding.
    Repaired,
}

/// The bytes to send, with what happened to them.
#[derive(Debug)]
pub struct Protected<'w> {
    /// Exactly the bytes to forward.
    pub bytes: &'w [u8],
    /// Redactor counts.
    pub stats: Stats,
    /// Guard outcome.
    pub guard: GuardOutcome,
    /// Guard findings (empty when clean). Every one is a guard intervention for the audit log.
    pub findings: &'w [GuardFinding],
}

impl Snapshot {
    /// Builds a snapshot. Expensive (milliseconds to about a second for 10,000 values); run it
    /// off the request path and publish it with [`SnapshotHandle::store`].
    ///
    /// Entries are ordered by id. When several entries hold the same value the lowest id wins, so
    /// the output does not depend on the order entries are given in.
    pub fn build(
        entries: Vec<Entry>,
        keyring: Arc<Keyring>,
        config: &Config,
    ) -> Result<Self, BuildError> {
        if config.short_floor < 4 {
            return Err(BuildError::InvalidConfig("short_floor below 4"));
        }
        if config.max_input > u32::MAX as usize {
            return Err(BuildError::InvalidConfig("max_input above 4 GiB"));
        }
        if config.min_len < config.short_floor {
            return Err(BuildError::InvalidConfig("min_len below short_floor"));
        }
        if !(2..=MAX_JSON_DEPTH).contains(&config.json_depth) {
            return Err(BuildError::InvalidConfig("json_depth outside 2 to 4"));
        }
        let mut entries = entries;
        entries.sort_by_key(|e| e.meta.id);

        let mut seen: HashSet<&[u8]> = HashSet::with_capacity(entries.len());
        let mut keep = vec![false; entries.len()];
        let mut rejected = Vec::new();
        let mut duplicates = 0;
        for (i, e) in entries.iter().enumerate() {
            if e.value.len() < config.short_floor {
                rejected.push(e.meta.id);
            } else if !seen.insert(e.value.expose()) {
                duplicates += 1;
            } else {
                keep[i] = true;
            }
        }
        drop(seen);
        let kept: Vec<Entry> = entries
            .into_iter()
            .zip(keep)
            .filter_map(|(e, k)| k.then_some(e))
            .collect();

        let key = keyring.current();
        let mut compiled = Vec::with_capacity(kept.len());
        let mut set = PatternSet::new();
        let mut pat_seen: HashSet<Vec<u8>> = HashSet::new();
        let mut short = 0;
        for (i, e) in kept.iter().enumerate() {
            let mut ph = Vec::with_capacity(MAX_PLACEHOLDER_LEN);
            write_placeholder(&mut ph, key, &e.meta.slug, e.value.expose());
            compiled.push(CompiledEntry {
                meta: e.meta.clone(),
                placeholder: ph.into(),
            });
            let is_short = e.value.len() < config.min_len;
            short += usize::from(is_short);
            for (variant, bytes) in variants(e.value.expose(), is_short, config.json_depth) {
                if pat_seen.contains(&bytes) {
                    zeroize::Zeroize::zeroize(&mut { bytes });
                    continue;
                }
                set.push(&bytes, i as u32, variant);
                pat_seen.insert(bytes);
            }
        }
        for mut k in pat_seen.drain() {
            zeroize::Zeroize::zeroize(&mut k);
        }

        let kind = match config.engine {
            EngineChoice::Fixed(k) => k,
            EngineChoice::Auto if set.len() > config.engine_threshold => EngineKind::HashWindow,
            EngineChoice::Auto => EngineKind::AhoCorasick,
        };
        let engine = build_engine(&set, kind)?;
        let detectors = Detectors::build(&config.detectors)?;

        let mut map = HashMap::with_capacity(kept.len() * 2);
        for (i, e) in kept.iter().enumerate() {
            for k in keyring.keys() {
                map.insert((k.version(), k.tag(e.value.expose())), i as u32);
            }
        }
        let res_entries: Arc<[ResolverEntry]> = kept
            .into_iter()
            .map(|e| ResolverEntry {
                meta: e.meta,
                value: e.value,
            })
            .collect();
        let resolver = Arc::new(Resolver::new(map, res_entries));

        let guard_inputs: Vec<GuardInput<'_>> = resolver
            .entries()
            .iter()
            .zip(&compiled)
            .map(|(e, c)| GuardInput {
                value: e.value.expose(),
                entry: e.meta.id,
                placeholder: &c.placeholder,
            })
            .collect();
        let guard = Guard::build(
            &guard_inputs,
            config.min_len,
            config.guard_max_repairs,
            config.json_depth,
            resolver.clone(),
        );
        drop(guard_inputs);

        let report = BuildReport {
            values: compiled.len(),
            duplicates,
            short,
            rejected,
            patterns: set.len(),
            engine: kind,
        };
        let det_slugs = crate::detect::builtin_rule_names()
            .into_iter()
            .chain(std::iter::once(crate::detect::ENTROPY_RULE))
            .map(|r| (r, detector_slug(r)))
            .collect();
        let redactor = Redactor {
            entries: compiled,
            set,
            engine,
            kind,
            detectors,
            keyring,
            det_slugs,
            resolver: resolver.clone(),
            max_input: config.max_input,
        };
        Ok(Self {
            redactor,
            guard,
            resolver,
            report,
        })
    }

    /// The redactor.
    pub fn redactor(&self) -> &Redactor {
        &self.redactor
    }

    /// The guard.
    pub fn guard(&self) -> &Guard {
        &self.guard
    }

    /// The resolver for placeholders in responses.
    pub fn resolver(&self) -> &Resolver {
        &self.resolver
    }

    /// Build counts (for `scrim status`).
    pub fn report(&self) -> &BuildReport {
        &self.report
    }

    /// Redacts `input` and runs the guard over the result: the full outbound check.
    ///
    /// `Ok` carries exactly the bytes to forward. `Err` means refuse the request; nothing may be
    /// forwarded, and there is no unredacted fallback.
    pub fn protect<'w>(&self, input: &[u8], ws: &'w mut Workspace) -> Result<Protected<'w>, Error> {
        let stats = self.redactor.redact(input, &mut ws.out)?;
        match self.guard.check(&ws.out, &mut ws.guard) {
            Verdict::Clean => Ok(Protected {
                bytes: &ws.out,
                stats,
                guard: GuardOutcome::Clean,
                findings: &[],
            }),
            Verdict::Repaired { bytes, findings } => Ok(Protected {
                bytes,
                stats,
                guard: GuardOutcome::Repaired,
                findings,
            }),
            Verdict::Withhold(r) => Err(Error::Withheld(r)),
        }
    }
}

/// Holds the current snapshot and swaps it atomically.
///
/// Readers call [`SnapshotHandle::load`] once per request and keep the returned `Arc` until the
/// request is done, so a request sees one consistent snapshot even if a rebuild is published
/// meanwhile. Loading is lock-free and never waits for a rebuild; [`SnapshotHandle::store`] is a
/// single atomic swap, and the old snapshot is freed when its last request drops it.
#[derive(Debug, Default)]
pub struct SnapshotHandle {
    cur: ArcSwapOption<Snapshot>,
}

impl SnapshotHandle {
    /// A handle with no snapshot: [`SnapshotHandle::load`] returns [`Error::NotReady`] until the
    /// first [`SnapshotHandle::store`].
    pub fn new() -> Self {
        Self::default()
    }

    /// The current snapshot, or [`Error::NotReady`] if none has been stored.
    pub fn load(&self) -> Result<Arc<Snapshot>, Error> {
        self.cur.load_full().ok_or(Error::NotReady)
    }

    /// Publishes `snap` for all later loads.
    pub fn store(&self, snap: Arc<Snapshot>) {
        self.cur.store(Some(snap));
    }

    /// Whether a snapshot has been stored.
    pub fn is_ready(&self) -> bool {
        self.cur.load().is_some()
    }
}
