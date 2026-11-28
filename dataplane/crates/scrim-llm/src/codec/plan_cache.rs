// SPDX-License-Identifier: AGPL-3.0-only

//! The codec plan cache (performance spec, "Codec plan cache").
//!
//! An agent's next turn resends the conversation: every message of the previous request comes
//! back byte for byte, and planning (a strict parse of the whole body) would read them all again.
//! The plan of a message depends on its bytes alone: whether it is valid JSON, and which spans
//! of it stay verbatim (signed thinking, redacted thinking). So once a message has been planned,
//! the cache keeps the BLAKE3 hash of its bytes, its length and its verbatim spans as offsets
//! into it; a later body that holds the same bytes at the start of an element of the same array
//! has that element stepped over unparsed ([`crate::json::Skip`]) and its spans added from the
//! cache. Only hashes, lengths and offsets are kept, never bytes or values.
//!
//! Which arrays: the root members a codec names, whose elements its plan reads one by one
//! (`messages`, `system`) or not at all (`tools`). Elements shorter than [`MIN_ELEMENT`] and
//! elements with binary parts or referenced attachments are always planned. A body planned with the cache gets exactly
//! the plan it gets without it: a skipped element is bytes that parsed as one object before, at
//! the same depth (an element of a root member array), and its spans are what planning it then
//! found. Errors elsewhere in the body are found as before; tests in `plan_cache_tests` check
//! plans with and without the cache against each other.
//!
//! The cache belongs to the engine's redactor ([`crate::engine::Redactor::plan_cache`]), so a
//! new snapshot starts with an empty one.

use std::collections::HashMap;
use std::sync::Mutex;

use super::{Plan, PlanError};
use crate::json::Value;

/// Runs of elements shorter than this are not remembered.
pub(crate) const MIN_ELEMENT: usize = 1024;

/// Bytes at the start of an element that pick the candidates; the rest is checked by hash.
const PROBE: usize = 256;

/// Elements with more verbatim spans than this are not remembered.
const MAX_SPANS: usize = 64;

/// Candidates kept per probe; the least recently used go first.
const MAX_PER_PROBE: usize = 8;

/// One remembered element.
struct Known {
    len: u32,
    key: [u8; 32],
    spans: Box<[(u32, u32)]>,
    stamp: u64,
}

struct Map {
    by_probe: HashMap<u64, Vec<Known>>,
    len: usize,
    clock: u64,
}

/// Plans of elements seen before, by hash: at most `cap` of them, least recently used out.
pub struct PlanCache {
    cap: usize,
    map: Mutex<Map>,
}

impl std::fmt::Debug for PlanCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlanCache")
            .field("cap", &self.cap)
            .finish_non_exhaustive()
    }
}

/// The BLAKE3 key of an element of array `role`: keyed by the array, so the same bytes in two
/// arrays have two keys.
fn key(role: usize, b: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(&[u8::try_from(role).unwrap_or(u8::MAX); 32], b).as_bytes()
}

/// A cheap hash of an element's first [`PROBE`] bytes and its array.
fn probe(role: usize, b: &[u8]) -> u64 {
    let mut x = 0x9e37_79b9_7f4a_7c15_u64 ^ role as u64;
    for c in b.chunks(8) {
        let mut w = [0u8; 8];
        w[..c.len()].copy_from_slice(c);
        x = (x.rotate_left(5) ^ u64::from_le_bytes(w)).wrapping_mul(0x5172_7a3c_9d1b_4e4b);
    }
    x
}

impl PlanCache {
    /// A cache of at most `cap` elements.
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            map: Mutex::new(Map {
                by_probe: HashMap::new(),
                len: 0,
                clock: 0,
            }),
        }
    }

    /// Forgets every element.
    pub fn clear(&self) {
        if let Ok(mut m) = self.map.lock() {
            m.by_probe.clear();
            m.len = 0;
        }
    }

    /// Elements held.
    pub fn len(&self) -> usize {
        self.map.lock().map_or(0, |m| m.len)
    }

    /// Whether no element is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The length of the element of array `role` known to start at `src[at..]`, with its spans
    /// appended to `spans` relative to `at`.
    fn find(
        &self,
        role: usize,
        src: &[u8],
        at: usize,
        spans: &mut Vec<(u32, u32)>,
    ) -> Option<usize> {
        let rest = src.get(at..)?;
        if rest.len() < MIN_ELEMENT {
            return None;
        }
        let pr = probe(role, &rest[..PROBE]);
        let mut cands: [(u32, [u8; 32]); MAX_PER_PROBE] = [(0, [0; 32]); MAX_PER_PROBE];
        let mut n = 0;
        {
            let m = self.map.lock().ok()?;
            for k in m.by_probe.get(&pr)? {
                let len = k.len as usize;
                // Cheap checks first: the bytes there end an object and a value.
                if len <= rest.len()
                    && rest[len - 1] == b'}'
                    && rest
                        .get(len)
                        .is_some_and(|c| matches!(c, b',' | b']' | b' ' | b'\t' | b'\n' | b'\r'))
                    && n < MAX_PER_PROBE
                {
                    cands[n] = (k.len, k.key);
                    n += 1;
                }
            }
        }
        let (len, want) = cands[..n]
            .iter()
            .find(|(len, want)| key(role, &rest[..*len as usize]) == *want)?;
        let mut m = self.map.lock().ok()?;
        m.clock += 1;
        let now = m.clock;
        let k = m
            .by_probe
            .get_mut(&pr)?
            .iter_mut()
            .find(|k| k.len == *len && k.key == *want)?;
        k.stamp = now;
        spans.extend_from_slice(&k.spans);
        Some(*len as usize)
    }

    fn insert(&self, items: Vec<(u64, Known)>) {
        let Ok(mut m) = self.map.lock() else {
            return;
        };
        m.clock += 1;
        let now = m.clock;
        for (pr, mut k) in items {
            k.stamp = now;
            let list = m.by_probe.entry(pr).or_default();
            if list.iter().any(|x| x.len == k.len && x.key == k.key) {
                continue;
            }
            if list.len() >= MAX_PER_PROBE
                && let Some(old) = (0..list.len()).min_by_key(|&i| list[i].stamp)
            {
                list.swap_remove(old);
                m.len -= 1;
            }
            let list = m.by_probe.entry(pr).or_default();
            list.push(k);
            m.len += 1;
        }
        if m.len > self.cap {
            // Down to seven eighths, oldest first.
            let keep = self.cap - self.cap / 8;
            let mut stamps: Vec<u64> = m.by_probe.values().flatten().map(|k| k.stamp).collect();
            let drop = stamps.len() - keep;
            let (_, &mut cut, _) = stamps.select_nth_unstable(drop - 1);
            m.by_probe.retain(|_, list| {
                list.retain(|k| k.stamp > cut);
                !list.is_empty()
            });
            m.len = m.by_probe.values().map(Vec::len).sum();
        }
    }
}

/// Whether an element ends a run of elements the cache keeps as one: decided by its last bytes
/// and length, so the same elements group the same way wherever the conversation changed.
fn ends_run(el: &[u8]) -> bool {
    let tail = &el[el.len().saturating_sub(16)..];
    let mut x = el.len() as u64 ^ 0x2545_f491_4f6c_dd1d;
    for c in tail.chunks(8) {
        let mut w = [0u8; 8];
        w[..c.len()].copy_from_slice(c);
        x = (x ^ u64::from_le_bytes(w)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }
    (x >> 40) & RUN_MASK == 0
}

/// About one element in `RUN_MASK + 1` ends a run.
const RUN_MASK: u64 = 7;

/// A run ends at the element that takes it to this many bytes, whatever its bytes.
const RUN_MAX: usize = 64 << 10;

/// A run being built: array, start, end, spans relative to its start.
type Run = (usize, usize, usize, Vec<(u32, u32)>);

/// An element of a cached array seen while planning.
enum Seen {
    /// Stepped over: a run the cache knew.
    Skipped,
    /// Planned: its span, its spans' range in [`Elements::spans`], and whether it holds binary
    /// parts or attachment references (neither is kept, so such an element is never skipped).
    Planned {
        start: usize,
        end: usize,
        spans: (usize, usize),
        binary: bool,
    },
}

/// One planning of a body with the cache: the runs stepped over, then the elements planned, to
/// remember in runs once the whole body planned.
pub(crate) struct Elements<'c> {
    cache: Option<&'c PlanCache>,
    /// Skipped runs: start, and their spans' range in `spans`.
    skipped: Vec<(usize, usize, usize)>,
    spans: Vec<(u32, u32)>,
    /// Per cached array, its elements in order.
    seen: Vec<(usize, Seen)>,
}

impl<'c> Elements<'c> {
    /// Without a cache: every element is planned, nothing is remembered.
    pub(crate) fn none() -> Self {
        Self {
            cache: None,
            skipped: Vec::new(),
            spans: Vec::new(),
            seen: Vec::new(),
        }
    }

    pub(crate) fn with(cache: &'c PlanCache) -> Self {
        Self {
            cache: Some(cache),
            ..Self::none()
        }
    }

    /// For [`crate::json::Skip::skip`]: the length of the known run at `at`, if any.
    pub(crate) fn skip(&mut self, role: usize, src: &[u8], at: usize) -> Option<usize> {
        let from = self.spans.len();
        let len = self.cache?.find(role, src, at, &mut self.spans)?;
        self.skipped.push((at, from, self.spans.len()));
        Some(len)
    }

    /// Plans element `v` of array `role` with `f`, or adds the remembered spans of the run it
    /// stands for when it was skipped.
    pub(crate) fn element(
        &mut self,
        role: usize,
        value: Value<'_, '_>,
        plan: &mut Plan,
        planner: impl FnOnce(&mut Plan) -> Result<(), PlanError>,
    ) -> Result<(), PlanError> {
        let (start, end) = value.span();
        if value.is_opaque() {
            let Ok(at) = self.skipped.binary_search_by_key(&start, |s| s.0) else {
                return Err(PlanError::Shape("plan cache lost an element"));
            };
            let (_, from, to) = self.skipped[at];
            plan.verbatim.extend(
                self.spans[from..to]
                    .iter()
                    .map(|&(s, e)| (start + s as usize, start + e as usize)),
            );
            if self.cache.is_some() {
                self.seen.push((role, Seen::Skipped));
            }
            return Ok(());
        }
        let (nv, nb, nr) = (plan.verbatim.len(), plan.binary.len(), plan.remote.len());
        planner(plan)?;
        if self.cache.is_some() {
            let from = self.spans.len();
            self.spans
                .extend(plan.verbatim[nv..].iter().filter_map(|&(s, e)| {
                    Some((
                        u32::try_from(s - start).ok()?,
                        u32::try_from(e - start).ok()?,
                    ))
                }));
            self.seen.push((
                role,
                Seen::Planned {
                    start,
                    end,
                    spans: (from, self.spans.len()),
                    binary: plan.binary.len() != nb || plan.remote.len() != nr,
                },
            ));
        }
        Ok(())
    }

    /// Element `v` of array `role`, which the plan does not read: remembered with no spans.
    pub(crate) fn unread(&mut self, role: usize, v: Value<'_, '_>) {
        if self.cache.is_none() {
            return;
        }
        if v.is_opaque() {
            self.seen.push((role, Seen::Skipped));
            return;
        }
        let (start, end) = v.span();
        let n = self.spans.len();
        self.seen.push((
            role,
            Seen::Planned {
                start,
                end,
                spans: (n, n),
                binary: false,
            },
        ));
    }

    /// The whole body planned: remembers the elements planned on the way, in runs. A run ends
    /// at an element [`ends_run`] picks, at [`RUN_MAX`] bytes, before a skipped run or an element
    /// with binary parts or references, and at the end of its array.
    pub(crate) fn remember(self, src: &[u8]) {
        let Some(cache) = self.cache else { return };
        let mut items: Vec<(u64, Known)> = Vec::new();
        let mut run: Option<Run> = None;
        let mut close = |run: &mut Option<Run>| {
            let Some((role, start, end, spans)) = run.take() else {
                return;
            };
            let bytes = &src[start..end];
            if bytes.len() < MIN_ELEMENT || spans.len() > MAX_SPANS || src[start] != b'{' {
                return;
            }
            if let Ok(len) = u32::try_from(bytes.len()) {
                items.push((
                    probe(role, &bytes[..PROBE]),
                    Known {
                        len,
                        key: key(role, bytes),
                        spans: spans.into(),
                        stamp: 0,
                    },
                ));
            }
        };
        for (k, (role, seen)) in self.seen.iter().enumerate() {
            if run.as_ref().is_some_and(|r| r.0 != *role) {
                close(&mut run);
            }
            match *seen {
                Seen::Skipped | Seen::Planned { binary: true, .. } => close(&mut run),
                Seen::Planned {
                    start,
                    end,
                    spans: (a, b),
                    binary: false,
                } => {
                    let r = run.get_or_insert_with(|| (*role, start, end, Vec::new()));
                    let base = r.1;
                    r.2 = end;
                    r.3.extend(self.spans[a..b].iter().map(|&(s, e)| {
                        let shift = u32::try_from(start - base).unwrap_or(u32::MAX);
                        (s.saturating_add(shift), e.saturating_add(shift))
                    }));
                    let last_of_array = self.seen.get(k + 1).is_none_or(|n| n.0 != *role);
                    if ends_run(&src[start..end]) || end - base >= RUN_MAX || last_of_array {
                        close(&mut run);
                    }
                }
            }
        }
        close(&mut run);
        if !items.is_empty() {
            cache.insert(items);
        }
    }
}
