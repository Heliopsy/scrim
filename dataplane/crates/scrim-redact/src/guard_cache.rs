//! The guard's verdict cache across requests (performance spec, "Guard verdict cache").
//!
//! LLM APIs are stateless: every turn of an agent resends the whole conversation, so most of a
//! request body is bytes the guard checked one request earlier. The guard splits a body into
//! segments at boundaries no occurrence of a value can cross (see [`cuts`]), and remembers the
//! BLAKE3 hash of every segment it found clean. A later body only has its new segments checked.
//!
//! The cache lives in the [`Guard`](crate::Guard), so a new snapshot (any change to the values)
//! starts with an empty one. It holds hashes only: never values, never request bytes. A segment
//! counts as cached only when its bytes hash to the same 32 bytes, so only byte-identical input
//! under the same snapshot reuses a verdict.
//!
//! # Why a segment can be checked on its own
//!
//! A cut sits at `p` where the outgoing bytes read `X},{Y`, `{` at `p`, `X` one of `"`, `]`,
//! `}` (what closes a JSON value) and `Y` one of `"`, `}` (what opens an object's body). Then:
//!
//! * no JSON escape and no percent escape spans `p` (neither can contain `,` or `{`), and the
//!   unescaped bytes around `p` still read `X'},{Y` with `X'` not a comma (an escape ending in
//!   `"`, `]` or `}` decodes to a quote or stays as it is), so every JSON and percent-decoded
//!   view of a segment is that view of the whole body cut at `p`, at every depth;
//! * an occurrence crossing `p` in the raw, JSON, percent or fragment views contains `,{`; the
//!   cache is off for a snapshot with a value (or derived form) containing `,{`;
//! * base64, hex and base32 runs hold neither `,` nor `{`;
//! * a run of separated units crossing `p` would have `}` and `{` as single-character units with
//!   `,` between them, and `X` or `Y` would have to be a comma for a third unit: two units are
//!   not a run;
//! * dump lines hold no line break, hex cells and `od -c` cells cannot hold `},{`, and only an
//!   ASCII column (`|...|`, or after `xxd`'s `offset: `) can reach across `p`; a cut whose line,
//!   as unescaped, back to its last line break, has a `|` or a `: ` (or a `\u` escape, which
//!   could decode to one) is not used.
//!
//! So the guard's findings in the whole body are the union of its findings in each segment, and
//! a segment found clean once stays clean wherever it appears under the same snapshot.

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::Mutex;

/// Bodies shorter than this are checked whole: hashing and lookups would cost more than they
/// save.
pub(crate) const MIN_BYTES: usize = 32 << 10;

/// Longest line before a cut that is searched for a dump's ASCII column; a longer line makes the
/// cut unused.
const MAX_LINE: usize = 4096;

/// A segment's key: the BLAKE3 hash of its bytes.
pub(crate) type Key = [u8; 32];

/// Hashes are uniform already: the first eight bytes are the table hash.
#[derive(Default)]
struct KeyHasher(u64);

impl Hasher for KeyHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        let mut w = [0u8; 8];
        let n = bytes.len().min(8);
        w[..n].copy_from_slice(&bytes[..n]);
        self.0 ^= u64::from_le_bytes(w);
    }
}

struct Map {
    /// Key to the clock value of its last use.
    entries: HashMap<Key, u64, BuildHasherDefault<KeyHasher>>,
    clock: u64,
}

/// Hashes of segments found clean, at most `cap` of them; the least recently used go first.
pub(crate) struct SegmentCache {
    cap: usize,
    map: Mutex<Map>,
}

impl SegmentCache {
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            cap,
            map: Mutex::new(Map {
                entries: HashMap::default(),
                clock: 0,
            }),
        }
    }

    /// Marks which of `keys` are known clean in `known` (same length), refreshing their use.
    pub(crate) fn lookup(&self, keys: &[Key], known: &mut Vec<bool>) {
        known.clear();
        let Ok(mut m) = self.map.lock() else {
            known.resize(keys.len(), false);
            return;
        };
        m.clock += 1;
        let now = m.clock;
        for k in keys {
            match m.entries.get_mut(k) {
                Some(t) => {
                    *t = now;
                    known.push(true);
                }
                None => known.push(false),
            }
        }
    }

    /// Records `keys` as clean, evicting the least recently used entries beyond the cap.
    pub(crate) fn insert(&self, keys: impl Iterator<Item = Key>) {
        let Ok(mut m) = self.map.lock() else {
            return;
        };
        m.clock += 1;
        let now = m.clock;
        for k in keys {
            m.entries.insert(k, now);
        }
        if m.entries.len() > self.cap {
            // Down to seven eighths, so eviction runs once per cap/8 insertions.
            let keep = self.cap - self.cap / 8;
            let mut stamps: Vec<u64> = m.entries.values().copied().collect();
            let drop = stamps.len() - keep;
            let (_, &mut cut, _) = stamps.select_nth_unstable(drop - 1);
            // Entries used together share a stamp: all of the oldest stamps go.
            m.entries.retain(|_, t| *t > cut);
        }
    }

    /// Drops every entry.
    pub(crate) fn clear(&self) {
        if let Ok(mut m) = self.map.lock() {
            m.entries.clear();
        }
    }

    /// Entries held.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.map.lock().map_or(0, |m| m.entries.len())
    }
}

/// Appends to `out` the cut positions of `b`, ascending: segments are `0..out[0]`,
/// `out[0]..out[1]`, ... `out[last]..b.len()`. See the module documentation for what makes a cut.
pub(crate) fn cuts(b: &[u8], out: &mut Vec<usize>) {
    for m in memchr::memmem::find_iter(b, b"},{") {
        let p = m + 2;
        if m == 0 || p + 1 >= b.len() {
            continue;
        }
        // What closes a JSON value before `}`, and what opens an object's body after `{`.
        if !matches!(b[m - 1], b'"' | b']' | b'}') || !matches!(b[p + 1], b'"' | b'}') {
            continue;
        }
        if !line_is_plain(b, m) {
            continue;
        }
        out.push(p);
    }
}

/// Whether the line ending at `end`, as the JSON-unescaped view reads it (back to the last line
/// break: a newline byte or a `\n` escape), is at most `MAX_LINE` bytes and has neither `|` nor
/// `: `, so no dump line's ASCII column can reach `end`. A `\u` escape on the line could decode
/// to either, so it makes the line not plain; other escapes decode to a quote, a backslash, a
/// slash or a control character.
fn line_is_plain(b: &[u8], end: usize) -> bool {
    let from = end.saturating_sub(MAX_LINE);
    // Back to the nearest line break, `|` or escape, found with `memrchr3` rather than byte by
    // byte: the lines before cuts can be long (base64 in a tool result).
    let mut hi = end;
    let start = loop {
        let Some(k) = memchr::memrchr3(b'\n', b'|', b'\\', &b[from..hi]) else {
            // The start of the body is a line start; a longer line is not searched.
            if from != 0 {
                return false;
            }
            break 0;
        };
        let i = from + k;
        match b[i] {
            b'\n' => break i + 1,
            b'|' => return false,
            _ => {
                // A run of backslashes ending at `i`: when odd, the byte after it is escaped.
                let run = b[..=i].iter().rev().take_while(|&&c| c == b'\\').count();
                if run % 2 == 1 {
                    match b.get(i + 1) {
                        Some(b'n') => break i + 2,
                        Some(b'u') => return false,
                        _ => {}
                    }
                }
                hi = i + 1 - run;
                if hi <= from {
                    if from != 0 {
                        return false;
                    }
                    break 0;
                }
            }
        }
    };
    memchr::memmem::find(&b[start..end], b": ").is_none()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::pedantic)]
mod tests {
    use super::*;

    fn cut_list(b: &[u8]) -> Vec<usize> {
        let mut v = Vec::new();
        cuts(b, &mut v);
        v
    }

    #[test]
    fn cuts_between_objects() {
        let b =
            br#"{"messages":[{"role":"user","content":"a"},{"role":"assistant","content":"b"}]}"#;
        let v = cut_list(b);
        assert_eq!(v.len(), 1);
        assert_eq!(b[v[0]], b'{');
        assert_eq!(&b[v[0] - 2..v[0]], b"},");
    }

    #[test]
    fn no_cut_near_commas_escapes_or_dump_columns() {
        for b in [
            &br#"x,},{"a":1}"#[..],
            br#"{"a":"b"},{,"#,
            br#"{"t":"00000000  41 42  |AB"},{"c":1}"#,
            br#"{"t":"00000000: 4142  AB"},{"c":1}"#,
            br#"{"a":"b"},{\"x"#,
            br#"{"a":"b"},{1}"#,
            br#"{"a":1},{"b":2}"#,
            br#"{"t":"\u007c"},{"c":1}"#,
        ] {
            assert!(cut_list(b).is_empty(), "{}", String::from_utf8_lossy(b));
        }
        // A line break before the column ends the line that matters.
        let b = br#"{"t":"| x |\nplain"},{"c":1}"#;
        assert_eq!(cut_list(b).len(), 1);
        // A literal backslash before `n` is no line break.
        let b = br#"{"t":"| x |\\nplain"},{"c":1}"#;
        assert!(cut_list(b).is_empty());
        // Escaped quotes and backslashes on the line are fine.
        let b = br#"{"t":"say \"hi\" \\ ok"},{"c":1}"#;
        assert_eq!(cut_list(b).len(), 1);
    }

    #[test]
    fn cache_evicts_least_recently_used() {
        let c = SegmentCache::new(16);
        let key = |i: u8| {
            let mut k = [0u8; 32];
            k[0] = i;
            k[9] = i;
            k
        };
        c.insert((0..16).map(key));
        let mut known = Vec::new();
        // Use 0..4 again, then overflow.
        c.lookup(&[key(0), key(1), key(2), key(3)], &mut known);
        c.insert((16..20).map(key));
        assert!(c.len() <= 16);
        c.lookup(&[key(0), key(1), key(2), key(3), key(19)], &mut known);
        assert_eq!(known, vec![true; 5]);
        c.lookup(&[key(4)], &mut known);
        assert_eq!(known, vec![false]);
    }
}
