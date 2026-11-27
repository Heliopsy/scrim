//! Values split across the requests of one session (`cross-request`).
//!
//! The split-fragments rule joins short pieces of a value found in one request. An agent that
//! sends one piece per request, or a provider that keeps earlier turns itself (a Responses
//! request's `previous_response_id` or conversation, a WebSocket session), never puts the pieces
//! in one body. This memory keeps, per session, which short pieces of which value already left: the
//! fragment index's form, the offset and the length of each piece, and when it was seen. Never
//! the bytes, never the value.
//!
//! Only pieces that read as random count ([`looks_random`]): over a long session, the pieces of
//! a value made of words would join into it from ordinary text.
//!
//! When the short pieces of a request, with the remembered pieces of the same form, cover the
//! value as the split-fragments rule wants it covered, the pieces in the request are repaired, so
//! the request that would complete the value never carries its last piece. Deciding and
//! remembering happen under one lock, so two requests of a session checked at the same time are
//! seen one after the other: the second one sees the first one's pieces. Pieces that are repaired
//! are remembered too: they show which value the session is sending, and the next piece may
//! need them once older pieces have expired.
//!
//! Bounded: [`MAX_PIECES`] per session (the oldest go first), [`MAX_SESSIONS`] sessions (the one
//! seen longest ago goes first), each piece forgotten [`TTL`] after it was last seen. The memory
//! belongs to one guard, which belongs to one snapshot: a new snapshot (a value added, changed or
//! removed, a session token revoked when its session ends) starts empty, and so does every
//! replica.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::extra::{Short, covers};

/// How long a piece is remembered after it was last seen.
pub(crate) const TTL: Duration = Duration::from_mins(30);
/// Most pieces remembered per session.
pub(crate) const MAX_PIECES: usize = 256;
/// Most sessions remembered.
pub(crate) const MAX_SESSIONS: usize = 1024;
/// Every this many calls, sessions not seen within [`TTL`] are dropped.
const SWEEP_EVERY: u32 = 256;

/// Consonants in a row that make a piece read as random (`https`, `strength`).
pub(crate) const CONSONANT_RUN: usize = 4;

/// Whether `c` is punctuation that does not join words (`!`, `"`, `#`, `%`, `\\`, ...: not
/// `-`, `_`, `.`, `/`, `:`, `,` or a space).
fn is_symbol(c: u8) -> bool {
    c.is_ascii_punctuation() && !b"-_./:,".contains(&c)
}

/// Whether a piece of a value reads as random rather than as words: a lower-case letter
/// followed by a capital, a letter next to a digit, two letters or digits next to punctuation
/// that does not join words, or [`CONSONANT_RUN`] consonants in a row. Pieces of words
/// (`billing`, `Service`, `production-database`, `20241127`) turn up all over a long session and
/// would join into any value made of words, so they are neither remembered nor joined.
pub(crate) fn looks_random(piece: &[u8]) -> bool {
    let mut run = 0;
    let mut symbols = 0;
    let mut prev = 0u8;
    for &c in piece {
        if (prev.is_ascii_lowercase() && c.is_ascii_uppercase())
            || (prev.is_ascii_alphabetic() && c.is_ascii_digit())
            || (prev.is_ascii_digit() && c.is_ascii_alphabetic())
        {
            return true;
        }
        if (prev.is_ascii_alphanumeric() && is_symbol(c))
            || (is_symbol(prev) && c.is_ascii_alphanumeric())
        {
            symbols += 1;
            if symbols >= 2 {
                return true;
            }
        }
        if c.is_ascii_alphabetic() && !b"aeiouyAEIOUY".contains(&c) {
            run += 1;
            if run >= CONSONANT_RUN {
                return true;
            }
        } else {
            run = 0;
        }
        prev = c;
    }
    false
}

/// A session, as the proxy names it: a hash of what the transport said about the caller. Opaque
/// here.
pub type SessionKey = [u8; 32];

#[derive(Clone, Copy)]
struct Piece {
    form: u32,
    off: u32,
    len: u32,
    /// Seconds since the memory was made, when last seen.
    at: u32,
}

#[derive(Default)]
struct Session {
    seen: u32,
    pieces: Vec<Piece>,
}

#[derive(Default)]
struct Sessions {
    by_key: HashMap<SessionKey, Session>,
    calls: u32,
}

/// The cross-request memory of one guard.
pub(crate) struct CrossMemory {
    start: Instant,
    ttl: u32,
    sessions: Mutex<Sessions>,
}

impl CrossMemory {
    pub(crate) fn new() -> Self {
        Self {
            start: Instant::now(),
            ttl: TTL.as_secs() as u32,
            sessions: Mutex::new(Sessions::default()),
        }
    }

    fn now(&self) -> u32 {
        u32::try_from(self.start.elapsed().as_secs()).unwrap_or(u32::MAX)
    }

    /// Joins `short` (the short pieces of the request being checked, in its coordinates) with the
    /// pieces remembered for `key`, skipping the forms in `done` (already joined within the
    /// request). Calls `emit(start, end, form)` for each piece of the request whose form is now
    /// covered, and remembers the others.
    pub(crate) fn join(
        &self,
        key: &SessionKey,
        short: &mut [Short],
        done: &[u32],
        form_len: &dyn Fn(u32) -> usize,
        emit: &mut dyn FnMut(usize, usize, u32),
    ) {
        self.join_at(self.now(), key, short, done, form_len, emit);
    }

    pub(crate) fn join_at(
        &self,
        now: u32,
        key: &SessionKey,
        short: &mut [Short],
        done: &[u32],
        form_len: &dyn Fn(u32) -> usize,
        emit: &mut dyn FnMut(usize, usize, u32),
    ) {
        if short.is_empty() {
            return;
        }
        short.sort_unstable();
        let ttl = self.ttl;
        let live = |at: u32| now.saturating_sub(at) <= ttl;
        // A poisoned lock only means another check panicked; the map is still consistent.
        let mut g = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        g.calls = g.calls.wrapping_add(1);
        if g.calls.is_multiple_of(SWEEP_EVERY) {
            g.by_key.retain(|_, s| live(s.seen));
        }
        if !g.by_key.contains_key(key) && g.by_key.len() >= MAX_SESSIONS {
            // Full: the session seen longest ago makes room.
            if let Some(old) = g.by_key.iter().min_by_key(|(_, s)| s.seen).map(|(k, _)| *k) {
                g.by_key.remove(&old);
            }
        }
        let sess = g.by_key.entry(*key).or_default();
        sess.seen = now;
        sess.pieces.retain(|p| live(p.at));
        let mut spans: Vec<(usize, usize)> = Vec::new();
        let mut i = 0;
        while i < short.len() {
            let form = short[i].form;
            let mut j = i;
            while j < short.len() && short[j].form == form {
                j += 1;
            }
            let group = &short[i..j];
            i = j;
            // Every piece is remembered, the repaired ones too: a value's piece that completed
            // it once (with pieces since forgotten, or within its request) still completes it
            // with the pieces that come after.
            let joined = !done.contains(&form) && {
                spans.clear();
                spans.extend(
                    sess.pieces
                        .iter()
                        .filter(|p| p.form == form)
                        .map(|p| (p.off as usize, (p.off + p.len) as usize)),
                );
                // Only together with pieces from earlier requests.
                !spans.is_empty() && {
                    spans.extend(
                        group
                            .iter()
                            .map(|f| (f.off as usize, (f.off + f.len) as usize)),
                    );
                    spans.sort_unstable();
                    covers(spans.iter().copied(), form_len(form))
                }
            };
            if joined {
                let mut last = None;
                for f in group {
                    if last != Some((f.start, f.end)) {
                        emit(f.start, f.end, form);
                        last = Some((f.start, f.end));
                    }
                }
            }
            for f in group {
                remember(&mut sess.pieces, f, now);
            }
        }
    }

    /// Pieces remembered for `key` (tests).
    #[cfg(test)]
    pub(crate) fn pieces(&self, key: &SessionKey) -> usize {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .by_key
            .get(key)
            .map_or(0, |s| s.pieces.len())
    }

    /// Sessions remembered (tests).
    #[cfg(test)]
    pub(crate) fn sessions(&self) -> usize {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .by_key
            .len()
    }
}

fn remember(pieces: &mut Vec<Piece>, f: &Short, now: u32) {
    if let Some(p) = pieces
        .iter_mut()
        .find(|p| p.form == f.form && p.off == f.off && p.len == f.len)
    {
        p.at = now;
        return;
    }
    if pieces.len() >= MAX_PIECES
        && let Some(k) = pieces
            .iter()
            .enumerate()
            .min_by_key(|(_, p)| p.at)
            .map(|(k, _)| k)
    {
        pieces.swap_remove(k);
    }
    pieces.push(Piece {
        form: f.form,
        off: f.off,
        len: f.len,
        at: now,
    });
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::pedantic)]
mod tests {
    use super::*;

    const LEN: usize = 40;

    fn piece(form: u32, off: u32, len: u32, start: usize) -> Short {
        Short {
            form,
            off,
            len,
            start,
            end: start + len as usize,
        }
    }

    fn join(m: &CrossMemory, now: u32, key: &SessionKey, mut short: Vec<Short>) -> Vec<usize> {
        let mut out = Vec::new();
        m.join_at(now, key, &mut short, &[], &|_| LEN, &mut |a, _, _| {
            out.push(a)
        });
        out
    }

    #[test]
    fn words_do_not_look_random() {
        for w in [
            &b"billing-service"[..],
            b"Production",
            b"DATABASE_PASSWORD",
            b"20241127",
            b"correct.horse",
        ] {
            assert!(!looks_random(w), "{}", String::from_utf8_lossy(w));
        }
        for w in [
            &b"aZk2mQ9xP"[..],
            b"ghp_x8Kq",
            b"deadbeef00",
            b"Summer2024",
            b"AKIAQWRTZPLM",
            b"q!x\"wr%a",
        ] {
            assert!(looks_random(w), "{}", String::from_utf8_lossy(w));
        }
    }

    #[test]
    fn two_requests_complete_a_value() {
        let m = CrossMemory::new();
        let k = [1u8; 32];
        assert!(join(&m, 0, &k, vec![piece(0, 0, 14, 100)]).is_empty());
        assert_eq!(m.pieces(&k), 1);
        // The second request completes it: its piece is repaired, and remembered too.
        assert_eq!(join(&m, 1, &k, vec![piece(0, 14, 26, 7)]), vec![7]);
        assert_eq!(m.pieces(&k), 2);
    }

    #[test]
    fn three_requests_complete_a_value() {
        let m = CrossMemory::new();
        let k = [2u8; 32];
        assert!(join(&m, 0, &k, vec![piece(0, 0, 13, 5)]).is_empty());
        assert!(join(&m, 1, &k, vec![piece(0, 26, 14, 5)]).is_empty());
        assert_eq!(join(&m, 2, &k, vec![piece(0, 13, 13, 9)]), vec![9]);
    }

    #[test]
    fn the_last_bytes_may_be_missing() {
        let m = CrossMemory::new();
        let k = [3u8; 32];
        assert!(join(&m, 0, &k, vec![piece(0, 0, 12, 0)]).is_empty());
        // 33 of 40 bytes: the last seven may stay uncovered.
        assert_eq!(join(&m, 0, &k, vec![piece(0, 12, 21, 0)]), vec![0]);
        let m = CrossMemory::new();
        assert!(join(&m, 0, &k, vec![piece(0, 0, 12, 0)]).is_empty());
        assert!(join(&m, 0, &k, vec![piece(0, 12, 20, 0)]).is_empty());
    }

    #[test]
    fn other_sessions_never_combine() {
        let m = CrossMemory::new();
        assert!(join(&m, 0, &[4u8; 32], vec![piece(0, 0, 20, 0)]).is_empty());
        assert!(join(&m, 0, &[5u8; 32], vec![piece(0, 20, 20, 0)]).is_empty());
        assert_eq!(m.pieces(&[4u8; 32]), 1);
        assert_eq!(m.pieces(&[5u8; 32]), 1);
    }

    #[test]
    fn other_values_never_combine() {
        let m = CrossMemory::new();
        let k = [6u8; 32];
        assert!(join(&m, 0, &k, vec![piece(0, 0, 20, 0)]).is_empty());
        assert!(join(&m, 0, &k, vec![piece(1, 20, 20, 0)]).is_empty());
    }

    #[test]
    fn pieces_expire() {
        let m = CrossMemory::new();
        let k = [7u8; 32];
        let ttl = TTL.as_secs() as u32;
        assert!(join(&m, 0, &k, vec![piece(0, 0, 20, 0)]).is_empty());
        assert!(join(&m, ttl + 1, &k, vec![piece(0, 20, 20, 0)]).is_empty());
        // Seen again, a piece lives on.
        assert!(join(&m, ttl + 2, &k, vec![piece(0, 20, 20, 0)]).is_empty());
        assert_eq!(
            join(&m, 2 * ttl, &k, vec![piece(0, 0, 20, 0)]),
            vec![0],
            "refreshed piece forgotten"
        );
    }

    #[test]
    fn joined_forms_within_the_request_are_skipped() {
        let m = CrossMemory::new();
        let k = [8u8; 32];
        assert!(join(&m, 0, &k, vec![piece(0, 0, 20, 0)]).is_empty());
        let mut short = vec![piece(0, 20, 20, 0)];
        let mut out = Vec::new();
        m.join_at(0, &k, &mut short, &[0], &|_| LEN, &mut |a, _, _| {
            out.push(a)
        });
        assert!(out.is_empty());
        assert_eq!(m.pieces(&k), 2);
    }

    /// A piece repaired because it completed a value with old pieces still completes it with
    /// the pieces sent after, once the old ones are gone (the leak gate's case).
    #[test]
    fn repaired_pieces_are_remembered() {
        let m = CrossMemory::new();
        let k = [10u8; 32];
        let ttl = TTL.as_secs() as u32;
        assert!(join(&m, 0, &k, vec![piece(0, 20, 20, 0)]).is_empty());
        assert_eq!(join(&m, ttl, &k, vec![piece(0, 0, 14, 3)]), vec![3]);
        // The first piece has expired; the second, repaired, has not.
        assert_eq!(join(&m, ttl + 10, &k, vec![piece(0, 14, 19, 5)]), vec![5]);
    }

    #[test]
    fn memory_is_bounded() {
        let m = CrossMemory::new();
        let k = [9u8; 32];
        for f in 0..(MAX_PIECES as u32 + 50) {
            join(&m, f, &k, vec![piece(f, 0, 10, 0)]);
        }
        assert_eq!(m.pieces(&k), MAX_PIECES);
        // The oldest went first: form 0 is gone, the newest is there.
        let newest = MAX_PIECES as u32 + 49;
        assert!(join(&m, newest, &k, vec![piece(0, 10, 30, 0)]).is_empty());
        assert_eq!(
            join(&m, newest, &k, vec![piece(newest, 10, 30, 0)]),
            vec![0]
        );
        for s in 0..(MAX_SESSIONS + 10) {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&(s as u64).to_le_bytes());
            join(&m, 1000 + s as u32, &key, vec![piece(0, 0, 10, 0)]);
        }
        assert_eq!(m.sessions(), MAX_SESSIONS);
    }

    #[test]
    fn sessions_not_seen_within_the_ttl_are_swept() {
        let m = CrossMemory::new();
        let ttl = TTL.as_secs() as u32;
        for s in 0..10u8 {
            join(&m, 0, &[s; 32], vec![piece(0, 0, 10, 0)]);
        }
        for c in 0..SWEEP_EVERY {
            join(&m, ttl + 1, &[200u8; 32], vec![piece(1, 0, 10, c as usize)]);
        }
        assert_eq!(m.sessions(), 1);
    }
}
