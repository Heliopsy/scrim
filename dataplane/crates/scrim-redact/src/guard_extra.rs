//! More transform decoders of the guard: look-alike Unicode, values spelled out in words,
//! compressed documents in base64, the base85 family, and values split into short fragments
//! across the fields of one request.
//!
//! Each one is switched by [`TransformConfig`] (`redaction.guard.enable` and
//! `redaction.guard.disable`) and plugs into [`Transforms`](super::Transforms) the way the
//! decoders of `guard_tx.rs` do: a decoded view with a raw span per decoded byte, scanned with the
//! guard's own matcher, or forms of each value indexed next to it.
//!
//! * Confusables: runs holding a character that NFKC folds to ASCII (fullwidth forms,
//!   mathematical letters, ligatures, superscripts, circled letters, accented letters once their
//!   marks are dropped), a look-alike from Cyrillic, Greek, Armenian or Latin extensions, a tag
//!   character (which spells ASCII invisibly), or an invisible character (zero-width, soft
//!   hyphen, variation selector, which are dropped), read
//!   as their ASCII skeleton: lower case, `0` as `o`, `1`, `I` and `|` as `l`. Values holding
//!   `0`, `1`, `I` or `|` get their skeleton indexed too. Only runs around such a character are
//!   decoded; text without one costs one test per eight bytes.
//! * Spelled out: runs of at least eight units where the units are NATO alphabet words, digit
//!   words (`zero` to `nine`, `niner`), symbol words (`dash`, `underscore`, `dot`, ...), single
//!   letters or digits, with case words (`capital`, `lowercase`, ...) skipped, at least half of
//!   them words. Found from a NATO word or a digit word prose rarely uses (`zero`, `three`,
//!   `seven`, `eight`), searched for with one automaton.
//! * Compressed: base64 runs (wrapped or not) whose bytes start a gzip, zlib or zstd stream, and
//!   headerless deflate or brotli streams in runs that are no known file format, inflated within
//!   [`MAX_INFLATED`] per request, and scanned like a base64 text document. A value found there
//!   replaces the whole run.
//! * Base85: the inner forms of each value at the four alignments of Ascii85 (`btoa`, Python's
//!   `a85encode`, PDF), Z85 and RFC 1924 base85 (Python's `b85encode`, git) are indexed next to
//!   it, as the inner base64 forms are; nothing is decoded per request.
//! * Split fragments: fragments of a value too short for the fragment rule (at least the
//!   minimum length, below half the value) count when together they cover all of the value
//!   but its last [`SPLIT_SLACK`] bytes at most, from at least two places of the request.
//! * Cross-request: the same rule over the requests of one session, from the pieces remembered
//!   by [`crate::guard_cross`] (which value, which bytes of it, when: never the bytes).

use std::io::Read;

use zeroize::{Zeroize, Zeroizing};

use super::{MIN_UNITS, TxScratch};
use crate::guard::GuardView;

/// Which transform decoders the guard runs. Defaults: confusables, spelled-out and split
/// fragments on, base85 and compressed off; see `docs/configuration.md` for what each costs.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct TransformConfig {
    /// Look-alike Unicode and invisible characters (`confusables`).
    pub confusables: bool,
    /// Inner Ascii85, Z85 and RFC 1924 forms of each value (`base85`).
    pub base85: bool,
    /// Compressed documents in base64 runs (`compressed`).
    pub compressed: bool,
    /// Values spelled out in words (`spelled-out`).
    pub spelled: bool,
    /// Short fragments that together cover a value (`split-fragments`).
    pub split_fragments: bool,
    /// Short fragments of a value spread over several requests of one session
    /// (`cross-request`).
    pub cross_request: bool,
}

impl Default for TransformConfig {
    fn default() -> Self {
        Self {
            confusables: true,
            base85: false,
            compressed: false,
            spelled: true,
            split_fragments: true,
            cross_request: true,
        }
    }
}

/// Names of the transforms, as `redaction.guard.enable` and `.disable` take them.
pub const TRANSFORM_NAMES: &[&str] = &[
    "confusables",
    "base85",
    "compressed",
    "spelled-out",
    "split-fragments",
    "cross-request",
];

impl TransformConfig {
    /// Every transform off.
    pub fn none() -> Self {
        Self {
            confusables: false,
            base85: false,
            compressed: false,
            spelled: false,
            split_fragments: false,
            cross_request: false,
        }
    }

    /// Switches the transform called `name`; false for an unknown name.
    pub fn set(&mut self, name: &str, on: bool) -> bool {
        let f = match name {
            "confusables" => &mut self.confusables,
            "base85" => &mut self.base85,
            "compressed" => &mut self.compressed,
            "spelled-out" => &mut self.spelled,
            "split-fragments" => &mut self.split_fragments,
            "cross-request" => &mut self.cross_request,
            _ => return false,
        };
        *f = on;
        true
    }
}

// ---------------------------------------------------------------------------- derived forms

const A85: &[u8; 85] =
    b"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu";
const Z85: &[u8; 85] =
    b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";
const B85: &[u8; 85] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";

/// The base85 characters that encode only `v`'s bytes when `v` starts at byte offset `k` (0 to
/// 3) of a stream: its whole four-byte groups.
fn b85_inner(v: &[u8], k: usize, alphabet: &[u8; 85]) -> Zeroizing<Vec<u8>> {
    let start = (4 - k) % 4;
    let mut out = Zeroizing::new(Vec::with_capacity(v.len() / 4 * 5 + 5));
    if start >= v.len() {
        return out;
    }
    for g in v[start..].chunks_exact(4) {
        let mut n = u32::from_be_bytes([g[0], g[1], g[2], g[3]]);
        let mut d = [0u8; 5];
        for x in d.iter_mut().rev() {
            *x = alphabet[(n % 85) as usize];
            n /= 85;
        }
        out.extend_from_slice(&d);
        d.zeroize();
    }
    out
}

/// Pushes the base85 forms of `v` (three alphabets, four alignments).
pub(super) fn base85_forms(v: &[u8], push: &mut dyn FnMut(Zeroizing<Vec<u8>>)) {
    for alphabet in [A85, Z85, B85] {
        for k in 0..4 {
            push(b85_inner(v, k, alphabet));
        }
    }
}

/// The ASCII skeleton of one byte: lower case, `0` as `o`, `1`, `I` and `|` as `l`.
#[inline]
fn skel(c: u8) -> u8 {
    match c {
        b'0' => b'o',
        b'1' | b'I' | b'|' => b'l',
        c => c.to_ascii_lowercase(),
    }
}

/// The skeleton of `v` when it differs from `v` beyond case (it holds `0`, `1`, `I` or `|`).
pub(super) fn skeleton_form(v: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    v.iter()
        .any(|c| matches!(c, b'0' | b'1' | b'I' | b'|'))
        .then(|| Zeroizing::new(v.iter().map(|&c| skel(c)).collect()))
}

// ---------------------------------------------------------------------------- confusables

/// Most bytes one confusable run decodes to.
const MAX_RUN: usize = 4096;
/// Furthest a run starts before its first confusable character.
const MAX_BACK: usize = 512;

/// What one non-ASCII character reads as.
enum Fold {
    /// Not a look-alike: ends a run.
    No,
    /// Invisible: dropped.
    Drop,
    /// Up to three ASCII bytes.
    Ascii([u8; 3], u8),
}

/// ASCII bytes a run around a look-alike takes: printable and space. A value may hold any of
/// them, and a run that also takes the text around a value costs nothing but its length.
#[inline]
fn run_byte(c: u8) -> bool {
    (0x20..0x7F).contains(&c)
}

fn combining(c: char) -> bool {
    matches!(c as u32, 0x0300..=0x036F | 0x1AB0..=0x1AFF | 0x1DC0..=0x1DFF | 0x20D0..=0x20FF | 0xFE20..=0xFE2F)
}

/// Look-alikes of ASCII letters and digits that NFKC leaves alone, from Unicode's
/// `confusables.txt` (Cyrillic, Greek, Armenian, Latin extensions, Cherokee is left out).
#[allow(clippy::match_same_arms)] // one arm per script reads better than merged ones
fn confusable(c: char) -> Option<u8> {
    Some(match c {
        // Cyrillic.
        'а' => b'a',
        'в' | 'В' => b'B',
        'е' | 'ё' => b'e',
        'һ' => b'h',
        'і' => b'i',
        'ј' => b'j',
        'к' | 'К' => b'K',
        'ӏ' | 'Ӏ' => b'l',
        'м' | 'М' => b'M',
        'н' | 'Н' => b'H',
        'о' => b'o',
        'р' => b'p',
        'с' => b'c',
        'т' | 'Т' => b'T',
        'у' => b'y',
        'х' => b'x',
        'ѕ' => b's',
        'ԁ' => b'd',
        'ԛ' => b'q',
        'ԝ' => b'w',
        'ү' | 'Ү' => b'Y',
        'А' => b'A',
        'Е' => b'E',
        'І' => b'I',
        'Ј' => b'J',
        'О' => b'O',
        'Р' => b'P',
        'С' => b'C',
        'У' => b'Y',
        'Х' => b'X',
        'Ѕ' => b'S',
        'Ԛ' => b'Q',
        'Ԝ' => b'W',
        'Ζ' => b'Z',
        // Greek.
        'Α' => b'A',
        'Β' => b'B',
        'Ε' => b'E',
        'Η' => b'H',
        'Ι' => b'I',
        'Κ' => b'K',
        'Μ' => b'M',
        'Ν' => b'N',
        'Ο' => b'O',
        'Ρ' => b'P',
        'Τ' => b'T',
        'Υ' => b'Y',
        'Χ' => b'X',
        'α' => b'a',
        'γ' => b'y',
        'ι' => b'i',
        'κ' => b'k',
        'ν' => b'v',
        'ο' => b'o',
        'ρ' => b'p',
        'υ' => b'u',
        'χ' => b'x',
        // Armenian.
        'օ' => b'o',
        'ս' => b'u',
        'զ' => b'q',
        'ց' => b'g',
        'հ' => b'h',
        'ո' => b'n',
        'ա' => b'w',
        // Latin extensions and IPA.
        'ı' => b'i',
        'ȷ' => b'j',
        'ɡ' => b'g',
        'ɑ' => b'a',
        'ʟ' => b'L',
        'ɪ' => b'I',
        'ɴ' => b'N',
        'ʀ' => b'R',
        'ʏ' => b'Y',
        'ᴀ' => b'A',
        'ᴄ' => b'C',
        'ᴅ' => b'D',
        'ᴇ' => b'E',
        'ᴋ' => b'K',
        'ᴍ' => b'M',
        'ᴏ' => b'O',
        'ᴘ' => b'P',
        'ᴛ' => b'T',
        'ᴜ' => b'U',
        'ᴠ' => b'V',
        'ᴡ' => b'W',
        'ᴢ' => b'Z',
        'ǀ' => b'l',
        '∣' | 'ǁ' => b'l',
        '‐' | '‑' | '‒' | '–' | '—' | '−' => b'-',
        '⁄' | '∕' => b'/',
        '꞉' | '∶' => b':',
        '․' => b'.',
        _ => return None,
    })
}

/// How `c` (not ASCII) reads.
fn fold(c: char) -> Fold {
    let u = c as u32;
    // Only blocks that hold look-alikes or compatibility forms of ASCII are looked up; CJK,
    // emoji and the rest end a run at once.
    if !matches!(u, 0x00A0..=0x05FF | 0x1D00..=0x24FF | 0x2C60..=0x2C7F | 0xA720..=0xA7FF
        | 0xFB00..=0xFB06 | 0xFE00..=0xFE0F | 0xFF00..=0xFFEF | 0x1D400..=0x1D7FF
        | 0x1F100..=0x1F1FF | 0xE0000..=0xE01EF)
    {
        return Fold::No;
    }
    // Tag characters spell ASCII invisibly ("ASCII smuggling"): read them as what they spell.
    if (0xE0021..=0xE007E).contains(&u) {
        return Fold::Ascii([(u - 0xE0000) as u8, 0, 0], 1);
    }
    if matches!(u, 0x00AD | 0x034F | 0x180E | 0x200B..=0x200F | 0x2060..=0x2064 | 0xFE00..=0xFE0F
        | 0xFEFF | 0xE0000..=0xE01EF)
    {
        return Fold::Drop;
    }
    if let Some(a) = confusable(c) {
        return Fold::Ascii([a, 0, 0], 1);
    }
    let mut out = [0u8; 3];
    let mut n = 0u8;
    let mut ok = true;
    unicode_normalization::char::decompose_compatible(c, |d| {
        if combining(d) || !ok {
            return;
        }
        let d = if d.is_ascii() {
            Some(d as u8)
        } else {
            confusable(d)
        };
        match d {
            Some(a) if (0x21..0x7F).contains(&a) && usize::from(n) < out.len() => {
                out[usize::from(n)] = a;
                n += 1;
            }
            _ => ok = false,
        }
    });
    if ok && n > 0 {
        Fold::Ascii(out, n)
    } else {
        Fold::No
    }
}

/// The character at `b[i..]` and its length, for a non-ASCII lead byte.
fn decode_char(b: &[u8], i: usize) -> Option<(char, usize)> {
    let len = match b[i] {
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return None,
    };
    let s = std::str::from_utf8(b.get(i..i + len)?).ok()?;
    s.chars().next().map(|c| (c, len))
}

/// The first byte at or after `i` with its high bit set.
fn next_non_ascii(b: &[u8], mut i: usize) -> Option<usize> {
    while i + 8 <= b.len() {
        let w = u64::from_le_bytes([
            b[i],
            b[i + 1],
            b[i + 2],
            b[i + 3],
            b[i + 4],
            b[i + 5],
            b[i + 6],
            b[i + 7],
        ]);
        let m = w & 0x8080_8080_8080_8080;
        if m != 0 {
            return Some(i + (m.trailing_zeros() / 8) as usize);
        }
        i += 8;
    }
    (i..b.len()).find(|&k| b[k] >= 0x80)
}

/// Decodes every run around a look-alike or invisible character into its ASCII skeleton.
pub(super) fn confusables(b: &[u8], s: &mut TxScratch) {
    let mut i = 0;
    let mut done = 0;
    while let Some(p) = next_non_ascii(b, i) {
        let Some((c, len)) = decode_char(b, p) else {
            i = p + 1;
            continue;
        };
        if matches!(fold(c), Fold::No) {
            i = p + len;
            continue;
        }
        let mut st = p;
        while st > done && p - st < MAX_BACK && run_byte(b[st - 1]) {
            st -= 1;
        }
        let at = s.mark();
        let mut j = st;
        let mut folded = 0;
        while j < b.len() && s.bytes.len() - at < MAX_RUN {
            let x = b[j];
            if x < 0x80 {
                if !run_byte(x) {
                    break;
                }
                s.push(skel(x), j, j + 1);
                j += 1;
                continue;
            }
            let Some((c, l)) = decode_char(b, j) else {
                break;
            };
            match fold(c) {
                Fold::No => break,
                Fold::Drop => {}
                Fold::Ascii(a, n) => {
                    for &y in &a[..usize::from(n)] {
                        s.push(skel(y), j, j + l);
                    }
                }
            }
            folded += 1;
            j += l;
        }
        if folded > 0 {
            s.close(at, MIN_UNITS, GuardView::Confusable);
        } else {
            s.bytes.truncate(at);
            s.spans.truncate(at);
        }
        done = j;
        i = j.max(p + len);
    }
}

// ---------------------------------------------------------------------------- spelled out

/// What one word stands for in a spelled-out value.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Word {
    /// A letter, digit or symbol; `anchor` when the word cannot be ordinary prose on its own.
    Unit(u8, bool),
    /// A case word (`capital`, `lowercase`): no byte.
    Case,
}

fn spelled_word(w: &[u8]) -> Option<Word> {
    if w.len() == 1 {
        return Some(Word::Unit(w[0].to_ascii_lowercase(), false));
    }
    // The longest word, `underscore`.
    if w.len() > 10 {
        return None;
    }
    let mut l = [0u8; 10];
    for (d, &c) in l.iter_mut().zip(w) {
        *d = c.to_ascii_lowercase();
    }
    let unit = |c: u8| Some(Word::Unit(c, true));
    match &l[..w.len()] {
        b"alfa" | b"alpha" => unit(b'a'),
        b"bravo" => unit(b'b'),
        b"charlie" => unit(b'c'),
        b"delta" => unit(b'd'),
        b"echo" => unit(b'e'),
        b"foxtrot" => unit(b'f'),
        b"golf" => unit(b'g'),
        b"hotel" => unit(b'h'),
        b"india" => unit(b'i'),
        b"juliet" | b"juliett" => unit(b'j'),
        b"kilo" => unit(b'k'),
        b"lima" => unit(b'l'),
        b"mike" => unit(b'm'),
        b"november" => unit(b'n'),
        b"oscar" => unit(b'o'),
        b"papa" => unit(b'p'),
        b"quebec" => unit(b'q'),
        b"romeo" => unit(b'r'),
        b"sierra" => unit(b's'),
        b"tango" => unit(b't'),
        b"uniform" => unit(b'u'),
        b"victor" => unit(b'v'),
        b"whiskey" | b"whisky" => unit(b'w'),
        b"xray" => unit(b'x'),
        b"yankee" => unit(b'y'),
        b"zulu" => unit(b'z'),
        b"zero" => unit(b'0'),
        b"one" => Some(Word::Unit(b'1', false)),
        b"two" => Some(Word::Unit(b'2', false)),
        b"three" => unit(b'3'),
        b"four" => Some(Word::Unit(b'4', false)),
        b"five" => unit(b'5'),
        b"six" => unit(b'6'),
        b"seven" => unit(b'7'),
        b"eight" => unit(b'8'),
        b"nine" | b"niner" => unit(b'9'),
        b"dash" | b"hyphen" | b"minus" => unit(b'-'),
        b"underscore" => unit(b'_'),
        b"dot" | b"period" | b"point" => unit(b'.'),
        b"slash" => unit(b'/'),
        b"colon" => unit(b':'),
        b"plus" => unit(b'+'),
        b"equals" => unit(b'='),
        b"capital" | b"uppercase" | b"upper" | b"lowercase" | b"lower" | b"small" | b"cap" => {
            Some(Word::Case)
        }
        _ => None,
    }
}

/// Separators between spelled units: spaces, tabs, line breaks and commas, at most three in a
/// row. Any other printable character is a unit of its own when it stands alone (a value's `-`
/// or `"` written as it is between words).
#[inline]
fn spell_sep(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r' | b',')
}

/// Bytes a string, list or assignment starts with, glued to its first spelled unit.
const OPENERS: &[u8] = b"\"'([{:=";
/// Bytes a string or list ends with, glued to its last spelled unit.
const CLOSERS: &[u8] = b"\"')]};";

/// A byte of a spelled unit.
#[inline]
fn spell_byte(c: u8) -> bool {
    (0x21..0x7F).contains(&c) && c != b','
}

/// The unit before the one starting at `s`: skips up to three separators.
fn word_before(b: &[u8], s: usize) -> Option<(usize, usize)> {
    let mut e = s;
    while e > 0 && s - e < 3 && spell_sep(b[e - 1]) {
        e -= 1;
    }
    if e == s || e == 0 || !spell_byte(b[e - 1]) {
        return None;
    }
    let mut st = e;
    while st > 0 && spell_byte(b[st - 1]) {
        st -= 1;
    }
    Some((st, e))
}

/// The unit after the one ending at `e`.
fn word_after(b: &[u8], e: usize) -> Option<(usize, usize)> {
    let mut s = e;
    while s < b.len() && s - e < 3 && spell_sep(b[s]) {
        s += 1;
    }
    if s == e || s >= b.len() || !spell_byte(b[s]) {
        return None;
    }
    let mut en = s;
    while en < b.len() && spell_byte(b[en]) {
        en += 1;
    }
    Some((s, en))
}

/// Words a spelled-out run is found from: NATO words and the digit words prose rarely uses,
/// in lower, capitalised and upper case.
fn spell_anchors() -> &'static aho_corasick::AhoCorasick {
    static AC: std::sync::OnceLock<aho_corasick::AhoCorasick> = std::sync::OnceLock::new();
    AC.get_or_init(|| {
        const WORDS: &[&str] = &[
            "alfa", "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
            "india", "juliet", "kilo", "lima", "mike", "november", "oscar", "papa", "quebec",
            "romeo", "sierra", "tango", "uniform", "victor", "whiskey", "whisky", "xray", "yankee",
            "zulu", "zero", "three", "seven", "eight", "niner",
        ];
        let mut pats = Vec::new();
        for w in WORDS {
            pats.push((*w).to_string());
            let mut c = w.to_string();
            c[..1].make_ascii_uppercase();
            pats.push(c);
            pats.push(w.to_ascii_uppercase());
        }
        aho_corasick::AhoCorasick::builder()
            .match_kind(aho_corasick::MatchKind::LeftmostFirst)
            .build(&pats)
            .unwrap_or_else(|_| unreachable!("fixed word list"))
    })
}

/// Decodes runs of spelled units (NATO alphabet, digit and symbol words, single characters).
pub(super) fn spelled(b: &[u8], s: &mut TxScratch) {
    let mut done = 0;
    let mut from = 0;
    while let Some(m) = spell_anchors().find(aho_corasick::Input::new(b).span(from..b.len())) {
        from = m.end();
        // A whole word, after the last run.
        let (ws, we) = (m.start(), m.end());
        if ws < done || (ws > 0 && spell_byte(b[ws - 1])) || (we < b.len() && spell_byte(b[we])) {
            continue;
        }
        // Back to the first unit of the run, then forward over it. The first and last units
        // may be glued to the quote or bracket a string or list starts or ends with.
        let mut st = (ws, we);
        while let Some(w) = word_before(b, st.0) {
            if w.0 < done {
                break;
            }
            if spelled_word(&b[w.0..w.1]).is_none() {
                if let Some(k) = b[w.0..w.1].iter().rposition(|&c| OPENERS.contains(&c))
                    && w.0 + k + 1 < w.1
                    && spelled_word(&b[w.0 + k + 1..w.1]).is_some()
                {
                    st = (w.0 + k + 1, w.1);
                }
                break;
            }
            st = w;
        }
        let at = s.mark();
        let mut w = Some(st);
        let mut end = st.1;
        let mut anchors = 0;
        while let Some((a, e)) = w {
            let (e, last) = match spelled_word(&b[a..e]) {
                Some(_) => (e, false),
                None => match b[a..e].iter().position(|&c| CLOSERS.contains(&c)) {
                    Some(k) if k > 0 && spelled_word(&b[a..a + k]).is_some() => (a + k, true),
                    _ => break,
                },
            };
            match spelled_word(&b[a..e]) {
                Some(Word::Unit(c, anchor)) => {
                    s.push(c, a, e);
                    anchors += usize::from(anchor);
                }
                Some(Word::Case) => {}
                None => break,
            }
            end = e;
            if last {
                break;
            }
            w = word_after(b, e);
        }
        // Mostly spelled words, not a sentence of single letters (the separated view's case).
        if anchors * 2 >= s.bytes.len() - at {
            s.close(at, MIN_UNITS, GuardView::Spelled);
        } else {
            s.bytes.truncate(at);
            s.spans.truncate(at);
        }
        done = end;
        from = from.max(end);
    }
}

// ---------------------------------------------------------------------------- compressed

/// Most bytes all compressed documents of one request may inflate to, as the binary scan's
/// bound (`redaction.binary`).
pub(super) const MAX_INFLATED: usize = 64 << 20;
/// Most bytes one headerless stream may inflate to before it is given up: a guess at deflate or
/// brotli over data that is neither stops early.
const MAX_HEADERLESS: usize = 1 << 20;
/// Shortest base64 run looked at: a gzip stream of eight bytes is longer.
const MIN_COMPRESSED_RUN: usize = 32;

/// Base64 values of both alphabets, 0xFF for anything else.
static B64: [u8; 256] = {
    let mut t = [0xFFu8; 256];
    let a = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut i = 0;
    while i < 64 {
        t[a[i] as usize] = i as u8;
        i += 1;
    }
    t[b'-' as usize] = 62;
    t[b'_' as usize] = 63;
    t
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Codec {
    Gzip,
    Zlib,
    Zstd,
    /// No header: raw deflate, then brotli, are tried.
    Headerless,
}

/// Known file formats: not compressed streams.
const MAGIC: &[&[u8]] = &[
    b"\x89PNG",
    b"\xFF\xD8\xFF",
    b"GIF8",
    b"%PDF",
    b"PK\x03\x04",
    b"RIFF",
    b"OggS",
    b"ID3",
    b"fLaC",
    b"\x1A\x45\xDF\xA3",
    b"BM",
    b"II*\x00",
    b"MM\x00*",
    b"\x00\x00\x00",
];

/// The codec a stream starting with `h` (at least four bytes) uses, if it may be compressed.
fn sniff(h: &[u8]) -> Option<Codec> {
    if h.starts_with(&[0x1F, 0x8B, 0x08]) {
        return Some(Codec::Gzip);
    }
    if h.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
        return Some(Codec::Zstd);
    }
    if h[0] & 0x0F == 8 && h[0] >> 4 <= 7 && (u16::from(h[0]) << 8 | u16::from(h[1])) % 31 == 0 {
        return Some(Codec::Zlib);
    }
    if MAGIC.iter().any(|m| h.starts_with(m)) || h.get(4..8) == Some(b"ftyp") || text_like(h) {
        return None;
    }
    Some(Codec::Headerless)
}

/// No control bytes but tab and line breaks.
fn text_like(b: &[u8]) -> bool {
    b.iter()
        .all(|&c| c >= 0x20 && c != 0x7F || matches!(c, b'\t' | b'\n' | b'\r'))
}

/// Reads at most `limit` bytes from `r` into `out`; false when the stream is not valid.
fn inflate_into(mut r: impl Read, limit: usize, out: &mut Vec<u8>) -> bool {
    let mut buf = [0u8; 8192];
    loop {
        let room = limit.saturating_sub(out.len());
        if room == 0 {
            buf.zeroize();
            return true;
        }
        let take = room.min(buf.len());
        match r.read(&mut buf[..take]) {
            Ok(0) => {
                buf.zeroize();
                return true;
            }
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => {
                buf.zeroize();
                return !out.is_empty() && out.len() >= 64;
            }
        }
    }
}

/// Inflates `data` with `codec` into `out` (cleared first), at most `limit` bytes; false when it
/// is not such a stream or holds no text.
fn inflate(codec: Codec, data: &[u8], limit: usize, out: &mut Vec<u8>) -> bool {
    out.zeroize();
    out.clear();
    let ok = match codec {
        Codec::Gzip => inflate_into(flate2::read::MultiGzDecoder::new(data), limit, out),
        Codec::Zlib => inflate_into(flate2::read::ZlibDecoder::new(data), limit, out),
        Codec::Zstd => match zstd::stream::read::Decoder::with_buffer(data) {
            Ok(d) => inflate_into(d, limit, out),
            Err(_) => false,
        },
        Codec::Headerless => {
            let lim = limit.min(MAX_HEADERLESS);
            let deflated = inflate_into(flate2::read::DeflateDecoder::new(data), lim, out)
                && text_like(&out[..out.len().min(256)]);
            if deflated {
                true
            } else {
                out.zeroize();
                out.clear();
                inflate_into(brotli_decompressor::Decompressor::new(data, 4096), lim, out)
            }
        }
    };
    ok && !out.is_empty() && text_like(&out[..out.len().min(256)])
}

/// Base64 runs of `b` (either alphabet, continuing across line breaks after a full line of at
/// least 60 characters): `(start, end)`, line breaks included.
fn b64_runs(b: &[u8], mut f: impl FnMut(usize, usize)) {
    let mut i = 0;
    while i < b.len() {
        if B64[usize::from(b[i])] == 0xFF {
            i += 1;
            continue;
        }
        let s = i;
        let mut line = 0;
        loop {
            while i < b.len() && B64[usize::from(b[i])] != 0xFF {
                i += 1;
                line += 1;
            }
            while i < b.len() && b[i] == b'=' {
                i += 1;
            }
            let brk = match b.get(i..i + 2) {
                Some([b'\r', b'\n']) => 2,
                _ if b.get(i) == Some(&b'\n') => 1,
                _ => 0,
            };
            if brk > 0 && line >= 60 && b.get(i + brk).is_some_and(|&c| B64[usize::from(c)] != 0xFF)
            {
                i += brk;
                line = 0;
                continue;
            }
            break;
        }
        if i - s >= MIN_COMPRESSED_RUN {
            f(s, i);
        }
    }
}

/// Base64 characters of `b` decoded into `out` (line breaks and padding skipped).
fn b64_decode_skip(b: &[u8], out: &mut Vec<u8>) {
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in b {
        let v = B64[usize::from(c)];
        if v == 0xFF {
            continue;
        }
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
}

/// Compressed documents in the base64 runs of `b`: calls `found(start, end, doc)` for each run
/// that inflates to text, with the inflated text. `budget` is what the request may still inflate.
pub(super) fn compressed(
    b: &[u8],
    raw: &mut Vec<u8>,
    doc: &mut Vec<u8>,
    budget: &mut usize,
    found: &mut dyn FnMut(usize, usize, &[u8]),
) {
    b64_runs(b, |s, e| {
        if *budget == 0 {
            return;
        }
        // The first six bytes, from the first eight characters (no line break that early).
        let mut head = [0u8; 6];
        let (mut acc, mut bits, mut n) = (0u32, 0u32, 0usize);
        for &c in &b[s..s + 8] {
            acc = (acc << 6) | u32::from(B64[usize::from(c)] & 63);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                head[n] = (acc >> bits) as u8;
                n += 1;
            }
        }
        let codec = sniff(&head);
        head.zeroize();
        let Some(codec) = codec else {
            return;
        };
        raw.zeroize();
        raw.clear();
        b64_decode_skip(&b[s..e], raw);
        if inflate(codec, raw, *budget, doc) {
            *budget = budget.saturating_sub(doc.len());
            found(s, e, doc);
        }
    });
}

// ---------------------------------------------------------------------------- split fragments

/// Bytes at the end of a value its fragments may leave uncovered (a last piece shorter than the
/// fragment index can see), at most a quarter of the value.
pub(super) const SPLIT_SLACK: usize = 7;
/// Most short fragments one scan keeps.
pub(super) const MAX_SHORT: usize = 512;

/// A fragment too short for the fragment rule: where it is and which bytes of which indexed
/// form it covers.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Short {
    pub form: u32,
    pub off: u32,
    pub len: u32,
    pub start: usize,
    pub end: usize,
}

/// Bytes of a value of `len` bytes that the pieces `(off, end)` cover, and whether that is all of
/// it but [`SPLIT_SLACK`] bytes (at most a quarter of it). `pieces` is sorted by offset.
pub(super) fn covers(pieces: impl Iterator<Item = (usize, usize)>, len: usize) -> bool {
    let mut covered = 0usize;
    let mut reach = 0usize;
    for (a, b) in pieces {
        if b > reach {
            covered += b - a.max(reach);
            reach = b;
        }
    }
    covered + SPLIT_SLACK.min(len / 4) >= len
}

/// Calls `emit(start, end, form)` for every short fragment of a form whose fragments, from at
/// least two places, cover all of it but [`SPLIT_SLACK`] bytes (at most a quarter of it).
pub(super) fn assemble(
    short: &mut [Short],
    form_len: &dyn Fn(u32) -> usize,
    emit: &mut dyn FnMut(usize, usize, u32),
) {
    short.sort_unstable();
    let mut i = 0;
    while i < short.len() {
        let form = short[i].form;
        let mut j = i;
        while j < short.len() && short[j].form == form {
            j += 1;
        }
        let group = &short[i..j];
        let len = form_len(form);
        let places = group
            .iter()
            .map(|f| f.start)
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        if places >= 2
            && covers(
                group
                    .iter()
                    .map(|f| (f.off as usize, (f.off + f.len) as usize)),
                len,
            )
        {
            let mut last = None;
            for f in group {
                if last != Some((f.start, f.end)) {
                    emit(f.start, f.end, form);
                    last = Some((f.start, f.end));
                }
            }
        }
        i = j;
    }
}
