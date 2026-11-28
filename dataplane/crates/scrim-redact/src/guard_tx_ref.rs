//! The transform decoders as they were before their bitmap prefilters (byte-by-byte scans),
//! kept to check that the prefilters only skip positions where nothing decodes.
#![allow(clippy::unwrap_used, clippy::pedantic)]

use super::*;
use proptest::prelude::*;

fn separated_ref(b: &[u8], s: &mut TxScratch) {
    let n = b.len();
    let mut i = 0;
    let mut lens = [0usize; MAX_SEP + 1];
    while i < n {
        let mut next = i + 1;
        // Inside a word no family can start: the cheap common case.
        if i > 0 && b[i].is_ascii_alphanumeric() && b[i - 1].is_ascii_alphanumeric() {
            i = next;
            continue;
        }
        for f in FAMS {
            if !f.starts(b, i) {
                continue;
            }
            let Some(first) = unit(f, b, i) else {
                continue;
            };
            let j = i + first.len;
            // Separator candidates: each prefix of the separator tokens after the first unit.
            let mut nl = 0;
            if f.self_delimiting() {
                lens[nl] = 0;
                nl += 1;
            }
            let mut q = j;
            while q - j < MAX_SEP {
                let t = sep_tok(b, q);
                if t == 0 || q + t - j > MAX_SEP {
                    break;
                }
                q += t;
                lens[nl] = q - j;
                nl += 1;
            }
            // A separator character can also be a unit ("a   b" is "ab" spaced by three, or
            // "a b" spaced by one), so every separator that gives a long enough run is decoded.
            for &l in &lens[..nl] {
                let sep = &b[j..j + l];
                // A first unit equal to the separator is a rule line ("-----", "....").
                if f == Fam::Char && sep.first() == Some(&b[i]) {
                    continue;
                }
                let (count, end) = walk(f, b, i, sep);
                if count < MIN_UNITS {
                    continue;
                }
                let at = s.mark();
                let mut p = i;
                while let Some(d) = unit(f, b, p) {
                    for &c in d.bytes() {
                        s.push(c, p, p + d.len);
                    }
                    let end = p + d.len;
                    if sep.is_empty() {
                        p = end;
                    } else if b[end..].starts_with(sep) {
                        p = end + sep.len();
                    } else {
                        break;
                    }
                }
                s.close(at, MIN_UNITS, GuardView::Separated);
                next = next.max(end);
            }
        }
        i = next;
    }
}

fn dumps_ref(b: &[u8], s: &mut TxScratch) {
    let mut done = 0;
    for st in 0..b.len() {
        let c = b[st];
        if st < done
            || !(c.is_ascii_hexdigit() || c == b' ')
            || (st > 0 && !DUMP_PRED[usize::from(b[st - 1])])
        {
            continue;
        }
        let at = s.mark();
        let mut p = st;
        let mut end = st;
        while let Some(e) = dump_line(b, p, s) {
            end = e;
            // The next line must follow directly.
            let mut q = e;
            if b.get(q) == Some(&b'\r') {
                q += 1;
            }
            if b.get(q) != Some(&b'\n') {
                break;
            }
            p = q + 1;
        }
        if s.close(at, MIN_DUMP_BYTES, GuardView::Dump) {
            done = end;
        }
    }
}

fn base32_ref(b: &[u8], s: &mut TxScratch) {
    let n = b.len();
    let cls = |i: usize| B32C[usize::from(b[i])] & (B32_STD | B32_HEX) != 0;
    let brk = |i: usize| {
        if b[i..].starts_with(b"\r\n") {
            2
        } else {
            usize::from(b[i] == b'\n')
        }
    };
    let mut i = 0;
    while i < n {
        if !cls(i) || (i > 0 && cls(i - 1)) {
            i += 1;
            continue;
        }
        // Extent of the run.
        let start = i;
        let (mut len, mut all, mut any, mut broken) = (0usize, 0xFFu8, 0u8, false);
        loop {
            while i < n && cls(i) {
                let c = B32C[usize::from(b[i])];
                all &= c;
                any |= c;
                len += 1;
                i += 1;
            }
            if i < n {
                let k = brk(i);
                if k > 0 && i + k < n && cls(i + k) {
                    broken = true;
                    i += k;
                    continue;
                }
            }
            break;
        }
        let end = i;
        // As the tools print it: upper-case letters and digits, at least one letter. Words and
        // lower-case hex digests are not decoded.
        let upper = any & B32_UPPER != 0 && any & B32_LOWER == 0;
        if len < MIN_B32_RUN || !upper || all & (B32_STD | B32_HEX) == 0 {
            continue;
        }
        // Character positions (only copied when line breaks interrupt the run).
        s.pos.clear();
        if broken {
            s.pos
                .extend((start..end).filter(|&p| cls(p)).map(|p| p as u32));
        }
        let pos = |s: &TxScratch, k: usize| {
            if broken { s.pos[k] as usize } else { start + k }
        };
        for hex in [false, true] {
            if all & if hex { B32_HEX } else { B32_STD } == 0 {
                continue;
            }
            for align in 0..8 {
                if len - align < MIN_B32_RUN {
                    break;
                }
                let at = s.mark();
                let (mut acc, mut bits, mut j) = (0u32, 0u32, 0usize);
                for k in align..len {
                    acc = (acc << 5) | u32::from(b32_val(b[pos(s, k)], hex));
                    bits += 5;
                    if bits >= 8 {
                        bits -= 8;
                        let byte = (acc >> bits) as u8;
                        acc &= (1 << bits) - 1;
                        let c0 = align + (8 * j) / 5;
                        let c1 = align + (8 * j + 7) / 5;
                        let (from, to) = (pos(s, c0), pos(s, c1) + 1);
                        s.push(byte, from, to);
                        j += 1;
                    }
                }
                s.close(at, 8, GuardView::Base32);
            }
        }
    }
}

type Out = (Vec<u8>, Vec<(u32, u32)>, Vec<(u32, u32, u8)>);

fn out(s: &TxScratch) -> Out {
    (
        s.bytes.clone(),
        s.spans.clone(),
        s.segs
            .iter()
            .map(|g| (g.at, g.end, g.view.rank()))
            .collect(),
    )
}

/// Every decoder, prefiltered and by reference, on `b`; panics with the decoder's name on a
/// difference.
fn same(b: &[u8]) -> Result<(), TestCaseError> {
    type Dec = fn(&[u8], &mut TxScratch);
    let pairs: [(&str, Dec, Dec); 3] = [
        ("separated", separated, separated_ref),
        ("dumps", dumps, dumps_ref),
        ("base32", base32, base32_ref),
    ];
    for (name, new, old) in pairs {
        let mut a = TxScratch::default();
        a.bits.build(b);
        new(b, &mut a);
        let mut r = TxScratch::default();
        old(b, &mut r);
        prop_assert!(
            out(&a) == out(&r),
            "{name} differs on {:?}",
            String::from_utf8_lossy(b)
        );
    }
    Ok(())
}

/// Pieces the decoders react to, so random concatenations hit their edge cases.
const PIECES: &[&[u8]] = &[
    b"a",
    b"B",
    b"z",
    b"Q",
    b"7",
    b"0",
    b"9",
    b"f",
    b"F",
    b" ",
    b"  ",
    b"   ",
    b"\t",
    b"\n",
    b"\r\n",
    b"\r",
    b",",
    b", ",
    b"-",
    b".",
    b"_",
    b":",
    b";",
    b"|",
    b"/",
    b"'",
    b"\"",
    b"\\",
    b"\\x",
    b"\\n",
    b"\\0",
    b"&#",
    b"&#x",
    b";",
    b"%25",
    b"0x",
    b"=",
    b"\xE2\x80\x8B",
    b"\xEF\xBB\xBF",
    b"\xC3\xA9",
    b"\xFF",
    b"00000010: ",
    b"0000000 ",
    b"00000000  ",
    b"|",
    b"41 ",
    b"4142 ",
    b"MZXW6YTB",
    b"ORSXG5A",
    b"word",
    b"hello world ",
    b"{\"a\":\"",
    b"\"}",
];

fn pieces() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(prop::sample::select(PIECES), 0..120).prop_map(|v| v.concat())
}

fn spaced(sep: &'static [&'static [u8]]) -> impl Strategy<Value = Vec<u8>> {
    (
        prop::collection::vec(prop::sample::select(PIECES), 0..6),
        prop::collection::vec(any::<u8>(), 6..20),
        prop::sample::select(sep),
        prop::sample::select(&[0usize, 1, 2, 3, 4, 5, 6][..]),
        prop::collection::vec(prop::sample::select(PIECES), 0..6),
    )
        .prop_map(|(pre, v, sep, fam, post)| {
            let mut b = pre.concat();
            for (k, &c) in v.iter().enumerate() {
                if k > 0 {
                    b.extend_from_slice(sep);
                }
                let c = c % 0x5f + 0x20;
                match fam {
                    0 => b.push(c),
                    1 => b.extend_from_slice(format!("'{}'", c as char).as_bytes()),
                    2 => b.extend_from_slice(c.to_string().as_bytes()),
                    3 => b.extend_from_slice(format!("0x{c:02x}").as_bytes()),
                    4 => b.extend_from_slice(format!("\\x{c:02x}").as_bytes()),
                    5 => b.extend_from_slice(format!("&#{c};").as_bytes()),
                    _ => b.extend_from_slice(format!("%25{c:02X}").as_bytes()),
                }
            }
            b.extend_from_slice(&post.concat());
            b
        })
}

const B32_PIECES: &[&[u8]] = &[
    b"A", b"Z", b"2", b"7", b"0", b"9", b"V", b"W", b"a", b"\n", b"\r\n", b" ", b"=", b"\r",
];

fn b32ish() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(prop::sample::select(B32_PIECES), 0..80).prop_map(|v| v.concat())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3000))]

    #[test]
    fn prefiltered_decoders_match_reference_on_pieces(b in pieces()) {
        same(&b)?;
    }

    #[test]
    fn prefiltered_decoders_match_reference_on_runs(
        b in spaced(&[b" ", b",", b", ", b"-", b"\n", b"\xE2\x80\x8B", b"", b" . "])
    ) {
        same(&b)?;
    }

    #[test]
    fn prefiltered_decoders_match_reference_on_base32(b in b32ish()) {
        same(&b)?;
    }

    #[test]
    fn prefiltered_decoders_match_reference_on_bytes(b in prop::collection::vec(any::<u8>(), 0..300)) {
        same(&b)?;
    }
}

#[test]
fn prefiltered_decoders_match_reference_on_fixtures() {
    use crate::guard_tests::fixtures;
    let set = fixtures::gen_secrets(7, 50);
    for seed in 0..4u64 {
        let body = fixtures::gen_body(seed, 200 << 10, &set).0;
        // Every 64-byte alignment of the cut matters to the bitmaps.
        for cut in [0usize, 1, 63, 64, 65, 1000] {
            same(&body[cut..]).unwrap();
        }
    }
    for x in [
        dump_fixture_xxd(),
        "0000000   h   e   l   l   o  \\n\n0000010   w\n".to_string(),
    ] {
        same(x.as_bytes()).unwrap();
    }
}

fn dump_fixture_xxd() -> String {
    let v = b"0123456789abcdefXYZW-and-more-bytes-for-two-lines!";
    let mut out = String::new();
    for (i, line) in v.chunks(16).enumerate() {
        out.push_str(&format!("{:08x}: ", i * 16));
        for pair in line.chunks(2) {
            for c in pair {
                out.push_str(&format!("{c:02x}"));
            }
            out.push(' ');
        }
        out.push(' ');
        out.push_str(&String::from_utf8_lossy(line));
        out.push('\n');
    }
    out
}
