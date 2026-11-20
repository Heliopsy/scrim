//! Restoring in chunks equals restoring at once, for any split points, and never emits a
//! credential.
#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use scrim_redact::*;

fuzz_target!(|data: &[u8]| {
    let (vals, rest) = common::split(data);
    let vals: Vec<Vec<u8>> = vals
        .into_iter()
        .filter(|v| std::str::from_utf8(v).is_ok())
        .collect();
    if vals.is_empty() || rest.is_empty() {
        return;
    }
    let class = if rest[0] & 1 == 0 {
        ValueClass::Display
    } else {
        ValueClass::Credential
    };
    let Some(s) = common::snapshot(&vals, 8, EngineChoice::Auto, class) else {
        return;
    };
    // Text: the rest, lossily as UTF-8, with the values interleaved and then redacted.
    let filler = String::from_utf8_lossy(&rest[1..]).into_owned();
    let mut text = Vec::new();
    for (i, part) in filler.split('|').enumerate() {
        text.extend_from_slice(part.as_bytes());
        text.extend_from_slice(&vals[i % vals.len()]);
    }
    let mut red = Vec::new();
    s.redactor().redact(&text, &mut red).unwrap();
    let Ok(red) = String::from_utf8(red) else {
        return;
    };
    let mut whole = String::new();
    restore_text(s.resolver(), &RestoreDisplay, &red, &mut whole);
    let mut chunked = String::new();
    let mut b = BlockRestorer::new();
    let mut at = 0;
    let mut k = 0usize;
    while at < red.len() {
        let step = 1 + usize::from(rest[k % rest.len()] % 23);
        k += 1;
        let mut end = (at + step).min(red.len());
        while !red.is_char_boundary(end) {
            end += 1;
        }
        b.push(s.resolver(), &RestoreDisplay, &red[at..end], &mut chunked);
        assert!(b.held_len() < MAX_PERCENT_PLACEHOLDER_LEN);
        at = end;
    }
    b.finish(&mut chunked);
    assert_eq!(chunked, whole);
    if class == ValueClass::Credential {
        assert_eq!(whole, red, "credential restored");
    }
});
