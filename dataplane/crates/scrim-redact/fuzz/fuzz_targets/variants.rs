//! A value embedded in any context, raw or encoded (hex, base64, URL, JSON nested in JSON strings),
//! never leaves protect() in that form.
#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use scrim_redact::*;

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64(d: &[u8]) -> Vec<u8> {
    let mut o = Vec::new();
    for c in d.chunks(3) {
        let x = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for q in 0..=c.len() {
            o.push(B64[((x >> (18 - 6 * q)) & 63) as usize]);
        }
    }
    o
}

fuzz_target!(|data: &[u8]| {
    let (vals, rest) = common::split(data);
    let Some(v) = vals.iter().find(|v| v.len() >= 8) else {
        return;
    };
    let Some(s) = common::snapshot(&vals, 8, EngineChoice::Auto, ValueClass::Credential) else {
        return;
    };
    let mid = rest.len() / 2;
    let (pre, post) = rest.split_at(mid);
    let form = rest.first().copied().unwrap_or(0) % 6;
    let enc: Vec<u8> = match form {
        0 => v.clone(),
        1 => v
            .iter()
            .flat_map(|b| format!("{b:02x}").into_bytes())
            .collect(),
        2 => {
            let off = usize::from(rest.get(1).copied().unwrap_or(0) % 3);
            let mut d = vec![b'#'; off];
            d.extend_from_slice(v);
            b64(&d)
        }
        // Nested JSON the redactor compiles: inner^k outer^(d-k), outer one of minimal, Go,
        // Python, depth 2 or 3.
        4 | 5 => {
            let sel = rest.get(1).copied().unwrap_or(0);
            let inner = [0u8, 1, 2, 3][usize::from(sel % 4)];
            let outer = [0u8, 1, 2][usize::from((sel / 4) % 3)];
            let d = 2 + usize::from(form == 5);
            let k = 1 + usize::from((sel / 12) % 2).min(d - 2);
            let styles: Vec<u8> = (0..d).map(|i| if i < k { inner } else { outer }).collect();
            common::json_nested(v, &styles)
        }
        _ => v
            .iter()
            .flat_map(|&b| {
                if b.is_ascii_alphanumeric() {
                    vec![b]
                } else {
                    format!("%{b:02X}").into_bytes()
                }
            })
            .collect(),
    };
    let body = [pre, &enc, post].concat();
    let mut ws = Workspace::new();
    if let Ok(p) = s.protect(&body, &mut ws) {
        assert!(!common::contains_outside(&s, p.bytes, v), "raw value left");
        if form == 1 || form >= 4 {
            assert!(
                !common::contains_outside(&s, p.bytes, &enc),
                "encoded form left"
            );
        }
    }
});
