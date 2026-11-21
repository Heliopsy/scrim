//! Format-preserving placeholders: derivation keeps the shape and never returns the value, and a
//! shaped placeholder anywhere in arbitrary text is recognised (kept byte for byte by the redactor,
//! never taken for a token by the detectors, resolved by the resolver) while the value itself
//! never leaves protect().
#![no_main]

use std::sync::Arc;

use libfuzzer_sys::fuzz_target;
use scrim_redact::*;

fuzz_target!(|data: &[u8]| {
    let cut = data.iter().position(|b| *b == 0).unwrap_or(data.len());
    let value = &data[..cut];
    let hay = data.get(cut + 1..).unwrap_or_default();
    let Ok(key) = PlaceholderKey::new(1, &[3u8; 32]) else {
        return;
    };
    let slug = RefSlug::from_alias("fuzz");
    let Some(ph) = shaped_placeholder_for(&key, &slug, value) else {
        return;
    };
    assert_ne!(ph.as_bytes(), value, "a shaped placeholder equals its value");
    assert_eq!(shaped_placeholder_for(&key, &slug, value).as_deref(), Some(ph.as_str()));
    let jwt = value.starts_with(b"eyJ") && value.iter().filter(|b| **b == b'.').count() == 2;
    if !jwt {
        assert_eq!(ph.len(), value.len(), "shape lost: length");
        let prefix = PREFIXES
            .iter()
            .filter(|p| value.starts_with(p.as_bytes()))
            .max_by_key(|p| p.len())
            .copied()
            .unwrap_or("");
        assert!(ph.starts_with(prefix), "shape lost: prefix");
    }
    // A snapshot build takes milliseconds: derivation is checked on every input, the redactor,
    // guard and resolver on one in eight.
    if hay.first().is_none_or(|b| b % 8 != 0) {
        return;
    }
    // Half the inputs run without the fallback detectors, which take most of a build, so the
    // recognition paths get many more iterations; the other half checks the detectors too.
    let mut config = Config::default();
    if hay.get(1).is_some_and(|b| b & 1 == 0) {
        config.detectors.rules_enabled = false;
    }
    let Ok(snap) = Snapshot::build(
        vec![Entry::new(1, slug, ValueClass::Credential, SecretValue::from_slice(value)).with_shape(true)],
        Arc::new(Keyring::new(key)),
        &config,
    ) else {
        return;
    };
    // The placeholder resolves, alone.
    let r = snap.resolver().resolve(ph.as_bytes()).expect("shaped placeholder resolves");
    assert_eq!(r.expose(), value);
    // Embedded in arbitrary text, next to the value: the value goes, the placeholder stays.
    let mut body = hay.to_vec();
    body.extend_from_slice(ph.as_bytes());
    body.extend_from_slice(hay);
    body.extend_from_slice(value);
    let mut ws = Workspace::new();
    if let Ok(out) = snap.protect(&body, &mut ws) {
        let out = out.bytes;
        assert!(
            !out.windows(value.len()).any(|w| w == value),
            "the value left protect()"
        );
        assert!(
            out.windows(ph.len()).any(|w| w == ph.as_bytes()),
            "the shaped placeholder was changed"
        );
    }
});
