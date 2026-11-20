//! Placeholder-shaped tokens that no credential in the snapshot resolves.
//!
//! A request toward a bound host that still carries a scrim placeholder after every known one has
//! been matched is refused with `credential_unavailable` instead of being forwarded with the
//! placeholder as plain text (credential-injection spec, "Unresolved placeholders are refused").
//! That happens while a store has not delivered a value yet, after a value left the snapshot, or
//! for a placeholder from another deployment.
//!
//! Only the exact placeholder grammar counts, so ordinary text that merely mentions scrim passes:
//!
//! - generated: `⟦scrim:<slug>:<vv><tag>⟧` (the grammar of [`scrim_redact::find_placeholders`]),
//!   as written, with its brackets or every reserved byte percent-encoded, or with its brackets
//!   JSON `\u`-escaped;
//! - reference: `{{scrim:<scheme>://<path>}}`, as written, percent-encoded or with JSON-escaped
//!   slashes.
//!
//! Declared placeholders (`SCRIM_ACME_KEY`) of credentials without a value are credentials in the
//! snapshot with no value, so the injector finds them and the request is refused there.

use crate::inject::Hit;

/// Longest reference accepted inside `{{scrim:...}}`.
const MAX_REF_LEN: usize = 512;

/// Longest token recognised here in any encoding, for stream holdback: a fully percent-encoded
/// reference placeholder.
pub(crate) const MAX_TOKEN_LEN: usize = 3 * (MAX_REF_LEN + b"{{scrim:}}".len());

/// What kind of unresolved placeholder was found. Carries no request bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Unresolved {
    /// `⟦scrim:<slug>:<code>⟧`.
    Generated,
    /// `{{scrim:<reference>}}`.
    Reference,
}

impl Unresolved {
    pub(crate) fn describe(self) -> &'static str {
        match self {
            Self::Generated => "a generated scrim placeholder (⟦scrim:…⟧)",
            Self::Reference => "a reference placeholder ({{scrim:…}})",
        }
    }
}

/// The first unresolved placeholder in `hay`, ignoring the spans of `hits` (placeholders the
/// injector resolved).
pub(crate) fn find(hay: &[u8], hits: &[Hit]) -> Option<Unresolved> {
    // Every form keeps the letters `scrim` as they are.
    if !hay.windows(5).any(|w| w.eq_ignore_ascii_case(b"scrim")) {
        return None;
    }
    let mut masked = hay.to_vec();
    for h in hits {
        if let Some(span) = masked.get_mut(h.start..h.end) {
            span.fill(b' ');
        }
    }
    let norm = normalise(&masked);
    if scrim_redact::find_placeholders(&norm).next().is_some() {
        return Some(Unresolved::Generated);
    }
    has_reference(&norm).then_some(Unresolved::Reference)
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decodes `%XX` escapes, the JSON escapes of the two brackets (`⟦`, `⟧`, either hex
/// case) and `\/`, so every encoded form reads as the raw placeholder.
fn normalise(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                    out.push((h << 4) | l);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b'\\' if b.get(i + 1) == Some(&b'/') => {
                out.push(b'/');
                i += 2;
            }
            b'\\' if b.len() >= i + 6 && b[i + 1] == b'u' => {
                let code = &b[i + 2..i + 6];
                if code.eq_ignore_ascii_case(b"27e6") {
                    out.extend_from_slice("\u{27e6}".as_bytes());
                    i += 6;
                } else if code.eq_ignore_ascii_case(b"27e7") {
                    out.extend_from_slice("\u{27e7}".as_bytes());
                    i += 6;
                } else {
                    out.push(b'\\');
                    i += 1;
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// Whether `b` holds `{{scrim:<scheme>://<path>}}`: a scheme of lower-case words joined by
/// dashes, a non-empty path of visible characters other than braces, at most [`MAX_REF_LEN`]
/// bytes of reference.
fn has_reference(b: &[u8]) -> bool {
    const OPEN: &[u8] = b"{{scrim:";
    let mut from = 0;
    while let Some(off) = b[from..].windows(OPEN.len()).position(|w| w == OPEN) {
        let start = from + off + OPEN.len();
        if reference_at(&b[start..]) {
            return true;
        }
        from = from + off + 1;
    }
    false
}

fn reference_at(b: &[u8]) -> bool {
    // Scheme.
    let mut i = 0;
    if !b.first().is_some_and(u8::is_ascii_lowercase) {
        return false;
    }
    while i < b.len() && (b[i].is_ascii_lowercase() || b[i].is_ascii_digit() || b[i] == b'-') {
        i += 1;
    }
    if b[i - 1] == b'-' || b[..i].windows(2).any(|w| w == b"--") {
        return false;
    }
    if !b[i..].starts_with(b"://") {
        return false;
    }
    i += 3;
    let path_start = i;
    while i < b.len() && i < MAX_REF_LEN {
        match b[i] {
            b'}' => break,
            b'{' => return false,
            c if c.is_ascii_whitespace() || c.is_ascii_control() => return false,
            _ => i += 1,
        }
    }
    i > path_start && b[i..].starts_with(b"}}")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::pedantic)]
mod tests {
    use super::*;

    const GEN: &str = "\u{27e6}scrim:acme:01a1b2c3d4e5f60718\u{27e7}";

    fn found(s: &str) -> Option<Unresolved> {
        find(s.as_bytes(), &[])
    }

    #[test]
    fn generated_in_every_form() {
        let pct_brackets = scrim_redact::percent_form(GEN);
        let pct_full =
            percent_encoding::percent_encode(GEN.as_bytes(), crate::inject::COMPONENT).to_string();
        let json = GEN
            .replace('\u{27e6}', "\\u27E6")
            .replace('\u{27e7}', "\\u27e7");
        for s in [
            format!("Bearer {GEN}"),
            format!("token={pct_brackets}"),
            format!("q={pct_full}&x=1"),
            format!("{{\"k\":\"{json}\"}}"),
            pct_full.to_lowercase(),
        ] {
            assert_eq!(found(&s), Some(Unresolved::Generated), "{s}");
        }
    }

    #[test]
    fn reference_in_every_form() {
        for s in [
            "key={{scrim:bao://kv/agents/acme#key}}",
            "{\"k\":\"{{scrim:bao:\\/\\/kv\\/acme}}\"}",
            "%7B%7Bscrim%3Aenv%3A%2F%2FACME_KEY%7D%7D",
            "{{scrim:vault-eu://a}}",
        ] {
            assert_eq!(found(s), Some(Unresolved::Reference), "{s}");
        }
    }

    #[test]
    fn similar_text_is_not_a_placeholder() {
        for s in [
            "scrim is a proxy",
            "\u{27e6}scrim:acme\u{27e7}",
            "\u{27e6}scrim:acme:xyz\u{27e7}",
            "\u{27e6}scrim:acme:01a1b2c3d4e5f6071\u{27e7}",
            "\u{27e6}scrim:withheld:capture-failed\u{27e7}",
            "\u{27e6}scrim:ACME:01a1b2c3d4e5f60718\u{27e7}",
            "{{scrim:notaref}}",
            "{{scrim:Bad://x}}",
            "{{scrim:bao://}}",
            "{{scrim:bao://a b}}",
            "{{ scrim:bao://x }}",
            "{scrim:bao://x}",
            "SCRIM_ACME_KEY",
            "100%",
            "%zz scrim",
        ] {
            assert_eq!(found(s), None, "{s}");
        }
    }

    #[test]
    fn resolved_hits_are_ignored() {
        let s = format!("a {GEN} b");
        let start = 2;
        let hit = Hit {
            start,
            end: start + GEN.len(),
            credential: 0,
            placeholder: 0,
            form: crate::inject::Form::Raw,
        };
        assert_eq!(find(s.as_bytes(), std::slice::from_ref(&hit)), None);
        let two = format!("a {GEN} b {}", GEN.replace("acme", "other"));
        assert_eq!(find(two.as_bytes(), &[hit]), Some(Unresolved::Generated));
    }
}
