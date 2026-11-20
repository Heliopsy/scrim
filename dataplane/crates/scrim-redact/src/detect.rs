//! Fallback detectors for secrets no store knows: pattern rules and an entropy check.
//!
//! Detectors are separate from exact matching. The redactor runs them only over the bytes
//! between exact matches, and replaces what they find with a placeholder whose slug is
//! `det-<rule>`. Such placeholders never resolve: there is no value behind them to restore.

use aho_corasick::{AhoCorasick, Input, MatchKind};
use regex::bytes::Regex;

use crate::error::BuildError;

/// Name of the entropy detector, as reported in [`crate::Hit::Detected`].
pub const ENTROPY_RULE: &str = "high-entropy";

/// Configuration of the fallback detectors.
///
/// Defaults: every built-in pattern rule on, entropy off. Entropy catches unknown random tokens
/// but also hashes, nonces and base64 data, so it is opt-in.
#[derive(Clone, Debug, PartialEq)]
pub struct DetectorConfig {
    /// Master switch for the pattern rules.
    pub rules_enabled: bool,
    /// Built-in rules switched off by name (see [`builtin_rule_names`]).
    pub disabled_rules: Vec<String>,
    /// Entropy detector; `None` disables it.
    pub entropy: Option<EntropyConfig>,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            rules_enabled: true,
            disabled_rules: Vec::new(),
            entropy: None,
        }
    }
}

/// Tuning of the entropy detector.
#[derive(Clone, Debug, PartialEq)]
pub struct EntropyConfig {
    /// Shortest token considered, in bytes.
    pub min_len: usize,
    /// Longest token considered; longer runs are data, not tokens.
    pub max_len: usize,
    /// Minimum Shannon entropy in bits per byte.
    pub threshold_bits: f64,
    /// Minimum number of character classes (lower, upper, digit) the token mixes.
    pub min_classes: u8,
}

impl Default for EntropyConfig {
    fn default() -> Self {
        Self {
            min_len: 32,
            max_len: 256,
            threshold_bits: 4.3,
            min_classes: 3,
        }
    }
}

struct Rule {
    name: &'static str,
    anchors: &'static [&'static str],
    /// Anchored at the candidate position; `^` is added at compile time.
    pattern: &'static str,
    /// Longest possible match, bounds the regex input.
    max_len: usize,
    /// Require a non-token byte before and after the match.
    boundary: bool,
}

const RULES: &[Rule] = &[
    Rule {
        name: "aws-access-key-id",
        anchors: &[
            "AKIA", "ASIA", "ABIA", "ACCA", "AGPA", "AIDA", "AROA", "ANPA", "ANVA", "AIPA",
        ],
        pattern: r"A[A-Z]{3}[A-Z2-7]{16}",
        max_len: 20,
        boundary: true,
    },
    Rule {
        name: "github-token",
        anchors: &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
        pattern: r"gh[pousr]_[A-Za-z0-9]{36,251}",
        max_len: 255,
        boundary: true,
    },
    Rule {
        name: "github-fine-grained-token",
        anchors: &["github_pat_"],
        pattern: r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}",
        max_len: 93,
        boundary: true,
    },
    Rule {
        name: "anthropic-api-key",
        anchors: &["sk-ant-"],
        pattern: r"sk-ant-[a-z]{3,8}[0-9]{2}-[A-Za-z0-9_-]{80,120}",
        max_len: 140,
        boundary: true,
    },
    Rule {
        name: "openai-api-key",
        anchors: &["sk-"],
        pattern: r"sk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,200}|[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})",
        max_len: 220,
        boundary: true,
    },
    Rule {
        name: "gitlab-token",
        anchors: &["glpat-", "gldt-", "glrt-"],
        pattern: r"gl(?:pat|dt|rt)-[A-Za-z0-9_-]{20,64}",
        max_len: 70,
        boundary: true,
    },
    Rule {
        name: "slack-token",
        anchors: &["xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-", "xoxe-"],
        pattern: r"xox[abprse]-[A-Za-z0-9-]{10,250}",
        max_len: 255,
        boundary: true,
    },
    Rule {
        name: "stripe-key",
        anchors: &["sk_live_", "rk_live_", "sk_test_", "rk_test_"],
        pattern: r"[sr]k_(?:live|test)_[A-Za-z0-9]{24,247}",
        max_len: 255,
        boundary: true,
    },
    Rule {
        name: "google-api-key",
        anchors: &["AIza"],
        pattern: r"AIza[0-9A-Za-z_-]{35}",
        max_len: 39,
        boundary: true,
    },
    Rule {
        name: "npm-token",
        anchors: &["npm_"],
        pattern: r"npm_[A-Za-z0-9]{36}",
        max_len: 40,
        boundary: true,
    },
    Rule {
        name: "jwt",
        anchors: &["eyJ"],
        pattern: r"eyJ[A-Za-z0-9_-]{8,2000}\.eyJ[A-Za-z0-9_-]{8,8000}\.[A-Za-z0-9_-]{16,1000}",
        max_len: 11_010,
        boundary: true,
    },
];

/// Private key blocks are found by code, not a regex: the body is too long for a bounded
/// repetition and may be JSON-escaped (`\n`) or literal.
const PRIVATE_KEY_RULE: &str = "private-key";
const PEM_BEGIN: &str = "-----BEGIN ";
const PEM_MAX: usize = 16 * 1024;

/// Names of all built-in pattern rules.
pub fn builtin_rule_names() -> Vec<&'static str> {
    RULES
        .iter()
        .map(|r| r.name)
        .chain(std::iter::once(PRIVATE_KEY_RULE))
        .collect()
}

struct CompiledRule {
    name: &'static str,
    anchors: &'static [&'static str],
    re: Regex,
    max_len: usize,
    boundary: bool,
}

pub(crate) struct Detectors {
    anchors: Option<AhoCorasick>,
    rules: Vec<CompiledRule>,
    pem: bool,
    entropy: Option<EntropyConfig>,
}

/// A detection: `[start, end)` and the rule name.
pub(crate) struct Detection {
    pub start: usize,
    pub end: usize,
    pub rule: &'static str,
}

#[inline]
fn is_token_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'-'
}

impl Detectors {
    pub(crate) fn build(cfg: &DetectorConfig) -> Result<Self, BuildError> {
        for name in &cfg.disabled_rules {
            if !builtin_rule_names().contains(&name.as_str()) {
                return Err(BuildError::InvalidConfig("unknown detector rule name"));
            }
        }
        let on = |n: &str| cfg.rules_enabled && !cfg.disabled_rules.iter().any(|d| d == n);
        let mut rules = Vec::new();
        for r in RULES.iter().filter(|r| on(r.name)) {
            let re =
                Regex::new(&format!("^(?-u:{})", r.pattern)).map_err(|_| BuildError::Automaton)?;
            rules.push(CompiledRule {
                name: r.name,
                anchors: r.anchors,
                re,
                max_len: r.max_len,
                boundary: r.boundary,
            });
        }
        let pem = on(PRIVATE_KEY_RULE);
        let mut anchors: Vec<&str> = rules
            .iter()
            .flat_map(|r| r.anchors.iter().copied())
            .collect();
        if pem {
            anchors.push(PEM_BEGIN);
        }
        anchors.sort_unstable();
        anchors.dedup();
        let anchors = if anchors.is_empty() {
            None
        } else {
            Some(
                AhoCorasick::builder()
                    .match_kind(MatchKind::LeftmostFirst)
                    .build(&anchors)
                    .map_err(|_| BuildError::Automaton)?,
            )
        };
        if let Some(e) = &cfg.entropy
            && (e.min_len < 8 || e.max_len < e.min_len || !(0.0..=8.0).contains(&e.threshold_bits))
        {
            return Err(BuildError::InvalidConfig("entropy detector bounds"));
        }
        Ok(Self {
            anchors,
            rules,
            pem,
            entropy: cfg.entropy.clone(),
        })
    }

    /// Longest span any enabled detector can match.
    pub(crate) fn max_match_len(&self) -> usize {
        let rules = self.rules.iter().map(|r| r.max_len).max().unwrap_or(0);
        let pem = if self.pem { PEM_MAX } else { 0 };
        let ent = self.entropy.as_ref().map_or(0, |e| e.max_len);
        rules.max(pem).max(ent)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.anchors.is_none() && self.entropy.is_none()
    }

    /// Calls `f` for each non-overlapping detection in `hay`, in order.
    pub(crate) fn scan(&self, hay: &[u8], mut f: impl FnMut(Detection)) {
        let mut pos = 0;
        // Pattern rules first: collect the next rule hit, and run entropy over the gap before it.
        while pos < hay.len() {
            let next = self.next_rule_hit(hay, pos);
            let gap_end = next.as_ref().map_or(hay.len(), |d| d.start);
            if let Some(e) = &self.entropy {
                entropy_scan(e, hay, pos, gap_end, &mut f);
            }
            match next {
                Some(d) => {
                    pos = d.end;
                    f(d);
                }
                None => break,
            }
        }
    }

    fn next_rule_hit(&self, hay: &[u8], mut pos: usize) -> Option<Detection> {
        let ac = self.anchors.as_ref()?;
        while pos < hay.len() {
            let m = ac.find(Input::new(hay).span(pos..hay.len()))?;
            let i = m.start();
            if let Some(d) = self.try_at(hay, i) {
                return Some(d);
            }
            pos = i + 1;
        }
        None
    }

    fn try_at(&self, hay: &[u8], i: usize) -> Option<Detection> {
        let left_ok = i == 0 || !is_token_byte(hay[i - 1]) || escaped_letter_before(hay, i);
        let rest = &hay[i..];
        if self.pem
            && rest.starts_with(PEM_BEGIN.as_bytes())
            && let Some(end) = pem_block(rest)
        {
            return Some(Detection {
                start: i,
                end: i + end,
                rule: PRIVATE_KEY_RULE,
            });
        }
        for r in &self.rules {
            if !r.anchors.iter().any(|a| rest.starts_with(a.as_bytes())) {
                continue;
            }
            if r.boundary && !left_ok {
                continue;
            }
            let window = &rest[..rest.len().min(r.max_len + 1)];
            if let Some(m) = r.re.find(window) {
                let end = i + m.end();
                if r.boundary && end < hay.len() && is_token_byte(hay[end]) {
                    continue;
                }
                return Some(Detection {
                    start: i,
                    end,
                    rule: r.name,
                });
            }
        }
        None
    }
}

/// `\nAKIA...` inside a JSON string: the byte before is the `n` of an escape, not a token byte.
fn escaped_letter_before(hay: &[u8], i: usize) -> bool {
    i >= 2 && hay[i - 2] == b'\\' && matches!(hay[i - 1], b'n' | b'r' | b't' | b'b' | b'f')
}

/// Length of a private key block starting at `b` (which starts with `-----BEGIN `).
///
/// The header must name a `PRIVATE KEY`. If the matching `-----END ` line is found within
/// [`PEM_MAX`] bytes the whole block is returned; otherwise the header plus the base64 body that
/// follows it (letters, digits, `+/=`, whitespace and `\n`-style escapes), so a truncated key is
/// still removed.
fn pem_block(b: &[u8]) -> Option<usize> {
    let head_end =
        memchr::memmem::find(&b[PEM_BEGIN.len()..b.len().min(80)], b"-----")? + PEM_BEGIN.len();
    let label = &b[PEM_BEGIN.len()..head_end];
    if !label.ends_with(b"PRIVATE KEY")
        || !label
            .iter()
            .all(|&c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b' ')
    {
        return None;
    }
    let body_start = head_end + 5;
    let lim = b.len().min(PEM_MAX);
    if let Some(e) = memchr::memmem::find(&b[body_start..lim], b"-----END ") {
        let e = body_start + e + 9;
        if let Some(close) = memchr::memmem::find(&b[e..lim.max(e).min(b.len())], b"-----") {
            return Some(e + close + 5);
        }
    }
    let mut j = body_start;
    while j < lim {
        let c = b[j];
        if c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=' | b'\n' | b'\r' | b' ') {
            j += 1;
        } else if c == b'\\' && j + 1 < lim && matches!(b[j + 1], b'n' | b'r') {
            j += 2;
        } else {
            break;
        }
    }
    Some(j)
}

fn entropy_scan(
    cfg: &EntropyConfig,
    hay: &[u8],
    from: usize,
    to: usize,
    f: &mut impl FnMut(Detection),
) {
    let is_tok = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'_' | b'-' | b'=');
    let mut i = from;
    while i < to {
        if !is_tok(hay[i]) {
            i += 1;
            continue;
        }
        let s = i;
        while i < to && is_tok(hay[i]) {
            i += 1;
        }
        // A JSON escape like `\n` leaves a letter glued to the token; drop it.
        let s = if s >= 1 && hay[s - 1] == b'\\' {
            s + 1
        } else {
            s
        };
        let len = i.saturating_sub(s);
        if len >= cfg.min_len && len <= cfg.max_len && high_entropy(cfg, &hay[s..i]) {
            f(Detection {
                start: s,
                end: i,
                rule: ENTROPY_RULE,
            });
        }
    }
}

fn high_entropy(cfg: &EntropyConfig, t: &[u8]) -> bool {
    let classes = u8::from(t.iter().any(u8::is_ascii_lowercase))
        + u8::from(t.iter().any(u8::is_ascii_uppercase))
        + u8::from(t.iter().any(u8::is_ascii_digit));
    if classes < cfg.min_classes {
        return false;
    }
    shannon(t) >= cfg.threshold_bits
}

/// Shannon entropy of `t` in bits per byte.
pub(crate) fn shannon(t: &[u8]) -> f64 {
    let mut counts = [0u32; 256];
    for &c in t {
        counts[usize::from(c)] += 1;
    }
    #[allow(clippy::cast_precision_loss)]
    let n = t.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / n;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]
mod tests {
    use super::*;

    fn hits(d: &Detectors, s: &str) -> Vec<(&'static str, String)> {
        let mut v = Vec::new();
        d.scan(s.as_bytes(), |x| {
            v.push((x.rule, s[x.start..x.end].to_string()))
        });
        v
    }

    fn all_on() -> Detectors {
        Detectors::build(&DetectorConfig {
            entropy: Some(EntropyConfig::default()),
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn entropy_values() {
        assert!(shannon(b"aaaaaaaa") < 0.01);
        assert!((shannon(b"abcdabcd") - 2.0).abs() < 1e-9);
    }

    #[test]
    fn disable_and_unknown() {
        let d = Detectors::build(&DetectorConfig {
            disabled_rules: vec!["jwt".into()],
            ..Default::default()
        })
        .unwrap();
        assert!(d.rules.iter().all(|r| r.name != "jwt"));
        assert!(
            Detectors::build(&DetectorConfig {
                disabled_rules: vec!["nope".into()],
                ..Default::default()
            })
            .is_err()
        );
        let off = Detectors::build(&DetectorConfig {
            rules_enabled: false,
            ..Default::default()
        })
        .unwrap();
        assert!(off.is_empty());
        assert!(hits(&off, "AKIAABCDEFGHIJKLMNOP").is_empty());
    }

    #[test]
    fn boundaries() {
        let d = all_on();
        assert_eq!(hits(&d, "key=AKIAABCDEFGHIJKLMNOP;").len(), 1);
        assert!(hits(&d, "xAKIAABCDEFGHIJKLMNOP").is_empty());
        assert!(hits(&d, "AKIAABCDEFGHIJKLMNOPQ").is_empty());
        assert_eq!(hits(&d, r#"{"t":"line\nAKIAABCDEFGHIJKLMNOP"}"#).len(), 1);
    }

    /// A projected Kubernetes service account token is a JWT signed RS256 with the cluster's
    /// issuer in its payload. The default `jwt` rule catches it whole, even before scrim has
    /// verified it and added it to the exact redaction set.
    #[test]
    fn kubernetes_service_account_token_is_a_jwt() {
        fn b64(s: &[u8]) -> String {
            const A: &[u8; 64] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            let mut out = String::new();
            for c in s.chunks(3) {
                let n = c
                    .iter()
                    .enumerate()
                    .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
                for i in 0..=c.len() {
                    out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
                }
            }
            out
        }
        let header = b64(br#"{"alg":"RS256","kid":"Nt3g0rBq1JGk5fSmW2vX7yAbCdEfGhIjKlMnOpQrStU"}"#);
        let payload = b64(
            br#"{"aud":["scrim"],"exp":1795000000,"iat":1794996400,"iss":"https://kubernetes.default.svc.cluster.local","kubernetes.io":{"namespace":"agents","pod":{"name":"agent-a-0","uid":"5b7e"},"serviceaccount":{"name":"agent-a","uid":"9c1d"}},"nbf":1794996400,"sub":"system:serviceaccount:agents:agent-a"}"#,
        );
        let sig = b64(&[0x5a; 256]);
        let tok = format!("{header}.{payload}.{sig}");
        let d = Detectors::build(&DetectorConfig::default()).unwrap();
        for text in [
            tok.clone(),
            format!("token: {tok}\n"),
            format!(r#"{{"content":"{tok}"}}"#),
        ] {
            let h = hits(&d, &text);
            assert_eq!(h.len(), 1, "{text}");
            assert_eq!(h[0], ("jwt", tok.clone()));
        }
    }

    #[test]
    fn pem_escaped_and_truncated() {
        let d = all_on();
        let s = "x -----BEGIN RSA PRIVATE KEY-----\\nMIIEow==\\n-----END RSA PRIVATE KEY----- y";
        let h = hits(&d, s);
        assert_eq!(h.len(), 1);
        assert!(h[0].1.ends_with("KEY-----"));
        let t = "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\\nAAAA\" tail";
        let h = hits(&d, t);
        assert_eq!(
            h[0].1,
            "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\\nAAAA"
        );
        assert!(
            hits(
                &d,
                "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
            )
            .is_empty()
        );
    }
}
