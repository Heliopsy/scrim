//! Fallback detectors for secrets no store knows: known-format pattern rules and an entropy check.
//!
//! Detectors are separate from exact matching. The redactor runs them only over the bytes
//! between exact matches, and replaces what they find with a placeholder whose slug is
//! `det-<rule>`. Such placeholders never resolve: there is no value behind them to restore.
//!
//! Matching keeps the shape of the exact matcher (design D13): multi-pattern automata find the
//! anchors of every enabled rule (a fixed prefix such as `ghp_` or `AKIA`, part of a key name
//! such as `s_key` in `aws_secret_access_key`, the `://` of a URL), and a rule's anchored regular
//! expression runs only where one of its own anchors was found. Anchors are case-sensitive and
//! at least three bytes; the automata are grouped so Teddy, the SIMD prefilter, keeps few false
//! candidates (see [`automata`]).
//!
//! No rule rejects a match on a checksum. GitHub documents only that the last six characters of
//! its classic tokens are a CRC32, not exactly what is summed (see `shape.rs`, which checks both
//! readings); a rule that dropped tokens failing a guessed checksum would miss real ones when the
//! guess is wrong, and prefix, alphabet and exact length already give no hits on the corpus.

use aho_corasick::{AhoCorasick, Input, MatchKind};
use regex::bytes::Regex;
use zeroize::Zeroize;

use crate::error::BuildError;

/// Name of the entropy detector, as reported in [`crate::Hit::Detected`].
pub const ENTROPY_RULE: &str = "high-entropy";

/// Configuration of the fallback detectors.
///
/// Defaults: every built-in pattern rule that is on by default (all but
/// [`default_off_rule_names`]), encoded forms and entropy off. Entropy catches unknown random
/// tokens but also hashes, nonces and base64 data, so it is opt-in. Decoding encoded forms finds
/// nothing in ordinary text but costs about 0.5 ms per MB of agent request on one core, a third
/// of the redactor's throughput, so it is opt-in too.
#[derive(Clone, Debug, PartialEq)]
pub struct DetectorConfig {
    /// Master switch for the pattern rules (`redaction.detectors.enabled`).
    pub rules_enabled: bool,
    /// Built-in rules switched off by name (see [`builtin_rule_names`]).
    pub disabled_rules: Vec<String>,
    /// Built-in rules that are off by default, switched on by name.
    pub enabled_rules: Vec<String>,
    /// Entropy detector; `None` disables it.
    pub entropy: Option<EntropyConfig>,
    /// Also run the pattern rules over the decoded form of base64 runs, hex runs and
    /// percent-encoded text (`redaction.detectors.encoded`), and replace the characters that
    /// encode a match.
    pub encoded: bool,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            rules_enabled: true,
            disabled_rules: Vec::new(),
            enabled_rules: Vec::new(),
            entropy: None,
            encoded: false,
        }
    }
}

/// Tuning of the entropy detector.
///
/// The default only looks at values assigned to a key name that says secret ([`KEY_WORDS`]:
/// `token`, `secret`, `password`, `api_key`, a name ending in `key` or `auth`, ...), at least 16
/// bytes, 3.5 bits per byte and three of lower case, upper case, digits and symbols.
/// [`EntropyConfig::any_context`] looks at every token, which needs a longer and more random one
/// to stay quiet on hashes and identifiers.
#[derive(Clone, Debug, PartialEq)]
pub struct EntropyConfig {
    /// Shortest token considered, in bytes.
    pub min_len: usize,
    /// Longest token considered; longer runs are data, not tokens.
    pub max_len: usize,
    /// Minimum Shannon entropy in bits per byte.
    pub threshold_bits: f64,
    /// Minimum number of character classes the token mixes: lower case, upper case and digits,
    /// and with `key_names` symbols as a fourth.
    pub min_classes: u8,
    /// Only values assigned to a key name that says secret (`redaction.detectors.entropy.context`
    /// `key-name`); false looks at every token (`any`).
    pub key_names: bool,
}

impl Default for EntropyConfig {
    fn default() -> Self {
        Self {
            min_len: 16,
            max_len: 256,
            threshold_bits: 3.5,
            min_classes: 3,
            key_names: true,
        }
    }
}

impl EntropyConfig {
    /// Every token of at least 32 bytes, 4.3 bits per byte, mixing lower case, upper case and
    /// digits, whatever precedes it.
    pub fn any_context() -> Self {
        Self {
            min_len: 32,
            max_len: 256,
            threshold_bits: 4.3,
            min_classes: 3,
            key_names: false,
        }
    }
}

/// Which bytes continue a token on either side of a match. A match must not be glued to one.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Edge {
    /// Anything may follow or precede.
    Free,
    /// Letters, digits, `_` and `-`.
    Token,
    /// Letters, digits and the base64 characters `+`, `/` and `=`.
    Base64,
    /// Letters, digits, `_`, `-`, `~` and `.` (Azure AD client secrets).
    Azure,
}

impl Edge {
    fn continues(self, c: u8) -> bool {
        match self {
            Self::Free => false,
            Self::Token => is_token_byte(c),
            Self::Base64 => c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'='),
            Self::Azure => c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'~' | b'.'),
        }
    }
}

/// Where a match starts, given the position `i` of its anchor.
#[derive(Clone, Copy)]
enum Start {
    /// At the anchor.
    At,
    /// This many bytes before it.
    Back(usize),
    /// At the start of the run of bytes the function accepts that ends at the anchor, at most
    /// this many bytes back (a key name around its anchor, a URL scheme before `://`).
    Scan(usize, fn(u8) -> bool),
    /// At the start of a URL scheme before `://` (at most this many bytes back), when it is one
    /// of [`DB_SCHEMES`].
    Scheme(usize),
}

impl Start {
    fn reach(self) -> usize {
        match self {
            Self::At => 0,
            Self::Back(n) | Self::Scan(n, _) | Self::Scheme(n) => n,
        }
    }

    /// The match start for an anchor at `i`, never before `pos`.
    fn of(self, hay: &[u8], i: usize, pos: usize) -> Option<usize> {
        match self {
            Self::At => Some(i),
            Self::Back(n) => i.checked_sub(n).filter(|&s| s >= pos),
            Self::Scan(n, accepts) => {
                let lo = i.saturating_sub(n).max(pos);
                let mut s = i;
                while s > lo && accepts(hay[s - 1]) {
                    s -= 1;
                }
                Some(s)
            }
            Self::Scheme(n) => {
                let mut s = Self::Scan(n, is_scheme_byte).of(hay, i, pos)?;
                // `\npostgres://` in a JSON string: the `n` belongs to the escape.
                if escaped_letter_before(hay, s + 1) {
                    s += 1;
                }
                DB_SCHEMES
                    .iter()
                    .any(|p| hay[s..i].starts_with(p))
                    .then_some(s)
            }
        }
    }
}

fn is_ident_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.')
}

fn is_host_byte(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'-' | b'.')
}

fn is_ascii_digit_byte(c: u8) -> bool {
    c.is_ascii_digit()
}

/// Schemes `database-url-password` accepts, checked before its regex runs: `://` is in every URL.
const DB_SCHEMES: &[&[u8]] = &[
    b"postgres",
    b"mysql",
    b"mongodb",
    b"redis",
    b"amqp",
    b"mssql",
];

fn is_scheme_byte(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'+'
}

/// A post-match check over `hay[start..end]`, the bytes that would be replaced.
type Check = fn(hay: &[u8], start: usize, end: usize) -> bool;

struct Rule {
    name: &'static str,
    /// Bytes the automata look for, case-sensitive. The first three bytes of an anchor are the
    /// prefilter's fingerprint, so they are chosen to be rare in ordinary text.
    anchors: &'static [&'static str],
    /// Where the match starts relative to the anchor.
    start: Start,
    /// Anchored at the match start; `^` is added at compile time. A group named `v` makes the
    /// detection that group (the value after a key name or inside a URL) instead of the match.
    pattern: &'static str,
    /// Longest possible match, bounds the regex input.
    max_len: usize,
    /// Byte class that must not precede the match.
    left: Edge,
    /// Byte class that must not follow the detection.
    right: Edge,
    /// On unless configured otherwise.
    default_on: bool,
    check: Option<Check>,
}

/// Key, optional closing quote (also JSON-escaped), an assignment, optional opening quote.
macro_rules! assign {
    () => {
        r#"\\?["']?[ \t]*(?::=|=>|[:=])[ \t]*\\?["']?"#
    };
}

const AWS_KEY_ID_RULE: &str = "aws-access-key-id";
const AWS_SECRET_RULE: &str = "aws-secret-access-key";
const GENERIC_RULE: &str = "generic-secret-assignment";

const RULES: &[Rule] = &[
    Rule {
        name: AWS_KEY_ID_RULE,
        anchors: &[
            "AKIA", "ASIA", "ABIA", "ACCA", "AGPA", "AIDA", "AROA", "ANPA", "ANVA", "AIPA",
        ],
        start: Start::At,
        pattern: r"A[A-Z]{3}[A-Z2-7]{16}",
        max_len: 20,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    // Also found next to an access key id on the same line (see `aws_secret_neighbour`).
    Rule {
        name: AWS_SECRET_RULE,
        anchors: &["s_key", "S_KEY", "s-key", "sKey", "t_key", "T_KEY"],
        start: Start::Scan(40, is_ident_byte),
        pattern: concat!(
            r"[A-Za-z0-9_.-]{0,40}?(?i:secret[_-]?access[_-]?key|aws_secret_key)",
            assign!(),
            r"(?P<v>[A-Za-z0-9/+]{40})"
        ),
        max_len: 140,
        left: Edge::Free,
        right: Edge::Base64,
        default_on: true,
        check: None,
    },
    Rule {
        name: "github-token",
        anchors: &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
        start: Start::At,
        pattern: r"gh[pousr]_[A-Za-z0-9]{36,251}",
        max_len: 255,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "github-fine-grained-token",
        anchors: &["github_pat_"],
        start: Start::At,
        pattern: r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}",
        max_len: 93,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "anthropic-api-key",
        anchors: &["sk-ant-"],
        start: Start::At,
        pattern: r"sk-ant-[a-z]{3,8}[0-9]{2}-[A-Za-z0-9_-]{80,120}",
        max_len: 140,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "openai-api-key",
        anchors: &["sk-"],
        start: Start::At,
        pattern: r"sk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,200}|[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})",
        max_len: 220,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    // Personal, deploy, runner, feed, SCIM, feature flag, pipeline trigger and CI job tokens,
    // and runner registration tokens. Newer tokens
    // carry `.`-separated routing parts.
    Rule {
        name: "gitlab-token",
        anchors: &[
            "glp",
            "gld",
            "glr",
            "glf",
            "gls",
            "glo",
            "gli",
            "gla",
            "glc",
            "GR1348941",
        ],
        start: Start::At,
        pattern: r"(?:gl(?:pat|dt|rt|ft|soat|ffct|ptt)-[A-Za-z0-9_-]{20,128}(?:\.[A-Za-z0-9_-]{2,64}){0,3}|glcbt-[A-Za-z0-9]{1,5}_[A-Za-z0-9_-]{20,128}|GR1348941[A-Za-z0-9_-]{20,64})",
        max_len: 340,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    // `gloas-` and `glimt-`, found from their second part (`glo` and `gli` start too many
    // words to be a fingerprint).
    Rule {
        name: "gitlab-token",
        anchors: &["oas-", "imt-"],
        start: Start::Back(2),
        pattern: r"gl(?:oas|imt)-[A-Za-z0-9_-]{20,128}(?:\.[A-Za-z0-9_-]{2,64}){0,3}",
        max_len: 340,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "slack-token",
        anchors: &["xox", "xapp-"],
        start: Start::At,
        pattern: r"(?:xox[abposre]-[A-Za-z0-9-]{10,250}|xapp-[0-9]-[A-Za-z0-9-]{10,250})",
        max_len: 255,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "slack-webhook-url",
        anchors: &["hooks.slack.com/"],
        start: Start::At,
        pattern: r"hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{20,120}",
        max_len: 150,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "stripe-key",
        anchors: &["sk_", "rk_"],
        start: Start::At,
        pattern: r"[sr]k_(?:live|test)_[A-Za-z0-9]{24,247}",
        max_len: 255,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "stripe-webhook-secret",
        anchors: &["whsec_"],
        start: Start::At,
        pattern: r"whsec_[A-Za-z0-9]{32,128}",
        max_len: 134,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "google-api-key",
        anchors: &["AIza"],
        start: Start::At,
        pattern: r"AIza[0-9A-Za-z_-]{35}",
        max_len: 39,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "google-oauth-client-secret",
        anchors: &["GOCSPX-"],
        start: Start::At,
        pattern: r"GOCSPX-[A-Za-z0-9_-]{28}",
        max_len: 35,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "npm-token",
        anchors: &["npm_"],
        start: Start::At,
        pattern: r"npm_[A-Za-z0-9]{36}",
        max_len: 40,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    // A macaroon whose first bytes encode the location `pypi.org` or `test.pypi.org`.
    Rule {
        name: "pypi-token",
        anchors: &["pypi-AgE"],
        start: Start::At,
        pattern: r"pypi-AgE(?:IcHlwaS5vcmc|NdGVzdC5weXBpLm9yZw)[A-Za-z0-9_-]{50,1000}",
        max_len: 1030,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "docker-hub-token",
        anchors: &["dckr_"],
        start: Start::At,
        pattern: r"dckr_(?:pat|oat)_[A-Za-z0-9_-]{20,100}",
        max_len: 109,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "huggingface-token",
        anchors: &["hf_"],
        start: Start::At,
        pattern: r"hf_[A-Za-z]{34}",
        max_len: 42,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: Some(mixed_case_tail34),
    },
    Rule {
        name: "huggingface-token",
        anchors: &["pi_org_"],
        start: Start::Back(1),
        pattern: r"api_org_[A-Za-z]{34}",
        max_len: 42,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: Some(mixed_case_tail34),
    },
    // Twilio's secrets (auth token, API key secret) have no prefix; they are recognised by a
    // key name that says Twilio and token, secret or key. Account SIDs are not secrets.
    Rule {
        name: "twilio-credential",
        anchors: &["twilio", "Twilio", "TWILIO"],
        start: Start::At,
        pattern: concat!(
            r"(?i:twilio)[A-Za-z0-9_.-]{0,32}?(?i:token|secret|key)[A-Za-z0-9_]{0,16}",
            assign!(),
            r"(?P<v>SK[0-9a-fA-F]{32}|[A-Za-z0-9]{32})"
        ),
        max_len: 120,
        left: Edge::Free,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "sendgrid-api-key",
        anchors: &["SG."],
        start: Start::At,
        pattern: r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        max_len: 69,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    // `AccountKey=` in a storage connection string: the base64 of a 64-byte key.
    Rule {
        name: "azure-storage-key",
        anchors: &["tKey=", "tkey=", "TKEY="],
        start: Start::Scan(16, is_ident_byte),
        pattern: r"[A-Za-z]{0,16}?(?i:accountkey)=(?P<v>[A-Za-z0-9+/]{86}==)",
        max_len: 120,
        left: Edge::Free,
        right: Edge::Base64,
        default_on: true,
        check: None,
    },
    // `SharedAccessKey=` in a Service Bus or Event Hubs connection string: a 32-byte key.
    Rule {
        name: "azure-shared-access-key",
        anchors: &["sKey=", "skey=", "SKEY="],
        start: Start::Scan(16, is_ident_byte),
        pattern: r"[A-Za-z]{0,16}?(?i:sharedaccesskey)=(?P<v>[A-Za-z0-9+/]{43}=)",
        max_len: 80,
        left: Edge::Free,
        right: Edge::Base64,
        default_on: true,
        check: None,
    },
    // Three characters, a digit, `Q~`, then 31 to 34 more. Found from the digit and `Q~`.
    Rule {
        name: "azure-ad-client-secret",
        anchors: &[
            "0Q~", "1Q~", "2Q~", "3Q~", "4Q~", "5Q~", "6Q~", "7Q~", "8Q~", "9Q~",
        ],
        start: Start::Back(3),
        pattern: r"[A-Za-z0-9_~.]{3}[0-9]Q~[A-Za-z0-9_~.-]{31,34}",
        max_len: 40,
        left: Edge::Azure,
        right: Edge::Azure,
        default_on: true,
        check: None,
    },
    Rule {
        name: "digitalocean-token",
        anchors: &["_v1_"],
        start: Start::Back(3),
        pattern: r"do[opr]_v1_[a-f0-9]{64}",
        max_len: 71,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "shopify-token",
        anchors: &["shp"],
        start: Start::At,
        pattern: r"shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}",
        max_len: 38,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "atlassian-api-token",
        anchors: &["ATATT3"],
        start: Start::At,
        pattern: r"ATATT3[A-Za-z0-9_=-]{180,200}",
        max_len: 206,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    // The password of a database or broker URL (`postgres://user:password@host`).
    Rule {
        name: "database-url-password",
        anchors: &["://"],
        start: Start::Scheme(32),
        pattern: r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?|mssql)(?:\+[a-z0-9]+)?://[A-Za-z0-9._~%!$&*+;=-]{0,128}:(?P<v>[!#-&(-.0-?A-\[\]-~]{1,256})@[A-Za-z0-9\[._-]",
        max_len: 420,
        left: Edge::Token,
        right: Edge::Free,
        default_on: true,
        check: Some(not_a_password_placeholder),
    },
    Rule {
        name: "hashicorp-vault-token",
        anchors: &["hvs.", "hvb."],
        start: Start::At,
        pattern: r"hv[sb]\.[A-Za-z0-9_-]{24,512}",
        max_len: 516,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "doppler-token",
        anchors: &["dp."],
        start: Start::At,
        pattern: r"dp\.(?:pt|st|sa|ct|scim|audit)\.(?:[A-Za-z0-9_-]{1,64}\.)?[A-Za-z0-9]{40,44}",
        max_len: 125,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "onepassword-service-account-token",
        anchors: &["_eyJ"],
        start: Start::Back(3),
        pattern: r"ops_eyJ[A-Za-z0-9+/_-]{100,4000}={0,3}",
        max_len: 4010,
        left: Edge::Token,
        right: Edge::Base64,
        default_on: true,
        check: None,
    },
    Rule {
        name: "grafana-token",
        anchors: &["gls", "glc"],
        start: Start::At,
        pattern: r"(?:glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}|glc_[A-Za-z0-9+/]{32,400}={0,2})",
        max_len: 406,
        left: Edge::Token,
        right: Edge::Base64,
        default_on: true,
        check: None,
    },
    Rule {
        name: "sentry-token",
        anchors: &["sntry"],
        start: Start::At,
        pattern: r"(?:sntrys_eyJ[A-Za-z0-9+/=_-]{60,500}|sntryu_[a-f0-9]{64})",
        max_len: 511,
        left: Edge::Token,
        right: Edge::Base64,
        default_on: true,
        check: None,
    },
    Rule {
        name: "linear-api-key",
        anchors: &["lin_api_"],
        start: Start::At,
        pattern: r"lin_api_[A-Za-z0-9]{40}",
        max_len: 48,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "postman-api-key",
        anchors: &["PMAK-"],
        start: Start::At,
        pattern: r"PMAK-[a-fA-F0-9]{24}-[a-fA-F0-9]{34}",
        max_len: 64,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "age-secret-key",
        anchors: &["AGE-SECRET-KEY-1"],
        start: Start::At,
        pattern: r"AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}",
        max_len: 74,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "databricks-token",
        anchors: &["dapi"],
        start: Start::At,
        pattern: r"dapi[a-f0-9]{32}(?:-[0-9]{1,2})?",
        max_len: 39,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: Some(hex_tail_has_digit_and_letter),
    },
    // Formats added in the November 2026 review: AI providers and developer platforms that
    // issue tokens with a fixed prefix.
    Rule {
        name: "groq-api-key",
        anchors: &["sk_"],
        start: Start::Back(1),
        pattern: r"gsk_[A-Za-z0-9]{52}",
        max_len: 56,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "xai-api-key",
        anchors: &["ai-"],
        start: Start::Back(1),
        pattern: r"xai-[A-Za-z0-9]{80}",
        max_len: 84,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "perplexity-api-key",
        anchors: &["lx-"],
        start: Start::Back(2),
        pattern: r"pplx-[A-Za-z0-9]{48}",
        max_len: 53,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "openrouter-api-key",
        anchors: &["sk-or-v1-"],
        start: Start::At,
        pattern: r"sk-or-v1-[a-f0-9]{64}",
        max_len: 73,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    // DeepSeek: `sk-` and 32 lower-case hex digits.
    Rule {
        name: "deepseek-api-key",
        anchors: &["sk-"],
        start: Start::At,
        pattern: r"sk-[a-f0-9]{32}",
        max_len: 35,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: Some(hex_run_has_digit_and_letter),
    },
    Rule {
        name: "langfuse-secret-key",
        anchors: &["sk-lf-"],
        start: Start::At,
        pattern: r"sk-lf-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        max_len: 42,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "elevenlabs-api-key",
        anchors: &["sk_"],
        start: Start::At,
        pattern: r"sk_[a-f0-9]{48}",
        max_len: 51,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: Some(hex_run_has_digit_and_letter),
    },
    Rule {
        name: "replicate-api-token",
        anchors: &["r8_"],
        start: Start::At,
        pattern: r"r8_[A-Za-z0-9]{37}",
        max_len: 40,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "langsmith-api-key",
        anchors: &["v2_"],
        start: Start::Back(2),
        pattern: r"lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}",
        max_len: 51,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "pinecone-api-key",
        anchors: &["sk_"],
        start: Start::Back(2),
        pattern: r"pcsk_[A-Za-z0-9_]{40,120}",
        max_len: 125,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "tavily-api-key",
        anchors: &["ly-"],
        start: Start::Back(2),
        pattern: r"tvly-(?:dev-|prod-)?[A-Za-z0-9]{32}",
        max_len: 42,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    // Amazon Bedrock API keys: long-term keys are `ABSK` and the base64 of `BedrockAPIKey-...`,
    // short-term keys `bedrock-api-key-` and the base64 of a presigned `bedrock.amazonaws.com`
    // URL (found from that base64, which is rare in text; `bed` is not).
    Rule {
        name: "aws-bedrock-api-key",
        anchors: &["ABSKQmVkcm9ja0FQSUtleS"],
        start: Start::At,
        pattern: r"ABSKQmVkcm9ja0FQSUtleS[A-Za-z0-9+/]{20,400}={0,2}",
        max_len: 430,
        left: Edge::Token,
        right: Edge::Base64,
        default_on: true,
        check: None,
    },
    Rule {
        name: "aws-bedrock-api-key",
        anchors: &["YmVkcm9jay5hbWF6b25hd3MuY29t"],
        start: Start::Back(16),
        pattern: r"bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t[A-Za-z0-9+/]{60,4000}={0,2}",
        max_len: 4050,
        left: Edge::Token,
        right: Edge::Base64,
        default_on: true,
        check: None,
    },
    Rule {
        name: "google-oauth-access-token",
        anchors: &["ya29."],
        start: Start::At,
        pattern: r"ya29\.[A-Za-z0-9_-]{30,2048}",
        max_len: 2053,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "heroku-api-key",
        anchors: &["HRKU-"],
        start: Start::At,
        pattern: r"HRKU-AA[A-Za-z0-9_-]{58}",
        max_len: 65,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "notion-token",
        anchors: &["tn_"],
        start: Start::Back(1),
        pattern: r"ntn_[0-9]{11}[A-Za-z0-9]{35}",
        max_len: 50,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "tailscale-key",
        anchors: &["tskey-"],
        start: Start::At,
        pattern: r"tskey-[a-z]{3,8}-[A-Za-z0-9]{6,32}-[A-Za-z0-9]{16,64}",
        max_len: 112,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "sourcegraph-token",
        anchors: &["gp_"],
        start: Start::Back(1),
        pattern: r"sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}",
        max_len: 61,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "planetscale-token",
        anchors: &["pscale_"],
        start: Start::At,
        pattern: r"pscale_(?:tkn|pw|oauth)_[A-Za-z0-9_.=-]{32,64}",
        max_len: 77,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "supabase-key",
        anchors: &["bp_"],
        start: Start::Back(1),
        pattern: r"sbp_[a-f0-9]{40}",
        max_len: 44,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "supabase-key",
        anchors: &["sb_secret_"],
        start: Start::At,
        pattern: r"sb_secret_[A-Za-z0-9_-]{20,128}",
        max_len: 138,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "contentful-token",
        anchors: &["CFPAT-"],
        start: Start::At,
        pattern: r"CFPAT-[A-Za-z0-9_-]{43}",
        max_len: 49,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "new-relic-key",
        anchors: &["NRAK-"],
        start: Start::At,
        pattern: r"NRAK-[A-Z0-9]{27}",
        max_len: 32,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "dynatrace-token",
        anchors: &["dt0c01."],
        start: Start::At,
        pattern: r"dt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}",
        max_len: 96,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "mapbox-secret-token",
        anchors: &["sk.eyJ"],
        start: Start::At,
        pattern: r"sk\.eyJ[A-Za-z0-9_-]{20,1000}\.[A-Za-z0-9_-]{20,100}",
        max_len: 1106,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "prefect-api-key",
        anchors: &["nu_"],
        start: Start::Back(1),
        pattern: r"pnu_[A-Za-z0-9]{36}",
        max_len: 40,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "posthog-personal-api-key",
        anchors: &["hx_"],
        start: Start::Back(1),
        pattern: r"phx_[A-Za-z0-9]{43}",
        max_len: 47,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "square-token",
        anchors: &["sq0csp-", "sq0atp-"],
        start: Start::At,
        pattern: r"sq0(?:csp|atp)-[A-Za-z0-9_-]{22,43}",
        max_len: 50,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    // A Discord webhook URL, found from its path; the host is read back from there (past the
    // letter of an escape such as `\n` before it).
    Rule {
        name: "discord-webhook-url",
        anchors: &["/api/webhooks/"],
        start: Start::Scan(32, is_host_byte),
        pattern: r"[a-z0-9.-]{0,32}?(?P<v>(?:[a-z0-9-]+\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,68})",
        max_len: 140,
        left: Edge::Free,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    // A Telegram bot token: the bot id, `:AA` and 33 more characters.
    Rule {
        name: "telegram-bot-token",
        anchors: &[":AA"],
        start: Start::Scan(10, is_ascii_digit_byte),
        pattern: r"[0-9]{8,10}:AA[A-Za-z0-9_-]{33}",
        max_len: 46,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    Rule {
        name: "jwt",
        anchors: &["eyJ"],
        start: Start::At,
        pattern: r"eyJ[A-Za-z0-9_-]{8,2000}\.eyJ[A-Za-z0-9_-]{8,8000}\.[A-Za-z0-9_-]{16,1000}",
        max_len: 11_010,
        left: Edge::Token,
        right: Edge::Token,
        default_on: true,
        check: None,
    },
    // `password = "..."`, `api_key: ...`: a key name that says secret, then a literal value that
    // looks random. Off by default: code assigns such names from variables and calls all the
    // time, and the checks below only keep that rare.
    Rule {
        name: GENERIC_RULE,
        anchors: &[
            "password", "Password", "PASSWORD", "passwd", "PASSWD", "secret", "Secret", "SECRET",
            "token", "Token", "TOKEN", "api_key", "API_KEY", "apikey", "apiKey", "ApiKey",
            "api-key",
        ],
        start: Start::At,
        pattern: concat!(
            r"(?i:password|passwd|secret|token|api[_-]?key)[A-Za-z0-9_.-]{0,24}",
            assign!(),
            r"(?P<v>[A-Za-z0-9!#$%&*+./:;<>?@^_~=-]{8,128})"
        ),
        max_len: 200,
        left: Edge::Free,
        right: Edge::Free,
        default_on: false,
        check: Some(generic_value),
    },
];

/// Private key blocks are found by code, not a regex: the body is too long for a bounded
/// repetition and may be JSON-escaped (`\n`) or literal.
const PRIVATE_KEY_RULE: &str = "private-key";
const PEM_BEGIN: &str = "-----BEGIN ";
const PEM_MAX: usize = 16 * 1024;

/// How far after an access key id, on the same line, its secret is looked for.
const AWS_NEIGHBOUR_WINDOW: usize = 200;

/// Names of all built-in pattern rules, the ones off by default included. A rule may have
/// several entries (anchors that need different starts); it is listed once.
pub fn builtin_rule_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = Vec::new();
    for n in RULES
        .iter()
        .map(|r| r.name)
        .chain(std::iter::once(PRIVATE_KEY_RULE))
    {
        if !names.contains(&n) {
            names.push(n);
        }
    }
    names
}

/// Names of the built-in pattern rules that are off unless switched on.
pub fn default_off_rule_names() -> Vec<&'static str> {
    RULES
        .iter()
        .filter(|r| !r.default_on)
        .map(|r| r.name)
        .fold(Vec::new(), |mut v, n| {
            if !v.contains(&n) {
                v.push(n);
            }
            v
        })
}

struct CompiledRule {
    name: &'static str,
    anchors: &'static [&'static str],
    start: Start,
    re: Regex,
    group: bool,
    max_len: usize,
    left: Edge,
    right: Edge,
    check: Option<Check>,
}

pub(crate) struct Detectors {
    /// Every enabled rule's anchors, split into automata (see [`automata`]).
    automata: Vec<Group>,
    /// Every rule index, for [`Self::try_at`].
    all: Vec<u16>,
    rules: Vec<CompiledRule>,
    pem: bool,
    /// Look for an AWS secret next to an access key id.
    aws_neighbour: bool,
    /// Furthest an enabled rule's match starts before its anchor.
    max_back: usize,
    entropy: Option<EntropyConfig>,
    encoded: bool,
}

/// A detection: `[start, end)` and the rule name.
#[derive(Clone, Copy)]
pub(crate) struct Detection {
    pub start: usize,
    pub end: usize,
    pub rule: &'static str,
}

#[inline]
fn is_token_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'-'
}

/// Most automata the anchors may need; [`Cursor`] keeps one search state per automaton inline.
const MAX_AUTOMATA: usize = 8;

/// Most anchors in one automaton.
const ANCHORS_PER_AUTOMATON: usize = 24;

/// Automata over `anchors`.
///
/// Teddy, the SIMD prefilter, checks the low and high half of each fingerprint byte separately,
/// so a bucket holding several fingerprints also admits their crossings, and ordinary text,
/// mostly lower case letters, then keeps it verifying. Anchors are grouped by their fingerprint
/// (three upper case-first letters, three lower case-first letters, or a digit or punctuation
/// among the three) so the crossings stay in byte ranges text rarely hits, each group is split
/// into automata of at most [`ANCHORS_PER_AUTOMATON`], and an anchor alone in its automaton is
/// found with `memmem`. Measured with the `detect` bench group: one automaton over every anchor
/// costs about three times as much, and grouping by first byte only cost 35% more on agent
/// bodies once the rules of the November 2026 review were in. New anchors should put a digit or
/// punctuation in their first three bytes (`sk_` with the match starting a byte earlier for
/// `gsk_`): text rarely crosses those.
fn automata(rules: &[CompiledRule], pem: bool) -> Result<Vec<Group>, BuildError> {
    let mut anchors: Vec<&str> = rules
        .iter()
        .flat_map(|r| r.anchors.iter().copied())
        .collect();
    if pem {
        anchors.push(PEM_BEGIN);
    }
    anchors.sort_unstable();
    anchors.dedup();
    // An anchor that extends another adds nothing: the shorter one already finds its position.
    let minimal: Vec<&str> = anchors
        .iter()
        .copied()
        .filter(|a| {
            !anchors
                .iter()
                .any(|m| m.len() < a.len() && a.starts_with(m))
        })
        .collect();
    // Text is mostly letters: fingerprints of three letters go together by case, and those with
    // a digit or punctuation among their three bytes, which text rarely crosses, share theirs.
    let class = |a: &str| {
        let b = a.as_bytes();
        if b[..3].iter().all(u8::is_ascii_alphabetic) {
            usize::from(b[0].is_ascii_lowercase())
        } else {
            2
        }
    };
    let mut groups: Vec<Vec<&str>> = Vec::new();
    for k in 0..3 {
        let g: Vec<&str> = minimal.iter().copied().filter(|a| class(a) == k).collect();
        // The URL separator is everywhere in text; alone, it is found with `memmem`.
        let (alone, rest): (Vec<&str>, Vec<&str>) = g.into_iter().partition(|a| *a == "://");
        groups.extend(alone.into_iter().map(|a| vec![a]));
        groups.extend(rest.chunks(ANCHORS_PER_AUTOMATON).map(<[&str]>::to_vec));
    }
    groups.retain(|g| !g.is_empty());
    if groups.len() > MAX_AUTOMATA {
        return Err(BuildError::InvalidConfig("too many detector anchors"));
    }
    groups
        .iter()
        .map(|g| {
            let ac = AhoCorasick::builder()
                .match_kind(MatchKind::LeftmostFirst)
                .build(g)
                .map_err(|_| BuildError::Automaton)?;
            // Each pattern dispatches to the rules with an anchor it starts.
            let dispatch = g
                .iter()
                .map(|p| {
                    let rules: Vec<u16> = (0..rules.len())
                        .filter(|&k| rules[k].anchors.iter().any(|a| a.starts_with(p)))
                        .filter_map(|k| u16::try_from(k).ok())
                        .collect();
                    (rules, pem && PEM_BEGIN.starts_with(p))
                })
                .collect();
            Ok(Group { ac, dispatch })
        })
        .collect()
}

/// One automaton and, per pattern, the rules its matches go to and whether a private key
/// block may start there.
struct Group {
    ac: AhoCorasick,
    dispatch: Vec<(Vec<u16>, bool)>,
}

impl Detectors {
    pub(crate) fn build(cfg: &DetectorConfig) -> Result<Self, BuildError> {
        let names = builtin_rule_names();
        for name in cfg.disabled_rules.iter().chain(&cfg.enabled_rules) {
            if !names.contains(&name.as_str()) {
                return Err(BuildError::InvalidConfig("unknown detector rule name"));
            }
        }
        if cfg
            .enabled_rules
            .iter()
            .any(|n| cfg.disabled_rules.contains(n))
        {
            return Err(BuildError::InvalidConfig(
                "detector rule both enabled and disabled",
            ));
        }
        let on = |n: &str, default_on: bool| {
            cfg.rules_enabled
                && !cfg.disabled_rules.iter().any(|d| d == n)
                && (default_on || cfg.enabled_rules.iter().any(|e| e == n))
        };
        let mut rules = Vec::new();
        for r in RULES.iter().filter(|r| on(r.name, r.default_on)) {
            let re =
                Regex::new(&format!("^(?-u:{})", r.pattern)).map_err(|_| BuildError::Automaton)?;
            let group = re.capture_names().any(|n| n == Some("v"));
            rules.push(CompiledRule {
                name: r.name,
                anchors: r.anchors,
                start: r.start,
                re,
                group,
                max_len: r.max_len,
                left: r.left,
                right: r.right,
                check: r.check,
            });
        }
        let pem = on(PRIVATE_KEY_RULE, true);
        let aws_neighbour = rules.iter().any(|r| r.name == AWS_KEY_ID_RULE)
            && rules.iter().any(|r| r.name == AWS_SECRET_RULE);
        let max_back = rules.iter().map(|r| r.start.reach()).max().unwrap_or(0);
        if let Some(e) = &cfg.entropy
            && (e.min_len < 8 || e.max_len < e.min_len || !(0.0..=8.0).contains(&e.threshold_bits))
        {
            return Err(BuildError::InvalidConfig("entropy detector bounds"));
        }
        Ok(Self {
            automata: automata(&rules, pem)?,
            all: (0..rules.len())
                .filter_map(|k| u16::try_from(k).ok())
                .collect(),
            rules,
            pem,
            aws_neighbour,
            max_back,
            entropy: cfg.entropy.clone(),
            encoded: cfg.encoded,
        })
    }

    /// Longest span any enabled detector can match.
    pub(crate) fn max_match_len(&self) -> usize {
        let rules = self
            .rules
            .iter()
            .map(|r| {
                if r.name == AWS_KEY_ID_RULE && self.aws_neighbour {
                    r.max_len + AWS_NEIGHBOUR_WINDOW + 40
                } else {
                    r.max_len
                }
            })
            .max()
            .unwrap_or(0);
        let pem = if self.pem { PEM_MAX } else { 0 };
        let ent = self.entropy.as_ref().map_or(0, |e| e.max_len);
        let enc = if self.encoded && !self.automata.is_empty() {
            ENC_MAX_RUN
        } else {
            0
        };
        rules.max(pem).max(ent).max(enc)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.automata.is_empty() && self.entropy.is_none()
    }

    /// Calls `f` for each non-overlapping detection in `hay`, in order.
    pub(crate) fn scan(&self, hay: &[u8], mut f: impl FnMut(Detection)) {
        let mut cur = Cursor::default();
        let mut pos = 0;
        // Pattern rules first: collect the next rule hit, and run entropy over the gap before it.
        while pos < hay.len() {
            let next = self.next_rule_hit(hay, pos, &mut cur);
            let gap_end = next.as_ref().map_or(hay.len(), |d| d.start);
            self.scan_gap(hay, pos, gap_end, &mut f);
            match next {
                Some(d) => {
                    pos = d.end;
                    f(d);
                }
                None => break,
            }
        }
    }

    /// Detections between two rule hits: encoded forms of a rule match, then entropy over what
    /// is left.
    fn scan_gap(&self, hay: &[u8], from: usize, to: usize, f: &mut impl FnMut(Detection)) {
        if from >= to {
            return;
        }
        let mut p = from;
        if self.encoded && !self.automata.is_empty() {
            let entropy = self.entropy.as_ref();
            self.encoded_scan(hay, from, to, &mut |d| {
                if let Some(e) = entropy {
                    entropy_scan(e, hay, p, d.start, f);
                }
                p = d.end;
                f(d);
            });
        }
        if let Some(e) = &self.entropy {
            entropy_scan(e, hay, p, to, f);
        }
    }

    /// Rule matches inside the decoded form of base64 runs, hex runs and percent-encoded spans
    /// of `hay[from..to]`, each reported as the characters that encode it, in order and without
    /// overlap.
    fn encoded_scan(&self, hay: &[u8], from: usize, to: usize, f: &mut dyn FnMut(Detection)) {
        // Found out of order (runs, then escapes); only grows when something is found.
        let mut found: Vec<Detection> = Vec::new();
        b64_runs(hay, from, to, &mut |mut s, i| {
            // `\n` before the run in a JSON string: the `n` belongs to the escape.
            if escaped_letter_before(hay, s + 1) {
                s += 1;
            }
            let run = &hay[s..i];
            if run.len() < ENC_MIN_B64 || run.len() > ENC_MAX_RUN {
                return;
            }
            let mut pad = i;
            while pad < to && hay[pad] == b'=' && pad - i < 2 {
                pad += 1;
            }
            let hs = if run.starts_with(b"0x") { s + 2 } else { s };
            if hay[hs..i].iter().all(u8::is_ascii_hexdigit) {
                if i - hs >= ENC_MIN_HEX {
                    self.decoded_hex(hay, hs, i, &mut |d| found.push(d));
                }
            } else {
                self.decoded_base64(hay, s, i, pad, &mut |d| found.push(d));
            }
        });
        let mut pct_done = from;
        for i in memchr::memchr_iter(b'%', &hay[from..to]).map(|k| from + k) {
            // `%s`, `50%`: not an escape.
            if i < pct_done
                || i + 2 >= to
                || hexv(hay[i + 1]).is_none()
                || hexv(hay[i + 2]).is_none()
            {
                continue;
            }
            // A percent-encoded span: the URL-ish run around the escape.
            let mut s = i;
            while s > from.max(i.saturating_sub(ENC_MAX_PCT)) && is_url_byte(hay[s - 1]) {
                s -= 1;
            }
            let mut e = i;
            while e < to && e - s < ENC_MAX_PCT && is_url_byte(hay[e]) {
                e += 1;
            }
            pct_done = e;
            self.decoded_percent(hay, s, e, &mut |d| found.push(d));
        }
        found.sort_unstable_by_key(|d| (d.start, std::cmp::Reverse(d.end)));
        let mut last_end = from;
        for d in found {
            if d.start >= last_end && d.end > d.start {
                last_end = d.end;
                f(d);
            }
        }
    }

    /// Rule matches in the base64 run `hay[s..e]` (`pad` is its end with `=` padding).
    fn decoded_base64(
        &self,
        hay: &[u8],
        s: usize,
        e: usize,
        pad: usize,
        f: &mut dyn FnMut(Detection),
    ) {
        let run = &hay[s..e];
        // Cheap reject first: the first characters of anything but text decode to control bytes.
        let mut probe = [0u8; 36];
        let n = b64_decode_into(&run[..run.len().min(48)], &mut probe);
        let text = looks_like_text(&probe[..n]);
        probe.zeroize();
        if !text {
            return;
        }
        with_buffer(run.len() / 4 * 3 + 3, |buf| {
            let n = b64_decode_into(run, buf);
            let mut cur = Cursor::default();
            let mut pos = 0;
            while let Some(d) = self.next_rule_hit(&buf[..n], pos, &mut cur) {
                pos = d.end;
                let a = s + (d.start * 8) / 6;
                let b = (s + (d.end * 8).div_ceil(6)).min(e);
                // Padding belongs to the last group: it goes with the characters before it.
                let b = if b == e { pad } else { b };
                f(Detection {
                    start: a,
                    end: b,
                    rule: d.rule,
                });
            }
        });
    }

    /// Rule matches in the hex run `hay[s..e]`.
    fn decoded_hex(&self, hay: &[u8], s: usize, e: usize, f: &mut dyn FnMut(Detection)) {
        // Odd runs are decoded from their start; a trailing digit is left over.
        let run = &hay[s..e];
        let mut probe = [0u8; 24];
        let n = hex_decode_into(&run[..run.len().min(48)], &mut probe);
        let text = looks_like_text(&probe[..n]);
        probe.zeroize();
        if !text {
            return;
        }
        with_buffer(run.len() / 2, |buf| {
            let n = hex_decode_into(run, buf);
            let mut cur = Cursor::default();
            let mut pos = 0;
            while let Some(d) = self.next_rule_hit(&buf[..n], pos, &mut cur) {
                pos = d.end;
                f(Detection {
                    start: s + 2 * d.start,
                    end: s + 2 * d.end,
                    rule: d.rule,
                });
            }
        });
    }

    /// Rule matches in the percent-decoded form of `hay[s..e]` that cover an escape (anything
    /// else the rules saw in the raw bytes already).
    fn decoded_percent(&self, hay: &[u8], s: usize, e: usize, f: &mut dyn FnMut(Detection)) {
        // Decoded bytes, then per decoded byte its raw offset from `s` (two bytes each).
        with_buffer(3 * (e - s) + 2, |buf| {
            let (dec, at) = buf.split_at_mut(e - s);
            let mut n = 0;
            let mut j = s;
            let mut escapes = 0;
            let mut put_at = |n: usize, off: usize| {
                at[2 * n..2 * n + 2].copy_from_slice(&(off as u16).to_le_bytes());
            };
            while j < e {
                put_at(n, j - s);
                if hay[j] == b'%'
                    && j + 2 < e
                    && let (Some(h), Some(l)) = (hexv(hay[j + 1]), hexv(hay[j + 2]))
                {
                    dec[n] = h << 4 | l;
                    j += 3;
                    escapes += 1;
                } else {
                    dec[n] = hay[j];
                    j += 1;
                }
                n += 1;
            }
            put_at(n, j - s);
            if escapes == 0 {
                return;
            }
            let at = |k: usize| s + usize::from(u16::from_le_bytes([at[2 * k], at[2 * k + 1]]));
            let mut cur = Cursor::default();
            let mut pos = 0;
            while let Some(d) = self.next_rule_hit(&dec[..n], pos, &mut cur) {
                pos = d.end;
                let (a, b) = (at(d.start), at(d.end));
                // Only a match whose bytes were escaped is new.
                if hay[a..b].contains(&b'%') {
                    f(Detection {
                        start: a,
                        end: b,
                        rule: d.rule,
                    });
                }
            }
        });
    }

    /// The detection starting first at or after `pos`.
    ///
    /// A rule whose detection is a group (a value after a key name or inside a URL) may report a
    /// detection that starts after anchors still to be tried, so candidates are tried until
    /// they pass the best start found. Detections found on the way that start later are kept in
    /// `cur.pending` for the next call.
    fn next_rule_hit(&self, hay: &[u8], pos: usize, cur: &mut Cursor) -> Option<Detection> {
        cur.pending.retain(|d| d.start >= pos);
        let mut best: Option<Detection> = None;
        if let Some(k) = (0..cur.pending.len()).min_by_key(|&k| cur.pending[k].start) {
            best = Some(cur.pending.swap_remove(k));
        }
        let mut p = pos;
        loop {
            let limit = best
                .as_ref()
                .map_or(hay.len(), |b| b.start.saturating_add(self.max_back))
                .min(hay.len());
            if p >= limit {
                break;
            }
            let next = self
                .automata
                .iter()
                .zip(cur.seeks.iter_mut())
                .enumerate()
                .filter_map(|(g, (group, seek))| {
                    seek.find(&group.ac, hay, p).map(|(i, pid)| (i, g, pid))
                })
                .min();
            let Some((i, g, pid)) = next else {
                break;
            };
            if i >= limit {
                break;
            }
            let (which, pem) = &self.automata[g].dispatch[pid];
            if let Some((d, extra)) = self.try_rules(hay, i, pos, *pem, which) {
                if let Some(x) = extra {
                    cur.pending.push(x);
                }
                match &best {
                    Some(b) if b.start <= d.start => {
                        if d.start > b.start {
                            cur.pending.push(d);
                        }
                    }
                    _ => {
                        if let Some(b) = best.take() {
                            cur.pending.push(b);
                        }
                        best = Some(d);
                    }
                }
            }
            p = i + 1;
        }
        best
    }

    /// The detection of the first enabled rule whose anchor is at `i`, and a second detection
    /// it implies (an AWS secret next to its key id).
    fn try_at(&self, hay: &[u8], i: usize, pos: usize) -> Option<(Detection, Option<Detection>)> {
        self.try_rules(hay, i, pos, self.pem, &self.all)
    }

    /// [`Self::try_at`] limited to the rules `which` names (the ones an anchor dispatches to).
    fn try_rules(
        &self,
        hay: &[u8],
        i: usize,
        pos: usize,
        pem: bool,
        which: &[u16],
    ) -> Option<(Detection, Option<Detection>)> {
        let rest = &hay[i..];
        if pem
            && rest.starts_with(PEM_BEGIN.as_bytes())
            && let Some(end) = pem_block(rest)
        {
            return Some((
                Detection {
                    start: i,
                    end: i + end,
                    rule: PRIVATE_KEY_RULE,
                },
                None,
            ));
        }
        for r in which.iter().map(|&k| &self.rules[usize::from(k)]) {
            if !r.anchors.iter().any(|a| rest.starts_with(a.as_bytes())) {
                continue;
            }
            let Some(s) = r.start.of(hay, i, pos) else {
                continue;
            };
            if s > 0 && r.left.continues(hay[s - 1]) && !escaped_letter_before(hay, s) {
                continue;
            }
            let window = &hay[s..hay.len().min(s + r.max_len + 1)];
            // The lazy DFA finds the match; captures (slower) run only over a match.
            let Some(m) = r.re.find(window) else {
                continue;
            };
            let (ds, de) = if r.group {
                let Some(v) = r.re.captures(&window[..m.end()]).and_then(|c| c.name("v")) else {
                    continue;
                };
                (s + v.start(), s + v.end())
            } else {
                (s, s + m.end())
            };
            if de < hay.len() && r.right.continues(hay[de]) {
                continue;
            }
            if let Some(check) = r.check
                && !check(hay, ds, de)
            {
                continue;
            }
            // A value after a key name that is itself a known format keeps that rule's name.
            if ds > i
                && let Some((own, _)) = self.try_at(hay, ds, ds)
                && own.start == ds
            {
                return Some((own, None));
            }
            let extra = if self.aws_neighbour && r.name == AWS_KEY_ID_RULE {
                aws_secret_neighbour(hay, de)
            } else {
                None
            };
            return Some((
                Detection {
                    start: ds,
                    end: de,
                    rule: r.name,
                },
                extra,
            ));
        }
        None
    }
}

/// Per-scan state: where each automaton matches next, and detections found ahead.
#[derive(Default)]
struct Cursor {
    /// One per automaton; a fixed array so a scan without detections allocates nothing.
    seeks: [Seek; MAX_AUTOMATA],
    /// Only grows when detections are found.
    pending: Vec<Detection>,
}

/// The last search of one automaton: from `from`, the first match started at `at`. It answers
/// any later search that starts at or before `at` without searching again.
#[derive(Clone, Copy, Default)]
struct Seek {
    searched: bool,
    from: usize,
    at: Option<(usize, usize)>,
}

impl Seek {
    /// The next match at or after `p`: its start and pattern index.
    fn find(&mut self, ac: &AhoCorasick, hay: &[u8], p: usize) -> Option<(usize, usize)> {
        if self.searched && self.from <= p && self.at.is_none_or(|(a, _)| a >= p) {
            return self.at;
        }
        self.searched = true;
        self.from = p;
        self.at = ac
            .find(Input::new(hay).span(p..hay.len()))
            .map(|m| (m.start(), m.pattern().as_usize()));
        self.at
    }
}

/// An AWS secret access key on the same line as an access key id that ends at `from`, as in
/// `credentials.csv` (`AKIA...,<secret>`) or a pasted pair: the first run of exactly 40
/// base64 characters within [`AWS_NEIGHBOUR_WINDOW`] bytes that mixes upper case, lower case
/// and digits.
fn aws_secret_neighbour(hay: &[u8], from: usize) -> Option<Detection> {
    let is_b64 = |c: u8| c.is_ascii_alphanumeric() || c == b'+' || c == b'/';
    let lim = hay.len().min(from + AWS_NEIGHBOUR_WINDOW);
    let mut j = from;
    while j < lim {
        let c = hay[j];
        if c == b'\n' || c == b'\r' {
            return None;
        }
        if c == b'\\' && j + 1 < hay.len() && matches!(hay[j + 1], b'n' | b'r') {
            return None;
        }
        if !is_b64(c) {
            j += 1;
            continue;
        }
        let mut s = j;
        while j < hay.len() && is_b64(hay[j]) {
            j += 1;
        }
        // `\t` before the secret in a JSON string leaves a `t` glued to it.
        if escaped_letter_before(hay, s + 1) {
            s += 1;
        }
        let t = &hay[s..j];
        if t.len() == 40
            && hay.get(j) != Some(&b'=')
            && t.iter().any(u8::is_ascii_uppercase)
            && t.iter().any(u8::is_ascii_lowercase)
            && t.iter().any(u8::is_ascii_digit)
        {
            return Some(Detection {
                start: s,
                end: j,
                rule: AWS_SECRET_RULE,
            });
        }
    }
    None
}

/// `\nAKIA...` inside a JSON string: the byte before is the `n` of an escape, not a token byte.
fn escaped_letter_before(hay: &[u8], i: usize) -> bool {
    i >= 2 && hay[i - 2] == b'\\' && matches!(hay[i - 1], b'n' | b'r' | b't' | b'b' | b'f')
}

/// Hugging Face tokens mix cases; a 34-letter identifier in one case is a word, not a token.
fn mixed_case_tail34(hay: &[u8], _start: usize, end: usize) -> bool {
    let t = &hay[end - 34..end];
    t.iter().any(u8::is_ascii_uppercase) && t.iter().any(u8::is_ascii_lowercase)
}

/// Databricks tokens are 32 random hex digits; a run of only digits or only letters is not one.
fn hex_tail_has_digit_and_letter(hay: &[u8], start: usize, _end: usize) -> bool {
    let t = &hay[start + 4..start + 36];
    t.iter().any(u8::is_ascii_digit) && t.iter().any(u8::is_ascii_lowercase)
}

/// A run of random hex digits holds both; `sk-` or `sk_` and only digits or only letters is a
/// name, not a key.
fn hex_run_has_digit_and_letter(hay: &[u8], start: usize, end: usize) -> bool {
    let t = &hay[start + 3..end];
    t.iter().any(u8::is_ascii_digit) && t.iter().any(u8::is_ascii_lowercase)
}

/// Words documentation writes where a password goes. Matched whole, ignoring case.
const PASSWORD_WORDS: &[&str] = &[
    "password", "passwd", "pass", "pwd", "pw", "secret", "redacted", "changeme", "example",
];

/// A URL password that is a template, a variable or a stand-in is not replaced.
fn not_a_password_placeholder(hay: &[u8], start: usize, end: usize) -> bool {
    let v = &hay[start..end];
    let wrapped = |open: u8, close: u8| v.len() > 2 && v[0] == open && v[v.len() - 1] == close;
    let variable = v.len() > 1
        && v[0] == b'$'
        && (matches!(v[1], b'{' | b'(')
            || v[1..]
                .iter()
                .all(|&c| c.is_ascii_alphanumeric() || c == b'_'));
    if variable
        || wrapped(b'<', b'>')
        || wrapped(b'{', b'}')
        || wrapped(b'[', b']')
        || v.starts_with(b"%(")
        || v.iter().all(|&c| c == v[0])
    {
        return false;
    }
    !PASSWORD_WORDS
        .iter()
        .any(|w| v.eq_ignore_ascii_case(w.as_bytes()))
}

/// A literal that looks like a secret: no variable, call or reference, at least three of lower
/// case, upper case, digits and symbols with a digit among them, and some entropy.
fn generic_value(hay: &[u8], start: usize, end: usize) -> bool {
    let v = &hay[start..end];
    if matches!(hay.get(end), Some(b'(' | b'[' | b'{')) {
        return false;
    }
    if matches!(v[0], b'$' | b'<' | b'{' | b'%' | b'.' | b'/') {
        return false;
    }
    if memchr::memmem::find(v, b"://").is_some() {
        return false;
    }
    // `settings.SECRET_KEY`, `os.environ`: dotted identifiers.
    if v.iter()
        .all(|&c| c.is_ascii_alphanumeric() || c == b'_' || c == b'.')
        && v.contains(&b'.')
    {
        return false;
    }
    let lower = v.iter().any(u8::is_ascii_lowercase);
    let upper = v.iter().any(u8::is_ascii_uppercase);
    let digit = v.iter().any(u8::is_ascii_digit);
    let symbol = v.iter().any(|c| !c.is_ascii_alphanumeric());
    let classes = u8::from(lower) + u8::from(upper) + u8::from(digit) + u8::from(symbol);
    digit && classes >= 3 && shannon(v) >= 3.0
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

/// Shortest base64 run decoded for rule matches: the shortest rule match is 20 bytes.
const ENC_MIN_B64: usize = 24;
/// Shortest hex run decoded for rule matches.
const ENC_MIN_HEX: usize = 40;
/// Longest base64 or hex run decoded for rule matches; longer runs are data (images, archives).
const ENC_MAX_RUN: usize = 16 * 1024;
/// Longest percent-encoded span decoded for rule matches.
const ENC_MAX_PCT: usize = 4096;

/// Base64 values of both alphabets, 0xFF for anything else.
const B64DEC: [u8; 256] = {
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

/// Decodes base64 characters (either alphabet, no padding) into `out`; returns the bytes
/// written. Stops when `out` is full.
fn b64_decode_into(chars: &[u8], out: &mut [u8]) -> usize {
    let (mut acc, mut bits, mut n) = (0u32, 0u32, 0usize);
    for &c in chars {
        let v = B64DEC[usize::from(c)];
        if v == 0xFF {
            break;
        }
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            if n == out.len() {
                break;
            }
            out[n] = (acc >> bits) as u8;
            n += 1;
        }
    }
    n
}

fn hexv(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn hex_decode_into(digits: &[u8], out: &mut [u8]) -> usize {
    let mut n = 0;
    for p in digits.chunks_exact(2) {
        let (Some(h), Some(l)) = (hexv(p[0]), hexv(p[1])) else {
            break;
        };
        if n == out.len() {
            break;
        }
        out[n] = h << 4 | l;
        n += 1;
    }
    n
}

fn is_b64_byte(c: u8) -> bool {
    B64DEC[usize::from(c)] != 0xFF
}

const fn rep8(b: u8) -> u64 {
    u64::from_ne_bytes([b; 8])
}

/// Bytes of `x` (high bits clear) in `lo..=hi`, as their high bit.
const fn in_range8(x: u64, lo: u8, hi: u8) -> u64 {
    x.wrapping_add(rep8(0x80 - lo)) & !x.wrapping_add(rep8(0x7F - hi)) & rep8(0x80)
}

/// Whether all eight bytes are base64 characters of either alphabet, eight at a time.
fn all_b64_8(b: &[u8]) -> bool {
    let Ok(b) = <[u8; 8]>::try_from(b) else {
        return false;
    };
    let w = u64::from_ne_bytes(b);
    // Any byte below `+` (space, quote, line break, control): no base64 character. One test
    // that rejects most chunks of text.
    if w.wrapping_sub(rep8(b'+')) & !w & rep8(0x80) != 0 {
        return false;
    }
    let x = w & rep8(0x7F);
    let ok = in_range8(x, b'0', b'9')
        | in_range8(x, b'A', b'Z')
        | in_range8(x, b'a', b'z')
        | in_range8(x, b'+', b'+')
        | in_range8(x, b'-', b'-')
        | in_range8(x, b'/', b'/')
        | in_range8(x, b'_', b'_');
    ok & !(w & rep8(0x80)) == rep8(0x80)
}

/// Calls `f(start, end)` for every maximal run of at least [`ENC_MIN_B64`] base64 characters
/// in `hay[from..to]`, in order. Such a run holds two consecutive aligned eight-byte chunks of
/// base64 characters, one of them at an offset divisible by sixteen, so the scan tests every
/// other chunk and expands only around a full pair: prose and code, whose words are shorter,
/// cost one test per sixteen bytes, most of them failing on the first byte below `+` (a space,
/// a quote, a line break).
fn b64_runs(hay: &[u8], from: usize, to: usize, f: &mut dyn FnMut(usize, usize)) {
    let full = |c: usize| all_b64_8(&hay[c..c + 8]);
    let mut c = from.div_ceil(16) * 16;
    while c + 8 <= to {
        if !full(c) || !((c >= from + 8 && full(c - 8)) || (c + 16 <= to && full(c + 8))) {
            c += 16;
            continue;
        }
        let mut s = c;
        while s >= from + 8 && full(s - 8) {
            s -= 8;
        }
        while s > from && is_b64_byte(hay[s - 1]) {
            s -= 1;
        }
        let mut e = c + 8;
        while e + 8 <= to && full(e) {
            e += 8;
        }
        while e < to && is_b64_byte(hay[e]) {
            e += 1;
        }
        if e - s >= ENC_MIN_B64 {
            f(s, e);
        }
        c = (e + 1).div_ceil(16) * 16;
    }
}

/// Calls `f(start, end)` for every maximal run of bytes `class` accepts in `hay[from..to]` that
/// is at least `min` long, in order. Such a run holds a position that is a multiple of `min`,
/// so only those positions are probed: text costs one lookup every `min` bytes plus the words
/// it lands in. `class` accepts every base64 character, so runs of them (data, blobs) are
/// stepped over eight bytes at a time.
fn long_runs(
    hay: &[u8],
    from: usize,
    to: usize,
    min: usize,
    class: impl Fn(u8) -> bool,
    f: &mut dyn FnMut(usize, usize),
) {
    let min = min.max(1);
    let mut p = from.div_ceil(min) * min;
    while p < to {
        if !class(hay[p]) {
            p += min;
            continue;
        }
        let mut s = p;
        while s >= from + 8 && all_b64_8(&hay[s - 8..s]) {
            s -= 8;
        }
        while s > from && class(hay[s - 1]) {
            s -= 1;
        }
        let mut e = p + 1;
        while e + 8 <= to && all_b64_8(&hay[e..e + 8]) {
            e += 8;
        }
        while e < to && class(hay[e]) {
            e += 1;
        }
        if e - s >= min {
            f(s, e);
        }
        p = (e + 1).div_ceil(min) * min;
    }
}

thread_local! {
    /// Decoded bytes of an encoded run, reused so a scan allocates nothing once warm.
    static DECODED: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Runs `f` with a zeroed buffer of `n` bytes, wiped afterwards.
fn with_buffer(n: usize, f: impl FnOnce(&mut [u8])) {
    DECODED.with(|b| {
        // A nested call (none today) gets a fresh buffer instead of a borrow panic.
        let Ok(mut v) = b.try_borrow_mut() else {
            let mut v = vec![0u8; n];
            f(&mut v);
            v.zeroize();
            return;
        };
        if v.len() < n {
            v.resize(n, 0);
        }
        f(&mut v[..n]);
        v[..n].zeroize();
    });
}

/// Characters of a URL, a query string or form data, `%` included.
fn is_url_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            b'%' | b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=' | b'&' | b':' | b'?' | b'@'
        )
}

/// No control bytes but tab and line breaks: decoded text, not binary data.
fn looks_like_text(b: &[u8]) -> bool {
    !b.is_empty()
        && b.iter()
            .all(|&c| c >= 0x20 && c != 0x7F || matches!(c, b'\t' | b'\n' | b'\r'))
}

/// Key names whose value the entropy detector looks at, matched in the lower-cased name (a name
/// ending in `key` or `auth` counts too).
const KEY_WORDS: &[&[u8]] = &[
    b"token",
    b"secret",
    b"password",
    b"passwd",
    b"passphrase",
    b"pwd",
    b"apikey",
    b"api_key",
    b"api-key",
    b"credential",
    b"bearer",
    b"private_key",
    b"privatekey",
];

/// Parts of key names whose high-entropy values are not secrets.
const NOT_SECRET_WORDS: &[&[u8]] = &[
    b"page",
    b"next",
    b"cursor",
    b"continuation",
    b"sync",
    b"csrf",
    b"xsrf",
    b"nonce",
];

/// Whether the token starting at `s` is the value of a key name that says secret: `name=`,
/// `name: `, `"name": "`, `name := `, `name => `, `--name ` or `Bearer `.
fn key_context(hay: &[u8], s: usize) -> bool {
    let lo = s.saturating_sub(96);
    let mut j = s;
    let quote = |j: &mut usize| {
        if *j > lo && matches!(hay[*j - 1], b'"' | b'\'') {
            *j -= 1;
            if *j > lo && hay[*j - 1] == b'\\' {
                *j -= 1;
            }
        }
    };
    let spaces = |j: &mut usize| {
        let at = *j;
        while *j > lo && at - *j < 4 && matches!(hay[*j - 1], b' ' | b'\t') {
            *j -= 1;
        }
        at - *j
    };
    quote(&mut j);
    let sp = spaces(&mut j);
    let op = if j >= lo + 2 && &hay[j - 2..j] == b"=>" {
        j -= 2;
        true
    } else if j > lo && hay[j - 1] == b'=' {
        j -= 1;
        if j > lo && hay[j - 1] == b':' {
            j -= 1;
        }
        true
    } else if j > lo && hay[j - 1] == b':' {
        j -= 1;
        true
    } else {
        false
    };
    if !op && sp == 0 {
        return false;
    }
    if op {
        spaces(&mut j);
        quote(&mut j);
    }
    let end = j;
    while j > lo && end - j < 64 && is_ident_byte(hay[j - 1]) {
        j -= 1;
    }
    let key = &hay[j..end];
    // `scheme://user:password@host`: a URL's user name, not a key.
    if key.is_empty() || key.len() > 63 || hay[..j].ends_with(b"//") {
        return false;
    }
    let mut low = [0u8; 64];
    for (d, &c) in low.iter_mut().zip(key) {
        *d = c.to_ascii_lowercase();
    }
    let low = &low[..key.len()];
    let low = low.strip_suffix(b"s").unwrap_or(low);
    // Tokens a client must send back as they are: pagination, sync and anti-forgery tokens.
    if NOT_SECRET_WORDS
        .iter()
        .any(|w| memchr::memmem::find(low, w).is_some())
    {
        return false;
    }
    if low.ends_with(b"key") || low.ends_with(b"auth") {
        return true;
    }
    KEY_WORDS
        .iter()
        .any(|w| memchr::memmem::find(low, w).is_some())
}

/// A byte of a value after a key name: letters, digits and the symbols passwords use, but no
/// quote, space, separator (`,;&`), bracket, `$` (a variable) or `.` (a dotted name).
fn is_value_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            b'+' | b'/' | b'_' | b'-' | b'~' | b'!' | b'#' | b'%' | b'*' | b'?' | b'@' | b'^'
        )
}

/// Entropy over values after a key name that says secret.
fn keyed_entropy_scan(
    cfg: &EntropyConfig,
    hay: &[u8],
    from: usize,
    to: usize,
    f: &mut impl FnMut(Detection),
) {
    long_runs(
        hay,
        from,
        to,
        cfg.min_len.min(16),
        is_value_byte,
        &mut |s, i| {
            // Base64 padding ends a value.
            let mut e = i;
            while e < to && hay[e] == b'=' && e - i < 2 {
                e += 1;
            }
            let len = e - s;
            if len < cfg.min_len || len > cfg.max_len {
                return;
            }
            // A call, an index or a template, not a literal.
            if matches!(hay.get(e), Some(b'(' | b'[' | b'{' | b'.')) {
                return;
            }
            let t = &hay[s..e];
            // A path (`/etc/...`, `AKID/20150830/us-east-1/s3/aws4_request`), not a token.
            if t[0] == b'/' || memchr::memchr_iter(b'/', t).count() >= 3 {
                return;
            }
            let classes = u8::from(t.iter().any(u8::is_ascii_lowercase))
                + u8::from(t.iter().any(u8::is_ascii_uppercase))
                + u8::from(t.iter().any(u8::is_ascii_digit))
                + u8::from(t.iter().any(|c| !c.is_ascii_alphanumeric() && *c != b'='));
            if classes >= cfg.min_classes && key_context(hay, s) && shannon(t) >= cfg.threshold_bits
            {
                f(Detection {
                    start: s,
                    end: e,
                    rule: ENTROPY_RULE,
                });
            }
        },
    );
}

fn entropy_scan(
    cfg: &EntropyConfig,
    hay: &[u8],
    from: usize,
    to: usize,
    f: &mut impl FnMut(Detection),
) {
    if cfg.key_names {
        keyed_entropy_scan(cfg, hay, from, to, f);
        return;
    }
    let is_tok = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'_' | b'-' | b'=');
    long_runs(hay, from, to, cfg.min_len, is_tok, &mut |s, i| {
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
    });
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

    /// Every automaton stays small enough for Teddy to keep few false candidates, and every
    /// anchor is at least three bytes (Teddy's longest fingerprint), with every rule on.
    #[test]
    fn automata_keep_the_simd_prefilter() {
        let d = Detectors::build(&DetectorConfig {
            enabled_rules: default_off_rule_names()
                .into_iter()
                .map(String::from)
                .collect(),
            ..Default::default()
        })
        .unwrap();
        assert!(!d.automata.is_empty() && d.automata.len() <= 8);
        for g in &d.automata {
            assert!(g.ac.patterns_len() <= ANCHORS_PER_AUTOMATON);
            assert!(g.ac.min_pattern_len() >= 3);
            assert!(
                g.dispatch
                    .iter()
                    .all(|(rules, pem)| *pem || !rules.is_empty())
            );
        }
        let mut compiled: Vec<&str> = d.rules.iter().map(|r| r.name).collect();
        compiled.dedup();
        assert_eq!(compiled.len() + 1, builtin_rule_names().len());
    }

    /// Every option on, over random mixes of fragments that steer the decoders (escapes, padding,
    /// `0x`, key names, prefixes): detections stay in bounds, in order and apart.
    #[test]
    fn scan_with_everything_on_is_ordered_and_in_bounds() {
        let d = Detectors::build(&DetectorConfig {
            entropy: Some(EntropyConfig::default()),
            encoded: true,
            enabled_rules: default_off_rule_names()
                .into_iter()
                .map(String::from)
                .collect(),
            ..Default::default()
        })
        .unwrap();
        let any = Detectors::build(&DetectorConfig {
            entropy: Some(EntropyConfig::any_context()),
            encoded: true,
            ..Default::default()
        })
        .unwrap();
        let parts: &[&[u8]] = &[
            b"%",
            b"%4",
            b"%41",
            b"%2F",
            b"0x",
            b"=",
            b"==",
            b"\\n",
            b"\\",
            b"\"",
            b" ",
            b"token=",
            b"Bearer ",
            b"Z2hwX",
            b"Z2hw",
            b"6768705f",
            b"ghp_",
            b"sk-",
            b"sk_",
            b"AKIA",
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef",
            b"0123456789abcdef",
            b"/",
            b"+",
            b"\xff",
            b":AA",
            b"/api/webhooks/",
            b"-----BEGIN ",
            b"://",
        ];
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..3000 {
            let mut hay = Vec::new();
            for _ in 0..(x % 60) {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                hay.extend_from_slice(parts[(x % parts.len() as u64) as usize]);
            }
            for det in [&d, &any] {
                let mut last = 0;
                det.scan(&hay, |m| {
                    assert!(m.start >= last && m.start < m.end && m.end <= hay.len());
                    last = m.end;
                });
            }
        }
    }

    /// The chunked run finder reports exactly the runs a byte-by-byte scan finds.
    #[test]
    fn b64_runs_match_a_plain_scan() {
        let mut x = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..300 {
            let mut hay = Vec::new();
            for _ in 0..40 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let n = (x % 70) as usize;
                hay.extend(std::iter::repeat_n(b'A' + (x % 26) as u8, n));
                hay.push(b" \"%."[(x >> 8) as usize % 4]);
            }
            let from = (x % 9) as usize;
            let to = hay.len() - (x >> 20) as usize % 9;
            let mut got = Vec::new();
            b64_runs(&hay, from, to, &mut |a, b| got.push((a, b)));
            let mut want = Vec::new();
            let mut i = from;
            while i < to {
                if !is_b64_byte(hay[i]) {
                    i += 1;
                    continue;
                }
                let s = i;
                while i < to && is_b64_byte(hay[i]) {
                    i += 1;
                }
                if i - s >= ENC_MIN_B64 {
                    want.push((s, i));
                }
            }
            assert_eq!(got, want);
        }
    }

    #[test]
    fn swar_base64_class_matches_the_table() {
        for c in 0..=255u8 {
            for k in 0..8 {
                let mut b = *b"AAAAAAAA";
                b[k] = c;
                assert_eq!(all_b64_8(&b), is_b64_byte(c), "{c:#x} at {k}");
            }
        }
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
