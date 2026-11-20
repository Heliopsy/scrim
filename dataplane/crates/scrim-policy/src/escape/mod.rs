// SPDX-License-Identifier: AGPL-3.0-only

//! Context-aware escaping (redaction spec "Context-aware escaping").
//!
//! A resolved display value lands in one or more language layers: a shell word inside a JSON
//! string, a Python string literal inside a single-quoted shell word, a heredoc body. The
//! analysers in this module ([`shell`], [`code`], [`files`]) find, for each placeholder, the
//! stack of layers it sits in, innermost first, or refuse it ([`Refusal`]) where the value's
//! content could be executed or could change what the surrounding code does. [`escape`] then
//! encodes a value for that stack, innermost layer first.
//!
//! Every escaper is minimal: a value that needs no escaping in a layer is returned unchanged.
//! That makes "insert the raw value" correct exactly when [`ValueTraits::raw_is_safe`] holds,
//! which is what the streaming restore path (which inserts values verbatim and JSON-escapes
//! them itself) relies on. `tests/escape_props.rs` checks the two agree on generated values.
//!
//! The JSON layer of tool-call arguments is not part of a [`Site`]: the caller re-encodes the
//! whole decoded string ([`crate::restore`]), and scrim-llm JSON-escapes what it inserts.

pub mod code;
pub mod files;
pub mod shell;

use std::fmt;

/// One language layer a value lands in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Layer {
    /// An unquoted shell word. `word_start`: nothing precedes the value in the word.
    ShellBare {
        /// The value starts the word.
        word_start: bool,
    },
    /// Inside a single-quoted shell string.
    ShellSingle {
        /// The value starts the word.
        word_start: bool,
    },
    /// Inside a double-quoted shell string.
    ShellDouble {
        /// The value starts the word.
        word_start: bool,
    },
    /// One argv element, passed to the program without a shell (`["cat", "<v>"]`). Nothing
    /// is escaped; a value starting the element with `-` is refused.
    Argv {
        /// The value starts the element.
        word_start: bool,
    },
    /// A heredoc body with a quoted delimiter (`<<'EOF'`): no expansion.
    HeredocQuoted,
    /// A heredoc body with an unquoted delimiter: `$`, `` ` `` and `\` are active.
    HeredocUnquoted,
    /// A Python string literal (not raw, not an f-string, not bytes).
    Python {
        /// `'` or `"`.
        quote: char,
    },
    /// A JavaScript string literal (not a template literal).
    JavaScript {
        /// `'` or `"`.
        quote: char,
    },
    /// An SQL string literal (`'...'`, quotes doubled), as SQLite reads it.
    SqlString,
    /// A JSON string literal (in a file body, not the tool-call arguments).
    JsonString,
    /// A YAML double-quoted scalar.
    YamlDouble,
    /// A whole YAML plain scalar (`key: value` to the end of the line): quoted when needed.
    YamlPlain,
}

impl Layer {
    fn shell_word_start(self) -> Option<bool> {
        match self {
            Layer::ShellBare { word_start }
            | Layer::ShellSingle { word_start }
            | Layer::ShellDouble { word_start }
            | Layer::Argv { word_start } => Some(word_start),
            _ => None,
        }
    }
}

/// Where one placeholder sits: its layers, innermost first. Empty means the value is inserted
/// as is (a file path, an edit already in the file, a read tool's argument).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Site {
    /// Innermost first.
    pub layers: Vec<Layer>,
}

impl Site {
    /// A site with no escaping.
    pub fn verbatim() -> Site {
        Site { layers: Vec::new() }
    }

    /// A site with one layer.
    pub fn of(layer: Layer) -> Site {
        Site {
            layers: vec![layer],
        }
    }

    /// This site wrapped in one more outer layer.
    #[must_use]
    pub fn within(mut self, outer: Layer) -> Site {
        self.layers.push(outer);
        self
    }
}

/// Why a placeholder is not restored at a site. Carries no value data; safe to log and audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// The value would be executed or parsed as code.
    Code,
    /// The command line runs something that is not a known data-only command, so any value in
    /// it could reach code.
    UnknownCommand,
    /// The command writes to a file that is itself code (a shell rc file, a script, a hook).
    CodeFile,
    /// The placeholder is in a construct the analyser does not model (backticks, arithmetic,
    /// parameter expansion, `case`, ...).
    Unsupported,
    /// The placeholder follows a backslash or `$`, which would change how the escaped value is
    /// read.
    Adjacent,
    /// The value starts a word with `-` and would be read as an option.
    LeadingDash,
    /// The value contains a NUL byte, which the layer cannot carry.
    Nul,
    /// The value contains a line break where a line break ends the construct (heredoc).
    LineBreak,
    /// The value is not valid UTF-8.
    NotText,
    /// The placeholder is in a comment, an assignment or a redirection target.
    Position,
}

impl Refusal {
    /// A short machine-readable name.
    pub fn as_str(self) -> &'static str {
        match self {
            Refusal::Code => "code",
            Refusal::UnknownCommand => "unknown_command",
            Refusal::CodeFile => "code_file",
            Refusal::Unsupported => "unsupported",
            Refusal::Adjacent => "adjacent",
            Refusal::LeadingDash => "leading_dash",
            Refusal::Nul => "nul",
            Refusal::LineBreak => "line_break",
            Refusal::NotText => "not_text",
            Refusal::Position => "position",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Characters a shell word may hold unquoted without changing meaning.
fn shell_bare_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(c, '_' | '@' | '%' | '+' | '=' | ':' | ',' | '.' | '/' | '-')
        || (!c.is_ascii() && !is_unicode_space(c))
}

fn is_unicode_space(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{85}' | '\u{2028}' | '\u{2029}' | '\u{feff}')
}

fn shell_double_special(c: char) -> bool {
    matches!(c, '\\' | '$' | '`' | '"' | '!')
}

fn heredoc_unquoted_special(c: char) -> bool {
    matches!(c, '\\' | '$' | '`')
}

fn is_line_break(c: char) -> bool {
    matches!(c, '\n' | '\r')
}

fn c0_or_del(c: char) -> bool {
    (c as u32) < 0x20 || c == '\u{7f}'
}

fn yaml_plain_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '-' | '@' | '+')
}

const YAML_RESERVED: &[&str] = &[
    "true", "false", "null", "yes", "no", "on", "off", "y", "n", "~",
];

fn yaml_plain_ok(v: &str) -> bool {
    !v.is_empty()
        && v.chars().all(yaml_plain_char)
        && !v.starts_with(['-', '.', '@'])
        && !YAML_RESERVED.contains(&v.to_ascii_lowercase().as_str())
        && !v
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.' || c == '-' || c == '+')
}

fn sq_escape(v: &str, out: &mut String) {
    for c in v.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
}

fn hex_escape(out: &mut String, c: char) {
    use std::fmt::Write as _;
    let _ = write!(out, "\\x{:02x}", c as u32);
}

/// Encodes `v` for one layer.
fn escape_one(layer: Layer, v: &str) -> Result<String, Refusal> {
    let mut out = String::with_capacity(v.len() + 8);
    match layer {
        Layer::ShellBare { .. } => {
            if v.contains('\0') {
                return Err(Refusal::Nul);
            }
            if !v.is_empty() && v.chars().all(shell_bare_char) {
                out.push_str(v);
            } else {
                out.push('\'');
                sq_escape(v, &mut out);
                out.push('\'');
            }
        }
        Layer::ShellSingle { .. } => {
            if v.contains('\0') {
                return Err(Refusal::Nul);
            }
            sq_escape(v, &mut out);
        }
        Layer::ShellDouble { .. } => {
            if v.contains('\0') {
                return Err(Refusal::Nul);
            }
            if v.chars().any(shell_double_special) {
                // Close the double quotes, single-quote the value, reopen: nothing inside
                // single quotes is special, in any shell mode.
                out.push_str("\"'");
                sq_escape(v, &mut out);
                out.push_str("'\"");
            } else {
                out.push_str(v);
            }
        }
        Layer::Argv { .. } => {
            if v.contains('\0') {
                return Err(Refusal::Nul);
            }
            out.push_str(v);
        }
        Layer::HeredocQuoted | Layer::HeredocUnquoted => {
            if v.contains('\0') {
                return Err(Refusal::Nul);
            }
            if v.chars().any(is_line_break) {
                return Err(Refusal::LineBreak);
            }
            for c in v.chars() {
                if layer == Layer::HeredocUnquoted && heredoc_unquoted_special(c) {
                    out.push('\\');
                }
                out.push(c);
            }
        }
        Layer::Python { quote } => {
            for c in v.chars() {
                match c {
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push('\t'),
                    c if c == quote => {
                        out.push('\\');
                        out.push(c);
                    }
                    c if c0_or_del(c) => hex_escape(&mut out, c),
                    c => out.push(c),
                }
            }
        }
        Layer::JavaScript { quote } => {
            for c in v.chars() {
                match c {
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push('\t'),
                    '\u{2028}' => out.push_str("\\u2028"),
                    '\u{2029}' => out.push_str("\\u2029"),
                    c if c == quote => {
                        out.push('\\');
                        out.push(c);
                    }
                    c if c0_or_del(c) => hex_escape(&mut out, c),
                    c => out.push(c),
                }
            }
        }
        Layer::SqlString => {
            if v.contains('\0') {
                return Err(Refusal::Nul);
            }
            for c in v.chars() {
                if c == '\'' {
                    out.push('\'');
                }
                out.push(c);
            }
        }
        Layer::JsonString => {
            use std::fmt::Write as _;
            for c in v.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if (c as u32) < 0x20 => {
                        let _ = write!(out, "\\u{:04x}", c as u32);
                    }
                    c => out.push(c),
                }
            }
        }
        Layer::YamlDouble => yaml_double(v, &mut out),
        Layer::YamlPlain => {
            if yaml_plain_ok(v) {
                out.push_str(v);
            } else {
                out.push('"');
                yaml_double(v, &mut out);
                out.push('"');
            }
        }
    }
    Ok(out)
}

fn yaml_double(v: &str, out: &mut String) {
    for c in v.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{85}' => out.push_str("\\N"),
            '\u{2028}' => out.push_str("\\L"),
            '\u{2029}' => out.push_str("\\P"),
            c if c0_or_del(c) => hex_escape(out, c),
            c => out.push(c),
        }
    }
}

/// Encodes `value` for `site`, innermost layer first. Refuses where no encoding keeps the value
/// data. The result replaces the placeholder in the source text.
pub fn escape(site: &Site, value: &[u8]) -> Result<String, Refusal> {
    let v = std::str::from_utf8(value).map_err(|_| Refusal::NotText)?;
    let mut cur = v.to_owned();
    for (i, layer) in site.layers.iter().enumerate() {
        // An option is only a concern for the text the innermost shell word starts with: for
        // an inner shell layer that is the value itself, for an outer one the encoding of the
        // inner layers, which never starts with `-` unless the value does.
        if layer.shell_word_start() == Some(true) && i == 0 && cur.starts_with('-') {
            return Err(Refusal::LeadingDash);
        }
        cur = escape_one(*layer, &cur)?;
    }
    Ok(cur)
}

/// Character classes of a value, enough to tell whether [`escape`] would return it unchanged
/// at a site, without keeping the value. Holds a few bits about the value's characters and
/// nothing else; it is still not printed (its `Debug` is opaque).
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct ValueTraits {
    bits: u32,
}

impl fmt::Debug for ValueTraits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ValueTraits(..)")
    }
}

const T_TEXT: u32 = 1 << 0;
const T_NUL: u32 = 1 << 1;
const T_LINE_BREAK: u32 = 1 << 2;
const T_SQ: u32 = 1 << 3;
const T_DQ: u32 = 1 << 4;
const T_BACKSLASH: u32 = 1 << 5;
const T_DQ_SPECIAL: u32 = 1 << 6;
const T_HEREDOC_SPECIAL: u32 = 1 << 7;
const T_C0_DEL_NOT_TAB: u32 = 1 << 8;
const T_TAB: u32 = 1 << 9;
const T_LS_PS: u32 = 1 << 10;
const T_NEL: u32 = 1 << 11;
const T_BARE_OK: u32 = 1 << 12;
const T_YAML_PLAIN_OK: u32 = 1 << 13;
const T_LEADING_DASH: u32 = 1 << 14;
const T_C0: u32 = 1 << 15;

impl ValueTraits {
    /// Computes the traits of `value`.
    pub fn of(value: &[u8]) -> ValueTraits {
        let Ok(v) = std::str::from_utf8(value) else {
            return ValueTraits { bits: 0 };
        };
        let mut bits = T_TEXT;
        let mut set = |b: u32, on: bool| {
            if on {
                bits |= b;
            }
        };
        set(T_LEADING_DASH, v.starts_with('-'));
        set(T_BARE_OK, !v.is_empty() && v.chars().all(shell_bare_char));
        set(T_YAML_PLAIN_OK, yaml_plain_ok(v));
        for c in v.chars() {
            set(T_NUL, c == '\0');
            set(T_LINE_BREAK, is_line_break(c));
            set(T_SQ, c == '\'');
            set(T_DQ, c == '"');
            set(T_BACKSLASH, c == '\\');
            set(T_DQ_SPECIAL, shell_double_special(c));
            set(T_HEREDOC_SPECIAL, heredoc_unquoted_special(c));
            set(T_C0_DEL_NOT_TAB, c0_or_del(c) && c != '\t');
            set(T_C0, (c as u32) < 0x20);
            set(T_TAB, c == '\t');
            set(T_LS_PS, matches!(c, '\u{2028}' | '\u{2029}'));
            set(T_NEL, c == '\u{85}');
        }
        ValueTraits { bits }
    }

    fn has(self, b: u32) -> bool {
        self.bits & b != 0
    }

    #[allow(clippy::match_same_arms)] // same rule, different languages
    fn identity(self, layer: Layer) -> bool {
        let quote = |q: char| if q == '\'' { T_SQ } else { T_DQ };
        match layer {
            Layer::ShellBare { .. } => self.has(T_BARE_OK),
            Layer::ShellSingle { .. } => !self.has(T_SQ | T_NUL),
            Layer::ShellDouble { .. } => !self.has(T_DQ_SPECIAL | T_NUL),
            Layer::HeredocQuoted => !self.has(T_NUL | T_LINE_BREAK),
            Layer::HeredocUnquoted => !self.has(T_NUL | T_LINE_BREAK | T_HEREDOC_SPECIAL),
            Layer::Python { quote: q } | Layer::JavaScript { quote: q } => {
                let mut bad = T_BACKSLASH | T_C0_DEL_NOT_TAB | quote(q);
                if matches!(layer, Layer::JavaScript { .. }) {
                    bad |= T_LS_PS;
                }
                !self.has(bad)
            }
            Layer::SqlString => !self.has(T_SQ | T_NUL),
            Layer::Argv { .. } => !self.has(T_NUL),
            Layer::JsonString => !self.has(T_DQ | T_BACKSLASH | T_C0),
            Layer::YamlDouble => {
                !self.has(T_DQ | T_BACKSLASH | T_C0_DEL_NOT_TAB | T_TAB | T_LS_PS | T_NEL)
            }
            Layer::YamlPlain => self.has(T_YAML_PLAIN_OK),
        }
    }

    /// Whether inserting the raw value at `site` is exactly what [`escape`] would produce.
    pub fn raw_is_safe(self, site: &Site) -> bool {
        if !self.has(T_TEXT) {
            return false;
        }
        if site
            .layers
            .first()
            .and_then(|l| l.shell_word_start())
            .unwrap_or(false)
            && self.has(T_LEADING_DASH)
        {
            return false;
        }
        site.layers.iter().all(|l| self.identity(*l))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::pedantic)]
mod tests {
    use super::*;

    fn esc(layers: &[Layer], v: &str) -> Result<String, Refusal> {
        escape(
            &Site {
                layers: layers.to_vec(),
            },
            v.as_bytes(),
        )
    }

    const BARE: Layer = Layer::ShellBare { word_start: false };
    const BARE0: Layer = Layer::ShellBare { word_start: true };
    const SQ: Layer = Layer::ShellSingle { word_start: false };
    const DQ: Layer = Layer::ShellDouble { word_start: false };

    #[test]
    fn shell_layers() {
        assert_eq!(esc(&[BARE], "abc-1.2/x").unwrap(), "abc-1.2/x");
        assert_eq!(esc(&[BARE], "a b").unwrap(), "'a b'");
        assert_eq!(esc(&[BARE], "it's").unwrap(), "'it'\\''s'");
        assert_eq!(esc(&[BARE], "").unwrap(), "''");
        assert_eq!(esc(&[BARE], "$(id)").unwrap(), "'$(id)'");
        assert_eq!(esc(&[BARE0], "-rf"), Err(Refusal::LeadingDash));
        assert_eq!(esc(&[BARE], "-rf").unwrap(), "-rf");
        assert_eq!(esc(&[SQ], "a'b").unwrap(), "a'\\''b");
        assert_eq!(esc(&[DQ], "plain text").unwrap(), "plain text");
        assert_eq!(esc(&[DQ], "a\"$b").unwrap(), "\"'a\"$b'\"");
        assert_eq!(esc(&[DQ], "x!").unwrap(), "\"'x!'\"");
        assert_eq!(esc(&[BARE], "a\0"), Err(Refusal::Nul));
        assert_eq!(escape(&Site::of(BARE), b"\xff"), Err(Refusal::NotText));
    }

    #[test]
    fn heredoc_layers() {
        assert_eq!(esc(&[Layer::HeredocQuoted], "a$b`c\\").unwrap(), "a$b`c\\");
        assert_eq!(
            esc(&[Layer::HeredocUnquoted], "a$b`c\\").unwrap(),
            "a\\$b\\`c\\\\"
        );
        assert_eq!(
            esc(&[Layer::HeredocQuoted], "a\nEOF"),
            Err(Refusal::LineBreak)
        );
        assert_eq!(
            esc(&[Layer::HeredocUnquoted], "a\rb"),
            Err(Refusal::LineBreak)
        );
    }

    #[test]
    fn code_layers() {
        let py = Layer::Python { quote: '"' };
        assert_eq!(esc(&[py], "a\"b\\c\n\x01").unwrap(), "a\\\"b\\\\c\\n\\x01");
        assert_eq!(esc(&[py], "it's").unwrap(), "it's");
        let js = Layer::JavaScript { quote: '\'' };
        assert_eq!(esc(&[js], "it's\u{2028}").unwrap(), "it\\'s\\u2028");
        assert_eq!(esc(&[Layer::SqlString], "O'Brien").unwrap(), "O''Brien");
        assert_eq!(
            esc(&[Layer::JsonString], "a\"\t\u{1}").unwrap(),
            "a\\\"\\t\\u0001"
        );
        assert_eq!(
            esc(&[Layer::YamlDouble], "a\"\u{2028}").unwrap(),
            "a\\\"\\L"
        );
        assert_eq!(esc(&[Layer::YamlPlain], "abc").unwrap(), "abc");
        assert_eq!(esc(&[Layer::YamlPlain], "yes").unwrap(), "\"yes\"");
        assert_eq!(esc(&[Layer::YamlPlain], "a: b #c").unwrap(), "\"a: b #c\"");
        assert_eq!(esc(&[Layer::YamlPlain], "123").unwrap(), "\"123\"");
    }

    #[test]
    fn nested_layers_compose_inside_out() {
        // python3 -c 'print("<v>")'
        let site = [Layer::Python { quote: '"' }, SQ];
        assert_eq!(esc(&site, "a'b\"c").unwrap(), "a'\\''b\\\"c");
        // bash -c "cat <v>"
        let site = [BARE0, DQ];
        assert_eq!(esc(&site, "x y").unwrap(), "'x y'");
        assert_eq!(esc(&site, "$x").unwrap(), "\"''\\''$x'\\'''\"");
        // An outer shell word start does not apply to inner encodings: only the innermost
        // layer's text can start a word with the value.
        let site = [
            Layer::Python { quote: '"' },
            Layer::ShellBare { word_start: true },
        ];
        assert_eq!(esc(&site, "-x").unwrap(), "-x");
    }

    #[test]
    fn traits_agree_on_examples() {
        let values = [
            "", "abc", "a b", "-rf", "it's", "a\"b", "$x", "a\nb", "a\rb", "\t", "\u{2028}",
            "\u{85}", "é", "\0", "x!", "yes", "123", "a\\b", "`id`", "\u{7f}",
        ];
        let layers = [
            BARE,
            BARE0,
            SQ,
            Layer::ShellSingle { word_start: true },
            DQ,
            Layer::ShellDouble { word_start: true },
            Layer::HeredocQuoted,
            Layer::HeredocUnquoted,
            Layer::Argv { word_start: true },
            Layer::Argv { word_start: false },
            Layer::Python { quote: '\'' },
            Layer::Python { quote: '"' },
            Layer::JavaScript { quote: '\'' },
            Layer::JavaScript { quote: '"' },
            Layer::SqlString,
            Layer::JsonString,
            Layer::YamlDouble,
            Layer::YamlPlain,
        ];
        for v in values {
            let t = ValueTraits::of(v.as_bytes());
            for a in layers {
                for site in [vec![a], vec![a, SQ], vec![a, BARE0]] {
                    let site = Site { layers: site };
                    let raw = escape(&site, v.as_bytes()).as_deref() == Ok(v);
                    assert_eq!(t.raw_is_safe(&site), raw, "{v:?} at {site:?}");
                }
            }
        }
        assert!(!ValueTraits::of(b"\xff").raw_is_safe(&Site::verbatim()));
        assert!(ValueTraits::of(b"x").raw_is_safe(&Site::verbatim()));
        assert_eq!(
            format!("{:?}", ValueTraits::of(b"secret")),
            "ValueTraits(..)"
        );
        assert_eq!(Refusal::LeadingDash.to_string(), "leading_dash");
    }
}
