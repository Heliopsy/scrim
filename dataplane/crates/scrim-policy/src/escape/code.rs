// SPDX-License-Identifier: AGPL-3.0-only

//! Interpreter programs passed on a command line (`python3 -c`, `node -e`, `sqlite3 db SQL`).
//!
//! A value may be restored into such a program only inside a plain string literal, escaped for
//! that literal, and only when the whole program is one the analyser can vouch for: it must not
//! be able to hand a string to an evaluator, a shell or the file system. For Python and
//! JavaScript that is an allowlist of identifiers (anything else, `exec`, `open`, `os`,
//! `require`, `constructor`, rejects the program); for SQLite, whose dangerous surface is a
//! closed set, a denylist of the shell's file and extension functions, `ATTACH`, `PRAGMA`,
//! `VACUUM` and dot-commands. A rejected program rejects every placeholder on its command
//! line, because the program could read a value from its arguments, stdin or a file.

use super::{Layer, Refusal};

/// An interpreter language.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    /// Python 3 (`python -c`, `python3 -c`).
    Python,
    /// JavaScript (`node -e`, `node -p`).
    JavaScript,
    /// SQLite's SQL as its command-line shell reads it.
    Sqlite,
}

/// The result of analysing one program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeAnalysis {
    /// The program can be vouched for (see the module documentation).
    pub program_ok: bool,
    /// One entry per placeholder span, in order: the literal it sits in, or why not.
    pub sites: Vec<Result<Layer, Refusal>>,
}

const PY_ALLOWED: &[&str] = &[
    "print",
    "len",
    "str",
    "repr",
    "upper",
    "lower",
    "strip",
    "lstrip",
    "rstrip",
    "split",
    "rsplit",
    "splitlines",
    "join",
    "replace",
    "startswith",
    "endswith",
    "encode",
    "decode",
    "sep",
    "end",
    "flush",
    "True",
    "False",
    "None",
    "and",
    "or",
    "not",
    "in",
    "is",
    "if",
    "else",
    "for",
    "range",
    "sorted",
    "reversed",
    "list",
    "tuple",
    "set",
    "int",
    "float",
    "bool",
    "ord",
    "chr",
    "hex",
    "min",
    "max",
    "sum",
    "abs",
    "count",
    "find",
    "rfind",
    "index",
    "isdigit",
    "isalpha",
    "isalnum",
    "isspace",
    "isupper",
    "islower",
    "center",
    "ljust",
    "rjust",
    "zfill",
    "title",
    "capitalize",
    "swapcase",
    "casefold",
    "partition",
    "rpartition",
    "import",
    "sys",
    "stdout",
    "stderr",
    "write",
    "utf",
    "ascii",
];

const JS_ALLOWED: &[&str] = &[
    "console",
    "log",
    "error",
    "info",
    "warn",
    "JSON",
    "stringify",
    "parse",
    "length",
    "toUpperCase",
    "toLowerCase",
    "trim",
    "trimStart",
    "trimEnd",
    "split",
    "join",
    "replace",
    "replaceAll",
    "String",
    "Number",
    "true",
    "false",
    "null",
    "undefined",
    "const",
    "let",
    "includes",
    "startsWith",
    "endsWith",
    "slice",
    "substring",
    "indexOf",
    "padStart",
    "padEnd",
    "repeat",
    "concat",
    "charAt",
];

const SQL_DENIED: &[&str] = &[
    "attach",
    "detach",
    "pragma",
    "vacuum",
    "load_extension",
    "edit",
    "writefile",
    "readfile",
    "fts3_tokenizer",
    "zipfile",
    "fsdir",
    "sqlar_compress",
    "sqlar_uncompress",
    "lsmode",
    "shell",
    "system",
    "eval",
    "sha3_query",
    "shell_add_schema",
    "shell_module_schema",
];

fn ident_allowed(lang: Lang, id: &str) -> bool {
    // Single lower-case letters are loop variables, never builtins worth worrying about.
    if id.len() == 1 && id.as_bytes()[0].is_ascii_lowercase() {
        return true;
    }
    match lang {
        Lang::Python => PY_ALLOWED.contains(&id),
        Lang::JavaScript => JS_ALLOWED.contains(&id),
        Lang::Sqlite => !SQL_DENIED.contains(&id.to_ascii_lowercase().as_str()),
    }
}

struct Lexer<'a> {
    lang: Lang,
    s: &'a str,
    b: &'a [u8],
    spans: &'a [(usize, usize)],
    sites: Vec<Result<Layer, Refusal>>,
    ok: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Prev {
    /// Start, operator or keyword: a `[` here opens an array literal.
    Open,
    /// An operand: a `[` here is a subscript.
    Operand,
}

impl Lexer<'_> {
    fn span_at(&self, i: usize) -> Option<usize> {
        self.spans.iter().position(|&(s, _)| s == i)
    }

    fn set(&mut self, k: usize, v: Result<Layer, Refusal>) {
        self.sites[k] = v;
    }

    fn char_at(&self, i: usize) -> char {
        self.s[i..].chars().next().unwrap_or('\0')
    }

    /// Skips to the end of the line, refusing placeholders on the way (comments).
    fn skip_line(&mut self, mut i: usize) -> usize {
        while i < self.b.len() && self.b[i] != b'\n' {
            if let Some(k) = self.span_at(i) {
                self.set(k, Err(Refusal::Position));
                i = self.spans[k].1;
            } else {
                i += 1;
            }
        }
        i
    }

    fn skip_block_comment(&mut self, mut i: usize) -> usize {
        while i < self.b.len() {
            if self.b[i..].starts_with(b"*/") {
                return i + 2;
            }
            if let Some(k) = self.span_at(i) {
                self.set(k, Err(Refusal::Position));
                i = self.spans[k].1;
            } else {
                i += 1;
            }
        }
        self.ok = false;
        i
    }

    /// Scans a string literal opening at `i`. `layer` is the literal's layer, or the refusal
    /// for placeholders inside it. Returns the offset after the literal.
    fn string(
        &mut self,
        i: usize,
        quote: u8,
        triple: bool,
        backslash: bool,
        layer: Result<Layer, Refusal>,
    ) -> usize {
        let open = if triple { 3 } else { 1 };
        let mut j = i + open;
        let mut esc = false;
        while j < self.b.len() {
            if let Some(k) = self.span_at(j) {
                self.set(k, if esc { Err(Refusal::Adjacent) } else { layer });
                esc = false;
                j = self.spans[k].1;
                continue;
            }
            let c = self.b[j];
            if esc {
                esc = false;
                j += 1;
                continue;
            }
            if backslash && c == b'\\' {
                esc = true;
                j += 1;
                continue;
            }
            if c == b'\n' && !triple {
                self.ok = false;
                return j;
            }
            if c == quote {
                if !triple {
                    // SQL doubles the quote to escape it.
                    if self.lang == Lang::Sqlite && self.b.get(j + 1) == Some(&quote) {
                        j += 2;
                        continue;
                    }
                    return j + 1;
                }
                if self.b[j..].starts_with(&[quote; 3]) {
                    return j + 3;
                }
            }
            j += 1;
        }
        self.ok = false;
        j
    }

    fn run(&mut self) {
        let mut i = 0;
        let mut prev = Prev::Open;
        let mut line_start = true;
        while i < self.b.len() {
            if let Some(k) = self.span_at(i) {
                self.set(k, Err(Refusal::Code));
                i = self.spans[k].1;
                prev = Prev::Operand;
                line_start = false;
                continue;
            }
            let c = self.char_at(i);
            let n = c.len_utf8();
            if c == '\n' {
                line_start = true;
                i += 1;
                continue;
            }
            if c.is_ascii_whitespace() {
                i += 1;
                continue;
            }
            let at_line_start = std::mem::replace(&mut line_start, false);
            match (self.lang, c) {
                (Lang::Python, '#') => i = self.skip_line(i),
                (Lang::Sqlite, '-') if self.b.get(i + 1) == Some(&b'-') => i = self.skip_line(i),
                (Lang::JavaScript | Lang::Sqlite, '/')
                    if self.b.get(i + 1) == Some(&b'/') && self.lang == Lang::JavaScript =>
                {
                    i = self.skip_line(i);
                }
                (Lang::JavaScript | Lang::Sqlite, '/') if self.b.get(i + 1) == Some(&b'*') => {
                    i = self.skip_block_comment(i + 2);
                }
                (Lang::JavaScript, '/') => {
                    // A regular expression literal or a division; telling them apart needs a
                    // parser, so neither is accepted.
                    self.ok = false;
                    i += 1;
                }
                (Lang::Python | Lang::JavaScript, '\\') => {
                    if self.b[i + 1..].starts_with(b"\n") {
                        i += 2;
                    } else if self.b[i + 1..].starts_with(b"\r\n") {
                        i += 3;
                    } else {
                        self.ok = false;
                        i += 1;
                    }
                }
                (Lang::Sqlite, '.') if at_line_start => {
                    // A dot-command (`.shell`, `.system`, `.load`, `.output`).
                    self.ok = false;
                    i = self.skip_line(i);
                }
                (_, '\'' | '"') => {
                    let q = c as u8;
                    let (layer, backslash) = match (self.lang, q) {
                        (Lang::Python, _) => (Ok(Layer::Python { quote: c }), true),
                        (Lang::JavaScript, _) => (Ok(Layer::JavaScript { quote: c }), true),
                        (Lang::Sqlite, b'\'') => (Ok(Layer::SqlString), false),
                        (Lang::Sqlite, _) => (Err(Refusal::Position), false),
                    };
                    let triple = self.lang == Lang::Python && self.b[i..].starts_with(&[q; 3]);
                    i = self.string(i, q, triple, backslash, layer);
                    prev = Prev::Operand;
                }
                (Lang::JavaScript, '`') => {
                    self.ok = false;
                    i += 1;
                }
                (Lang::Sqlite, '[' | '`') => {
                    let close = if c == '[' { b']' } else { b'`' };
                    i = self.string(i, close, false, false, Err(Refusal::Position));
                }
                (_, c)
                    if c.is_ascii_alphabetic()
                        || c == '_'
                        || (c == '$' && self.lang != Lang::Python) =>
                {
                    let start = i;
                    while i < self.b.len()
                        && (self.b[i].is_ascii_alphanumeric()
                            || self.b[i] == b'_'
                            || self.b[i] == b'$')
                    {
                        if self.b[i] == b'$' && self.lang == Lang::Python {
                            break;
                        }
                        i += 1;
                    }
                    let id = &self.s[start..i];
                    let next = self.b.get(i).copied();
                    if self.lang == Lang::Python && matches!(next, Some(b'\'' | b'"')) {
                        let p = id.to_ascii_lowercase();
                        if !p.is_empty()
                            && p.len() <= 2
                            && p.chars().all(|x| matches!(x, 'r' | 'b' | 'u' | 'f'))
                        {
                            // A string prefix.
                            if p.contains('f') {
                                // f-strings evaluate the expressions they contain.
                                self.ok = false;
                            }
                            let q = self.b[i];
                            let triple = self.b[i..].starts_with(&[q; 3]);
                            let raw = p.contains('r');
                            let layer = if raw || p.contains('b') {
                                Err(Refusal::Unsupported)
                            } else {
                                Ok(Layer::Python { quote: q as char })
                            };
                            i = self.string(i, q, triple, !raw, layer);
                            prev = Prev::Operand;
                            continue;
                        }
                    }
                    if (id.starts_with('_') && self.lang != Lang::Sqlite)
                        || !ident_allowed(self.lang, id)
                    {
                        self.ok = false;
                    }
                    prev = Prev::Operand;
                }
                (_, c) if c.is_ascii_digit() => {
                    while i < self.b.len()
                        && (self.b[i].is_ascii_alphanumeric()
                            || self.b[i] == b'.'
                            || self.b[i] == b'_')
                    {
                        i += 1;
                    }
                    prev = Prev::Operand;
                }
                (Lang::JavaScript, '[') => {
                    if prev == Prev::Operand {
                        // obj["constructor"] reaches what the identifier allowlist forbids.
                        self.ok = false;
                    }
                    prev = Prev::Open;
                    i += 1;
                }
                (_, ')' | ']') => {
                    prev = Prev::Operand;
                    i += 1;
                }
                (
                    _,
                    '(' | '[' | '{' | '}' | ',' | '.' | ':' | ';' | '+' | '-' | '*' | '%' | '='
                    | '<' | '>' | '!' | '&' | '|' | '^' | '~',
                ) => {
                    prev = Prev::Open;
                    i += n;
                }
                (Lang::Python, '/' | '@')
                | (Lang::JavaScript, '?')
                | (Lang::Sqlite, '/' | '?' | '@' | '$') => {
                    prev = Prev::Open;
                    i += 1;
                }
                _ => {
                    self.ok = false;
                    i += n;
                }
            }
        }
    }
}

/// Analyses `code` in `lang`. `spans` are the byte ranges of placeholders in `code`, sorted and
/// not overlapping.
pub fn analyze(lang: Lang, code: &str, spans: &[(usize, usize)]) -> CodeAnalysis {
    let mut lx = Lexer {
        lang,
        s: code,
        b: code.as_bytes(),
        spans,
        sites: vec![Err(Refusal::Code); spans.len()],
        ok: true,
    };
    lx.run();
    CodeAnalysis {
        program_ok: lx.ok,
        sites: lx.sites,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::pedantic)]
mod tests {
    use super::*;

    fn run(lang: Lang, code: &str) -> CodeAnalysis {
        let spans: Vec<_> = code.match_indices("PH").map(|(i, _)| (i, i + 2)).collect();
        analyze(lang, code, &spans)
    }

    #[test]
    fn python() {
        let a = run(
            Lang::Python,
            "print(\"x PH\", 'PH'); print(len('''a\nPH'''))",
        );
        assert!(a.program_ok);
        assert_eq!(
            a.sites,
            vec![
                Ok(Layer::Python { quote: '"' }),
                Ok(Layer::Python { quote: '\'' }),
                Ok(Layer::Python { quote: '\'' })
            ]
        );
        for bad in [
            "exec('PH')",
            "eval(\"PH\")",
            "import os; os.system('PH')",
            "open('x','w').write('PH')",
            "print(f'{PH}')",
            "getattr(__builtins__, 'ex'+'ec')('PH')",
            "print('PH'.__class__)",
            "print('PH\n')",
            "x = `PH`",
            "print(\\\n'PH')\\x",
        ] {
            assert!(!run(Lang::Python, bad).program_ok, "{bad}");
        }
        let a = run(
            Lang::Python,
            "print(PH) # PH\nprint(r'PH', b'PH', '\\PH', u'PH')",
        );
        assert!(a.program_ok);
        assert_eq!(
            a.sites,
            vec![
                Err(Refusal::Code),
                Err(Refusal::Position),
                Err(Refusal::Unsupported),
                Err(Refusal::Unsupported),
                Err(Refusal::Adjacent),
                Ok(Layer::Python { quote: '\'' }),
            ]
        );
        assert!(run(Lang::Python, "import sys; sys.stdout.write('PH')").program_ok);
        assert!(run(Lang::Python, "for c in 'PH': print(c)").program_ok);
    }

    #[test]
    fn javascript() {
        let a = run(
            Lang::JavaScript,
            "console.log('PH', \"PH\".length, [1, 'PH'])",
        );
        assert!(a.program_ok, "{a:?}");
        assert_eq!(a.sites.len(), 3);
        assert!(a.sites.iter().all(Result::is_ok));
        for bad in [
            "require('child_process').execSync('PH')",
            "''['constructor']['constructor']('PH')()",
            "console.log(`PH`)",
            "console.log('PH'.replace(/x/, 'y'))",
            "eval('PH')",
            "process.mainModule",
            "Function('PH')()",
            "console.log('PH' / 2)",
            "#!x",
        ] {
            assert!(!run(Lang::JavaScript, bad).program_ok, "{bad}");
        }
        let a = run(Lang::JavaScript, "// PH\n/* PH */ console.log(PH)");
        assert!(a.program_ok);
        assert_eq!(
            a.sites,
            vec![
                Err(Refusal::Position),
                Err(Refusal::Position),
                Err(Refusal::Code)
            ]
        );
    }

    #[test]
    fn sqlite() {
        let a = run(
            Lang::Sqlite,
            "select 'PH', length('it''s PH') from t where \"PH\" = 1 -- PH",
        );
        assert!(a.program_ok);
        assert_eq!(
            a.sites,
            vec![
                Ok(Layer::SqlString),
                Ok(Layer::SqlString),
                Err(Refusal::Position),
                Err(Refusal::Position)
            ]
        );
        for bad in [
            ".shell PH",
            "select 1;\n.system PH",
            "select load_extension('PH')",
            "select edit('x', 'PH')",
            "select writefile('PH', 'x')",
            "ATTACH 'PH' AS x",
            "pragma x",
            "select sha3_query('PH')",
            "select eval('PH')",
            "vacuum into 'PH'",
            "select 'PH",
        ] {
            assert!(!run(Lang::Sqlite, bad).program_ok, "{bad}");
        }
        assert_eq!(
            run(Lang::Sqlite, "select PH").sites,
            vec![Err(Refusal::Code)]
        );
        assert!(
            run(
                Lang::Sqlite,
                "create table t(a text); insert into t values ('PH'); select * from t"
            )
            .program_ok
        );
    }
}
