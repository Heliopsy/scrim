// SPDX-License-Identifier: AGPL-3.0-only

//! Glob patterns, identical to the control plane's (`internal/policy/glob.go`).
//!
//! | Pattern | Matches |
//! | --- | --- |
//! | `*` | any run of characters except `/` |
//! | `**` | any run of characters including `/` (three or more stars are one `**`) |
//! | `?` | exactly one character except `/` |
//! | `\x` | the literal character `x` |
//!
//! Every other character matches itself. Matching is on Unicode scalar values and anchored at
//! both ends. There are no character classes or alternation. A trailing backslash makes the
//! pattern invalid.
//!
//! Matching is a dynamic programme over (token, position) with no backtracking, so it runs in
//! `O(tokens * chars)` whatever the input; hostile patterns cannot blow it up.

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tok {
    Lit(char),
    One,
    Star,
    DoubleStar,
}

/// A compiled glob pattern.
#[derive(Clone, PartialEq, Eq)]
pub struct Glob {
    toks: Box<[Tok]>,
    src: Box<str>,
}

/// The pattern ends in a lone backslash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("glob: trailing backslash")]
pub struct GlobError;

impl Glob {
    /// Compiles `pattern`.
    pub fn new(pattern: &str) -> Result<Self, GlobError> {
        let rs: Vec<char> = pattern.chars().collect();
        let mut toks = Vec::with_capacity(rs.len());
        let mut i = 0;
        while i < rs.len() {
            match rs[i] {
                '\\' => {
                    let Some(&c) = rs.get(i + 1) else {
                        return Err(GlobError);
                    };
                    i += 1;
                    toks.push(Tok::Lit(c));
                }
                '?' => toks.push(Tok::One),
                '*' => {
                    if rs.get(i + 1) == Some(&'*') {
                        while rs.get(i + 1) == Some(&'*') {
                            i += 1;
                        }
                        toks.push(Tok::DoubleStar);
                    } else {
                        toks.push(Tok::Star);
                    }
                }
                c => toks.push(Tok::Lit(c)),
            }
            i += 1;
        }
        Ok(Self {
            toks: toks.into(),
            src: pattern.into(),
        })
    }

    /// The pattern text.
    pub fn as_str(&self) -> &str {
        &self.src
    }

    /// Whether `s` matches the whole pattern.
    pub fn matches(&self, s: &str) -> bool {
        let s: Vec<char> = s.chars().collect();
        let n = s.len();
        let mut cur = vec![false; n + 1];
        let mut next = vec![false; n + 1];
        cur[0] = true;
        for t in &*self.toks {
            next.fill(false);
            match *t {
                Tok::Lit(r) => {
                    for j in 0..n {
                        if cur[j] && s[j] == r {
                            next[j + 1] = true;
                        }
                    }
                }
                Tok::One => {
                    for j in 0..n {
                        if cur[j] && s[j] != '/' {
                            next[j + 1] = true;
                        }
                    }
                }
                Tok::Star => {
                    for j in 0..=n {
                        // Zero characters, or one more non-separator.
                        next[j] = cur[j] || (j > 0 && next[j - 1] && s[j - 1] != '/');
                    }
                }
                Tok::DoubleStar => {
                    for j in 0..=n {
                        next[j] = cur[j] || (j > 0 && next[j - 1]);
                    }
                }
            }
            std::mem::swap(&mut cur, &mut next);
        }
        cur[n]
    }
}

impl fmt::Debug for Glob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Glob({:?})", self.src)
    }
}

/// Whether `s` matches `pattern`. An invalid pattern matches nothing, as in the control plane.
pub fn glob_match(pattern: &str, s: &str) -> bool {
    Glob::new(pattern).is_ok_and(|g| g.matches(s))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::pedantic)]
mod tests {
    use super::*;

    /// The control plane's table (`internal/policy/glob_test.go` `TestGlob`), verbatim.
    #[test]
    fn go_glob_table() {
        let cases: &[(&str, &str, bool)] = &[
            ("", "", true),
            ("", "a", false),
            ("abc", "abc", true),
            ("abc", "abcd", false),
            ("bao://kv/prod/*", "bao://kv/prod/db", true),
            ("bao://kv/prod/*", "bao://kv/prod/a/b", false),
            ("bao://kv/prod/*", "bao://kv/prod/", true),
            ("bao://kv/prod/**", "bao://kv/prod/a/b", true),
            ("bao://kv/**/db", "bao://kv/prod/eu/db", true),
            ("bao://kv/**/db", "bao://kv/db", false),
            ("bao://kv/**db", "bao://kv/db", true),
            ("*.github.com", "api.github.com", true),
            ("*.github.com", "github.com", false),
            ("*.github.com", "a.b.github.com", true),
            ("*.github.com", "evilgithub.com", false),
            ("?", "a", true),
            ("?", "/", false),
            ("?", "é", true),
            ("a?c", "abc", true),
            (r"a\*c", "a*c", true),
            (r"a\*c", "abc", false),
            (r"\\", r"\", true),
            ("***", "a/b", true),
            ("*", "", true),
            ("*a*b*", "xxaxxbxx", true),
            ("*a*b*", "xxbxxaxx", false),
        ];
        for &(p, s, want) in cases {
            assert_eq!(glob_match(p, s), want, "glob({p:?}, {s:?})");
        }
        assert!(!glob_match(r"a\", "a"), "invalid pattern matched");
        assert_eq!(Glob::new(r"a\"), Err(GlobError));
    }

    #[test]
    fn hostile_pattern_is_linear() {
        let p = "*a".repeat(200) + "b";
        let s = "a".repeat(5000);
        assert!(!glob_match(&p, &s));
    }

    #[test]
    fn debug_shows_pattern() {
        assert_eq!(format!("{:?}", Glob::new("a*").unwrap()), "Glob(\"a*\")");
        assert_eq!(Glob::new("a*").unwrap().as_str(), "a*");
    }
}
