// SPDX-License-Identifier: AGPL-3.0-only

//! File-level context: which paths hold code, and the JSON or YAML layer of a heredoc body
//! written to a `.json`, `.yaml` or `.yml` file.
//!
//! [`is_code_path`] is a heuristic. It catches the common ways data written by a command later
//! runs as code (shell rc files, scripts, git hooks and config, ssh config, CI workflows,
//! cron, systemd units, `/dev/tcp`); it cannot know every program that reads a file as code.
//! The primary guard is the shell analyser's command allowlist.

use super::{Layer, Refusal};

const CODE_EXTENSIONS: &[&str] = &[
    "sh", "bash", "zsh", "ksh", "fish", "csh", "tcsh", "py", "pyw", "pth", "rb", "pl", "pm", "php",
    "js", "mjs", "cjs", "ts", "mts", "cts", "jsx", "tsx", "lua", "tcl", "ps1", "psm1", "bat",
    "cmd", "vbs", "r", "awk", "sed", "mk", "service", "timer", "socket", "desktop", "plist", "vim",
    "el", "envrc", "command", "tool", "zshrc", "bashrc", "profile",
];

const CODE_NAMES: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".zlogin",
    ".zlogout",
    ".kshrc",
    ".cshrc",
    ".tcshrc",
    ".inputrc",
    ".vimrc",
    ".exrc",
    ".gvimrc",
    "init.vim",
    "init.lua",
    ".emacs",
    ".gitconfig",
    ".gitattributes",
    ".gitmodules",
    ".npmrc",
    ".yarnrc",
    ".yarnrc.yml",
    ".envrc",
    ".env",
    "makefile",
    "gnumakefile",
    "justfile",
    ".justfile",
    "dockerfile",
    "containerfile",
    "vagrantfile",
    "rakefile",
    "gemfile",
    "jenkinsfile",
    "pkgbuild",
    "crontab",
    "authorized_keys",
    "environment",
    "package.json",
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
    "conftest.py",
    "build.rs",
    "cargo.toml",
    ".pre-commit-config.yaml",
    ".gitlab-ci.yml",
    ".travis.yml",
];

const CODE_DIRS: &[&str] = &[
    ".git/",
    ".ssh/",
    ".github/",
    ".husky/",
    ".config/fish/",
    ".config/autostart/",
    ".config/systemd/",
    ".local/bin/",
    "/bin/",
    "/sbin/",
    "/etc/",
    "/proc/",
    "/sys/",
    "/dev/tcp/",
    "/dev/udp/",
    "cron",
    "systemd/",
    "profile.d/",
    "rc.d/",
    "init.d/",
    "hooks/",
];

/// Whether writing to `path` (as written in the command, `~` unexpanded) could make data run
/// as code later. Paths with expansions should be treated as code by the caller.
pub fn is_code_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let base = lower.rsplit('/').next().unwrap_or(&lower);
    if lower.starts_with("bin/") || lower.starts_with("/dev/tcp") || lower.starts_with("/dev/udp") {
        return true;
    }
    if CODE_NAMES.contains(&base) {
        return true;
    }
    if let Some((_, ext)) = base.rsplit_once('.')
        && CODE_EXTENSIONS.contains(&ext)
    {
        return true;
    }
    CODE_DIRS.iter().any(|d| lower.contains(d))
}

/// The file format a heredoc body is written in, from its redirection target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyFormat {
    /// No format layer.
    Text,
    /// JSON (`.json`).
    Json,
    /// YAML (`.yaml`, `.yml`).
    Yaml,
}

impl BodyFormat {
    /// The format of a file at `path`.
    #[allow(clippy::case_sensitive_file_extension_comparisons)] // compared lower-cased
    pub fn of(path: &str) -> BodyFormat {
        let lower = path.to_ascii_lowercase();
        if lower.ends_with(".json") {
            BodyFormat::Json
        } else if lower.ends_with(".yaml") || lower.ends_with(".yml") {
            BodyFormat::Yaml
        } else {
            BodyFormat::Text
        }
    }
}

/// The format layer of each placeholder span (byte ranges into `body`) of a body in `fmt`.
/// `None` means no extra layer.
pub fn body_layers(
    fmt: BodyFormat,
    body: &str,
    spans: &[(usize, usize)],
) -> Vec<Result<Option<Layer>, Refusal>> {
    match fmt {
        BodyFormat::Text => spans.iter().map(|_| Ok(None)).collect(),
        BodyFormat::Json => json_layers(body, spans),
        BodyFormat::Yaml => yaml_layers(body, spans),
    }
}

/// A placeholder must be inside a JSON string literal.
fn json_layers(body: &str, spans: &[(usize, usize)]) -> Vec<Result<Option<Layer>, Refusal>> {
    let b = body.as_bytes();
    // in_string[i] for every byte offset: inside a string literal, and the byte before is not
    // an escaping backslash.
    let mut inside = vec![false; b.len() + 1];
    let mut after_backslash = vec![false; b.len() + 1];
    let mut in_str = false;
    let mut esc = false;
    for (i, &c) in b.iter().enumerate() {
        inside[i] = in_str;
        after_backslash[i] = esc;
        if in_str {
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                in_str = false;
            }
        } else if c == b'"' {
            in_str = true;
        }
    }
    inside[b.len()] = in_str;
    spans
        .iter()
        .map(|&(s, e)| {
            if !inside[s] || !inside[e.min(b.len())] {
                Err(Refusal::Position)
            } else if after_backslash[s] {
                Err(Refusal::Adjacent)
            } else {
                Ok(Some(Layer::JsonString))
            }
        })
        .collect()
}

/// A placeholder is accepted in a YAML body only as a whole plain scalar after `key: ` or
/// `- `, or inside a double-quoted scalar on one line that holds no other quotes.
fn yaml_layers(body: &str, spans: &[(usize, usize)]) -> Vec<Result<Option<Layer>, Refusal>> {
    spans
        .iter()
        .map(|&(s, e)| {
            let line_start = body[..s].rfind('\n').map_or(0, |i| i + 1);
            let line_end = body[e..].find('\n').map_or(body.len(), |i| e + i);
            let before = &body[line_start..s];
            let after = body[e..line_end].trim_end_matches('\r');
            let head = before.trim_start();
            let plain_prefix = head.is_empty()
                || head == "- "
                || (head.ends_with(": ")
                    && !head[..head.len() - 2]
                        .contains(['"', '\'', '#', '{', '[', '&', '*', '!', '|', '>']));
            if plain_prefix && !head.is_empty() && after.trim_end().is_empty() {
                return Ok(Some(Layer::YamlPlain));
            }
            let line = &body[line_start..line_end];
            let quotes = line.matches('"').count();
            if quotes == 2
                && !line.contains(['\'', '\\', '#'])
                && before.matches('"').count() == 1
                && after.matches('"').count() == 1
            {
                return Ok(Some(Layer::YamlDouble));
            }
            Err(Refusal::Position)
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::pedantic)]
mod tests {
    use super::*;

    #[test]
    fn code_paths() {
        for p in [
            "~/.bashrc",
            "/home/u/.profile",
            "x.sh",
            "a/b/run.py",
            ".git/hooks/pre-commit",
            ".git/config",
            "~/.ssh/config",
            ".github/workflows/ci.yml",
            "Makefile",
            "/etc/cron.d/x",
            "/dev/tcp/1.2.3.4/80",
            "bin/tool",
            "~/.local/bin/tool",
            "package.json",
        ] {
            assert!(is_code_path(p), "{p}");
        }
        for p in [
            "notes.txt",
            "out.json",
            "config.yaml",
            "/tmp/x.log",
            "README.md",
            "data.csv",
        ] {
            assert!(!is_code_path(p), "{p}");
        }
    }

    #[test]
    fn formats() {
        assert_eq!(BodyFormat::of("a/B.JSON"), BodyFormat::Json);
        assert_eq!(BodyFormat::of("x.yml"), BodyFormat::Yaml);
        assert_eq!(BodyFormat::of("x.txt"), BodyFormat::Text);
    }

    fn spans_of(body: &str) -> Vec<(usize, usize)> {
        body.match_indices("PH").map(|(i, _)| (i, i + 2)).collect()
    }

    #[test]
    fn json_body() {
        let body = "{\"a\": \"x PH y\", \"b\": PH, \"c\": \"\\PH\"}";
        let got = body_layers(BodyFormat::Json, body, &spans_of(body));
        assert_eq!(
            got,
            vec![
                Ok(Some(Layer::JsonString)),
                Err(Refusal::Position),
                Err(Refusal::Adjacent)
            ]
        );
    }

    #[test]
    fn yaml_body() {
        let body = "a: PH\nlist:\n  - PH\nq: \"x PH\"\nbad: x PH\nm: 'PH'\n";
        let got = body_layers(BodyFormat::Yaml, body, &spans_of(body));
        assert_eq!(
            got,
            vec![
                Ok(Some(Layer::YamlPlain)),
                Ok(Some(Layer::YamlPlain)),
                Ok(Some(Layer::YamlDouble)),
                Err(Refusal::Position),
                Err(Refusal::Position),
            ]
        );
        assert_eq!(
            body_layers(BodyFormat::Text, "PH", &[(0, 2)]),
            vec![Ok(None)]
        );
    }
}
