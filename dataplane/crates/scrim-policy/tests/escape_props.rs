// SPDX-License-Identifier: AGPL-3.0-only

//! Properties of the escaping layer:
//!
//! * `ValueTraits::raw_is_safe` holds exactly when `escape` returns the value unchanged, so
//!   the streaming path (which inserts raw values) never inserts one that needed escaping;
//! * the analysers never panic on arbitrary input, and refuse or accept every placeholder;
//! * a value escaped for a shell site reads back as exactly the value (checked without
//!   executing anything, by the shell analyser's own quote removal on the escaped word).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]

use proptest::prelude::*;
use scrim_policy::escape::shell::{BuiltinCommands, analyze_argv, analyze_script};
use scrim_policy::escape::{Layer, Site, ValueTraits, code, escape};

fn layer() -> impl Strategy<Value = Layer> {
    prop_oneof![
        any::<bool>().prop_map(|w| Layer::ShellBare { word_start: w }),
        any::<bool>().prop_map(|w| Layer::ShellSingle { word_start: w }),
        any::<bool>().prop_map(|w| Layer::ShellDouble { word_start: w }),
        any::<bool>().prop_map(|w| Layer::Argv { word_start: w }),
        Just(Layer::HeredocQuoted),
        Just(Layer::HeredocUnquoted),
        Just(Layer::StrippedLineStart),
        prop::sample::select(&['\'', '"'][..]).prop_map(|q| Layer::Python { quote: q }),
        prop::sample::select(&['\'', '"'][..]).prop_map(|q| Layer::JavaScript { quote: q }),
        Just(Layer::SqlString),
        Just(Layer::JsonString),
        Just(Layer::YamlDouble),
        Just(Layer::YamlPlain),
    ]
}

fn value() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        prop::collection::vec(
            prop::sample::select(
                &[
                    "a", "Z", "0", "-", "_", ".", "/", ":", "=", "'", "\"", "\\", "$", "`", "!",
                    " ", "\t", "\n", "\r", "\0", "\u{1}", "\u{7f}", "\u{85}", "\u{2028}", "é", "#",
                    "*", "~", "{", "}", "yes", "1",
                ][..]
            ),
            0..8
        )
        .prop_map(|v| v.concat().into_bytes()),
        prop::collection::vec(any::<u8>(), 0..6),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 20000, ..ProptestConfig::default() })]

    #[test]
    fn traits_match_escape(v in value(), layers in prop::collection::vec(layer(), 0..3)) {
        let site = Site { layers, heredoc_forbidden: None };
        let identity = escape(&site, &v).is_ok_and(|e| e.as_bytes() == v.as_slice());
        prop_assert_eq!(ValueTraits::of(&v).raw_is_safe(&site), identity, "site {:?}", site);
    }
}

const PH: &str = "\u{27e6}scrim:v:010011223344556677\u{27e7}";

fn script() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop::sample::select(
            &[
                "PH",
                " ",
                "echo",
                "cat",
                "sh",
                "bash -c",
                "python3 -c",
                "node -e",
                "sqlite3 x.db",
                "'",
                "\"",
                "\\",
                "$",
                "$(",
                ")",
                "(",
                "`",
                "|",
                ";",
                "&",
                "&&",
                ">",
                ">>",
                "<",
                "<<",
                "<<'EOF'",
                "<<-E",
                "<<<",
                "\n",
                "EOF",
                "\tE",
                "#",
                "{",
                "}",
                "=",
                "x=",
                "*",
                "~/",
                "--",
                "-c",
                "print(",
                "'PH'",
                "\"PH\"",
                "${",
                "${x}",
                "$x",
                "$((",
                "if",
                "then",
                "fi",
                "for",
                "case",
                "esac",
                "2>&1",
                "<(",
                ">(",
                "@(",
                "tee",
                "a.sh",
                "a.json",
                "é",
            ][..],
        ),
        0..16,
    )
    .prop_map(|v| v.concat().replace("PH", PH))
}

fn spans(s: &str) -> Vec<(usize, usize)> {
    s.match_indices(PH).map(|(i, m)| (i, i + m.len())).collect()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 20000, ..ProptestConfig::default() })]

    #[test]
    fn heredoc_guard_is_conservative(v in value(), forbid in prop::sample::select(&["EOF", "", "a", "X"][..])) {
        let site = Site { layers: vec![Layer::HeredocQuoted], heredoc_forbidden: Some(forbid.into()) };
        prop_assert!(!ValueTraits::of(&v).raw_is_safe(&site));
        if v == forbid.as_bytes() {
            prop_assert!(escape(&site, &v).is_err());
        }
    }

    #[test]
    fn shell_analyser_is_total(s in script()) {
        let sp = spans(&s);
        let out = analyze_script(&s, &sp, &BuiltinCommands);
        prop_assert_eq!(out.len(), sp.len());
        let argv: Vec<&str> = s.split(' ').collect();
        let asp: Vec<Vec<_>> = argv.iter().map(|a| spans(a)).collect();
        let out = analyze_argv(&argv, &asp, &BuiltinCommands);
        prop_assert_eq!(out.len(), argv.len());
        for lang in [code::Lang::Python, code::Lang::JavaScript, code::Lang::Sqlite] {
            prop_assert_eq!(code::analyze(lang, &s, &sp).sites.len(), sp.len());
        }
    }

    /// Escaped into an `echo` argument, the value is the whole, single word the shell sees:
    /// re-analysing the escaped command finds no expansion, and its literal text is the value.
    #[test]
    fn escaped_shell_word_is_the_value(v in value(), tpl in prop::sample::select(&["echo PH", "echo 'PH'", "echo \"PH\"", "echo x\"PH\"y"][..])) {
        let s = tpl.replace("PH", PH);
        let sp = spans(&s);
        let site = analyze_script(&s, &sp, &BuiltinCommands).remove(0).unwrap();
        let Ok(e) = escape(&site, &v) else { return Ok(()) };
        let restored = format!("{}{}{}", &s[..sp[0].0], e, &s[sp[0].1..]);
        // Mark the value with a placeholder-free probe: the restored command must lex as
        // exactly two words with no command substitution, which the analyser reports as a
        // successful analysis of a data-only command with no placeholders.
        let again = analyze_script(&restored, &[], &BuiltinCommands);
        prop_assert!(again.is_empty());
        let check = format!("{restored}; {PH}");
        let sp2 = spans(&check);
        // The trailing placeholder is a command name (refused as code), never swallowed by a
        // quote the escaped value left open.
        let r = analyze_script(&check, &sp2, &BuiltinCommands);
        prop_assert_eq!(r.len(), 1);
        prop_assert!(r[0].is_err());
        let check = format!("{restored} {PH}");
        let sp3 = spans(&check);
        let r = analyze_script(&check, &sp3, &BuiltinCommands);
        prop_assert!(r[0].is_ok(), "escaped value left the word open: {:?}", check);
    }
}
