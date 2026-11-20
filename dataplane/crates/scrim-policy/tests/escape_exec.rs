// SPDX-License-Identifier: AGPL-3.0-only

//! Escaping fuzzer (leak-assurance spec "Fuzzing gates", scenario "Escaping fuzz"): hostile
//! display values are restored into generated shell and interpreter commands through the
//! restore engine, and every command that had a value restored is executed in a sandbox. The
//! hostile values all try to create a marker file; the test fails if one ever appears, if a
//! data-only command prints anything but the value, or if the streaming decision would insert a
//! value raw where the escaping path changes it.
//!
//! Sandbox: each command runs with `unshare -rn` (new user and network namespace: no network)
//! when the kernel allows it, in a fresh temporary directory that is also `$HOME`, with an
//! empty environment, no stdin and a timeout. Without unprivileged user namespaces the command
//! still runs in the temporary directory, without network isolation; set
//! `SCRIM_ESCAPE_FUZZ_REQUIRE_SANDBOX=1` to fail instead. `SCRIM_ESCAPE_FUZZ_CASES` sets the
//! number of generated cases (default 1500).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic,
    clippy::print_stderr
)]

use std::collections::HashMap;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};
use scrim_policy::escape::ValueTraits;
use scrim_policy::{
    At, Caller, ResolvedValue, RestoreEngine, Settings, ValueClass, ValueIndex, ValueInfo,
    ValueSource, Verdict,
};

const PH: &str = "\u{27e6}scrim:v:010011223344556677\u{27e7}";
const REF: &str = "bao://kv/fuzz#v";
const MARKER: &str = "pwned";

struct One(Vec<u8>);

impl ValueSource for One {
    fn resolve(&self, placeholder: &str) -> Option<ResolvedValue<'_>> {
        (placeholder == PH).then(|| ResolvedValue {
            reference: REF,
            class: ValueClass::Display,
            value: &self.0,
        })
    }
}

fn engine(value: &[u8]) -> RestoreEngine {
    let mut ix = ValueIndex::new();
    ix.push(ValueInfo {
        reference: REF.into(),
        slug: "v".into(),
        class: ValueClass::Display,
        name: "".into(),
        store: "fuzz".into(),
        traits: ValueTraits::of(value),
    });
    RestoreEngine::new(Settings::standard(), None, ix)
}

/// The sandbox's `PATH`: the system directories plus the directory of the real `node` binary
/// (version managers put a shim on the user's `PATH` that needs their environment).
fn sandbox_path() -> &'static str {
    static P: OnceLock<String> = OnceLock::new();
    P.get_or_init(|| {
        let mut p = String::from("/usr/local/bin:/usr/bin:/bin");
        if let Ok(out) = Command::new("node")
            .args([
                "-e",
                "process.stdout.write(require('path').dirname(process.execPath))",
            ])
            .stderr(Stdio::null())
            .output()
            && out.status.success()
            && let Ok(dir) = String::from_utf8(out.stdout)
        {
            p.push(':');
            p.push_str(&dir);
        }
        p
    })
}

fn have(cmd: &str) -> bool {
    static CACHE: OnceLock<std::sync::Mutex<HashMap<String, bool>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(&b) = cache.lock().unwrap().get(cmd) {
        return b;
    }
    let b = Command::new("sh")
        .args(["-c", &format!("command -v {cmd} >/dev/null 2>&1")])
        .env("PATH", sandbox_path())
        .status()
        .is_ok_and(|s| s.success());
    cache.lock().unwrap().insert(cmd.to_string(), b);
    b
}

fn sandbox_prefix() -> &'static [&'static str] {
    static P: OnceLock<Vec<&'static str>> = OnceLock::new();
    P.get_or_init(|| {
        let ok = Command::new("unshare")
            .args(["-rn", "true"])
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if ok {
            vec!["unshare", "-rn", "--"]
        } else {
            assert!(
                std::env::var("SCRIM_ESCAPE_FUZZ_REQUIRE_SANDBOX").is_err(),
                "unshare -rn is not available and SCRIM_ESCAPE_FUZZ_REQUIRE_SANDBOX is set"
            );
            eprintln!("escape fuzz: unshare -rn unavailable; running without network isolation");
            Vec::new()
        }
    })
}

/// Runs argv in a fresh sandbox directory. Returns stdout and whether the marker appeared.
fn run(argv: &[String]) -> (Vec<u8>, bool) {
    let dir = tempfile::tempdir().unwrap();
    let mut full: Vec<String> = sandbox_prefix().iter().map(|s| (*s).to_string()).collect();
    full.extend(["timeout".into(), "5".into()]);
    full.extend(argv.iter().cloned());
    let out = Command::new(&full[0])
        .args(&full[1..])
        .current_dir(dir.path())
        .env_clear()
        .env("PATH", sandbox_path())
        .env("HOME", dir.path())
        .env("LC_ALL", "C.UTF-8")
        .env("PYTHONIOENCODING", "utf-8")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .expect("spawn sandboxed command");
    let hit = marker_in(dir.path());
    (out.stdout, hit)
}

fn marker_in(dir: &Path) -> bool {
    walk(dir).iter().any(|p| {
        p.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n == MARKER)
    })
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            }
            out.push(p);
        }
    }
    out
}

/// A command template. `PH` marks the placeholder. `expect` is the stdout a correct restore
/// produces, with `{}` for the value, when the command only prints it.
#[derive(Clone, Copy, Debug)]
struct Template {
    script: &'static str,
    expect: Option<&'static str>,
    /// The engine must never restore here.
    unsafe_: bool,
    /// Needs this program.
    needs: &'static str,
    /// Argv form (Codex `shell`): `["bash", "-lc", script]`.
    argv: bool,
}

const fn t(script: &'static str, expect: Option<&'static str>) -> Template {
    Template {
        script,
        expect,
        unsafe_: false,
        needs: "bash",
        argv: false,
    }
}
const fn bad(script: &'static str) -> Template {
    Template {
        script,
        expect: None,
        unsafe_: true,
        needs: "bash",
        argv: false,
    }
}

const TEMPLATES: &[Template] = &[
    t("echo PH", Some("{}\n")),
    t("echo x PH y", Some("x {} y\n")),
    t("echo 'PH'", Some("{}\n")),
    t("echo 'a PH b'", Some("a {} b\n")),
    t("echo \"PH\"", Some("{}\n")),
    t("echo \"a PH b\"", Some("a {} b\n")),
    t("echo \"$HOME/PH\" >/dev/null; echo \"PH\"", Some("{}\n")),
    t("echo x-PH", Some("x-{}\n")),
    t("echo pre'PH'post", Some("pre{}post\n")),
    t("echo \"$(echo \"PH\")\"", None),
    t("echo $(cat <<< \"PH\")", None),
    t("cat <<< PH", Some("{}\n")),
    t("cat <<< \"x PH\"", Some("x {}\n")),
    t("cat <<'EOF'\nPH\nEOF\n", Some("{}\n")),
    t("cat <<EOF\nline PH end\nEOF\n", Some("line {} end\n")),
    t("cat <<-'EOF'\n\tPH\n\tEOF\n", Some("{}\n")),
    t(
        "echo PH | cat | wc -c >/dev/null; echo done",
        Some("done\n"),
    ),
    t("grep -c PH /dev/null; true", None),
    t("ls PH 2>/dev/null; true", None),
    t(
        "cat > out.json <<'EOF'\n{\"k\": \"PH\"}\nEOF\ncat out.json",
        Some(JSON_FILE),
    ),
    t("cat > out.yaml <<'EOF'\nk: PH\nEOF\n", None),
    t("bash -c 'echo PH'", Some("{}\n")),
    t("bash -c \"echo 'PH'\"", Some("{}\n")),
    // dash's echo interprets backslashes, so only execution is checked.
    t("sh -c 'echo \"PH\"'", None),
    t("bash -c 'cat <<< \"PH\"'", Some("{}\n")),
    Template {
        needs: "python3",
        ..t("python3 -c 'print(\"PH\")'", Some("{}\n"))
    },
    Template {
        needs: "python3",
        ..t("python3 -c \"print('PH')\"", Some("{}\n"))
    },
    Template {
        needs: "python3",
        ..t(
            "python3 -c 'print(\"x\", \"PH\", sep=\"|\")'",
            Some("x|{}\n"),
        )
    },
    Template {
        needs: "python3",
        ..t(
            "python3 -c 'import sys; sys.stdout.write(\"\"\"PH\"\"\")'",
            Some("{}"),
        )
    },
    Template {
        needs: "node",
        ..t("node -e 'console.log(\"PH\")'", Some("{}\n"))
    },
    Template {
        needs: "sqlite3",
        ..t("sqlite3 :memory: \"select 'PH';\"", Some("{}\n"))
    },
    Template {
        argv: true,
        ..t("echo 'PH'", Some("{}\n"))
    },
    Template {
        argv: true,
        ..t("cat <<< \"PH\"", Some("{}\n"))
    },
    bad("PH"),
    bad("eval PH"),
    bad("eval \"echo PH\""),
    bad("echo PH | sh"),
    bad("echo PH | bash"),
    bad("sh -c PH"),
    bad("bash -c \"PH\""),
    bad("bash -c 'eval \"PH\"'"),
    bad("echo PH > x.sh; sh x.sh"),
    bad("echo PH | xargs -I{} sh -c {}"),
    bad("X=PH; eval \"$X\""),
    bad("echo $(PH)"),
    bad("echo `echo PH`"),
    bad("echo $((PH))"),
    bad("cat <<EOF | sh\nPH\nEOF\n"),
    bad("source <(echo PH)"),
    Template {
        needs: "python3",
        ..bad("python3 -c 'exec(\"PH\")'")
    },
    Template {
        needs: "python3",
        ..bad("python3 -c 'import os; os.system(\"PH\")'")
    },
    Template {
        needs: "python3",
        ..bad("python3 -c 'print(f\"{PH}\")'")
    },
    Template {
        needs: "python3",
        ..bad("python3 -c PH")
    },
    Template {
        needs: "node",
        ..bad("node -e 'eval(\"PH\")'")
    },
    Template {
        needs: "node",
        ..bad("node -e 'require(\"child_process\").execSync(\"PH\")'")
    },
    Template {
        needs: "sqlite3",
        ..bad("sqlite3 :memory: \".shell PH\"")
    },
    Template {
        needs: "sqlite3",
        ..bad("sqlite3 :memory: \"select 1;\n.system PH\"")
    },
];

/// Expectation marker: stdout is a JSON object whose `k` is the value.
const JSON_FILE: &str = "<json k>";

const FRAGMENTS: &[&str] = &[
    "$(touch pwned)",
    "`touch pwned`",
    "'; touch pwned; '",
    "\"; touch pwned; \"",
    "\ntouch pwned\n",
    ";touch pwned;",
    "|touch pwned",
    "&& touch pwned",
    "$'\\x27'",
    "\\",
    "'",
    "\"",
    "$",
    "`",
    "!",
    "!!",
    "*",
    "?",
    "[a]",
    "{a,b}",
    "~",
    "#",
    "|",
    "&",
    ";",
    "<",
    ">",
    "(",
    ")",
    " ",
    "  ",
    "\t",
    "\n",
    "\r",
    "EOF",
    "\nEOF\ntouch pwned\n",
    "\n\tEOF\ntouch pwned\n",
    "%s",
    "%n",
    "-n",
    "-e",
    "--",
    "-",
    "é",
    "\u{2028}",
    "\u{85}",
    "a",
    "abc",
    "touch pwned",
    "__import__('os').system('touch pwned')",
    "\")+__import__('os').system('touch pwned')+(\"",
    "')+__import__('os').system('touch pwned')+('",
    "\"\"\"+__import__('os').system('touch pwned')+\"\"\"",
    "{__import__('os').system('touch pwned')}",
    "require('child_process').execSync('touch pwned')",
    "\");require('child_process').execSync('touch pwned');(\"",
    "');require('child_process').execSync('touch pwned');('",
    "'||edit('x','touch pwned')||'",
    "');.shell touch pwned\n",
    "\n.shell touch pwned\n",
    "${IFS}",
    "$HOME",
    "${HOME}",
    "\\n",
    "\\x27",
    "\\'",
    "\\\"",
    "\\\\",
    "\\u0027",
    "\0",
];

fn value() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        8 => prop::collection::vec(prop::sample::select(FRAGMENTS), 1..6).prop_map(|v| v.concat().into_bytes()),
        1 => "[ -~]{0,12}".prop_map(String::into_bytes),
        1 => prop::collection::vec(any::<u8>(), 0..8),
    ]
}

fn args_for(tpl: &Template) -> String {
    let script = tpl.script.replace("PH", PH);
    if tpl.argv {
        serde_json::json!({ "command": ["bash", "-lc", script] }).to_string()
    } else {
        serde_json::json!({ "command": script }).to_string()
    }
}

fn argv_of(tpl: &Template, restored: &serde_json::Value) -> Vec<String> {
    if tpl.argv {
        restored["command"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    } else {
        vec![
            "bash".into(),
            "--noprofile".into(),
            "--norc".into(),
            "-c".into(),
            restored["command"].as_str().unwrap().to_string(),
        ]
    }
}

fn json_escaped(v: &str) -> String {
    let s = serde_json::to_string(v).unwrap();
    s[1..s.len() - 1].to_string()
}

#[derive(Default, Debug)]
struct Stats {
    cases: usize,
    restored: usize,
    executed: usize,
    raw_ok: usize,
    per_template: HashMap<&'static str, (usize, usize)>,
}

fn check(tpl: &Template, value: &[u8], stats: &mut Stats) -> Result<(), TestCaseError> {
    let engine = engine(value);
    let source = One(value.to_vec());
    let args = args_for(tpl);
    let caller = Caller::default();
    let tool = if tpl.argv { "shell" } else { "Bash" };
    let out = engine.restore_tool_input(&caller, tool, &args, &source);
    stats.cases += 1;
    let entry = stats.per_template.entry(tpl.script).or_default();
    entry.0 += 1;
    let verdict = engine.decide(
        &caller,
        At::Tool {
            name: tool,
            arguments: Some(&args),
        },
        REF,
        ValueClass::Display,
    );
    let Some(text) = out.text else {
        prop_assert!(
            !verdict.resolves(),
            "decide resolved where restore kept: {:?}",
            tpl.script
        );
        return Ok(());
    };
    prop_assert!(
        !tpl.unsafe_,
        "restored into an unsafe template {:?}: {}",
        tpl.script,
        text
    );
    entry.1 += 1;
    stats.restored += 1;
    let restored: serde_json::Value = serde_json::from_str(&text).expect("arguments stay JSON");
    if verdict == Verdict::Resolve {
        // The streaming path inserts the raw value: it must equal the escaped restore.
        let raw = args.replace(PH, &json_escaped(std::str::from_utf8(value).unwrap()));
        let raw: serde_json::Value = serde_json::from_str(&raw).unwrap();
        prop_assert_eq!(
            &raw,
            &restored,
            "raw insertion differs from escaping for {:?}",
            tpl.script
        );
        stats.raw_ok += 1;
    }
    if !have(tpl.needs) {
        return Ok(());
    }
    let argv = argv_of(tpl, &restored);
    let (stdout, hit) = run(&argv);
    stats.executed += 1;
    prop_assert!(
        !hit,
        "restored value executed as code: {:?} -> {:?}",
        tpl.script,
        argv
    );
    let v = std::str::from_utf8(value).unwrap();
    if text.contains(PH) {
        // Some occurrences were kept (a value starting with `-` at a word start, say): the
        // output is not the value's, but nothing may have executed.
        return Ok(());
    }
    if tpl.expect == Some(JSON_FILE) {
        let got: serde_json::Value = serde_json::from_slice(&stdout).expect("file is JSON");
        prop_assert_eq!(got["k"].as_str(), Some(v), "JSON file for {:?}", tpl.script);
    } else if let Some(expect) = tpl.expect {
        let want = expect.replace("{}", v);
        prop_assert_eq!(
            String::from_utf8_lossy(&stdout),
            want,
            "wrong output for {:?} with argv {:?}",
            tpl.script,
            argv
        );
    }
    Ok(())
}

#[test]
fn hostile_values_never_execute() {
    if !have("bash") {
        eprintln!("escape fuzz: bash not found; skipped");
        return;
    }
    let cases = std::env::var("SCRIM_ESCAPE_FUZZ_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1500);
    let mut runner = TestRunner::new(Config {
        cases,
        failure_persistence: None,
        ..Config::default()
    });
    let stats = std::cell::RefCell::new(Stats::default());
    let strategy = (prop::sample::select(TEMPLATES), value());
    runner
        .run(&strategy, |(tpl, v)| {
            check(&tpl, &v, &mut stats.borrow_mut())
        })
        .unwrap();
    let s = stats.into_inner();
    eprintln!(
        "escape fuzz: {} cases, {} restored, {} executed, {} raw-equal",
        s.cases, s.restored, s.executed, s.raw_ok
    );
    // Every safe template must restore something across the run, or the fuzzer proves little.
    for tpl in TEMPLATES.iter().filter(|t| !t.unsafe_ && have(t.needs)) {
        if let Some((n, r)) = s.per_template.get(tpl.script) {
            assert!(
                *n < 5 || *r > 0,
                "template {:?} never restored in {n} cases",
                tpl.script
            );
        }
    }
}

/// Every template with a few fixed hostile values, executed: a deterministic floor under the
/// randomised run.
#[test]
fn fixed_hostile_values() {
    if !have("bash") {
        return;
    }
    let mut stats = Stats::default();
    let values: &[&[u8]] = &[
        b"plain",
        b"it's \"quoted\" $(touch pwned) `touch pwned` \\ !",
        b"a\nEOF\ntouch pwned\nb",
        b"'; touch pwned; '",
        b"\")+__import__('os').system('touch pwned')+(\"",
        b"');require('child_process').execSync('touch pwned');('",
        b"x';.shell touch pwned\n",
        b"",
    ];
    for tpl in TEMPLATES {
        for v in values {
            check(tpl, v, &mut stats).unwrap_or_else(|e| panic!("{e}"));
        }
    }
    assert!(stats.executed > 0 || !have("bash"));
    // The plain value is restored into every safe template.
    for tpl in TEMPLATES.iter().filter(|t| !t.unsafe_) {
        let e = engine(b"plain");
        let tool = if tpl.argv { "shell" } else { "Bash" };
        let out = e.restore_tool_input(
            &Caller::default(),
            tool,
            &args_for(tpl),
            &One(b"plain".to_vec()),
        );
        assert!(
            out.text.is_some(),
            "plain value kept in {:?}: {:?}",
            tpl.script,
            out.kept
        );
    }
}
