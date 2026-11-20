// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;

use super::*;
use crate::escape::ValueTraits;
use crate::request::Agent;

/// Test values: placeholder text -> (reference, class, value).
struct Values(HashMap<String, (String, ValueClass, Vec<u8>)>);

impl ValueSource for Values {
    fn resolve(&self, placeholder: &str) -> Option<ResolvedValue<'_>> {
        self.0.get(placeholder).map(|(r, c, v)| ResolvedValue {
            reference: r,
            class: *c,
            value: v,
        })
    }
}

fn ph(slug: &str) -> String {
    format!("\u{27e6}scrim:{slug}:01{}\u{27e7}", "00112233aabbccdd")
}

struct Fixture {
    engine: RestoreEngine,
    values: Values,
}

fn fixture(settings: Settings, table: Option<Table>, vals: &[(&str, ValueClass, &str)]) -> Fixture {
    let mut index = ValueIndex::new();
    let mut map = HashMap::new();
    for (slug, class, v) in vals {
        let reference = format!("bao://kv/{slug}#v");
        index.push(ValueInfo {
            reference: reference.as_str().into(),
            slug: (*slug).into(),
            class: *class,
            name: "".into(),
            store: "bao".into(),
            traits: ValueTraits::of(v.as_bytes()),
        });
        map.insert(ph(slug), (reference, *class, v.as_bytes().to_vec()));
    }
    Fixture {
        engine: RestoreEngine::new(settings, table.map(Arc::new), index),
        values: Values(map),
    }
}

fn r(slug: &str) -> String {
    format!("bao://kv/{slug}#v")
}

fn bash(cmd: &str) -> String {
    serde_json::json!({ "command": cmd, "description": "d" }).to_string()
}

const D: ValueClass = ValueClass::Display;
const C: ValueClass = ValueClass::Credential;

#[test]
fn credentials_are_never_restored() {
    let f = fixture(
        Settings::standard(),
        None,
        &[("tok", C, "ghp_secret_token")],
    );
    let caller = Caller::default();
    let curl = bash(&format!("curl -H {}", ph("tok")));
    for at in [
        At::Text,
        At::Tool {
            name: "Read",
            arguments: None,
        },
        At::Tool {
            name: "Bash",
            arguments: Some(&curl),
        },
    ] {
        // Even when the caller claims display, the index says credential.
        assert_eq!(
            f.engine.decide(&caller, at, &r("tok"), D),
            Verdict::Keep(KeepReason::Credential)
        );
    }
    let args = bash(&format!("echo {}", ph("tok")));
    let out = f
        .engine
        .restore_tool_input(&caller, "Bash", &args, &f.values);
    assert_eq!(out.text, None);
    assert_eq!(
        out.kept,
        vec![(Some(r("tok").into()), KeepReason::Credential)]
    );
    assert_eq!(
        f.engine.restore_text(&caller, &ph("tok"), &f.values).text,
        None
    );
    assert_eq!(f.engine.reveal(&ph("tok"), &f.values).text, None);
}

#[test]
fn roles() {
    let f = fixture(Settings::standard(), None, &[("name", D, "alice")]);
    let c = Caller::default();
    let tool = |name, args: Option<&str>| {
        f.engine.decide(
            &c,
            At::Tool {
                name,
                arguments: args,
            },
            &r("name"),
            D,
        )
    };
    assert_eq!(tool("Read", None), Verdict::Resolve);
    assert_eq!(tool("Grep", None), Verdict::Resolve);
    assert_eq!(
        tool("mcp__x__y", None),
        Verdict::Keep(KeepReason::Role(ToolRole::None))
    );
    assert_eq!(
        tool("WebFetch", None),
        Verdict::Keep(KeepReason::Role(ToolRole::Network))
    );
    assert_eq!(
        tool("Write", None),
        Verdict::Keep(KeepReason::Role(ToolRole::Write))
    );
    assert_eq!(tool("Bash", None), Verdict::Keep(KeepReason::Streaming));
    assert_eq!(tool("Edit", None), Verdict::Keep(KeepReason::Streaming));
    assert!(f.engine.needs_arguments("Bash") && f.engine.needs_arguments("apply_patch"));
    assert!(!f.engine.needs_arguments("Read"));
    let args = bash(&format!("echo {}", ph("name")));
    assert_eq!(tool("Bash", Some(&args)), Verdict::Resolve);
    let args = bash(&format!("echo {} | sh", ph("name")));
    assert_eq!(
        tool("Bash", Some(&args)),
        Verdict::Keep(KeepReason::Context(Refusal::UnknownCommand))
    );
    assert_eq!(
        tool("Bash", Some(&bash("echo none"))),
        Verdict::Keep(KeepReason::Context(Refusal::Unsupported))
    );
    assert_eq!(
        f.engine.decide(&c, At::Text, "bao://kv/missing", D),
        Verdict::Keep(KeepReason::UnknownValue)
    );
    // The slug works as a reference too.
    assert_eq!(f.engine.decide(&c, At::Text, "name", D), Verdict::Resolve);
}

#[test]
fn unknown_tool_gets_placeholder_and_alias_maps_role() {
    let mut s = Settings::standard();
    let f = fixture(s.clone(), None, &[("name", D, "alice")]);
    let args = serde_json::json!({ "cmd": format!("cat {}", ph("name")) }).to_string();
    let out = f
        .engine
        .restore_tool_input(&Caller::default(), "run_shell", &args, &f.values);
    assert_eq!(out.text, None);
    assert_eq!(out.kept[0].1, KeepReason::Role(ToolRole::None));
    let mut spec = ToolSpec::new(ToolRole::Shell);
    spec.command_field = "cmd".into();
    s.set_tool("run_shell", spec);
    let f = fixture(s, None, &[("name", D, "alice")]);
    let out = f
        .engine
        .restore_tool_input(&Caller::default(), "run_shell", &args, &f.values);
    assert_eq!(out.text.unwrap(), r#"{"cmd":"cat alice"}"#);
}

#[test]
fn shell_values_are_escaped() {
    let v = "it's $(touch pwned) \"x\" `y`";
    let f = fixture(Settings::standard(), None, &[("v", D, v)]);
    let c = Caller::default();
    let args = bash(&format!("echo {}", ph("v")));
    // The streaming path cannot escape, so it keeps.
    assert_eq!(
        f.engine.decide(
            &c,
            At::Tool {
                name: "Bash",
                arguments: Some(&args)
            },
            &r("v"),
            D
        ),
        Verdict::Keep(KeepReason::NeedsEscaping)
    );
    let out = f.engine.restore_tool_input(&c, "Bash", &args, &f.values);
    let text = out.text.unwrap();
    let cmd: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(cmd["command"], "echo 'it'\\''s $(touch pwned) \"x\" `y`'");
    assert_eq!(cmd["description"], "d");
    assert_eq!(out.resolved, vec![Arc::<str>::from(r("v"))]);
}

#[test]
fn edits_only_restore_values_already_in_the_file() {
    let f = fixture(
        Settings::standard(),
        None,
        &[("a", D, "alpha"), ("b", D, "beta")],
    );
    let c = Caller::default();
    let args = serde_json::json!({
        "file_path": "/f",
        "old_string": format!("x = {}", ph("a")),
        "new_string": format!("x = {} + {}", ph("a"), ph("b")),
    })
    .to_string();
    let at = At::Tool {
        name: "Edit",
        arguments: Some(&args),
    };
    assert_eq!(f.engine.decide(&c, at, &r("a"), D), Verdict::Resolve);
    assert_eq!(
        f.engine.decide(&c, at, &r("b"), D),
        Verdict::Keep(KeepReason::NewInFile)
    );
    let out = f.engine.restore_tool_input(&c, "Edit", &args, &f.values);
    let v: serde_json::Value = serde_json::from_str(&out.text.unwrap()).unwrap();
    assert_eq!(v["old_string"], "x = alpha");
    assert_eq!(v["new_string"], format!("x = alpha + {}", ph("b")));
}

#[test]
fn display_mode() {
    let mut s = Settings::standard();
    let f = fixture(s.clone(), None, &[("a", D, "alpha")]);
    let c = Caller::default();
    let text = format!("value: {} and {}", ph("a"), ph("zz"));
    let out = f.engine.restore_text(&c, &text, &f.values);
    assert_eq!(out.text.unwrap(), format!("value: alpha and {}", ph("zz")));
    assert_eq!(out.kept, vec![(None, KeepReason::UnknownValue)]);
    s.display = DisplayMode::Placeholders;
    let f = fixture(s, None, &[("a", D, "alpha")]);
    assert_eq!(f.engine.restore_text(&c, &text, &f.values).text, None);
    assert_eq!(
        f.engine.decide(&c, At::Text, &r("a"), D),
        Verdict::Keep(KeepReason::DisplayMode)
    );
    // Tool policy resolution continues.
    assert_eq!(
        f.engine.decide(
            &c,
            At::Tool {
                name: "Read",
                arguments: None
            },
            &r("a"),
            D
        ),
        Verdict::Resolve
    );
    // No restore settings at all: nothing.
    let none = RestoreEngine::keep_all();
    assert_eq!(
        none.decide(&c, At::Text, &r("a"), D),
        Verdict::Keep(KeepReason::UnknownValue)
    );
}

fn table(rules: Vec<pb::TableRule>, break_glass: bool) -> Table {
    Table::from_proto(&pb::Policy {
        version: 1,
        default_effect: pb::Effect::Deny as i32,
        break_glass,
        table_format: 1,
        table: rules,
        ..Default::default()
    })
    .unwrap()
}

type Cond<'a> = (&'a str, &'a str, pb::ConditionOp, &'a str, bool);

fn rule(name: &str, effect: pb::Effect, conds: Vec<Cond<'_>>) -> pb::TableRule {
    pb::TableRule {
        name: name.into(),
        effect: effect as i32,
        clauses: vec![pb::Clause {
            conditions: conds
                .into_iter()
                .map(|(f, k, op, v, neg)| pb::Condition {
                    field: f.into(),
                    key: k.into(),
                    op: op as i32,
                    values: vec![v.into()],
                    negate: neg,
                })
                .collect(),
            residual: false,
        }],
        ..Default::default()
    }
}

#[test]
fn rules_only_take_restores_away() {
    use pb::ConditionOp::{Glob, In};
    let t = table(
        vec![
            rule(
                "unknown-callers",
                pb::Effect::Deny,
                vec![("agent.known", "", In, "true", true)],
            ),
            rule(
                "no-prod-restore",
                pb::Effect::Deny,
                vec![
                    ("op", "", In, "restore", false),
                    ("secret.ref", "", Glob, "bao://kv/prod**", false),
                ],
            ),
            rule("allow-all", pb::Effect::Allow, vec![]),
        ],
        false,
    );
    let f = fixture(
        Settings::standard(),
        Some(t),
        &[("app", D, "alpha"), ("prod", D, "beta")],
    );
    let unknown = Caller::default();
    let known = Caller {
        agent: Some(Agent {
            id: "a".into(),
            kind: "session".into(),
            ..Agent::default()
        }),
        provider: Some("anthropic".into()),
    };
    let read = At::Tool {
        name: "Read",
        arguments: None,
    };
    // The agent is unknown to the engine: the unknown-callers rule could match.
    assert_eq!(
        f.engine.decide(&unknown, read, &r("app"), D),
        Verdict::Keep(KeepReason::Rule("unknown-callers".into()))
    );
    assert_eq!(
        f.engine.decide(&known, read, &r("app"), D),
        Verdict::Resolve
    );
    assert_eq!(
        f.engine.decide(&known, read, &r("prod"), D),
        Verdict::Keep(KeepReason::Rule("no-prod-restore".into()))
    );
    // A caller established as unknown.
    let anon = Caller {
        agent: Some(Agent::default()),
        provider: None,
    };
    assert_eq!(
        f.engine.decide(&anon, read, &r("app"), D),
        Verdict::Keep(KeepReason::Rule("unknown-callers".into()))
    );
    // A default of deny does not stop restores: the tool policy is restore's default.
    let f = fixture(
        Settings::standard(),
        Some(table(vec![], false)),
        &[("app", D, "alpha")],
    );
    assert_eq!(
        f.engine.decide(&known, read, &r("app"), D),
        Verdict::Resolve
    );
}

#[test]
fn break_glass_keeps_everything() {
    let f = fixture(
        Settings::standard(),
        Some(table(vec![], true)),
        &[("app", D, "alpha")],
    );
    let c = Caller::default();
    assert_eq!(
        f.engine.decide(&c, At::Text, &r("app"), D),
        Verdict::Keep(KeepReason::BreakGlass)
    );
    assert_eq!(
        f.engine.decide(
            &c,
            At::Tool {
                name: "Read",
                arguments: None
            },
            &r("app"),
            D
        ),
        Verdict::Keep(KeepReason::BreakGlass)
    );
    assert_eq!(f.engine.reveal(&ph("app"), &f.values).text, None);
    assert_eq!(
        f.engine.restore_text(&c, &ph("app"), &f.values).kept[0].1,
        KeepReason::BreakGlass
    );
}

#[test]
fn reveal_credentials_only_when_listed() {
    let mut s = Settings::standard();
    s.display = DisplayMode::Placeholders;
    let f = fixture(s.clone(), None, &[("tok", C, "ghp_x"), ("app", D, "alpha")]);
    let text = format!("{} {}", ph("tok"), ph("app"));
    // Display mode does not apply to reveal.
    assert_eq!(
        f.engine.reveal(&text, &f.values).text.unwrap(),
        format!("{} alpha", ph("tok"))
    );
    s.add_reveal_credentials(crate::Glob::new("bao://kv/tok#*").unwrap());
    let f = fixture(s, None, &[("tok", C, "ghp_x"), ("app", D, "alpha")]);
    assert_eq!(
        f.engine.reveal(&text, &f.values).text.unwrap(),
        "ghp_x alpha"
    );
    // Restore into responses still never resolves the credential.
    let c = Caller::default();
    assert_eq!(
        f.engine.decide(
            &c,
            At::Tool {
                name: "Read",
                arguments: None
            },
            &r("tok"),
            C
        ),
        Verdict::Keep(KeepReason::Credential)
    );
}

#[test]
fn from_snapshot() {
    let snap = pb::Snapshot {
        values: vec![{
            let mut e = pb::ValueEntry::default();
            e.r#ref = "bao://kv/a#x".into();
            e.slug = "a".into();
            e.value = b"alpha".to_vec();
            e.class = pb::ValueClass::Display as i32;
            e
        }],
        restore: Some(pb::RestoreSettings {
            display_mode: pb::DisplayMode::Values as i32,
            ..Default::default()
        }),
        policy: Some(pb::Policy {
            table_format: 1,
            ..Default::default()
        }),
        ..Default::default()
    };
    let e = RestoreEngine::from_snapshot(&snap).unwrap();
    assert_eq!(
        e.decide(&Caller::default(), At::Text, "bao://kv/a#x", D),
        Verdict::Resolve
    );
    assert_eq!(e.settings().display, DisplayMode::Values);
    assert_eq!(e.values().len(), 1);
    let mut bad = snap.clone();
    bad.policy.as_mut().unwrap().table_format = 9;
    assert!(matches!(
        RestoreEngine::from_snapshot(&bad),
        Err(RestoreError::Table(_))
    ));
    let mut bad = snap;
    bad.restore.as_mut().unwrap().reveal_credential_refs = vec!["x\\".into()];
    assert!(matches!(
        RestoreEngine::from_snapshot(&bad),
        Err(RestoreError::Settings(_))
    ));
}

#[test]
fn free_form_input_and_non_text_values() {
    let f = fixture(
        Settings::standard(),
        None,
        &[("a", D, "alpha"), ("bin", D, "x")],
    );
    let c = Caller::default();
    let out = f
        .engine
        .restore_tool_input(&c, "Bash", &format!("echo {}", ph("a")), &f.values);
    assert_eq!(out.text.unwrap(), "echo alpha");
    let mut vals = f.values.0;
    vals.get_mut(&ph("bin")).unwrap().2 = vec![0xff, 0xfe];
    let values = Values(vals);
    let args = format!("{{\"file_path\":\"{}\"}}", ph("bin"));
    let out = f.engine.restore_tool_input(&c, "Read", &args, &values);
    assert_eq!(out.text, None);
    assert_eq!(out.kept[0].1, KeepReason::Context(Refusal::NotText));
    let out = f.engine.restore_text(&c, &ph("bin"), &values);
    assert_eq!(out.kept[0].1, KeepReason::Context(Refusal::NotText));
    assert_eq!(KeepReason::NeedsEscaping.as_str(), "needs_escaping");
}

#[test]
fn block_policy_for_streams() {
    use scrim_redact::RestorePolicy as _;
    let f = fixture(Settings::standard(), None, &[("a", D, "alpha")]);
    let c = Caller::default();
    let meta = scrim_redact::EntryMeta {
        id: scrim_redact::EntryId(0),
        slug: scrim_redact::RefSlug::new("a").unwrap(),
        class: scrim_redact::ValueClass::Display,
    };
    assert!(f.engine.block_policy(&c, At::Text).allow(&meta));
    assert!(
        f.engine
            .block_policy(
                &c,
                At::Tool {
                    name: "Grep",
                    arguments: None
                }
            )
            .allow(&meta)
    );
    assert!(
        !f.engine
            .block_policy(
                &c,
                At::Tool {
                    name: "Bash",
                    arguments: None
                }
            )
            .allow(&meta)
    );
    assert!(
        !f.engine
            .block_policy(
                &c,
                At::Tool {
                    name: "nope",
                    arguments: None
                }
            )
            .allow(&meta)
    );
    let cred = scrim_redact::EntryMeta {
        class: scrim_redact::ValueClass::Credential,
        ..meta.clone()
    };
    assert!(!f.engine.block_policy(&c, At::Text).allow(&cred));
    let other = scrim_redact::EntryMeta {
        slug: scrim_redact::RefSlug::new("zz").unwrap(),
        ..meta
    };
    assert!(!f.engine.block_policy(&c, At::Text).allow(&other));
}
