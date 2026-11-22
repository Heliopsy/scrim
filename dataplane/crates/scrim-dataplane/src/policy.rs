// SPDX-License-Identifier: AGPL-3.0-only

//! Restore, injection and forwarding decisions (design D5, D7), from `scrim-policy`.
//!
//! One [`Decisions`] is built per snapshot, from `Snapshot.policy` (the decision table,
//! [`Table`]) and `Snapshot.restore` with the value dictionary's metadata (the restore policy,
//! [`RestoreEngine`]), and published in the bundle with everything else. It decides:
//!
//! | Operation | Request | Local outcome |
//! | --- | --- | --- |
//! | `inject` (tool proxy, per credential) | `secret.*`, `dest.host`, `dest.method`, `dest.path`, agent | the table's: allow, deny, or ask the control plane |
//! | `llm.forward` (LLM proxy, per request) | `provider`, agent | deny and ask rules only: the default effect does not stop provider traffic, which is always redacted |
//! | `restore` (LLM proxy, per placeholder) | `tool.name`, `secret.*`, agent, `provider` | the tool policy, which rules can only take away (`scrim-policy`) |
//!
//! "Ask the control plane" goes over the `Asks` stream ([`crate::engine::Engine::ask`]): the
//! operation is held until the answer, at most `Policy.ask_timeout_millis` (default
//! [`DEFAULT_ASK_TIMEOUT`]), and anything but an allow answer in time denies, including a
//! timeout and a control plane that is not connected. Grants are never cached: every request
//! that needs one asks again (design D7). A restore cannot be held, so a rule that would ask
//! keeps the placeholder.
//!
//! Break-glass (`Policy.break_glass`) denies every injection and restore and sends no ask,
//! while redaction and forwarding continue. The tool proxy's credentials also lose their
//! bindings, so nothing is injected even before the table is consulted.
//!
//! Identity comes from the transport ([`crate::identity`]).

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use scrim_llm::{Admission, RequestGate, RequestInfo};
use scrim_policy::{
    AskReason, Caller, DecidedBy, Effect, Field, LlmRestorePolicy, Outcome, Request, RestoreEngine,
    Settings, Table, ValueIndex,
};
use scrim_proto::v1;
use scrim_toolproxy::{InjectionDecision, InjectionPolicy, InjectionRequest};

use crate::asks::Broker;
use crate::events::Bus;
use crate::identity::Identity;

/// The decision engine this build runs, reported as `StatusResponse.policy_engine`: the
/// decision table of format 1.
pub const ENGINE: &str = "table/v1";

const _: () = assert!(
    scrim_policy::TABLE_FORMAT == 1,
    "ENGINE names the table format"
);

/// How long an ask waits when the snapshot does not say (`approvals.timeout`'s default).
pub const DEFAULT_ASK_TIMEOUT: Duration = Duration::from_secs(120);

/// Where decisions send asks and events. Shared by every bundle.
#[derive(Clone, Debug)]
pub struct Hooks {
    /// The ask broker.
    pub asks: Arc<Broker>,
    /// The event bus.
    pub events: Arc<Bus>,
}

impl Default for Hooks {
    fn default() -> Self {
        Self {
            asks: Arc::new(Broker::default()),
            events: Arc::new(Bus::default()),
        }
    }
}

/// Why the policy inputs of a snapshot were rejected.
#[derive(Debug)]
pub struct PolicyError(pub String);

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The outcome of one decision that may have gone to the control plane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    /// Whether the operation may proceed.
    pub allowed: bool,
    /// The rule that decided (or asked), `default`, or empty under break-glass.
    pub rule: String,
    /// Why, for the refusal message and audit. Never a value.
    pub reason: String,
    /// Whether the control plane was asked.
    pub asked: bool,
}

/// The decisions of one snapshot.
pub struct Decisions {
    version: u64,
    table: Arc<Table>,
    restore: Arc<RestoreEngine>,
    ask_timeout: Duration,
    hooks: Hooks,
}

impl fmt::Debug for Decisions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decisions")
            .field("version", &self.version)
            .field("table", &self.table)
            .field("ask_timeout", &self.ask_timeout)
            .finish_non_exhaustive()
    }
}

/// `policy` as the table compiler reads it: a policy with nothing in it but the default and
/// break-glass (what a control plane without rules sends, `table_format` 0) is an empty table
/// of the current format.
pub fn normalise(policy: &mut v1::Policy) {
    if policy.table_format == 0
        && policy.table.is_empty()
        && policy.rules.is_empty()
        && policy.engine.is_empty()
        && policy.compiled.is_empty()
    {
        policy.table_format = scrim_policy::TABLE_FORMAT;
    }
}

impl Decisions {
    /// Builds the decisions of snapshot `version`: the table from `policy` (normalised), the
    /// restore engine from `restore` and the value dictionary's metadata (entry `i` of `values`
    /// is entry id `i` of the redaction core, with the slug the core uses).
    pub fn new(
        version: u64,
        policy: &v1::Policy,
        restore: Option<&v1::RestoreSettings>,
        values: ValueIndex,
        hooks: Hooks,
    ) -> Result<Self, PolicyError> {
        let table =
            Arc::new(Table::from_proto(policy).map_err(|e| PolicyError(format!("policy: {e}")))?);
        let settings = Settings::from_proto(restore).map_err(|e| PolicyError(e.to_string()))?;
        let restore = Arc::new(RestoreEngine::new(
            settings,
            Some(Arc::clone(&table)),
            values,
        ));
        let ask_timeout = match policy.ask_timeout_millis {
            0 => DEFAULT_ASK_TIMEOUT,
            ms => Duration::from_millis(ms),
        };
        Ok(Self {
            version,
            table,
            restore,
            ask_timeout,
            hooks,
        })
    }

    /// Whether break-glass deny-all is engaged: no restore, no injection, no ask.
    pub fn break_glass(&self) -> bool {
        self.table.break_glass()
    }

    /// The decision table.
    pub fn table(&self) -> &Table {
        &self.table
    }

    /// The restore engine.
    pub fn restore(&self) -> &Arc<RestoreEngine> {
        &self.restore
    }

    /// How long an ask waits.
    pub fn ask_timeout(&self) -> Duration {
        self.ask_timeout
    }

    /// The restore policy for a caller, as scrim-llm takes it.
    pub fn restore_policy(&self, caller: Caller) -> LlmRestorePolicy {
        LlmRestorePolicy::new(Arc::clone(&self.restore), caller)
    }

    /// The request gate the LLM proxy runs per request.
    pub fn llm_gate(self: &Arc<Self>) -> Arc<dyn RequestGate> {
        Arc::new(LlmGate(Arc::clone(self)))
    }

    /// The injection policy the tool proxy runs per credential and request.
    pub fn injection_policy(self: &Arc<Self>) -> Arc<dyn InjectionPolicy> {
        Arc::new(ToolGate(Arc::clone(self)))
    }

    /// Decides `req` with the full table: allow and deny locally, ask the control plane
    /// otherwise.
    pub async fn decide(&self, req: &Request, who: &Identity, target: &str) -> Verdict {
        let d = self.table.evaluate(req);
        self.settle(req, who, target, d.outcome, d.ask, d.by).await
    }

    /// Decides an `llm.forward` request: deny and ask rules apply, the default effect and
    /// residual allow rules (which can only allow) do not, and break-glass does not stop
    /// forwarding (only restore and injection).
    pub async fn decide_forward(&self, req: &Request, who: &Identity, target: &str) -> Verdict {
        if self.break_glass() {
            return Verdict {
                allowed: true,
                rule: String::new(),
                reason: String::new(),
                asked: false,
            };
        }
        let d = self.table.evaluate(req);
        let allow_anyway = match (d.by, d.ask) {
            (DecidedBy::Default, _) => true,
            (DecidedBy::Rule(id), Some(AskReason::Residual)) => {
                self.table.rule(id).effect == Effect::Allow
            }
            _ => false,
        };
        if allow_anyway {
            return Verdict {
                allowed: true,
                rule: self.table.rule_name(d.by).to_owned(),
                reason: String::new(),
                asked: false,
            };
        }
        self.settle(req, who, target, d.outcome, d.ask, d.by).await
    }

    async fn settle(
        &self,
        req: &Request,
        who: &Identity,
        target: &str,
        outcome: Outcome,
        ask: Option<AskReason>,
        by: DecidedBy,
    ) -> Verdict {
        let rule = self.table.rule_name(by).to_owned();
        let rule_reason = self.table.reason(by).to_owned();
        let v = match outcome {
            Outcome::Allow => Verdict {
                allowed: true,
                rule,
                reason: rule_reason,
                asked: false,
            },
            Outcome::Deny => Verdict {
                allowed: false,
                reason: if by == DecidedBy::BreakGlass {
                    "break-glass deny-all is engaged".to_owned()
                } else if rule_reason.is_empty() {
                    format!("rule `{rule}`")
                } else {
                    format!("rule `{rule}`: {rule_reason}")
                },
                rule,
                asked: false,
            },
            Outcome::ControlPlane => {
                let why = match ask {
                    Some(AskReason::Residual) => "needs the control plane's rules",
                    Some(AskReason::SideEffect) => "grants on approval",
                    _ => "asks for approval",
                };
                let reason = if rule_reason.is_empty() {
                    why.to_owned()
                } else {
                    rule_reason
                };
                let a = self
                    .hooks
                    .asks
                    .ask_proven(
                        req.to_proto(),
                        who.ask_caller(),
                        who.verifier.as_ref(),
                        &rule,
                        &reason,
                        self.ask_timeout,
                    )
                    .await;
                self.emit_answer(req, who, target, &rule, &a);
                Verdict {
                    allowed: a.allowed,
                    reason: if a.allowed {
                        a.reason
                    } else if a.reason.is_empty() {
                        format!("rule `{rule}`: not approved")
                    } else {
                        format!("rule `{rule}`: {}", a.reason)
                    },
                    rule,
                    asked: true,
                }
            }
        };
        if !v.asked {
            self.emit_local(req, who, target, &v);
        }
        v
    }

    fn event(&self, req: &Request, who: &Identity, target: &str, rule: &str) -> v1::Event {
        let mut attrs = std::collections::HashMap::new();
        attrs.insert("op".to_owned(), req.op.clone());
        if let Some(s) = &who.session {
            attrs.insert("session".to_owned(), s.clone());
        }
        if let Some(p) = who.peer {
            attrs.insert("peer_uid".to_owned(), p.uid.to_string());
        }
        v1::Event {
            kind: v1::EventKind::Decision.into(),
            provider: req.provider.clone(),
            r#ref: req.secret.reference.clone(),
            rule: rule.to_owned(),
            target: target.to_owned(),
            snapshot_version: self.version,
            attrs,
            ..Default::default()
        }
    }

    fn emit_local(&self, req: &Request, who: &Identity, target: &str, v: &Verdict) {
        let mut ev = self.event(req, who, target, &v.rule);
        ev.effect = if v.allowed {
            v1::Effect::Allow
        } else {
            v1::Effect::Deny
        }
        .into();
        ev.reason.clone_from(&v.reason);
        ev.attrs.insert("decided".into(), "data_plane".into());
        self.hooks.events.emit(ev);
    }

    fn emit_answer(
        &self,
        req: &Request,
        who: &Identity,
        target: &str,
        rule: &str,
        a: &crate::asks::Answer,
    ) {
        let mut ev = self.event(req, who, target, rule);
        ev.effect = if a.allowed {
            v1::Effect::Allow
        } else {
            v1::Effect::Deny
        }
        .into();
        ev.reason.clone_from(&a.reason);
        ev.attrs.insert("decided".into(), "control_plane".into());
        if !a.grant_id.is_empty() {
            ev.attrs.insert("grant_id".into(), a.grant_id.clone());
        }
        self.hooks.events.emit(ev);
    }
}

/// The LLM proxy's per-request gate: `llm.forward` for the caller, then the restore policy
/// bound to that caller.
struct LlmGate(Arc<Decisions>);

impl RequestGate for LlmGate {
    fn admit<'a>(
        &'a self,
        info: RequestInfo<'a>,
    ) -> Pin<Box<dyn Future<Output = Admission> + Send + 'a>> {
        let who = Identity::of_llm(info.headers, info.extensions);
        Box::pin(async move {
            let d = &self.0;
            let mut req = Request {
                op: "llm.forward".into(),
                provider: info.provider.to_owned(),
                ..Request::default()
            };
            who.apply(&mut req);
            let v = d.decide_forward(&req, &who, info.route).await;
            if !v.allowed {
                return Admission::Deny { detail: v.reason };
            }
            Admission::Forward {
                policy: Arc::new(d.restore_policy(who.caller(Some(info.provider)))),
            }
        })
    }
}

/// The tool proxy's per-credential injection policy: `inject` with the full table.
struct ToolGate(Arc<Decisions>);

impl InjectionPolicy for ToolGate {
    fn decide<'a>(
        &'a self,
        r: &'a InjectionRequest,
        extensions: &'a http::Extensions,
    ) -> Pin<Box<dyn Future<Output = InjectionDecision> + Send + 'a>> {
        let who = Identity::of_tool(extensions);
        Box::pin(async move {
            let d = &self.0;
            let mut req = Request {
                op: "inject".into(),
                ..Request::default()
            };
            req.secret.reference.clone_from(&r.reference);
            let info = d.restore.values().lookup(&r.reference);
            if let Some(info) = info {
                req.secret.name = info.name.to_string();
                req.secret.store = info.store.to_string();
                info.class.as_str().clone_into(&mut req.secret.class);
                if let Some(l) = info.labels.as_ref().filter(|l| !l.is_empty()) {
                    req.secret.labels.clone_from(l);
                }
            }
            req.dest.host.clone_from(&r.destination.host);
            req.dest.method.clone_from(&r.method);
            req.dest.path.clone_from(&r.path);
            who.apply(&mut req);
            if info.is_none_or(|i| i.labels.is_none()) {
                // No labels from the control plane: a rule on them could match.
                req.unknown = req.unknown.with(Field::SecretLabels);
            }
            let v = d.decide(&req, &who, &r.destination.to_string()).await;
            if v.allowed {
                InjectionDecision::Allow
            } else {
                InjectionDecision::Deny(v.reason)
            }
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn cond(field: &str, value: &str) -> v1::Condition {
        v1::Condition {
            field: field.into(),
            op: v1::ConditionOp::In.into(),
            values: vec![value.into()],
            ..Default::default()
        }
    }

    fn rule(name: &str, effect: v1::Effect, conditions: Vec<v1::Condition>) -> v1::TableRule {
        v1::TableRule {
            name: name.into(),
            effect: effect.into(),
            clauses: vec![v1::Clause {
                conditions,
                residual: false,
            }],
            ..Default::default()
        }
    }

    fn decisions(policy: v1::Policy) -> Arc<Decisions> {
        let mut policy = policy;
        normalise(&mut policy);
        Arc::new(Decisions::new(1, &policy, None, ValueIndex::new(), Hooks::default()).unwrap())
    }

    fn inject(host: &str) -> Request {
        let mut r = Request {
            op: "inject".into(),
            ..Request::default()
        };
        r.dest.host = host.into();
        r
    }

    #[test]
    fn normalises_an_empty_policy_and_rejects_legacy_forms() {
        let d = decisions(v1::Policy {
            default_effect: v1::Effect::Deny.into(),
            ..Default::default()
        });
        assert_eq!(d.table().rules().len(), 0);
        assert_eq!(d.ask_timeout(), DEFAULT_ASK_TIMEOUT);
        let mut legacy = v1::Policy {
            rules: vec![v1::PolicyRule::default()],
            ..Default::default()
        };
        normalise(&mut legacy);
        assert!(Decisions::new(1, &legacy, None, ValueIndex::new(), Hooks::default()).is_err());
    }

    #[tokio::test]
    async fn local_allow_deny_and_ask_without_control_plane() {
        let anon_rule = rule(
            "anon",
            v1::Effect::Deny,
            vec![cond("agent.known", "false"), cond("dest.host", "anon.test")],
        );
        let d = decisions(v1::Policy {
            default_effect: v1::Effect::Deny.into(),
            table_format: 1,
            ask_timeout_millis: 50,
            table: vec![
                rule("ok", v1::Effect::Allow, vec![cond("dest.host", "ok.test")]),
                rule("no", v1::Effect::Deny, vec![cond("dest.host", "no.test")]),
                rule("ask", v1::Effect::Ask, vec![cond("dest.host", "ask.test")]),
                anon_rule,
            ],
            ..Default::default()
        });
        assert_eq!(d.ask_timeout(), Duration::from_millis(50));
        let anon = Identity::default();
        let v = d.decide(&inject("ok.test"), &anon, "t").await;
        assert!(v.allowed && v.rule == "ok" && !v.asked);
        let v = d.decide(&inject("no.test"), &anon, "t").await;
        assert!(!v.allowed && v.reason.contains("`no`"));
        let v = d.decide(&inject("elsewhere.test"), &anon, "t").await;
        assert!(!v.allowed && v.rule == "default");
        // No control plane attached: the ask denies at once.
        let v = d.decide(&inject("ask.test"), &anon, "t").await;
        assert!(!v.allowed && v.asked);
        // An unknown caller is decided locally; a session the data plane cannot place asks.
        let mut r = inject("anon.test");
        anon.apply(&mut r);
        assert!(!d.decide(&r, &anon, "t").await.asked);
        let sess = Identity {
            session: Some("s1".into()),
            peer: None,
            verifier: None,
            kubernetes_token: None,
        };
        sess.apply(&mut r);
        assert!(d.decide(&r, &sess, "t").await.asked);
    }

    #[tokio::test]
    async fn inject_rules_see_value_labels() {
        use scrim_policy::{ValueClass, ValueInfo, escape::ValueTraits};
        use scrim_toolproxy::{Destination, Scheme};
        let mut prod = cond("secret.labels", "");
        prod.key = "vaultwarden.collection.Prod".into();
        prod.op = v1::ConditionOp::HasKey.into();
        prod.values = vec![];
        let mut policy = v1::Policy {
            default_effect: v1::Effect::Deny.into(),
            table_format: 1,
            table: vec![
                rule("prod-collection", v1::Effect::Deny, vec![prod]),
                rule("inject", v1::Effect::Allow, vec![cond("op", "inject")]),
            ],
            ..Default::default()
        };
        normalise(&mut policy);
        let mut ix = ValueIndex::new();
        for (slug, labels) in [
            (
                "prod",
                vec![
                    ("store.name", "vw"),
                    ("vaultwarden.collection.Prod", "true"),
                ],
            ),
            ("dev", vec![("store.name", "vw")]),
            ("old", vec![]),
        ] {
            ix.push(ValueInfo {
                reference: format!("vw://{slug}#v").as_str().into(),
                slug: slug.into(),
                class: ValueClass::Credential,
                name: "".into(),
                store: "vw".into(),
                traits: ValueTraits::of(b"secret-bytes"),
                labels: (!labels.is_empty()).then(|| {
                    Arc::new(
                        labels
                            .into_iter()
                            .map(|(k, v)| (k.to_owned(), v.to_owned()))
                            .collect(),
                    )
                }),
            });
        }
        let d = Arc::new(Decisions::new(1, &policy, None, ix, Hooks::default()).unwrap());
        let gate = d.injection_policy();
        let ext = http::Extensions::new();
        let decide = |slug: &str| InjectionRequest {
            credential: slug.into(),
            reference: format!("vw://{slug}#v"),
            destination: Destination::new(Scheme::Https, "api.test", 443),
            method: "GET".into(),
            path: "/".into(),
        };
        assert_eq!(
            gate.decide(&decide("dev"), &ext).await,
            InjectionDecision::Allow
        );
        match gate.decide(&decide("prod"), &ext).await {
            InjectionDecision::Deny(why) => assert!(why.contains("prod-collection"), "{why}"),
            InjectionDecision::Allow => panic!("a prod credential was injected"),
        }
        // Without labels from the control plane the rule could match: it asks, and with no
        // control plane attached the ask denies.
        assert!(matches!(
            gate.decide(&decide("old"), &ext).await,
            InjectionDecision::Deny(_)
        ));
    }

    #[tokio::test]
    async fn forward_ignores_the_default_and_break_glass() {
        let fwd = Request {
            op: "llm.forward".into(),
            provider: "openai".into(),
            ..Request::default()
        };
        let d = decisions(v1::Policy {
            default_effect: v1::Effect::Deny.into(),
            ..Default::default()
        });
        assert!(
            d.decide_forward(&fwd, &Identity::default(), "r")
                .await
                .allowed
        );
        let d = decisions(v1::Policy {
            table_format: 1,
            table: vec![rule(
                "no-openai",
                v1::Effect::Deny,
                vec![cond("provider", "openai")],
            )],
            ..Default::default()
        });
        let v = d.decide_forward(&fwd, &Identity::default(), "r").await;
        assert!(!v.allowed && v.rule == "no-openai");
        let d = decisions(v1::Policy {
            break_glass: true,
            ..Default::default()
        });
        assert!(
            d.decide_forward(&fwd, &Identity::default(), "r")
                .await
                .allowed
        );
        assert!(
            !d.decide(&inject("x"), &Identity::default(), "r")
                .await
                .allowed
        );
    }
}
