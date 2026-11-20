// SPDX-License-Identifier: AGPL-3.0-only

//! The request context a decision table is evaluated against.
//!
//! Field names and meanings are the rule language's (`docs/policy.md` "What a rule can see"):
//! fields that do not apply are empty strings, and `agent.known` is derived from `agent.kind`
//! (empty kind means an unknown caller). [`Request::unknown`] additionally marks fields the
//! caller cannot fill in at all, for example the agent identity at a site that does not carry
//! it; a condition on an unknown field is unknown, so a rule that depends on it never decides
//! locally (see [`crate::Table::evaluate`]).

use std::collections::HashMap;

use scrim_proto::v1 as pb;

/// A request attribute the decision table can test.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Field {
    /// `op`: the operation (`inject`, `restore`, `store.read`, ...).
    Op,
    /// `provider`: the model provider.
    Provider,
    /// `agent.id`.
    AgentId,
    /// `agent.kind`: `peer`, `session`, `k8s`, `mtls`, or empty when unknown.
    AgentKind,
    /// `agent.known`: `"true"` or `"false"`, derived from `agent.kind`.
    AgentKnown,
    /// `agent.session`.
    AgentSession,
    /// `agent.labels` (map).
    AgentLabels,
    /// `secret.ref`: canonical reference string.
    SecretRef,
    /// `secret.name`: catalog name.
    SecretName,
    /// `secret.store`: store instance name.
    SecretStore,
    /// `secret.class`: catalog class.
    SecretClass,
    /// `secret.labels` (map).
    SecretLabels,
    /// `dest.host`.
    DestHost,
    /// `dest.method`.
    DestMethod,
    /// `dest.path`.
    DestPath,
    /// `tool.name`.
    ToolName,
    /// `tool.command`.
    ToolCommand,
}

impl Field {
    /// Every field, in wire order.
    pub const ALL: [Field; 17] = [
        Field::Op,
        Field::Provider,
        Field::AgentId,
        Field::AgentKind,
        Field::AgentKnown,
        Field::AgentSession,
        Field::AgentLabels,
        Field::SecretRef,
        Field::SecretName,
        Field::SecretStore,
        Field::SecretClass,
        Field::SecretLabels,
        Field::DestHost,
        Field::DestMethod,
        Field::DestPath,
        Field::ToolName,
        Field::ToolCommand,
    ];

    /// The dotted name used in rules and on the wire.
    pub fn name(self) -> &'static str {
        match self {
            Field::Op => "op",
            Field::Provider => "provider",
            Field::AgentId => "agent.id",
            Field::AgentKind => "agent.kind",
            Field::AgentKnown => "agent.known",
            Field::AgentSession => "agent.session",
            Field::AgentLabels => "agent.labels",
            Field::SecretRef => "secret.ref",
            Field::SecretName => "secret.name",
            Field::SecretStore => "secret.store",
            Field::SecretClass => "secret.class",
            Field::SecretLabels => "secret.labels",
            Field::DestHost => "dest.host",
            Field::DestMethod => "dest.method",
            Field::DestPath => "dest.path",
            Field::ToolName => "tool.name",
            Field::ToolCommand => "tool.command",
        }
    }

    /// Parses a dotted field name.
    pub fn from_name(name: &str) -> Option<Field> {
        Field::ALL.into_iter().find(|f| f.name() == name)
    }

    /// Whether the field is a string map (`agent.labels`, `secret.labels`).
    pub fn is_map(self) -> bool {
        matches!(self, Field::AgentLabels | Field::SecretLabels)
    }

    const fn bit(self) -> u32 {
        1 << (self as u8)
    }
}

/// A set of [`Field`]s.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct FieldSet(u32);

impl FieldSet {
    /// No fields.
    pub const EMPTY: FieldSet = FieldSet(0);

    /// The agent identity: `agent.id`, `agent.kind`, `agent.known`, `agent.session`,
    /// `agent.labels`.
    pub const AGENT: FieldSet = FieldSet(
        Field::AgentId.bit()
            | Field::AgentKind.bit()
            | Field::AgentKnown.bit()
            | Field::AgentSession.bit()
            | Field::AgentLabels.bit(),
    );

    /// Adds `f`.
    #[must_use]
    pub const fn with(self, f: Field) -> FieldSet {
        FieldSet(self.0 | f.bit())
    }

    /// Whether `f` is in the set.
    pub const fn contains(self, f: Field) -> bool {
        self.0 & f.bit() != 0
    }

    /// Whether the set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl std::fmt::Debug for FieldSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_set()
            .entries(
                Field::ALL
                    .iter()
                    .filter(|x| self.contains(**x))
                    .map(|x| x.name()),
            )
            .finish()
    }
}

/// `agent` in a rule.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Agent {
    /// Stable identity key, for example `k8s:agents/reviewer`.
    pub id: String,
    /// How the identity was established; empty for unknown callers.
    pub kind: String,
    /// The scrim session id, if any.
    pub session: String,
    /// Identity attributes.
    pub labels: HashMap<String, String>,
}

impl Agent {
    /// `agent.known`: the caller's identity was established.
    pub fn known(&self) -> bool {
        !self.kind.is_empty()
    }
}

/// `secret` in a rule.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Secret {
    /// Canonical reference, `bao://kv/agents/github`; empty when no secret is involved.
    pub reference: String,
    /// Catalog name.
    pub name: String,
    /// Store instance name.
    pub store: String,
    /// Catalog class (`credential`, `display`).
    pub class: String,
    /// Catalog or store metadata labels.
    pub labels: HashMap<String, String>,
}

/// `dest` in a rule.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Dest {
    /// Destination host.
    pub host: String,
    /// HTTP method.
    pub method: String,
    /// Request path.
    pub path: String,
}

/// `tool` in a rule.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tool {
    /// Tool name as the model called it.
    pub name: String,
    /// Command, for shell tools and the exec broker.
    pub command: String,
}

/// Everything a decision-table rule can see except `now`, which is always residual.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Request {
    /// `op`.
    pub op: String,
    /// `agent`.
    pub agent: Agent,
    /// `secret`.
    pub secret: Secret,
    /// `provider`.
    pub provider: String,
    /// `dest`.
    pub dest: Dest,
    /// `tool`.
    pub tool: Tool,
    /// Fields whose value the caller does not know. Empty for ordinary requests.
    pub unknown: FieldSet,
}

impl Request {
    /// The scalar value of `f`; empty for map fields.
    pub fn scalar(&self, f: Field) -> &str {
        match f {
            Field::Op => &self.op,
            Field::Provider => &self.provider,
            Field::AgentId => &self.agent.id,
            Field::AgentKind => &self.agent.kind,
            Field::AgentKnown => {
                if self.agent.known() {
                    "true"
                } else {
                    "false"
                }
            }
            Field::AgentSession => &self.agent.session,
            Field::SecretRef => &self.secret.reference,
            Field::SecretName => &self.secret.name,
            Field::SecretStore => &self.secret.store,
            Field::SecretClass => &self.secret.class,
            Field::DestHost => &self.dest.host,
            Field::DestMethod => &self.dest.method,
            Field::DestPath => &self.dest.path,
            Field::ToolName => &self.tool.name,
            Field::ToolCommand => &self.tool.command,
            Field::AgentLabels | Field::SecretLabels => "",
        }
    }

    /// The map value of `f`; `None` for scalar fields.
    pub fn map(&self, f: Field) -> Option<&HashMap<String, String>> {
        match f {
            Field::AgentLabels => Some(&self.agent.labels),
            Field::SecretLabels => Some(&self.secret.labels),
            _ => None,
        }
    }

    /// The wire form, as sent in an `AskRequest` so the control plane evaluates the same
    /// request. Unknown fields are sent empty.
    pub fn to_proto(&self) -> pb::PolicyRequest {
        let s = |f: Field, v: &str| {
            if self.unknown.contains(f) {
                String::new()
            } else {
                v.to_owned()
            }
        };
        let m = |f: Field, v: &HashMap<String, String>| {
            if self.unknown.contains(f) {
                HashMap::new()
            } else {
                v.clone()
            }
        };
        pb::PolicyRequest {
            agent_id: s(Field::AgentId, &self.agent.id),
            action: s(Field::Op, &self.op),
            r#ref: s(Field::SecretRef, &self.secret.reference),
            name: s(Field::SecretName, &self.secret.name),
            provider: s(Field::Provider, &self.provider),
            host: s(Field::DestHost, &self.dest.host),
            method: s(Field::DestMethod, &self.dest.method),
            path: s(Field::DestPath, &self.dest.path),
            tool: s(Field::ToolName, &self.tool.name),
            agent_kind: s(Field::AgentKind, &self.agent.kind),
            session: s(Field::AgentSession, &self.agent.session),
            agent_labels: m(Field::AgentLabels, &self.agent.labels),
            store: s(Field::SecretStore, &self.secret.store),
            secret_class: s(Field::SecretClass, &self.secret.class),
            secret_labels: m(Field::SecretLabels, &self.secret.labels),
            command: s(Field::ToolCommand, &self.tool.command),
        }
    }

    /// Builds a request from its wire form (every field known).
    pub fn from_proto(p: &pb::PolicyRequest) -> Request {
        Request {
            op: p.action.clone(),
            agent: Agent {
                id: p.agent_id.clone(),
                kind: p.agent_kind.clone(),
                session: p.session.clone(),
                labels: p.agent_labels.clone(),
            },
            secret: Secret {
                reference: p.r#ref.clone(),
                name: p.name.clone(),
                store: p.store.clone(),
                class: p.secret_class.clone(),
                labels: p.secret_labels.clone(),
            },
            provider: p.provider.clone(),
            dest: Dest {
                host: p.host.clone(),
                method: p.method.clone(),
                path: p.path.clone(),
            },
            tool: Tool {
                name: p.tool.clone(),
                command: p.command.clone(),
            },
            unknown: FieldSet::EMPTY,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_names_round_trip() {
        for f in Field::ALL {
            assert_eq!(Field::from_name(f.name()), Some(f));
        }
        assert_eq!(Field::from_name("agent.nmae"), None);
        assert_eq!(Field::from_name("now"), None);
        let maps: Vec<_> = Field::ALL.into_iter().filter(|f| f.is_map()).collect();
        assert_eq!(maps, vec![Field::AgentLabels, Field::SecretLabels]);
    }

    #[test]
    fn known_follows_kind() {
        let mut r = Request::default();
        assert_eq!(r.scalar(Field::AgentKnown), "false");
        r.agent.kind = "peer".into();
        assert_eq!(r.scalar(Field::AgentKnown), "true");
    }

    #[test]
    fn proto_round_trip_and_unknown_fields_are_blank() {
        let mut r = Request {
            op: "restore".into(),
            provider: "anthropic".into(),
            ..Request::default()
        };
        r.agent.id = "a".into();
        r.agent.kind = "session".into();
        r.agent.labels.insert("team".into(), "infra".into());
        r.secret.reference = "bao://kv/x".into();
        r.tool.name = "Bash".into();
        let back = Request::from_proto(&r.to_proto());
        assert_eq!(back, r);
        r.unknown = FieldSet::AGENT;
        let p = r.to_proto();
        assert!(p.agent_id.is_empty() && p.agent_kind.is_empty() && p.agent_labels.is_empty());
        assert_eq!(p.r#ref, "bao://kv/x");
        assert_eq!(format!("{:?}", FieldSet::EMPTY.with(Field::Op)), "{\"op\"}");
    }
}
