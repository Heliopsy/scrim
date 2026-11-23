// SPDX-License-Identifier: AGPL-3.0-only

//! Narrower redaction for some sessions (`Snapshot.redaction_scopes`).
//!
//! The control plane writes scopes only while the weakening setting
//! `redaction.limit-to-agent-identity` is on (agent-identity spec, "Redaction coverage is separate
//! from use"). Each scope names an agent's sessions and the references whose store refused that
//! agent's own identity; the data plane builds one more redaction core without those entries and
//! hands its redactor and guard to the LLM proxy for requests that prove they hold one of those
//! sessions' tokens. Everything else (a bare session id, another session's token, a peer, a
//! Kubernetes caller, the tool proxy, captures) keeps the core built from the whole dictionary.
//!
//! The proof is the session token itself, checked against the token of that session among the
//! dictionary's values of store [`SESSION_STORE`] (which the control plane holds there so that an
//! agent printing its own token never sends it anywhere). Only those entries count: an agent can
//! write secrets into a store that is redacted, so a token-shaped value elsewhere proves nothing.
//! The check proves possession of the token, not the process tree it was minted for, which the
//! control plane checks on an ask; a process that stole a session's token gets that session's
//! narrower redaction. This is part of what the setting weakens.

use std::collections::{HashMap, HashSet};
use std::fmt;

use scrim_llm::ScopedRedaction;
use scrim_proto::v1;
use scrim_toolproxy::{SessionVerifier, parse_session_token};

use crate::identity::Identity;

/// The store whose values are the session tokens the control plane minted.
pub const SESSION_STORE: &str = "scrim-sessions";
/// The reference of those values.
pub const SESSION_REF: &str = "store:scrim-sessions";

/// One session's narrower redaction.
struct Scope {
    verifier: SessionVerifier,
    redaction: ScopedRedaction,
}

/// The scopes of one snapshot, by session id.
#[derive(Default)]
pub struct Scopes {
    by_session: HashMap<String, Scope>,
    agents: Vec<String>,
}

impl fmt::Debug for Scopes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scopes")
            .field("sessions", &self.by_session.len())
            .field("agents", &self.agents)
            .finish()
    }
}

impl Scopes {
    /// Builds the scopes of `snap`. `build` turns the set of exempt references into a redactor
    /// and guard over every other entry of the dictionary. A scope with no exempt reference, or
    /// whose sessions have no token in the dictionary, is dropped.
    pub fn build<E>(
        snap: &v1::Snapshot,
        mut build: impl FnMut(&HashSet<&str>) -> Result<ScopedRedaction, E>,
    ) -> Result<Self, E> {
        let mut out = Self::default();
        if snap.redaction_scopes.is_empty() {
            return Ok(out);
        }
        let mut tokens: HashMap<String, SessionVerifier> = HashMap::new();
        for v in &snap.values {
            if v.store == SESSION_STORE
                && v.r#ref == SESSION_REF
                && let Some((id, ver)) = parse_session_token(&v.value)
            {
                tokens.insert(id, ver);
            }
        }
        for s in &snap.redaction_scopes {
            let exempt: HashSet<&str> = s
                .exempt_refs
                .iter()
                .map(String::as_str)
                .filter(|r| !r.is_empty())
                .collect();
            let sessions: Vec<(&String, &SessionVerifier)> = s
                .sessions
                .iter()
                .filter_map(|id| tokens.get(id).map(|v| (id, v)))
                .collect();
            if exempt.is_empty() || sessions.is_empty() {
                continue;
            }
            let redaction = build(&exempt)?;
            for (id, ver) in sessions {
                out.by_session.insert(
                    id.clone(),
                    Scope {
                        verifier: ver.clone(),
                        redaction: redaction.clone(),
                    },
                );
            }
            out.agents.push(s.agent.clone());
        }
        Ok(out)
    }

    /// Whether no session has a scope.
    pub fn is_empty(&self) -> bool {
        self.by_session.is_empty()
    }

    /// How many sessions have a scope.
    pub fn sessions(&self) -> usize {
        self.by_session.len()
    }

    /// The narrower redaction of the session `who` proved it holds the token of, if that session
    /// has one.
    pub fn for_caller(&self, who: &Identity) -> Option<ScopedRedaction> {
        let (Some(id), Some(ver)) = (who.session.as_deref(), who.verifier.as_ref()) else {
            return None;
        };
        let s = self.by_session.get(id)?;
        same(s.verifier.as_bytes(), ver.as_bytes()).then(|| s.redaction.clone())
    }
}

/// Constant-time equality of two verifiers.
fn same(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
