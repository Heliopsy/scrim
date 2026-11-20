// SPDX-License-Identifier: AGPL-3.0-only

//! Who sent a request, as far as the transport tells (specs `agent-identity`, "Identity is not
//! taken from request content").
//!
//! The data plane holds no session tokens and no mapping from Unix users to agents, so it can
//! establish what a request carries but not whose it is:
//!
//! | Transport | What the data plane reads |
//! | --- | --- |
//! | Unix socket listener | the kernel's peer credentials (uid, gid, pid) |
//! | forward proxy | the session named in `Proxy-Authorization: Basic` (user name; the password is never read) |
//! | base-URL listener | the session named in the `x-scrim-session` header (stripped before forwarding) |
//!
//! A request that carries none of these is an unknown caller: `agent.known` is false, decided
//! locally, so a rule such as `deny when !agent.known` refuses it without a round trip. A
//! request that carries any of them is one the data plane cannot place: its agent fields are
//! unknown to the decision table, a rule that depends on them goes to the control plane, and
//! the ask carries what the transport said ([`v1::AskCaller`]) for the control plane to resolve
//! and verify. A restore cannot wait for an answer, so a restore rule on the agent keeps the
//! placeholder for such a request.

use scrim_llm::server::UnixPeer;
use scrim_policy::{Agent, Caller, FieldSet, Request};
use scrim_proto::v1;
use scrim_toolproxy::{ClientInfo, is_session_id};

/// What one request's transport said about its sender.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Identity {
    /// The session the request names. A claim, not verified here.
    pub session: Option<String>,
    /// Unix socket peer credentials.
    pub peer: Option<UnixPeer>,
}

impl Identity {
    /// The identity of a request to the LLM proxy: the Unix peer of a socket listener, the
    /// session of the forward-proxy connection it was tunnelled through, else the
    /// `x-scrim-session` header.
    pub fn of_llm(headers: &http::HeaderMap, extensions: &http::Extensions) -> Self {
        let session = extensions
            .get::<ClientInfo>()
            .and_then(|c| c.session.clone())
            .or_else(|| {
                headers
                    .get(scrim_llm::SESSION_HEADER)
                    .map(http::HeaderValue::as_bytes)
                    .filter(|s| is_session_id(s))
                    .map(|s| String::from_utf8_lossy(s).into_owned())
            });
        Self {
            session,
            peer: extensions.get::<UnixPeer>().copied(),
        }
    }

    /// The identity of a request through the tool proxy: the session of its proxy connection.
    pub fn of_tool(extensions: &http::Extensions) -> Self {
        Self {
            session: extensions
                .get::<ClientInfo>()
                .and_then(|c| c.session.clone()),
            peer: None,
        }
    }

    /// Whether the transport carried nothing: an unknown caller.
    pub fn is_anonymous(&self) -> bool {
        self.session.is_none() && self.peer.is_none()
    }

    /// The restore engine's caller: an unknown caller (`agent.known` false) when the transport
    /// carried nothing, else an agent the data plane cannot place (agent fields unknown).
    pub fn caller(&self, provider: Option<&str>) -> Caller {
        Caller {
            agent: self.is_anonymous().then(Agent::default),
            provider: provider.map(str::to_owned),
        }
    }

    /// Fills the agent part of a decision-table request.
    pub fn apply(&self, req: &mut Request) {
        req.agent = Agent::default();
        if !self.is_anonymous() {
            req.unknown = FieldSet::AGENT;
        }
    }

    /// What an ask about this request tells the control plane, `None` for an unknown caller.
    pub fn ask_caller(&self) -> Option<v1::AskCaller> {
        if self.is_anonymous() {
            return None;
        }
        Some(v1::AskCaller {
            session_id: self.session.clone().unwrap_or_default(),
            unix_peer: self.peer.is_some(),
            peer_uid: self.peer.map_or(0, |p| p.uid),
            peer_gid: self.peer.map_or(0, |p| p.gid),
            peer_pid: self.peer.and_then(|p| p.pid).unwrap_or(0),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn sources_in_order() {
        let mut h = http::HeaderMap::new();
        let mut ext = http::Extensions::new();
        let anon = Identity::of_llm(&h, &ext);
        assert!(anon.is_anonymous() && anon.ask_caller().is_none());
        assert_eq!(anon.caller(None).agent, Some(Agent::default()));

        h.insert(scrim_llm::SESSION_HEADER, "sess-1".parse().unwrap());
        assert_eq!(
            Identity::of_llm(&h, &ext).session.as_deref(),
            Some("sess-1")
        );
        ext.insert(ClientInfo {
            peer: None,
            session: Some("from-proxy".into()),
        });
        let id = Identity::of_llm(&h, &ext);
        assert_eq!(id.session.as_deref(), Some("from-proxy"));
        assert_eq!(id.caller(Some("anthropic")).agent, None);
        assert_eq!(
            Identity::of_tool(&ext).session.as_deref(),
            Some("from-proxy")
        );

        h.insert(scrim_llm::SESSION_HEADER, "not a session".parse().unwrap());
        assert!(Identity::of_llm(&h, &http::Extensions::new()).is_anonymous());

        let mut ext = http::Extensions::new();
        ext.insert(UnixPeer {
            uid: 1000,
            gid: 100,
            pid: Some(42),
        });
        let id = Identity::of_llm(&http::HeaderMap::new(), &ext);
        let ask = id.ask_caller().unwrap();
        assert!(ask.unix_peer && ask.peer_uid == 1000 && ask.peer_pid == 42);
        let mut req = Request::default();
        id.apply(&mut req);
        assert_eq!(req.unknown, FieldSet::AGENT);
    }
}
