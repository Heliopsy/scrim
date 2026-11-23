// SPDX-License-Identifier: AGPL-3.0-only

//! Who sent a request, as far as the transport tells (specs `agent-identity`, "Identity is not
//! taken from request content").
//!
//! The data plane holds no mapping from Unix users to agents and checks no session token (the
//! tokens it holds are redaction values; only a redaction scope, [`crate::scopes`], looks at
//! them), so it can establish what a request carries but not whose it is:
//!
//! | Transport | What the data plane reads |
//! | --- | --- |
//! | Unix socket listener | the kernel's peer credentials (uid, gid, pid) |
//! | forward proxy | the session named in `Proxy-Authorization: Basic` (user name), and the verifier of the session token sent as the password; or a Kubernetes service account token as the password of the user `k8s` |
//! | base-URL listener | the `x-scrim-session` header (stripped before forwarding): a session token, a bare session id, or a Kubernetes service account token |
//!
//! A request that carries none of these is an unknown caller: `agent.known` is false, decided
//! locally, so a rule such as `deny when !agent.known` refuses it without a round trip. A
//! request that carries any of them is one the data plane cannot place: its agent fields are
//! unknown to the decision table, a rule that depends on them goes to the control plane, and
//! the ask carries what the transport said ([`v1::AskCaller`]) for the control plane to resolve
//! and verify. A session token is never kept, logged or forwarded: it is reduced to its verifier
//! ([`SessionVerifier`]) on arrival, and an ask carries only a proof derived from that verifier
//! and bound to the ask (`AskCaller.session_proof`, design D14). A Kubernetes service account
//! token cannot be reduced that way, since the control plane must see it to verify it: it is
//! held in a zeroed type for the request (or the proxy connection) and sent in the ask
//! (`AskCaller.kubernetes_token`), never logged or forwarded. A restore cannot wait for an
//! answer, so a restore rule on the agent keeps the placeholder for such a request.

use scrim_llm::server::UnixPeer;
use scrim_policy::{Agent, Caller, FieldSet, Request};
use scrim_proto::v1;
use scrim_toolproxy::{
    ClientInfo, KubernetesToken, SessionVerifier, is_session_id, parse_kubernetes_token,
    parse_session_token,
};

/// What one request's transport said about its sender.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Identity {
    /// The session the request names. A claim, not verified here.
    pub session: Option<String>,
    /// Unix socket peer credentials.
    pub peer: Option<UnixPeer>,
    /// The verifier of the session token the request carried, if it carried the token of
    /// `session`.
    pub verifier: Option<SessionVerifier>,
    /// The Kubernetes service account token the request carried instead of a session.
    pub kubernetes_token: Option<KubernetesToken>,
}

impl Identity {
    /// The identity of a request to the LLM proxy: the Unix peer of a socket listener, the
    /// session of the forward-proxy connection it was tunnelled through, else the
    /// `x-scrim-session` header.
    pub fn of_llm(headers: &http::HeaderMap, extensions: &http::Extensions) -> Self {
        let peer = extensions.get::<UnixPeer>().copied();
        if let Some(c) = extensions
            .get::<ClientInfo>()
            .filter(|c| c.session.is_some() || c.kubernetes_token.is_some())
        {
            return Self {
                session: c.session.clone(),
                peer,
                verifier: c.verifier.clone(),
                kubernetes_token: c.kubernetes_token.clone(),
            };
        }
        let mut id = Self {
            peer,
            ..Self::default()
        };
        if let Some(v) = headers
            .get(scrim_llm::SESSION_HEADER)
            .map(http::HeaderValue::as_bytes)
        {
            if let Some((sid, ver)) = parse_session_token(v) {
                id.session = Some(sid);
                id.verifier = Some(ver);
            } else if let Some(t) = parse_kubernetes_token(v) {
                id.kubernetes_token = Some(t);
            } else if is_session_id(v) {
                id.session = Some(String::from_utf8_lossy(v).into_owned());
            }
        }
        id
    }

    /// The identity of a request through the tool proxy: the session of its proxy connection.
    pub fn of_tool(extensions: &http::Extensions) -> Self {
        let c = extensions.get::<ClientInfo>();
        Self {
            session: c.and_then(|c| c.session.clone()),
            peer: None,
            verifier: c.and_then(|c| c.verifier.clone()),
            kubernetes_token: c.and_then(|c| c.kubernetes_token.clone()),
        }
    }

    /// Whether the transport carried nothing: an unknown caller.
    pub fn is_anonymous(&self) -> bool {
        self.session.is_none() && self.peer.is_none() && self.kubernetes_token.is_none()
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
            session_proof: Vec::new(),
            kubernetes_token: self
                .kubernetes_token
                .as_ref()
                .map_or_else(Vec::new, |t| t.as_bytes().to_vec()),
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
            verifier: None,
            kubernetes_token: None,
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

        // A token in the header: the session is its id, and only the verifier is kept.
        let token = format!("scrim_st_abcdefghijklmn23_{}", "x".repeat(43));
        h.insert(scrim_llm::SESSION_HEADER, token.parse().unwrap());
        let id = Identity::of_llm(&h, &http::Extensions::new());
        assert_eq!(id.session.as_deref(), Some("abcdefghijklmn23"));
        assert!(id.verifier.is_some());
        assert!(!format!("{id:?}").contains(&token[26..]));

        // A Kubernetes service account token in the header: no session, the token goes to the
        // control plane in the ask and nowhere else.
        let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJlLWJ5dGVz";
        h.insert(scrim_llm::SESSION_HEADER, jwt.parse().unwrap());
        let id = Identity::of_llm(&h, &http::Extensions::new());
        assert!(id.session.is_none() && !id.is_anonymous());
        assert!(!format!("{id:?}").contains("eyJ"));
        let ask = id.ask_caller().unwrap();
        assert_eq!(ask.kubernetes_token, jwt.as_bytes());
        assert_eq!(ask.session_id, "");
        assert!(!format!("{ask:?}").contains("eyJ"));
        let mut ext = http::Extensions::new();
        ext.insert(ClientInfo {
            peer: None,
            session: None,
            verifier: None,
            kubernetes_token: parse_kubernetes_token(jwt.as_bytes()),
        });
        let id = Identity::of_tool(&ext);
        assert_eq!(
            id.ask_caller().unwrap().kubernetes_token,
            jwt.as_bytes().to_vec()
        );
        assert!(!Identity::of_llm(&http::HeaderMap::new(), &ext).is_anonymous());

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
