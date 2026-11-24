// SPDX-License-Identifier: AGPL-3.0-only

//! TLS listeners that identify agents by client certificate (agent-identity spec, "Mutual TLS
//! identity").
//!
//! A `BASE_URL`, `FORWARD_PROXY` or `TOOL_PROXY` listener with `tls` set accepts TLS only. Its own
//! certificate is issued by the current tool-proxy CA for one of
//! `ClientCertificateTrust.server_names`, and it requires a client certificate that chains to the
//! snapshot's trust anchors (no system roots), is valid now, carries the client-auth key usage
//! and, when revocation lists are configured, is not revoked by a current list of its issuer
//! ([`ClientTrust`]). The client's private key never reaches scrim: rustls checks the handshake
//! signature made with it.
//!
//! A certificate that fails is refused in the handshake, and the refusal is reported to the
//! control plane as an `EVENT_KIND_CLIENT_CERTIFICATE_REFUSED` event with a short reason
//! ([`refusal_reason`]) and the leaf's public details, never anything else. A verified chain goes
//! with every request of the connection as [`ClientCertificate`] in its `ClientInfo`, and on to the
//! control plane in `AskCaller.client_certificate_chain`, where it is verified again and mapped to
//! an agent.
//!
//! The trust is part of the snapshot bundle and read once per handshake, so a snapshot with new
//! anchors or revocation lists applies to the next connection without rebinding the listener.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, SignatureScheme};
use scrim_proto::v1;
use scrim_toolproxy::{ClientCertificate, ToolProxy};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

use crate::engine::Bundle;
use crate::events::Bus;

/// How long a client has to complete the TLS handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The client certificates TLS listeners accept, built from `Snapshot.client_certificates`.
pub struct ClientTrust {
    verifier: Arc<dyn ClientCertVerifier>,
    server_names: Vec<String>,
    anchors: usize,
    crls: usize,
}

impl std::fmt::Debug for ClientTrust {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientTrust")
            .field("anchors", &self.anchors)
            .field("crls", &self.crls)
            .field("server_names", &self.server_names)
            .finish_non_exhaustive()
    }
}

impl ClientTrust {
    /// Builds the verifier: the trust anchors (at least one), the revocation lists (when any,
    /// the end entity's issuer must have a current one; a list past its next update refuses),
    /// and the listener names (at least one).
    pub fn from_proto(t: &v1::ClientCertificateTrust) -> Result<Self, String> {
        let mut roots = rustls::RootCertStore::empty();
        for c in CertificateDer::pem_slice_iter(t.trust_anchors_pem.as_bytes()) {
            let c = c.map_err(|e| format!("client_certificates: trust anchors: {e}"))?;
            roots
                .add(c)
                .map_err(|e| format!("client_certificates: trust anchor: {e}"))?;
        }
        if roots.is_empty() {
            return Err("client_certificates: no trust anchors".into());
        }
        let server_names: Vec<String> = t
            .server_names
            .iter()
            .map(|n| n.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|n| !n.is_empty())
            .collect();
        if server_names.is_empty() {
            return Err("client_certificates: no server names".into());
        }
        let anchors = roots.len();
        let crls: Vec<CertificateRevocationListDer<'static>> = t
            .crls_der
            .iter()
            .map(|d| CertificateRevocationListDer::from(d.clone()))
            .collect();
        let n_crls = crls.len();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut b = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider);
        if !crls.is_empty() {
            b = b
                .with_crls(crls)
                .only_check_end_entity_revocation()
                .enforce_revocation_expiration();
        }
        let verifier = b.build().map_err(|e| format!("client_certificates: {e}"))?;
        Ok(Self {
            verifier,
            server_names,
            anchors,
            crls: n_crls,
        })
    }

    /// The names the listener's certificate is issued for.
    pub fn server_names(&self) -> &[String] {
        &self.server_names
    }

    /// The name to issue the listener's certificate for: the client's server name if listed,
    /// else the address it connected to if listed, else the first name.
    fn name_for(&self, sni: Option<&str>, local: Option<IpAddr>) -> &str {
        if let Some(s) = sni.map(|s| s.trim_end_matches('.').to_ascii_lowercase())
            && let Some(n) = self.server_names.iter().find(|n| **n == s)
        {
            return n;
        }
        if let Some(ip) = local.map(canonical)
            && let Some(n) = self
                .server_names
                .iter()
                .find(|n| n.parse::<IpAddr>().is_ok_and(|a| canonical(a) == ip))
        {
            return n;
        }
        &self.server_names[0]
    }
}

/// An IPv4-mapped IPv6 address as IPv4.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// The short, stable reason a client certificate was refused, as audited.
pub fn refusal_reason(e: &rustls::Error) -> &'static str {
    match e {
        rustls::Error::NoCertificatesPresented => "no certificate",
        rustls::Error::InvalidCertificate(c) => match c {
            CertificateError::Expired | CertificateError::ExpiredContext { .. } => "expired",
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                "not yet valid"
            }
            CertificateError::Revoked => "revoked",
            CertificateError::UnknownRevocationStatus => "revocation status unknown",
            CertificateError::ExpiredRevocationList
            | CertificateError::ExpiredRevocationListContext { .. } => "crl expired",
            CertificateError::UnknownIssuer | CertificateError::BadSignature => "untrusted",
            CertificateError::InvalidPurpose | CertificateError::InvalidPurposeContext { .. } => {
                "not a client certificate"
            }
            _ => "invalid",
        },
        _ => "invalid",
    }
}

/// A per-connection wrapper that remembers why the shared verifier refused the client's chain.
#[derive(Debug)]
struct Recording {
    inner: Arc<dyn ClientCertVerifier>,
    failure: Mutex<Option<(rustls::Error, CertificateDer<'static>)>>,
}

impl ClientCertVerifier for Recording {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.inner
            .verify_client_cert(end_entity, intermediates, now)
            .inspect_err(|e| {
                if let Ok(mut f) = self.failure.lock() {
                    *f = Some((e.clone(), end_entity.clone().into_owned()));
                }
            })
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// The listener's own certificate, issued by the tool-proxy CA for the name the client asked
/// for when it is one of the trust's server names.
#[derive(Debug)]
struct ListenerCert {
    trust: Arc<ClientTrust>,
    proxy: ToolProxy,
    local: Option<IpAddr>,
}

impl ResolvesServerCert for ListenerCert {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = self.trust.name_for(hello.server_name(), self.local);
        match self.proxy.ca().leaf_for(name) {
            Ok(k) => Some(k),
            Err(e) => {
                tracing::warn!(error = %e, "issuing the TLS listener's certificate failed");
                None
            }
        }
    }
}

/// What a TLS listener needs for its handshakes. Cheap to clone.
#[derive(Clone)]
pub struct Acceptor {
    /// The listener's name, reported in refusals.
    pub listener: String,
    /// The bundle in force, read once per handshake for the trust.
    pub snapshot: Arc<arc_swap::ArcSwapOption<Bundle>>,
    /// Where refusals go.
    pub events: Arc<Bus>,
    /// The tool proxy, whose CA issues the listener's certificate.
    pub proxy: ToolProxy,
    /// ALPN protocols offered.
    pub alpn: Vec<Vec<u8>>,
}

impl std::fmt::Debug for Acceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Acceptor")
            .field("listener", &self.listener)
            .finish_non_exhaustive()
    }
}

impl Acceptor {
    /// Completes the TLS handshake of `stream` and returns the connection with the client's
    /// verified chain. `None` closes it: no trust in force, a refused certificate (reported), or
    /// any other handshake failure (logged at debug).
    pub async fn accept(
        &self,
        stream: TcpStream,
        peer: SocketAddr,
    ) -> Option<(TlsStream<TcpStream>, ClientCertificate)> {
        let Some(trust) = self
            .snapshot
            .load()
            .as_ref()
            .and_then(|b| b.applied.client_trust.clone())
        else {
            tracing::warn!(
                listener = self.listener.as_str(),
                "TLS listener has no client certificate trust; connection closed"
            );
            return None;
        };
        let recording = Arc::new(Recording {
            inner: Arc::clone(&trust.verifier),
            failure: Mutex::new(None),
        });
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cfg = match rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
        {
            Ok(b) => b
                .with_client_cert_verifier(Arc::clone(&recording) as Arc<dyn ClientCertVerifier>)
                .with_cert_resolver(Arc::new(ListenerCert {
                    trust,
                    proxy: self.proxy.clone(),
                    local: stream.local_addr().ok().map(|a| a.ip()),
                })),
            Err(e) => {
                tracing::error!(error = %e, "TLS server config failed");
                return None;
            }
        };
        cfg.alpn_protocols.clone_from(&self.alpn);
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
            Ok(Ok(tls)) => tls,
            Ok(Err(e)) => {
                let recorded = recording.failure.lock().ok().and_then(|mut f| f.take());
                let rustls_err = e
                    .get_ref()
                    .and_then(|i| i.downcast_ref::<rustls::Error>())
                    .cloned();
                match (recorded, rustls_err) {
                    (Some((err, leaf)), _) => self.refused(&err, Some(&leaf), peer),
                    (None, Some(err @ rustls::Error::NoCertificatesPresented)) => {
                        self.refused(&err, None, peer);
                    }
                    _ => tracing::debug!(
                        listener = self.listener.as_str(),
                        %peer,
                        error = %e,
                        "TLS handshake failed"
                    ),
                }
                return None;
            }
            Err(_) => {
                tracing::debug!(listener = self.listener.as_str(), %peer, "TLS handshake timed out");
                return None;
            }
        };
        let chain: Vec<CertificateDer<'static>> = tls
            .get_ref()
            .1
            .peer_certificates()
            .map_or_else(Vec::new, |c| {
                c.iter().map(|c| c.clone().into_owned()).collect()
            });
        // A mandatory verifier never lets a handshake finish without a chain; refuse anyway.
        let Some(cert) = ClientCertificate::new(chain) else {
            self.refused(&rustls::Error::NoCertificatesPresented, None, peer);
            return None;
        };
        Some((tls, cert))
    }

    /// Reports a refused client certificate to the control plane.
    fn refused(&self, err: &rustls::Error, leaf: Option<&CertificateDer<'_>>, peer: SocketAddr) {
        let reason = refusal_reason(err);
        let mut attrs = BTreeMap::new();
        attrs.insert("listener".to_owned(), self.listener.clone());
        attrs.insert("peer".to_owned(), peer.to_string());
        if let Some(leaf) = leaf {
            attrs.extend(leaf_attrs(leaf));
        }
        tracing::info!(
            listener = self.listener.as_str(),
            %peer,
            reason,
            "client certificate refused"
        );
        self.events.emit(v1::Event {
            kind: v1::EventKind::ClientCertificateRefused as i32,
            target: self.listener.clone(),
            reason: reason.to_owned(),
            effect: v1::Effect::Deny as i32,
            attrs: attrs.into_iter().collect(),
            ..v1::Event::default()
        });
    }
}

/// The public details of a leaf certificate reported with a refusal: `cert_sha256` (hex SHA-256
/// of the DER), and when it parses `cert_cn` (subject common name) and `spiffe_id` (the first URI
/// subject alternative name starting `spiffe://`).
pub fn leaf_attrs(leaf: &CertificateDer<'_>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let sha = ClientCertificate::new(vec![leaf.clone().into_owned()])
        .map_or_else(String::new, |c| c.leaf_sha256());
    out.insert("cert_sha256".to_owned(), sha);
    if let Ok((_, cert)) = x509_parser::parse_x509_certificate(leaf.as_ref()) {
        if let Some(cn) = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|a| a.as_str().ok())
        {
            out.insert("cert_cn".to_owned(), clip(cn));
        }
        if let Ok(Some(san)) = cert.subject_alternative_name() {
            for n in &san.value.general_names {
                if let x509_parser::extensions::GeneralName::URI(u) = n
                    && u.starts_with("spiffe://")
                {
                    out.insert("spiffe_id".to_owned(), clip(u));
                    break;
                }
            }
        }
    }
    out
}

/// At most 256 bytes of printable text: a certificate's fields are chosen by whoever made it.
fn clip(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .scan(0usize, |n, c| {
            *n += c.len_utf8();
            (*n <= 256).then_some(c)
        })
        .collect()
}
