// SPDX-License-Identifier: AGPL-3.0-only

//! TLS listeners that identify agents by client certificate: a valid certificate is served and
//! its chain reaches the control plane in every ask; untrusted, expired, revoked, stale-CRL and
//! missing certificates are refused in the handshake and reported; new trust applies without
//! rebinding.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CertifiedIssuer, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose, RevokedCertParams,
    SanType, SerialNumber, date_time_ymd,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use scrim_dataplane::engine::Shared;
use scrim_dataplane::events::Subscriber;
use scrim_proto::v1;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

type Issuer = CertifiedIssuer<'static, KeyPair>;

fn ca(name: &str) -> Issuer {
    let key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::default();
    p.distinguished_name.push(DnType::CommonName, name);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    CertifiedIssuer::self_signed(p, key).unwrap()
}

/// A client certificate and its key.
struct Client {
    der: CertificateDer<'static>,
    key: KeyPair,
}

fn client(issuer: &Issuer, cn: &str, serial: u64, from: (i32, u8), until: (i32, u8)) -> Client {
    let key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::default();
    p.distinguished_name.push(DnType::CommonName, cn);
    p.subject_alt_names = vec![SanType::URI(
        format!("spiffe://example.org/agents/{cn}")
            .try_into()
            .unwrap(),
    )];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    p.serial_number = Some(SerialNumber::from(serial));
    p.not_before = date_time_ymd(from.0, from.1, 1);
    p.not_after = date_time_ymd(until.0, until.1, 1);
    let cert = p.signed_by(&key, issuer).unwrap();
    Client {
        der: cert.der().clone(),
        key,
    }
}

fn valid(issuer: &Issuer, cn: &str, serial: u64) -> Client {
    client(issuer, cn, serial, (2020, 1), (2090, 1))
}

fn crl(issuer: &Issuer, revoked: &[u64], next_update: (i32, u8)) -> Vec<u8> {
    CertificateRevocationListParams {
        this_update: date_time_ymd(2000, 1, 1),
        next_update: date_time_ymd(next_update.0, next_update.1, 1),
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: revoked
            .iter()
            .map(|s| RevokedCertParams {
                serial_number: SerialNumber::from(*s),
                revocation_time: date_time_ymd(2000, 1, 1),
                reason_code: None,
                invalidity_date: None,
            })
            .collect(),
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(issuer)
    .unwrap()
    .der()
    .to_vec()
}

fn snapshot(version: u64, anchors: &[&Issuer], crls: Vec<Vec<u8>>) -> v1::Snapshot {
    let mut key = v1::PlaceholderKey::default();
    key.version = 1;
    key.key = vec![7; 32];
    key.current = true;
    let listener = |name: &str, kind: v1::ListenerKind| v1::Listener {
        name: name.into(),
        kind: kind.into(),
        address: "127.0.0.1:0".into(),
        tls: true,
        ..Default::default()
    };
    v1::Snapshot {
        protocol: v1::PROTOCOL,
        version,
        placeholder_keys: vec![key],
        listeners: vec![
            listener("llm-tls", v1::ListenerKind::BaseUrl),
            listener("forward-tls", v1::ListenerKind::ForwardProxy),
        ],
        client_certificates: Some(v1::ClientCertificateTrust {
            trust_anchors_pem: anchors.iter().map(|a| a.pem()).collect(),
            crls_der: crls,
            server_names: vec!["localhost".into()],
        }),
        policy: Some(v1::Policy {
            version: 1,
            default_effect: v1::Effect::Allow.into(),
            table_format: 1,
            ask_timeout_millis: 5000,
            // A rule on the agent: a certificate caller cannot be placed by the data plane, so
            // every provider request asks.
            table: vec![v1::TableRule {
                name: "no-builder".into(),
                effect: v1::Effect::Deny.into(),
                clauses: vec![v1::Clause {
                    conditions: vec![v1::Condition {
                        field: "agent.id".into(),
                        op: v1::ConditionOp::In.into(),
                        values: vec!["builder".into()],
                        ..Default::default()
                    }],
                    residual: false,
                }],
                reason: "test".into(),
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..Default::default()
    }
}

struct Plane {
    shared: Arc<Shared>,
    events: Subscriber,
}

impl Plane {
    async fn start(snap: v1::Snapshot) -> Self {
        let shared = Arc::new(Shared::new().unwrap());
        let events = shared.events.subscribe().unwrap();
        shared.apply(snap).await.unwrap();
        Self { shared, events }
    }

    fn addr(&self, name: &str) -> String {
        let st = self.shared.listeners.status();
        let l = st.iter().find(|l| l.name == name).unwrap();
        assert!(l.bound, "{l:?}");
        l.address.clone()
    }

    fn ca_pem(&self) -> String {
        self.shared.tool_proxy.ca().trust_bundle_pem()
    }

    /// The next client certificate refusal.
    async fn refusal(&mut self) -> v1::Event {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let b = self.events.next_batch().await.unwrap();
                if let Some(e) = b
                    .events
                    .into_iter()
                    .find(|e| e.kind() == v1::EventKind::ClientCertificateRefused)
                {
                    return e;
                }
            }
        })
        .await
        .expect("no CLIENT_CERTIFICATE_REFUSED event")
    }
}

fn tls_config(ca_pem: &str, cert: Option<&Client>) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        roots.add(c.unwrap()).unwrap();
    }
    let b = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots);
    let mut cfg = match cert {
        Some(c) => b
            .with_client_auth_cert(
                vec![c.der.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(c.key.serialize_der())),
            )
            .unwrap(),
        None => b.with_no_client_auth(),
    };
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

async fn tls(
    addr: &str,
    name: &str,
    cfg: Arc<rustls::ClientConfig>,
    tcp: Option<TcpStream>,
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = match tcp {
        Some(t) => t,
        None => TcpStream::connect(addr).await?,
    };
    tokio_rustls::TlsConnector::from(cfg)
        .connect(ServerName::try_from(name.to_owned()).unwrap(), tcp)
        .await
}

/// Sends a provider request over `io`; `None` when the connection fails.
async fn post<IO>(io: IO, path: &str) -> Option<u16>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .ok()?;
    tokio::spawn(conn);
    let req = http::Request::post(path)
        .header("host", "api.anthropic.com")
        .header("content-type", "application/json")
        .header("x-scrim-session", "sess-ignored")
        .body(Full::new(Bytes::from_static(
            br#"{"model":"m","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}"#,
        )))
        .unwrap();
    let resp = send.send_request(req).await.ok()?;
    let status = resp.status().as_u16();
    let _ = resp.into_body().collect().await;
    Some(status)
}

/// Answers every ask with deny and returns the asks it saw.
fn deny_asks(shared: &Arc<Shared>) -> tokio::sync::mpsc::UnboundedReceiver<v1::AskRequest> {
    let mut rx = shared.asks.attach().unwrap();
    let (tx, out) = tokio::sync::mpsc::unbounded_channel();
    let shared = Arc::clone(shared);
    tokio::spawn(async move {
        while let Some(a) = rx.recv().await {
            shared.asks.answer(v1::AskAnswer {
                protocol: v1::PROTOCOL,
                id: a.id,
                effect: v1::Effect::Deny.into(),
                reason: "test".into(),
                ..Default::default()
            });
            let _ = tx.send(a);
        }
    });
    out
}

#[tokio::test]
async fn valid_certificate_is_served_and_its_chain_reaches_the_control_plane() {
    let issuer = ca("agents CA");
    let builder = valid(&issuer, "builder", 10);
    let plane = Plane::start(snapshot(1, &[&issuer], vec![])).await;
    let mut asks = deny_asks(&plane.shared);
    let ca_pem = plane.ca_pem();

    // Base URL over TLS.
    let conn = tls(
        &plane.addr("llm-tls"),
        "localhost",
        tls_config(&ca_pem, Some(&builder)),
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        post(conn, "/anthropic/v1/messages").await,
        Some(403),
        "the control plane denied it"
    );
    let a = tokio::time::timeout(Duration::from_secs(5), asks.recv())
        .await
        .unwrap()
        .unwrap();
    let caller = a.caller.unwrap();
    assert_eq!(caller.client_certificate_chain, vec![builder.der.to_vec()]);
    assert!(
        caller.session_id.is_empty() && caller.kubernetes_token.is_empty(),
        "the certificate is the only identity: {caller:?}"
    );

    // Forward proxy over TLS, a provider host inside the CONNECT tunnel.
    let proxy = plane.addr("forward-tls");
    let mut outer = tls(
        &proxy,
        "localhost",
        tls_config(&ca_pem, Some(&builder)),
        None,
    )
    .await
    .unwrap();
    outer
        .write_all(
            b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\nProxy-Authorization: Basic c2Vzcy14Onk=\r\n\r\n",
        )
        .await
        .unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(outer.read(&mut b).await.unwrap(), 1);
        head.push(b[0]);
    }
    assert!(head.starts_with(b"HTTP/1.1 200"));
    let inner = tokio_rustls::TlsConnector::from(tls_config(&ca_pem, None))
        .connect(ServerName::try_from("api.anthropic.com").unwrap(), outer)
        .await
        .unwrap();
    assert_eq!(post(inner, "/v1/messages").await, Some(403));
    let a = tokio::time::timeout(Duration::from_secs(5), asks.recv())
        .await
        .unwrap()
        .unwrap();
    let caller = a.caller.unwrap();
    assert_eq!(caller.client_certificate_chain, vec![builder.der.to_vec()]);
    assert!(caller.session_id.is_empty(), "{caller:?}");
}

#[tokio::test]
async fn refused_certificates_are_reported() {
    let issuer = ca("agents CA");
    let other = ca("someone else's CA");
    let mut plane = Plane::start(snapshot(
        1,
        &[&issuer],
        vec![crl(&issuer, &[66], (2090, 1))],
    ))
    .await;
    let ca_pem = plane.ca_pem();
    let addr = plane.addr("llm-tls");

    let cases = [
        ("untrusted", Some(valid(&other, "stranger", 20))),
        (
            "expired",
            Some(client(&issuer, "old", 21, (2000, 1), (2001, 1))),
        ),
        (
            "not yet valid",
            Some(client(&issuer, "early", 22, (2089, 1), (2090, 1))),
        ),
        ("revoked", Some(valid(&issuer, "revoked", 66))),
        ("no certificate", None),
    ];
    for (reason, cert) in cases {
        let got = match tls(&addr, "localhost", tls_config(&ca_pem, cert.as_ref()), None).await {
            Ok(conn) => post(conn, "/anthropic/v1/messages").await,
            Err(_) => None,
        };
        assert_eq!(got, None, "{reason}: served");
        let e = plane.refusal().await;
        assert_eq!(e.reason, reason);
        assert_eq!(e.attrs.get("listener").map(String::as_str), Some("llm-tls"));
        assert!(e.attrs.contains_key("peer"));
        if cert.is_some() {
            let cn = e.attrs.get("cert_cn").unwrap();
            assert_ne!(cn, "");
            assert_eq!(
                e.attrs.get("spiffe_id"),
                Some(&format!("spiffe://example.org/agents/{cn}"))
            );
            assert_eq!(e.attrs.get("cert_sha256").map(String::len), Some(64));
        }
    }
}

#[tokio::test]
async fn stale_crl_and_new_trust_apply_without_rebinding() {
    let issuer = ca("agents CA");
    let a = valid(&issuer, "agent-a", 30);
    let mut plane = Plane::start(snapshot(1, &[&issuer], vec![])).await;
    let mut asks = deny_asks(&plane.shared);
    let ca_pem = plane.ca_pem();
    let addr = plane.addr("llm-tls");

    let conn = tls(&addr, "localhost", tls_config(&ca_pem, Some(&a)), None)
        .await
        .unwrap();
    assert_eq!(post(conn, "/anthropic/v1/messages").await, Some(403));
    assert!(asks.recv().await.is_some());

    // A CRL past its next update refuses every certificate of its issuer.
    plane
        .shared
        .apply(snapshot(2, &[&issuer], vec![crl(&issuer, &[], (2001, 1))]))
        .await
        .unwrap();
    assert_eq!(plane.addr("llm-tls"), addr, "the listener was not rebound");
    let got = match tls(&addr, "localhost", tls_config(&ca_pem, Some(&a)), None).await {
        Ok(c) => post(c, "/anthropic/v1/messages").await,
        Err(_) => None,
    };
    assert_eq!(got, None);
    assert_eq!(plane.refusal().await.reason, "crl expired");

    // A current CRL that revokes it.
    plane
        .shared
        .apply(snapshot(
            3,
            &[&issuer],
            vec![crl(&issuer, &[30], (2090, 1))],
        ))
        .await
        .unwrap();
    assert_eq!(plane.addr("llm-tls"), addr);
    let got = match tls(&addr, "localhost", tls_config(&ca_pem, Some(&a)), None).await {
        Ok(c) => post(c, "/anthropic/v1/messages").await,
        Err(_) => None,
    };
    assert_eq!(got, None);
    assert_eq!(plane.refusal().await.reason, "revoked");
}

#[tokio::test]
async fn tls_listeners_need_trust_and_an_http_kind() {
    let issuer = ca("agents CA");
    let shared = Arc::new(Shared::new().unwrap());
    let mut snap = snapshot(1, &[&issuer], vec![]);
    snap.client_certificates = None;
    assert!(shared.apply(snap).await.is_err(), "tls without trust");

    let mut snap = snapshot(1, &[&issuer], vec![]);
    snap.client_certificates.as_mut().unwrap().trust_anchors_pem = String::new();
    assert!(shared.apply(snap).await.is_err(), "no anchors");

    let mut snap = snapshot(1, &[&issuer], vec![]);
    snap.client_certificates.as_mut().unwrap().crls_der = vec![b"not a crl".to_vec()];
    assert!(shared.apply(snap).await.is_err(), "unparseable CRL");

    let mut snap = snapshot(1, &[&issuer], vec![]);
    snap.listeners.push(v1::Listener {
        name: "sock".into(),
        kind: v1::ListenerKind::Unix.into(),
        address: "/nonexistent/sock".into(),
        tls: true,
        ..Default::default()
    });
    assert!(shared.apply(snap).await.is_err(), "tls on a Unix listener");
}
