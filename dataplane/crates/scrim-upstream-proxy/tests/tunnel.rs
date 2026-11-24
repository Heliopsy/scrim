// SPDX-License-Identifier: AGPL-3.0-only

//! Tunnels through the recording test proxy: with and without credentials, plain and TLS
//! proxies, `NO_PROXY` bypass through the connector, and TLS to the destination verified end to
//! end inside the tunnel (a proxy that presents its own certificate is refused).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    unreachable_pub
)]

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine as _;
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use scrim_upstream_proxy::testing::{Options, TestProxy};
use scrim_upstream_proxy::{ProxyConnector, ProxyHandle, TunnelError, UpstreamProxy, connect};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tower_service::Service;

const T: Duration = Duration::from_secs(5);

fn ca(name: &str) -> CertifiedIssuer<'static, KeyPair> {
    let mut p = CertificateParams::default();
    p.distinguished_name.push(rcgen::DnType::CommonName, name);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    CertifiedIssuer::self_signed(p, KeyPair::generate().unwrap()).unwrap()
}

fn server_config(
    ca: &CertifiedIssuer<'static, KeyPair>,
    names: &[&str],
) -> Arc<rustls::ServerConfig> {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(names.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
        .unwrap()
        .signed_by(&key, ca)
        .unwrap();
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap(),
    )
}

fn client_config(ca: &CertifiedIssuer<'static, KeyPair>) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(ca.der().to_vec())).unwrap();
    Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth(),
    )
}

/// A TLS echo server: answers each line with `echo: <line>`.
async fn tls_echo(cfg: Arc<rustls::ServerConfig>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = l.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = [0u8; 1024];
                let n = tls.read(&mut buf).await.unwrap_or(0);
                let mut out = b"echo: ".to_vec();
                out.extend_from_slice(&buf[..n]);
                let _ = tls.write_all(&out).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    addr
}

async fn talk<S>(
    s: S,
    client: &Arc<rustls::ClientConfig>,
    name: &str,
    msg: &[u8],
) -> std::io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut tls = tokio_rustls::TlsConnector::from(Arc::clone(client))
        .connect(ServerName::try_from(name.to_owned()).unwrap(), s)
        .await?;
    tls.write_all(msg).await?;
    let mut out = Vec::new();
    tls.read_to_end(&mut out).await?;
    Ok(out)
}

fn basic(user: &str, pw: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pw}"))
    )
}

#[tokio::test]
async fn tunnels_with_credentials_and_verifies_the_destination_inside() {
    let dest_ca = ca("dest CA");
    let echo = tls_echo(server_config(&dest_ca, &["api.provider.test"])).await;
    let pw = "generated-proxy-pw-5e1d0c";
    let proxy = TestProxy::start(Options {
        require_authorization: Some(basic("scrim", pw)),
        redirect: Some(echo),
        ..Options::default()
    })
    .await;
    let url = format!("http://{}", proxy.addr());
    let client = client_config(&dest_ca);

    // Right credentials: the tunnel opens and TLS verifies api.provider.test end to end.
    let up = UpstreamProxy::new::<&str>(&url, &[], "scrim", pw.as_bytes()).unwrap();
    let s = connect(&up, &client, "api.provider.test", 443, T)
        .await
        .unwrap();
    let got = talk(s, &client, "api.provider.test", b"value-in-tls-7c1")
        .await
        .unwrap();
    assert_eq!(got, b"echo: value-in-tls-7c1");
    let seen = proxy.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].target, "api.provider.test:443");
    assert!(seen[0].sent_authorization && seen[0].opened);
    // The proxy relayed ciphertext only.
    let relayed = proxy.tunnelled_bytes();
    assert!(
        relayed.len() > 100,
        "the proxy relayed {} bytes",
        relayed.len()
    );
    assert!(!relayed.windows(16).any(|w| w == b"value-in-tls-7c1"));

    // No credentials, and wrong ones: 407, nothing opened.
    for (user, pass) in [("", ""), ("scrim", "wrong-password-0000")] {
        let up = UpstreamProxy::new::<&str>(&url, &[], user, pass.as_bytes()).unwrap();
        let err = connect(&up, &client, "api.provider.test", 443, T)
            .await
            .err()
            .unwrap();
        assert!(matches!(err, TunnelError::AuthRequired { .. }), "{err}");
        let msg = err.to_string();
        assert!(
            !msg.contains(pw) && !msg.contains("wrong-password"),
            "{msg}"
        );
    }
    assert_eq!(proxy.seen().iter().filter(|s| s.opened).count(), 1);
}

#[tokio::test]
async fn tunnels_without_credentials() {
    let dest_ca = ca("dest CA");
    let echo = tls_echo(server_config(&dest_ca, &["api.provider.test"])).await;
    let proxy = TestProxy::start(Options {
        redirect: Some(echo),
        ..Options::default()
    })
    .await;
    let up = UpstreamProxy::new::<&str>(&format!("http://{}", proxy.addr()), &[], "", b"").unwrap();
    let client = client_config(&dest_ca);
    let s = connect(&up, &client, "api.provider.test", 443, T)
        .await
        .unwrap();
    assert_eq!(
        talk(s, &client, "api.provider.test", b"hi").await.unwrap(),
        b"echo: hi"
    );
    assert!(!proxy.seen()[0].sent_authorization);
}

#[tokio::test]
async fn a_proxy_that_presents_its_own_certificate_is_refused() {
    // The proxy sends the tunnel to a server with a certificate for the right name from a CA the
    // client does not trust, as an intercepting proxy would.
    let dest_ca = ca("dest CA");
    let mitm_ca = ca("intercepting proxy CA");
    let mitm = tls_echo(server_config(&mitm_ca, &["api.provider.test"])).await;
    let proxy = TestProxy::start(Options {
        redirect: Some(mitm),
        ..Options::default()
    })
    .await;
    let up = UpstreamProxy::new::<&str>(&format!("http://{}", proxy.addr()), &[], "", b"").unwrap();
    let client = client_config(&dest_ca);
    let s = connect(&up, &client, "api.provider.test", 443, T)
        .await
        .unwrap();
    let err = talk(s, &client, "api.provider.test", b"value-must-not-leave-a91")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("certificate"), "{err}");
    assert!(
        !proxy
            .tunnelled_bytes()
            .windows(24)
            .any(|w| w == b"value-must-not-leave-a91")
    );
}

#[tokio::test]
async fn https_proxies_are_verified_too() {
    let dest_ca = ca("dest CA");
    let proxy_ca = ca("proxy CA");
    let echo = tls_echo(server_config(&dest_ca, &["api.provider.test"])).await;
    let proxy = TestProxy::start(Options {
        tls: Some(server_config(&proxy_ca, &["localhost"])),
        redirect: Some(echo),
        ..Options::default()
    })
    .await;
    let url = format!("https://localhost:{}", proxy.addr().port());
    let up = UpstreamProxy::new::<&str>(&url, &[], "", b"").unwrap();
    let dest_client = client_config(&dest_ca);
    // The proxy's own certificate verifies against the roots given for it.
    let s = connect(&up, &client_config(&proxy_ca), "api.provider.test", 443, T)
        .await
        .unwrap();
    assert_eq!(
        talk(s, &dest_client, "api.provider.test", b"x")
            .await
            .unwrap(),
        b"echo: x"
    );
    // An untrusted proxy certificate fails before CONNECT is sent.
    let err = connect(&up, &dest_client, "api.provider.test", 443, T)
        .await
        .err()
        .unwrap();
    assert!(matches!(err, TunnelError::Tls { .. }), "{err}");
    assert_eq!(proxy.seen().len(), 1);
}

#[tokio::test]
async fn refused_and_unreachable() {
    let proxy = TestProxy::start(Options {
        // Nothing listens there: the proxy answers 502.
        redirect: Some("127.0.0.1:1".parse().unwrap()),
        ..Options::default()
    })
    .await;
    let up = UpstreamProxy::new::<&str>(&format!("http://{}", proxy.addr()), &[], "", b"").unwrap();
    let client = client_config(&ca("x"));
    let err = connect(&up, &client, "api.provider.test", 443, T)
        .await
        .err()
        .unwrap();
    assert!(
        matches!(err, TunnelError::Refused { status: 502, .. }),
        "{err}"
    );

    let dead = UpstreamProxy::new::<&str>("http://127.0.0.1:1", &[], "", b"").unwrap();
    let err = connect(&dead, &client, "api.provider.test", 443, T)
        .await
        .err()
        .unwrap();
    assert!(matches!(err, TunnelError::Connect { .. }), "{err}");
}

/// An inner connector that records what it was asked to dial and connects to one address.
#[derive(Clone)]
struct Direct {
    to: SocketAddr,
    dialled: Arc<Mutex<Vec<String>>>,
}

impl Service<http::Uri> for Direct {
    type Response = TokioIo<TcpStream>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = std::io::Result<TokioIo<TcpStream>>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: http::Uri) -> Self::Future {
        self.dialled.lock().unwrap().push(dst.to_string());
        let to = self.to;
        Box::pin(async move { Ok(TokioIo::new(TcpStream::connect(to).await?)) })
    }
}

#[tokio::test]
async fn connector_bypasses_no_proxy_and_follows_the_handle() {
    let dest_ca = ca("dest CA");
    let echo = tls_echo(server_config(
        &dest_ca,
        &["api.provider.test", "vault.corp.test"],
    ))
    .await;
    let proxy = TestProxy::start(Options {
        redirect: Some(echo),
        ..Options::default()
    })
    .await;
    let handle = ProxyHandle::new();
    let dialled = Arc::new(Mutex::new(Vec::new()));
    let mut conn = ProxyConnector::new(
        Direct {
            to: echo,
            dialled: Arc::clone(&dialled),
        },
        handle.clone(),
        client_config(&dest_ca),
        T,
    );
    let client = client_config(&dest_ca);
    let mut send = async |uri: &str, name: &str| {
        let io = conn.call(uri.parse().unwrap()).await.unwrap();
        let tunnelled = io.is_tunnelled();
        let got = talk(TokioIo::new(io), &client, name, b"m").await.unwrap();
        assert_eq!(got, b"echo: m");
        tunnelled
    };

    // No proxy: direct.
    assert!(!send("https://api.provider.test", "api.provider.test").await);
    // A proxy: tunnelled, except NO_PROXY destinations.
    handle.set(Some(
        UpstreamProxy::new(&format!("http://{}", proxy.addr()), &["corp.test"], "", b"").unwrap(),
    ));
    assert!(send("https://api.provider.test", "api.provider.test").await);
    assert!(!send("https://vault.corp.test:8200", "vault.corp.test").await);
    assert_eq!(
        proxy
            .seen()
            .iter()
            .map(|s| s.target.clone())
            .collect::<Vec<_>>(),
        ["api.provider.test:443"]
    );
    assert_eq!(
        *dialled.lock().unwrap(),
        [
            "https://api.provider.test/",
            "https://vault.corp.test:8200/"
        ]
    );
    // Back to direct after the handle is cleared.
    handle.set(None);
    assert!(!send("https://api.provider.test", "api.provider.test").await);
    assert_eq!(proxy.seen().len(), 1);
}
