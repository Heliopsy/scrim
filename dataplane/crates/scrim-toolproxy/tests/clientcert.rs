//! Client certificates toward upstreams through a real proxy listener (credential-injection spec,
//! "Client certificates toward upstreams"). The upstream requires a certificate from its own
//! client CA; the agent only holds the placeholder certificate.
#![allow(
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    unreachable_pub
)]

mod common;

use bytes::Bytes;
use common::*;
use http::StatusCode;
use scrim_toolproxy::*;

const DECLARED: &str = "SCRIM_KIND_ADMIN_CERT";

struct World {
    proxy: Proxy,
    up: Upstream,
    plain: Upstream,
    real_pem: String,
}

fn config(port: u16, plain_port: u16) -> String {
    format!(
        r"
credentials:
  - name: kube-admin
    reference: env://KUBE_ADMIN
    placeholders: [{DECLARED}]
    binding: {{ hosts: ['kube.acme.test:{port}'], paths: ['/api/*', '/version'] }}
    client_certificate: true
  - name: other
    reference: env://OTHER
    placeholders: [SCRIM_OTHER_TOKEN]
    binding: {{ hosts: ['plain.acme.test:{plain_port}'] }}
"
    )
}

async fn world() -> World {
    let ca = UpstreamCa::new();
    let client_ca = UpstreamCa::new();
    let up = tls_upstream_with(
        ca.server_config_mtls(&["kube.acme.test", "evil.test"], &client_ca),
        echo_handler(),
    )
    .await;
    let plain = tls_upstream(&ca, &["plain.acme.test"], echo_handler()).await;
    let mut opts = ProxyOptions::default();
    opts.roots.push(ca.der());
    opts.hosts.push(("kube.acme.test".into(), up.addr));
    opts.hosts.push(("evil.test".into(), up.addr));
    opts.hosts.push(("plain.acme.test".into(), plain.addr));
    let proxy = start_proxy(opts).await;
    let real_pem = client_ca.client_identity_pem("system:admin");
    proxy
        .proxy
        .apply(snapshot(
            &config(up.port(), plain.port()),
            &[
                ("env://KUBE_ADMIN", &real_pem),
                ("env://OTHER", "other-value-0a1b2c3d4e5f"),
            ],
        ))
        .unwrap();
    World {
        proxy,
        up,
        plain,
        real_pem,
    }
}

fn agent(w: &World, identity: Option<String>) -> Client {
    let mut c = Client::new(&w.proxy);
    c.identity = identity;
    c
}

fn placeholder_identity(ph: &str) -> String {
    let (cert, key) = placeholder_certificate(ph, "scrim placeholder kube-admin").unwrap();
    format!("{cert}{key}")
}

async fn get(c: &Client, host: &str, port: u16, path: &str) -> Got {
    c.send(
        host,
        port,
        req("GET", host, port, path)
            .body(body(Bytes::new()))
            .unwrap(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn placeholder_certificate_gets_the_real_one_presented_upstream() {
    let w = world().await;
    let c = agent(&w, Some(placeholder_identity(DECLARED)));
    let got = get(&c, "kube.acme.test", w.up.port(), "/api/v1/namespaces").await;
    assert_eq!(got.status, StatusCode::OK, "{}", got.text());
    assert_eq!(w.up.seen().len(), 1);
    // The audit names the credential, never its value.
    let texts = audit_texts(&w.proxy);
    assert!(texts.iter().any(|t| t.contains("kube-admin")), "{texts:?}");
    for t in texts.iter().chain([&got.text()]) {
        assert!(
            !t.contains("PRIVATE KEY") && !t.contains(&w.real_pem[30..90]),
            "{t}"
        );
    }
}

#[tokio::test]
async fn without_the_placeholder_certificate_nothing_is_presented() {
    let w = world().await;
    // No certificate, or a certificate that is not a placeholder: the upstream handshake has no
    // client certificate and fails.
    for id in [None, Some(placeholder_identity("SCRIM_SOMETHING_ELSE"))] {
        let c = agent(&w, id);
        let got = get(&c, "kube.acme.test", w.up.port(), "/api/v1/namespaces").await;
        assert_eq!(
            got.error_code().as_deref(),
            Some("upstream_unavailable"),
            "{}",
            got.text()
        );
    }
    assert!(w.up.seen().is_empty());
}

#[tokio::test]
async fn bindings_apply_to_the_certificate() {
    let w = world().await;
    let c = agent(&w, Some(placeholder_identity(DECLARED)));
    let got = get(&c, "kube.acme.test", w.up.port(), "/admin").await;
    assert_eq!(
        got.error_code().as_deref(),
        Some("unbound_destination"),
        "{}",
        got.text()
    );
    assert!(w.up.seen().is_empty());
}

#[tokio::test]
async fn the_proxy_asks_for_a_certificate_only_toward_bound_hosts() {
    let w = world().await;
    // A client with a certificate toward a host no certificate credential is bound to: the proxy
    // does not ask, so nothing is presented and the request goes through without one.
    let c = agent(&w, Some(placeholder_identity(DECLARED)));
    let got = get(&c, "plain.acme.test", w.plain.port(), "/x").await;
    assert_eq!(got.status, StatusCode::OK, "{}", got.text());
    assert_eq!(w.plain.seen().len(), 1);
}

#[tokio::test]
async fn the_certificate_value_is_never_sent_as_text() {
    let w = world().await;
    let c = agent(&w, None);
    let got = c
        .send(
            "kube.acme.test",
            w.up.port(),
            req("GET", "kube.acme.test", w.up.port(), "/api/v1/x")
                .header("authorization", format!("Bearer {DECLARED}"))
                .body(body(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        got.error_code().as_deref(),
        Some("undeclared_location"),
        "{}",
        got.text()
    );
    assert!(w.up.seen().is_empty());
}
