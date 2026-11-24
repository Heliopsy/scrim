// SPDX-License-Identifier: AGPL-3.0-only

//! The boundary protocol from the client side, over a real socketpair (an in-memory duplex
//! stream where there are no Unix sockets).

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use scrim_dataplane::engine::{Engine, Shared};
use scrim_dataplane::harden::Hardening;
use scrim_proto::v1;
use scrim_proto::v1::data_plane_client::DataPlaneClient;
use tokio::task::JoinHandle;
use tonic::transport::{Channel, Endpoint};

type Served = JoinHandle<std::io::Result<()>>;

#[cfg(unix)]
fn pair() -> (tokio::net::UnixStream, tokio::net::UnixStream) {
    tokio::net::UnixStream::pair().unwrap()
}

// Windows has no socketpair; the server is generic over the stream.
#[cfg(not(unix))]
fn pair() -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
    tokio::io::duplex(1 << 16)
}

async fn connect() -> (DataPlaneClient<Channel>, Arc<Shared>, Served) {
    let (ours, theirs) = pair();
    let shared = Arc::new(Shared::new().unwrap());
    let server = tokio::spawn(scrim_dataplane::server::serve(
        theirs,
        Arc::clone(&shared),
        Hardening::default(),
    ));
    let slot = Arc::new(Mutex::new(Some(ours)));
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
    (DataPlaneClient::new(channel), shared, server)
}

fn snapshot(version: u64) -> v1::Snapshot {
    let mut value = v1::ValueEntry::default();
    value.r#ref = "bao://kv/agents/github#token".into();
    value.slug = "github".into();
    value.value = format!("test-{version}-{:x}", std::process::id()).into_bytes();
    value.bound_hosts = vec!["api.github.com".into()];
    let mut key = v1::PlaceholderKey::default();
    key.version = 1;
    key.key = vec![7; 32];
    key.current = true;
    v1::Snapshot {
        protocol: v1::PROTOCOL,
        version,
        values: vec![value],
        placeholder_keys: vec![key],
        ..Default::default()
    }
}

#[tokio::test]
async fn handshake_snapshot_status_and_shutdown() {
    let (mut c, shared, server) = connect().await;

    let hello = c
        .hello(v1::HelloRequest {
            protocol: v1::PROTOCOL,
            control_plane_version: "test".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(hello.protocol, v1::PROTOCOL);
    assert_eq!(hello.applied_snapshot_version, 0);

    let err = c
        .hello(v1::HelloRequest {
            protocol: 99,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);

    let applied = c.apply_snapshot(snapshot(5)).await.unwrap().into_inner();
    assert_eq!((applied.applied_version, applied.value_count), (5, 1));
    let stale = c.apply_snapshot(snapshot(5)).await.unwrap_err();
    assert_eq!(stale.code(), tonic::Code::InvalidArgument);
    assert!(!stale.message().contains("test-5"), "error echoes a value");

    let engine = Engine::new(Arc::clone(&shared));
    assert_eq!(engine.snapshot().map(|s| s.version), Some(5));

    let status = c
        .status(v1::StatusRequest {
            protocol: v1::PROTOCOL,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(status.ready);
    assert_eq!(status.applied_snapshot_version, 5);
    assert_eq!(status.policy_engine, scrim_dataplane::policy::ENGINE);
    let redaction = status.redaction.unwrap();
    assert_eq!(redaction.engine, "aho-corasick");
    assert!(redaction.patterns > 0 && redaction.unprotected_refs.is_empty());

    let mut events = c
        .events(v1::EventsRequest {
            protocol: v1::PROTOCOL,
        })
        .await
        .unwrap()
        .into_inner();
    engine.emit(v1::Event {
        kind: v1::EventKind::Redaction.into(),
        ..Default::default()
    });
    let batch = tokio::time::timeout(Duration::from_secs(5), events.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(batch.events.len(), 1);
    let second = c
        .events(v1::EventsRequest {
            protocol: v1::PROTOCOL,
        })
        .await;
    assert!(
        second.is_err(),
        "a second events subscriber must be refused"
    );

    drop(events);
    drop(c);
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        shared.snapshot.load().is_none(),
        "the dictionary must be dropped at shutdown"
    );
}

#[tokio::test]
async fn asks_round_trip_and_deny_on_disconnect() {
    let (mut c, shared, _server) = connect().await;
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let mut asks = c
        .asks(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    let engine = Engine::new(Arc::clone(&shared));

    let waiter = tokio::spawn({
        let engine = engine.clone();
        async move {
            let req = v1::PolicyRequest {
                host: "api.github.com".into(),
                ..Default::default()
            };
            engine.ask(req, "gh", "push", Duration::from_secs(5)).await
        }
    });
    let req = asks.message().await.unwrap().unwrap();
    assert_eq!(
        req.request.as_ref().map(|r| r.host.as_str()),
        Some("api.github.com")
    );
    tx.send(v1::AskAnswer {
        protocol: v1::PROTOCOL,
        id: req.id,
        effect: v1::Effect::Allow.into(),
        ..Default::default()
    })
    .await
    .unwrap();
    assert!(waiter.await.unwrap().allowed);

    drop(tx);
    drop(asks);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let denied = engine
        .ask(
            v1::PolicyRequest::default(),
            "gh",
            "push",
            Duration::from_secs(1),
        )
        .await;
    assert!(!denied.allowed);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn tool_proxy_listener_ca_and_captures() {
    let (mut c, shared, _server) = connect().await;
    let mut snap = snapshot(1);
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    snap.listeners = vec![
        v1::Listener {
            name: "transparent".into(),
            kind: v1::ListenerKind::Transparent.into(),
            address: "127.0.0.1:0".into(),
            ..Default::default()
        },
        v1::Listener {
            name: "tools".into(),
            kind: v1::ListenerKind::ToolProxy.into(),
            address: "127.0.0.1:0".into(),
            ..Default::default()
        },
        v1::Listener {
            name: "llm".into(),
            kind: v1::ListenerKind::BaseUrl.into(),
            address: "127.0.0.1:0".into(),
            ..Default::default()
        },
        v1::Listener {
            name: "sni".into(),
            kind: v1::ListenerKind::Sni.into(),
            address: taken.local_addr().unwrap().to_string(),
            ..Default::default()
        },
    ];
    c.apply_snapshot(snap).await.unwrap();

    let status = c
        .status(v1::StatusRequest {
            protocol: v1::PROTOCOL,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(
        status
            .ca_trust_bundle_pem
            .starts_with("-----BEGIN CERTIFICATE-----")
    );
    let tools = status.listeners.iter().find(|l| l.name == "tools").unwrap();
    assert!(tools.bound, "{tools:?}");
    assert!(!tools.address.ends_with(":0"), "the bound port is reported");
    let llm = status.listeners.iter().find(|l| l.name == "llm").unwrap();
    assert!(
        llm.bound && llm.kind() == v1::ListenerKind::BaseUrl,
        "{llm:?}"
    );
    let transparent = status
        .listeners
        .iter()
        .find(|l| l.name == "transparent")
        .unwrap();
    // Transparent listeners need SO_ORIGINAL_DST, which only Linux has.
    assert_eq!(
        transparent.bound,
        cfg!(target_os = "linux"),
        "{transparent:?}"
    );
    let sni = status.listeners.iter().find(|l| l.name == "sni").unwrap();
    assert!(!sni.bound && sni.error.contains("cannot bind"), "{sni:?}");
    assert!(
        !status.ready,
        "an unbound listener keeps the data plane not ready"
    );
    assert_eq!(status.tool_proxy.map(|t| t.snapshot_version), Some(1));

    // A captured value goes to the control plane, which answers with the
    // placeholder.
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let mut captures = c
        .captures(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    let broker = Arc::clone(&shared.captures);
    let pending = tokio::spawn(async move {
        broker
            .capture(
                scrim_toolproxy::CaptureRequest {
                    rule: "issued".into(),
                    reference: "mem://captured#token".into(),
                    destination: "https://api.example:443".into(),
                    value: scrim_toolproxy::SecretValue::new("issued-by-a-fake-api"),
                },
                Duration::from_secs(5),
            )
            .await
    });
    let req = captures.message().await.unwrap().unwrap();
    assert_eq!(req.value, b"issued-by-a-fake-api");
    assert!(!format!("{req:?}").contains("issued-by-a-fake-api"));
    tx.send(v1::CaptureResult {
        protocol: v1::PROTOCOL,
        id: req.id,
        placeholder: "SCRIM_CAPTURED_TOKEN".into(),
        error: String::new(),
    })
    .await
    .unwrap();
    assert_eq!(
        pending.await.unwrap().ok().as_deref(),
        Some("SCRIM_CAPTURED_TOKEN")
    );

    // Removing the listener stops it.
    c.apply_snapshot(snapshot(2)).await.unwrap();
    let status = c
        .status(v1::StatusRequest {
            protocol: v1::PROTOCOL,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(status.listeners.is_empty() && status.ready);
}
