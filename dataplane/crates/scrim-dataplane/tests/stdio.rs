// SPDX-License-Identifier: AGPL-3.0-only

//! The real `scrim-dataplane` binary over the stdio transport, the way the control plane starts
//! it on Windows: `--stdio`, gRPC over the child's stdin and stdout, JSON logs on stderr, and EOF
//! on stdin shuts it down. Runs on every platform.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use scrim_proto::v1;
use scrim_proto::v1::data_plane_client::DataPlaneClient;
use tokio::io::AsyncReadExt;
use tonic::transport::Endpoint;

fn command() -> tokio::process::Command {
    let mut c = tokio::process::Command::new(env!("CARGO_BIN_EXE_scrim-dataplane"));
    c.env_remove("SCRIM_DP_FD")
        .env_remove("SCRIM_DP_STDIO")
        .env("SCRIM_DP_MLOCK", "off")
        .env("SCRIM_DP_LOG", "debug")
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    c
}

/// Collects the child's stderr in the background.
fn collect_stderr(child: &mut tokio::process::Child) -> Arc<Mutex<Vec<u8>>> {
    let out = Arc::new(Mutex::new(Vec::new()));
    let mut pipe = child.stderr.take().unwrap();
    let sink = Arc::clone(&out);
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok(n) = pipe.read(&mut buf).await {
            if n == 0 {
                break;
            }
            sink.lock().unwrap().extend_from_slice(&buf[..n]);
        }
    });
    out
}

fn text(buf: &Arc<Mutex<Vec<u8>>>) -> String {
    String::from_utf8_lossy(&buf.lock().unwrap()).into_owned()
}

#[tokio::test]
async fn hello_over_stdio_then_exit_on_eof() {
    let mut child = command()
        .arg("--stdio")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = collect_stderr(&mut child);
    let stream = tokio::io::join(child.stdout.take().unwrap(), child.stdin.take().unwrap());
    let slot = Arc::new(Mutex::new(Some(stream)));
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
    let hello = tokio::time::timeout(
        Duration::from_secs(20),
        client.hello(v1::HelloRequest {
            protocol: v1::PROTOCOL,
            control_plane_version: "stdio-test".into(),
        }),
    )
    .await
    .unwrap_or_else(|_| panic!("no Hello answer; stderr: {}", text(&stderr)))
    .unwrap()
    .into_inner();
    assert_eq!(hello.protocol, v1::PROTOCOL);
    assert_eq!(hello.data_plane_version, scrim_dataplane::VERSION);
    assert_eq!(hello.applied_snapshot_version, 0);
    assert_eq!(hello.pid, child.id().unwrap());
    assert!(!hello.memory_locked);

    let status = client
        .status(v1::StatusRequest {
            protocol: v1::PROTOCOL,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!status.ready, "no snapshot applied yet");

    // Dropping the client closes the child's stdin: the control plane went away.
    drop(client);
    let exit = tokio::time::timeout(Duration::from_secs(20), child.wait())
        .await
        .unwrap_or_else(|_| panic!("still running after EOF; stderr: {}", text(&stderr)))
        .unwrap();
    // Give the reader a moment to drain the last lines.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let logs = text(&stderr);
    assert!(exit.success(), "{exit:?}; stderr: {logs}");
    assert!(logs.contains("control plane connected"), "{logs}");
    for line in logs.lines().filter(|l| !l.is_empty()) {
        assert!(line.starts_with('{'), "stderr is JSON lines: {line}");
    }
}

#[tokio::test]
async fn refuses_to_start_without_a_connection() {
    let mut child = command()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = collect_stderr(&mut child);
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .await
        .unwrap();
    let exit = tokio::time::timeout(Duration::from_secs(20), child.wait())
        .await
        .unwrap()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let logs = text(&stderr);
    assert_eq!(exit.code(), Some(2), "{logs}");
    assert!(stdout.is_empty(), "nothing on stdout");
    assert!(logs.contains("--fd") && logs.contains("--stdio"), "{logs}");
}

// Descriptor inheritance only exists on Unix.
#[cfg(not(unix))]
#[tokio::test]
async fn refuses_fd_on_windows() {
    let mut child = command()
        .args(["--fd", "3"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let stderr = collect_stderr(&mut child);
    let exit = tokio::time::timeout(Duration::from_secs(20), child.wait())
        .await
        .unwrap()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let logs = text(&stderr);
    assert_eq!(exit.code(), Some(2), "{logs}");
    assert!(logs.contains("--stdio"), "{logs}");
}
