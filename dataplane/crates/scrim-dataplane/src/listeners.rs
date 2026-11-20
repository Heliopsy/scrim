// SPDX-License-Identifier: AGPL-3.0-only

//! The listeners (design D8), bound from the snapshot's listener list.
//!
//! | Kind | Address | Served by |
//! | --- | --- | --- |
//! | `BASE_URL` | `host:port` | the LLM proxy: agents set their provider base URL to it |
//! | `UNIX` | socket path (mode 0600) | the LLM proxy, as above |
//! | `FORWARD_PROXY`, `TOOL_PROXY` | `host:port` | the HTTPS tool proxy (`CONNECT` with TLS interception); provider hosts of the LLM routes are handed to the LLM proxy |
//! | `TRANSPARENT` | | not implemented yet: reported unbound |
//!
//! A listener that cannot be bound, or whose kind is not implemented, reports itself unbound
//! with the reason, which keeps the data plane not ready: nothing is served that cannot be
//! redacted.
//!
//! Each apply reconciles: listeners whose kind and address are unchanged keep running, new ones
//! are bound, removed or changed ones are stopped (in-flight requests finish).

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use scrim_proto::v1;
use tokio::sync::oneshot;

use crate::engine::Shared;
use crate::metrics::{DataPlaneMetrics, ProxyListener};

#[derive(Debug)]
struct Running {
    kind: i32,
    address: String,
    status: v1::ListenerStatus,
    stop: Option<oneshot::Sender<()>>,
    /// The Unix socket this listener created, removed when it stops.
    socket: Option<Socket>,
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        // Removed now rather than when the server task ends: the process may exit first, and a
        // listener for the same path started next must find the path free.
        if let Some(s) = self.socket.take() {
            s.remove_if_ours();
        }
    }
}

/// A socket file and the identity it had when bound.
#[derive(Debug)]
struct Socket {
    path: PathBuf,
    id: (u64, u64),
}

impl Socket {
    fn new(path: PathBuf) -> Option<Self> {
        socket_id(&path).map(|id| Self { path, id })
    }

    /// Removes the file only while it is still the socket this listener bound.
    fn remove_if_ours(&self) {
        if socket_id(&self.path) == Some(self.id) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// The set of listeners in force.
#[derive(Debug, Default)]
pub struct Listeners {
    running: Mutex<BTreeMap<String, Running>>,
}

impl Listeners {
    /// Binds, keeps or stops listeners so they match `want`. Must run inside a tokio runtime.
    pub fn reconcile(&self, want: &[v1::Listener], shared: &Shared) {
        let Ok(mut running) = self.running.lock() else {
            return;
        };
        running.retain(|name, r| {
            want.iter()
                .any(|l| &l.name == name && l.kind == r.kind && l.address == r.address)
        });
        for l in want {
            if running.contains_key(&l.name) {
                continue;
            }
            let r = start(l, shared);
            running.insert(l.name.clone(), r);
        }
    }

    /// Stops every listener.
    pub fn stop_all(&self) {
        if let Ok(mut running) = self.running.lock() {
            running.clear();
        }
    }

    /// The status of each listener.
    pub fn status(&self) -> Vec<v1::ListenerStatus> {
        self.running.lock().map_or_else(
            |_| Vec::new(),
            |r| r.values().map(|r| r.status.clone()).collect(),
        )
    }

    /// Whether any bound listener serves the tool proxy.
    pub fn serves_tool_proxy(&self) -> bool {
        self.serves(is_proxy)
    }

    fn serves(&self, kind: impl Fn(i32) -> bool) -> bool {
        self.running
            .lock()
            .is_ok_and(|r| r.values().any(|r| kind(r.kind) && r.status.bound))
    }
}

fn is_proxy(kind: i32) -> bool {
    kind == v1::ListenerKind::ToolProxy as i32 || kind == v1::ListenerKind::ForwardProxy as i32
}

fn start(l: &v1::Listener, shared: &Shared) -> Running {
    let mut status = v1::ListenerStatus {
        name: l.name.clone(),
        address: l.address.clone(),
        bound: false,
        error: String::new(),
        kind: l.kind,
    };
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let shutdown = async {
        let _ = stop_rx.await;
    };
    let name = l.name.clone();
    let mut socket = None;
    let result = match l.kind() {
        v1::ListenerKind::ToolProxy | v1::ListenerKind::ForwardProxy => {
            bind_tcp(&l.address).map(|listener| {
                status.address = local(&listener, &l.address);
                let proxy = shared.tool_proxy.clone();
                match shared.metrics.clone() {
                    None => {
                        tokio::spawn(async move {
                            if let Err(err) = proxy.serve(listener, shutdown).await {
                                tracing::error!(listener = name.as_str(), %err, "tool proxy listener failed");
                            }
                        });
                    }
                    Some(m) => {
                        let kind = if l.kind() == v1::ListenerKind::ForwardProxy {
                            ProxyListener::ForwardProxy
                        } else {
                            ProxyListener::ToolProxy
                        };
                        tokio::spawn(serve_counted(proxy, listener, shutdown, m, kind));
                    }
                }
                "tool proxy"
            })
        }
        v1::ListenerKind::BaseUrl => bind_tcp(&l.address).map(|listener| {
            status.address = local(&listener, &l.address);
            let llm = shared.llm.clone();
            tokio::spawn(scrim_llm::server::serve_tcp(listener, llm, shutdown));
            "LLM proxy"
        }),
        v1::ListenerKind::Unix => {
            let path = PathBuf::from(&l.address);
            scrim_llm::server::bind_unix(&path).map(|listener| {
                socket = Socket::new(path);
                let llm = shared.llm.clone();
                tokio::spawn(scrim_llm::server::serve_unix(listener, llm, shutdown));
                "LLM proxy"
            })
        }
        other => {
            status.error = format!(
                "listener kind {} is not implemented yet",
                other.as_str_name()
            );
            return Running {
                kind: l.kind,
                address: l.address.clone(),
                status,
                stop: None,
                socket: None,
            };
        }
    };
    let stop = match result {
        Ok(what) => {
            tracing::info!(
                listener = l.name.as_str(),
                kind = l.kind().as_str_name(),
                address = status.address.as_str(),
                "{what} listening"
            );
            status.bound = true;
            Some(stop_tx)
        }
        Err(err) => {
            tracing::error!(listener = l.name.as_str(), address = l.address.as_str(), %err, "cannot bind listener");
            status.error = format!("cannot bind {}: {err}", l.address);
            None
        }
    };
    Running {
        kind: l.kind,
        address: l.address.clone(),
        status,
        stop,
        socket,
    }
}

/// The tool proxy's accept loop ([`scrim_toolproxy::ToolProxy::serve`]) with each connection
/// counted while it is open.
async fn serve_counted(
    proxy: scrim_toolproxy::ToolProxy,
    listener: tokio::net::TcpListener,
    shutdown: impl std::future::Future<Output = ()>,
    metrics: std::sync::Arc<DataPlaneMetrics>,
    kind: ProxyListener,
) {
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => return,
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed");
                        continue;
                    }
                };
                let _ = stream.set_nodelay(true);
                let open = metrics.connection(kind);
                let proxy = proxy.clone();
                tokio::spawn(async move {
                    proxy.serve_connection(stream, Some(peer)).await;
                    drop(open);
                });
            }
        }
    }
}

fn bind_tcp(address: &str) -> std::io::Result<tokio::net::TcpListener> {
    let s = std::net::TcpListener::bind(address)?;
    s.set_nonblocking(true)?;
    tokio::net::TcpListener::from_std(s)
}

/// The bound address (with the real port when the snapshot asked for port 0).
fn local(listener: &tokio::net::TcpListener, asked: &str) -> String {
    listener
        .local_addr()
        .map_or_else(|_| asked.to_owned(), |a| a.to_string())
}

fn socket_id(path: &Path) -> Option<(u64, u64)> {
    std::fs::symlink_metadata(path)
        .ok()
        .map(|m| (m.dev(), m.ino()))
}
