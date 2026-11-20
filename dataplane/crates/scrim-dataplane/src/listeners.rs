// SPDX-License-Identifier: AGPL-3.0-only

//! The listeners (design D8), bound from the snapshot's listener list.
//!
//! `TOOL_PROXY` and `FORWARD_PROXY` listeners serve the HTTPS tool proxy
//! (CONNECT with TLS interception; model provider hosts reach the LLM proxy
//! through its intercept hook once that exists). Other kinds are not
//! implemented yet and report themselves unbound, which keeps the data plane
//! not ready: nothing is served that cannot be redacted.
//!
//! Each apply reconciles: listeners whose kind and address are unchanged
//! keep running, new ones are bound, removed or changed ones are stopped.

use std::collections::BTreeMap;
use std::sync::Mutex;

use scrim_proto::v1;
use scrim_toolproxy::ToolProxy;
use tokio::sync::oneshot;

#[derive(Debug)]
struct Running {
    kind: i32,
    address: String,
    status: v1::ListenerStatus,
    stop: Option<oneshot::Sender<()>>,
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

/// The set of listeners in force.
#[derive(Debug, Default)]
pub struct Listeners {
    running: Mutex<BTreeMap<String, Running>>,
}

impl Listeners {
    /// Binds, keeps or stops listeners so they match `want`. Must run inside
    /// a tokio runtime.
    pub fn reconcile(&self, want: &[v1::Listener], proxy: &ToolProxy) {
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
            let r = start(l, proxy);
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

    /// Whether any listener serves the tool proxy.
    pub fn serves_tool_proxy(&self) -> bool {
        self.running
            .lock()
            .is_ok_and(|r| r.values().any(|r| is_proxy(r.kind) && r.status.bound))
    }
}

fn is_proxy(kind: i32) -> bool {
    kind == v1::ListenerKind::ToolProxy as i32 || kind == v1::ListenerKind::ForwardProxy as i32
}

fn start(l: &v1::Listener, proxy: &ToolProxy) -> Running {
    let mut status = v1::ListenerStatus {
        name: l.name.clone(),
        address: l.address.clone(),
        bound: false,
        error: String::new(),
    };
    let mut r = Running {
        kind: l.kind,
        address: l.address.clone(),
        status: status.clone(),
        stop: None,
    };
    if !is_proxy(l.kind) {
        status.error = format!(
            "listener kind {} is not implemented yet",
            l.kind().as_str_name()
        );
        r.status = status;
        return r;
    }
    let bound = std::net::TcpListener::bind(&l.address)
        .and_then(|s| {
            s.set_nonblocking(true)?;
            Ok(s)
        })
        .and_then(tokio::net::TcpListener::from_std);
    match bound {
        Ok(listener) => {
            if let Ok(addr) = listener.local_addr() {
                status.address = addr.to_string();
            }
            let (stop_tx, stop_rx) = oneshot::channel::<()>();
            let proxy = proxy.clone();
            let name = l.name.clone();
            tokio::spawn(async move {
                let shutdown = async {
                    let _ = stop_rx.await;
                };
                if let Err(err) = proxy.serve(listener, shutdown).await {
                    tracing::error!(listener = name.as_str(), %err, "tool proxy listener failed");
                }
            });
            tracing::info!(
                listener = l.name.as_str(),
                address = status.address.as_str(),
                "tool proxy listening"
            );
            status.bound = true;
            r.stop = Some(stop_tx);
        }
        Err(err) => {
            tracing::error!(listener = l.name.as_str(), address = l.address.as_str(), %err, "cannot bind listener");
            status.error = format!("cannot bind {}: {err}", l.address);
        }
    }
    r.status = status;
    r
}
