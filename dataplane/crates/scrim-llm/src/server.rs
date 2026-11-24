// SPDX-License-Identifier: AGPL-3.0-only

//! Base-URL listeners: TCP and Unix socket, HTTP/1.1 and HTTP/2 (prior knowledge, `h2c`) on the
//! same port, with graceful shutdown.

use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::metrics::Listener;
use crate::proxy::Proxy;

/// How long in-flight requests may run after shutdown starts.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(30);

fn builder() -> auto::Builder<TokioExecutor> {
    let mut b = auto::Builder::new(TokioExecutor::new());
    b.http1()
        .keep_alive(true)
        .timer(hyper_util::rt::TokioTimer::new());
    b.http2()
        .timer(hyper_util::rt::TokioTimer::new())
        .max_concurrent_streams(1024);
    b
}

/// The peer credentials of a Unix socket connection, as the kernel reports them. Attached to
/// every request that arrives over [`serve_unix`] as a request extension, so a
/// [`crate::RequestGate`] can identify the caller by the transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnixPeer {
    /// User id.
    pub uid: u32,
    /// Group id.
    pub gid: u32,
    /// Process id, when the platform reports it.
    pub pid: Option<i32>,
}

fn serve_conn<S, E>(
    io: S,
    proxy: Arc<Proxy>,
    graceful: &GracefulShutdown,
    ext: Option<E>,
    listener: Listener,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    E: Clone + Send + Sync + 'static,
{
    let open = proxy.metrics().map(|m| m.connection(listener));
    let svc = service_fn(move |mut req: hyper::Request<Incoming>| {
        let p = proxy.clone();
        if let Some(ext) = &ext {
            req.extensions_mut().insert(ext.clone());
        }
        async move { Ok::<_, Infallible>(p.handle(req).await) }
    });
    let conn = builder()
        .serve_connection_with_upgrades(TokioIo::new(io), svc)
        .into_owned();
    let conn = graceful.watch(conn);
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "connection ended with an error");
        }
        drop(open);
    });
}

async fn drain(graceful: GracefulShutdown) {
    tokio::select! {
        () = graceful.shutdown() => {}
        () = tokio::time::sleep(SHUTDOWN_GRACE) => tracing::warn!("shutdown grace period over, closing connections"),
    }
}

/// Serves `proxy` on a bound TCP listener until `shutdown` resolves, then drains connections.
pub async fn serve_tcp(
    listener: tokio::net::TcpListener,
    proxy: Arc<Proxy>,
    shutdown: impl Future<Output = ()>,
) {
    let graceful = GracefulShutdown::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            r = listener.accept() => match r {
                Ok((stream, _)) => {
                    let _ = stream.set_nodelay(true);
                    serve_conn::<_, UnixPeer>(stream, proxy.clone(), &graceful, None, Listener::BaseUrl);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            },
            () = &mut shutdown => break,
        }
    }
    drain(graceful).await;
}

/// Serves `proxy` on a bound TCP listener whose connections first go through `handshake` (TLS,
/// for example) until `shutdown` resolves, then drains connections. Each handshake runs on its
/// own task; a connection it returns is served with `ext` inserted into every request's
/// extensions (the client's verified identity, for example), one it drops (`None`) is closed.
pub async fn serve_tcp_with<H, F, S, E>(
    listener: tokio::net::TcpListener,
    proxy: Arc<Proxy>,
    shutdown: impl Future<Output = ()>,
    handshake: H,
) where
    H: Fn(tokio::net::TcpStream, std::net::SocketAddr) -> F,
    F: Future<Output = Option<(S, E)>> + Send + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    E: Clone + Send + Sync + 'static,
{
    let graceful = GracefulShutdown::new();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(S, E)>(64);
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            r = listener.accept() => match r {
                Ok((stream, peer)) => {
                    let _ = stream.set_nodelay(true);
                    let done = handshake(stream, peer);
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        if let Some(conn) = done.await {
                            let _ = tx.send(conn).await;
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            },
            Some((io, ext)) = rx.recv() => {
                serve_conn(io, proxy.clone(), &graceful, Some(ext), Listener::BaseUrl);
            }
            () = &mut shutdown => break,
        }
    }
    drain(graceful).await;
}

/// Binds a Unix socket at `path` with mode 0600, replacing a stale socket file. Refuses to
/// replace anything that is not a socket.
#[cfg(unix)]
pub fn bind_unix(path: &std::path::Path) -> std::io::Result<tokio::net::UnixListener> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    match std::fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let l = tokio::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(l)
}

/// Serves `proxy` on a Unix socket listener until `shutdown` resolves.
#[cfg(unix)]
pub async fn serve_unix(
    listener: tokio::net::UnixListener,
    proxy: Arc<Proxy>,
    shutdown: impl Future<Output = ()>,
) {
    let graceful = GracefulShutdown::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            r = listener.accept() => match r {
                Ok((stream, _)) => {
                    // A connection whose peer cannot be read is still served: it is an unknown
                    // caller, which is what the gate assumes without credentials.
                    let peer = stream.peer_cred().ok().map(|c| UnixPeer {
                        uid: c.uid(),
                        gid: c.gid(),
                        pid: c.pid(),
                    });
                    serve_conn(stream, proxy.clone(), &graceful, peer, Listener::Unix);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            },
            () = &mut shutdown => break,
        }
    }
    drain(graceful).await;
}
