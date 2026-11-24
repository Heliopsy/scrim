//! Connections that reach scrim without asking for it: the transparent listener (connections
//! redirected by nftables, task 13.3) and the SNI listener (names resolved to scrim, task 15.2).
//!
//! Neither kind of client says where it wants to go, so the destination comes from the
//! connection itself: the TLS server name (SNI) of the client hello, or the `Host` header of a
//! plain HTTP request, with the port of the original destination. Then:
//!
//! - a host scrim routes (a provider host of the LLM proxy, or a host a credential binding or
//!   capture rule names) is intercepted exactly like a `CONNECT` tunnel to it;
//! - any other host is passed through untouched, connecting to the name the client asked for
//!   (never to the address it dialled, so a connection by address cannot reach a provider under
//!   a borrowed name), or closed when the listener blocks unrouted hosts;
//! - a TLS connection without a server name cannot be routed and is always closed: passing it
//!   through would let a client reach a provider by address.
//!
//! Plain HTTP requests are proxied through the tool proxy (response redaction applies), or
//! refused when the listener blocks unrouted hosts.

use std::convert::Infallible;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::Request;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::server::Acceptor;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::body::full;
use crate::decide::ClientInfo;
use crate::error::{ErrorCode, Refusal};
use crate::host::{Destination, Scheme};
use crate::proxy::ToolProxy;

/// How long a client may take to send its TLS client hello or first request line.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest client hello read before giving up.
const MAX_HELLO: usize = 64 << 10;
/// Connect timeout of a passed-through connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// One accepted connection of a transparent or SNI listener.
#[derive(Clone, Copy, Debug)]
pub struct TransparentConn {
    /// The client's address.
    pub peer: Option<SocketAddr>,
    /// The port the client dialled: the original destination's port for a redirected connection,
    /// 443 for the SNI listener.
    pub port: u16,
    /// Where the client connected to, for audit entries: the original destination, or the
    /// listener address.
    pub dialled: Option<SocketAddr>,
    /// Close connections to hosts scrim does not route instead of passing them through.
    pub block_unrouted: bool,
    /// Only TLS is served (the SNI listener); plain HTTP is closed.
    pub tls_only: bool,
}

impl ToolProxy {
    /// Whether scrim intercepts connections to `dest`: a host another engine claims (a model
    /// provider) or a host a credential binding or capture rule names.
    pub fn routes(&self, dest: &Destination) -> bool {
        if let Some(h) = &self.shared.intercept
            && h.claims(dest)
        {
            return true;
        }
        let Some(engine) = self.shared.current() else {
            return false;
        };
        engine.credentials.credentials().iter().any(|c| {
            c.binding
                .as_ref()
                .is_some_and(|b| b.covers_destination(dest))
        }) || engine.capture_rules.iter().any(|r| r.matches_host(dest))
    }

    /// Serves one connection of a transparent or SNI listener (see the module documentation).
    pub async fn serve_transparent<IO>(&self, mut io: IO, conn: TransparentConn)
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let mut first = [0u8; 1];
        match tokio::time::timeout(HELLO_TIMEOUT, io.read(&mut first)).await {
            Ok(Ok(1)) => {}
            _ => return,
        }
        if first[0] == 0x16 {
            self.serve_tls(io, first[0], conn).await;
        } else if conn.tls_only {
            self.refused(&conn, None, "not TLS: this listener serves TLS only");
        } else {
            self.serve_http(Prefixed::new(Bytes::copy_from_slice(&first), io), conn)
                .await;
        }
    }

    async fn serve_tls<IO>(&self, mut io: IO, first: u8, conn: TransparentConn)
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let mut seen = vec![first];
        let mut acceptor = Acceptor::default();
        let mut feed: &[u8] = &seen[..];
        let _ = acceptor.read_tls(&mut feed);
        let sni = loop {
            match acceptor.accept() {
                Ok(Some(accepted)) => {
                    break accepted
                        .client_hello()
                        .server_name()
                        .map(|s| s.trim_end_matches('.').to_ascii_lowercase());
                }
                Ok(None) => {}
                Err((e, _)) => {
                    self.refused(&conn, None, &format!("no TLS client hello: {e}"));
                    return;
                }
            }
            if seen.len() > MAX_HELLO {
                self.refused(&conn, None, "TLS client hello too large");
                return;
            }
            let mut chunk = [0u8; 4096];
            let n = match tokio::time::timeout(HELLO_TIMEOUT, io.read(&mut chunk)).await {
                Ok(Ok(n)) if n > 0 => n,
                _ => return,
            };
            seen.extend_from_slice(&chunk[..n]);
            let mut feed: &[u8] = &chunk[..n];
            let _ = acceptor.read_tls(&mut feed);
        };
        let Some(sni) = sni.filter(|s| !s.is_empty() && s.parse::<IpAddr>().is_err()) else {
            self.refused(
                &conn,
                None,
                "TLS without a server name cannot be routed; connections by address are not passed through",
            );
            return;
        };
        let dest = Destination::new(Scheme::Https, &sni, conn.port);
        let io = Prefixed::new(Bytes::from(seen), io);
        if self.routes(&dest) {
            if self.shared.current().is_none() {
                self.refused(&conn, Some(&dest), "scrim has not loaded its snapshot yet");
                return;
            }
            let client = ClientInfo {
                peer: conn.peer,
                ..ClientInfo::default()
            };
            self.tunnel(dest, io, client).await;
        } else if conn.block_unrouted {
            self.refused(
                &conn,
                Some(&dest),
                "scrim has no route for this host and blocks unrouted hosts",
            );
        } else {
            self.pass_through(io, &dest, &conn).await;
        }
    }

    async fn serve_http<IO>(&self, io: Prefixed<IO>, conn: TransparentConn)
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let this = self.clone();
        let svc = service_fn(move |mut req: Request<Incoming>| {
            let this = this.clone();
            async move {
                let host = req
                    .headers()
                    .get(http::header::HOST)
                    .and_then(|h| h.to_str().ok())
                    .map(str::to_owned)
                    .or_else(|| req.uri().authority().map(|a| a.as_str().to_owned()));
                let dest = host.as_deref().and_then(|h| {
                    let mut d = Destination::from_authority(Scheme::Http, h)?;
                    if !h.contains(':') || h.ends_with(']') {
                        d.port = conn.port;
                    }
                    Some(d)
                });
                let Some(dest) = dest.filter(|d| d.host.parse::<IpAddr>().is_err()) else {
                    let r = Refusal::new(
                        ErrorCode::BadRequest,
                        "a request without a Host name cannot be routed",
                    );
                    return Ok::<_, Infallible>(r.to_response().map(full));
                };
                req.extensions_mut().insert(ClientInfo {
                    peer: conn.peer,
                    ..ClientInfo::default()
                });
                if this.routes(&dest) {
                    return Ok(this.route(dest, req, false).await);
                }
                if conn.block_unrouted {
                    this.refused(
                        &conn,
                        Some(&dest),
                        "scrim has no route for this host and blocks unrouted hosts",
                    );
                    let r = Refusal::new(
                        ErrorCode::PolicyDenied,
                        format!("scrim blocks {dest}: it has no route for this host"),
                    );
                    return Ok(r.to_response().map(full));
                }
                if resolves_here(&dest).await {
                    this.refused(
                        &conn,
                        Some(&dest),
                        "the name resolves to this host; not passed through",
                    );
                    let r = Refusal::new(
                        ErrorCode::PolicyDenied,
                        format!("scrim does not relay {dest}: the name resolves to this host"),
                    );
                    return Ok(r.to_response().map(full));
                }
                Ok(this.handle(dest, req).await)
            }
        });
        if let Err(e) = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(io), svc)
            .with_upgrades()
            .await
        {
            tracing::debug!(error = %e, "transparent HTTP connection ended with an error");
        }
    }

    /// Connects to the name the client asked for and relays bytes both ways, untouched.
    async fn pass_through<IO>(&self, io: Prefixed<IO>, dest: &Destination, conn: &TransparentConn)
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        // Through the upstream proxy: the proxy resolves the name (networks that only reach out
        // through it may have no outside DNS), and it is not this host, so the loop check below
        // does not apply.
        if let Some((proxy, tls, timeout)) = self.shared.upstreams.proxy_for(&dest.host, dest.port)
        {
            match scrim_upstream_proxy::connect(&proxy, &tls, &dest.host, dest.port, timeout).await
            {
                Ok(upstream) => relay(io, upstream, dest).await,
                Err(e) => {
                    tracing::debug!(destination = %dest, error = %e, "pass-through: upstream proxy");
                }
            }
            return;
        }
        let addrs = match tokio::net::lookup_host((dest.host.as_str(), dest.port)).await {
            Ok(a) => a.collect::<Vec<_>>(),
            Err(e) => {
                tracing::debug!(destination = %dest, error = %e, "pass-through: name does not resolve");
                return;
            }
        };
        // A name resolving to this host would come back to scrim (a DNS override, or a loop).
        if addrs.is_empty()
            || addrs
                .iter()
                .any(|a| a.ip().is_loopback() || a.ip().is_unspecified())
        {
            self.refused(
                conn,
                Some(dest),
                "the name resolves to this host; not passed through",
            );
            return;
        }
        let mut upstream = None;
        for a in &addrs {
            if let Ok(Ok(s)) =
                tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(a)).await
            {
                upstream = Some(s);
                break;
            }
        }
        let Some(upstream) = upstream else {
            tracing::debug!(destination = %dest, "pass-through: cannot connect");
            return;
        };
        let _ = upstream.set_nodelay(true);
        relay(io, upstream, dest).await;
    }

    fn refused(&self, conn: &TransparentConn, dest: Option<&Destination>, reason: &str) {
        let destination = match (dest, conn.dialled) {
            (Some(d), _) => d.clone(),
            (None, Some(a)) => Destination::new(Scheme::Https, &a.ip().to_string(), a.port()),
            (None, None) => Destination::new(Scheme::Https, "unknown", conn.port),
        };
        self.interception_refused(&destination, reason.to_owned(), false);
    }
}

/// Relays bytes both ways, untouched, starting with what was already read from the client.
async fn relay<IO, U>(mut io: Prefixed<IO>, mut upstream: U, dest: &Destination)
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let prefix = std::mem::take(&mut io.prefix);
    if upstream.write_all(&prefix).await.is_err() {
        return;
    }
    let mut inner = io.inner;
    if let Err(e) = tokio::io::copy_bidirectional(&mut inner, &mut upstream).await {
        tracing::debug!(destination = %dest, error = %e, "pass-through ended with an error");
    }
}

/// Whether `dest`'s name resolves to a loopback or unspecified address: relaying there would reach
/// this host's services as scrim, or come back to scrim. Names that do not resolve count as not.
async fn resolves_here(dest: &Destination) -> bool {
    tokio::net::lookup_host((dest.host.as_str(), dest.port))
        .await
        .is_ok_and(|mut a| a.any(|a| a.ip().is_loopback() || a.ip().is_unspecified()))
}

/// A stream with bytes already read from it put back in front.
pub(crate) struct Prefixed<IO> {
    prefix: Bytes,
    inner: IO,
}

impl<IO> Prefixed<IO> {
    fn new(prefix: Bytes, inner: IO) -> Self {
        Self { prefix, inner }
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for Prefixed<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let n = self.prefix.len().min(buf.remaining());
            let head = self.prefix.split_to(n);
            buf.put_slice(&head);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for Prefixed<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}
