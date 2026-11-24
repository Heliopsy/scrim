// SPDX-License-Identifier: AGPL-3.0-only

//! A hyper connector that tunnels through the upstream proxy in force.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http::Uri;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tower_service::Service;

use crate::ProxyHandle;
use crate::tunnel::{Stream, connect};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Wraps a TCP connector (hyper's `HttpConnector`, with whatever resolver): a destination the
/// proxy in force applies to is reached through a `CONNECT` tunnel, any other through the inner
/// connector. Put a TLS connector (hyper-rustls) around this one: TLS to the destination then runs
/// inside the tunnel, verified against the destination's name, as on a direct connection.
///
/// A tunnelled destination is never resolved here; the proxy resolves it, which is what networks
/// without outside DNS need.
#[derive(Clone)]
pub struct ProxyConnector<C> {
    inner: C,
    proxy: ProxyHandle,
    tls: Arc<rustls::ClientConfig>,
    timeout: Duration,
}

impl<C> ProxyConnector<C> {
    /// `tls` verifies `https://` proxies; `timeout` bounds reaching the proxy and its answer.
    pub fn new(
        inner: C,
        proxy: ProxyHandle,
        tls: Arc<rustls::ClientConfig>,
        timeout: Duration,
    ) -> Self {
        Self {
            inner,
            proxy,
            tls,
            timeout,
        }
    }
}

impl<C> Service<Uri> for ProxyConnector<C>
where
    C: Service<Uri, Response = TokioIo<TcpStream>> + Clone + Send + 'static,
    C::Future: Send + 'static,
    C::Error: Into<BoxError>,
{
    type Response = ProxyIo;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<ProxyIo, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let host = dst.host().unwrap_or_default().to_owned();
        let port = dst.port_u16().unwrap_or(match dst.scheme_str() {
            Some("https") => 443,
            _ => 80,
        });
        let Some(proxy) = self.proxy.route(&host, port) else {
            let fut = self.inner.call(dst);
            return Box::pin(async move {
                let tcp = fut.await.map_err(Into::into)?.into_inner();
                Ok(ProxyIo::new(Stream::Tcp(tcp), false))
            });
        };
        let tls = Arc::clone(&self.tls);
        let timeout = self.timeout;
        Box::pin(async move {
            let s = connect(&proxy, &tls, &host, port, timeout)
                .await
                .map_err(io::Error::from)?;
            Ok(ProxyIo::new(s, true))
        })
    }
}

/// A connection made by [`ProxyConnector`].
pub struct ProxyIo {
    inner: TokioIo<Stream>,
    tunnelled: bool,
}

impl ProxyIo {
    fn new(s: Stream, tunnelled: bool) -> Self {
        Self {
            inner: TokioIo::new(s),
            tunnelled,
        }
    }

    /// Whether the connection goes through the upstream proxy.
    pub fn is_tunnelled(&self) -> bool {
        self.tunnelled
    }
}

impl Connection for ProxyIo {
    fn connected(&self) -> Connected {
        // Never `proxy(true)`: requests inside a tunnel are origin-form, as on a direct
        // connection.
        Connected::new()
    }
}

impl Read for ProxyIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl Write for ProxyIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }
}
