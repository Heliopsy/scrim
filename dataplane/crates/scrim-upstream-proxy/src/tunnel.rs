// SPDX-License-Identifier: AGPL-3.0-only

//! The `CONNECT` handshake.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use crate::UpstreamProxy;

/// Longest response head accepted from the proxy.
const MAX_HEAD: usize = 16 * 1024;

/// Opening a tunnel failed. Messages name the proxy and the destination, never credentials.
#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    /// The proxy could not be reached.
    #[error("upstream proxy {proxy}: {source}")]
    Connect {
        /// The proxy, `scheme://host:port`.
        proxy: String,
        /// Why.
        source: io::Error,
    },
    /// TLS to an `https://` proxy failed (its certificate did not verify, for one).
    #[error("upstream proxy {proxy}: TLS: {source}")]
    Tls {
        /// The proxy.
        proxy: String,
        /// Why.
        source: io::Error,
    },
    /// The proxy wants credentials, or refused the ones sent.
    #[error("upstream proxy {proxy} refused CONNECT {dest}: 407 proxy authentication required")]
    AuthRequired {
        /// The proxy.
        proxy: String,
        /// The destination.
        dest: String,
    },
    /// The proxy answered something other than 2xx.
    #[error("upstream proxy {proxy} refused CONNECT {dest}: status {status}")]
    Refused {
        /// The proxy.
        proxy: String,
        /// The destination.
        dest: String,
        /// The status code.
        status: u16,
    },
    /// The proxy's answer was not an HTTP response, was too long, or the connection ended.
    #[error("upstream proxy {proxy}: bad answer to CONNECT {dest}: {why}")]
    Protocol {
        /// The proxy.
        proxy: String,
        /// The destination.
        dest: String,
        /// What was wrong.
        why: &'static str,
    },
    /// The proxy did not answer in time.
    #[error("upstream proxy {proxy}: no answer to CONNECT {dest} within {secs}s")]
    Timeout {
        /// The proxy.
        proxy: String,
        /// The destination.
        dest: String,
        /// The timeout.
        secs: u64,
    },
}

impl From<TunnelError> for io::Error {
    fn from(e: TunnelError) -> Self {
        let kind = match &e {
            TunnelError::Connect { source, .. } => source.kind(),
            TunnelError::Timeout { .. } => io::ErrorKind::TimedOut,
            TunnelError::AuthRequired { .. } | TunnelError::Refused { .. } => {
                io::ErrorKind::ConnectionRefused
            }
            _ => io::ErrorKind::Other,
        };
        io::Error::new(kind, e)
    }
}

/// A connection to the destination: direct, or a tunnel through the proxy (plain or inside TLS
/// to an `https://` proxy). TLS to the destination, if any, goes on top.
pub enum Stream {
    /// A TCP connection: to the destination, or to an `http://` proxy that tunnels to it.
    Tcp(TcpStream),
    /// A tunnel inside TLS to an `https://` proxy.
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Tcp(s) => Pin::new(s).poll_flush(cx),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Tcp(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Stream::Tcp(s) => s.is_write_vectored(),
            Stream::Tls(s) => s.is_write_vectored(),
        }
    }
}

/// `host:port` for a `CONNECT` line, IPv6 addresses in brackets.
fn authority(host: &str, port: u16) -> String {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    if h.contains(':') {
        format!("[{h}]:{port}")
    } else {
        format!("{h}:{port}")
    }
}

/// Opens a tunnel to `host:port` through `proxy`. `tls` verifies an `https://` proxy's own
/// certificate; the destination's TLS is the caller's, inside the returned stream. `timeout`
/// bounds reaching the proxy and, separately, its answer.
pub async fn connect(
    proxy: &UpstreamProxy,
    tls: &Arc<rustls::ClientConfig>,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<Stream, TunnelError> {
    let name = proxy.display();
    let dest = authority(host, port);
    let timed_out = || TunnelError::Timeout {
        proxy: name.clone(),
        dest: dest.clone(),
        secs: timeout.as_secs(),
    };
    let tcp = tokio::time::timeout(timeout, TcpStream::connect((proxy.host(), proxy.port())))
        .await
        .map_err(|_| timed_out())?
        .map_err(|source| TunnelError::Connect {
            proxy: name.clone(),
            source,
        })?;
    let _ = tcp.set_nodelay(true);
    let mut stream = if proxy.is_tls() {
        let server =
            ServerName::try_from(proxy.host().to_owned()).map_err(|_| TunnelError::Tls {
                proxy: name.clone(),
                source: io::Error::other("the proxy host is not a valid TLS server name"),
            })?;
        let tls = tokio::time::timeout(
            timeout,
            tokio_rustls::TlsConnector::from(Arc::clone(tls)).connect(server, tcp),
        )
        .await
        .map_err(|_| timed_out())?
        .map_err(|source| TunnelError::Tls {
            proxy: name.clone(),
            source,
        })?;
        Stream::Tls(Box::new(tls))
    } else {
        Stream::Tcp(tcp)
    };

    let mut req = Zeroizing::new(Vec::with_capacity(256));
    req.extend_from_slice(b"CONNECT ");
    req.extend_from_slice(dest.as_bytes());
    req.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    req.extend_from_slice(dest.as_bytes());
    req.extend_from_slice(b"\r\n");
    if let Some(auth) = proxy.authorization() {
        req.extend_from_slice(b"Proxy-Authorization: ");
        req.extend_from_slice(auth);
        req.extend_from_slice(b"\r\n");
    }
    req.extend_from_slice(b"\r\n");
    let io_err = |source: io::Error| TunnelError::Connect {
        proxy: name.clone(),
        source,
    };
    tokio::time::timeout(timeout, async {
        stream.write_all(&req).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| timed_out())?
    .map_err(io_err)?;
    drop(req);

    let head = tokio::time::timeout(timeout, read_head(&mut stream))
        .await
        .map_err(|_| timed_out())?;
    let protocol = |why| TunnelError::Protocol {
        proxy: name.clone(),
        dest: dest.clone(),
        why,
    };
    let head = match head {
        Ok(h) => h,
        Err(HeadError::Io(e)) => return Err(io_err(e)),
        Err(HeadError::TooLong) => return Err(protocol("response head too long")),
        Err(HeadError::Eof) => return Err(protocol("connection closed before a response")),
        Err(HeadError::Extra) => return Err(protocol("data after the response head")),
    };
    match parse_status(&head) {
        None => Err(protocol("not an HTTP/1.x response")),
        Some(s) if (200..300).contains(&s) => {
            tracing::debug!(proxy = %name, destination = %dest, "upstream proxy tunnel open");
            Ok(stream)
        }
        Some(407) => Err(TunnelError::AuthRequired { proxy: name, dest }),
        Some(status) => Err(TunnelError::Refused {
            proxy: name,
            dest,
            status,
        }),
    }
}

enum HeadError {
    Io(io::Error),
    TooLong,
    Eof,
    Extra,
}

/// Reads up to the end of the response head. The destination speaks only after the client's
/// first bytes, so anything after the head is a protocol error.
async fn read_head<S: AsyncRead + Unpin>(s: &mut S) -> Result<Vec<u8>, HeadError> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    loop {
        let n = s.read(&mut chunk).await.map_err(HeadError::Io)?;
        if n == 0 {
            return Err(HeadError::Eof);
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            if end + 4 != buf.len() {
                return Err(HeadError::Extra);
            }
            return Ok(buf);
        }
        if buf.len() > MAX_HEAD {
            return Err(HeadError::TooLong);
        }
    }
}

fn parse_status(head: &[u8]) -> Option<u16> {
    let line = head.split(|&b| b == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?.trim_end();
    let mut parts = line.splitn(3, ' ');
    let version = parts.next()?;
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return None;
    }
    let code = parts.next()?;
    if code.len() != 3 {
        return None;
    }
    code.parse().ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn status_lines() {
        assert_eq!(
            parse_status(b"HTTP/1.1 200 Connection established\r\n\r\n"),
            Some(200)
        );
        assert_eq!(
            parse_status(b"HTTP/1.0 407 Proxy Authentication Required\r\n"),
            Some(407)
        );
        assert_eq!(parse_status(b"HTTP/1.1 200\r\n\r\n"), Some(200));
        assert_eq!(parse_status(b"SSH-2.0-OpenSSH\r\n"), None);
        assert_eq!(parse_status(b"HTTP/2 200\r\n"), None);
        assert_eq!(parse_status(b"HTTP/1.1 20\r\n"), None);
    }

    #[test]
    fn authorities() {
        assert_eq!(authority("api.anthropic.com", 443), "api.anthropic.com:443");
        assert_eq!(authority("fd00::1", 8443), "[fd00::1]:8443");
        assert_eq!(authority("[fd00::1]", 8443), "[fd00::1]:8443");
    }
}
