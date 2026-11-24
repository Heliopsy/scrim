// SPDX-License-Identifier: AGPL-3.0-only

//! A recording `CONNECT` proxy for tests (feature `test-util`). Never in a release build.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// How the test proxy behaves.
#[derive(Clone, Default)]
pub struct Options {
    /// The `Proxy-Authorization` value required; `None` accepts any or none.
    pub require_authorization: Option<String>,
    /// Serve TLS to the client first (an `https://` proxy).
    pub tls: Option<Arc<rustls::ServerConfig>>,
    /// Send every tunnel here instead of `127.0.0.1:<CONNECT port>`, which is what lets tests use
    /// destination names that do not resolve.
    pub redirect: Option<SocketAddr>,
}

/// One `CONNECT` the proxy saw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seen {
    /// The `host:port` asked for.
    pub target: String,
    /// Whether a `Proxy-Authorization` header was sent.
    pub sent_authorization: bool,
    /// Whether the tunnel was opened (credentials accepted, destination reachable).
    pub opened: bool,
}

/// A running test proxy on loopback.
pub struct TestProxy {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    tunnelled: Arc<Mutex<Vec<u8>>>,
}

impl TestProxy {
    /// Starts the proxy.
    pub async fn start(opts: Options) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let tunnelled = Arc::new(Mutex::new(Vec::new()));
        let (s, t) = (Arc::clone(&seen), Arc::clone(&tunnelled));
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let opts = opts.clone();
                let (s, t) = (Arc::clone(&s), Arc::clone(&t));
                tokio::spawn(async move {
                    if let Some(cfg) = &opts.tls {
                        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(cfg));
                        if let Ok(tls) = acceptor.accept(tcp).await {
                            serve(tls, &opts, &s, &t).await;
                        }
                    } else {
                        serve(tcp, &opts, &s, &t).await;
                    }
                });
            }
        });
        Self {
            addr,
            seen,
            tunnelled,
        }
    }

    /// `http://127.0.0.1:<port>` (or `https://` for a TLS proxy, with the name the caller's
    /// certificate holds).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Every `CONNECT` so far.
    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    /// Every byte the client sent through any tunnel: ciphertext when TLS runs inside, so a
    /// test can check a value never crossed the proxy in clear.
    pub fn tunnelled_bytes(&self) -> Vec<u8> {
        self.tunnelled.lock().unwrap().clone()
    }
}

async fn serve<S>(mut s: S, opts: &Options, seen: &Mutex<Vec<Seen>>, tunnelled: &Mutex<Vec<u8>>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 16 * 1024 || s.read(&mut b).await.unwrap_or(0) == 0 {
            return;
        }
        head.push(b[0]);
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let mut lines = text.split("\r\n");
    let first = lines.next().unwrap_or_default();
    let mut parts = first.split(' ');
    if parts.next() != Some("CONNECT") {
        let _ = s
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            .await;
        return;
    }
    let target = parts.next().unwrap_or_default().to_owned();
    let auth = lines.find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case("proxy-authorization")
            .then(|| v.trim().to_owned())
    });
    let mut rec = Seen {
        target: target.clone(),
        sent_authorization: auth.is_some(),
        opened: false,
    };
    if let Some(want) = &opts.require_authorization
        && auth.as_deref() != Some(want.as_str())
    {
        seen.lock().unwrap().push(rec);
        let _ = s
            .write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"test\"\r\nContent-Length: 0\r\n\r\n",
            )
            .await;
        return;
    }
    let dest = opts.redirect.unwrap_or_else(|| {
        let port = target
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse().ok())
            .unwrap_or(443);
        SocketAddr::from(([127, 0, 0, 1], port))
    });
    let Ok(mut up) = TcpStream::connect(dest).await else {
        seen.lock().unwrap().push(rec);
        let _ = s.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
        return;
    };
    rec.opened = true;
    seen.lock().unwrap().push(rec);
    if s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await
        .is_err()
    {
        return;
    }
    // Relay both ways, recording what the client sent.
    let (mut cr, mut cw) = tokio::io::split(s);
    let (mut ur, mut uw) = up.split();
    let up_to_client = tokio::io::copy(&mut ur, &mut cw);
    let client_to_up = async {
        let mut buf = [0u8; 8192];
        loop {
            let n = cr.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                let _ = uw.shutdown().await;
                return;
            }
            tunnelled.lock().unwrap().extend_from_slice(&buf[..n]);
            if uw.write_all(&buf[..n]).await.is_err() {
                return;
            }
        }
    };
    let _ = tokio::join!(up_to_client, client_to_up);
}
