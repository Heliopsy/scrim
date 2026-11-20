// SPDX-License-Identifier: AGPL-3.0-only

//! The gRPC service the control plane calls, served on the inherited socket.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use scrim_proto::v1;
use scrim_proto::v1::data_plane_server::{DataPlane, DataPlaneServer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tokio_stream::{Stream, StreamExt};
use tonic::transport::server::Connected;
use tonic::{Request, Response, Status, Streaming};

use crate::VERSION;
use crate::engine::Shared;
use crate::harden::Hardening;
use crate::policy;
use crate::settings::Settings;

/// Serves the control plane on `stream` until the control plane closes its
/// end, then returns. Returning means the process must exit: a data plane
/// without its control plane refuses all traffic.
pub async fn run(stream: std::os::unix::net::UnixStream, hardening: Hardening) -> io::Result<()> {
    stream.set_nonblocking(true)?;
    let stream = UnixStream::from_std(stream)?;
    let shared = Shared::with_settings(&Settings::from_env()).map_err(io::Error::other)?;
    serve(stream, Arc::new(shared), hardening).await
}

/// Serves `stream` with the given shared state. Used by [`run`] and tests.
pub async fn serve(
    stream: UnixStream,
    shared: Arc<Shared>,
    hardening: Hardening,
) -> io::Result<()> {
    let (closed_tx, closed_rx) = oneshot::channel();
    let conn = ParentConn {
        inner: stream,
        closed: Some(closed_tx),
    };
    // Yield the one connection, then never end: tonic stops accepting when
    // the incoming stream ends, and the shutdown signal is the connection
    // closing instead.
    let incoming = tokio_stream::once(Ok::<_, io::Error>(conn)).chain(tokio_stream::pending());
    let svc = Service {
        shared: Arc::clone(&shared),
        hardening,
    };
    let result = tonic::transport::Server::builder()
        .add_service(DataPlaneServer::new(svc))
        .serve_with_incoming_shutdown(incoming, async {
            let _ = closed_rx.await;
        })
        .await;
    shared.shutdown(); // drops the dictionary now, zeroing it
    result.map_err(io::Error::other)
}

/// The inherited connection. Dropping it (when hyper finishes the
/// connection) signals shutdown.
struct ParentConn {
    inner: UnixStream,
    closed: Option<oneshot::Sender<()>>,
}

impl Drop for ParentConn {
    fn drop(&mut self) {
        if let Some(tx) = self.closed.take() {
            let _ = tx.send(());
        }
    }
}

impl Connected for ParentConn {
    type ConnectInfo = ();
    fn connect_info(&self) -> Self::ConnectInfo {}
}

impl AsyncRead for ParentConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ParentConn {
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
}

struct Service {
    shared: Arc<Shared>,
    hardening: Hardening,
}

fn check(protocol: u32) -> Result<(), Status> {
    if protocol == v1::PROTOCOL {
        Ok(())
    } else {
        Err(Status::failed_precondition(format!(
            "protocol {protocol} is not supported; this data plane speaks {}",
            v1::PROTOCOL
        )))
    }
}

type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl DataPlane for Service {
    async fn hello(
        &self,
        req: Request<v1::HelloRequest>,
    ) -> Result<Response<v1::HelloResponse>, Status> {
        let req = req.into_inner();
        check(req.protocol)?;
        tracing::info!(
            control_plane = req.control_plane_version.as_str(),
            "control plane connected"
        );
        Ok(Response::new(v1::HelloResponse {
            protocol: v1::PROTOCOL,
            data_plane_version: VERSION.to_owned(),
            pid: std::process::id(),
            applied_snapshot_version: self.applied_version(),
            memory_locked: self.hardening.memory_locked,
            dumpable: self.hardening.dumpable,
        }))
    }

    async fn apply_snapshot(
        &self,
        req: Request<v1::Snapshot>,
    ) -> Result<Response<v1::ApplySnapshotResponse>, Status> {
        let snap = req.into_inner();
        check(snap.protocol)?;
        match self.shared.apply(snap).await {
            Ok((version, count)) => {
                tracing::info!(version, values = count, "snapshot applied");
                Ok(Response::new(v1::ApplySnapshotResponse {
                    protocol: v1::PROTOCOL,
                    applied_version: version,
                    value_count: count,
                }))
            }
            Err(e) => {
                let e = e.to_string();
                tracing::warn!(reason = e.as_str(), "snapshot rejected");
                Err(Status::invalid_argument(e))
            }
        }
    }

    type EventsStream = BoxStream<v1::EventBatch>;

    async fn events(
        &self,
        req: Request<v1::EventsRequest>,
    ) -> Result<Response<Self::EventsStream>, Status> {
        check(req.into_inner().protocol)?;
        let sub = self
            .shared
            .events
            .subscribe()
            .ok_or_else(|| Status::failed_precondition("events already have a subscriber"))?;
        let stream = futures_unfold(sub);
        Ok(Response::new(Box::pin(stream)))
    }

    type AsksStream = BoxStream<v1::AskRequest>;

    async fn asks(
        &self,
        req: Request<Streaming<v1::AskAnswer>>,
    ) -> Result<Response<Self::AsksStream>, Status> {
        let mut answers = req.into_inner();
        let rx = self
            .shared
            .asks
            .attach()
            .ok_or_else(|| Status::failed_precondition("asks already attached"))?;
        let shared = Arc::clone(&self.shared);
        tokio::spawn(async move {
            while let Some(Ok(a)) = answers.next().await {
                if a.protocol == v1::PROTOCOL {
                    shared.asks.answer(a);
                }
            }
            shared.asks.detach();
        });
        let out = tokio_stream::wrappers::ReceiverStream::new(rx).map(Ok);
        Ok(Response::new(Box::pin(out)))
    }

    async fn status(
        &self,
        req: Request<v1::StatusRequest>,
    ) -> Result<Response<v1::StatusResponse>, Status> {
        check(req.into_inner().protocol)?;
        let snap = self.shared.snapshot.load_full();
        let listeners = self.shared.listeners.status();
        let proxy = self.shared.tool_proxy.status();
        let proxy_ok = proxy.ready || !self.shared.listeners.serves_tool_proxy();
        let tool_proxy = v1::ToolProxyStatus {
            ready: proxy.ready,
            snapshot_version: proxy.snapshot_version.unwrap_or(0),
            unsupported_destinations: proxy.unsupported_destinations.into_iter().collect(),
            cached_leaves: u32::try_from(proxy.cached_leaves).unwrap_or(u32::MAX),
        };
        Ok(Response::new(v1::StatusResponse {
            protocol: v1::PROTOCOL,
            ready: snap.is_some() && proxy_ok && listeners.iter().all(|l| l.bound),
            applied_snapshot_version: snap.as_ref().map_or(0, |s| s.version),
            value_count: snap.as_ref().map_or(0, |s| {
                u32::try_from(s.applied.values.len()).unwrap_or(u32::MAX)
            }),
            memory_locked: self.hardening.memory_locked,
            dumpable: self.hardening.dumpable,
            listeners,
            data_plane_version: VERSION.to_owned(),
            ca_trust_bundle_pem: self.shared.tool_proxy.ca().trust_bundle_pem(),
            tool_proxy: Some(tool_proxy),
            redaction: snap.as_ref().map(|s| s.applied.redaction_status()),
            policy_engine: policy::ENGINE.to_owned(),
        }))
    }

    type CapturesStream = BoxStream<v1::CaptureRequest>;

    async fn captures(
        &self,
        req: Request<Streaming<v1::CaptureResult>>,
    ) -> Result<Response<Self::CapturesStream>, Status> {
        let mut results = req.into_inner();
        let rx = self
            .shared
            .captures
            .attach()
            .ok_or_else(|| Status::failed_precondition("captures already attached"))?;
        let shared = Arc::clone(&self.shared);
        tokio::spawn(async move {
            while let Some(Ok(r)) = results.next().await {
                if r.protocol == v1::PROTOCOL {
                    shared.captures.result(r);
                }
            }
            shared.captures.detach();
        });
        let out = tokio_stream::wrappers::ReceiverStream::new(rx).map(Ok);
        Ok(Response::new(Box::pin(out)))
    }
}

impl Service {
    fn applied_version(&self) -> u64 {
        self.shared.applied_version()
    }
}

/// Turns the subscriber into a stream of batches.
fn futures_unfold(
    sub: crate::events::Subscriber,
) -> impl Stream<Item = Result<v1::EventBatch, Status>> {
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        let mut sub = sub;
        while let Some(batch) = sub.next_batch().await {
            if tx.send(Ok(batch)).await.is_err() {
                break;
            }
        }
    });
    tokio_stream::wrappers::ReceiverStream::new(rx)
}
