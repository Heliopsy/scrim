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

use crate::engine::Shared;
use crate::harden::Hardening;
use crate::snapshot::Applied;
use crate::{VERSION, listeners};

/// Serves the control plane on `stream` until the control plane closes its
/// end, then returns. Returning means the process must exit: a data plane
/// without its control plane refuses all traffic.
pub async fn run(stream: std::os::unix::net::UnixStream, hardening: Hardening) -> io::Result<()> {
    stream.set_nonblocking(true)?;
    let stream = UnixStream::from_std(stream)?;
    serve(stream, Arc::new(Shared::default()), hardening).await
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
    shared.asks.detach();
    shared.snapshot.store(None); // drop the dictionary now, zeroing it
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
        let applied = Applied::from_proto(snap, self.applied_version()).map_err(|e| {
            tracing::warn!(reason = %e, "snapshot rejected");
            Status::invalid_argument(e.to_string())
        })?;
        let version = applied.version;
        let count = u32::try_from(applied.values.len()).unwrap_or(u32::MAX);
        self.shared.snapshot.store(Some(Arc::new(applied)));
        tracing::info!(version, values = count, "snapshot applied");
        Ok(Response::new(v1::ApplySnapshotResponse {
            protocol: v1::PROTOCOL,
            applied_version: version,
            value_count: count,
        }))
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
        let listeners = snap
            .as_ref()
            .map_or_else(Vec::new, |s| listeners::status(&s.listeners));
        Ok(Response::new(v1::StatusResponse {
            protocol: v1::PROTOCOL,
            ready: snap.is_some() && listeners.iter().all(|l| l.bound),
            applied_snapshot_version: snap.as_ref().map_or(0, |s| s.version),
            value_count: snap
                .as_ref()
                .map_or(0, |s| u32::try_from(s.values.len()).unwrap_or(u32::MAX)),
            memory_locked: self.hardening.memory_locked,
            dumpable: self.hardening.dumpable,
            listeners,
            data_plane_version: VERSION.to_owned(),
        }))
    }
}

impl Service {
    fn applied_version(&self) -> u64 {
        self.shared
            .snapshot
            .load()
            .as_ref()
            .map_or(0, |s| s.version)
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
