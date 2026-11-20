//! Body types and the streaming transform pipeline.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::HeaderMap;
use http_body::{Body, Frame, SizeHint};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full};

use crate::codec::Transform;
use crate::inject::Injector;
use crate::redactor::{RedactorChain, StreamRedactor};

/// Error type of proxied bodies.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The body type the proxy sends and returns.
pub type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;

/// A complete body.
pub fn full(b: impl Into<Bytes>) -> ProxyBody {
    Full::new(b.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

/// An empty body.
pub fn empty() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed_unsync()
}

/// One step of a pipeline.
pub(crate) enum Stage {
    Codec(Box<dyn Transform>),
    Redact(StreamRedactor),
    /// Refuses the stream when a placeholder shows up (oversized request bodies).
    Scan(ScanStage),
}

pub(crate) struct ScanStage {
    injector: Arc<Injector>,
    pending: Vec<u8>,
}

impl ScanStage {
    pub(crate) fn new(injector: Arc<Injector>) -> Self {
        Self {
            injector,
            pending: Vec::new(),
        }
    }

    fn push(&mut self, data: &[u8], out: &mut Vec<u8>, last: bool) -> io::Result<()> {
        self.pending.extend_from_slice(data);
        if !self.injector.scan(&self.pending).is_empty() {
            return Err(io::Error::other(
                "a placeholder appeared in a request body too large to rewrite",
            ));
        }
        let keep = if last {
            0
        } else {
            self.injector.max_len().saturating_sub(1)
        };
        let emit = self.pending.len().saturating_sub(keep);
        out.extend(self.pending.drain(..emit));
        Ok(())
    }
}

/// Stages applied in order to every data frame.
pub(crate) struct Pipeline {
    stages: Vec<Stage>,
}

impl Pipeline {
    pub(crate) fn new(stages: Vec<Stage>) -> Self {
        Self { stages }
    }

    fn run(&mut self, data: &[u8], finish: bool) -> io::Result<Vec<u8>> {
        let mut cur = data.to_vec();
        for st in &mut self.stages {
            let mut out = Vec::with_capacity(cur.len());
            match st {
                Stage::Codec(t) => {
                    t.push(&cur, &mut out)?;
                    if finish {
                        t.finish(&mut out)?;
                    }
                }
                Stage::Redact(r) => {
                    r.push(&cur, &mut out).map_err(io::Error::other)?;
                    if finish {
                        r.finish(&mut out).map_err(io::Error::other)?;
                    }
                }
                Stage::Scan(s) => s.push(&cur, &mut out, finish)?,
            }
            cur = out;
        }
        Ok(cur)
    }

    pub(crate) fn replacements(&self) -> u64 {
        self.stages
            .iter()
            .map(|s| match s {
                Stage::Redact(r) => r.replaced() as u64,
                _ => 0,
            })
            .sum()
    }
}

/// Called once when the body ends: `Ok(replacements)` or `Err(message)`.
pub(crate) type OnEnd = Box<dyn FnOnce(Result<u64, String>) + Send>;

/// A body passed through a [`Pipeline`]. Trailers are redacted with `trailer_redactor`.
pub(crate) struct TransformBody<B> {
    inner: B,
    pipeline: Pipeline,
    trailer_redactor: Option<RedactorChain>,
    pending_trailers: Option<HeaderMap>,
    finished: bool,
    on_end: Option<OnEnd>,
}

impl<B> TransformBody<B> {
    pub(crate) fn new(
        inner: B,
        pipeline: Pipeline,
        trailer_redactor: Option<RedactorChain>,
        on_end: OnEnd,
    ) -> Self {
        Self {
            inner,
            pipeline,
            trailer_redactor,
            pending_trailers: None,
            finished: false,
            on_end: Some(on_end),
        }
    }

    fn end(&mut self, r: Result<u64, String>) {
        if let Some(f) = self.on_end.take() {
            f(r);
        }
    }

    fn fail(&mut self, msg: String) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        self.finished = true;
        self.end(Err(msg.clone()));
        Poll::Ready(Some(Err(msg.into())))
    }
}

impl<B> Body for TransformBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = &mut *self;
        loop {
            if this.finished {
                if let Some(t) = this.pending_trailers.take() {
                    return Poll::Ready(Some(Ok(Frame::trailers(t))));
                }
                return Poll::Ready(None);
            }
            match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(e))) => {
                    let e: BoxError = e.into();
                    return this.fail(format!("body stream failed: {e}"));
                }
                Poll::Ready(Some(Ok(frame))) => {
                    if frame.is_data() {
                        let data = frame.into_data().unwrap_or_default();
                        match this.pipeline.run(&data, false) {
                            Ok(out) if out.is_empty() => continue,
                            Ok(out) => return Poll::Ready(Some(Ok(Frame::data(Bytes::from(out))))),
                            Err(e) => return this.fail(e.to_string()),
                        }
                    }
                    if let Ok(trailers) = frame.into_trailers() {
                        let mut t = trailers;
                        if let Some(r) = &this.trailer_redactor
                            && let Err(e) = redact_headers(r, &mut t)
                        {
                            return this.fail(e);
                        }
                        this.pending_trailers = Some(t);
                        // Trailers end the body: flush the pipeline first.
                        return this.finish_now();
                    }
                }
                Poll::Ready(None) => return this.finish_now(),
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished && self.pending_trailers.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

impl<B> TransformBody<B> {
    fn finish_now(&mut self) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        match self.pipeline.run(&[], true) {
            Ok(out) => {
                self.finished = true;
                let n = self.pipeline.replacements();
                self.end(Ok(n));
                if out.is_empty() {
                    if let Some(t) = self.pending_trailers.take() {
                        return Poll::Ready(Some(Ok(Frame::trailers(t))));
                    }
                    return Poll::Ready(None);
                }
                Poll::Ready(Some(Ok(Frame::data(Bytes::from(out)))))
            }
            Err(e) => self.fail(e.to_string()),
        }
    }
}

/// Redacts every header value in place. Values that would become invalid are an error.
pub(crate) fn redact_headers(r: &RedactorChain, headers: &mut HeaderMap) -> Result<u64, String> {
    let mut n = 0;
    for v in headers.values_mut() {
        if let Some((out, k)) = r.redact_all(v.as_bytes()).map_err(|e| e.to_string())? {
            *v = http::HeaderValue::from_bytes(&out)
                .map_err(|_| "redacted header value is invalid".to_owned())?;
            n += k as u64;
        }
    }
    Ok(n)
}

/// Prepends already-read bytes to the rest of a body.
pub(crate) struct Prefixed<B> {
    prefix: Option<Bytes>,
    inner: B,
}

impl<B> Prefixed<B> {
    pub(crate) fn new(prefix: Bytes, inner: B) -> Self {
        Self {
            prefix: (!prefix.is_empty()).then_some(prefix),
            inner,
        }
    }
}

impl<B> Body for Prefixed<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, B::Error>>> {
        if let Some(p) = self.prefix.take() {
            return Poll::Ready(Some(Ok(Frame::data(p))));
        }
        Pin::new(&mut self.inner).poll_frame(cx)
    }
}

/// Reads a body until it ends or exceeds `limit` bytes.
pub(crate) enum Collected<B> {
    /// The whole body and its trailers.
    Complete(Bytes, Option<HeaderMap>),
    /// The limit was exceeded: the bytes read so far and the unread rest.
    Overflow(Bytes, B),
}

pub(crate) async fn collect_limited<B>(mut body: B, limit: usize) -> Result<Collected<B>, BoxError>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    let mut buf = bytes::BytesMut::new();
    let mut trailers = None;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(Into::into)?;
        if frame.is_data() {
            let d = frame.into_data().unwrap_or_default();
            buf.extend_from_slice(&d);
            if buf.len() > limit {
                return Ok(Collected::Overflow(buf.freeze(), body));
            }
        } else if let Ok(t) = frame.into_trailers() {
            trailers = Some(t);
        }
    }
    Ok(Collected::Complete(buf.freeze(), trailers))
}
