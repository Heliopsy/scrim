// SPDX-License-Identifier: AGPL-3.0-only

//! Response bodies: the streaming restorer and small helpers.

use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use http_body_util::combinators::UnsyncBoxBody;

use crate::capture::BodyTee;
use crate::stream::SseRestorer;

/// Boxed error type of proxy bodies.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The body type of every response the proxy returns.
pub type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;

/// A complete body.
pub(crate) fn full(b: impl Into<Bytes>) -> ProxyBody {
    http_body_util::Full::new(b.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

/// Called once when a response body ends (or is dropped) with the restore counters.
pub(crate) type OnEnd = Box<dyn FnOnce(u64, u64) + Send>;

/// Wraps an upstream body: copies it to capture, and when a codec is given, frames it as SSE
/// and restores placeholders event by event.
pub(crate) struct Restoring<B> {
    inner: B,
    prefix: Option<Bytes>,
    tee: Option<BodyTee>,
    restorer: Option<SseRestorer>,
    trailers: Option<http::HeaderMap>,
    done: bool,
    on_end: Option<OnEnd>,
}

impl<B> Restoring<B> {
    pub(crate) fn new(
        inner: B,
        prefix: Option<Bytes>,
        tee: Option<BodyTee>,
        restorer: Option<SseRestorer>,
        on_end: Option<OnEnd>,
    ) -> Self {
        Self {
            inner,
            prefix,
            tee,
            restorer,
            trailers: None,
            done: false,
            on_end,
        }
    }

    fn process(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() + 64);
        match self.restorer.as_mut() {
            Some(r) => r.push(data, &mut out),
            None => out.extend_from_slice(data),
        }
        out
    }

    fn counters(&self) -> (u64, u64) {
        self.restorer
            .as_ref()
            .map_or((0, 0), |r| (r.resolved(), r.kept()))
    }

    fn end(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(r) = self.restorer.as_mut() {
            r.finish(&mut out);
        }
        if let Some(t) = self.tee.take() {
            drop(t.close());
        }
        if let Some(f) = self.on_end.take() {
            let (a, b) = self.counters();
            f(a, b);
        }
        out
    }
}

impl<B> Drop for Restoring<B> {
    fn drop(&mut self) {
        if let Some(f) = self.on_end.take() {
            let (a, b) = self.counters();
            f(a, b);
        }
    }
}

impl<B> Body for Restoring<B>
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
        if let Some(p) = this.prefix.take() {
            if let Some(t) = &this.tee {
                t.write(&p);
            }
            let out = this.process(&p);
            if !out.is_empty() {
                return Poll::Ready(Some(Ok(Frame::data(Bytes::from(out)))));
            }
        }
        loop {
            if this.done {
                return Poll::Ready(this.trailers.take().map(|t| Ok(Frame::trailers(t))));
            }
            match ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => {
                        if let Some(t) = &this.tee {
                            t.write(&data);
                        }
                        let out = this.process(&data);
                        if !out.is_empty() {
                            return Poll::Ready(Some(Ok(Frame::data(Bytes::from(out)))));
                        }
                    }
                    Err(frame) => {
                        if let Ok(t) = frame.into_trailers() {
                            this.trailers = Some(t);
                        }
                    }
                },
                Some(Err(e)) => {
                    this.done = true;
                    this.tee.take();
                    if let Some(f) = this.on_end.take() {
                        let (a, b) = this.counters();
                        f(a, b);
                    }
                    return Poll::Ready(Some(Err(e.into())));
                }
                None => {
                    this.done = true;
                    let out = this.end();
                    if !out.is_empty() {
                        return Poll::Ready(Some(Ok(Frame::data(Bytes::from(out)))));
                    }
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done && self.trailers.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        if self.restorer.is_none() && self.prefix.is_none() {
            self.inner.size_hint()
        } else {
            SizeHint::default()
        }
    }
}
