// SPDX-License-Identifier: AGPL-3.0-only

//! Zeroing for the boundary connection.
//!
//! The snapshot carries every secret value from the control plane, and asks
//! and captures carry tokens back. Three pieces keep tonic and h2 from leaving
//! copies of those bytes behind:
//!
//! - [`WipingCodec`] decodes each message from a range it splits out of
//!   tonic's receive buffer and zeroes that range once decoded. It encodes a
//!   message into a buffer reserved for its whole length and has tonic hand
//!   every message to h2 on its own, so the encode buffer never grows (and
//!   leaves a copy behind) with a message in it.
//! - [`WipeBodies`] wraps the service. It zeroes each DATA frame payload it
//!   receives from h2 once tonic has copied it, and each one tonic sends once
//!   h2 has written it. It passes a message's 5-byte gRPC header to tonic on
//!   its own, so tonic grows its receive buffer to the message's length before
//!   any of the message is in it.
//! - The generated types zero their secret fields on drop (`secret_fields`).
//!
//! What stays out of reach is listed in docs/limitations.md: h2's read buffer
//! when it is reallocated with part of a frame in it, h2's write buffer for
//! DATA frames too small to send without copying, and tokio's stdin and stdout
//! buffers under `--stdio`.

// Zeroing a `Bytes` range needs a write through the pointer `Bytes` holds:
// `Bytes` only hands out shared slices. `wiping` is the one place that does
// it, under the conditions its safety section states.
#![allow(unsafe_code)]

use std::convert::Infallible;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use http_body::{Body, Frame, SizeHint};
use prost::Message;
use tonic::Status;
use tonic::codec::{BufferSettings, Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::codegen::{BoxFuture, Service, http};
use tonic::server::NamedService;
use zeroize::Zeroize;

/// tonic's default initial buffer size.
const BUFFER_SIZE: usize = 8 * 1024;

/// gRPC's message header: a compression flag and a 4-byte length.
const HEADER: usize = 5;

/// Owns a `Bytes` and zeroes its range when the last handle to it is dropped.
struct WipeOnDrop(Bytes);

impl AsRef<[u8]> for WipeOnDrop {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for WipeOnDrop {
    fn drop(&mut self) {
        let len = self.0.len();
        if len == 0 {
            return;
        }
        let ptr = self.0.as_ptr().cast_mut();
        // SAFETY: `wiping`'s caller guaranteed that the range is heap memory
        // that no other `Bytes` or reference covers. The only handles to it
        // were the `Bytes` that `Bytes::from_owner` built over this owner, and
        // the owner is dropped after the last of them, so nothing reads the
        // range now. `&mut self` rules out a borrow of `self.0`.
        let range = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
        range.zeroize();
    }
}

/// Returns `b` as a `Bytes` whose range is zeroed once the last handle to
/// it (including slices split from it) is dropped.
///
/// # Safety
///
/// `b` must be the only handle to its range, and the range must be writable
/// heap memory: a range split out of a `BytesMut` (`split_to`, `split`,
/// `copy_to_bytes`) and frozen, never a clone, a static or an owner-backed
/// `Bytes`. Other `Bytes` may share the allocation, but not the range.
unsafe fn wiping(b: Bytes) -> Bytes {
    if b.is_empty() {
        return b;
    }
    Bytes::from_owner(WipeOnDrop(b))
}

/// Decodes `bytes` and zeroes them, whatever the outcome.
fn decode_wiping<U: Message + Default>(bytes: Bytes) -> Result<U, Status> {
    // prost copies `bytes` fields out of a slice, so the message owns its
    // values and the input can be zeroed.
    let decoded = U::decode(bytes.as_ref()).map_err(|e| Status::internal(e.to_string()));
    drop(bytes); // zeroes the range once no other handle is left
    decoded
}

/// The prost codec over buffers that are zeroed once used. Generated clients
/// and servers use it (`codec_path` in `dataplane/tools/protogen`).
#[derive(Debug, Clone)]
pub struct WipingCodec<T, U>(PhantomData<(T, U)>);

impl<T, U> Default for WipingCodec<T, U> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

/// Every encoded message is yielded on its own (a yield threshold of one
/// byte): tonic would otherwise batch several in its encode buffer and, when
/// that grows, leave the batch behind in the old buffer.
fn buffer_settings() -> BufferSettings {
    BufferSettings::new(BUFFER_SIZE, 1)
}

impl<T, U> Codec for WipingCodec<T, U>
where
    T: Message + Send + 'static,
    U: Message + Default + Send + 'static,
{
    type Encode = T;
    type Decode = U;
    type Encoder = WipingEncoder<T>;
    type Decoder = WipingDecoder<U>;

    fn encoder(&mut self) -> Self::Encoder {
        WipingEncoder(PhantomData)
    }

    fn decoder(&mut self) -> Self::Decoder {
        WipingDecoder(PhantomData)
    }
}

/// See [`WipingCodec`].
#[derive(Debug, Clone)]
pub struct WipingEncoder<T>(PhantomData<T>);

impl<T: Message> Encoder for WipingEncoder<T> {
    type Item = T;
    type Error = Status;

    fn encode(&mut self, item: T, buf: &mut EncodeBuf<'_>) -> Result<(), Status> {
        // Grow once, with no part of the message in the buffer yet.
        buf.reserve(item.encoded_len());
        item.encode(buf)
            .map_err(|e| Status::internal(e.to_string()))
    }

    fn buffer_settings(&self) -> BufferSettings {
        buffer_settings()
    }
}

/// See [`WipingCodec`].
#[derive(Debug, Clone)]
pub struct WipingDecoder<U>(PhantomData<U>);

impl<U: Message + Default> Decoder for WipingDecoder<U> {
    type Item = U;
    type Error = Status;

    fn decode(&mut self, buf: &mut DecodeBuf<'_>) -> Result<Option<U>, Status> {
        let len = buf.remaining();
        // SAFETY: tonic's `DecodeBuf` is a view of its receive (or
        // decompression) `BytesMut`, and its `copy_to_bytes` is
        // `BytesMut::split_to(len).freeze()`: heap memory, and the returned
        // `Bytes` is the only handle to its range.
        let bytes = unsafe { wiping(buf.copy_to_bytes(len)) };
        decode_wiping(bytes).map(Some)
    }

    fn buffer_settings(&self) -> BufferSettings {
        buffer_settings()
    }
}

/// Wraps the boundary's gRPC service so the DATA frames it receives and
/// sends are zeroed once consumed. See the module documentation.
#[derive(Debug, Clone)]
pub struct WipeBodies<S>(pub S);

impl<S: NamedService> NamedService for WipeBodies<S> {
    const NAME: &'static str = S::NAME;
}

impl<S, B, R> Service<http::Request<B>> for WipeBodies<S>
where
    S: Service<http::Request<WipeRequest<B>>, Response = http::Response<R>, Error = Infallible>,
    S::Future: Send + 'static,
    R: Body<Data = Bytes> + Send + Unpin + 'static,
    R::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = BoxFuture<Self::Response, Infallible>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.0.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        let fut = self.0.call(req.map(WipeRequest::new));
        Box::pin(async move {
            let resp = fut.await?;
            Ok(resp.map(|b| tonic::body::Body::new(WipeResponse(b))))
        })
    }
}

/// A request body whose DATA frames are zeroed once tonic has copied them,
/// and which hands each message's gRPC header to tonic on its own.
#[derive(Debug)]
pub struct WipeRequest<B> {
    inner: B,
    /// The rest of the last frame, not yet passed on.
    pending: Bytes,
    /// Header bytes seen of the next message.
    header: [u8; HEADER],
    have: usize,
    /// Bytes of the current message's body still to come; zero while the
    /// next piece is header.
    body_left: usize,
}

impl<B> WipeRequest<B> {
    fn new(inner: B) -> Self {
        Self {
            inner,
            pending: Bytes::new(),
            header: [0; HEADER],
            have: 0,
            body_left: 0,
        }
    }

    /// Splits the next piece off `pending`: the rest of a header, or of a
    /// message body, whichever comes first.
    fn next_piece(&mut self) -> Bytes {
        let want = if self.body_left > 0 {
            self.body_left
        } else {
            HEADER - self.have
        };
        let piece = self.pending.split_to(want.min(self.pending.len()));
        if self.body_left > 0 {
            self.body_left -= piece.len();
        } else {
            self.header[self.have..self.have + piece.len()].copy_from_slice(&piece);
            self.have += piece.len();
            if self.have == HEADER {
                self.have = 0;
                let len = u32::from_be_bytes([
                    self.header[1],
                    self.header[2],
                    self.header[3],
                    self.header[4],
                ]);
                self.body_left = usize::try_from(len).unwrap_or(usize::MAX);
            }
        }
        piece
    }
}

impl<B> Body for WipeRequest<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, B::Error>>> {
        let this = &mut *self;
        loop {
            if !this.pending.is_empty() {
                return Poll::Ready(Some(Ok(Frame::data(this.next_piece()))));
            }
            match ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
                Some(Ok(frame)) => match frame.into_data() {
                    // SAFETY: a request body's data is the payload of an h2
                    // DATA frame, split out of h2's read `BytesMut` and frozen;
                    // h2 and hyper pass it on without keeping a handle.
                    Ok(data) => this.pending = unsafe { wiping(data) },
                    Err(frame) => return Poll::Ready(Some(Ok(frame))),
                },
                other => return Poll::Ready(other),
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.pending.is_empty() && self.inner.is_end_stream()
    }
}

/// A response body whose DATA frames are zeroed once h2 has written them.
#[derive(Debug)]
pub struct WipeResponse<B>(B);

impl<B> Body for WipeResponse<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, B::Error>>> {
        let frame = ready!(Pin::new(&mut self.0).poll_frame(cx));
        // SAFETY: tonic's encoder yields each chunk as
        // `BytesMut::split_to(len).freeze()` of its encode buffer: heap
        // memory, and the only handle to its range.
        Poll::Ready(frame.map(|f| f.map(|f| f.map_data(|d| unsafe { wiping(d) }))))
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.0.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use std::collections::VecDeque;

    use crate::v1::{CaptureRequest, ValueEntry};

    fn generated(n: usize) -> Vec<u8> {
        // A value the test makes up at run time; never a real secret.
        (0..n)
            .map(|i| b"abcdefghijklmnopqrstuvwxyz0123456789"[(i * 7 + n) % 36])
            .collect()
    }

    /// `frames` split out of one buffer, as h2 or tonic would hand them over,
    /// plus clones that let the test look at their ranges afterwards. The
    /// clones break `wiping`'s sole-handle condition on purpose: no slice of
    /// them is alive while the range is zeroed.
    fn split(data: &[u8], cuts: &[usize]) -> (VecDeque<Bytes>, Vec<Bytes>) {
        let mut buf = BytesMut::from(data);
        let mut frames = VecDeque::new();
        let mut last = 0;
        for &cut in cuts.iter().chain(std::iter::once(&data.len())) {
            frames.push_back(buf.split_to(cut - last).freeze());
            last = cut;
        }
        let observers = frames.iter().cloned().collect();
        (frames, observers)
    }

    fn zeroed(observers: &[Bytes]) -> bool {
        observers.iter().all(|b| b.iter().all(|&x| x == 0))
    }

    // The message types zero on drop, so they cannot be built with `..`.
    fn capture(id: u64, value: Vec<u8>) -> CaptureRequest {
        let mut c = CaptureRequest::default();
        c.id = id;
        c.value = value;
        c
    }

    fn grpc_frame(m: &impl Message) -> Vec<u8> {
        let body = m.encode_to_vec();
        let mut out = vec![0];
        out.extend_from_slice(&u32::try_from(body.len()).unwrap_or(0).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn wiping_zeroes_the_range_after_the_last_handle() {
        let (mut frames, observers) = split(&generated(64), &[]);
        let b = frames.pop_front().unwrap_or_default();
        // SAFETY: test; see `split`.
        let w = unsafe { wiping(b) };
        let half = w.slice(..32);
        drop(w);
        assert!(!zeroed(&observers), "zeroed while a slice was alive");
        drop(half);
        assert!(zeroed(&observers), "range not zeroed after the last handle");
    }

    #[test]
    fn decoder_zeroes_what_it_decoded() {
        let value = generated(40);
        let wire = capture(3, value.clone()).encode_to_vec();
        let (mut frames, observers) = split(&wire, &[]);
        // SAFETY: test; see `split`.
        let b = unsafe { wiping(frames.pop_front().unwrap_or_default()) };
        let got: CaptureRequest = decode_wiping(b).unwrap_or_default();
        assert_eq!(got.value, value);
        assert!(zeroed(&observers));
    }

    /// Body that yields fixed frames.
    struct Frames(VecDeque<Bytes>);

    impl Body for Frames {
        type Data = Bytes;
        type Error = Status;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Status>>> {
            Poll::Ready(self.0.pop_front().map(|b| Ok(Frame::data(b))))
        }
    }

    fn poll_all<B: Body<Data = Bytes> + Unpin>(mut b: B) -> Vec<Bytes>
    where
        B::Error: std::fmt::Debug,
    {
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut out = Vec::new();
        while let Poll::Ready(Some(f)) = Pin::new(&mut b).poll_frame(&mut cx) {
            if let Ok(d) = f.map(Frame::into_data) {
                out.extend(d.ok());
            }
        }
        out
    }

    #[test]
    fn request_bodies_split_headers_off_and_are_zeroed() {
        let mut a = ValueEntry::default();
        a.r#ref = "mem://t#a".into();
        a.value = generated(300);
        let b = capture(9, generated(20));
        let mut wire = grpc_frame(&a);
        let first = wire.len();
        wire.extend(grpc_frame(&b));
        // Frames cut inside the first header, inside a body, and across the
        // boundary between the messages.
        let (frames, observers) = split(&wire, &[3, 100, first + 2]);
        let pieces = poll_all(WipeRequest::new(Frames(frames)));
        // Each header reaches tonic apart from its body, cut where the frames
        // were cut.
        let lens: Vec<usize> = pieces.iter().map(Bytes::len).collect();
        let body_b = wire.len() - first - HEADER;
        assert_eq!(lens, [3, 2, 95, first - 100, 2, 3, body_b]);
        let joined: Vec<u8> = pieces.iter().flat_map(|p| p.iter().copied()).collect();
        assert_eq!(joined, wire);
        assert!(!zeroed(&observers), "zeroed while pieces were alive");
        drop(pieces);
        assert!(zeroed(&observers), "received frames not zeroed");
    }

    #[test]
    fn response_bodies_are_zeroed_once_written() {
        let wire = grpc_frame(&capture(1, generated(64)));
        let (frames, observers) = split(&wire, &[30]);
        let sent = poll_all(WipeResponse(Frames(frames)));
        assert_eq!(sent.concat(), wire);
        drop(sent);
        assert!(zeroed(&observers), "sent frames not zeroed");
    }

    #[test]
    fn codec_yields_each_message_on_its_own() {
        let mut c = WipingCodec::<CaptureRequest, CaptureRequest>::default();
        assert_eq!(
            format!("{:?}", c.encoder().buffer_settings()),
            format!("{:?}", BufferSettings::new(BUFFER_SIZE, 1))
        );
    }
}
