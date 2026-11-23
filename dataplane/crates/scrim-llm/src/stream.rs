// SPDX-License-Identifier: AGPL-3.0-only

//! Public restore entry points, usable without the HTTP proxy (benchmarks, other listeners).

use std::sync::Arc;

use crate::codec::{self, Api, ArrayCodec, StreamCodec, StreamLimits};
use crate::config::Limits;
use crate::engine::Snapshot;
use crate::jsonarray::{self, ArrayFramer};
use crate::restore::{Ctx, RestoreStats};
use crate::sse::{Framer, Piece};

/// How the stream is framed.
enum Framing {
    /// Server-sent events.
    Sse(Framer, Box<dyn StreamCodec>),
    /// The elements of one JSON array (Gemini `streamGenerateContent` without `alt=sse`).
    Array(ArrayFramer, Box<dyn ArrayCodec>),
}

/// A response body restorer fed chunk by chunk: SSE ([`SseRestorer`]) or an Amazon event
/// stream ([`crate::eventstream::EventStreamRestorer`]).
pub trait ChunkRestore: Send {
    /// Feeds one chunk as received from the provider and appends what the agent should receive.
    fn push(&mut self, chunk: &[u8], out: &mut Vec<u8>);
    /// Ends the stream: releases held text and any unterminated trailing bytes.
    fn finish(&mut self, out: &mut Vec<u8>);
    /// Placeholders resolved so far.
    fn resolved(&self) -> u64;
    /// Placeholders kept so far.
    fn kept(&self) -> u64;
}

impl ChunkRestore for SseRestorer {
    fn push(&mut self, chunk: &[u8], out: &mut Vec<u8>) {
        SseRestorer::push(self, chunk, out);
    }
    fn finish(&mut self, out: &mut Vec<u8>) {
        SseRestorer::finish(self, out);
    }
    fn resolved(&self) -> u64 {
        SseRestorer::resolved(self)
    }
    fn kept(&self) -> u64 {
        SseRestorer::kept(self)
    }
}

/// Restores placeholders in one provider stream: SSE, or a streamed JSON array
/// ([`SseRestorer::json_array`]).
///
/// Memory is bounded by `limits.max_event` (one partial event or array element) plus, per open
/// content block, `Placeholders::max_len() - 1` held bytes, plus
/// `limits.max_buffered_tool_input` across the stream for tools fed in buffered mode.
pub struct SseRestorer {
    framing: Framing,
    snap: Arc<Snapshot>,
    stats: RestoreStats,
}

impl std::fmt::Debug for SseRestorer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let buffered = match &self.framing {
            Framing::Sse(fr, _) => fr.buffered(),
            Framing::Array(fr, _) => fr.buffered(),
        };
        f.debug_struct("SseRestorer")
            .field("buffered", &buffered)
            .finish_non_exhaustive()
    }
}

impl SseRestorer {
    /// A restorer for `api`'s stream format, or `None` for [`Api::Generic`] (pass through).
    pub fn new(api: Api, snap: Arc<Snapshot>, limits: &Limits) -> Option<Self> {
        let codec = codec::stream_codec(
            api,
            StreamLimits {
                max_buffered_tool_input: limits.max_buffered_tool_input,
            },
        )?;
        Some(Self {
            framing: Framing::Sse(Framer::new(limits.max_event), codec),
            snap,
            stats: RestoreStats::default(),
        })
    }

    /// A restorer for `api`'s streamed JSON array (Gemini `streamGenerateContent` without
    /// `alt=sse`), or `None` when the API has no such stream.
    pub fn json_array(api: Api, snap: Arc<Snapshot>, limits: &Limits) -> Option<Self> {
        let codec = codec::array_codec(
            api,
            StreamLimits {
                max_buffered_tool_input: limits.max_buffered_tool_input,
            },
        )?;
        Some(Self {
            framing: Framing::Array(ArrayFramer::new(limits.max_event), codec),
            snap,
            stats: RestoreStats::default(),
        })
    }

    /// Feeds one chunk as received from the provider and appends what the agent should receive.
    pub fn push(&mut self, chunk: &[u8], out: &mut Vec<u8>) {
        let ctx = Ctx {
            snap: &self.snap,
            stats: &self.stats,
        };
        match &mut self.framing {
            Framing::Sse(framer, codec) => framer.push(chunk, &mut |p| match p {
                Piece::Event(e) => codec.event(&ctx, e, out),
                Piece::Raw(r) => out.extend_from_slice(r),
            }),
            Framing::Array(framer, codec) => framer.push(chunk, &mut |p| match p {
                jsonarray::Piece::Element(e) => codec.element(&ctx, e, out),
                jsonarray::Piece::Raw(r) => out.extend_from_slice(r),
                jsonarray::Piece::Close(c) => {
                    codec.close(&ctx, out);
                    out.extend_from_slice(c);
                }
            }),
        }
    }

    /// Ends the stream: releases held text and any unterminated trailing bytes.
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        let ctx = Ctx {
            snap: &self.snap,
            stats: &self.stats,
        };
        match &mut self.framing {
            Framing::Sse(framer, codec) => {
                codec.finish(&ctx, out);
                out.extend_from_slice(&framer.finish());
            }
            Framing::Array(framer, codec) => {
                // An unterminated element goes first, so held text is not placed inside it.
                out.extend_from_slice(&framer.finish());
                codec.finish(&ctx, out);
            }
        }
    }

    /// Placeholders resolved so far.
    pub fn resolved(&self) -> u64 {
        self.stats.resolved.get()
    }

    /// Placeholders kept so far.
    pub fn kept(&self) -> u64 {
        self.stats.kept.get()
    }
}

/// Restores a complete (non-streaming) JSON response of `api`. Returns `None` when nothing was
/// resolved or the body is not a response the codec understands, in which case the original
/// bytes are what the agent should receive.
pub fn restore_json(api: Api, snap: &Snapshot, body: &[u8]) -> Option<Vec<u8>> {
    let stats = RestoreStats::default();
    codec::restore_json(
        api,
        &Ctx {
            snap,
            stats: &stats,
        },
        body,
    )
}
