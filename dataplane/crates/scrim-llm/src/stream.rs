// SPDX-License-Identifier: AGPL-3.0-only

//! Public restore entry points, usable without the HTTP proxy (benchmarks, other listeners).

use std::sync::Arc;

use crate::codec::{self, Api, StreamCodec, StreamLimits};
use crate::config::Limits;
use crate::engine::Snapshot;
use crate::restore::{Ctx, RestoreStats};
use crate::sse::{Framer, Piece};

/// Restores placeholders in one provider SSE stream.
///
/// Memory is bounded by `limits.max_event` (one partial event) plus, per open content block,
/// `Placeholders::max_len() - 1` held bytes, plus `limits.max_buffered_tool_input` across the
/// stream for tools fed in buffered mode.
pub struct SseRestorer {
    framer: Framer,
    codec: Box<dyn StreamCodec>,
    snap: Arc<Snapshot>,
    stats: RestoreStats,
}

impl std::fmt::Debug for SseRestorer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SseRestorer")
            .field("buffered", &self.framer.buffered())
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
            framer: Framer::new(limits.max_event),
            codec,
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
        let codec = &mut self.codec;
        self.framer.push(chunk, &mut |p| match p {
            Piece::Event(e) => codec.event(&ctx, e, out),
            Piece::Raw(r) => out.extend_from_slice(r),
        });
    }

    /// Ends the stream: releases held text and any unterminated trailing bytes.
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        let ctx = Ctx {
            snap: &self.snap,
            stats: &self.stats,
        };
        self.codec.finish(&ctx, out);
        out.extend_from_slice(&self.framer.finish());
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
