// SPDX-License-Identifier: AGPL-3.0-only

//! Amazon event stream framing (`application/vnd.amazon.eventstream`), as Bedrock streams
//! `InvokeModelWithResponseStream` and `ConverseStream` responses.
//!
//! A message is `total length (u32) | headers length (u32) | prelude CRC | headers | payload |
//! message CRC`, big-endian, CRC-32 (IEEE) over the prelude and over everything before the
//! message CRC. Headers are `name length (u8) | name | type (u8) | value`.
//!
//! [`EventStreamRestorer`] restores placeholders inside the frames and recomputes both CRCs for
//! every frame it changes. Unchanged frames leave byte for byte. A frame it cannot parse (bad
//! CRC, impossible lengths) and everything after it passes through untouched: placeholders stay
//! placeholders, which is safe.
//!
//! Two payload shapes are handled:
//!
//! * `InvokeModelWithResponseStream` (Claude): `chunk` events whose JSON payload holds the
//!   Anthropic Messages stream event base64-encoded in `bytes`. The decoded events go through the
//!   Anthropic stream restorer and come back out re-encoded, one frame per event.
//! * `ConverseStream`: `contentBlockStart`, `contentBlockDelta`, `contentBlockStop`,
//!   `messageStop` and `metadata` events with plain JSON payloads, restored by
//!   [`crate::codec::converse`].

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

use crate::codec::converse;
use crate::codec::{Api, StreamLimits};
use crate::config::Limits;
use crate::engine::Snapshot;
use crate::json::{self, Doc};
use crate::restore::{Ctx, RestoreStats};
use crate::sse::{self, Framer, Piece};
use crate::stream::{ChunkRestore, SseRestorer};

/// The media type of an event stream.
pub const CONTENT_TYPE: &str = "application/vnd.amazon.eventstream";

/// Smallest possible message: prelude, no headers, no payload, message CRC.
const MIN_MESSAGE: usize = 16;

/// A header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderValue {
    /// Type 0 (true) or 1 (false).
    Bool(bool),
    /// Type 2.
    Byte(i8),
    /// Type 3.
    Short(i16),
    /// Type 4.
    Int(i32),
    /// Type 5.
    Long(i64),
    /// Type 6.
    Bytes(Vec<u8>),
    /// Type 7.
    String(String),
    /// Type 8, milliseconds since the epoch.
    Timestamp(i64),
    /// Type 9.
    Uuid([u8; 16]),
}

/// One decoded message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Headers in wire order.
    pub headers: Vec<(String, HeaderValue)>,
    /// Payload bytes.
    pub payload: Vec<u8>,
}

impl Message {
    /// The string value of header `name`.
    pub fn header_str(&self, name: &str) -> Option<&str> {
        self.headers.iter().find_map(|(n, v)| match v {
            HeaderValue::String(s) if n == name => Some(s.as_str()),
            _ => None,
        })
    }

    /// Encodes the message, computing both CRCs.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "names and values are cut to their field widths first; a message is far below 4 GiB"
    )]
    pub fn encode(&self) -> Vec<u8> {
        let mut hdr = Vec::new();
        for (name, v) in &self.headers {
            // Names longer than 255 bytes cannot be represented; they never come from a parsed
            // message, which holds at most 255.
            let n = name.as_bytes();
            let n = &n[..n.len().min(255)];
            hdr.push(n.len() as u8);
            hdr.extend_from_slice(n);
            match v {
                HeaderValue::Bool(true) => hdr.push(0),
                HeaderValue::Bool(false) => hdr.push(1),
                HeaderValue::Byte(b) => {
                    hdr.push(2);
                    hdr.extend_from_slice(&b.to_be_bytes());
                }
                HeaderValue::Short(s) => {
                    hdr.push(3);
                    hdr.extend_from_slice(&s.to_be_bytes());
                }
                HeaderValue::Int(i) => {
                    hdr.push(4);
                    hdr.extend_from_slice(&i.to_be_bytes());
                }
                HeaderValue::Long(l) => {
                    hdr.push(5);
                    hdr.extend_from_slice(&l.to_be_bytes());
                }
                HeaderValue::Bytes(b) => {
                    hdr.push(6);
                    let b = &b[..b.len().min(u16::MAX as usize)];
                    hdr.extend_from_slice(&(b.len() as u16).to_be_bytes());
                    hdr.extend_from_slice(b);
                }
                HeaderValue::String(s) => {
                    hdr.push(7);
                    let b = &s.as_bytes()[..s.len().min(u16::MAX as usize)];
                    hdr.extend_from_slice(&(b.len() as u16).to_be_bytes());
                    hdr.extend_from_slice(b);
                }
                HeaderValue::Timestamp(t) => {
                    hdr.push(8);
                    hdr.extend_from_slice(&t.to_be_bytes());
                }
                HeaderValue::Uuid(u) => {
                    hdr.push(9);
                    hdr.extend_from_slice(u);
                }
            }
        }
        let total = 12 + hdr.len() + self.payload.len() + 4;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&(total as u32).to_be_bytes());
        out.extend_from_slice(&(hdr.len() as u32).to_be_bytes());
        let prelude_crc = crc32fast::hash(&out[..8]);
        out.extend_from_slice(&prelude_crc.to_be_bytes());
        out.extend_from_slice(&hdr);
        out.extend_from_slice(&self.payload);
        let crc = crc32fast::hash(&out);
        out.extend_from_slice(&crc.to_be_bytes());
        out
    }
}

/// Why a message could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// Lengths that cannot describe a message.
    #[error("event stream: bad lengths")]
    Length,
    /// The prelude CRC does not match.
    #[error("event stream: prelude CRC mismatch")]
    PreludeCrc,
    /// The message CRC does not match.
    #[error("event stream: message CRC mismatch")]
    MessageCrc,
    /// A header could not be read.
    #[error("event stream: bad header")]
    Header,
}

/// The total length a buffer's first message announces, once 12 bytes are there.
fn announced(buf: &[u8]) -> Option<Result<usize, FrameError>> {
    if buf.len() < 12 {
        return None;
    }
    let total = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let hlen = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
    let crc = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
    if crc32fast::hash(&buf[..8]) != crc {
        return Some(Err(FrameError::PreludeCrc));
    }
    if total < MIN_MESSAGE || hlen > total - MIN_MESSAGE {
        return Some(Err(FrameError::Length));
    }
    Some(Ok(total))
}

fn fixed<const N: usize>(h: &mut &[u8]) -> Result<[u8; N], FrameError> {
    let (a, b) = h.split_first_chunk::<N>().ok_or(FrameError::Header)?;
    *h = b;
    Ok(*a)
}

/// Decodes one complete message.
pub fn decode(raw: &[u8]) -> Result<Message, FrameError> {
    let total = match announced(raw) {
        None => return Err(FrameError::Length),
        Some(r) => r?,
    };
    if raw.len() != total {
        return Err(FrameError::Length);
    }
    let crc = u32::from_be_bytes([
        raw[total - 4],
        raw[total - 3],
        raw[total - 2],
        raw[total - 1],
    ]);
    if crc32fast::hash(&raw[..total - 4]) != crc {
        return Err(FrameError::MessageCrc);
    }
    let hlen = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize;
    let mut h = &raw[12..12 + hlen];
    let mut headers = Vec::new();
    let take = |h: &mut &[u8], n: usize| -> Result<Vec<u8>, FrameError> {
        if h.len() < n {
            return Err(FrameError::Header);
        }
        let (a, b) = h.split_at(n);
        *h = b;
        Ok(a.to_vec())
    };
    while !h.is_empty() {
        let n = take(&mut h, 1)?[0] as usize;
        let name = String::from_utf8(take(&mut h, n)?).map_err(|_| FrameError::Header)?;
        let ty = take(&mut h, 1)?[0];
        let v = match ty {
            0 => HeaderValue::Bool(true),
            1 => HeaderValue::Bool(false),
            2 => HeaderValue::Byte(i8::from_be_bytes(fixed(&mut h)?)),
            3 => HeaderValue::Short(i16::from_be_bytes(fixed(&mut h)?)),
            4 => HeaderValue::Int(i32::from_be_bytes(fixed(&mut h)?)),
            5 => HeaderValue::Long(i64::from_be_bytes(fixed(&mut h)?)),
            6 | 7 => {
                let l = take(&mut h, 2)?;
                let l = u16::from_be_bytes([l[0], l[1]]) as usize;
                let b = take(&mut h, l)?;
                if ty == 6 {
                    HeaderValue::Bytes(b)
                } else {
                    HeaderValue::String(String::from_utf8(b).map_err(|_| FrameError::Header)?)
                }
            }
            8 => HeaderValue::Timestamp(i64::from_be_bytes(fixed(&mut h)?)),
            9 => {
                let b = take(&mut h, 16)?;
                let mut u = [0u8; 16];
                u.copy_from_slice(&b);
                HeaderValue::Uuid(u)
            }
            _ => return Err(FrameError::Header),
        };
        headers.push((name, v));
    }
    Ok(Message {
        headers,
        payload: raw[12 + hlen..total - 4].to_vec(),
    })
}

/// What the restorer does with the bytes of the frame it is in.
enum Mode {
    /// Collecting frames.
    Frames,
    /// Passing `n` more bytes of an oversized frame through, then back to framing.
    Skip(usize),
    /// Everything from here on passes through.
    Raw,
}

/// The payload codec of one stream.
enum Payloads {
    /// `InvokeModelWithResponseStream`: Anthropic Messages events in `chunk.bytes`.
    Invoke {
        sse: Box<SseRestorer>,
        framer: Framer,
        /// Headers of the last `chunk` frame, for frames built from restored events.
        template: Vec<(String, HeaderValue)>,
    },
    /// `ConverseStream`.
    Converse {
        codec: converse::Stream,
        snap: Arc<Snapshot>,
        stats: RestoreStats,
    },
}

/// Restores placeholders in one Bedrock event stream.
///
/// Memory is bounded by `limits.max_event` (one partial frame) plus what the payload codec holds
/// (one placeholder length per open content block, buffered tool arguments).
pub struct EventStreamRestorer {
    buf: Vec<u8>,
    max: usize,
    mode: Mode,
    payloads: Payloads,
}

impl std::fmt::Debug for EventStreamRestorer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventStreamRestorer")
            .field("buffered", &self.buf.len())
            .finish_non_exhaustive()
    }
}

impl EventStreamRestorer {
    /// A restorer for `api`'s event stream: [`Api::AnthropicMessages`] for
    /// `InvokeModelWithResponseStream`, [`Api::BedrockConverse`] for `ConverseStream`. `None`
    /// for anything else (pass through).
    pub fn new(api: Api, snap: Arc<Snapshot>, limits: &Limits) -> Option<Self> {
        let payloads = match api {
            Api::AnthropicMessages => Payloads::Invoke {
                sse: Box::new(SseRestorer::new(api, snap, limits)?),
                framer: Framer::new(usize::MAX),
                template: chunk_headers(),
            },
            Api::BedrockConverse => Payloads::Converse {
                codec: converse::Stream::new(StreamLimits {
                    max_buffered_tool_input: limits.max_buffered_tool_input,
                }),
                snap,
                stats: RestoreStats::default(),
            },
            _ => return None,
        };
        Some(Self {
            buf: Vec::new(),
            max: limits.max_event.max(MIN_MESSAGE),
            mode: Mode::Frames,
            payloads,
        })
    }

    fn frame(&mut self, raw: &[u8], out: &mut Vec<u8>) {
        let Ok(msg) = decode(raw) else {
            // A frame the announced length and CRCs vouch for but whose headers do not parse:
            // pass it on unchanged.
            return out.extend_from_slice(raw);
        };
        match &mut self.payloads {
            Payloads::Invoke {
                sse,
                framer,
                template,
            } => {
                let Some(event) = invoke_event(&msg) else {
                    return out.extend_from_slice(raw);
                };
                template.clone_from(&msg.headers);
                let mut restored = Vec::new();
                sse.push(&event.sse, &mut restored);
                if restored == event.sse {
                    // Nothing changed: the frame leaves exactly as it came.
                    return out.extend_from_slice(raw);
                }
                reframe(framer, template, &restored, out);
            }
            Payloads::Converse { codec, snap, stats } => {
                let ctx = Ctx { snap, stats };
                codec.message(&ctx, raw, &msg, out);
            }
        }
    }
}

/// The headers Bedrock sends on every `chunk` event.
fn chunk_headers() -> Vec<(String, HeaderValue)> {
    vec![
        (":event-type".into(), HeaderValue::String("chunk".into())),
        (
            ":content-type".into(),
            HeaderValue::String("application/json".into()),
        ),
        (":message-type".into(), HeaderValue::String("event".into())),
    ]
}

/// An Anthropic stream event carried in an `InvokeModelWithResponseStream` chunk.
struct InvokeEvent {
    /// The event as one SSE event (`event: <type>` and one data line).
    sse: Vec<u8>,
}

fn invoke_event(msg: &Message) -> Option<InvokeEvent> {
    if msg.header_str(":message-type") != Some("event")
        || msg.header_str(":event-type") != Some("chunk")
    {
        return None;
    }
    let doc = Doc::parse(&msg.payload).ok()?;
    let b64 = doc.root().get_str("bytes").ok()??;
    let data = B64.decode(b64.as_bytes()).ok()?;
    // The decoded event is one JSON object; an SSE data line holds no line break, and JSON
    // whitespace may be one, so such an event is left alone.
    if memchr::memchr2(b'\n', b'\r', &data).is_some() {
        return None;
    }
    let ty = Doc::parse(&data).ok()?.root().get_str("type").ok()??;
    Some(InvokeEvent {
        sse: sse::build(Some(&ty), &data),
    })
}

/// Turns restored SSE events back into `chunk` frames.
fn reframe(
    framer: &mut Framer,
    template: &[(String, HeaderValue)],
    restored: &[u8],
    out: &mut Vec<u8>,
) {
    framer.push(restored, &mut |p| {
        let Piece::Event(raw) = p else { return };
        let Some(ev) = sse::Event::parse(raw) else {
            return;
        };
        if !ev.has_data {
            return;
        }
        let mut payload = Vec::with_capacity(ev.data.len() * 4 / 3 + 16);
        payload.extend_from_slice(b"{\"bytes\":");
        payload.extend_from_slice(&json::quote(&B64.encode(ev.data.as_bytes())));
        payload.push(b'}');
        out.extend_from_slice(
            &Message {
                headers: template.to_vec(),
                payload,
            }
            .encode(),
        );
    });
}

impl ChunkRestore for EventStreamRestorer {
    fn push(&mut self, mut chunk: &[u8], out: &mut Vec<u8>) {
        loop {
            match self.mode {
                Mode::Raw => return out.extend_from_slice(chunk),
                Mode::Skip(n) => {
                    let k = n.min(chunk.len());
                    out.extend_from_slice(&chunk[..k]);
                    chunk = &chunk[k..];
                    self.mode = if k == n {
                        Mode::Frames
                    } else {
                        Mode::Skip(n - k)
                    };
                    if chunk.is_empty() {
                        return;
                    }
                }
                Mode::Frames => {
                    self.buf.extend_from_slice(chunk);
                    loop {
                        match announced(&self.buf) {
                            Some(Err(_)) => {
                                out.append(&mut self.buf);
                                self.mode = Mode::Raw;
                                return;
                            }
                            Some(Ok(total)) if total > self.max => {
                                // Too large to hold: pass this frame through as it comes.
                                let k = total.min(self.buf.len());
                                out.extend(self.buf.drain(..k));
                                if k < total {
                                    self.mode = Mode::Skip(total - k);
                                    return;
                                }
                            }
                            Some(Ok(total)) if self.buf.len() >= total => {
                                let raw: Vec<u8> = self.buf.drain(..total).collect();
                                self.frame(&raw, out);
                            }
                            None | Some(Ok(_)) => return,
                        }
                    }
                }
            }
        }
    }

    fn finish(&mut self, out: &mut Vec<u8>) {
        match &mut self.payloads {
            Payloads::Invoke {
                sse,
                framer,
                template,
            } => {
                let mut restored = Vec::new();
                sse.finish(&mut restored);
                reframe(framer, template, &restored, out);
            }
            Payloads::Converse { codec, snap, stats } => {
                let ctx = Ctx { snap, stats };
                codec.finish(&ctx, out);
            }
        }
        out.append(&mut self.buf);
    }

    fn resolved(&self) -> u64 {
        match &self.payloads {
            Payloads::Invoke { sse, .. } => sse.resolved(),
            Payloads::Converse { stats, .. } => stats.resolved.get(),
        }
    }

    fn kept(&self) -> u64 {
        match &self.payloads {
            Payloads::Invoke { sse, .. } => sse.kept(),
            Payloads::Converse { stats, .. } => stats.kept.get(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(event: &str, payload: &[u8]) -> Message {
        Message {
            headers: vec![
                (":event-type".into(), HeaderValue::String(event.into())),
                (
                    ":content-type".into(),
                    HeaderValue::String("application/json".into()),
                ),
                (":message-type".into(), HeaderValue::String("event".into())),
            ],
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn round_trips_every_header_type() {
        let m = Message {
            headers: vec![
                ("t".into(), HeaderValue::Bool(true)),
                ("f".into(), HeaderValue::Bool(false)),
                ("b".into(), HeaderValue::Byte(-3)),
                ("s".into(), HeaderValue::Short(-300)),
                ("i".into(), HeaderValue::Int(-70_000)),
                ("l".into(), HeaderValue::Long(-5_000_000_000)),
                ("y".into(), HeaderValue::Bytes(vec![0, 1, 2])),
                ("str".into(), HeaderValue::String("hé".into())),
                ("ts".into(), HeaderValue::Timestamp(1_700_000_000_000)),
                ("u".into(), HeaderValue::Uuid([7; 16])),
            ],
            payload: b"{\"a\":1}".to_vec(),
        };
        let enc = m.encode();
        assert_eq!(decode(&enc).unwrap(), m);
    }

    #[test]
    fn known_vector() {
        // The empty message from the AWS event stream test suite (`empty_message`).
        let raw = [
            0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x05, 0xc2, 0x48, 0xeb, 0x7d, 0x98,
            0xc8, 0xff,
        ];
        let m = decode(&raw).unwrap();
        assert!(m.headers.is_empty() && m.payload.is_empty());
        assert_eq!(m.encode(), raw);
    }

    #[test]
    fn corrupt_frames_are_refused() {
        let mut enc = msg("chunk", b"{}").encode();
        let last = enc.len() - 1;
        enc[last] ^= 1;
        assert_eq!(decode(&enc), Err(FrameError::MessageCrc));
        let mut enc = msg("chunk", b"{}").encode();
        enc[0] ^= 1;
        assert_eq!(decode(&enc), Err(FrameError::PreludeCrc));
    }

    #[test]
    fn frames_any_split() {
        let frames: Vec<u8> = (0..3)
            .flat_map(|i| msg("other", format!("{{\"n\":{i}}}").as_bytes()).encode())
            .collect();
        for cut in 1..frames.len() {
            let mut buf = Vec::new();
            let mut got = Vec::new();
            for part in [&frames[..cut], &frames[cut..]] {
                buf.extend_from_slice(part);
                while let Some(Ok(total)) = announced(&buf) {
                    if buf.len() < total {
                        break;
                    }
                    got.push(decode(&buf.drain(..total).collect::<Vec<_>>()).unwrap());
                }
            }
            assert_eq!(got.len(), 3, "cut {cut}");
        }
    }
}
