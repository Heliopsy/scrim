//! Content codings: gzip, deflate, br and zstd, decoded and re-encoded incrementally.
//!
//! Every coder is a push-style [`Transform`]: bytes in, bytes out, then `finish`. Encoders flush
//! after every push so a streamed response keeps flowing chunk by chunk. Decoders enforce an output
//! limit so a small compressed body cannot expand without bound.

use std::io::{self, Write};

use http::HeaderMap;

/// A supported content coding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coding {
    /// `gzip`, `x-gzip`.
    Gzip,
    /// `deflate` (zlib framing; raw deflate is accepted on decode).
    Deflate,
    /// `br`.
    Brotli,
    /// `zstd`.
    Zstd,
}

impl Coding {
    /// The token written in `Content-Encoding`.
    pub fn token(self) -> &'static str {
        match self {
            Coding::Gzip => "gzip",
            Coding::Deflate => "deflate",
            Coding::Brotli => "br",
            Coding::Zstd => "zstd",
        }
    }
}

/// The `Content-Encoding` chain of a message, in the order the codings were applied.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Codings(pub Vec<Coding>);

/// Parses every `Content-Encoding` header. `Err` carries the first unsupported token.
pub(crate) fn parse_codings(headers: &HeaderMap) -> Result<Codings, String> {
    let mut out = Vec::new();
    for v in headers.get_all(http::header::CONTENT_ENCODING) {
        let s = v.to_str().map_err(|_| "(non-ASCII)".to_owned())?;
        for tok in s.split(',') {
            let t = tok.trim().to_ascii_lowercase();
            match t.as_str() {
                "" | "identity" => {}
                "gzip" | "x-gzip" => out.push(Coding::Gzip),
                "deflate" => out.push(Coding::Deflate),
                "br" => out.push(Coding::Brotli),
                "zstd" => out.push(Coding::Zstd),
                other => return Err(other.to_owned()),
            }
        }
    }
    Ok(Codings(out))
}

/// Incremental byte transform.
pub(crate) trait Transform: Send {
    /// Processes `input`, appending output to `out`.
    fn push(&mut self, input: &[u8], out: &mut Vec<u8>) -> io::Result<()>;
    /// Ends the stream, appending any remaining output.
    fn finish(&mut self, out: &mut Vec<u8>) -> io::Result<()>;
}

/// Shared sink the write-side coders write into.
#[derive(Default)]
struct Sink {
    buf: Vec<u8>,
    total: u64,
    limit: u64,
}

impl Write for Sink {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.total += data.len() as u64;
        if self.total > self.limit {
            return Err(io::Error::other(
                "decoded body exceeds the configured limit",
            ));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

enum Dec {
    Gzip(flate2::write::MultiGzDecoder<Sink>),
    Zlib(flate2::write::ZlibDecoder<Sink>),
    Raw(flate2::write::DeflateDecoder<Sink>),
    /// Deflate before the first bytes decide between zlib and raw framing.
    DeflatePending(Vec<u8>, u64),
    Brotli(Box<brotli::DecompressorWriter<Sink>>),
    Zstd(Box<ZstdDec>),
}

/// zstd through the raw API, which tells whether the last frame ended.
struct ZstdDec {
    d: zstd::stream::raw::Decoder<'static>,
    sink: Sink,
    /// Bytes still expected by the current frame; 0 when a frame has just ended.
    hint: usize,
    started: bool,
}

impl ZstdDec {
    fn push(&mut self, input: &[u8]) -> io::Result<()> {
        use zstd::stream::raw::{InBuffer, Operation, OutBuffer};
        let mut inb = InBuffer::around(input);
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let mut outb = OutBuffer::around(buf.as_mut_slice());
            if inb.pos() < input.len() {
                self.started = true;
            }
            self.hint = self.d.run(&mut inb, &mut outb)?;
            let produced = outb.pos();
            self.sink.write_all(&buf[..produced])?;
            if inb.pos() >= input.len() && produced < buf.len() {
                return Ok(());
            }
        }
    }
}

/// Decoder for one coding.
pub(crate) struct Decoder(Dec);

impl Decoder {
    pub(crate) fn new(c: Coding, limit: u64) -> io::Result<Self> {
        let sink = Sink {
            buf: Vec::new(),
            total: 0,
            limit,
        };
        Ok(Self(match c {
            Coding::Gzip => Dec::Gzip(flate2::write::MultiGzDecoder::new(sink)),
            Coding::Deflate => Dec::DeflatePending(Vec::new(), limit),
            Coding::Brotli => Dec::Brotli(Box::new(brotli::DecompressorWriter::new(sink, 8192))),
            Coding::Zstd => Dec::Zstd(Box::new(ZstdDec {
                d: zstd::stream::raw::Decoder::new()?,
                sink,
                hint: 0,
                started: false,
            })),
        }))
    }

    fn sink(&mut self) -> Option<&mut Sink> {
        match &mut self.0 {
            Dec::Gzip(d) => Some(d.get_mut()),
            Dec::Zlib(d) => Some(d.get_mut()),
            Dec::Raw(d) => Some(d.get_mut()),
            Dec::DeflatePending(..) => None,
            Dec::Brotli(d) => Some(d.get_mut()),
            Dec::Zstd(d) => Some(&mut d.sink),
        }
    }

    fn drain(&mut self, out: &mut Vec<u8>) {
        if let Some(s) = self.sink() {
            out.append(&mut s.buf);
        }
    }
}

/// zlib streams start with a CMF byte for deflate (low nibble 8) and a check value.
fn looks_like_zlib(head: &[u8]) -> bool {
    head.len() >= 2
        && head[0] & 0x0f == 8
        && (u16::from(head[0]) << 8 | u16::from(head[1])) % 31 == 0
}

impl Transform for Decoder {
    fn push(&mut self, input: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        if let Dec::DeflatePending(buf, limit) = &mut self.0 {
            buf.extend_from_slice(input);
            if buf.len() < 2 {
                return Ok(());
            }
            let head = std::mem::take(buf);
            let sink = Sink {
                buf: Vec::new(),
                total: 0,
                limit: *limit,
            };
            self.0 = if looks_like_zlib(&head) {
                Dec::Zlib(flate2::write::ZlibDecoder::new(sink))
            } else {
                Dec::Raw(flate2::write::DeflateDecoder::new(sink))
            };
            return self.push(&head, out);
        }
        match &mut self.0 {
            Dec::Gzip(d) => {
                d.write_all(input)?;
                d.flush()?;
            }
            Dec::Zlib(d) => {
                d.write_all(input)?;
                d.flush()?;
            }
            Dec::Raw(d) => {
                d.write_all(input)?;
                d.flush()?;
            }
            Dec::Brotli(d) => {
                d.write_all(input)?;
                d.flush()?;
            }
            Dec::Zstd(d) => d.push(input)?,
            Dec::DeflatePending(..) => unreachable!(),
        }
        self.drain(out);
        Ok(())
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        match &mut self.0 {
            Dec::DeflatePending(buf, _) if buf.is_empty() => return Ok(()),
            Dec::DeflatePending(..) => return Err(io::Error::other("truncated deflate stream")),
            Dec::Gzip(d) => d.try_finish()?,
            Dec::Zlib(d) => d.try_finish()?,
            Dec::Raw(d) => d.try_finish()?,
            Dec::Brotli(d) => {
                d.flush()?;
                // `close` reports an incomplete stream.
                d.close()?;
            }
            Dec::Zstd(d) => {
                if d.started && d.hint != 0 {
                    return Err(io::Error::other("truncated zstd stream"));
                }
            }
        }
        self.drain(out);
        Ok(())
    }
}

enum Enc {
    Gzip(flate2::write::GzEncoder<Vec<u8>>),
    Zlib(flate2::write::ZlibEncoder<Vec<u8>>),
    Brotli(Box<brotli::CompressorWriter<Vec<u8>>>),
    Zstd(zstd::stream::write::Encoder<'static, Vec<u8>>),
    Done,
}

/// Encoder for one coding. `flush_each` flushes after every push (streaming).
pub(crate) struct Encoder {
    enc: Enc,
    flush_each: bool,
}

impl Encoder {
    pub(crate) fn new(c: Coding, flush_each: bool) -> io::Result<Self> {
        let level = flate2::Compression::default();
        let enc = match c {
            Coding::Gzip => Enc::Gzip(flate2::write::GzEncoder::new(Vec::new(), level)),
            Coding::Deflate => Enc::Zlib(flate2::write::ZlibEncoder::new(Vec::new(), level)),
            Coding::Brotli => Enc::Brotli(Box::new(brotli::CompressorWriter::new(
                Vec::new(),
                8192,
                5,
                22,
            ))),
            Coding::Zstd => Enc::Zstd(zstd::stream::write::Encoder::new(Vec::new(), 3)?),
        };
        Ok(Self { enc, flush_each })
    }

    fn take(&mut self, out: &mut Vec<u8>) {
        match &mut self.enc {
            Enc::Gzip(e) => out.append(e.get_mut()),
            Enc::Zlib(e) => out.append(e.get_mut()),
            Enc::Brotli(e) => out.append(e.get_mut()),
            Enc::Zstd(e) => out.append(e.get_mut()),
            Enc::Done => {}
        }
    }
}

impl Transform for Encoder {
    fn push(&mut self, input: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        if input.is_empty() {
            return Ok(());
        }
        match &mut self.enc {
            Enc::Gzip(e) => e.write_all(input)?,
            Enc::Zlib(e) => e.write_all(input)?,
            Enc::Brotli(e) => e.write_all(input)?,
            Enc::Zstd(e) => e.write_all(input)?,
            Enc::Done => return Err(io::Error::other("encoder already finished")),
        }
        if self.flush_each {
            match &mut self.enc {
                Enc::Gzip(e) => e.flush()?,
                Enc::Zlib(e) => e.flush()?,
                Enc::Brotli(e) => e.flush()?,
                Enc::Zstd(e) => e.flush()?,
                Enc::Done => {}
            }
        }
        self.take(out);
        Ok(())
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        let data = match std::mem::replace(&mut self.enc, Enc::Done) {
            Enc::Gzip(e) => e.finish()?,
            Enc::Zlib(e) => e.finish()?,
            Enc::Brotli(mut e) => {
                e.flush()?;
                e.into_inner()
            }
            Enc::Zstd(e) => e.finish()?,
            Enc::Done => Vec::new(),
        };
        out.extend_from_slice(&data);
        Ok(())
    }
}

/// Decodes a whole body through `codings` (applied in order, so decoded in reverse).
pub(crate) fn decode_all(body: &[u8], codings: &Codings, limit: u64) -> io::Result<Vec<u8>> {
    let mut cur = body.to_vec();
    for c in codings.0.iter().rev() {
        let mut d = Decoder::new(*c, limit)?;
        let mut out = Vec::new();
        d.push(&cur, &mut out)?;
        d.finish(&mut out)?;
        cur = out;
    }
    Ok(cur)
}

/// Encodes a whole body through `codings` in order.
pub(crate) fn encode_all(body: &[u8], codings: &Codings) -> io::Result<Vec<u8>> {
    let mut cur = body.to_vec();
    for c in &codings.0 {
        let mut e = Encoder::new(*c, false)?;
        let mut out = Vec::new();
        e.push(&cur, &mut out)?;
        e.finish(&mut out)?;
        cur = out;
    }
    Ok(cur)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]
mod tests {
    use super::*;

    const ALL: [Coding; 4] = [Coding::Gzip, Coding::Deflate, Coding::Brotli, Coding::Zstd];

    #[test]
    fn round_trip_each_coding() {
        let body = b"{\"hello\":\"world\"}".repeat(200);
        for c in ALL {
            let cs = Codings(vec![c]);
            let enc = encode_all(&body, &cs).unwrap();
            assert_ne!(enc, body);
            assert_eq!(decode_all(&enc, &cs, 1 << 20).unwrap(), body, "{c:?}");
        }
    }

    #[test]
    fn stacked_codings() {
        let body = b"stacked".repeat(100);
        let cs = Codings(vec![Coding::Gzip, Coding::Brotli]);
        let enc = encode_all(&body, &cs).unwrap();
        assert_eq!(decode_all(&enc, &cs, 1 << 20).unwrap(), body);
    }

    #[test]
    fn raw_deflate_accepted() {
        let body = b"raw deflate body".repeat(10);
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(&body).unwrap();
        let raw = e.finish().unwrap();
        assert_eq!(
            decode_all(&raw, &Codings(vec![Coding::Deflate]), 1 << 20).unwrap(),
            body
        );
    }

    #[test]
    fn decode_limit_is_enforced() {
        let body = vec![0u8; 1 << 20];
        for c in ALL {
            let cs = Codings(vec![c]);
            let enc = encode_all(&body, &cs).unwrap();
            assert!(decode_all(&enc, &cs, 1000).is_err(), "{c:?}");
        }
    }

    #[test]
    fn truncated_streams_fail() {
        let body = b"some content that compresses".repeat(50);
        for c in ALL {
            let cs = Codings(vec![c]);
            let enc = encode_all(&body, &cs).unwrap();
            let cut = &enc[..enc.len() / 2];
            assert!(decode_all(cut, &cs, 1 << 20).is_err(), "{c:?}");
        }
    }

    #[test]
    fn streaming_encoder_flushes() {
        for c in ALL {
            let mut e = Encoder::new(c, true).unwrap();
            let mut d = Decoder::new(c, 1 << 20).unwrap();
            let mut decoded = Vec::new();
            for chunk in [b"data: one\n\n".as_slice(), b"data: two\n\n"] {
                let mut wire = Vec::new();
                e.push(chunk, &mut wire).unwrap();
                d.push(&wire, &mut decoded).unwrap();
            }
            // Both chunks are decodable before the stream ends.
            assert_eq!(decoded, b"data: one\n\ndata: two\n\n", "{c:?}");
        }
    }

    #[test]
    fn parse_header_chain() {
        let mut h = HeaderMap::new();
        h.append(
            http::header::CONTENT_ENCODING,
            "gzip, identity".parse().unwrap(),
        );
        h.append(http::header::CONTENT_ENCODING, "br".parse().unwrap());
        assert_eq!(
            parse_codings(&h).unwrap(),
            Codings(vec![Coding::Gzip, Coding::Brotli])
        );
        h.insert(http::header::CONTENT_ENCODING, "compress".parse().unwrap());
        assert_eq!(parse_codings(&h).unwrap_err(), "compress");
    }
}
