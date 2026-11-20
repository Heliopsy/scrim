//! Minimal `multipart/*` parsing: where each part's body is and what type it declares.
//!
//! Substitution then encodes each value for the part it lands in (a JSON part gets JSON escaping)
//! and checks that no value contains the boundary, which would split the part.

use std::ops::Range;

/// One part of a multipart body.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Part {
    /// Byte range of the part's headers (without the blank line).
    pub headers: Range<usize>,
    /// Byte range of the part's body.
    pub body: Range<usize>,
    /// Lower-cased media type from the part's `Content-Type`, if any.
    pub content_type: Option<String>,
}

/// Extracts the `boundary` parameter of a multipart media type.
pub(crate) fn boundary(content_type: &str) -> Option<String> {
    content_type.split(';').skip(1).find_map(|param| {
        let (k, v) = param.split_once('=')?;
        if k.trim().eq_ignore_ascii_case("boundary") {
            let v = v.trim().trim_matches('"');
            (!v.is_empty() && v.len() <= 200).then(|| v.to_owned())
        } else {
            None
        }
    })
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from > hay.len() {
        return None;
    }
    memchr::memmem::find(&hay[from..], needle).map(|i| i + from)
}

/// Splits `body` into parts. `None` when the body is not well-formed for `boundary`.
pub(crate) fn parse(body: &[u8], boundary: &str) -> Option<Vec<Part>> {
    let dash = format!("--{boundary}");
    let delim = format!("\r\n--{boundary}");
    let mut pos = if body.starts_with(dash.as_bytes()) {
        dash.len()
    } else {
        find(body, delim.as_bytes(), 0)? + delim.len()
    };
    let mut parts = Vec::new();
    loop {
        if body[pos..].starts_with(b"--") {
            return Some(parts);
        }
        // Transport padding, then CRLF.
        while pos < body.len() && (body[pos] == b' ' || body[pos] == b'\t') {
            pos += 1;
        }
        if !body[pos..].starts_with(b"\r\n") {
            return None;
        }
        pos += 2;
        let (headers, body_start) = if body[pos..].starts_with(b"\r\n") {
            (pos..pos, pos + 2)
        } else {
            let end = find(body, b"\r\n\r\n", pos)?;
            (pos..end, end + 4)
        };
        let body_end = find(body, delim.as_bytes(), body_start)?;
        let content_type = std::str::from_utf8(&body[headers.clone()])
            .ok()
            .and_then(|h| {
                h.split("\r\n").find_map(|line| {
                    let (k, v) = line.split_once(':')?;
                    k.trim().eq_ignore_ascii_case("content-type").then(|| {
                        v.split(';')
                            .next()
                            .unwrap_or("")
                            .trim()
                            .to_ascii_lowercase()
                    })
                })
            });
        parts.push(Part {
            headers,
            body: body_start..body_end,
            content_type,
        });
        pos = body_end + delim.len();
        if pos > body.len() {
            return None;
        }
    }
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

    #[test]
    fn parses_parts() {
        let body = b"--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nvalue-a\r\n--XyZ\r\nContent-Disposition: form-data; name=\"j\"\r\nContent-Type: application/json\r\n\r\n{\"k\":1}\r\n--XyZ--\r\n";
        let parts = parse(body, "XyZ").unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(&body[parts[0].body.clone()], b"value-a");
        assert_eq!(parts[0].content_type, None);
        assert_eq!(&body[parts[1].body.clone()], b"{\"k\":1}");
        assert_eq!(parts[1].content_type.as_deref(), Some("application/json"));
    }

    #[test]
    fn rejects_truncated() {
        assert!(parse(b"--XyZ\r\nA: b\r\n\r\nvalue", "XyZ").is_none());
        assert!(parse(b"no boundary here", "XyZ").is_none());
    }

    #[test]
    fn boundary_param() {
        assert_eq!(
            boundary("multipart/form-data; boundary=\"abc\"").as_deref(),
            Some("abc")
        );
        assert_eq!(
            boundary("multipart/form-data; charset=x; Boundary=q1").as_deref(),
            Some("q1")
        );
        assert_eq!(boundary("multipart/form-data"), None);
    }
}
