// SPDX-License-Identifier: AGPL-3.0-only

//! Provider file IDs whose upload scrim scanned.
//!
//! scrim cannot read a file the provider holds, so a request that names one by ID is refused
//! under `inline` and `refuse`, unless the upload went through scrim on the same route and its
//! content was scanned there. Uploads recognised ([`upload`]): Anthropic and `OpenAI`
//! `POST .../files` (`multipart/form-data`, the `file` field), and Gemini
//! `POST /upload/.../files` sent in one request (`uploadType=media` or `multipart`, or a
//! resumable upload whose single `upload, finalize` request carries the whole file from offset
//! 0). The ID in a successful answer (`id`, or Gemini `file.name`) is remembered per route,
//! bounded ([`MAX_PER_ROUTE`], oldest first out), in memory: another replica, or the same one
//! after a restart, does not know it.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;

use http::{HeaderMap, Method, header};

use crate::config::Provider;
use crate::json::{Doc, Kind};

/// Most file IDs remembered per route.
pub(crate) const MAX_PER_ROUTE: usize = 4096;

/// Largest upload answer read for its ID.
pub(crate) const MAX_ANSWER: usize = 1 << 20;

#[derive(Default)]
struct Known {
    set: HashSet<String>,
    order: VecDeque<String>,
}

/// File IDs scanned on upload, per route.
#[derive(Default)]
pub(crate) struct FileIds {
    routes: Mutex<HashMap<String, Known>>,
}

impl FileIds {
    /// Remembers `id` as scanned on `route`.
    pub(crate) fn insert(&self, route: &str, id: &str) {
        let Ok(mut m) = self.routes.lock() else {
            return;
        };
        let k = m.entry(route.to_owned()).or_default();
        if k.set.insert(id.to_owned()) {
            k.order.push_back(id.to_owned());
            while k.order.len() > MAX_PER_ROUTE {
                if let Some(old) = k.order.pop_front() {
                    k.set.remove(&old);
                }
            }
        }
    }

    /// Whether `id` was scanned on upload on `route`.
    pub(crate) fn contains(&self, route: &str, id: &str) -> bool {
        self.routes
            .lock()
            .is_ok_and(|m| m.get(route).is_some_and(|k| k.set.contains(id)))
    }
}

/// How an upload carries its file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Upload {
    /// A multipart body (`form-data` with a `file` field, or Gemini `related` with metadata
    /// first) with this boundary.
    Multipart {
        /// The boundary parameter.
        boundary: String,
        /// `form-data` (else `related`).
        form: bool,
    },
    /// The body is the file (Gemini media and resumable uploads).
    Raw,
}

/// Whether a request is a Files API upload whose answer names the file, and how it carries it.
pub(crate) fn upload(
    provider: Provider,
    method: &Method,
    path: &str,
    query: Option<&str>,
    headers: &HeaderMap,
) -> Option<Upload> {
    if method != Method::POST {
        return None;
    }
    let path = path.trim_end_matches('/');
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let (mime, params) = ct.split_once(';').unwrap_or((ct, ""));
    let mime = mime.trim().to_ascii_lowercase();
    let boundary = || {
        params.split(';').find_map(|p| {
            let (k, v) = p.split_once('=')?;
            k.trim()
                .eq_ignore_ascii_case("boundary")
                .then(|| v.trim().trim_matches('"').to_owned())
                .filter(|b| !b.is_empty() && b.len() <= 70)
        })
    };
    match provider {
        Provider::Anthropic | Provider::Openai if path.ends_with("/files") => {
            (mime == "multipart/form-data").then_some(())?;
            Some(Upload::Multipart {
                boundary: boundary()?,
                form: true,
            })
        }
        Provider::Gemini if path.contains("/upload/") && path.ends_with("/files") => {
            let hv = |n: &str| {
                headers
                    .get(n)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_ascii_lowercase)
            };
            if let Some(cmd) = hv("x-goog-upload-command") {
                let finalize = cmd.split(',').any(|c| c.trim() == "finalize");
                let upload = cmd.split(',').any(|c| c.trim() == "upload");
                let offset = hv("x-goog-upload-offset");
                return (finalize && upload && offset.as_deref().is_none_or(|o| o.trim() == "0"))
                    .then_some(Upload::Raw);
            }
            let kind = query.and_then(|q| {
                q.split('&')
                    .find_map(|kv| kv.strip_prefix("uploadType="))
                    .map(str::to_owned)
            });
            match kind.as_deref() {
                Some("multipart") if mime == "multipart/related" => Some(Upload::Multipart {
                    boundary: boundary()?,
                    form: false,
                }),
                Some("media") => Some(Upload::Raw),
                _ => None,
            }
        }
        _ => None,
    }
}

/// The file in an upload body and its declared media type. `None` when the body does not hold
/// one where [`Upload`] says.
pub(crate) fn file<'a>(
    u: &Upload,
    headers: &HeaderMap,
    body: &'a [u8],
) -> Option<(String, &'a [u8])> {
    match u {
        Upload::Raw => {
            let ct = headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream");
            Some((media(ct), body))
        }
        Upload::Multipart { boundary, form } => {
            let parts = multipart(body, boundary)?;
            let found = if *form {
                parts
                    .into_iter()
                    .find(|p| p.name.as_deref() == Some("file"))
            } else {
                parts.into_iter().nth(1)
            }?;
            Some((
                media(
                    found
                        .content_type
                        .as_deref()
                        .unwrap_or("application/octet-stream"),
                ),
                found.body,
            ))
        }
    }
}

fn media(ct: &str) -> String {
    crate::codec::sanitize_media_type(ct.split(';').next().unwrap_or_default().trim())
}

struct Part<'a> {
    name: Option<String>,
    content_type: Option<String>,
    body: &'a [u8],
}

/// Splits a multipart body. `None` when it is not well formed.
fn multipart<'a>(body: &'a [u8], boundary: &str) -> Option<Vec<Part<'a>>> {
    let delim = format!("--{boundary}");
    let finder = memchr::memmem::Finder::new(delim.as_bytes());
    let mut starts: Vec<usize> = finder.find_iter(body).collect();
    // A delimiter is at the start of the body or of a line.
    starts.retain(|&i| {
        i == 0
            || body.get(i.saturating_sub(2)..i) == Some(b"\r\n")
            || body.get(i - 1..i) == Some(b"\n")
    });
    let mut parts = Vec::new();
    for w in starts.windows(2) {
        let (a, b) = (w[0], w[1]);
        let seg = body.get(a + delim.len()..b)?;
        let seg = seg
            .strip_prefix(b"\r\n")
            .or_else(|| seg.strip_prefix(b"\n"))?;
        let seg = seg
            .strip_suffix(b"\r\n")
            .or_else(|| seg.strip_suffix(b"\n"))
            .unwrap_or(seg);
        let (head, content) = if let Some(i) = memchr::memmem::find(seg, b"\r\n\r\n") {
            (seg.get(..i)?, seg.get(i + 4..)?)
        } else {
            let i = memchr::memmem::find(seg, b"\n\n")?;
            (seg.get(..i)?, seg.get(i + 2..)?)
        };
        let head = std::str::from_utf8(head).ok()?;
        let mut part = Part {
            name: None,
            content_type: None,
            body: content,
        };
        for line in head.lines() {
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            if k.trim().eq_ignore_ascii_case("content-type") {
                part.content_type = Some(v.trim().to_owned());
            } else if k.trim().eq_ignore_ascii_case("content-disposition") {
                part.name = v.split(';').find_map(|p| {
                    let (k, v) = p.split_once('=')?;
                    (k.trim() == "name").then(|| v.trim().trim_matches('"').to_owned())
                });
            }
        }
        parts.push(part);
    }
    // The last delimiter closes the body.
    let last = *starts.last()?;
    body.get(last + delim.len()..)?
        .starts_with(b"--")
        .then_some(parts)
}

/// The file ID in a successful upload answer: `id` (Anthropic, `OpenAI`) or `file.name`
/// (Gemini, `files/...`).
pub(crate) fn answer_id(provider: Provider, body: &[u8]) -> Option<String> {
    let doc = Doc::parse(body).ok()?;
    let root = doc.root();
    if root.kind() != Kind::Object {
        return None;
    }
    let id = match provider {
        Provider::Gemini => root.get("file").ok()??.get_str("name").ok()??,
        _ => root.get_str("id").ok()??,
    };
    (!id.is_empty() && id.len() <= 256).then(|| id.into_owned())
}

/// The ID of a Gemini file named by URI: `files/abc` for
/// `https://generativelanguage.googleapis.com/v1beta/files/abc`, or the name itself.
pub(crate) fn gemini_file_id(uri: &str) -> Option<String> {
    if uri.starts_with("files/") {
        return Some(uri.to_owned());
    }
    let rest = uri
        .strip_prefix("https://generativelanguage.googleapis.com/")?
        .split(['?', '#'])
        .next()?;
    let i = rest.find("files/")?;
    Some(rest.get(i..)?.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.insert(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        m
    }

    #[test]
    fn remembers_ids_per_route_bounded() {
        let ids = FileIds::default();
        ids.insert("a", "file-1");
        assert!(ids.contains("a", "file-1"));
        assert!(!ids.contains("b", "file-1"));
        for i in 0..MAX_PER_ROUTE {
            ids.insert("a", &format!("f{i}"));
        }
        assert!(!ids.contains("a", "file-1"), "oldest evicted");
        assert!(ids.contains("a", &format!("f{}", MAX_PER_ROUTE - 1)));
    }

    #[test]
    fn recognises_uploads() {
        let form = h(&[("content-type", "multipart/form-data; boundary=XyZ")]);
        assert_eq!(
            upload(Provider::Openai, &Method::POST, "/v1/files", None, &form),
            Some(Upload::Multipart {
                boundary: "XyZ".into(),
                form: true
            })
        );
        assert_eq!(
            upload(Provider::Openai, &Method::GET, "/v1/files", None, &form),
            None
        );
        assert_eq!(
            upload(
                Provider::Anthropic,
                &Method::POST,
                "/v1/messages",
                None,
                &form
            ),
            None
        );
        let fin = h(&[
            ("x-goog-upload-command", "upload, finalize"),
            ("x-goog-upload-offset", "0"),
        ]);
        assert_eq!(
            upload(
                Provider::Gemini,
                &Method::POST,
                "/upload/v1beta/files",
                None,
                &fin
            ),
            Some(Upload::Raw)
        );
        let later = h(&[
            ("x-goog-upload-command", "upload, finalize"),
            ("x-goog-upload-offset", "8388608"),
        ]);
        assert_eq!(
            upload(
                Provider::Gemini,
                &Method::POST,
                "/upload/v1beta/files",
                None,
                &later
            ),
            None
        );
        let start = h(&[("x-goog-upload-command", "start")]);
        assert_eq!(
            upload(
                Provider::Gemini,
                &Method::POST,
                "/upload/v1beta/files",
                None,
                &start
            ),
            None
        );
        assert_eq!(
            upload(
                Provider::Gemini,
                &Method::POST,
                "/upload/v1beta/files",
                Some("uploadType=media"),
                &HeaderMap::new()
            ),
            Some(Upload::Raw)
        );
    }

    #[test]
    fn finds_the_file_part() {
        let body = b"--XyZ\r\nContent-Disposition: form-data; name=\"purpose\"\r\n\r\nuser_data\r\n--XyZ\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.pdf\"\r\nContent-Type: application/pdf\r\n\r\n%PDF-1.4 body\r\n--XyZ--\r\n";
        let u = Upload::Multipart {
            boundary: "XyZ".into(),
            form: true,
        };
        let (mt, f) = file(&u, &HeaderMap::new(), body).unwrap();
        assert_eq!(mt, "application/pdf");
        assert_eq!(f, b"%PDF-1.4 body");
        assert!(file(&u, &HeaderMap::new(), b"--XyZ\r\nno end").is_none());
        let related = b"--b\r\nContent-Type: application/json\r\n\r\n{}\r\n--b\r\nContent-Type: image/png\r\n\r\nPNGDATA\r\n--b--";
        let u = Upload::Multipart {
            boundary: "b".into(),
            form: false,
        };
        assert_eq!(file(&u, &HeaderMap::new(), related).unwrap().1, b"PNGDATA");
    }

    #[test]
    fn reads_answer_ids() {
        assert_eq!(
            answer_id(Provider::Openai, br#"{"id":"file-abc","object":"file"}"#).as_deref(),
            Some("file-abc")
        );
        assert_eq!(
            answer_id(
                Provider::Gemini,
                br#"{"file":{"name":"files/xyz","uri":"u"}}"#
            )
            .as_deref(),
            Some("files/xyz")
        );
        assert_eq!(answer_id(Provider::Anthropic, b"[]"), None);
        assert_eq!(
            gemini_file_id("https://generativelanguage.googleapis.com/v1beta/files/abc").as_deref(),
            Some("files/abc")
        );
        assert_eq!(gemini_file_id("https://example.com/files/abc"), None);
    }
}
