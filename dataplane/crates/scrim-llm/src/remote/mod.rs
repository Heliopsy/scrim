// SPDX-License-Identifier: AGPL-3.0-only

//! Attachments a request only references (`redaction.remote-attachments`).
//!
//! A provider request can name an attachment instead of carrying it: an image or document URL
//! (Anthropic `source.type: url`, `OpenAI` `image_url`, `input_image` and `input_file` with
//! `file_url`, Gemini `fileData.fileUri`), a file ID from the provider's Files API (Anthropic
//! `source.type: file` and `container_upload`, `OpenAI` `file_id`, Gemini `files/...` URIs), or
//! a cloud storage location (Bedrock `s3Location`, Gemini `gs://` URIs). The provider fetches
//! it, so scrim would never see the content.
//!
//! The codecs list every reference in the plan ([`crate::codec::Plan::remote`]). [`check`]
//! applies the policy before anything is redacted:
//!
//! - `inline` (default): every URL is fetched by scrim ([`fetch::Fetcher`]), through the
//!   upstream proxy in force and never to a private, loopback, link-local or metadata address
//!   unless allowed, and spliced into the body as the provider's own inline form (a base64
//!   `data:` URL, an Anthropic base64 source, a Gemini `inlineData` part). The body is then
//!   planned again, so the content goes through the binary policy like any attachment the agent
//!   sent inline: what was scanned is exactly what the model sees.
//! - `refuse`: a request with a URL refuses.
//! - `pass`: references are forwarded unfetched and audited as unscanned (weakening).
//!
//! Under `inline` and `refuse`, a file ID passes only when scrim scanned its upload on the same
//! route ([`files::FileIds`]); anything scrim cannot fetch (other file IDs, storage locations,
//! `YouTube` URIs) refuses the request. Errors name the reference by its position and kind, never
//! its URL or ID.

pub(crate) mod addr;
pub(crate) mod fetch;
pub(crate) mod files;

pub use addr::Network;

use crate::audit::RefusalReason;
use crate::engine::{RemoteMode, RemotePolicy};
use crate::error::Refusal;

/// Most references one request may carry under `inline`.
pub(crate) const MAX_REFERENCES: usize = 32;

/// What a reference points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Target {
    /// A URL the provider would fetch.
    Url(String),
    /// A provider file ID (`file-...`, `file_...`, Gemini `files/...`).
    FileId(String),
    /// Something scrim cannot fetch: the label says what (`S3 location`, ...).
    Unfetchable(&'static str),
}

impl Target {
    fn kind(&self) -> &'static str {
        match self {
            Self::Url(_) => "URL",
            Self::FileId(_) => "file ID",
            Self::Unfetchable(k) => k,
        }
    }
}

/// How the fetched content replaces the reference in the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Edit {
    /// Never rewritten (file IDs, unfetchable references).
    None,
    /// The reference is the JSON string at `span` (quotes included); it becomes a base64
    /// `data:` URL string (`OpenAI` `image_url`).
    DataUrl {
        /// Byte span of the string value.
        span: (usize, usize),
    },
    /// The Anthropic `source` object at `span` becomes a base64 source, or a text source for a
    /// plain text document.
    AnthropicSource {
        /// Byte span of the source object.
        span: (usize, usize),
    },
    /// The object at `span` is rebuilt from the members in `keep` plus new ones.
    Rebuild {
        /// Byte span of the object.
        span: (usize, usize),
        /// Members kept as they are: unescaped key, byte span of the value.
        keep: Vec<(String, (usize, usize))>,
        /// Members added.
        add: Add,
    },
}

/// Members a rebuilt object gains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Add {
    /// `OpenAI` Responses `input_file`: `file_data` as a `data:` URL, and `filename` (derived
    /// from the URL) when the part has none.
    ResponsesFile {
        /// Whether the part already names the file.
        has_filename: bool,
    },
    /// Gemini part: `inlineData` (or `inline_data`) with the media type and base64 data.
    GeminiInline {
        /// The part used snake case (`file_data`), so the new member does too.
        snake: bool,
        /// The media type the part declared.
        declared: Option<String>,
    },
}

/// One reference in a request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reference {
    /// What it points at.
    pub target: Target,
    /// How content replaces it.
    pub edit: Edit,
}

/// What a request's references need, after [`check`].
#[derive(Debug, Default)]
pub(crate) struct Checked {
    /// References to fetch and inline (`inline` only).
    pub fetch: Vec<(usize, Reference)>,
    /// Audit labels of references forwarded unfetched under `pass`.
    pub unscanned: Vec<String>,
}

/// How [`check`] treats a request.
#[derive(Clone, Copy)]
pub(crate) struct Context<'a> {
    /// Whether scrim scanned the upload of a file ID on this route.
    pub known: &'a dyn Fn(&str) -> bool,
    /// Whether this path can fetch (the HTTP proxy can; a WebSocket message cannot).
    pub can_fetch: bool,
    /// The references were already fetched and inlined once: any URL left refuses.
    pub fetched: bool,
}

impl Context<'_> {
    /// A path that fetches nothing and knows no uploads.
    pub(crate) const NONE: Context<'static> = Context {
        known: &|_| false,
        can_fetch: false,
        fetched: false,
    };
}

/// Applies `policy` to the references of one request.
pub(crate) fn check(
    policy: &RemotePolicy,
    refs: &[Reference],
    cx: Context<'_>,
) -> Result<Checked, Refusal> {
    let mut out = Checked::default();
    if refs.is_empty() {
        return Ok(out);
    }
    if policy.mode == RemoteMode::Pass {
        for r in refs {
            let label = match r.target {
                Target::Url(_) => "remote:url",
                Target::FileId(_) => "remote:file-id",
                Target::Unfetchable(_) => "remote:storage",
            };
            if !out.unscanned.iter().any(|l| l == label) {
                out.unscanned.push(label.to_owned());
            }
        }
        return Ok(out);
    }
    let refuse = |i: usize, r: &Reference, why: &str| {
        Refusal::new(
            RefusalReason::RemoteAttachment,
            format!("reference {} ({}): {why}", i + 1, r.target.kind()),
        )
    };
    for (i, r) in refs.iter().enumerate() {
        match &r.target {
            Target::FileId(id) if (cx.known)(id) => {}
            Target::FileId(_) => {
                return Err(refuse(
                    i,
                    r,
                    "scrim cannot read a file the provider holds, and this one was not uploaded \
                     through scrim on this route",
                ));
            }
            Target::Unfetchable(_) => {
                return Err(refuse(i, r, "scrim cannot fetch it to scan it"));
            }
            Target::Url(_) if policy.mode == RemoteMode::Refuse => {
                return Err(refuse(i, r, "redaction.remote-attachments is refuse"));
            }
            Target::Url(_) if cx.fetched => {
                return Err(refuse(i, r, "still a reference after inlining"));
            }
            Target::Url(_) if !cx.can_fetch => {
                return Err(refuse(
                    i,
                    r,
                    "attachments referenced by URL cannot be fetched on this connection; send \
                     the content inline",
                ));
            }
            Target::Url(_) => out.fetch.push((i, r.clone())),
        }
    }
    if out.fetch.len() > MAX_REFERENCES {
        return Err(Refusal::new(
            RefusalReason::RemoteAttachment,
            format!("more than {MAX_REFERENCES} attachments referenced by URL"),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(u: &str) -> Reference {
        Reference {
            target: Target::Url(u.into()),
            edit: Edit::DataUrl { span: (0, 0) },
        }
    }

    fn file(id: &str) -> Reference {
        Reference {
            target: Target::FileId(id.into()),
            edit: Edit::None,
        }
    }

    fn policy(mode: RemoteMode) -> RemotePolicy {
        RemotePolicy {
            mode,
            ..RemotePolicy::default()
        }
    }

    const FETCH: Context<'static> = Context {
        known: &|id| id == "file-known",
        can_fetch: true,
        fetched: false,
    };

    #[test]
    fn inline_fetches_urls_and_keeps_known_files() {
        let refs = [url("https://example.com/a.png"), file("file-known")];
        let c = check(&policy(RemoteMode::Inline), &refs, FETCH).unwrap();
        assert_eq!(c.fetch.len(), 1);
        assert_eq!(c.fetch[0].0, 0);
        assert_eq!(c.unscanned, Vec::<String>::new());
    }

    #[test]
    fn unknown_files_and_storage_refuse_under_inline_and_refuse() {
        for mode in [RemoteMode::Inline, RemoteMode::Refuse] {
            for r in [
                file("file-other"),
                Reference {
                    target: Target::Unfetchable("S3 location"),
                    edit: Edit::None,
                },
            ] {
                let e = check(&policy(mode), &[r], FETCH).unwrap_err();
                assert_eq!(e.reason, RefusalReason::RemoteAttachment);
                assert!(!e.detail.contains("file-other"), "{}", e.detail);
            }
        }
    }

    #[test]
    fn refuse_mode_refuses_urls_without_naming_them() {
        let e = check(
            &policy(RemoteMode::Refuse),
            &[url("https://example.com/x")],
            FETCH,
        )
        .unwrap_err();
        assert_eq!(e.reason, RefusalReason::RemoteAttachment);
        assert!(!e.detail.contains("example.com"));
    }

    #[test]
    fn pass_forwards_and_labels() {
        let refs = [url("https://a/"), url("https://b/"), file("file-x")];
        let c = check(&policy(RemoteMode::Pass), &refs, Context::NONE).unwrap();
        assert_eq!(c.fetch.len(), 0);
        assert_eq!(c.unscanned, vec!["remote:url", "remote:file-id"]);
    }

    #[test]
    fn urls_left_after_inlining_or_without_a_fetcher_refuse() {
        let refs = [url("https://a/")];
        let after = Context {
            fetched: true,
            ..FETCH
        };
        assert!(check(&policy(RemoteMode::Inline), &refs, after).is_err());
        assert!(check(&policy(RemoteMode::Inline), &refs, Context::NONE).is_err());
    }

    #[test]
    fn too_many_urls_refuse() {
        let refs: Vec<_> = (0..=MAX_REFERENCES).map(|_| url("https://a/")).collect();
        assert!(check(&policy(RemoteMode::Inline), &refs, FETCH).is_err());
    }
}
