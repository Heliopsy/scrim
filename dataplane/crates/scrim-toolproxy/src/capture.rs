//! Response capture rules: store a secret an API returns and hand the agent its placeholder.
//!
//! A rule matches a request (host, method, path) and a response status, and names one field: a
//! JSON pointer into the response body or a response header. The field's value goes to the
//! [`CaptureSink`] (the control plane, which writes it to the store reference and replies with the
//! placeholder). The agent receives the placeholder. If storing fails, the agent receives
//! [`WITHHELD_MARKER`] instead and the value is dropped.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use http::{HeaderName, Method};
use serde::{Deserialize, Serialize};

use crate::credential::ValidationError;
use crate::host::{Destination, HostPattern, glob_match};
use crate::redactor::{RedactError, RedactMatch, Redactor, ValueRedactor};
use crate::secret::SecretValue;

/// Written in place of a captured field when storing it failed.
pub const WITHHELD_MARKER: &str = "⟦scrim:withheld:capture-failed⟧";

/// A capture rule as configured.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureRuleSpec {
    /// Rule name, shown in audit entries.
    pub name: String,
    /// Host patterns of the request, see [`HostPattern`].
    pub hosts: Vec<String>,
    /// Methods of the request. Empty matches every method.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    /// Path glob of the request. Absent matches every path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Response status codes. Empty matches every 2xx status.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub status: Vec<u16>,
    /// JSON pointer (RFC 6901) of the field in a JSON response body, for example `/token`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Response header carrying the value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    /// Store reference the value is written to.
    pub store: String,
}

/// Where a capture rule reads its value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaptureSource {
    /// JSON pointer into the body.
    JsonPointer(String),
    /// A response header.
    Header(HeaderName),
}

/// A validated capture rule.
#[derive(Clone, Debug)]
pub struct CaptureRule {
    /// Rule name.
    pub name: String,
    hosts: Vec<HostPattern>,
    methods: Vec<Method>,
    path: Option<String>,
    status: Vec<u16>,
    /// Field to capture.
    pub source: CaptureSource,
    /// Store reference.
    pub store: String,
}

impl CaptureRule {
    /// Validates a spec.
    pub fn parse(spec: &CaptureRuleSpec) -> Result<Self, ValidationError> {
        let bad = |reason: &str| ValidationError::InvalidCaptureRule {
            rule: spec.name.clone(),
            reason: reason.to_owned(),
        };
        if spec.name.is_empty() {
            return Err(bad("missing name"));
        }
        if spec.hosts.is_empty() {
            return Err(bad("needs at least one host"));
        }
        if spec.store.is_empty() {
            return Err(bad("needs a store reference"));
        }
        let hosts = spec
            .hosts
            .iter()
            .map(|h| HostPattern::parse(h))
            .collect::<Result<Vec<_>, _>>()?;
        let methods = spec
            .methods
            .iter()
            .map(|m| {
                Method::from_bytes(m.to_ascii_uppercase().as_bytes())
                    .map_err(|_| bad("invalid method"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let source = match (&spec.field, &spec.header) {
            (Some(f), None) => {
                if !(f.is_empty() || f.starts_with('/')) {
                    return Err(bad("field must be a JSON pointer starting with `/`"));
                }
                CaptureSource::JsonPointer(f.clone())
            }
            (None, Some(h)) => CaptureSource::Header(
                HeaderName::from_bytes(h.to_ascii_lowercase().as_bytes())
                    .map_err(|_| bad("invalid header name"))?,
            ),
            _ => return Err(bad("set exactly one of `field` and `header`")),
        };
        if spec.status.iter().any(|s| !(100..=599).contains(s)) {
            return Err(bad("invalid status code"));
        }
        Ok(Self {
            name: spec.name.clone(),
            hosts,
            methods,
            path: spec.path.clone(),
            status: spec.status.clone(),
            source,
            store: spec.store.clone(),
        })
    }

    /// Whether the rule names the host of `dest`.
    pub fn matches_host(&self, dest: &Destination) -> bool {
        self.hosts.iter().any(|h| h.matches(dest))
    }

    /// Whether the rule applies to this request (before the response arrives).
    pub fn matches_request(&self, dest: &Destination, method: &Method, path: &str) -> bool {
        self.hosts.iter().any(|h| h.matches(dest))
            && (self.methods.is_empty() || self.methods.contains(method))
            && self.path.as_deref().is_none_or(|p| glob_match(p, path))
    }

    /// Whether the rule applies to a response status.
    pub fn matches_status(&self, status: u16) -> bool {
        if self.status.is_empty() {
            (200..300).contains(&status)
        } else {
            self.status.contains(&status)
        }
    }
}

/// A value to store, sent to the control plane.
#[derive(Debug)]
pub struct CaptureRequest {
    /// Rule name.
    pub rule: String,
    /// Store reference to write.
    pub reference: String,
    /// `scheme://host:port` the value came from.
    pub destination: String,
    /// The captured value.
    pub value: SecretValue,
}

/// Storing a captured value failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("capture failed: {0}")]
pub struct CaptureError(pub String);

/// Boxed future returned by [`CaptureSink::store`].
pub type CaptureFuture = Pin<Box<dyn Future<Output = Result<String, CaptureError>> + Send>>;

/// Stores captured values. Returns the placeholder the agent sees for the stored value.
pub trait CaptureSink: Send + Sync + 'static {
    /// Writes `req.value` to `req.reference` and returns its placeholder.
    fn store(&self, req: CaptureRequest) -> CaptureFuture;
}

/// A sink that stores nothing: every captured field is withheld. The default until the control
/// plane is connected.
#[derive(Clone, Copy, Debug, Default)]
pub struct RefusingCaptureSink;

impl CaptureSink for RefusingCaptureSink {
    fn store(&self, _req: CaptureRequest) -> CaptureFuture {
        Box::pin(async { Err(CaptureError("no capture store is configured".into())) })
    }
}

/// Values captured by this process that the redaction core may not know yet. Responses are
/// redacted against them too, so an API that returns the same token again shows the placeholder.
pub(crate) struct CapturedValues {
    entries: Mutex<Vec<(SecretValue, Vec<u8>)>>,
    matcher: ArcSwap<ValueRedactor>,
    capacity: usize,
}

impl CapturedValues {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            matcher: ArcSwap::from_pointee(ValueRedactor::empty()),
            capacity,
        }
    }

    pub(crate) fn add(&self, value: SecretValue, placeholder: &str) {
        let mut e = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if e.iter().any(|(v, _)| v == &value) {
            return;
        }
        e.push((value, placeholder.as_bytes().to_vec()));
        if e.len() > self.capacity {
            e.remove(0);
        }
        match ValueRedactor::new(e.iter().map(|(v, p)| (v, p.as_slice()))) {
            Ok(m) => self.matcher.store(Arc::new(m)),
            Err(err) => tracing::error!(error = %err, "captured values matcher not rebuilt"),
        }
    }
}

impl Redactor for CapturedValues {
    fn max_match_len(&self) -> usize {
        self.matcher.load().max_match_len()
    }

    fn find(&self, haystack: &[u8], out: &mut Vec<RedactMatch>) -> Result<(), RedactError> {
        self.matcher.load().find(haystack, out)
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
    use crate::host::Scheme;

    fn spec() -> CaptureRuleSpec {
        CaptureRuleSpec {
            name: "acme-token".into(),
            hosts: vec!["api.acme.test".into()],
            methods: vec!["post".into()],
            path: Some("/v1/tokens*".into()),
            status: vec![],
            field: Some("/token".into()),
            header: None,
            store: "bao://kv/acme-new#token".into(),
        }
    }

    #[test]
    fn matching() {
        let r = CaptureRule::parse(&spec()).unwrap();
        let d = Destination::new(Scheme::Https, "api.acme.test", 443);
        assert!(r.matches_request(&d, &Method::POST, "/v1/tokens"));
        assert!(!r.matches_request(&d, &Method::GET, "/v1/tokens"));
        assert!(!r.matches_request(&d, &Method::POST, "/v2/tokens"));
        assert!(r.matches_status(201));
        assert!(!r.matches_status(404));
    }

    #[test]
    fn validation() {
        let mut s = spec();
        s.header = Some("x-token".into());
        assert!(CaptureRule::parse(&s).is_err());
        let mut s = spec();
        s.field = Some("token".into());
        assert!(CaptureRule::parse(&s).is_err());
        let mut s = spec();
        s.hosts.clear();
        assert!(CaptureRule::parse(&s).is_err());
    }
}
