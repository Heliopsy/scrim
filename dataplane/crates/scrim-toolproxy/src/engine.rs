//! Snapshots: everything the tool proxy decides with, swapped atomically.

use std::sync::Arc;

use http::request::Parts;
use serde::{Deserialize, Serialize};

use crate::capture::{CaptureRule, CaptureRuleSpec, CapturedValues};
use crate::credential::{CredentialSet, CredentialSpec, ValidationError};
use crate::decide::InjectionPolicy;
use crate::error::Refusal;
use crate::host::Destination;
use crate::inject::Injector;
use crate::redactor::{Redactor, RedactorChain, ValueRedactor};
use crate::secret::SecretValue;

/// The tool proxy part of the configuration, as the control plane writes it into the snapshot.
///
/// ```yaml
/// credentials:
///   - name: acme
///     reference: bao://kv/agents/acme#key
///     placeholders: [SCRIM_ACME_KEY]
///     binding: { hosts: [api.acme.example] }
///     inject: [header]
/// capture:
///   - name: acme-new-token
///     hosts: [api.acme.example]
///     methods: [POST]
///     path: /v1/tokens
///     field: /token
///     store: bao://kv/agents/acme-new#token
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolProxyConfig {
    /// Injectable credentials.
    #[serde(default)]
    pub credentials: Vec<CredentialSpec>,
    /// Response capture rules.
    #[serde(default)]
    pub capture: Vec<CaptureRuleSpec>,
}

impl ToolProxyConfig {
    /// Validates the configuration without values: placeholders unique across credentials,
    /// bindings, locations and capture rules well-formed.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let mut b = CredentialSet::builder();
        for c in &self.credentials {
            b.add(c.clone(), None, Vec::new());
        }
        b.build()?;
        for r in &self.capture {
            CaptureRule::parse(r)?;
        }
        Ok(())
    }
}

/// Re-signs a request whose signature covers bytes that substitution changed (AWS `SigV4` and
/// similar). Registered on the builder; none ship yet, so signed requests that need rewriting are
/// refused with [`crate::ErrorCode::ResigningUnsupported`].
pub trait RequestSigner: Send + Sync + 'static {
    /// Whether this signer handles the scheme the request is signed with.
    fn applies(&self, parts: &Parts) -> bool;
    /// Replaces the signature after substitution. `body` is the body as it will be sent.
    fn resign(
        &self,
        parts: &mut Parts,
        body: &[u8],
        dest: &Destination,
        credentials: &CredentialSet,
    ) -> Result<(), Refusal>;
}

/// Everything the tool proxy needs from one control-plane snapshot.
pub struct Snapshot {
    /// Snapshot version, acknowledged to the control plane.
    pub version: u64,
    /// Credentials with values and placeholders.
    pub credentials: CredentialSet,
    /// Capture rules.
    pub capture_rules: Vec<CaptureRule>,
    /// The redaction core's matcher over every known value. When `None`, responses are redacted
    /// against the credential values only.
    pub redactor: Option<Arc<dyn Redactor>>,
    /// Per-request injection decisions. `None` injects wherever the bindings allow.
    pub injection: Option<Arc<dyn InjectionPolicy>>,
}

impl Snapshot {
    /// Builds a snapshot from configuration. `value_of` returns the value for a store reference
    /// (`None` when unavailable); `placeholders_of` returns the generated placeholders for a
    /// reference and value (from the redaction core).
    pub fn from_config(
        version: u64,
        config: &ToolProxyConfig,
        value_of: impl Fn(&str) -> Option<SecretValue>,
        placeholders_of: impl Fn(&str, &SecretValue) -> Vec<String>,
    ) -> Result<Self, ValidationError> {
        let mut b = CredentialSet::builder();
        for c in &config.credentials {
            let v = value_of(&c.reference);
            let generated = v
                .as_ref()
                .map_or_default(|v| placeholders_of(&c.reference, v));
            b.add(c.clone(), v, generated);
        }
        let credentials = b.build()?;
        let capture_rules = config
            .capture
            .iter()
            .map(CaptureRule::parse)
            .collect::<Result<_, _>>()?;
        Ok(Self {
            version,
            credentials,
            capture_rules,
            redactor: None,
            injection: None,
        })
    }
}

/// The compiled form of a snapshot.
pub(crate) struct Engine {
    pub(crate) version: u64,
    pub(crate) credentials: CredentialSet,
    pub(crate) injector: Arc<Injector>,
    pub(crate) redactors: RedactorChain,
    pub(crate) capture_rules: Vec<CaptureRule>,
    pub(crate) injection: Option<Arc<dyn InjectionPolicy>>,
    /// Public keys of the placeholder certificates of client certificate credentials.
    pub(crate) cert_keys: Vec<([u8; 32], usize)>,
}

impl Engine {
    pub(crate) fn compile(
        s: Snapshot,
        captured: Arc<CapturedValues>,
    ) -> Result<Self, ValidationError> {
        let injector = Arc::new(
            Injector::new(&s.credentials).map_err(|e| ValidationError::Matcher(e.to_string()))?,
        );
        let base: Arc<dyn Redactor> = if let Some(r) = s.redactor {
            r
        } else {
            let entries: Vec<(SecretValue, Vec<u8>)> = s
                .credentials
                .credentials()
                .iter()
                .filter_map(|c| {
                    let v = c.value.clone()?;
                    let p = c.placeholders.first()?.text.as_bytes().to_vec();
                    Some((v, p))
                })
                .collect();
            Arc::new(
                ValueRedactor::new(entries.iter().map(|(v, p)| (v, p.as_slice())))
                    .map_err(|e| ValidationError::Matcher(e.0))?,
            )
        };
        let mut cert_keys = Vec::new();
        for (i, c) in s.credentials.credentials().iter().enumerate() {
            if !c.client_certificate {
                continue;
            }
            for p in &c.placeholders {
                cert_keys.push((crate::clientcert::placeholder_public_key(&p.text), i));
                if p.kind == crate::credential::PlaceholderKind::Generated {
                    let pct = p
                        .text
                        .replace('\u{27e6}', "%E2%9F%A6")
                        .replace('\u{27e7}', "%E2%9F%A7");
                    cert_keys.push((crate::clientcert::placeholder_public_key(&pct), i));
                }
            }
        }
        Ok(Self {
            cert_keys,
            version: s.version,
            credentials: s.credentials,
            injector,
            redactors: RedactorChain(vec![base, captured]),
            capture_rules: s.capture_rules,
            injection: s.injection,
        })
    }

    /// The client certificate credential whose placeholder certificate has `key`.
    pub(crate) fn client_certificate_by_key(&self, key: &[u8; 32]) -> Option<usize> {
        self.cert_keys
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, i)| *i)
    }

    pub(crate) fn credential_name(&self, i: usize) -> &str {
        &self.credentials.credentials()[i].name
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
    fn config_validation_catches_duplicates() {
        let y = r#"
credentials:
  - name: a
    reference: env://A
    placeholders: [SCRIM_SAME]
    binding: { hosts: [a.test] }
  - name: b
    reference: env://B
    placeholders: [SCRIM_SAME]
    binding: { hosts: [b.test] }
"#;
        let c: ToolProxyConfig = serde_yaml::from_str(y).unwrap();
        let e = c.validate().unwrap_err().to_string();
        assert!(
            e.contains("`a`") && e.contains("`b`") && e.contains("SCRIM_SAME"),
            "{e}"
        );
    }
}
