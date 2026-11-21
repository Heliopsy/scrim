//! Credentials, their bindings and the placeholders that stand for them.
//!
//! A [`CredentialSpec`] is configuration: an alias, the store reference, the user-declared
//! placeholder strings, the destination binding and the request locations it may be injected
//! into. It holds no value. A [`CredentialSet`] combines specs with values from the value
//! dictionary and the generated placeholders from the redaction core, and is validated as a whole:
//! a placeholder string that two credentials claim fails validation and names both.

use std::collections::{HashMap, HashSet};
use std::fmt;

use http::{HeaderName, Method};
use serde::{Deserialize, Serialize};

use crate::host::{Destination, HostPattern, HostPatternError, Scheme, glob_match};
use crate::secret::SecretValue;

/// Configuration of one injectable credential. Contains no value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialSpec {
    /// Alias shown in audit entries and errors, for example `acme`.
    pub name: String,
    /// Store reference the value comes from, for example `bao://kv/agents/acme#key`. Every
    /// credential also answers to the reference placeholder `{{scrim:<reference>}}`.
    pub reference: String,
    /// User-declared placeholder strings, for example `SCRIM_ACME_KEY`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub placeholders: Vec<String>,
    /// Where the credential may be sent. Without a binding it is never injected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<BindingSpec>,
    /// Request locations the placeholder may be substituted in. Defaults to `["header"]`.
    #[serde(default = "default_inject")]
    pub inject: Vec<String>,
    /// Set on the credential holding an AWS secret access key: the request is re-signed with it
    /// (`SigV4`) when its access key id placeholder signs a request toward a bound endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws_sigv4: Option<AwsSigV4Spec>,
    /// The value is a PEM client certificate chain and private key, presented in the upstream TLS
    /// handshake toward the bound hosts when the agent presents the credential's placeholder
    /// certificate to the proxy.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub client_certificate: bool,
}

/// AWS `SigV4` re-signing for a secret access key credential.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsSigV4Spec {
    /// Store reference of the credential holding the access key id that goes with this secret.
    pub access_key_id: String,
    /// Regions the request's credential scope may name. Empty allows every region.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regions: Vec<String>,
    /// Services the request's credential scope may name (`s3`, `sts`, ...). Empty allows every
    /// service.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<String>,
}

impl AwsSigV4Spec {
    /// Whether a credential scope's region and service are allowed.
    pub fn allows(&self, region: &str, service: &str) -> bool {
        (self.regions.is_empty() || self.regions.iter().any(|r| r == region))
            && (self.services.is_empty() || self.services.iter().any(|s| s == service))
    }
}

fn default_inject() -> Vec<String> {
    vec!["header".to_owned()]
}

/// Destination binding as configured.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingSpec {
    /// Host patterns, see [`HostPattern`]. At least one is required.
    pub hosts: Vec<String>,
    /// Allowed methods. Empty allows every method.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    /// Allowed path globs (`*` matches any run, including `/`). Empty allows every path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    /// Also inject over plain `http://`. Off by default: this sends the real value in clear text
    /// and weakens the credential's protection.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_plaintext_http: bool,
}

/// A parsed, validated binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    hosts: Vec<HostPattern>,
    methods: Vec<Method>,
    paths: Vec<String>,
    allow_plaintext_http: bool,
}

impl Binding {
    /// Parses a binding spec.
    pub fn parse(spec: &BindingSpec) -> Result<Self, ValidationError> {
        if spec.hosts.is_empty() {
            return Err(ValidationError::EmptyBinding);
        }
        let hosts = spec
            .hosts
            .iter()
            .map(|h| HostPattern::parse(h))
            .collect::<Result<Vec<_>, HostPatternError>>()?;
        let methods = spec
            .methods
            .iter()
            .map(|m| {
                Method::from_bytes(m.to_ascii_uppercase().as_bytes())
                    .map_err(|_| ValidationError::InvalidMethod(m.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for p in &spec.paths {
            if !p.starts_with('/') && p != "*" {
                return Err(ValidationError::InvalidPath(p.clone()));
            }
        }
        Ok(Self {
            hosts,
            methods,
            paths: spec.paths.clone(),
            allow_plaintext_http: spec.allow_plaintext_http,
        })
    }

    /// Whether the host part of `dest` (host, port, scheme) is covered.
    pub fn covers_destination(&self, dest: &Destination) -> bool {
        if dest.scheme == Scheme::Http && !self.allow_plaintext_http {
            return false;
        }
        self.hosts.iter().any(|h| h.matches(dest))
    }

    /// Whether a request to `dest` with `method` and `path` (no query) is covered.
    pub fn covers(&self, dest: &Destination, method: &Method, path: &str) -> bool {
        self.covers_destination(dest)
            && (self.methods.is_empty() || self.methods.contains(method))
            && (self.paths.is_empty() || self.paths.iter().any(|p| glob_match(p, path)))
    }
}

/// A place in a request where a placeholder can sit.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Location {
    /// A request header other than `Cookie`, by lower-case name.
    Header(HeaderName),
    /// The `Cookie` header.
    Cookie,
    /// The URL query string.
    Query,
    /// The URL path.
    Path,
    /// The request body.
    Body,
    /// The client certificate the agent presented to the proxy (a placeholder certificate).
    ClientCertificate,
    /// The request's signature (AWS `SigV4`): the credential signs, it is never sent.
    Signature,
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Location::Header(h) => write!(f, "header `{h}`"),
            Location::Cookie => f.write_str("cookie"),
            Location::Query => f.write_str("query"),
            Location::Path => f.write_str("path"),
            Location::Body => f.write_str("body"),
            Location::ClientCertificate => f.write_str("client certificate"),
            Location::Signature => f.write_str("signature"),
        }
    }
}

/// The set of locations a credential may be injected into.
///
/// Configured as a list of `header` (any header except `Cookie`), `header:<name>`, `cookie`,
/// `query`, `path`, `body` or `anywhere`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // one flag per request part, read as a set
pub struct Locations {
    any_header: bool,
    headers: Vec<HeaderName>,
    cookie: bool,
    query: bool,
    path: bool,
    body: bool,
}

impl Locations {
    /// Parses the configured list.
    pub fn parse(items: &[String]) -> Result<Self, ValidationError> {
        let mut l = Locations::default();
        for item in items {
            match item.as_str() {
                "header" | "headers" => l.any_header = true,
                "cookie" => l.cookie = true,
                "query" => l.query = true,
                "path" => l.path = true,
                "body" => l.body = true,
                "anywhere" => {
                    l = Locations {
                        any_header: true,
                        headers: Vec::new(),
                        cookie: true,
                        query: true,
                        path: true,
                        body: true,
                    }
                }
                other => match other.strip_prefix("header:") {
                    Some(name) => {
                        let h = HeaderName::from_bytes(name.trim().to_ascii_lowercase().as_bytes())
                            .map_err(|_| ValidationError::InvalidLocation(item.clone()))?;
                        if h == http::header::COOKIE {
                            l.cookie = true;
                        } else {
                            l.headers.push(h);
                        }
                    }
                    None => return Err(ValidationError::InvalidLocation(item.clone())),
                },
            }
        }
        if l == Locations::default() {
            return Err(ValidationError::InvalidLocation("(empty list)".to_owned()));
        }
        Ok(l)
    }

    /// Whether `loc` is allowed.
    pub fn allows(&self, loc: &Location) -> bool {
        match loc {
            Location::Header(h) => self.any_header || self.headers.contains(h),
            Location::Cookie => self.cookie,
            Location::Query => self.query,
            Location::Path => self.path,
            Location::Body => self.body,
            Location::ClientCertificate | Location::Signature => false,
        }
    }
}

/// Origin of a placeholder string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PlaceholderKind {
    /// Generated by the redaction core, `⟦scrim:<slug>:<hmac>⟧`.
    Generated,
    /// Declared by the user in configuration, for example `SCRIM_ACME_KEY`.
    Declared,
    /// Derived from the store reference, `{{scrim:<reference>}}`.
    Reference,
}

/// A placeholder string with its origin.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Placeholder {
    /// The exact bytes the agent writes.
    pub text: String,
    /// Where it came from.
    pub kind: PlaceholderKind,
}

/// One credential ready for injection: spec, parsed binding and locations, value and placeholders.
#[derive(Clone, Debug)]
pub struct Credential {
    /// Alias.
    pub name: String,
    /// Store reference.
    pub reference: String,
    /// `None` means the credential is never injected.
    pub binding: Option<Binding>,
    /// Allowed request locations.
    pub locations: Locations,
    /// `None` while the store has not delivered the value; requests using it are refused.
    pub value: Option<SecretValue>,
    /// Every placeholder that stands for this credential.
    pub placeholders: Vec<Placeholder>,
    /// AWS `SigV4` re-signing, on a secret access key credential.
    pub aws_sigv4: Option<AwsSigV4Spec>,
    /// The value is a client certificate chain and key for upstream TLS.
    pub client_certificate: bool,
}

/// Configuration errors. None of them carries a secret value.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ValidationError {
    /// Two credentials claim the same placeholder string.
    #[error("placeholder `{placeholder}` is declared by both `{first}` and `{second}`")]
    DuplicatePlaceholder {
        /// The contested string.
        placeholder: String,
        /// First credential alias.
        first: String,
        /// Second credential alias.
        second: String,
    },
    /// Two credentials share an alias.
    #[error("credential name `{0}` is used twice")]
    DuplicateName(String),
    /// A declared placeholder is too short or contains characters that make it ambiguous.
    #[error("placeholder `{placeholder}` of `{credential}` is invalid: {reason}")]
    InvalidPlaceholder {
        /// The declared string.
        placeholder: String,
        /// Owning credential.
        credential: String,
        /// What is wrong.
        reason: &'static str,
    },
    /// A binding with no hosts.
    #[error("a binding needs at least one host")]
    EmptyBinding,
    /// A host pattern failed to parse.
    #[error(transparent)]
    Host(#[from] HostPatternError),
    /// A method name failed to parse.
    #[error("invalid method `{0}`")]
    InvalidMethod(String),
    /// A path glob does not start with `/`.
    #[error("invalid path pattern `{0}`, it must start with `/`")]
    InvalidPath(String),
    /// Unknown injection location.
    #[error("invalid injection location `{0}`")]
    InvalidLocation(String),
    /// A credential has an empty name or reference.
    #[error("credential needs a non-empty name and reference")]
    MissingField,
    /// A matcher could not be built (pattern set too large).
    #[error("building a matcher failed: {0}")]
    Matcher(String),
    /// The snapshot speaks another boundary protocol version.
    #[error("snapshot protocol version {0} is not supported")]
    ProtocolMismatch(u32),
    /// An AWS `SigV4` credential is misconfigured.
    #[error("credential `{credential}`: {reason}")]
    InvalidSigV4 {
        /// Owning credential.
        credential: String,
        /// What is wrong.
        reason: &'static str,
    },
    /// A capture rule is invalid.
    #[error("capture rule `{rule}`: {reason}")]
    InvalidCaptureRule {
        /// Rule name.
        rule: String,
        /// What is wrong.
        reason: String,
    },
}

/// Minimum length of a user-declared placeholder. Shorter strings collide with ordinary text.
pub const MIN_DECLARED_PLACEHOLDER_LEN: usize = 6;

/// A validated set of credentials. Built once per snapshot and shared read-only.
#[derive(Clone, Debug, Default)]
pub struct CredentialSet {
    credentials: Vec<Credential>,
}

/// Collects credentials and validates them together.
#[derive(Default)]
pub struct CredentialSetBuilder {
    items: Vec<(CredentialSpec, Option<SecretValue>, Vec<String>)>,
    lenient_links: bool,
}

impl CredentialSetBuilder {
    /// Adds a credential. `value` is `None` when the store has not delivered it yet.
    /// `generated` holds the placeholders the redaction core produced for this value (one per
    /// placeholder key version still retained).
    pub fn add(
        &mut self,
        spec: CredentialSpec,
        value: Option<SecretValue>,
        generated: Vec<String>,
    ) -> &mut Self {
        self.items.push((spec, value, generated));
        self
    }

    /// Drops a `SigV4` link whose access key id credential is missing instead of failing the
    /// whole set: for snapshots, where one entry must not take every credential down with it.
    pub fn lenient_links(&mut self) -> &mut Self {
        self.lenient_links = true;
        self
    }

    /// Validates and builds the set.
    pub fn build(self) -> Result<CredentialSet, ValidationError> {
        let mut owners: HashMap<String, String> = HashMap::new();
        let mut names: HashSet<String> = HashSet::new();
        let mut credentials = Vec::with_capacity(self.items.len());
        for (spec, value, generated) in self.items {
            if spec.name.trim().is_empty() || spec.reference.trim().is_empty() {
                return Err(ValidationError::MissingField);
            }
            if !names.insert(spec.name.clone()) {
                return Err(ValidationError::DuplicateName(spec.name));
            }
            let binding = spec.binding.as_ref().map(Binding::parse).transpose()?;
            let locations = Locations::parse(&spec.inject)?;
            let mut placeholders = Vec::new();
            for text in generated {
                placeholders.push(Placeholder {
                    text,
                    kind: PlaceholderKind::Generated,
                });
            }
            for text in &spec.placeholders {
                validate_declared(text, &spec.name)?;
                placeholders.push(Placeholder {
                    text: text.clone(),
                    kind: PlaceholderKind::Declared,
                });
            }
            placeholders.push(Placeholder {
                text: format!("{{{{scrim:{}}}}}", spec.reference),
                kind: PlaceholderKind::Reference,
            });
            for p in &placeholders {
                if p.text.is_empty() {
                    return Err(ValidationError::InvalidPlaceholder {
                        placeholder: String::new(),
                        credential: spec.name.clone(),
                        reason: "empty",
                    });
                }
                if let Some(first) = owners.get(&p.text) {
                    if first != &spec.name {
                        return Err(ValidationError::DuplicatePlaceholder {
                            placeholder: p.text.clone(),
                            first: first.clone(),
                            second: spec.name.clone(),
                        });
                    }
                    return Err(ValidationError::InvalidPlaceholder {
                        placeholder: p.text.clone(),
                        credential: spec.name.clone(),
                        reason: "declared twice",
                    });
                }
                owners.insert(p.text.clone(), spec.name.clone());
            }
            credentials.push(Credential {
                name: spec.name,
                reference: spec.reference,
                binding,
                locations,
                value: value.filter(|v| !v.is_empty()),
                placeholders,
                aws_sigv4: spec.aws_sigv4,
                client_certificate: spec.client_certificate,
            });
        }
        let refs: Vec<(String, String)> = credentials
            .iter()
            .map(|k| (k.reference.clone(), k.name.clone()))
            .collect();
        for c in &mut credentials {
            if let Some(a) = &c.aws_sigv4 {
                let ok = refs
                    .iter()
                    .any(|(r, n)| *r == a.access_key_id && *n != c.name);
                if !ok && self.lenient_links {
                    tracing::warn!(credential = %c.name, "SigV4 access key id credential is missing; re-signing is off for it");
                    c.aws_sigv4 = None;
                    continue;
                }
                if !ok {
                    return Err(ValidationError::InvalidSigV4 {
                        credential: c.name.clone(),
                        reason: "its access key id names no other credential's reference",
                    });
                }
                if c.client_certificate {
                    return Err(ValidationError::InvalidSigV4 {
                        credential: c.name.clone(),
                        reason: "a credential cannot be both a SigV4 secret and a client certificate",
                    });
                }
            }
        }
        Ok(CredentialSet { credentials })
    }
}

fn validate_declared(text: &str, credential: &str) -> Result<(), ValidationError> {
    let bad = |reason| ValidationError::InvalidPlaceholder {
        placeholder: text.to_owned(),
        credential: credential.to_owned(),
        reason,
    };
    if text.len() < MIN_DECLARED_PLACEHOLDER_LEN {
        return Err(bad("shorter than 6 bytes"));
    }
    if text
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(bad("contains whitespace or control characters"));
    }
    if text.contains(['"', '\\']) {
        return Err(bad("contains a quote or backslash"));
    }
    Ok(())
}

impl CredentialSet {
    /// Starts a builder.
    pub fn builder() -> CredentialSetBuilder {
        CredentialSetBuilder::default()
    }

    /// The credentials in declaration order.
    pub fn credentials(&self) -> &[Credential] {
        &self.credentials
    }

    /// The `SigV4` secret credential whose access key id credential has a placeholder that is
    /// exactly `text`: `(secret index, access key id index)`.
    pub fn sigv4_by_access_key(&self, text: &str) -> Option<(usize, usize)> {
        let ak = self
            .credentials
            .iter()
            .position(|c| c.placeholders.iter().any(|p| p.text == text))?;
        let reference = &self.credentials[ak].reference;
        let sk = self.credentials.iter().position(|c| {
            c.aws_sigv4
                .as_ref()
                .is_some_and(|a| &a.access_key_id == reference)
        })?;
        Some((sk, ak))
    }

    /// Whether a client certificate credential is bound to the host of `dest`.
    pub fn client_certificate_bound_to(&self, dest: &Destination) -> bool {
        self.credentials.iter().any(|c| {
            c.client_certificate
                && c.binding
                    .as_ref()
                    .is_some_and(|b| b.covers_destination(dest))
        })
    }

    /// Whether any credential is bound to the host of `dest`.
    pub fn any_bound_to(&self, dest: &Destination) -> bool {
        self.credentials.iter().any(|c| {
            c.binding
                .as_ref()
                .is_some_and(|b| b.covers_destination(dest))
        })
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

    fn spec(name: &str, declared: &[&str]) -> CredentialSpec {
        CredentialSpec {
            name: name.into(),
            reference: format!("bao://kv/{name}#key"),
            placeholders: declared.iter().map(|s| s.to_string()).collect(),
            binding: Some(BindingSpec {
                hosts: vec!["api.acme.test".into()],
                ..Default::default()
            }),
            inject: default_inject(),
            aws_sigv4: None,
            client_certificate: false,
        }
    }

    #[test]
    fn duplicate_declaration_names_both() {
        let mut b = CredentialSet::builder();
        b.add(spec("acme", &["SCRIM_ACME_KEY"]), None, vec![]);
        b.add(spec("other", &["SCRIM_ACME_KEY"]), None, vec![]);
        let err = b.build().unwrap_err();
        assert_eq!(
            err,
            ValidationError::DuplicatePlaceholder {
                placeholder: "SCRIM_ACME_KEY".into(),
                first: "acme".into(),
                second: "other".into()
            }
        );
        let msg = err.to_string();
        assert!(msg.contains("acme") && msg.contains("other"), "{msg}");
    }

    #[test]
    fn declared_cannot_shadow_generated() {
        let mut b = CredentialSet::builder();
        b.add(spec("acme", &[]), None, vec!["⟦scrim:acme:abcd⟧".into()]);
        b.add(spec("other", &["⟦scrim:acme:abcd⟧"]), None, vec![]);
        assert!(matches!(
            b.build(),
            Err(ValidationError::DuplicatePlaceholder { .. })
        ));
    }

    #[test]
    fn duplicate_references_conflict() {
        let mut b = CredentialSet::builder();
        let mut s2 = spec("two", &[]);
        s2.reference = "bao://kv/one#key".into();
        b.add(spec("one", &[]), None, vec![]);
        b.add(s2, None, vec![]);
        assert!(matches!(
            b.build(),
            Err(ValidationError::DuplicatePlaceholder { .. })
        ));
    }

    #[test]
    fn declared_placeholder_rules() {
        for bad in ["ABC", "has space", "quo\"te", "tab\there"] {
            let mut b = CredentialSet::builder();
            b.add(spec("acme", &[bad]), None, vec![]);
            assert!(
                matches!(b.build(), Err(ValidationError::InvalidPlaceholder { .. })),
                "{bad}"
            );
        }
    }

    #[test]
    fn locations() {
        let l = Locations::parse(&["header:Authorization".into(), "query".into()]).unwrap();
        assert!(l.allows(&Location::Header(http::header::AUTHORIZATION)));
        assert!(!l.allows(&Location::Header(HeaderName::from_static("x-api-key"))));
        assert!(l.allows(&Location::Query));
        assert!(!l.allows(&Location::Body));
        assert!(!l.allows(&Location::Cookie));
        let any = Locations::parse(&["anywhere".into()]).unwrap();
        assert!(any.allows(&Location::Body) && any.allows(&Location::Cookie));
        assert!(Locations::parse(&["bogus".into()]).is_err());
        assert!(Locations::parse(&[]).is_err());
    }

    #[test]
    fn binding_rules() {
        let b = Binding::parse(&BindingSpec {
            hosts: vec!["api.acme.test".into()],
            methods: vec!["get".into()],
            paths: vec!["/v1/*".into()],
            allow_plaintext_http: false,
        })
        .unwrap();
        let d = Destination::new(Scheme::Https, "api.acme.test", 443);
        assert!(b.covers(&d, &Method::GET, "/v1/x"));
        assert!(!b.covers(&d, &Method::POST, "/v1/x"));
        assert!(!b.covers(&d, &Method::GET, "/v2/x"));
        assert!(!b.covers(
            &Destination::new(Scheme::Http, "api.acme.test", 80),
            &Method::GET,
            "/v1/x"
        ));
        assert!(Binding::parse(&BindingSpec::default()).is_err());
    }

    #[test]
    fn yaml_spec_round_trip() {
        let y = r#"
name: acme
reference: bao://kv/agents/acme#key
placeholders: [SCRIM_ACME_KEY]
binding:
  hosts: [api.acme.test]
inject: [header, body]
"#;
        let s: CredentialSpec = serde_yaml::from_str(y).unwrap();
        assert_eq!(s.placeholders, vec!["SCRIM_ACME_KEY"]);
        let mut b = CredentialSet::builder();
        b.add(s, Some(SecretValue::new("v")), vec![]);
        let set = b.build().unwrap();
        let c = &set.credentials()[0];
        assert_eq!(c.placeholders.len(), 2);
        assert_eq!(c.placeholders[1].text, "{{scrim:bao://kv/agents/acme#key}}");
    }
}
