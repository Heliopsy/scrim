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
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Location::Header(h) => write!(f, "header `{h}`"),
            Location::Cookie => f.write_str("cookie"),
            Location::Query => f.write_str("query"),
            Location::Path => f.write_str("path"),
            Location::Body => f.write_str("body"),
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
            });
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
