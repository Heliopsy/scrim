//! Secret values and the metadata that travels with them.

use std::fmt;

use zeroize::Zeroizing;

use crate::error::BuildError;

/// A secret value held in memory.
///
/// The bytes are wiped when the value is dropped. `Debug` prints `SecretValue(<redacted>)` and the
/// type implements neither `Display` nor `Clone`, so the value cannot leak through formatting or be
/// copied by accident. Use [`SecretValue::expose`] where the bytes are really needed.
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    /// Wraps `bytes`. The vector is moved in, so no unwiped copy is left behind by this call.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Copies `bytes` into a new value. The caller stays responsible for wiping its own copy.
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }

    /// The secret bytes. Every call site is a place the value can escape; keep them few.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the value is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue(<redacted>)")
    }
}

/// How a value may be restored into responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ValueClass {
    /// Authenticates something (token, password, key). Never restored into tool arguments,
    /// commands or file contents; reaches its destination only through credential injection.
    Credential,
    /// Data that is sensitive to show to a provider but may be restored into tool calls the
    /// restore policy allows (a hostname, an account number).
    Display,
}

/// Stable identifier of a dictionary entry, chosen by the caller (for example a row id of the
/// secret reference). Ties between entries holding the same value are broken by the lowest id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EntryId(pub u64);

/// The alias of a secret reference as it appears inside a placeholder.
///
/// Alphabet `[a-z0-9-]`, 1 to [`RefSlug::MAX_LEN`] bytes, no leading or trailing `-`. The slug
/// names the reference, never the value.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RefSlug(Box<str>);

impl RefSlug {
    /// Longest accepted slug in bytes.
    pub const MAX_LEN: usize = 48;

    /// Validates `s` as a slug.
    pub fn new(s: &str) -> Result<Self, BuildError> {
        let b = s.as_bytes();
        let ok = !b.is_empty()
            && b.len() <= Self::MAX_LEN
            && b.iter().all(|&c| is_slug_byte(c))
            && b[0] != b'-'
            && b[b.len() - 1] != b'-';
        if ok {
            Ok(Self(s.into()))
        } else {
            Err(BuildError::InvalidSlug)
        }
    }

    /// Derives a slug from any alias: ASCII letters are lower-cased, every run of other
    /// characters becomes one `-`, and the result is trimmed and cut to [`RefSlug::MAX_LEN`].
    /// An alias with no usable character becomes `ref`.
    pub fn from_alias(alias: &str) -> Self {
        let mut out = String::with_capacity(alias.len().min(Self::MAX_LEN));
        let mut dash = false;
        for c in alias.bytes() {
            let c = c.to_ascii_lowercase();
            if c.is_ascii_lowercase() || c.is_ascii_digit() {
                if dash && !out.is_empty() {
                    out.push('-');
                }
                dash = false;
                out.push(c as char);
            } else {
                dash = true;
            }
            if out.len() >= Self::MAX_LEN {
                break;
            }
        }
        out.truncate(Self::MAX_LEN);
        while out.ends_with('-') {
            out.pop();
        }
        if out.is_empty() {
            out.push_str("ref");
        }
        Self(out.into())
    }

    /// The slug text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RefSlug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RefSlug({})", self.0)
    }
}

impl fmt::Display for RefSlug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub(crate) fn is_slug_byte(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'
}

/// Everything about an entry except its value. Safe to log, audit and hand to policy code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryMeta {
    /// Caller-chosen id.
    pub id: EntryId,
    /// Alias shown in the placeholder.
    pub slug: RefSlug,
    /// Restore class.
    pub class: ValueClass,
}

/// One known secret value with its metadata, as handed to [`crate::Snapshot::build`].
#[derive(Debug)]
pub struct Entry {
    /// Metadata.
    pub meta: EntryMeta,
    /// The value.
    pub value: SecretValue,
    /// Use a format-preserving placeholder ([`crate::shaped_placeholder_for`]) when the value
    /// has a shape and is a credential.
    pub shape: bool,
}

impl Entry {
    /// Asks for a format-preserving placeholder (credentials only; a value without a shape keeps
    /// the bracket form).
    #[must_use]
    pub fn with_shape(mut self, shape: bool) -> Self {
        self.shape = shape;
        self
    }

    /// Convenience constructor.
    pub fn new(id: u64, slug: RefSlug, class: ValueClass, value: SecretValue) -> Self {
        Self {
            meta: EntryMeta {
                id: EntryId(id),
                slug,
                class,
            },
            value,
            shape: false,
        }
    }
}
