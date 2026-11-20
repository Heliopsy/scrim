//! A byte string holding a secret value.

use std::fmt;

use zeroize::Zeroizing;

/// A secret value held in memory only.
///
/// The bytes are wiped when the last copy is dropped. `Debug` and `Display` never print the value
/// or its length, and the type implements neither `Serialize` nor `Deserialize`, so it cannot end up
/// in a log line, an error, a metric or an audit entry by accident. Code that needs the bytes calls
/// [`SecretValue::expose`] at the single place it writes them to the wire.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    /// Wraps `bytes`. The caller's buffer is moved, not copied.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(Zeroizing::new(bytes.into()))
    }

    /// The secret bytes. Every call site is a place where the value can leave the process, so keep
    /// them few and reviewed.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Whether the value is empty. An empty value is never injected.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue(<redacted>)")
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
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
    fn debug_and_display_hide_the_value() {
        let v = SecretValue::new("hunter2-very-secret");
        assert_eq!(format!("{v:?}"), "SecretValue(<redacted>)");
        assert_eq!(format!("{v}"), "<redacted>");
        assert_eq!(v.expose(), b"hunter2-very-secret");
    }
}
