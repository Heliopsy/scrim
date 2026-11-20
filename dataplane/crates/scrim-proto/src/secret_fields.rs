// SPDX-License-Identifier: AGPL-3.0-only

//! Redacting `Debug` and zeroing `Drop` for the messages that hold secrets.

use std::fmt;

use zeroize::Zeroize;

use crate::v1::{PlaceholderKey, ValueEntry};

/// What `Debug` prints in place of secret bytes.
pub const REDACTED: &str = "[scrim:redacted]";

struct Redacted(usize);

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{REDACTED} ({} bytes)", self.0)
    }
}

impl fmt::Debug for ValueEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValueEntry")
            .field("ref", &self.r#ref)
            .field("slug", &self.slug)
            .field("value", &Redacted(self.value.len()))
            .field("class", &self.class)
            .field("bound_hosts", &self.bound_hosts)
            .field("name", &self.name)
            .field("store", &self.store)
            .finish()
    }
}

impl fmt::Debug for PlaceholderKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlaceholderKey")
            .field("version", &self.version)
            .field("key", &Redacted(self.key.len()))
            .field("current", &self.current)
            .finish()
    }
}

impl Drop for ValueEntry {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl Drop for PlaceholderKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use crate::v1::{PlaceholderKey, Snapshot, ValueEntry};

    #[test]
    fn debug_never_prints_secret_bytes() {
        let secret = b"generated-for-this-test-7f3a9c".to_vec();
        let mut entry = ValueEntry::default();
        entry.r#ref = "bao://kv/x#token".into();
        entry.value.clone_from(&secret);
        let mut key = PlaceholderKey::default();
        key.key.clone_from(&secret);
        let mut snap = Snapshot::default();
        snap.values.push(entry);
        snap.placeholder_keys.push(key);

        let out = format!("{snap:?} {snap:#?}");
        let as_text = String::from_utf8(secret.clone()).unwrap_or_default();
        assert!(!out.contains(&as_text), "debug output leaks: {out}");
        assert!(
            !out.contains(&format!("{secret:?}")),
            "debug output leaks bytes"
        );
        assert!(out.contains(super::REDACTED));
        assert!(out.contains("bao://kv/x#token"));
    }

    #[test]
    fn round_trip() {
        let mut entry = ValueEntry::default();
        entry.value = vec![1, 2, 3];
        let snap = Snapshot {
            version: 7,
            values: vec![entry],
            ..Default::default()
        };
        let back = Snapshot::decode(snap.encode_to_vec().as_slice()).ok();
        assert_eq!(
            back.map(|s| (s.version, s.values[0].value.clone())),
            Some((7, vec![1, 2, 3]))
        );
    }
}
