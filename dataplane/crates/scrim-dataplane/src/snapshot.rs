// SPDX-License-Identifier: AGPL-3.0-only

//! The applied snapshot: the validated, in-memory form of a
//! [`v1::Snapshot`]. Secret bytes move out of the protobuf message into
//! [`SecretBytes`], which zeroes them on drop and never prints them.

use std::fmt;

use scrim_proto::v1;
use zeroize::Zeroizing;

/// Secret bytes. `Debug` prints only the length; drop zeroes the buffer.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Takes ownership of `v`.
    pub fn new(v: Vec<u8>) -> Self {
        Self(Zeroizing::new(v))
    }

    /// The bytes. Callers must not copy them anywhere that outlives the
    /// request or reaches output.
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

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({} bytes)", scrim_proto::REDACTED, self.0.len())
    }
}

/// How a value may be restored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// Injected toward bound hosts only.
    Credential,
    /// Restorable under the tool policy.
    Display,
}

/// One dictionary entry.
#[derive(Debug)]
pub struct Value {
    /// Store reference, safe to log.
    pub reference: String,
    /// Placeholder slug.
    pub slug: String,
    /// The secret.
    pub bytes: SecretBytes,
    /// Restore class.
    pub class: Class,
    /// Hosts a credential may be injected toward.
    pub bound_hosts: Vec<String>,
    /// Catalog name, if any.
    pub name: String,
    /// Store instance.
    pub store: String,
}

/// A placeholder HMAC key.
#[derive(Debug)]
pub struct Key {
    /// Version embedded in placeholders.
    pub version: u32,
    /// Key material.
    pub key: SecretBytes,
}

/// A validated snapshot in force.
#[derive(Debug)]
pub struct Applied {
    /// Snapshot version.
    pub version: u64,
    /// Value dictionary.
    pub values: Vec<Value>,
    /// Version of the key new placeholders use.
    pub current_key: Option<u32>,
    /// Every placeholder key, current and older.
    pub keys: Vec<Key>,
    /// Compiled policy.
    pub policy: v1::Policy,
    /// Provider routes.
    pub routes: Vec<v1::Route>,
    /// Listeners to bind.
    pub listeners: Vec<v1::Listener>,
    /// Shortest value matched in free text.
    pub min_value_length: u32,
}

/// Why a snapshot was rejected. Messages name fields and references, never
/// values.
#[derive(Debug, PartialEq, Eq)]
pub enum Rejected {
    /// The version is not newer than the one in force.
    Stale {
        /// Offered version.
        offered: u64,
        /// Version in force.
        applied: u64,
    },
    /// A field failed validation.
    Invalid(String),
}

impl fmt::Display for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stale { offered, applied } => {
                write!(f, "snapshot version {offered} is not newer than {applied}")
            }
            Self::Invalid(why) => f.write_str(why),
        }
    }
}

/// Policy engines this build can run, besides the structured rules.
const ENGINES: &[&str] = &[];

impl Applied {
    /// Validates `snap` against the version in force and converts it. On
    /// error nothing changes and `snap`'s secret bytes are zeroed when it
    /// drops.
    pub fn from_proto(mut snap: v1::Snapshot, applied: u64) -> Result<Self, Rejected> {
        if snap.version <= applied {
            return Err(Rejected::Stale {
                offered: snap.version,
                applied,
            });
        }
        let current: Vec<u32> = snap
            .placeholder_keys
            .iter()
            .filter(|k| k.current)
            .map(|k| k.version)
            .collect();
        if current.len() > 1 {
            return Err(Rejected::Invalid(
                "more than one current placeholder key".into(),
            ));
        }
        if !snap.values.is_empty() && current.is_empty() {
            return Err(Rejected::Invalid(
                "values without a current placeholder key".into(),
            ));
        }
        let policy = snap.policy.take().unwrap_or_default();
        if !policy.engine.is_empty() && !ENGINES.contains(&policy.engine.as_str()) {
            return Err(Rejected::Invalid(format!(
                "policy engine {:?} is not supported by this data plane",
                policy.engine
            )));
        }
        for l in &snap.listeners {
            if l.kind() == v1::ListenerKind::Unspecified || l.address.is_empty() {
                return Err(Rejected::Invalid(format!(
                    "listener {:?} needs a kind and address",
                    l.name
                )));
            }
        }
        let mut values = Vec::with_capacity(snap.values.len());
        for v in &mut snap.values {
            if v.value.is_empty() {
                return Err(Rejected::Invalid(format!("value for {} is empty", v.r#ref)));
            }
            let class = match v.class() {
                v1::ValueClass::Display => Class::Display,
                v1::ValueClass::Credential | v1::ValueClass::Unspecified => Class::Credential,
            };
            values.push(Value {
                reference: std::mem::take(&mut v.r#ref),
                slug: std::mem::take(&mut v.slug),
                bytes: SecretBytes::new(std::mem::take(&mut v.value)),
                class,
                bound_hosts: std::mem::take(&mut v.bound_hosts),
                name: std::mem::take(&mut v.name),
                store: std::mem::take(&mut v.store),
            });
        }
        let keys = snap
            .placeholder_keys
            .iter_mut()
            .map(|k| Key {
                version: k.version,
                key: SecretBytes::new(std::mem::take(&mut k.key)),
            })
            .collect();
        Ok(Self {
            version: snap.version,
            values,
            current_key: current.first().copied(),
            keys,
            policy,
            routes: std::mem::take(&mut snap.routes),
            listeners: std::mem::take(&mut snap.listeners),
            min_value_length: snap.redaction.map_or(8, |r| r.min_value_length.max(1)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(value: &[u8]) -> v1::ValueEntry {
        let mut e = v1::ValueEntry::default();
        e.r#ref = "bao://kv/a#token".into();
        e.value = value.to_vec();
        e
    }

    fn key(version: u32, current: bool) -> v1::PlaceholderKey {
        let mut k = v1::PlaceholderKey::default();
        k.version = version;
        k.key = vec![9; 32];
        k.current = current;
        k
    }

    fn snap(version: u64) -> v1::Snapshot {
        v1::Snapshot {
            version,
            values: vec![entry(b"runtime-made-value")],
            placeholder_keys: vec![key(1, false), key(2, true)],
            ..Default::default()
        }
    }

    #[test]
    fn applies_and_redacts_debug() {
        let a = Applied::from_proto(snap(1), 0);
        let a = a.as_ref().ok();
        assert_eq!(a.map(|a| a.current_key), Some(Some(2)));
        assert_eq!(a.map(|a| a.values[0].class), Some(Class::Credential));
        let out = format!("{a:?}");
        assert!(!out.contains("runtime-made-value"));
        assert!(out.contains(scrim_proto::REDACTED));
    }

    #[test]
    fn rejects() {
        assert_eq!(
            Applied::from_proto(snap(3), 3).err(),
            Some(Rejected::Stale {
                offered: 3,
                applied: 3
            })
        );
        let mut s = snap(1);
        s.placeholder_keys = vec![key(1, false)];
        assert!(matches!(
            Applied::from_proto(s, 0),
            Err(Rejected::Invalid(_))
        ));
        let mut s = snap(1);
        s.placeholder_keys.push(key(3, true));
        assert!(matches!(
            Applied::from_proto(s, 0),
            Err(Rejected::Invalid(_))
        ));
        let mut s = snap(1);
        s.values = vec![entry(b"")];
        assert!(matches!(
            Applied::from_proto(s, 0),
            Err(Rejected::Invalid(_))
        ));
        let mut s = snap(1);
        s.policy = Some(v1::Policy {
            engine: "cel/v1".into(),
            ..Default::default()
        });
        assert!(matches!(
            Applied::from_proto(s, 0),
            Err(Rejected::Invalid(_))
        ));
        let mut s = snap(1);
        s.listeners = vec![v1::Listener {
            name: "x".into(),
            ..Default::default()
        }];
        assert!(matches!(
            Applied::from_proto(s, 0),
            Err(Rejected::Invalid(_))
        ));
    }
}
