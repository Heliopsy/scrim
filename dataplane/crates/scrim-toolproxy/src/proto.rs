//! Building a [`Snapshot`] from the control plane's protobuf snapshot (`scrim-proto`).

use std::collections::HashSet;
use std::sync::Arc;

use scrim_proto::v1;

use crate::capture::{CaptureRule, CaptureRuleSpec};
use crate::credential::{BindingSpec, CredentialSet, CredentialSpec, ValidationError};
use crate::engine::Snapshot;
use crate::redactor::{Redactor, ValueRedactor};
use crate::secret::SecretValue;

impl Snapshot {
    /// Converts a boundary snapshot.
    ///
    /// Every value entry of class credential (or unspecified, which is treated as credential)
    /// becomes an injectable credential: its `bound_hosts`, `bound_methods` and `bound_paths` are
    /// the binding (no hosts means never injected), `declared_placeholders` its user-declared
    /// placeholders and `inject_locations` where it may be substituted. Every entry, display
    /// values included, is redacted from responses.
    ///
    /// `placeholders_of` returns the generated placeholders for an entry, derived by the
    /// redaction core from the snapshot's placeholder keys (current key first). The first one is
    /// what responses show for the value.
    pub fn from_proto(
        snapshot: &v1::Snapshot,
        placeholders_of: impl Fn(&v1::ValueEntry) -> Vec<String>,
    ) -> Result<Self, ValidationError> {
        if snapshot.protocol != v1::PROTOCOL {
            return Err(ValidationError::ProtocolMismatch(snapshot.protocol));
        }
        let mut builder = CredentialSet::builder();
        let mut redact: Vec<(SecretValue, Vec<u8>)> = Vec::new();
        // Names and references of the bound entries. A value with no binding that shares one
        // (a rotated value retained beside its current one, a second session token, a store's
        // second own credential) can never be injected, so it is redacted only and adds no
        // credential: two credentials of one name or reference would fail validation and the
        // whole snapshot with them.
        let credential_name = |e: &v1::ValueEntry| {
            if e.name.is_empty() {
                e.r#ref.clone()
            } else {
                e.name.clone()
            }
        };
        let mut taken: HashSet<String> = snapshot
            .values
            .iter()
            .filter(|e| !e.bound_hosts.is_empty() && e.class() != v1::ValueClass::Display)
            .flat_map(|e| [credential_name(e), e.r#ref.clone()])
            .collect();
        for entry in &snapshot.values {
            let value = SecretValue::new(entry.value.clone());
            let generated = placeholders_of(entry);
            let shown = generated
                .first()
                .cloned()
                .or_else(|| entry.declared_placeholders.first().cloned())
                .unwrap_or_else(|| format!("{{{{scrim:{}}}}}", entry.r#ref));
            redact.push((value.clone(), shown.into_bytes()));
            if entry.class() == v1::ValueClass::Display {
                continue;
            }
            if entry.bound_hosts.is_empty() {
                let name = credential_name(entry);
                let fresh_ref = name == entry.r#ref || taken.insert(entry.r#ref.clone());
                let fresh_name = taken.insert(name);
                if !(fresh_name && fresh_ref) {
                    continue;
                }
            }
            let binding = (!entry.bound_hosts.is_empty()).then(|| BindingSpec {
                hosts: entry.bound_hosts.clone(),
                methods: entry.bound_methods.clone(),
                paths: entry.bound_paths.clone(),
                allow_plaintext_http: entry.allow_plaintext_http,
            });
            let inject = if entry.inject_locations.is_empty() {
                vec!["header".to_owned()]
            } else {
                entry.inject_locations.clone()
            };
            let spec = CredentialSpec {
                name: credential_name(entry),
                reference: entry.r#ref.clone(),
                placeholders: entry.declared_placeholders.clone(),
                binding,
                inject,
            };
            builder.add(spec, Some(value), generated);
        }
        let credentials = builder.build()?;
        let capture_rules = snapshot
            .capture_rules
            .iter()
            .map(|r| {
                CaptureRule::parse(&CaptureRuleSpec {
                    name: r.name.clone(),
                    hosts: r.hosts.clone(),
                    methods: r.methods.clone(),
                    path: (!r.path.is_empty()).then(|| r.path.clone()),
                    status: r
                        .status
                        .iter()
                        .filter_map(|s| u16::try_from(*s).ok())
                        .collect(),
                    field: (!r.json_pointer.is_empty()).then(|| r.json_pointer.clone()),
                    header: (!r.header.is_empty()).then(|| r.header.clone()),
                    store: r.store_ref.clone(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let redactor: Arc<dyn Redactor> = Arc::new(
            ValueRedactor::new(redact.iter().map(|(v, p)| (v, p.as_slice())))
                .map_err(|e| ValidationError::Matcher(e.0))?,
        );
        Ok(Self {
            version: snapshot.version,
            credentials,
            capture_rules,
            redactor: Some(redactor),
            injection: None,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::pedantic)]
mod tests {
    use super::*;

    fn entry(
        r: &str,
        name: &str,
        value: &str,
        hosts: &[&str],
        declared: &[&str],
    ) -> v1::ValueEntry {
        let mut e = v1::ValueEntry::default();
        e.r#ref = r.into();
        e.name = name.into();
        e.value = value.as_bytes().to_vec();
        e.class = v1::ValueClass::Credential as i32;
        e.bound_hosts = hosts.iter().map(|s| (*s).to_owned()).collect();
        e.declared_placeholders = declared.iter().map(|s| (*s).to_owned()).collect();
        e
    }

    fn snap(values: Vec<v1::ValueEntry>) -> v1::Snapshot {
        v1::Snapshot {
            protocol: v1::PROTOCOL,
            version: 7,
            values,
            ..Default::default()
        }
    }

    #[test]
    fn maps_entries_to_credentials() {
        let mut display = entry("env://D", "d", "display-value-123", &[], &[]);
        display.class = v1::ValueClass::Display as i32;
        let s = snap(vec![
            entry(
                "bao://kv/acme#key",
                "acme",
                "acme-value-123",
                &["api.acme.test"],
                &["SCRIM_ACME_KEY"],
            ),
            entry("env://UNBOUND", "", "unbound-value-1", &[], &[]),
            display,
        ]);
        let out = Snapshot::from_proto(&s, |e| vec![format!("⟦scrim:{}:00⟧", e.name)]).unwrap();
        assert_eq!(out.version, 7);
        let creds = out.credentials.credentials();
        assert_eq!(creds.len(), 2);
        assert_eq!(creds[0].name, "acme");
        assert!(creds[0].binding.is_some());
        assert_eq!(creds[0].placeholders.len(), 3);
        assert_eq!(creds[1].name, "env://UNBOUND");
        assert!(creds[1].binding.is_none());
        let r = out.redactor.unwrap();
        let mut m = Vec::new();
        r.find(b"x display-value-123 acme-value-123", &mut m)
            .unwrap();
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn unbound_values_sharing_a_name_are_redacted_only() {
        // A rotated value retained next to its current one, and two values
        // of the same store with no reference (session tokens, a store's own
        // credentials), share a name and reference.
        let s = snap(vec![
            entry("bao://kv/acme#key", "acme", "acme-old-value-1", &[], &[]),
            entry(
                "bao://kv/acme#key",
                "acme",
                "acme-new-value-1",
                &["api.acme.test"],
                &["SCRIM_ACME_KEY"],
            ),
            entry("store:scrim-sessions", "", "session-token-one", &[], &[]),
            entry("store:scrim-sessions", "", "session-token-two", &[], &[]),
        ]);
        let out = Snapshot::from_proto(&s, |e| {
            vec![format!(
                "⟦scrim:{}:{}⟧",
                e.name,
                e.value.len() + e.value[4] as usize
            )]
        })
        .unwrap();
        let creds = out.credentials.credentials();
        assert_eq!(creds.len(), 2);
        assert_eq!(creds[0].name, "acme");
        assert!(creds[0].binding.is_some(), "the current value stays bound");
        assert!(creds[0].value.is_some());
        assert_eq!(creds[1].name, "store:scrim-sessions");
        let mut m = Vec::new();
        out.redactor
            .unwrap()
            .find(
                b"acme-old-value-1 acme-new-value-1 session-token-one session-token-two",
                &mut m,
            )
            .unwrap();
        assert_eq!(m.len(), 4, "every value is still redacted");
    }

    #[test]
    fn bound_values_sharing_a_name_fail() {
        let s = snap(vec![
            entry("env://A", "a", "value-a-12345", &["a.test"], &[]),
            entry("env://B", "a", "value-b-12345", &["b.test"], &[]),
        ]);
        let e = Snapshot::from_proto(&s, |_| vec![]).err().unwrap();
        assert!(matches!(e, ValidationError::DuplicateName(_)));
    }

    #[test]
    fn duplicate_declared_placeholders_fail() {
        let s = snap(vec![
            entry(
                "env://A",
                "a",
                "value-a-12345",
                &["a.test"],
                &["SCRIM_SAME"],
            ),
            entry(
                "env://B",
                "b",
                "value-b-12345",
                &["b.test"],
                &["SCRIM_SAME"],
            ),
        ]);
        let e = Snapshot::from_proto(&s, |_| vec![]).err().unwrap();
        assert!(matches!(e, ValidationError::DuplicatePlaceholder { .. }));
    }

    #[test]
    fn protocol_mismatch_is_rejected() {
        let mut s = snap(vec![]);
        s.protocol = 99;
        assert!(matches!(
            Snapshot::from_proto(&s, |_| vec![]),
            Err(ValidationError::ProtocolMismatch(99))
        ));
    }

    #[test]
    fn capture_rules_are_converted() {
        let mut s = snap(vec![]);
        s.capture_rules.push(v1::CaptureRule {
            name: "tok".into(),
            hosts: vec!["api.acme.test".into()],
            json_pointer: "/token".into(),
            store_ref: "bao://kv/new#token".into(),
            ..Default::default()
        });
        let out = Snapshot::from_proto(&s, |_| vec![]).unwrap();
        assert_eq!(out.capture_rules.len(), 1);
        s.capture_rules[0].header = "x-token".into();
        assert!(Snapshot::from_proto(&s, |_| vec![]).is_err());
    }
}
