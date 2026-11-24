// SPDX-License-Identifier: AGPL-3.0-only

//! Redacting `Debug` and zeroing `Drop` for the messages that hold secrets.

use std::fmt;

use zeroize::Zeroize;

use crate::v1::{
    AskCaller, CaCertificate, CaptureRequest, PlaceholderKey, RedactRequest, UpstreamProxy,
    ValueEntry,
};

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
            .field("declared_placeholders", &self.declared_placeholders)
            .field("bound_methods", &self.bound_methods)
            .field("bound_paths", &self.bound_paths)
            .field("inject_locations", &self.inject_locations)
            .field("allow_plaintext_http", &self.allow_plaintext_http)
            .field("aws_sigv4", &self.aws_sigv4)
            .field("placeholder_format", &self.placeholder_format)
            .field("client_certificate", &self.client_certificate)
            .field("labels", &self.labels)
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

impl fmt::Debug for CaptureRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaptureRequest")
            .field("protocol", &self.protocol)
            .field("id", &self.id)
            .field("rule", &self.rule)
            .field("ref", &self.r#ref)
            .field("destination", &self.destination)
            .field("value", &Redacted(self.value.len()))
            .field("deadline_unix_nano", &self.deadline_unix_nano)
            .finish()
    }
}

impl fmt::Debug for CaCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaCertificate")
            .field("cert_pem", &self.cert_pem)
            .field("key_pem", &Redacted(self.key_pem.len()))
            .field("current", &self.current)
            .finish()
    }
}

impl fmt::Debug for AskCaller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AskCaller")
            .field("session_id", &self.session_id)
            .field("unix_peer", &self.unix_peer)
            .field("peer_uid", &self.peer_uid)
            .field("peer_gid", &self.peer_gid)
            .field("peer_pid", &self.peer_pid)
            .field("session_proof", &self.session_proof)
            .field("kubernetes_token", &Redacted(self.kubernetes_token.len()))
            .finish()
    }
}

impl fmt::Debug for RedactRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedactRequest")
            .field("protocol", &self.protocol)
            .field("text", &Redacted(self.text.len()))
            .finish()
    }
}

impl fmt::Debug for UpstreamProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpstreamProxy")
            .field("url", &self.url)
            .field("no_proxy", &self.no_proxy)
            .field("username", &self.username)
            .field("password", &Redacted(self.password.len()))
            .finish()
    }
}

impl Drop for UpstreamProxy {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

impl Drop for RedactRequest {
    fn drop(&mut self) {
        self.text.zeroize();
    }
}

impl Drop for AskCaller {
    fn drop(&mut self) {
        self.kubernetes_token.zeroize();
    }
}

impl Drop for CaCertificate {
    fn drop(&mut self) {
        self.key_pem.zeroize();
    }
}

impl Drop for CaptureRequest {
    fn drop(&mut self) {
        self.value.zeroize();
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

        let mut ca = crate::v1::CaCertificate::default();
        ca.cert_pem = "-----BEGIN CERTIFICATE-----".into();
        ca.key_pem.clone_from(&secret);
        snap.tool_proxy_ca.push(ca);

        let mut capture = crate::v1::CaptureRequest::default();
        capture.value.clone_from(&secret);
        let redact = crate::v1::RedactRequest {
            protocol: 1,
            text: secret.clone(),
        };
        let mut caller = crate::v1::AskCaller::default();
        caller.kubernetes_token.clone_from(&secret);
        let ask = crate::v1::AskRequest {
            caller: Some(caller),
            ..Default::default()
        };
        let mut proxy = crate::v1::UpstreamProxy::default();
        proxy.url = "http://proxy.example.test:3128".into();
        proxy.username = "scrim".into();
        proxy.password.clone_from(&secret);
        snap.upstream_proxy = Some(proxy);
        let out = format!("{snap:?} {snap:#?} {capture:?} {ask:?} {ask:#?} {redact:?}");
        let as_text = String::from_utf8(secret.clone()).unwrap_or_default();
        assert!(!out.contains(&as_text), "debug output leaks: {out}");
        assert!(
            !out.contains(&format!("{secret:?}")),
            "debug output leaks bytes"
        );
        assert!(out.contains(super::REDACTED));
        assert!(out.contains("bao://kv/x#token"));
        assert!(out.contains("proxy.example.test:3128"));
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
