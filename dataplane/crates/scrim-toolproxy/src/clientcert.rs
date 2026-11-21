//! Client certificates toward upstreams (credential-injection spec, "Client certificates toward
//! upstreams"; task 10a.4).
//!
//! A credential can be a client certificate chain and private key (PEM, from a store). The agent
//! never holds it. Its configuration (a kubeconfig, for example) holds a placeholder certificate
//! instead: an Ed25519 key whose seed is `SHA-256("scrim-placeholder-cert-v1" || 0x00 ||
//! placeholder)`, for any placeholder string of the credential, in a self-signed certificate. When
//! the agent opens a tunnel toward a host a client-certificate credential is bound to, the proxy
//! asks for a client certificate in its own TLS handshake; if the agent presents the placeholder
//! certificate (recognised by its public key), the request counts as using the credential, goes
//! through the binding and policy checks like any other, and the proxy presents the real
//! certificate in its upstream handshake. The placeholder key is derived from public placeholder
//! text, so it proves nothing by itself: it says which credential the agent means, as a
//! placeholder string does.

use std::sync::Arc;

use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"scrim-placeholder-cert-v1\0";
/// The Ed25519 algorithm identifier, `1.3.101.112`.
const ED25519_OID: &str = "1.3.101.112";

/// The Ed25519 seed of the placeholder certificate for `placeholder`.
fn seed(placeholder: &str) -> Zeroizing<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(placeholder.as_bytes());
    Zeroizing::new(h.finalize().into())
}

/// PKCS#8 v1 for an Ed25519 seed (RFC 8410).
fn pkcs8(seed: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    let mut v = Zeroizing::new(Vec::with_capacity(48));
    v.extend_from_slice(&[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ]);
    v.extend_from_slice(seed);
    v
}

/// The public key of the placeholder certificate for `placeholder`.
pub fn placeholder_public_key(placeholder: &str) -> [u8; 32] {
    use ring::signature::KeyPair as _;
    let s = seed(placeholder);
    let kp = ring::signature::Ed25519KeyPair::from_seed_unchecked(&*s)
        .unwrap_or_else(|_| unreachable!("any 32 bytes are an Ed25519 seed"));
    let mut out = [0u8; 32];
    out.copy_from_slice(kp.public_key().as_ref());
    out
}

/// The placeholder certificate and key for `placeholder`, PEM, for a tool's configuration (the
/// Go control plane writes the same key; any self-signed certificate over it works). Not secret.
pub fn placeholder_certificate(
    placeholder: &str,
    common_name: &str,
) -> Result<(String, String), String> {
    let s = seed(placeholder);
    let der = pkcs8(&s);
    let key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(der.as_slice()),
        &rcgen::PKCS_ED25519,
    )
    .map_err(|e| e.to_string())?;
    let mut params =
        rcgen::CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params.not_before = time::OffsetDateTime::UNIX_EPOCH + time::Duration::days(10_957);
    params.not_after = params.not_before + time::Duration::days(365 * 100);
    let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// The Ed25519 public key of a presented end-entity certificate, if it has one.
pub(crate) fn presented_key(cert: &CertificateDer<'_>) -> Option<[u8; 32]> {
    let (_, c) = x509_parser::parse_x509_certificate(cert.as_ref()).ok()?;
    let spki = c.public_key();
    if spki.algorithm.algorithm.to_id_string() != ED25519_OID {
        return None;
    }
    spki.subject_public_key.data.as_ref().try_into().ok()
}

/// A client certificate chain and key parsed from a credential value. The key is wiped when
/// the identity drops (rustls holds its own copy inside the client configuration).
pub(crate) struct ClientIdentity {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

/// Parses a PEM bundle: one or more certificates (end-entity first) and one private key.
/// Errors never quote the input.
pub(crate) fn parse_identity(value: &[u8]) -> Result<ClientIdentity, String> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(value)
        .collect::<Result<_, _>>()
        .map_err(|_| "the client certificate is not valid PEM".to_owned())?;
    if chain.is_empty() {
        return Err("the client certificate credential holds no certificate".to_owned());
    }
    let key = PrivateKeyDer::from_pem_slice(value)
        .map_err(|_| "the client certificate credential holds no usable private key".to_owned())?;
    Ok(ClientIdentity { chain, key })
}

/// Asks the agent for a client certificate without requiring one, and accepts any: the proxy
/// only uses it to recognise a placeholder certificate by its key. Handshake signatures are
/// still verified, so the presented certificate is the one the client holds the key of.
#[derive(Debug)]
pub(crate) struct OptionalClientCert {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl OptionalClientCert {
    pub(crate) fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        Self { provider }
    }
}

impl ClientCertVerifier for OptionalClientCert {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The certificate the agent presented in its TLS handshake with the proxy, attached to every
/// request of the tunnel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PresentedCertificate(pub [u8; 32]);

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
    fn placeholder_certificate_carries_the_derived_key() {
        let ph = "\u{27e6}scrim:kind-admin:01aabbccddeeff0011\u{27e7}";
        let (cert, key) = placeholder_certificate(ph, "scrim placeholder kind-admin").unwrap();
        assert!(key.contains("PRIVATE KEY"));
        let der = CertificateDer::from_pem_slice(cert.as_bytes()).unwrap();
        assert_eq!(presented_key(&der), Some(placeholder_public_key(ph)));
        // Deterministic: Ed25519 signatures are, and every field is fixed.
        assert_eq!(
            placeholder_certificate(ph, "scrim placeholder kind-admin")
                .unwrap()
                .0,
            cert
        );
        assert_ne!(
            placeholder_public_key(ph),
            placeholder_public_key("SCRIM_OTHER")
        );
    }

    /// The vector the Go control plane checks too (`internal/placeholder/testdata/cert.json`).
    #[test]
    fn shared_vector() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../internal/placeholder/testdata/cert.json"
        );
        let text = std::fs::read_to_string(path).unwrap();
        let v: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap();
        assert!(!v.is_empty());
        for row in v {
            let ph = row["placeholder"].as_str().unwrap();
            let want = row["public_key_hex"].as_str().unwrap();
            let got: String = placeholder_public_key(ph)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(got, want, "{ph}");
        }
    }

    #[test]
    fn identity_parsing() {
        let k = rcgen::KeyPair::generate().unwrap();
        let c = rcgen::CertificateParams::new(vec!["client".into()])
            .unwrap()
            .self_signed(&k)
            .unwrap();
        let pem = format!("{}{}", c.pem(), k.serialize_pem());
        let id = parse_identity(pem.as_bytes()).unwrap();
        assert_eq!(id.chain.len(), 1);
        assert!(parse_identity(c.pem().as_bytes()).is_err());
        assert!(parse_identity(b"not pem").is_err());
    }
}
