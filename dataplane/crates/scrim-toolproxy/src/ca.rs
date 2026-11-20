//! The interception certificate authority and per-host leaf certificates.
//!
//! [`CertificateAuthority`] is one CA generation: a P-256 key and a self-signed certificate.
//! [`CaRing`] holds the current generation and, during a rotation's overlap period, the previous
//! one. While the overlap lasts, every leaf is served with a cross certificate (the new CA's key
//! and name, signed by the previous CA), so clients that only trust the previous CA keep
//! connecting and clients that trust the new CA anchor directly. When the overlap ends the cross
//! certificate is dropped.
//!
//! Only the public certificate leaves this module for trust installation ([`CaRing::trust_bundle_pem`]).
//! The private key is exported solely through [`CertificateAuthority::key_pem`] for the control
//! plane to persist it in a location agents cannot read.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SanType, SerialNumber,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use time::OffsetDateTime;
use zeroize::Zeroizing;

/// CA errors. None contains key material.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CaError {
    /// Certificate generation or signing failed.
    #[error("certificate generation failed: {0}")]
    Generate(String),
    /// The PEM input could not be parsed.
    #[error("could not parse CA certificate or key: {0}")]
    Parse(String),
    /// The host name cannot be put into a certificate.
    #[error("invalid host name for a certificate")]
    InvalidHost,
}

impl From<rcgen::Error> for CaError {
    fn from(e: rcgen::Error) -> Self {
        CaError::Generate(e.to_string())
    }
}

/// Options for a new CA generation.
#[derive(Clone, Debug)]
pub struct CaOptions {
    /// Common name; a timestamp is appended so generations have distinct names.
    pub common_name: String,
    /// Validity of the CA certificate.
    pub validity: Duration,
}

impl Default for CaOptions {
    fn default() -> Self {
        Self {
            common_name: "scrim interception CA".into(),
            validity: Duration::from_hours(17520),
        }
    }
}

/// One CA generation.
pub struct CertificateAuthority {
    /// Issuer handle for signing (rebuilt from parameters when loaded from PEM).
    issuer: rcgen::Certificate,
    key: KeyPair,
    cert_der: CertificateDer<'static>,
    cert_pem: String,
    not_after: OffsetDateTime,
}

impl std::fmt::Debug for CertificateAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateAuthority")
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

fn ca_params(opts: &CaOptions, now: OffsetDateTime) -> Result<CertificateParams, CaError> {
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    let stamp = now.unix_timestamp();
    dn.push(DnType::CommonName, format!("{} {stamp}", opts.common_name));
    dn.push(DnType::OrganizationName, "scrim");
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    p.not_before = now - time::Duration::minutes(5);
    p.not_after = now + opts.validity;
    p.serial_number = Some(random_serial()?);
    Ok(p)
}

fn random_serial() -> Result<SerialNumber, CaError> {
    let mut b = [0u8; 16];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut b)
        .map_err(|_| CaError::Generate("system random source failed".into()))?;
    b[0] &= 0x7f;
    Ok(SerialNumber::from_slice(&b))
}

impl CertificateAuthority {
    /// Generates a new CA generation.
    pub fn generate(opts: &CaOptions) -> Result<Self, CaError> {
        let now = OffsetDateTime::now_utc();
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let params = ca_params(opts, now)?;
        let not_after = params.not_after;
        let issuer = params.self_signed(&key)?;
        let cert_der = issuer.der().clone();
        let cert_pem = issuer.pem();
        Ok(Self {
            issuer,
            key,
            cert_der,
            cert_pem,
            not_after,
        })
    }

    /// Loads a persisted generation from its certificate and PKCS#8 key in PEM.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, CaError> {
        let key = KeyPair::from_pem(key_pem).map_err(|_| CaError::Parse("private key".into()))?;
        let params = CertificateParams::from_ca_cert_pem(cert_pem)
            .map_err(|e| CaError::Parse(e.to_string()))?;
        let not_after = params.not_after;
        let der = rustls_pki_pem_cert(cert_pem)?;
        let issuer = params.self_signed(&key)?;
        // The certificate must belong to the key.
        if issuer_spki(&der).as_deref() != Some(rcgen::PublicKeyData::der_bytes(&key)) {
            return Err(CaError::Parse("certificate does not match the key".into()));
        }
        Ok(Self {
            issuer,
            key,
            cert_der: der,
            cert_pem: cert_pem.to_owned(),
            not_after,
        })
    }

    /// The CA certificate in PEM, for trust installation.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The CA certificate in DER.
    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }

    /// The private key in PKCS#8 PEM, wiped on drop. Only for persisting the CA where agents
    /// cannot read it; never log or send it.
    pub fn key_pem(&self) -> Zeroizing<String> {
        Zeroizing::new(self.key.serialize_pem())
    }

    /// When the CA certificate expires.
    pub fn not_after(&self) -> OffsetDateTime {
        self.not_after
    }

    /// Issues a cross certificate: `newer`'s name and key, signed by `self`.
    fn cross_sign(&self, newer: &CertificateAuthority) -> Result<CertificateDer<'static>, CaError> {
        let mut p = CertificateParams::default();
        p.distinguished_name = newer.issuer.params().distinguished_name.clone();
        p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        p.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        p.not_before = OffsetDateTime::now_utc() - time::Duration::minutes(5);
        p.not_after = self.not_after.min(newer.not_after);
        p.serial_number = Some(random_serial()?);
        // Chain builders that match issuers by key identifier (OpenSSL, so curl, git, Python and
        // Node) accept the cross certificate as the leaf's issuer only when its subject key
        // identifier is the one the leaf's authority key identifier names: the newer CA's own,
        // which a CA loaded from disk may have computed another way.
        p.key_identifier_method = newer.issuer.params().key_identifier_method.clone();
        p.use_authority_key_identifier_extension = true;
        Ok(p.signed_by(&newer.key, &self.issuer, &self.key)?
            .der()
            .clone())
    }

    /// Issues a leaf certificate for `host` valid for `validity` (capped at the CA's expiry).
    fn issue_leaf(
        &self,
        host: &str,
        validity: Duration,
    ) -> Result<
        (
            CertificateDer<'static>,
            PrivateKeyDer<'static>,
            OffsetDateTime,
        ),
        CaError,
    > {
        let now = OffsetDateTime::now_utc();
        let mut p = CertificateParams::default();
        let san = match host.parse::<IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(
                host.to_owned()
                    .try_into()
                    .map_err(|_| CaError::InvalidHost)?,
            ),
        };
        p.subject_alt_names = vec![san];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        p.distinguished_name = dn;
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p.not_before = now - time::Duration::minutes(5);
        p.not_after = (now + validity).min(self.not_after);
        p.serial_number = Some(random_serial()?);
        p.use_authority_key_identifier_extension = true;
        let not_after = p.not_after;
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let cert = p.signed_by(&key, &self.issuer, &self.key)?;
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        Ok((cert.der().clone(), key_der, not_after))
    }
}

fn rustls_pki_pem_cert(pem: &str) -> Result<CertificateDer<'static>, CaError> {
    use rustls::pki_types::pem::PemObject;
    CertificateDer::from_pem_slice(pem.as_bytes()).map_err(|e| CaError::Parse(e.to_string()))
}

/// The `SubjectPublicKeyInfo`'s public key bit string of a certificate, compared against the key.
fn issuer_spki(der: &CertificateDer<'_>) -> Option<Vec<u8>> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    Some(
        cert.tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .to_vec(),
    )
}

/// Settings of the leaf cache.
#[derive(Clone, Debug)]
pub struct LeafSettings {
    /// Validity of issued leaves. Leaves are re-issued when a quarter of it remains.
    pub validity: Duration,
    /// Number of hosts kept. The oldest entry is evicted first.
    pub capacity: usize,
}

impl Default for LeafSettings {
    fn default() -> Self {
        Self {
            validity: Duration::from_hours(168),
            capacity: 4096,
        }
    }
}

struct Previous {
    ca: Arc<CertificateAuthority>,
    cross: CertificateDer<'static>,
    until: OffsetDateTime,
}

struct State {
    generation: u64,
    current: Arc<CertificateAuthority>,
    previous: Option<Previous>,
}

struct CachedLeaf {
    generation: u64,
    key: Arc<CertifiedKey>,
    refresh_at: OffsetDateTime,
}

#[derive(Default)]
struct LeafCache {
    map: HashMap<String, CachedLeaf>,
    order: VecDeque<String>,
}

/// The CA generations in use and the leaf cache.
pub struct CaRing {
    state: RwLock<State>,
    cache: Mutex<LeafCache>,
    settings: LeafSettings,
}

impl std::fmt::Debug for CaRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaRing").finish_non_exhaustive()
    }
}

impl CaRing {
    /// Starts with one generation.
    pub fn new(ca: CertificateAuthority, settings: LeafSettings) -> Self {
        Self {
            state: RwLock::new(State {
                generation: 0,
                current: Arc::new(ca),
                previous: None,
            }),
            cache: Mutex::new(LeafCache::default()),
            settings,
        }
    }

    /// Makes `next` the current generation. The previous one stays trusted through a cross
    /// certificate for `overlap`. Cached leaves are dropped.
    pub fn rotate(&self, next: CertificateAuthority, overlap: Duration) -> Result<(), CaError> {
        let mut st = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cross = st.current.cross_sign(&next)?;
        let until = OffsetDateTime::now_utc() + overlap;
        st.previous = Some(Previous {
            ca: st.current.clone(),
            cross,
            until,
        });
        st.current = Arc::new(next);
        st.generation += 1;
        drop(st);
        self.clear_cache();
        Ok(())
    }

    /// Replaces the generations with `current` and, when given, `previous`, kept trusted
    /// through a cross certificate until the control plane drops it from the snapshot (or it
    /// expires). The control plane holds the CA and sends both in every snapshot; this makes
    /// the ring match them exactly. Cached leaves are dropped.
    pub fn install(
        &self,
        current: CertificateAuthority,
        previous: Option<CertificateAuthority>,
    ) -> Result<(), CaError> {
        let prev = match previous {
            Some(ca) => {
                let cross = ca.cross_sign(&current)?;
                let until = ca.not_after;
                Some(Previous {
                    ca: Arc::new(ca),
                    cross,
                    until,
                })
            }
            None => None,
        };
        let mut st = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        st.current = Arc::new(current);
        st.previous = prev;
        st.generation += 1;
        drop(st);
        self.clear_cache();
        Ok(())
    }

    /// The previous CA certificate in PEM while an overlap lasts.
    pub fn previous_cert_pem(&self) -> Option<String> {
        self.expire_overlap();
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .previous
            .as_ref()
            .map(|p| p.ca.cert_pem().to_owned())
    }

    /// Ends the overlap now: leaves no longer carry the cross certificate.
    pub fn end_overlap(&self) {
        let mut st = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if st.previous.take().is_some() {
            st.generation += 1;
        }
        drop(st);
        self.clear_cache();
    }

    fn clear_cache(&self) {
        let mut c = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        c.map.clear();
        c.order.clear();
    }

    /// The current CA certificate in PEM.
    pub fn current_cert_pem(&self) -> String {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .current
            .cert_pem()
            .to_owned()
    }

    /// The current generation, for persisting its key.
    pub fn current(&self) -> Arc<CertificateAuthority> {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .current
            .clone()
    }

    /// Certificates to install as trusted: the current CA and, during an overlap, the previous.
    pub fn trust_bundle_pem(&self) -> String {
        self.expire_overlap();
        let st = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut s = st.current.cert_pem().to_owned();
        if let Some(p) = &st.previous {
            s.push_str(p.ca.cert_pem());
        }
        s
    }

    fn expire_overlap(&self) {
        let expired = {
            let st = self
                .state
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            st.previous
                .as_ref()
                .is_some_and(|p| p.until <= OffsetDateTime::now_utc())
        };
        if expired {
            self.end_overlap();
        }
    }

    /// A certified key for `host`, from the cache or freshly issued.
    pub fn leaf_for(&self, host: &str) -> Result<Arc<CertifiedKey>, CaError> {
        self.expire_overlap();
        let now = OffsetDateTime::now_utc();
        let (generation, ca, cross) = {
            let st = self
                .state
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (
                st.generation,
                st.current.clone(),
                st.previous.as_ref().map(|p| p.cross.clone()),
            )
        };
        {
            let c = self
                .cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(l) = c.map.get(host)
                && l.generation == generation
                && l.refresh_at > now
            {
                return Ok(l.key.clone());
            }
        }
        let (leaf, key_der, not_after) = ca.issue_leaf(host, self.settings.validity)?;
        let signer = rustls::crypto::ring::sign::any_supported_type(&key_der)
            .map_err(|e| CaError::Generate(e.to_string()))?;
        let mut chain = vec![leaf];
        if let Some(x) = cross {
            chain.push(x);
        }
        let ck = Arc::new(CertifiedKey::new(chain, signer));
        let remaining = not_after - now;
        let refresh_at = now + remaining * 3 / 4;
        let mut c = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if c.map
            .insert(
                host.to_owned(),
                CachedLeaf {
                    generation,
                    key: ck.clone(),
                    refresh_at,
                },
            )
            .is_none()
        {
            c.order.push_back(host.to_owned());
        }
        while c.map.len() > self.settings.capacity.max(1) {
            let Some(old) = c.order.pop_front() else {
                break;
            };
            c.map.remove(&old);
        }
        Ok(ck)
    }

    /// Number of cached leaves.
    pub fn cached_leaves(&self) -> usize {
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .map
            .len()
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
    #[test]
    fn install_matches_the_control_plane() {
        let a = CertificateAuthority::generate(&CaOptions::default()).unwrap();
        let b = CertificateAuthority::generate(&CaOptions::default()).unwrap();
        let (a_cert, a_key) = (a.cert_pem().to_owned(), a.key_pem());
        let b_cert = b.cert_pem().to_owned();
        let ring = CaRing::new(
            CertificateAuthority::generate(&CaOptions::default()).unwrap(),
            LeafSettings::default(),
        );
        ring.install(
            b,
            Some(CertificateAuthority::from_pem(&a_cert, &a_key).unwrap()),
        )
        .unwrap();
        assert_eq!(ring.current_cert_pem(), b_cert);
        assert_eq!(ring.previous_cert_pem().as_deref(), Some(a_cert.as_str()));
        assert!(ring.trust_bundle_pem().contains(&a_cert));
        assert_eq!(ring.leaf_for("api.example.com").unwrap().cert.len(), 2);
        let b2 = CertificateAuthority::from_pem(&b_cert, &ring.current().key_pem()).unwrap();
        ring.install(b2, None).unwrap();
        assert_eq!(ring.previous_cert_pem(), None);
        assert_eq!(ring.leaf_for("api.example.com").unwrap().cert.len(), 1);
    }

    use super::*;

    #[test]
    fn pem_round_trip() {
        let ca = CertificateAuthority::generate(&CaOptions::default()).unwrap();
        let again = CertificateAuthority::from_pem(ca.cert_pem(), &ca.key_pem()).unwrap();
        assert_eq!(again.cert_der(), ca.cert_der());
        let other = CertificateAuthority::generate(&CaOptions::default()).unwrap();
        assert!(CertificateAuthority::from_pem(ca.cert_pem(), &other.key_pem()).is_err());
        assert!(!format!("{ca:?}").contains("PRIVATE"));
    }

    #[test]
    fn leaves_are_cached_and_evicted() {
        let ring = CaRing::new(
            CertificateAuthority::generate(&CaOptions::default()).unwrap(),
            LeafSettings {
                capacity: 2,
                ..Default::default()
            },
        );
        let a = ring.leaf_for("a.test").unwrap();
        assert!(Arc::ptr_eq(&a, &ring.leaf_for("a.test").unwrap()));
        ring.leaf_for("b.test").unwrap();
        ring.leaf_for("c.test").unwrap();
        assert_eq!(ring.cached_leaves(), 2);
        assert!(!Arc::ptr_eq(&a, &ring.leaf_for("a.test").unwrap()));
        ring.leaf_for("127.0.0.1").unwrap();
    }

    /// A CA whose subject key identifier is not the one rcgen computes, as with a CA
    /// certificate the control plane generated and the data plane loads from PEM.
    fn ca_with_key_id(id: u8) -> CertificateAuthority {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut p = ca_params(&CaOptions::default(), OffsetDateTime::now_utc()).unwrap();
        p.key_identifier_method = rcgen::KeyIdMethod::PreSpecified(vec![id; 20]);
        let cert = p.self_signed(&key).unwrap();
        CertificateAuthority::from_pem(&cert.pem(), &key.serialize_pem()).unwrap()
    }

    fn key_ids(der: &[u8]) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        use x509_parser::extensions::ParsedExtension;
        let (_, c) = x509_parser::parse_x509_certificate(der).unwrap();
        let (mut ski, mut aki) = (None, None);
        for ext in c.extensions() {
            match ext.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(k) => ski = Some(k.0.to_vec()),
                ParsedExtension::AuthorityKeyIdentifier(a) => {
                    aki = a.key_identifier.as_ref().map(|k| k.0.to_vec());
                }
                _ => {}
            }
        }
        (ski, aki)
    }

    #[test]
    fn cross_certificate_carries_the_newer_key_identifier() {
        let ring = CaRing::new(ca_with_key_id(0x11), LeafSettings::default());
        ring.rotate(ca_with_key_id(0x22), Duration::from_secs(3600))
            .unwrap();
        let leaf = ring.leaf_for("a.test").unwrap();
        let (_, leaf_aki) = key_ids(&leaf.cert[0]);
        let (cross_ski, cross_aki) = key_ids(&leaf.cert[1]);
        assert_eq!(leaf_aki, Some(vec![0x22; 20]));
        assert_eq!(
            cross_ski, leaf_aki,
            "the cross certificate is the leaf's issuer"
        );
        assert_eq!(cross_aki, Some(vec![0x11; 20]), "the previous CA issued it");
    }

    #[test]
    fn rotation_adds_and_drops_the_cross_certificate() {
        let ring = CaRing::new(
            CertificateAuthority::generate(&CaOptions::default()).unwrap(),
            LeafSettings::default(),
        );
        assert_eq!(ring.leaf_for("a.test").unwrap().cert.len(), 1);
        ring.rotate(
            CertificateAuthority::generate(&CaOptions::default()).unwrap(),
            Duration::from_secs(3600),
        )
        .unwrap();
        assert_eq!(ring.leaf_for("a.test").unwrap().cert.len(), 2);
        assert_eq!(
            ring.trust_bundle_pem().matches("BEGIN CERTIFICATE").count(),
            2
        );
        ring.end_overlap();
        assert_eq!(ring.leaf_for("a.test").unwrap().cert.len(), 1);
        assert_eq!(
            ring.trust_bundle_pem().matches("BEGIN CERTIFICATE").count(),
            1
        );
    }
}
