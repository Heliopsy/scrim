// SPDX-License-Identifier: AGPL-3.0-only

//! From a control-plane [`v1::Snapshot`] to everything the traffic path reads.
//!
//! [`build`] validates the message and derives, from one value dictionary and one keyring:
//!
//! - the redaction core ([`scrim_redact::Snapshot`]): redactor, guard and resolver;
//! - the decisions ([`crate::policy::Decisions`]): the decision table from `policy` and the
//!   restore engine from `restore` and the dictionary's metadata;
//! - the LLM proxy's engine snapshot (the core behind `scrim-llm`'s engine traits, with the
//!   decisions as its request gate and restore policy) and its route table;
//! - the tool proxy's snapshot: credentials with their bindings and generated placeholders, the
//!   core as its response redactor and the decisions as its injection policy;
//! - [`Applied`], the metadata the service reports (no secret bytes).
//!
//! Building is the expensive part (up to about a second for 10,000 values) and runs off the
//! request path; nothing is published until every part has built, so a rejected snapshot leaves
//! the one in force untouched. Secret bytes are copied out of the message only into types that
//! wipe themselves, and the message itself zeroes its secret fields when it drops.

use std::fmt;
use std::sync::Arc;

use scrim_llm::auth::AuthConfig;
use scrim_llm::config::{ChainConfig, OnUnavailable, Provider, RouteConfig, default_routes};
use scrim_llm::core::CoreEngine;
use scrim_llm::route::RouteTable;
use scrim_llm::{BinaryPolicy, SecretRef};
use scrim_proto::v1;
use scrim_redact as rc;

use crate::policy::{self, Decisions, Hooks};

/// Shortest value matched in free text when the snapshot does not say
/// (`RedactionSettings.min_value_length` unset).
pub const DEFAULT_MIN_VALUE_LENGTH: u32 = 8;

/// How a value may be restored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// Injected toward bound hosts only.
    Credential,
    /// Restorable under the restore policy.
    Display,
}

/// One dictionary entry's metadata. The value itself lives only in the redaction core and the
/// tool proxy's credential set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Value {
    /// Store reference, safe to log.
    pub reference: String,
    /// Placeholder slug in force (the snapshot's slug, or one derived from the name or
    /// reference when that is not a valid slug).
    pub slug: String,
    /// Restore class.
    pub class: Class,
    /// Hosts a credential may be injected toward.
    pub bound_hosts: Vec<String>,
    /// Catalog name, if any.
    pub name: String,
    /// Store instance.
    pub store: String,
}

/// A validated snapshot in force.
pub struct Applied {
    /// Snapshot version.
    pub version: u64,
    /// Value dictionary metadata, in snapshot order (entry id `i` is `values[i]`).
    pub values: Vec<Value>,
    /// Version of the key new placeholders use.
    pub current_key: u8,
    /// Compiled policy.
    pub policy: v1::Policy,
    /// Decisions taken under `policy` and the restore settings.
    pub decisions: Arc<Decisions>,
    /// Provider routes as received (empty means the built-in defaults).
    pub routes: Vec<v1::Route>,
    /// Listeners to bind.
    pub listeners: Vec<v1::Listener>,
    /// Shortest value matched in free text.
    pub min_value_length: u32,
    /// The redaction core built from the dictionary.
    pub redaction: Arc<rc::Snapshot>,
}

impl fmt::Debug for Applied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Applied")
            .field("version", &self.version)
            .field("values", &self.values)
            .field("current_key", &self.current_key)
            .field("listeners", &self.listeners)
            .field("redaction", &self.redaction)
            .finish_non_exhaustive()
    }
}

impl Applied {
    /// References whose values are below the redaction floor and so are not protected.
    pub fn unprotected_refs(&self) -> Vec<String> {
        self.redaction
            .report()
            .rejected
            .iter()
            .filter_map(|id| usize::try_from(id.0).ok())
            .filter_map(|i| self.values.get(i))
            .map(|v| v.reference.clone())
            .collect()
    }

    /// The redaction status reported to the control plane.
    pub fn redaction_status(&self) -> v1::RedactionStatus {
        let r = self.redaction.report();
        v1::RedactionStatus {
            engine: engine_name(r.engine).to_owned(),
            patterns: u32::try_from(r.patterns).unwrap_or(u32::MAX),
            short_values: u32::try_from(r.short).unwrap_or(u32::MAX),
            unprotected_refs: self.unprotected_refs(),
            duplicates: u32::try_from(r.duplicates).unwrap_or(u32::MAX),
        }
    }
}

/// The matcher's name in Status.
pub fn engine_name(kind: rc::EngineKind) -> &'static str {
    match kind {
        rc::EngineKind::AhoCorasick => "aho-corasick",
        rc::EngineKind::HashWindow => "hash-window",
    }
}

/// Everything one snapshot publishes, built and not yet in force.
pub struct Built {
    /// The metadata and redaction core.
    pub applied: Applied,
    /// The LLM proxy's engine snapshot, routes included.
    pub llm: scrim_llm::Snapshot,
    /// The tool proxy's snapshot, not yet compiled.
    pub tool_proxy: scrim_toolproxy::Snapshot,
}

impl fmt::Debug for Built {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Built")
            .field("applied", &self.applied)
            .finish_non_exhaustive()
    }
}

/// Why a snapshot was rejected. Messages name fields and references, never values.
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

fn invalid(why: impl Into<String>) -> Rejected {
    Rejected::Invalid(why.into())
}

/// Validates `snap` against the version in force and builds every part. On error nothing is
/// published and `snap`'s secret bytes are zeroed when it drops. `hooks` are where the
/// decisions send asks and events.
pub fn build(mut snap: v1::Snapshot, applied: u64, hooks: &Hooks) -> Result<Built, Rejected> {
    if snap.version <= applied {
        return Err(Rejected::Stale {
            offered: snap.version,
            applied,
        });
    }
    let mut policy = snap.policy.take().unwrap_or_default();
    policy::normalise(&mut policy);
    check_entries(&snap)?;
    let routes = route_table(&snap)?;
    let keyring = Arc::new(keyring(&snap.placeholder_keys, !snap.values.is_empty())?);
    let min_value_length = match snap.redaction.as_ref().map(|r| r.min_value_length) {
        None | Some(0) => DEFAULT_MIN_VALUE_LENGTH,
        Some(n) => n.max(4),
    };

    // The redaction core. Entry id i is the i-th value of the snapshot.
    let slugs: Vec<rc::RefSlug> = snap.values.iter().map(slug_of).collect();
    let decisions = Arc::new(
        Decisions::new(
            snap.version,
            &policy,
            snap.restore.as_ref(),
            value_index(&snap.values, &slugs, snap.value_labels),
            hooks.clone(),
        )
        .map_err(|e| invalid(e.to_string()))?,
    );
    let entries = snap
        .values
        .iter()
        .zip(&slugs)
        .enumerate()
        .map(|(i, (v, slug))| {
            rc::Entry::new(
                i as u64,
                slug.clone(),
                core_class(v.class()),
                rc::SecretValue::from_slice(&v.value),
            )
            .with_shape(v.placeholder_format == "shape")
        })
        .collect();
    let config = rc::Config {
        min_len: usize::try_from(min_value_length).unwrap_or(usize::MAX),
        ..rc::Config::default()
    };
    let core = Arc::new(
        rc::Snapshot::build(entries, Arc::clone(&keyring), &config)
            .map_err(|e| invalid(format!("redaction: {e}")))?,
    );

    let bound_hosts: Vec<Vec<String>> = snap.values.iter().map(|v| v.bound_hosts.clone()).collect();
    let tool_proxy = tool_proxy_snapshot(&mut snap, &keyring, &core, &decisions)?;

    // The LLM proxy's engine.
    let engine = CoreEngine::new(
        Arc::clone(&core),
        snap.values
            .iter()
            .enumerate()
            .map(|(i, v)| (rc::EntryId(i as u64), SecretRef::new(v.r#ref.as_str()))),
    );
    // The snapshot-wide policy is for an unknown caller; the gate binds it to each request's.
    let mut llm = engine.snapshot(
        snap.version,
        Arc::new(decisions.restore_policy(scrim_policy::Caller::default())),
        BinaryPolicy::Pass,
    );
    llm.routes = Some(Arc::new(routes));
    llm.gate = Some(decisions.llm_gate());

    let values = snap
        .values
        .iter_mut()
        .zip(slugs)
        .zip(bound_hosts)
        .map(|((v, slug), bound_hosts)| Value {
            reference: std::mem::take(&mut v.r#ref),
            slug: slug.as_str().to_owned(),
            class: match core_class(v.class()) {
                rc::ValueClass::Credential => Class::Credential,
                rc::ValueClass::Display => Class::Display,
            },
            bound_hosts,
            name: std::mem::take(&mut v.name),
            store: std::mem::take(&mut v.store),
        })
        .collect();
    let applied = Applied {
        version: snap.version,
        values,
        current_key: keyring.current().version(),
        policy,
        decisions,
        routes: std::mem::take(&mut snap.routes),
        listeners: std::mem::take(&mut snap.listeners),
        min_value_length,
        redaction: core,
    };
    Ok(Built {
        applied,
        llm,
        tool_proxy,
    })
}

/// The LLM proxy's routes. Routes that authenticate themselves take their credentials from the
/// snapshot's values, by exact reference. The first entry for a reference is its current value:
/// the control plane lists a store's current values before the retained ones of a rotation.
fn route_table(snap: &v1::Snapshot) -> Result<RouteTable, Rejected> {
    RouteTable::with_credentials(&route_configs(&snap.routes)?, &|r| {
        snap.values
            .iter()
            .find(|v| v.r#ref == r && !v.value.is_empty())
            .map(|v| scrim_llm::SecretValue::new(v.value.clone()))
    })
    .map_err(|e| invalid(format!("routes: {e}")))
}

/// Every listener has a kind and an address, every value bytes.
fn check_entries(snap: &v1::Snapshot) -> Result<(), Rejected> {
    for l in &snap.listeners {
        if l.kind() == v1::ListenerKind::Unspecified || l.address.is_empty() {
            return Err(invalid(format!(
                "listener {:?} needs a kind and address",
                l.name
            )));
        }
    }
    for v in &snap.values {
        if v.value.is_empty() {
            return Err(invalid(format!("value for {} is empty", v.r#ref)));
        }
    }
    Ok(())
}

/// The tool proxy's snapshot: credentials with generated placeholders (current key first), the
/// core as response redactor, the decisions as injection policy. Under break-glass no
/// credential keeps a binding either, so none is injected; the caller keeps the original
/// bindings for status.
fn tool_proxy_snapshot(
    snap: &mut v1::Snapshot,
    keyring: &rc::Keyring,
    core: &Arc<rc::Snapshot>,
    decisions: &Arc<Decisions>,
) -> Result<scrim_toolproxy::Snapshot, Rejected> {
    if decisions.break_glass() {
        for v in &mut snap.values {
            v.bound_hosts.clear();
        }
    }
    let mut tool_proxy = scrim_toolproxy::Snapshot::from_proto(snap, |e| {
        let slug = slug_of(e);
        // Format-preserving placeholders first (current key first), as the redaction core shows
        // them, then the bracket forms, which keep resolving.
        let shaped: Option<Vec<String>> = (e.placeholder_format == "shape"
            && core_class(e.class()) == rc::ValueClass::Credential)
            .then(|| {
                keyring
                    .keys()
                    .map(|k| rc::shaped_placeholder_for(k, &slug, &e.value))
                    .collect()
            })
            .flatten();
        let mut out: Vec<String> = Vec::new();
        for p in shaped.into_iter().flatten().chain(
            keyring
                .keys()
                .map(|k| rc::placeholder_for(k, &slug, &e.value)),
        ) {
            // Keys with equal bytes derive one shaped placeholder; list it once.
            if !out.contains(&p) {
                out.push(p);
            }
        }
        out
    })
    .map_err(|e| invalid(format!("tool proxy: {e}")))?;
    let handle = Arc::new(rc::SnapshotHandle::new());
    handle.store(Arc::clone(core));
    tool_proxy.redactor = Some(Arc::new(scrim_toolproxy::CoreRedactor::new(handle)));
    tool_proxy.injection = Some(decisions.injection_policy());
    Ok(tool_proxy)
}

/// The restore engine's value index: entry `i` is `values[i]`, with the slug the redaction core
/// uses for it, so placeholders map back to their entries by position and slug.
fn value_index(
    values: &[v1::ValueEntry],
    slugs: &[rc::RefSlug],
    value_labels: bool,
) -> scrim_policy::ValueIndex {
    let mut ix = scrim_policy::ValueIndex::new();
    let mut labels = scrim_policy::LabelInterner::default();
    for (e, slug) in values.iter().zip(slugs) {
        ix.push(scrim_policy::ValueInfo {
            reference: e.r#ref.as_str().into(),
            slug: slug.as_str().into(),
            class: scrim_policy::ValueClass::from_proto(e.class),
            name: e.name.as_str().into(),
            store: e.store.as_str().into(),
            traits: scrim_policy::escape::ValueTraits::of(&e.value),
            labels: labels.labels(&e.labels, value_labels),
        });
    }
    ix
}

fn core_class(c: v1::ValueClass) -> rc::ValueClass {
    match c {
        v1::ValueClass::Display => rc::ValueClass::Display,
        v1::ValueClass::Credential | v1::ValueClass::Unspecified => rc::ValueClass::Credential,
    }
}

/// The placeholder slug of an entry: its own slug when valid, otherwise one derived from the
/// slug, name or reference (in that order). Deterministic, so every replica agrees.
pub fn slug_of(e: &v1::ValueEntry) -> rc::RefSlug {
    rc::RefSlug::new(&e.slug).unwrap_or_else(|_| {
        let alias = [&e.slug, &e.name, &e.r#ref]
            .into_iter()
            .find(|s| !s.is_empty())
            .map_or("", String::as_str);
        rc::RefSlug::from_alias(alias)
    })
}

/// The keyring from the snapshot's keys. Without keys and without values an ephemeral random
/// key stands in: detector placeholders still need one, and nothing has to resolve across
/// processes.
fn keyring(keys: &[v1::PlaceholderKey], have_values: bool) -> Result<rc::Keyring, Rejected> {
    let mut current = None;
    let mut older = Vec::new();
    for k in keys {
        let version = u8::try_from(k.version)
            .ok()
            .filter(|v| *v > 0)
            .ok_or_else(|| {
                invalid(format!(
                    "placeholder key version {} is outside 1 to 255",
                    k.version
                ))
            })?;
        let key = rc::PlaceholderKey::new(version, &k.key)
            .map_err(|e| invalid(format!("placeholder key {version}: {e}")))?;
        if k.current {
            if current.is_some() {
                return Err(invalid("more than one current placeholder key"));
            }
            current = Some(key);
        } else {
            older.push(key);
        }
    }
    let current = match current {
        Some(c) => c,
        None if have_values => return Err(invalid("values without a current placeholder key")),
        None => ephemeral_key(&older)?,
    };
    older
        .into_iter()
        .try_fold(rc::Keyring::new(current), |ring, k| {
            ring.retain(k)
                .map_err(|e| invalid(format!("placeholder keys: {e}")))
        })
}

fn ephemeral_key(taken: &[rc::PlaceholderKey]) -> Result<rc::PlaceholderKey, Rejected> {
    let version = (1..=u8::MAX)
        .rev()
        .find(|v| taken.iter().all(|k| k.version() != *v))
        .ok_or_else(|| invalid("no free placeholder key version"))?;
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    // The OS generator on every platform (getrandom(2) on Linux,
    // getentropy(2) on macOS); it retries interrupted calls itself.
    getrandom::fill(key.as_mut_slice())
        .map_err(|e| invalid(format!("no randomness for a placeholder key: {e}")))?;
    rc::PlaceholderKey::new(version, key.as_slice())
        .map_err(|e| invalid(format!("placeholder key: {e}")))
}

/// The LLM proxy's routes: the snapshot's, or the built-in Anthropic, `OpenAI` and Gemini routes
/// when it has none.
fn route_configs(routes: &[v1::Route]) -> Result<Vec<RouteConfig>, Rejected> {
    if routes.is_empty() {
        return Ok(default_routes());
    }
    routes
        .iter()
        .map(|r| {
            if r.name.is_empty() || r.upstream.is_empty() {
                return Err(invalid("every route needs a name and an upstream"));
            }
            let provider = match r.provider.to_ascii_lowercase().as_str() {
                "anthropic" => Provider::Anthropic,
                "openai" => Provider::Openai,
                "gemini" => Provider::Gemini,
                "bedrock" => Provider::Bedrock,
                other => {
                    return Err(invalid(format!(
                        "route {}: provider {other:?} is not supported by this data plane",
                        r.name
                    )));
                }
            };
            let prefix = if r.path_prefix.is_empty() {
                format!("/{}", r.name)
            } else {
                r.path_prefix.clone()
            };
            let chain = r
                .chain
                .as_ref()
                .filter(|c| !c.url.is_empty())
                .map(|c| ChainConfig {
                    url: c.url.clone(),
                    on_unavailable: if c.direct_on_unavailable {
                        OnUnavailable::Direct
                    } else {
                        OnUnavailable::Fail
                    },
                });
            Ok(RouteConfig {
                name: r.name.clone(),
                prefix,
                upstream: r.upstream.clone(),
                provider,
                strip_prefix: true,
                chain,
                hosts: r.hosts.clone(),
                auth: r
                    .auth
                    .as_ref()
                    .map(|a| route_auth(&r.name, a))
                    .transpose()?,
            })
        })
        .collect()
}

/// A route's authentication: references only, values are looked up when the table is built.
fn route_auth(route: &str, a: &v1::RouteAuth) -> Result<AuthConfig, Rejected> {
    let opt = |s: &str| (!s.is_empty()).then(|| s.to_owned());
    match &a.kind {
        Some(v1::route_auth::Kind::AwsSigv4(k)) => Ok(AuthConfig::AwsSigv4 {
            region: k.region.clone(),
            service: k.service.clone(),
            access_key_id: k.access_key_id_ref.clone(),
            secret_access_key: k.secret_access_key_ref.clone(),
            session_token: opt(&k.session_token_ref),
        }),
        Some(v1::route_auth::Kind::Header(h)) => Ok(AuthConfig::Header {
            name: h.name.clone(),
            prefix: h.prefix.clone(),
            value: h.value_ref.clone(),
        }),
        None => Err(invalid(format!(
            "route {route}: auth names no kind this data plane supports"
        ))),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const VALUE: &[u8] = b"runtime-made-value-for-tests";

    fn entry(value: &[u8]) -> v1::ValueEntry {
        let mut e = v1::ValueEntry::default();
        e.r#ref = "bao://kv/a#token".into();
        e.slug = "a-token".into();
        e.value = value.to_vec();
        e.bound_hosts = vec!["api.example.test".into()];
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
            protocol: v1::PROTOCOL,
            version,
            values: vec![entry(VALUE)],
            placeholder_keys: vec![key(1, false), key(2, true)],
            ..Default::default()
        }
    }

    fn ok(s: v1::Snapshot) -> Built {
        match build(s, 0, &Hooks::default()) {
            Ok(b) => b,
            Err(e) => panic!("rejected: {e}"),
        }
    }

    #[test]
    fn shaped_entries_get_the_same_placeholder_in_the_core_and_the_tool_proxy() {
        // Generated-looking test token, not a real one.
        const TOKEN: &[u8] = b"ghp_TeStV4lu3N0tR34l0123456789abcdefABCD";
        let mut s = snap(1);
        s.values[0] = entry(TOKEN);
        s.values[0].placeholder_format = "shape".into();
        let b = ok(s);
        let k = rc::PlaceholderKey::new(2, &[9; 32]).unwrap();
        let shaped =
            rc::shaped_placeholder_for(&k, &rc::RefSlug::new("a-token").unwrap(), TOKEN).unwrap();
        assert!(shaped.starts_with("ghp_") && shaped.len() == TOKEN.len());
        let mut redacted = Vec::new();
        b.applied
            .redaction
            .redactor()
            .redact(TOKEN, &mut redacted)
            .unwrap();
        assert_eq!(redacted, shaped.as_bytes());
        let creds = b.tool_proxy.credentials.credentials();
        assert_eq!(creds[0].placeholders[0].text, shaped);
        // The bracket forms keep resolving.
        assert!(
            creds[0]
                .placeholders
                .iter()
                .any(|p| p.text.starts_with('\u{27e6}'))
        );
    }

    #[test]
    fn builds_every_part_from_one_dictionary() {
        let b = ok(snap(1));
        let a = &b.applied;
        assert_eq!(a.current_key, 2);
        assert_eq!(a.values[0].class, Class::Credential);
        assert_eq!(a.redaction.report().values, 1);
        let out = format!("{b:?}");
        assert!(!out.contains("runtime-made-value"), "{out}");

        // The tool proxy injects the same placeholder the core redacts to.
        let k = rc::PlaceholderKey::new(2, &[9; 32]).unwrap();
        let expected = rc::placeholder_for(&k, &rc::RefSlug::new("a-token").unwrap(), VALUE);
        let mut redacted = Vec::new();
        a.redaction.redactor().redact(VALUE, &mut redacted).unwrap();
        assert_eq!(redacted, expected.as_bytes());
        let creds = b.tool_proxy.credentials.credentials();
        assert_eq!(creds.len(), 1);
        assert!(creds[0].placeholders.iter().any(|p| p.text == expected));
        assert!(creds[0].binding.is_some());

        // The LLM engine resolves it.
        let r = b.llm.placeholders.resolve(&expected).unwrap();
        assert_eq!(r.reference.as_str(), "bao://kv/a#token");
        assert_eq!(b.llm.version, 1);
    }

    #[test]
    fn break_glass_strips_bindings() {
        let mut s = snap(1);
        s.policy = Some(v1::Policy {
            break_glass: true,
            ..Default::default()
        });
        let b = ok(s);
        assert!(b.tool_proxy.credentials.credentials()[0].binding.is_none());
        assert_eq!(b.applied.values[0].bound_hosts, vec!["api.example.test"]);
    }

    #[test]
    fn short_values_are_reported_not_protected() {
        let mut s = snap(1);
        s.values.push({
            let mut e = entry(b"abc");
            e.r#ref = "env://SHORT".into();
            e.bound_hosts.clear();
            e
        });
        let b = ok(s);
        assert_eq!(b.applied.unprotected_refs(), vec!["env://SHORT"]);
        let st = b.applied.redaction_status();
        assert_eq!(st.unprotected_refs, vec!["env://SHORT"]);
        assert_eq!(st.engine, "aho-corasick");
    }

    #[test]
    fn invalid_slugs_are_derived_and_empty_dictionaries_get_a_key() {
        let mut e = entry(VALUE);
        e.slug = "Not A Slug".into();
        assert_eq!(slug_of(&e).as_str(), "not-a-slug");
        e.slug.clear();
        e.name = "GitHub".into();
        assert_eq!(slug_of(&e).as_str(), "github");
        let b = ok(v1::Snapshot {
            protocol: v1::PROTOCOL,
            version: 1,
            ..Default::default()
        });
        assert_eq!(b.applied.current_key, 255);
    }

    #[test]
    fn routes_from_snapshot_or_defaults() {
        assert_eq!(route_configs(&[]).unwrap(), default_routes());
        let r = route_configs(&[v1::Route {
            name: "claude".into(),
            provider: "Anthropic".into(),
            upstream: "http://127.0.0.1:9".into(),
            hosts: vec!["api.anthropic.com".into()],
            chain: Some(v1::RouteChain {
                url: "http://127.0.0.1:10".into(),
                direct_on_unavailable: true,
            }),
            ..Default::default()
        }])
        .unwrap();
        assert_eq!(r[0].prefix, "/claude");
        assert_eq!(r[0].provider, Provider::Anthropic);
        assert_eq!(
            r[0].chain.as_ref().map(|c| c.on_unavailable),
            Some(OnUnavailable::Direct)
        );
    }

    #[test]
    fn auth_routes_take_credentials_from_the_snapshot() {
        let route = v1::Route {
            name: "bedrock".into(),
            provider: "bedrock".into(),
            upstream: "https://bedrock-runtime.us-east-1.amazonaws.com".into(),
            auth: Some(v1::RouteAuth {
                kind: Some(v1::route_auth::Kind::AwsSigv4(v1::AwsSigV4Auth {
                    region: "us-east-1".into(),
                    service: "bedrock".into(),
                    access_key_id_ref: "bao://kv/aws#id".into(),
                    secret_access_key_ref: "bao://kv/aws#secret".into(),
                    session_token_ref: String::new(),
                })),
            }),
            ..Default::default()
        };
        let r = route_configs(std::slice::from_ref(&route)).unwrap();
        assert_eq!(r[0].provider, Provider::Bedrock);
        assert!(matches!(
            r[0].auth,
            Some(AuthConfig::AwsSigv4 {
                session_token: None,
                ..
            })
        ));
        let mut snap = snap(1);
        snap.values.clear();
        snap.routes = vec![route.clone()];
        for (r, v) in [
            ("bao://kv/aws#id", "AKIDRUNTIME"),
            ("bao://kv/aws#secret", "made-at-runtime-secret"),
        ] {
            let mut e = entry(v.as_bytes());
            e.r#ref = r.into();
            e.slug = r.replace([':', '/', '#'], "-");
            snap.values.push(e);
        }
        let built = ok(snap.clone());
        let table = built.llm.routes.unwrap();
        let auth = table
            .find("/bedrock/model/m/invoke")
            .unwrap()
            .0
            .auth
            .clone()
            .unwrap();
        assert_eq!(auth.missing(), [] as [String; 0]);
        snap.values.pop();
        let built = ok(snap);
        let table = built.llm.routes.unwrap();
        let auth = table
            .find("/bedrock/model/m/invoke")
            .unwrap()
            .0
            .auth
            .clone()
            .unwrap();
        assert_eq!(auth.missing(), ["bao://kv/aws#secret"]);
        let mut bad = route;
        bad.auth = Some(v1::RouteAuth { kind: None });
        assert!(route_configs(&[bad]).is_err());
    }

    #[test]
    fn rejects() {
        assert_eq!(
            build(snap(3), 3, &Hooks::default()).err(),
            Some(Rejected::Stale {
                offered: 3,
                applied: 3
            })
        );
        let reject = |f: &dyn Fn(&mut v1::Snapshot)| {
            let mut s = snap(1);
            f(&mut s);
            match build(s, 0, &Hooks::default()) {
                Err(Rejected::Invalid(why)) => {
                    assert!(!why.contains("runtime-made-value"), "{why}");
                    why
                }
                Err(e) => panic!("unexpected {e:?}"),
                Ok(_) => panic!("accepted"),
            }
        };
        reject(&|s| s.placeholder_keys = vec![key(1, false)]);
        reject(&|s| s.placeholder_keys.push(key(3, true)));
        reject(&|s| s.placeholder_keys = vec![key(300, true)]);
        reject(&|s| s.placeholder_keys[1].key = vec![1; 4]);
        reject(&|s| s.values = vec![entry(b"")]);
        reject(&|s| {
            s.policy = Some(v1::Policy {
                engine: "cel/v1".into(),
                ..Default::default()
            });
        });
        reject(&|s| {
            s.policy = Some(v1::Policy {
                table: vec![v1::TableRule::default()],
                table_format: 2,
                ..Default::default()
            });
        });
        reject(&|s| {
            s.listeners = vec![v1::Listener {
                name: "x".into(),
                ..Default::default()
            }];
        });
        reject(&|s| {
            s.routes = vec![v1::Route {
                name: "c".into(),
                provider: "cohere".into(),
                upstream: "https://c.example".into(),
                ..Default::default()
            }];
        });
        reject(&|s| {
            let mut dup = entry(b"another-runtime-value-1234");
            dup.declared_placeholders = vec!["SCRIM_SAME".into()];
            s.values[0].declared_placeholders = vec!["SCRIM_SAME".into()];
            s.values.push(dup);
        });
        let mut s = snap(1);
        s.policy = Some(v1::Policy {
            table: vec![v1::TableRule::default()],
            table_format: 1,
            ..Default::default()
        });
        assert!(build(s, 0, &Hooks::default()).is_ok());
    }
}
