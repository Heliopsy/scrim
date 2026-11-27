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
use crate::scopes::Scopes;

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
    /// Narrower redaction for the sessions of `redaction_scopes`.
    pub redaction_scopes: Arc<Scopes>,
    /// The client certificates TLS listeners accept, when the snapshot has any.
    pub client_trust: Option<Arc<crate::mtls::ClientTrust>>,
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
    let client_trust = client_trust(&snap)?;
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
    let config = rc::Config {
        min_len: usize::try_from(min_value_length).unwrap_or(usize::MAX),
        detectors: detector_config(snap.redaction.as_ref()),
        guard_cache_entries: if snap.redaction.as_ref().is_some_and(|r| r.guard_cache_off) {
            0
        } else {
            rc::Config::default().guard_cache_entries
        },
        transforms: transform_config(snap.redaction.as_ref())?,
        ..rc::Config::default()
    };
    let core = Arc::new(
        rc::Snapshot::build(
            core_entries(&snap.values, &slugs, |_| true),
            Arc::clone(&keyring),
            &config,
        )
        .map_err(|e| invalid(format!("redaction: {e}")))?,
    );
    let scopes = redaction_scopes(
        &mut snap,
        &slugs,
        &keyring,
        &config,
        decisions.break_glass(),
    )?;

    let bound_hosts: Vec<Vec<String>> = snap.values.iter().map(|v| v.bound_hosts.clone()).collect();
    let tool_proxy = tool_proxy_snapshot(&mut snap, &keyring, &core, &decisions)?;

    // The LLM proxy's engine.
    let engine = CoreEngine::new(Arc::clone(&core), entry_refs(&snap.values));
    // The snapshot-wide policy is for an unknown caller; the gate binds it to each request's.
    let mut llm = engine.snapshot(
        snap.version,
        Arc::new(decisions.restore_policy(scrim_policy::Caller::default())),
        binary_policy(snap.redaction.as_ref()),
    );
    llm.routes = Some(Arc::new(routes));
    llm.gate = Some(decisions.llm_gate_scoped(Arc::clone(&scopes)));

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
        redaction_scopes: scopes,
        client_trust,
    };
    Ok(Built {
        applied,
        llm,
        tool_proxy,
    })
}

/// The fallback detector settings of `redaction.detectors.*`. Unset fields keep the defaults.
fn detector_config(r: Option<&v1::RedactionSettings>) -> rc::DetectorConfig {
    let mut d = rc::DetectorConfig::default();
    if let Some(r) = r {
        d.rules_enabled = !r.detectors_off;
        d.disabled_rules.clone_from(&r.detectors_disabled);
        d.enabled_rules.clone_from(&r.detectors_enabled);
        d.encoded = r.detectors_encoded;
        d.entropy = r.entropy.as_ref().filter(|e| e.enabled).map(entropy_config);
    }
    d
}

/// The guard's transform decoders (`redaction.guard.enable` and `.disable`). Unset keeps the
/// defaults; an unknown name rejects the snapshot.
/// The guard's cross-request memory, one per process: every snapshot gets it, so pieces a
/// session sent before a change to the redaction set (a session token added or revoked, a value
/// refreshed) still join with the pieces it sends after.
static CROSS_MEMORY: std::sync::LazyLock<Arc<rc::CrossMemory>> =
    std::sync::LazyLock::new(|| Arc::new(rc::CrossMemory::new()));

fn transform_config(r: Option<&v1::RedactionSettings>) -> Result<rc::TransformConfig, Rejected> {
    let mut t = rc::TransformConfig {
        memory: Some(Arc::clone(&CROSS_MEMORY)),
        ..rc::TransformConfig::default()
    };
    if let Some(r) = r {
        for (names, on) in [(&r.guard_disabled, false), (&r.guard_enabled, true)] {
            for n in names {
                if !t.set(n, on) {
                    return Err(invalid(format!("unknown guard transform {n:?}")));
                }
            }
        }
    }
    Ok(t)
}

/// `redaction.detectors.entropy.*`; zero fields keep the context's defaults.
fn entropy_config(e: &v1::EntropySettings) -> rc::EntropyConfig {
    let mut c = if e.any_context {
        rc::EntropyConfig::any_context()
    } else {
        rc::EntropyConfig::default()
    };
    if e.threshold_bits > 0.0 {
        c.threshold_bits = e.threshold_bits;
    }
    if e.min_length > 0 {
        c.min_len = e.min_length as usize;
    }
    if e.max_length > 0 {
        c.max_len = e.max_length as usize;
    }
    if e.min_classes > 0 {
        c.min_classes = u8::try_from(e.min_classes).unwrap_or(u8::MAX);
    }
    c
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

/// The client certificate trust. A listener with `tls` set needs one, and only kinds that serve
/// HTTP to agents can have it: anything else would serve without the identity it asked for.
fn client_trust(snap: &v1::Snapshot) -> Result<Option<Arc<crate::mtls::ClientTrust>>, Rejected> {
    for l in snap.listeners.iter().filter(|l| l.tls) {
        if !matches!(
            l.kind(),
            v1::ListenerKind::BaseUrl
                | v1::ListenerKind::ForwardProxy
                | v1::ListenerKind::ToolProxy
        ) {
            return Err(invalid(format!(
                "listener {:?}: tls is only for BASE_URL, FORWARD_PROXY and TOOL_PROXY listeners",
                l.name
            )));
        }
    }
    match &snap.client_certificates {
        Some(t) => crate::mtls::ClientTrust::from_proto(t)
            .map(|t| Some(Arc::new(t)))
            .map_err(invalid),
        None if snap.listeners.iter().any(|l| l.tls) => Err(invalid(
            "a listener has tls set but the snapshot has no client_certificates",
        )),
        None => Ok(None),
    }
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

/// Narrower cores for the sessions of `redaction_scopes`, with the same entry ids as the core, so
/// audit events and restores name the same references. Break-glass drops them with everything
/// else that lets a value through.
fn redaction_scopes(
    snap: &mut v1::Snapshot,
    slugs: &[rc::RefSlug],
    keyring: &Arc<rc::Keyring>,
    config: &rc::Config,
    break_glass: bool,
) -> Result<Arc<Scopes>, Rejected> {
    if break_glass {
        snap.redaction_scopes.clear();
    }
    let scopes = Scopes::build(snap, |exempt| {
        let narrow = rc::Snapshot::build(
            core_entries(&snap.values, slugs, |v| !exempt.contains(v.r#ref.as_str())),
            Arc::clone(keyring),
            config,
        )
        .map_err(|e| invalid(format!("redaction scope: {e}")))?;
        Ok::<_, Rejected>(CoreEngine::new(Arc::new(narrow), entry_refs(&snap.values)).redaction())
    })?;
    if !scopes.is_empty() {
        tracing::info!(
            version = snap.version,
            sessions = scopes.sessions(),
            scopes = ?scopes,
            "redaction narrowed to each agent's own store identity for some sessions \
             (redaction.limit-to-agent-identity, a weakening setting)"
        );
    }
    Ok(Arc::new(scopes))
}

/// The secret reference of each entry id, for audit events.
fn entry_refs(values: &[v1::ValueEntry]) -> impl Iterator<Item = (rc::EntryId, SecretRef)> + '_ {
    values
        .iter()
        .enumerate()
        .map(|(i, v)| (rc::EntryId(i as u64), SecretRef::new(v.r#ref.as_str())))
}

/// The redaction core's entries for the values `keep` accepts. Entry id `i` is the i-th value of
/// the snapshot whichever values are left out.
fn core_entries(
    values: &[v1::ValueEntry],
    slugs: &[rc::RefSlug],
    keep: impl Fn(&v1::ValueEntry) -> bool,
) -> Vec<rc::Entry> {
    values
        .iter()
        .zip(slugs)
        .enumerate()
        .filter(|(_, (v, _))| keep(v))
        .map(|(i, (v, slug))| {
            rc::Entry::new(
                i as u64,
                slug.clone(),
                core_class(v.class()),
                rc::SecretValue::from_slice(&v.value),
            )
            .with_shape(v.placeholder_format == "shape")
        })
        .collect()
}

/// The LLM proxy's binary policy (`redaction.binary`). Unset is `scan`, the safe default.
fn binary_policy(r: Option<&v1::RedactionSettings>) -> BinaryPolicy {
    match r.map_or(v1::BinaryPolicy::Unspecified, v1::RedactionSettings::binary) {
        v1::BinaryPolicy::Scan | v1::BinaryPolicy::Unspecified => BinaryPolicy::Scan,
        v1::BinaryPolicy::Block => BinaryPolicy::Block,
        v1::BinaryPolicy::Pass => BinaryPolicy::Pass,
    }
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
                "vertex" => Provider::Vertex,
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
        Some(v1::route_auth::Kind::GoogleServiceAccount(g)) => {
            Ok(AuthConfig::GoogleServiceAccount {
                key: g.key_ref.clone(),
                token_url: g.token_url.clone(),
                scope: g.scope.clone(),
            })
        }
        Some(v1::route_auth::Kind::GoogleMetadata(g)) => Ok(AuthConfig::GoogleMetadata {
            url: g.url.clone(),
            scope: g.scope.clone(),
        }),
        Some(v1::route_auth::Kind::EntraClientSecret(e)) => Ok(AuthConfig::EntraClientSecret {
            token_url: e.token_url.clone(),
            client_id: e.client_id.clone(),
            client_secret: e.client_secret_ref.clone(),
            scope: e.scope.clone(),
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
    use crate::identity::Identity;
    use crate::scopes;

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
    fn binary_policy_from_snapshot() {
        assert_eq!(ok(snap(1)).llm.binary, BinaryPolicy::Scan, "unset is scan");
        for (p, want) in [
            (v1::BinaryPolicy::Unspecified, BinaryPolicy::Scan),
            (v1::BinaryPolicy::Scan, BinaryPolicy::Scan),
            (v1::BinaryPolicy::Block, BinaryPolicy::Block),
            (v1::BinaryPolicy::Pass, BinaryPolicy::Pass),
        ] {
            let mut s = snap(1);
            let mut r = v1::RedactionSettings::default();
            r.set_binary(p);
            s.redaction = Some(r);
            assert_eq!(ok(s).llm.binary, want, "{p:?}");
        }
    }

    /// A session token as the control plane mints it, with a generated secret part.
    fn session_token(id: &str) -> String {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).unwrap();
        let secret: String = b
            .iter()
            .flat_map(|x| [b'a' + (x >> 4), b'A' + (x & 15)])
            .take(43)
            .map(char::from)
            .collect();
        format!("scrim_st_{id}_{secret}")
    }

    fn session_entry(token: &str, store: &str, reference: &str) -> v1::ValueEntry {
        let mut e = v1::ValueEntry::default();
        e.r#ref = reference.into();
        e.store = store.into();
        e.slug = "scrim-sessions-credential".into();
        e.value = token.as_bytes().to_vec();
        e
    }

    fn redacts(r: &scrim_llm::ScopedRedaction, value: &[u8]) -> bool {
        let mut out = Vec::new();
        r.redactor.redact(value, &mut out).unwrap();
        !out.windows(value.len()).any(|w| w == value)
    }

    fn guard_sees(r: &scrim_llm::ScopedRedaction, value: &[u8]) -> bool {
        !matches!(
            r.guard.check(value).unwrap(),
            scrim_llm::GuardVerdict::Clean
        )
    }

    /// A redaction scope leaves its exempt references out of both the redactor and the guard,
    /// for a request that carries the session's token and for nobody else: not a bare session
    /// id, not a token of the same id with another secret, not a token that only appears in an
    /// ordinary store, not another session.
    #[test]
    fn redaction_scope_applies_only_to_a_proven_session() {
        // Shares no run with VALUE: the guard also finds fragments of a value.
        const OTHER: &[u8] = b"Zk82Lmq0PxW4vNa7HbR3";
        let (sa, sb) = ("abcdefghijklmnop", "qrstuvwxyzabcd23");
        let (ta, tb) = (session_token(sa), session_token(sb));
        let forged = session_token(sa);
        let planted = session_token("plantedsession23");
        let mut s = snap(1);
        let mut other = entry(OTHER);
        other.r#ref = "bao://kv/agents/a#token".into();
        other.slug = "agents-a".into();
        s.values.push(other);
        s.values.push(session_entry(
            &ta,
            scopes::SESSION_STORE,
            scopes::SESSION_REF,
        ));
        s.values.push(session_entry(
            &tb,
            scopes::SESSION_STORE,
            scopes::SESSION_REF,
        ));
        // A token-shaped value an agent wrote into an ordinary store proves nothing.
        s.values
            .push(session_entry(&planted, "bao", "bao://kv/inbox/x#token"));
        s.redaction_scopes = vec![
            v1::RedactionScope {
                agent: "agent-a".into(),
                sessions: vec![sa.into(), "plantedsession23".into()],
                exempt_refs: vec!["bao://kv/a#token".into()],
            },
            // A scope without exemptions is dropped.
            v1::RedactionScope {
                agent: "agent-b".into(),
                sessions: vec![sb.into()],
                exempt_refs: vec![],
            },
        ];
        // Break-glass drops every scope.
        let mut glass = s.clone();
        glass.policy = Some(v1::Policy {
            break_glass: true,
            ..Default::default()
        });
        assert!(ok(glass).applied.redaction_scopes.is_empty());
        let b = ok(s);
        let scopes = &b.applied.redaction_scopes;
        assert_eq!(scopes.sessions(), 1);
        let caller = |tok: &str| {
            let mut h = http::HeaderMap::new();
            h.insert(scrim_llm::SESSION_HEADER, tok.parse().unwrap());
            Identity::of_llm(&h, &http::Extensions::new())
        };
        let Some(a) = scopes.for_caller(&caller(&ta)) else {
            panic!("session a has no scope");
        };
        assert!(!redacts(&a, VALUE), "the exempt value was redacted");
        assert!(
            !guard_sees(&a, VALUE),
            "the guard still sees the exempt value"
        );
        assert!(redacts(&a, OTHER) && guard_sees(&a, OTHER));
        for (what, who) in [
            ("bare session id", caller(sa)),
            ("forged secret", caller(&forged)),
            ("planted token", caller(&planted)),
            ("session without exemptions", caller(&tb)),
            ("anonymous", Identity::default()),
        ] {
            assert!(scopes.for_caller(&who).is_none(), "{what} got a scope");
        }
        // The snapshot-wide redaction still covers everything.
        let mut out = Vec::new();
        b.applied
            .redaction
            .redactor()
            .redact(VALUE, &mut out)
            .unwrap();
        assert!(!out.windows(VALUE.len()).any(|w| w == VALUE));
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

    /// `redaction.detectors.*` reaches the redaction core: the group switch, a rule switched
    /// off, a rule off by default switched on, and an unknown name rejecting the snapshot.
    fn hex_lower(b: &[u8]) -> String {
        const H: &[u8; 16] = b"0123456789abcdef";
        b.iter()
            .flat_map(|&c| [H[usize::from(c >> 4)], H[usize::from(c & 15)]])
            .map(char::from)
            .collect()
    }

    #[test]
    fn detector_settings_apply() {
        // Built at run time so no token-shaped literal is committed.
        let tok = format!("dop_v1_{}", "0123456789abcdef".repeat(4));
        let assign = "DB_PASSWORD=Xk9#mQ2vL7pR4zT";
        let detects = |r: Option<v1::RedactionSettings>, text: &str| {
            let mut s = snap(1);
            s.redaction = r;
            let b = ok(s);
            let mut out = Vec::new();
            b.applied
                .redaction
                .redactor()
                .redact(text.as_bytes(), &mut out)
                .unwrap();
            out != text.as_bytes()
        };
        assert!(detects(None, &tok));
        assert!(!detects(None, assign));
        let off = v1::RedactionSettings {
            detectors_off: true,
            ..Default::default()
        };
        assert!(!detects(Some(off), &tok));
        let one_off = v1::RedactionSettings {
            detectors_disabled: vec!["digitalocean-token".into()],
            ..Default::default()
        };
        assert!(!detects(Some(one_off), &tok));
        let generic = v1::RedactionSettings {
            detectors_enabled: vec!["generic-secret-assignment".into()],
            ..Default::default()
        };
        assert!(detects(Some(generic), assign));
        // Every snapshot's guard shares one cross-request memory.
        let (a, b) = (
            transform_config(None).unwrap(),
            transform_config(None).unwrap(),
        );
        assert!(Arc::ptr_eq(
            a.memory.as_ref().unwrap(),
            b.memory.as_ref().unwrap()
        ));
        // Guard transforms: unknown names reject the snapshot.
        let mut bad_tx = snap(1);
        bad_tx.redaction = Some(v1::RedactionSettings {
            guard_disabled: vec!["no-such-transform".into()],
            ..Default::default()
        });
        assert!(build(bad_tx, 0, &Hooks::default()).is_err());
        let mut tx = snap(1);
        tx.redaction = Some(v1::RedactionSettings {
            guard_disabled: vec!["confusables".into()],
            guard_enabled: vec!["compressed".into()],
            ..Default::default()
        });
        assert!(build(tx, 0, &Hooks::default()).is_ok());
        // Encoded forms and entropy are opt-in.
        let encoded = format!("token: {}", hex_lower(tok.as_bytes()));
        assert!(!detects(None, &encoded));
        let on = v1::RedactionSettings {
            detectors_encoded: true,
            ..Default::default()
        };
        assert!(detects(Some(on), &encoded));
        let keyed = "SESSION_SECRET=Zq7xR2mK9pLw4TbN8vYc";
        assert!(!detects(None, keyed));
        let entropy = |e: v1::EntropySettings| {
            Some(v1::RedactionSettings {
                entropy: Some(e),
                ..Default::default()
            })
        };
        assert!(detects(
            entropy(v1::EntropySettings {
                enabled: true,
                ..Default::default()
            }),
            keyed
        ));
        // Configured but not enabled, and a threshold no value reaches.
        assert!(!detects(entropy(v1::EntropySettings::default()), keyed));
        assert!(!detects(
            entropy(v1::EntropySettings {
                enabled: true,
                threshold_bits: 7.5,
                ..Default::default()
            }),
            keyed
        ));
        let mut bad = snap(1);
        bad.redaction = Some(v1::RedactionSettings {
            detectors_disabled: vec!["no-such-rule".into()],
            ..Default::default()
        });
        assert!(build(bad, 0, &Hooks::default()).is_err());
    }

    /// `redaction.guard-cache` reaches the guard: on by default, off when the control plane
    /// says so.
    #[test]
    fn guard_cache_setting_applies() {
        let caches = |r: Option<v1::RedactionSettings>| {
            let mut s = snap(1);
            s.redaction = r;
            ok(s).applied.redaction.guard().caches()
        };
        assert!(caches(None));
        assert!(caches(Some(v1::RedactionSettings::default())));
        assert!(!caches(Some(v1::RedactionSettings {
            guard_cache_off: true,
            ..Default::default()
        })));
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
