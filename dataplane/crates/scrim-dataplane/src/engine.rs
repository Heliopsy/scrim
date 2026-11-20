// SPDX-License-Identifier: AGPL-3.0-only

//! The request engines and the state they share: the LLM proxy (`scrim-llm`), the HTTPS tool
//! proxy (`scrim-toolproxy`) and the redaction core (`scrim-redact`) both build on, fed from one
//! control-plane snapshot. Listeners hand each request to an engine, which reads the snapshot
//! in force with one atomic load and never waits on the control plane except through
//! [`Engine::ask`].
//!
//! Applying a snapshot ([`Shared::apply`]) builds everything off the request path into one
//! immutable [`Bundle`] (redaction core, LLM engine snapshot with its routes and restore policy,
//! compiled tool-proxy snapshot, policy and metadata) and publishes it with a single atomic swap.
//! Both engines read the bundle in force through a snapshot source, once per request, so a
//! request sees exactly one version. Listeners are reconciled after the swap. Until the first
//! apply there is no listener and every engine refuses (503).

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use scrim_llm::intercept::LlmIntercept;
use scrim_llm::{ProxyConfig, config::TlsConfig};
use scrim_proto::v1;
use scrim_toolproxy::{CompiledSnapshot, ToolProxy, UpstreamSettings};

use crate::asks::{Answer, Broker};
use crate::events::Bus;
use crate::listeners::Listeners;
use crate::settings::Settings;
use crate::snapshot::{self, Applied, Rejected};
use crate::{audit, captures};

/// The engines could not be built.
#[derive(Debug)]
pub struct SetupError(pub String);

impl fmt::Display for SetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "data plane setup failed: {}", self.0)
    }
}

impl std::error::Error for SetupError {}

/// One snapshot version, everything the traffic path reads. Immutable; replaced as a whole.
pub struct Bundle {
    /// Snapshot version.
    pub version: u64,
    /// Metadata, policy and the redaction core.
    pub applied: Applied,
    /// The LLM proxy's engine snapshot (redactor, guard, placeholders, restore policy, routes).
    pub llm: Arc<scrim_llm::Snapshot>,
    /// The tool proxy's compiled snapshot (credentials, bindings, response redactor, capture
    /// rules).
    pub tool_proxy: CompiledSnapshot,
}

impl fmt::Debug for Bundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bundle")
            .field("version", &self.version)
            .field("applied", &self.applied)
            .finish_non_exhaustive()
    }
}

/// The bundle in force, shared with the engines' snapshot sources.
type Current = Arc<ArcSwapOption<Bundle>>;

struct LlmSource(Current);

impl scrim_llm::SnapshotSource for LlmSource {
    fn load(&self) -> Option<Arc<scrim_llm::Snapshot>> {
        self.0.load().as_ref().map(|b| Arc::clone(&b.llm))
    }
}

struct ToolSource(Current);

impl scrim_toolproxy::SnapshotSource for ToolSource {
    fn current(&self) -> Option<CompiledSnapshot> {
        self.0.load().as_ref().map(|b| b.tool_proxy.clone())
    }
}

/// Shared state between the control-plane service and the traffic path.
pub struct Shared {
    /// The bundle in force, swapped once per apply.
    pub snapshot: Current,
    /// Outgoing events.
    pub events: Arc<Bus>,
    /// Outgoing asks.
    pub asks: Broker,
    /// Outgoing captures.
    pub captures: Arc<captures::Broker>,
    /// The HTTPS tool proxy (task 10.2). Provider hosts reached through it go to `llm`.
    pub tool_proxy: ToolProxy,
    /// The LLM proxy behind base-URL listeners and the forward proxy's provider hosts.
    pub llm: Arc<scrim_llm::Proxy>,
    /// Bound listeners.
    pub listeners: Listeners,
    /// Serialises applies, so versions are checked and published in order.
    apply: tokio::sync::Mutex<()>,
}

impl fmt::Debug for Shared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shared")
            .field(
                "snapshot",
                &self.snapshot.load().as_ref().map(|s| s.version),
            )
            .field("listeners", &self.listeners)
            .finish_non_exhaustive()
    }
}

impl Shared {
    /// Builds the shared state with default settings.
    pub fn new() -> Result<Self, SetupError> {
        Self::with_settings(&Settings::default())
    }

    /// Builds the shared state: the LLM proxy with its audit sink on the event bus, and the tool
    /// proxy with its audit and capture sinks wired to the control plane and the LLM proxy as its
    /// handler for provider hosts.
    pub fn with_settings(settings: &Settings) -> Result<Self, SetupError> {
        let events = Arc::new(Bus::default());
        let captures = Arc::new(captures::Broker::default());
        let current: Current = Arc::new(ArcSwapOption::empty());
        let llm_cfg = ProxyConfig {
            tls: TlsConfig {
                extra_ca_file: settings.extra_ca_file.clone(),
                ..TlsConfig::default()
            },
            ..ProxyConfig::default()
        };
        let llm = Arc::new(
            scrim_llm::Proxy::new(
                llm_cfg,
                Arc::new(scrim_llm::SnapshotCell::from_source(Arc::new(LlmSource(
                    Arc::clone(&current),
                )))),
                Arc::new(audit::LlmSink(Arc::clone(&events))),
            )
            .map_err(|e| SetupError(format!("LLM proxy: {e}")))?,
        );
        let upstream = UpstreamSettings {
            extra_roots: settings
                .extra_roots()
                .map_err(|e| SetupError(format!("tool proxy: {e}")))?,
            ..UpstreamSettings::default()
        };
        let tool_proxy = ToolProxy::builder()
            .upstream(upstream)
            .audit(Arc::new(audit::Sink(Arc::clone(&events))))
            .capture_sink(Arc::new(captures::Sink(Arc::clone(&captures))))
            .intercept(Arc::new(LlmIntercept::new(Arc::clone(&llm))))
            .snapshot_source(Arc::new(ToolSource(Arc::clone(&current))))
            .build()
            .map_err(|e| SetupError(e.to_string()))?;
        Ok(Self {
            snapshot: current,
            events,
            asks: Broker::default(),
            captures,
            tool_proxy,
            llm,
            listeners: Listeners::default(),
            apply: tokio::sync::Mutex::new(()),
        })
    }

    /// The version in force, 0 before the first apply.
    pub fn applied_version(&self) -> u64 {
        self.snapshot.load().as_ref().map_or(0, |s| s.version)
    }

    /// Validates, builds and publishes `snap`. Returns the version now in force and the number
    /// of values. On error the snapshot in force stays. Must run inside a tokio runtime.
    pub async fn apply(self: &Arc<Self>, snap: v1::Snapshot) -> Result<(u64, u32), Rejected> {
        let _serial = self.apply.lock().await;
        let in_force = self.applied_version();
        let this = Arc::clone(self);
        // Building the dictionary and compiling the tool proxy's credentials is CPU work of up
        // to about a second: keep it off the runtime's I/O threads.
        let bundle = tokio::task::spawn_blocking(move || {
            let snapshot::Built {
                applied,
                llm,
                tool_proxy,
            } = snapshot::build(snap, in_force)?;
            let tool_proxy = this
                .tool_proxy
                .compile(tool_proxy)
                .map_err(|e| Rejected::Invalid(format!("tool proxy: {e}")))?;
            Ok::<_, Rejected>(Bundle {
                version: applied.version,
                applied,
                llm: Arc::new(llm),
                tool_proxy,
            })
        })
        .await
        .map_err(|_| Rejected::Invalid("snapshot build failed".into()))??;
        let version = bundle.version;
        let count = u32::try_from(bundle.applied.values.len()).unwrap_or(u32::MAX);
        let bundle = Arc::new(bundle);
        // The one swap: from here every new request of every engine reads this version.
        self.snapshot.store(Some(Arc::clone(&bundle)));
        self.listeners.reconcile(&bundle.applied.listeners, self);
        Ok((version, count))
    }

    /// Stops serving: listeners closed, asks and captures denied, the dictionary dropped (and
    /// zeroed) wherever this process can drop it.
    pub fn shutdown(&self) {
        self.listeners.stop_all();
        self.asks.detach();
        self.captures.detach();
        self.snapshot.store(None);
    }
}

/// A handle the traffic path uses. Cheap to clone.
#[derive(Clone, Debug)]
pub struct Engine {
    shared: Arc<Shared>,
}

impl Engine {
    /// Wraps the shared state.
    pub fn new(shared: Arc<Shared>) -> Self {
        Self { shared }
    }

    /// The bundle in force, or `None` before the first apply. A request that finds `None` is
    /// refused: nothing is forwarded without a dictionary.
    pub fn snapshot(&self) -> Option<Arc<Bundle>> {
        self.shared.snapshot.load_full()
    }

    /// Emits an event. It must not contain a value.
    pub fn emit(&self, ev: v1::Event) {
        self.shared.events.emit(ev);
    }

    /// Asks the control plane; denies on timeout or disconnect.
    pub async fn ask(
        &self,
        req: v1::PolicyRequest,
        rule: &str,
        reason: &str,
        timeout: Duration,
    ) -> Answer {
        self.shared.asks.ask(req, rule, reason, timeout).await
    }
}
