// SPDX-License-Identifier: AGPL-3.0-only

//! Seam for the request engine: provider codecs, redactor, guard, restorer
//! and credential injector. Listeners hand each request to the engine, which
//! reads the snapshot in force with one atomic load and never waits on the
//! control plane except through [`Engine::ask`].

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use scrim_proto::v1;

use crate::asks::{Answer, Broker};
use crate::events::Bus;
use crate::snapshot::Applied;

/// Shared state between the control-plane service and the traffic path.
#[derive(Debug, Default)]
pub struct Shared {
    /// The snapshot in force, swapped atomically on apply.
    pub snapshot: ArcSwapOption<Applied>,
    /// Outgoing events.
    pub events: Bus,
    /// Outgoing asks.
    pub asks: Broker,
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

    /// The snapshot in force, or `None` before the first apply. A request
    /// that finds `None` is refused: nothing is forwarded without a
    /// dictionary.
    pub fn snapshot(&self) -> Option<Arc<Applied>> {
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
