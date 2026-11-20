// SPDX-License-Identifier: AGPL-3.0-only

//! Seam for the listeners (design D8): base URL, Unix socket, forward proxy,
//! transparent and tool proxy, each feeding [`crate::engine::Engine`].
//!
//! No listener kind is implemented yet, so every configured listener reports
//! itself unbound and the data plane is not ready while any is configured.
//! That is the fail-closed answer: nothing is served that cannot be
//! redacted.

use scrim_proto::v1;

/// The status of each configured listener.
pub fn status(listeners: &[v1::Listener]) -> Vec<v1::ListenerStatus> {
    listeners
        .iter()
        .map(|l| v1::ListenerStatus {
            name: l.name.clone(),
            address: l.address.clone(),
            bound: false,
            error: format!(
                "listener kind {} is not implemented yet",
                l.kind().as_str_name()
            ),
        })
        .collect()
}
