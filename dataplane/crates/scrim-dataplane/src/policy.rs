// SPDX-License-Identifier: AGPL-3.0-only

//! Restore and injection decisions (design D5, D7).
//!
//! The decision-table evaluator (`scrim-policy`, tasks 9.1 and 9.2) is not part of this build
//! yet. Until it is, the data plane runs a conservative stand-in, reported in Status as
//! [`ENGINE`]:
//!
//! - Display values are restored only into plain text the agent shows (assistant text). Tool
//!   arguments keep every placeholder, whatever the tool, so nothing restored can reach a shell,
//!   a file or the network.
//! - Credentials are never restored; they reach their hosts only through injection at the tool
//!   proxy, which enforces each credential's host, method, path and location binding.
//! - The rule table (`Policy.table`) is not evaluated, so no request is sent to the control
//!   plane as an ask; an operation that would need one is refused.
//! - Break-glass deny-all (`Policy.break_glass`) keeps every placeholder and injects nothing,
//!   while redaction continues.

use scrim_llm::{RestoreDecision, RestorePolicy, RestoreSite, SecretRef, ToolMode, ValueClass};
use scrim_proto::v1;

/// The decision engine this build runs, reported as `StatusResponse.policy_engine`.
pub const ENGINE: &str = "standin/v1";

/// The decisions taken under one snapshot's policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decisions {
    break_glass: bool,
}

impl Decisions {
    /// Decisions for `policy`.
    pub fn new(policy: &v1::Policy) -> Self {
        Self {
            break_glass: policy.break_glass,
        }
    }

    /// Whether break-glass deny-all is engaged: no restore, no injection, no ask.
    pub fn break_glass(&self) -> bool {
        self.break_glass
    }

    /// Whether a credential may be injected at all under this policy. The tool proxy still
    /// checks each credential's binding per request.
    pub fn injection_allowed(&self) -> bool {
        !self.break_glass
    }

    /// The restore policy the LLM proxy applies to responses.
    pub fn restore_policy(&self) -> StandInRestore {
        StandInRestore {
            break_glass: self.break_glass,
        }
    }
}

/// The stand-in restore policy: display values in text only, nothing in tool arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StandInRestore {
    break_glass: bool,
}

impl RestorePolicy for StandInRestore {
    fn decide(
        &self,
        site: &RestoreSite<'_>,
        _reference: &SecretRef,
        class: ValueClass,
    ) -> RestoreDecision {
        match (self.break_glass, site, class) {
            (false, RestoreSite::Text, ValueClass::Display) => RestoreDecision::Resolve,
            _ => RestoreDecision::Keep,
        }
    }

    fn tool_mode(&self, _tool: &str) -> ToolMode {
        // Nothing is restored into tool arguments, so there is nothing to buffer for.
        ToolMode::Stream
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(break_glass: bool) -> v1::Policy {
        v1::Policy {
            break_glass,
            ..Default::default()
        }
    }

    #[test]
    fn display_in_text_only() {
        let r = Decisions::new(&policy(false)).restore_policy();
        let reference = SecretRef::new("bao://kv/a#b");
        let tool = RestoreSite::ToolInput {
            tool: "Bash",
            arguments: None,
        };
        assert_eq!(
            r.decide(&RestoreSite::Text, &reference, ValueClass::Display),
            RestoreDecision::Resolve
        );
        assert_eq!(
            r.decide(&RestoreSite::Text, &reference, ValueClass::Credential),
            RestoreDecision::Keep
        );
        assert_eq!(
            r.decide(&tool, &reference, ValueClass::Display),
            RestoreDecision::Keep
        );
        assert_eq!(
            r.decide(&tool, &reference, ValueClass::Credential),
            RestoreDecision::Keep
        );
    }

    #[test]
    fn break_glass_keeps_everything() {
        let d = Decisions::new(&policy(true));
        assert!(d.break_glass() && !d.injection_allowed());
        assert_eq!(
            d.restore_policy().decide(
                &RestoreSite::Text,
                &SecretRef::new("x"),
                ValueClass::Display
            ),
            RestoreDecision::Keep
        );
        assert!(Decisions::new(&policy(false)).injection_allowed());
    }
}
