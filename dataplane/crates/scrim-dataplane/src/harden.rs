// SPDX-License-Identifier: AGPL-3.0-only

//! Process hardening applied before any secret is received (design D11):
//! no core dumps, no ptrace attach by other processes of the same user
//! (Linux), and locked memory so values are not swapped out. None of it is
//! available on Windows: there the data plane reports memory unlocked and the
//! process dumpable, and [`MlockMode::Require`] refuses to start.

use std::fmt;

#[cfg(unix)]
use rustix::process::{Resource, Rlimit};

/// What to do about locking memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlockMode {
    /// Lock memory when the memlock limit is unlimited, warn otherwise.
    Auto,
    /// Refuse to start unless memory is locked.
    Require,
    /// Do not lock memory.
    Off,
}

/// The hardening that is in effect.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Hardening {
    /// `mlockall` succeeded.
    pub memory_locked: bool,
    /// Core dumps or ptrace attach are still possible.
    pub dumpable: bool,
}

/// Why hardening refused to start.
#[derive(Debug)]
pub struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// Applies the hardening. Only [`MlockMode::Require`] can fail; everything
/// else degrades with a warning.
#[cfg(unix)]
pub fn apply(mode: MlockMode) -> Result<Hardening, Error> {
    let mut h = Hardening {
        memory_locked: false,
        dumpable: true,
    };

    let no_core = rustix::process::setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    );
    if let Err(err) = no_core {
        tracing::warn!(%err, "could not disable core dumps");
    }
    h.dumpable = !disable_dumpable() || no_core.is_err();

    if mode != MlockMode::Off {
        match lock_memory() {
            Ok(()) => h.memory_locked = true,
            Err(reason) if mode == MlockMode::Require => {
                return Err(Error(format!("memory locking is required but {reason}")));
            }
            Err(reason) => tracing::warn!(
                reason = reason.as_str(),
                "memory is not locked; secret values may be swapped to disk"
            ),
        }
    }
    Ok(h)
}

/// Applies the hardening. Windows has none of it: [`MlockMode::Require`]
/// refuses to start, the other modes start with one warning.
#[cfg(not(unix))]
pub fn apply(mode: MlockMode) -> Result<Hardening, Error> {
    if mode == MlockMode::Require {
        return Err(Error(
            "memory locking is required but it is not available on Windows; set SCRIM_DP_MLOCK \
             to auto or off"
                .to_owned(),
        ));
    }
    tracing::warn!(
        "memory locking and core dump suppression are not available on Windows; secret values \
         may be swapped to disk or written to crash dumps"
    );
    Ok(Hardening {
        memory_locked: false,
        dumpable: true,
    })
}

#[cfg(target_os = "linux")]
fn disable_dumpable() -> bool {
    match rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable) {
        Ok(()) => true,
        Err(err) => {
            tracing::warn!(%err, "could not mark the process non-dumpable");
            false
        }
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn disable_dumpable() -> bool {
    // Only core dumps are disabled (RLIMIT_CORE); ptrace attach is not.
    false
}

/// Locks current and future pages. Locking with `MCL_FUTURE` under a finite
/// memlock limit makes later allocations fail once the limit is reached, so
/// it is only attempted when the limit is unlimited (for example
/// `LimitMEMLOCK=infinity` in a systemd unit, or `CAP_IPC_LOCK`).
#[cfg(target_os = "linux")]
fn lock_memory() -> Result<(), String> {
    use rustix::mm::MlockAllFlags;
    let limit = rustix::process::getrlimit(Resource::Memlock);
    if let Some(max) = limit.current {
        return Err(format!(
            "the memlock limit is {max} bytes; raise it to unlimited (LimitMEMLOCK=infinity)"
        ));
    }
    rustix::mm::mlockall(MlockAllFlags::CURRENT | MlockAllFlags::FUTURE)
        .map_err(|err| format!("mlockall failed: {err}"))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn lock_memory() -> Result<(), String> {
    Err("memory locking is only implemented on Linux".to_owned())
}

// rlimits, prctl and mlockall are Unix only.
#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn off_never_fails_and_disables_core_dumps() {
        let h = apply(MlockMode::Off).ok();
        assert_eq!(h.map(|h| h.memory_locked), Some(false));
        assert_eq!(rustix::process::getrlimit(Resource::Core).current, Some(0));
        #[cfg(target_os = "linux")]
        assert_eq!(h.map(|h| h.dumpable), Some(false));
    }

    #[test]
    fn require_fails_under_a_finite_limit() {
        if rustix::process::getrlimit(Resource::Memlock)
            .current
            .is_some()
        {
            assert!(apply(MlockMode::Require).is_err());
        }
    }
}

#[cfg(all(test, not(unix)))]
mod tests {
    use super::*;

    #[test]
    fn require_refuses_naming_windows() {
        let err = apply(MlockMode::Require).err().map(|e| e.to_string());
        assert!(err.is_some_and(|e| e.contains("Windows")));
    }

    #[test]
    fn auto_and_off_start_unhardened() {
        let want = Hardening {
            memory_locked: false,
            dumpable: true,
        };
        assert_eq!(apply(MlockMode::Auto).ok(), Some(want));
        assert_eq!(apply(MlockMode::Off).ok(), Some(want));
    }
}
