//! Error types. No variant carries a value or any byte of a request.

use std::fmt;

/// Why a request cannot be forwarded. Every variant means: refuse the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No snapshot has been stored in the [`crate::SnapshotHandle`] yet: the known values have
    /// not loaded.
    NotReady,
    /// The input is larger than [`crate::Config::max_input`].
    InputTooLarge,
    /// The guard found a known value it could not repair. The request must be withheld.
    Withheld(WithholdReason),
}

/// Why the guard withheld a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WithholdReason {
    /// A known value was still present after repair.
    RepairIncomplete,
    /// More interventions were needed than [`crate::Config::guard_max_repairs`] allows.
    TooManyInterventions,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotReady => f.write_str("redaction is not ready: known values have not loaded"),
            Self::InputTooLarge => f.write_str("request body exceeds the redaction size limit"),
            Self::Withheld(WithholdReason::RepairIncomplete) => {
                f.write_str("guard withheld the request: a known value could not be repaired")
            }
            Self::Withheld(WithholdReason::TooManyInterventions) => {
                f.write_str("guard withheld the request: too many known values reached the guard")
            }
        }
    }
}

impl std::error::Error for Error {}

/// Why a [`crate::Snapshot`] could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// A slug is outside the placeholder alphabet or too long.
    InvalidSlug,
    /// Two keys in the keyring share a version.
    DuplicateKeyVersion,
    /// Key version 0 is reserved.
    InvalidKeyVersion,
    /// The configuration is inconsistent (for example `short_floor > min_len`).
    InvalidConfig(&'static str),
    /// The pattern automaton could not be built (resource limits).
    Automaton,
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSlug => f.write_str("invalid reference slug"),
            Self::DuplicateKeyVersion => f.write_str("duplicate placeholder key version"),
            Self::InvalidKeyVersion => f.write_str("placeholder key version 0 is reserved"),
            Self::InvalidConfig(why) => write!(f, "invalid redaction config: {why}"),
            Self::Automaton => f.write_str("pattern automaton could not be built"),
        }
    }
}

impl std::error::Error for BuildError {}
