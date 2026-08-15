//! Protocol range validation and highest-common-version negotiation.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use automata_ci_core::{JobIrVersion, JobIrVersionRange};

/// Lowest protocol version spoken by this build.
pub const PROTOCOL_MIN_VERSION: ProtocolVersion = ProtocolVersion(2);
/// Highest protocol version spoken by this build.
pub const PROTOCOL_MAX_VERSION: ProtocolVersion = ProtocolVersion(2);
/// Complete supported range for this build.
pub const SUPPORTED_PROTOCOL_RANGE: ProtocolRange = ProtocolRange {
    min: PROTOCOL_MIN_VERSION,
    max: PROTOCOL_MAX_VERSION,
};

/// Positive, monotonically assigned wire protocol version.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ProtocolVersion(u16);

impl ProtocolVersion {
    /// Validates a non-zero wire protocol version.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolRangeError::ZeroVersion`] for the reserved zero value.
    pub const fn new(value: u16) -> Result<Self, ProtocolRangeError> {
        if value == 0 {
            Err(ProtocolRangeError::ZeroVersion)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the numeric version.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Inclusive minimum/maximum versions supported by one peer.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProtocolRange {
    min: ProtocolVersion,
    max: ProtocolVersion,
}

impl ProtocolRange {
    /// Creates an ordered inclusive range.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolRangeError::Inverted`] when `min` exceeds `max`.
    pub const fn new(
        min: ProtocolVersion,
        max: ProtocolVersion,
    ) -> Result<Self, ProtocolRangeError> {
        if min.0 > max.0 {
            Err(ProtocolRangeError::Inverted { min, max })
        } else {
            Ok(Self { min, max })
        }
    }

    #[must_use]
    /// Returns the inclusive lower endpoint.
    pub const fn min(self) -> ProtocolVersion {
        self.min
    }

    #[must_use]
    /// Returns the inclusive upper endpoint.
    pub const fn max(self) -> ProtocolVersion {
        self.max
    }

    /// Checks invariants after deserialization.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolRangeError`] when either endpoint is zero or the range
    /// is inverted.
    pub const fn validate(self) -> Result<(), ProtocolRangeError> {
        if self.min.0 == 0 || self.max.0 == 0 {
            Err(ProtocolRangeError::ZeroVersion)
        } else if self.min.0 > self.max.0 {
            Err(ProtocolRangeError::Inverted {
                min: self.min,
                max: self.max,
            })
        } else {
            Ok(())
        }
    }

    /// Whether an individual version is inside this inclusive range.
    #[must_use]
    pub const fn contains(self, version: ProtocolVersion) -> bool {
        version.0 >= self.min.0 && version.0 <= self.max.0
    }
}

/// Negotiates the highest common version so newer semantics are preferred.
///
/// # Errors
///
/// Returns [`ProtocolNegotiationError`] when either range is invalid or the
/// peers have no version in common.
pub const fn negotiate_protocol(
    local: ProtocolRange,
    remote: ProtocolRange,
) -> Result<ProtocolVersion, ProtocolNegotiationError> {
    if local.min.0 == 0 || local.max.0 == 0 {
        return Err(ProtocolNegotiationError::InvalidLocalRange);
    }
    if remote.min.0 == 0 || remote.max.0 == 0 {
        return Err(ProtocolNegotiationError::InvalidRemoteRange);
    }
    if local.min.0 > local.max.0 {
        return Err(ProtocolNegotiationError::InvalidLocalRange);
    }
    if remote.min.0 > remote.max.0 {
        return Err(ProtocolNegotiationError::InvalidRemoteRange);
    }

    let common_min = if local.min.0 > remote.min.0 {
        local.min
    } else {
        remote.min
    };
    let common_max = if local.max.0 < remote.max.0 {
        local.max
    } else {
        remote.max
    };
    if common_min.0 <= common_max.0 {
        Ok(common_max)
    } else {
        Err(ProtocolNegotiationError::NoCommonVersion { local, remote })
    }
}

/// Negotiates the newest `JobIR` schema accepted by both peers.
///
/// # Errors
///
/// Returns [`JobIrNegotiationError::NoCommonVersion`] when the inclusive
/// ranges do not overlap.
pub fn negotiate_job_ir(
    local: JobIrVersionRange,
    remote: JobIrVersionRange,
) -> Result<JobIrVersion, JobIrNegotiationError> {
    let common_min = local.minimum().max(remote.minimum());
    let common_max = local.maximum().min(remote.maximum());
    if common_min <= common_max {
        Ok(common_max)
    } else {
        Err(JobIrNegotiationError::NoCommonVersion { local, remote })
    }
}

/// Invalid protocol range.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProtocolRangeError {
    /// Protocol version zero was supplied even though it is reserved.
    #[error("protocol version zero is reserved and invalid")]
    ZeroVersion,
    /// The lower endpoint exceeds the upper endpoint.
    #[error("protocol range minimum {min:?} is greater than maximum {max:?}")]
    Inverted {
        /// Invalid inclusive lower endpoint.
        min: ProtocolVersion,
        /// Invalid inclusive upper endpoint.
        max: ProtocolVersion,
    },
}

/// Failed peer negotiation with enough data for a typed handshake error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProtocolNegotiationError {
    /// The local range is zero-valued or inverted.
    #[error("local protocol range is invalid")]
    InvalidLocalRange,
    /// The remote range is zero-valued or inverted.
    #[error("remote protocol range is invalid")]
    InvalidRemoteRange,
    /// The valid peer ranges do not overlap.
    #[error("no common protocol version between local {local:?} and remote {remote:?}")]
    NoCommonVersion {
        /// Versions supported by the negotiating process.
        local: ProtocolRange,
        /// Versions advertised by its peer.
        remote: ProtocolRange,
    },
}

/// Failed `JobIR` schema negotiation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum JobIrNegotiationError {
    /// The peers have no mutually supported `JobIR` schema.
    #[error("no common JobIR schema version between local {local:?} and remote {remote:?}")]
    NoCommonVersion {
        /// `JobIR` schemas supported by the negotiating process.
        local: JobIrVersionRange,
        /// `JobIR` schemas advertised by its peer.
        remote: JobIrVersionRange,
    },
}
