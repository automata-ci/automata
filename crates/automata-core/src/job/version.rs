//! Independently negotiated `JobIR` schema versions.

use std::num::NonZeroU16;

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use thiserror::Error;

/// Schema version emitted by this build for [`super::JobIrEnvelope`].
pub const JOB_IR_SCHEMA_VERSION: u16 = JobIrVersion::current().get();

/// A positive `JobIR` schema version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct JobIrVersion(NonZeroU16);

impl JobIrVersion {
    /// Creates a positive `JobIR` schema version.
    ///
    /// # Errors
    ///
    /// Returns [`JobIrVersionError::Zero`] when `version` is zero.
    pub fn new(version: u16) -> Result<Self, JobIrVersionError> {
        NonZeroU16::new(version)
            .map(Self)
            .ok_or(JobIrVersionError::Zero)
    }

    /// Returns the `JobIR` schema emitted by this build.
    #[must_use]
    pub const fn current() -> Self {
        match NonZeroU16::new(4) {
            Some(version) => Self(version),
            None => unreachable!(),
        }
    }

    /// Returns the numeric wire representation.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

impl<'de> Deserialize<'de> for JobIrVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let version = u16::deserialize(deserializer)?;
        Self::new(version).map_err(D::Error::custom)
    }
}

/// Inclusive range of `JobIR` schemas accepted by one protocol peer.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(try_from = "UncheckedJobIrVersionRange")]
pub struct JobIrVersionRange {
    minimum: JobIrVersion,
    maximum: JobIrVersion,
}

impl JobIrVersionRange {
    /// Creates an inclusive, ordered version range.
    ///
    /// # Errors
    ///
    /// Returns [`JobIrVersionError::InvertedRange`] when `minimum` is newer
    /// than `maximum`.
    pub fn new(minimum: JobIrVersion, maximum: JobIrVersion) -> Result<Self, JobIrVersionError> {
        if minimum > maximum {
            return Err(JobIrVersionError::InvertedRange { minimum, maximum });
        }
        Ok(Self { minimum, maximum })
    }

    /// Returns the singleton range emitted and accepted by this build.
    #[must_use]
    pub const fn current() -> Self {
        let current = JobIrVersion::current();
        Self {
            minimum: current,
            maximum: current,
        }
    }

    /// Returns the oldest accepted version.
    #[must_use]
    pub const fn minimum(self) -> JobIrVersion {
        self.minimum
    }

    /// Returns the newest accepted version.
    #[must_use]
    pub const fn maximum(self) -> JobIrVersion {
        self.maximum
    }

    /// Reports whether this inclusive range accepts `version`.
    #[must_use]
    pub const fn supports(self, version: JobIrVersion) -> bool {
        version.get() >= self.minimum.get() && version.get() <= self.maximum.get()
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
struct UncheckedJobIrVersionRange {
    minimum: JobIrVersion,
    maximum: JobIrVersion,
}

impl TryFrom<UncheckedJobIrVersionRange> for JobIrVersionRange {
    type Error = JobIrVersionError;

    fn try_from(value: UncheckedJobIrVersionRange) -> Result<Self, Self::Error> {
        Self::new(value.minimum, value.maximum)
    }
}

/// Invalid `JobIR` version or negotiation range.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum JobIrVersionError {
    /// Schema zero is reserved and cannot appear on the wire.
    #[error("JobIR schema versions must be positive")]
    Zero,
    /// An inclusive range cannot run from a newer version to an older one.
    #[error("JobIR version range {minimum:?}..={maximum:?} is inverted")]
    InvertedRange {
        minimum: JobIrVersion,
        maximum: JobIrVersion,
    },
}
