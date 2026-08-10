//! Strongly typed identifiers used by the domain model.

use std::{fmt, num::NonZeroU32, num::NonZeroU64, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use uuid::Uuid;

macro_rules! uuid_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(
            Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Creates a new random, RFC 9562 version-4 identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            /// Constructs the typed identifier from a UUID.
            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            /// Returns the underlying UUID value.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value).map(Self)
            }
        }
    };
}

uuid_id!(/// Identifies a workflow definition independently of any invocation.
    WorkflowId);
uuid_id!(/// Identifies one workflow run.
    RunId);
uuid_id!(/// Identifies one planned job in a workflow run.
    JobId);
uuid_id!(/// Identifies one execution attempt for a job.
    AttemptId);
uuid_id!(/// Identifies a registered runner.
    RunnerId);
uuid_id!(/// Identifies one authenticated runner connection/session.
    RunnerSessionId);
uuid_id!(/// Identifies one exclusive, fenced assignment of an attempt.
    LeaseId);
uuid_id!(/// Idempotency key for a mutating operation.
    OperationId);
uuid_id!(/// Identifies a durable stream of log frames.
    LogStreamId);

/// One-based attempt number as presented to workflow semantics.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AttemptNumber(NonZeroU32);

impl AttemptNumber {
    /// Creates a valid one-based attempt number.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError::ZeroAttemptNumber`] when `value` is zero.
    pub fn new(value: u32) -> Result<Self, IdentifierError> {
        NonZeroU32::new(value)
            .map(Self)
            .ok_or(IdentifierError::ZeroAttemptNumber)
    }

    /// Returns the numeric attempt number.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// Monotonically increasing token that fences superseded leases.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct FencingToken(NonZeroU64);

impl FencingToken {
    /// Largest value representable by the durable `PostgreSQL` `BIGINT` column.
    pub const MAX: u64 = i64::MAX as u64;

    /// Creates a non-zero fencing token.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError::ZeroFencingToken`] when `value` is zero.
    pub fn new(value: u64) -> Result<Self, IdentifierError> {
        if value > Self::MAX {
            return Err(IdentifierError::FencingTokenOutOfRange);
        }
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(IdentifierError::ZeroFencingToken)
    }

    /// Returns the token's integer representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns the next token, rejecting exhaustion rather than wrapping.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError::FencingTokenExhausted`] at [`Self::MAX`].
    pub fn checked_next(self) -> Result<Self, IdentifierError> {
        let next = self
            .get()
            .checked_add(1)
            .ok_or(IdentifierError::FencingTokenExhausted)?;
        Self::new(next).map_err(|_| IdentifierError::FencingTokenExhausted)
    }
}

impl<'de> Deserialize<'de> for FencingToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Validation errors for compact numeric identifiers.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum IdentifierError {
    /// An attempt number violated its one-based representation.
    #[error("attempt numbers are one-based and cannot be zero")]
    ZeroAttemptNumber,
    /// A fencing token violated its non-zero representation.
    #[error("fencing tokens cannot be zero")]
    ZeroFencingToken,
    /// A fencing token could not be represented in the durable signed column.
    #[error("fencing tokens must fit the durable signed 64-bit representation")]
    FencingTokenOutOfRange,
    /// Incrementing a fencing token would exceed its durable maximum.
    #[error("the durable fencing token counter is exhausted")]
    FencingTokenExhausted,
}
