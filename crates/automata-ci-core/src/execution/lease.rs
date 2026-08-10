//! Exclusive leases and the credentials that fence them.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{AttemptId, CORE_SCHEMA_VERSION, FencingToken, LeaseId, RunnerId, UnixMillis};

/// Short credential carried by every lease-authorized mutation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LeaseGuard {
    lease_id: LeaseId,
    fencing_token: FencingToken,
}

impl LeaseGuard {
    /// Creates a credential from an issued lease identity and fencing token.
    #[must_use]
    pub const fn new(lease_id: LeaseId, fencing_token: FencingToken) -> Self {
        Self {
            lease_id,
            fencing_token,
        }
    }

    /// Returns the exclusive lease identity named by this credential.
    #[must_use]
    pub const fn lease_id(self) -> LeaseId {
        self.lease_id
    }

    /// Returns the lease generation named by this credential.
    #[must_use]
    pub const fn fencing_token(self) -> FencingToken {
        self.fencing_token
    }
}

/// Exclusive, expiring assignment of an attempt to a runner.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Lease {
    schema_version: u16,
    #[serde(rename = "lease_id")]
    id: LeaseId,
    attempt_id: AttemptId,
    runner_id: RunnerId,
    fencing_token: FencingToken,
    issued_at: UnixMillis,
    expires_at: UnixMillis,
}

impl Lease {
    /// Creates a lease after checking its time interval.
    ///
    /// # Errors
    ///
    /// Returns [`LeaseError::InvalidInterval`] unless expiration is strictly
    /// after issuance.
    pub fn new(
        lease_id: LeaseId,
        attempt_id: AttemptId,
        runner_id: RunnerId,
        fencing_token: FencingToken,
        issued_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, LeaseError> {
        if expires_at <= issued_at {
            return Err(LeaseError::InvalidInterval {
                issued_at,
                expires_at,
            });
        }
        Ok(Self {
            schema_version: CORE_SCHEMA_VERSION,
            id: lease_id,
            attempt_id,
            runner_id,
            fencing_token,
            issued_at,
            expires_at,
        })
    }

    /// Validates a lease deserialized from a durable boundary.
    ///
    /// # Errors
    ///
    /// Returns [`LeaseError`] for an unsupported schema or invalid time interval.
    pub fn validate(&self) -> Result<(), LeaseError> {
        if self.schema_version != CORE_SCHEMA_VERSION {
            return Err(LeaseError::UnsupportedSchema {
                supported: CORE_SCHEMA_VERSION,
                received: self.schema_version,
            });
        }
        if self.expires_at <= self.issued_at {
            return Err(LeaseError::InvalidInterval {
                issued_at: self.issued_at,
                expires_at: self.expires_at,
            });
        }
        Ok(())
    }

    /// Returns the lease schema encoded by this value.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Returns this lease's durable identity.
    #[must_use]
    pub const fn lease_id(&self) -> LeaseId {
        self.id
    }

    /// Returns the attempt exclusively assigned by this lease.
    #[must_use]
    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    /// Returns the runner authorized to execute the attempt.
    #[must_use]
    pub const fn runner_id(&self) -> RunnerId {
        self.runner_id
    }

    /// Returns the monotonic generation that fences prior leases.
    #[must_use]
    pub const fn fencing_token(&self) -> FencingToken {
        self.fencing_token
    }

    /// Returns the trusted clock instant at which this lease was issued.
    #[must_use]
    pub const fn issued_at(&self) -> UnixMillis {
        self.issued_at
    }

    /// Returns the trusted clock instant after which this lease is expired.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }

    /// Returns the exact credential required to mutate this attempt.
    #[must_use]
    pub const fn guard(&self) -> LeaseGuard {
        LeaseGuard::new(self.id, self.fencing_token)
    }

    /// Whether this lease is already expired at the supplied clock value.
    #[must_use]
    pub const fn is_expired_at(&self, now: UnixMillis) -> bool {
        now.get() >= self.expires_at.get()
    }

    pub(super) fn renew(&mut self, expires_at: UnixMillis) -> Result<(), LeaseError> {
        if expires_at <= self.expires_at {
            return Err(LeaseError::RenewalDoesNotExtend {
                current: self.expires_at,
                received: expires_at,
            });
        }
        self.expires_at = expires_at;
        Ok(())
    }
}

/// Lease construction/validation errors.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LeaseError {
    /// The lease uses a schema this build cannot interpret safely.
    #[error("unsupported lease schema {received}; this build supports {supported}")]
    UnsupportedSchema {
        /// Schema understood by this build.
        supported: u16,
        /// Schema carried by the lease.
        received: u16,
    },
    /// Expiration is not strictly later than issuance.
    #[error("lease expiration {expires_at:?} must be after issuance {issued_at:?}")]
    InvalidInterval {
        /// Trusted issuance instant.
        issued_at: UnixMillis,
        /// Supplied expiration instant.
        expires_at: UnixMillis,
    },
    /// A renewal does not move expiration strictly forward.
    #[error("lease renewal must extend expiration beyond {current:?}; received {received:?}")]
    RenewalDoesNotExtend {
        /// Current lease expiration.
        current: UnixMillis,
        /// Supplied replacement expiration.
        received: UnixMillis,
    },
}
