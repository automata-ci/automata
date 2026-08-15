use std::fmt;

use async_trait::async_trait;
use automata_ci_auth::{machine::ExternalRunnerIdentity, time::UnixTimestamp};
use automata_ci_core::{RunnerId, Sha256Digest};
use automata_ci_store::RunnerGeneration;
use thiserror::Error;

use crate::runner_control::DesiredRunnerState;

/// One complete, server-owned runner machine registration read atomically from
/// durable state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerMachineRecord {
    external_identity: ExternalRunnerIdentity,
    runner_id: RunnerId,
    generation: RunnerGeneration,
    certificate_sha256: Sha256Digest,
    certificate_expires_at: UnixTimestamp,
    desired_state: DesiredRunnerState,
}

impl RunnerMachineRecord {
    /// Creates a validated durable runner machine record.
    ///
    /// # Errors
    ///
    /// Rejects a nil internal runner ID, an all-zero certificate digest, or an
    /// expiration at the Unix epoch. Other fields are validated by their domain
    /// types before reaching this boundary.
    pub fn new(
        external_identity: ExternalRunnerIdentity,
        runner_id: RunnerId,
        generation: RunnerGeneration,
        certificate_sha256: Sha256Digest,
        certificate_expires_at: UnixTimestamp,
        desired_state: DesiredRunnerState,
    ) -> Result<Self, RunnerMachineRecordError> {
        if runner_id.as_uuid().is_nil() {
            return Err(RunnerMachineRecordError::InvalidRunnerId);
        }
        if certificate_sha256.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(RunnerMachineRecordError::InvalidCertificateDigest);
        }
        if certificate_expires_at.as_seconds() == 0 {
            return Err(RunnerMachineRecordError::InvalidCertificateExpiration);
        }
        Ok(Self {
            external_identity,
            runner_id,
            generation,
            certificate_sha256,
            certificate_expires_at,
            desired_state,
        })
    }

    /// Returns the administrator-owned external machine identity.
    #[must_use]
    pub const fn external_identity(&self) -> &ExternalRunnerIdentity {
        &self.external_identity
    }

    /// Returns the internal durable runner identity.
    #[must_use]
    pub const fn runner_id(&self) -> RunnerId {
        self.runner_id
    }

    /// Returns the current certificate/configuration generation.
    #[must_use]
    pub const fn generation(&self) -> RunnerGeneration {
        self.generation
    }

    /// Returns the exact registered TLS leaf digest.
    #[must_use]
    pub const fn certificate_sha256(&self) -> Sha256Digest {
        self.certificate_sha256
    }

    /// Returns the server-recorded certificate expiration.
    #[must_use]
    pub const fn certificate_expires_at(&self) -> UnixTimestamp {
        self.certificate_expires_at
    }

    /// Returns the current administrator-owned lifecycle state.
    #[must_use]
    pub const fn desired_state(&self) -> DesiredRunnerState {
        self.desired_state
    }
}

/// Invalid data at the durable runner-machine adapter boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RunnerMachineRecordError {
    /// The internal runner UUID is nil.
    #[error("runner machine record contains an invalid runner identity")]
    InvalidRunnerId,
    /// The registered SHA-256 value is an impossible sentinel.
    #[error("runner machine record contains an invalid certificate digest")]
    InvalidCertificateDigest,
    /// The registered expiration is an impossible sentinel.
    #[error("runner machine record contains an invalid certificate expiration")]
    InvalidCertificateExpiration,
}

/// Sanitized failure from shared runner-machine registration state.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RunnerMachineDirectoryError {
    /// Shared durable state could not be read.
    #[error("runner machine directory is unavailable")]
    Unavailable,
    /// Durable data violated a schema or domain invariant.
    #[error("runner machine directory contains corrupt data")]
    Corrupt,
}

/// Narrow shared-state lookup keyed only by the TLS-validated leaf digest.
///
/// Implementations must perform a fresh durable read and return every field from
/// one consistent row or transaction snapshot. They must not accept an external
/// identity, internal runner ID, or runner-supplied value as a lookup authority.
#[async_trait]
pub trait RunnerMachineDirectory: fmt::Debug + Send + Sync {
    /// Finds the exact registered machine for a SHA-256 TLS leaf digest.
    async fn find_by_leaf_sha256(
        &self,
        leaf_sha256: Sha256Digest,
    ) -> Result<Option<RunnerMachineRecord>, RunnerMachineDirectoryError>;
}
