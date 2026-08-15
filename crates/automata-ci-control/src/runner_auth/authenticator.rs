use std::{fmt, sync::Arc};

use crate::runner_control::{
    AuthorizedRunnerRegistration, ControlPortError, RunnerRegistrationAuthorizer,
};
use async_trait::async_trait;
use automata_ci_auth::{
    machine::{
        AuthenticatedMachine, MachineAuthenticationError, MachineAuthenticationEvidence,
        MachineAuthenticationFuture, MachineIdentityVerifier,
    },
    time::Clock,
};
use automata_ci_core::Sha256Digest;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use super::{
    RunnerMachineAuthLimits, RunnerMachineDirectory, RunnerMachineDirectoryError,
    RunnerMachineRecord,
};

/// Shared, stateless adapter for transport authentication and control-plane
/// registration authorization.
pub struct DurableRunnerMachineAuthenticator {
    directory: Arc<dyn RunnerMachineDirectory>,
    clock: Arc<dyn Clock>,
    limits: RunnerMachineAuthLimits,
}

impl DurableRunnerMachineAuthenticator {
    /// Composes a durable machine directory and trusted clock behind both runner
    /// authentication ports.
    #[must_use]
    pub fn new(
        directory: Arc<dyn RunnerMachineDirectory>,
        clock: Arc<dyn Clock>,
        limits: RunnerMachineAuthLimits,
    ) -> Self {
        Self {
            directory,
            clock,
            limits,
        }
    }

    async fn authenticate_inner(
        &self,
        evidence: &MachineAuthenticationEvidence,
    ) -> Result<AuthenticatedMachine, MachineAuthenticationError> {
        let leaf_sha256 = self.bounded_leaf_sha256(evidence)?;
        let record = self
            .directory
            .find_by_leaf_sha256(leaf_sha256)
            .await
            .map_err(map_authentication_directory_error)?
            .ok_or(MachineAuthenticationError::Untrusted)?;
        if !digest_matches(leaf_sha256, &record) {
            return Err(MachineAuthenticationError::Untrusted);
        }
        let authenticated_at = self.clock.now();
        if authenticated_at.as_seconds() == 0 {
            return Err(MachineAuthenticationError::Unavailable);
        }
        if record.certificate_expires_at() <= authenticated_at {
            return Err(MachineAuthenticationError::Expired);
        }
        AuthenticatedMachine::new(
            record.external_identity().clone(),
            leaf_sha256.into_bytes(),
            authenticated_at,
            record.certificate_expires_at(),
        )
        .map_err(|_| MachineAuthenticationError::Expired)
    }

    fn bounded_leaf_sha256(
        &self,
        evidence: &MachineAuthenticationEvidence,
    ) -> Result<Sha256Digest, MachineAuthenticationError> {
        let chain = evidence.certificate_chain_der();
        if chain.is_empty() || chain.len() > self.limits.maximum_chain_certificates() {
            return Err(MachineAuthenticationError::Untrusted);
        }
        let mut aggregate_bytes = 0_usize;
        for certificate in chain {
            if certificate.is_empty() || certificate.len() > self.limits.maximum_certificate_bytes()
            {
                return Err(MachineAuthenticationError::Untrusted);
            }
            aggregate_bytes = aggregate_bytes
                .checked_add(certificate.len())
                .ok_or(MachineAuthenticationError::Untrusted)?;
            if aggregate_bytes > self.limits.maximum_chain_bytes() {
                return Err(MachineAuthenticationError::Untrusted);
            }
        }
        let leaf = chain.first().ok_or(MachineAuthenticationError::Untrusted)?;
        Ok(Sha256Digest::from_bytes(Sha256::digest(leaf).into()))
    }
}

impl MachineIdentityVerifier for DurableRunnerMachineAuthenticator {
    fn authenticate<'a>(
        &'a self,
        evidence: &'a MachineAuthenticationEvidence,
    ) -> MachineAuthenticationFuture<'a> {
        Box::pin(async move { self.authenticate_inner(evidence).await })
    }
}

#[async_trait]
impl RunnerRegistrationAuthorizer for DurableRunnerMachineAuthenticator {
    async fn authorize(
        &self,
        machine: &AuthenticatedMachine,
    ) -> Result<Option<AuthorizedRunnerRegistration>, ControlPortError> {
        let authenticated_digest = Sha256Digest::from_bytes(*machine.certificate_sha256());
        let Some(record) = self
            .directory
            .find_by_leaf_sha256(authenticated_digest)
            .await
            .map_err(map_control_directory_error)?
        else {
            return Ok(None);
        };
        if machine.external_identity() != record.external_identity()
            || !digest_matches(authenticated_digest, &record)
            || machine.certificate_expires_at() != record.certificate_expires_at()
        {
            return Ok(None);
        }
        let now = self.clock.now();
        if now.as_seconds() == 0 || now < machine.authenticated_at() {
            return Err(ControlPortError::Unavailable);
        }
        if record.certificate_expires_at() <= now {
            return Ok(None);
        }
        Ok(Some(AuthorizedRunnerRegistration::new(
            record.external_identity().clone(),
            record.runner_id(),
            record.generation(),
            record.certificate_sha256().into_bytes(),
            record.desired_state(),
        )))
    }
}

impl fmt::Debug for DurableRunnerMachineAuthenticator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableRunnerMachineAuthenticator")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

fn digest_matches(expected: Sha256Digest, record: &RunnerMachineRecord) -> bool {
    bool::from(
        expected
            .as_bytes()
            .ct_eq(record.certificate_sha256().as_bytes()),
    )
}

const fn map_authentication_directory_error(
    _error: RunnerMachineDirectoryError,
) -> MachineAuthenticationError {
    MachineAuthenticationError::Unavailable
}

const fn map_control_directory_error(error: RunnerMachineDirectoryError) -> ControlPortError {
    match error {
        RunnerMachineDirectoryError::Unavailable => ControlPortError::Unavailable,
        RunnerMachineDirectoryError::Corrupt => ControlPortError::Corrupt,
    }
}
