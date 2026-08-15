//! Product binding for exact job-scoped GitHub repository authority.
//!
//! The durable Store adapter is the sole source of provider installation,
//! repository, manifest, profile, lease, session, and `JobIR` coordinates.
//! This module never selects a default installation and never derives
//! authority from caller-supplied repository names alone.

use std::{collections::BTreeMap, fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_control::runner_control::{
    ControlPortError, JobIrObjectReader, OptionalRuntimeAuthorityIssuer,
    RuntimeAuthorityIssueRequest, verify_job_ir_blob,
};
use automata_ci_core::{JobAuthorityProfile, JobIrVersion, TrustPermissionAuthority};
use automata_ci_credential_github::{
    GithubRepositoryRuntimeAuthorityIssuer, GithubRuntimeAuthorityIdentityResolutionError,
    GithubRuntimeAuthorityIdentityResolver, GithubRuntimeAuthorityRequestResolver,
    GithubRuntimeAuthorityResolutionError, ResolvedGithubRuntimeAuthorityIdentity,
    ResolvedGithubRuntimeAuthorityRequest, github_job_runtime_authority_request,
};
use automata_ci_protocol::{JobRuntimeAuthorities, MAX_CONFIGURABLE_FRAME_BYTES, ProtocolLimits};
use automata_ci_store::{
    GithubJobRuntimeAuthorityExecution, GithubJobRuntimeAuthorityRepository,
    GithubJobRuntimeAuthorityResolution, GithubJobRuntimeAuthorityStoreError, GithubRepositoryName,
    GithubRuntimeAuthorityIdentity,
};
use thiserror::Error;

use automata_ci_credential_github::MAX_GITHUB_SERVER_SERVICE_INSTALLATION_BROKERS;

/// Durable product resolver shared by identity issuance and least-authority minting.
pub(crate) struct GithubJobRuntimeAuthorityResolver {
    repository: Arc<dyn GithubJobRuntimeAuthorityRepository>,
    job_ir_objects: Arc<dyn JobIrObjectReader>,
    protocol_limits: ProtocolLimits,
}

impl GithubJobRuntimeAuthorityResolver {
    /// Binds the exact durable resolver to the immutable control-plane object reader.
    #[must_use]
    pub(crate) fn new(
        repository: Arc<dyn GithubJobRuntimeAuthorityRepository>,
        job_ir_objects: Arc<dyn JobIrObjectReader>,
    ) -> Self {
        let protocol_limits = ProtocolLimits::new(
            MAX_CONFIGURABLE_FRAME_BYTES,
            MAX_CONFIGURABLE_FRAME_BYTES,
            MAX_CONFIGURABLE_FRAME_BYTES,
            MAX_CONFIGURABLE_FRAME_BYTES,
            MAX_CONFIGURABLE_FRAME_BYTES,
        )
        .expect("the protocol absolute ceilings form coherent JobIR limits");
        Self {
            repository,
            job_ir_objects,
            protocol_limits,
        }
    }

    async fn revalidate(
        &self,
        identity: &GithubRuntimeAuthorityIdentity,
    ) -> Result<
        automata_ci_store::GithubJobRuntimeAuthorityEvidence,
        GithubRuntimeAuthorityResolutionError,
    > {
        self.repository
            .revalidate_github_job_runtime_authority(identity)
            .await
            .map_err(|error| request_store_error(&error))
    }
}

impl fmt::Debug for GithubJobRuntimeAuthorityResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubJobRuntimeAuthorityResolver")
            .field("repository", &"[GITHUB JOB AUTHORITY REPOSITORY]")
            .field("job_ir_objects", &self.job_ir_objects)
            .field("protocol_limits", &self.protocol_limits)
            .finish()
    }
}

#[async_trait]
impl GithubRuntimeAuthorityIdentityResolver for GithubJobRuntimeAuthorityResolver {
    async fn resolve_github_runtime_authority_identity(
        &self,
        request: RuntimeAuthorityIssueRequest<'_>,
    ) -> Result<
        Option<ResolvedGithubRuntimeAuthorityIdentity>,
        GithubRuntimeAuthorityIdentityResolutionError,
    > {
        let job = request.job();
        if job.source().provider() != "github" {
            return Ok(None);
        }
        let repository_name = GithubRepositoryName::new(job.source().repository())
            .map_err(|_| GithubRuntimeAuthorityIdentityResolutionError::Inconsistent)?;
        let execution = GithubJobRuntimeAuthorityExecution::new(
            job.workflow_id(),
            repository_name,
            job.job().authority_profile(),
            request.job_ir_metadata().digest(),
            request.lease().clone(),
            request.session(),
            request.slot(),
            request.job_ir_metadata().clone(),
        )
        .map_err(|_| GithubRuntimeAuthorityIdentityResolutionError::Inconsistent)?;
        match self
            .repository
            .resolve_github_job_runtime_authority(&execution)
            .await
            .map_err(|error| identity_store_error(&error))?
        {
            GithubJobRuntimeAuthorityResolution::CredentialFree => Ok(None),
            GithubJobRuntimeAuthorityResolution::Standard(evidence) => {
                if job.job().authority_profile() != JobAuthorityProfile::Standard
                    || evidence.workflow_id() != job.workflow_id()
                    || evidence.job_ir() != request.job_ir_metadata()
                {
                    return Err(GithubRuntimeAuthorityIdentityResolutionError::Inconsistent);
                }
                ResolvedGithubRuntimeAuthorityIdentity::new(request, evidence.into_parts().0)
                    .map(Some)
                    .map_err(|_| GithubRuntimeAuthorityIdentityResolutionError::Inconsistent)
            }
        }
    }
}

#[async_trait]
impl GithubRuntimeAuthorityRequestResolver for GithubJobRuntimeAuthorityResolver {
    async fn resolve_github_runtime_authority_request(
        &self,
        identity: &GithubRuntimeAuthorityIdentity,
    ) -> Result<Option<ResolvedGithubRuntimeAuthorityRequest>, GithubRuntimeAuthorityResolutionError>
    {
        let before = self.revalidate(identity).await?;
        if before.identity() != identity
            || before.job_ir().digest() != identity.policy_digest()
            || before.workflow_id().as_uuid().is_nil()
        {
            return Err(GithubRuntimeAuthorityResolutionError::Inconsistent);
        }
        let bytes = self
            .job_ir_objects
            .read_job_ir(before.job_ir(), before.job_ir().encoded_size())
            .await
            .map_err(job_ir_read_error)?;
        let job = verify_job_ir_blob(
            before.job_ir(),
            &bytes,
            JobIrVersion::current(),
            &self.protocol_limits,
        )
        .map_err(|_| GithubRuntimeAuthorityResolutionError::Inconsistent)?;
        if job.workflow_id() != before.workflow_id()
            || job.job().authority_profile() != JobAuthorityProfile::Standard
            || job.source().provider() != "github"
        {
            return Err(GithubRuntimeAuthorityResolutionError::Inconsistent);
        }
        let credential_request = github_job_runtime_authority_request(identity, &job)
            .map_err(|_| GithubRuntimeAuthorityResolutionError::Inconsistent)?;

        // Revalidate after the immutable object read as well. Although the
        // historical evidence is immutable, the live lease/session/attempt
        // coordinates may have changed while bytes were loaded.
        let after = self.revalidate(identity).await?;
        if after != before {
            return Err(GithubRuntimeAuthorityResolutionError::Inconsistent);
        }
        ResolvedGithubRuntimeAuthorityRequest::new(identity.clone(), credential_request)
            .map(Some)
            .map_err(|_| GithubRuntimeAuthorityResolutionError::Inconsistent)
    }
}

/// Bounded no-default optional issuer for configured GitHub App installations.
pub(crate) struct GithubJobRuntimeAuthorityIssuer {
    identities: Arc<dyn GithubRuntimeAuthorityIdentityResolver>,
    issuers: BTreeMap<u64, Arc<GithubRepositoryRuntimeAuthorityIssuer>>,
}

impl GithubJobRuntimeAuthorityIssuer {
    /// Builds an exact installation router.
    ///
    /// # Errors
    ///
    /// Rejects an empty, oversized, zero, or duplicate route registry.
    pub(crate) fn new(
        identities: Arc<dyn GithubRuntimeAuthorityIdentityResolver>,
        entries: impl IntoIterator<Item = (u64, Arc<GithubRepositoryRuntimeAuthorityIssuer>)>,
    ) -> Result<Self, GithubJobRuntimeAuthorityIssuerError> {
        let mut issuers = BTreeMap::new();
        for (installation_id, issuer) in entries {
            if installation_id == 0 {
                return Err(GithubJobRuntimeAuthorityIssuerError::InvalidInstallationId);
            }
            if issuers.len() >= MAX_GITHUB_SERVER_SERVICE_INSTALLATION_BROKERS {
                return Err(GithubJobRuntimeAuthorityIssuerError::TooManyInstallations);
            }
            if issuers.insert(installation_id, issuer).is_some() {
                return Err(GithubJobRuntimeAuthorityIssuerError::DuplicateInstallationId);
            }
        }
        if issuers.is_empty() {
            return Err(GithubJobRuntimeAuthorityIssuerError::Empty);
        }
        Ok(Self {
            identities,
            issuers,
        })
    }
}

impl fmt::Debug for GithubJobRuntimeAuthorityIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubJobRuntimeAuthorityIssuer")
            .field("identities", &"[DURABLE IDENTITY RESOLVER]")
            .field("installation_ids", &self.issuers.keys().collect::<Vec<_>>())
            .field("issuers", &"[EXACT INSTALLATION ISSUERS]")
            .finish()
    }
}

#[async_trait]
impl OptionalRuntimeAuthorityIssuer for GithubJobRuntimeAuthorityIssuer {
    async fn issue_optional(
        &self,
        request: RuntimeAuthorityIssueRequest<'_>,
    ) -> Result<Option<JobRuntimeAuthorities>, ControlPortError> {
        if request.job().source().provider() != "github" {
            return Ok(None);
        }
        if request
            .job()
            .job()
            .trust_snapshot()
            .authority()
            .permissions()
            == TrustPermissionAuthority::DenyAll
        {
            return Ok(None);
        }
        let resolved = self
            .identities
            .resolve_github_runtime_authority_identity(request)
            .await
            .map_err(identity_control_error)?;
        let Some(resolved) = resolved else {
            return match request.job().job().authority_profile() {
                JobAuthorityProfile::CredentialFree => Ok(None),
                JobAuthorityProfile::Standard => Err(ControlPortError::Corrupt),
            };
        };
        if request.job().job().authority_profile() != JobAuthorityProfile::Standard {
            return Err(ControlPortError::Corrupt);
        }
        let installation_id = resolved.identity().provider_installation_id().get();
        let issuer = self
            .issuers
            .get(&installation_id)
            .ok_or(ControlPortError::Unavailable)?;
        issuer.issue_resolved(request, resolved).await.map(Some)
    }
}

/// Disabled-provider entitlement guard installed even when GitHub is unconfigured.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct UnavailableGithubJobRuntimeAuthorityIssuer;

/// Returns the fail-closed optional issuer installed when GitHub is disabled.
///
/// Non-GitHub and verified `CredentialFree` jobs receive no contribution. A
/// GitHub `Standard` job remains entitled to repository authority and therefore
/// receives `Unavailable` instead of silently running without it.
#[must_use]
pub(crate) fn unavailable_github_job_runtime_authority_issuer()
-> Arc<dyn OptionalRuntimeAuthorityIssuer> {
    Arc::new(UnavailableGithubJobRuntimeAuthorityIssuer)
}

#[async_trait]
impl OptionalRuntimeAuthorityIssuer for UnavailableGithubJobRuntimeAuthorityIssuer {
    async fn issue_optional(
        &self,
        request: RuntimeAuthorityIssueRequest<'_>,
    ) -> Result<Option<JobRuntimeAuthorities>, ControlPortError> {
        if request.job().source().provider() != "github"
            || request.job().job().authority_profile() == JobAuthorityProfile::CredentialFree
            || request
                .job()
                .job()
                .trust_snapshot()
                .authority()
                .permissions()
                == TrustPermissionAuthority::DenyAll
        {
            Ok(None)
        } else {
            Err(ControlPortError::Unavailable)
        }
    }
}

/// Invalid exact installation registry for the optional repository issuer.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum GithubJobRuntimeAuthorityIssuerError {
    /// At least one exact installation is required.
    #[error("the GitHub job runtime-authority issuer registry is empty")]
    Empty,
    /// The registry exceeds the bounded provider-repository limit.
    #[error("the GitHub job runtime-authority issuer registry is too large")]
    TooManyInstallations,
    /// The zero installation sentinel cannot authorize a broker.
    #[error("the GitHub job runtime-authority issuer registry contains an invalid ID")]
    InvalidInstallationId,
    /// Two brokers claim the same exact installation.
    #[error("the GitHub job runtime-authority issuer registry contains a duplicate ID")]
    DuplicateInstallationId,
}

fn identity_store_error(
    error: &GithubJobRuntimeAuthorityStoreError,
) -> GithubRuntimeAuthorityIdentityResolutionError {
    match error {
        GithubJobRuntimeAuthorityStoreError::Operation(_) => {
            GithubRuntimeAuthorityIdentityResolutionError::Unavailable
        }
        GithubJobRuntimeAuthorityStoreError::Unauthorized
        | GithubJobRuntimeAuthorityStoreError::CorruptData => {
            GithubRuntimeAuthorityIdentityResolutionError::Inconsistent
        }
    }
}

fn request_store_error(
    error: &GithubJobRuntimeAuthorityStoreError,
) -> GithubRuntimeAuthorityResolutionError {
    match error {
        GithubJobRuntimeAuthorityStoreError::Operation(_) => {
            GithubRuntimeAuthorityResolutionError::Unavailable
        }
        GithubJobRuntimeAuthorityStoreError::Unauthorized
        | GithubJobRuntimeAuthorityStoreError::CorruptData => {
            GithubRuntimeAuthorityResolutionError::Inconsistent
        }
    }
}

const fn job_ir_read_error(error: ControlPortError) -> GithubRuntimeAuthorityResolutionError {
    match error {
        ControlPortError::Unavailable => GithubRuntimeAuthorityResolutionError::Unavailable,
        ControlPortError::Corrupt | ControlPortError::Conflict => {
            GithubRuntimeAuthorityResolutionError::Inconsistent
        }
    }
}

const fn identity_control_error(
    error: GithubRuntimeAuthorityIdentityResolutionError,
) -> ControlPortError {
    match error {
        GithubRuntimeAuthorityIdentityResolutionError::Unavailable => ControlPortError::Unavailable,
        GithubRuntimeAuthorityIdentityResolutionError::Inconsistent => ControlPortError::Corrupt,
    }
}

#[cfg(test)]
#[path = "github_job_runtime_authority_tests.rs"]
mod tests;
