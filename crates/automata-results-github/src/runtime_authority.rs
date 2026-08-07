use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_protocol::{
    JobRuntimeAuthorities, JobRuntimeAuthority, RuntimeAuthorityCredential, RuntimeAuthorityName,
};
use automata_runner_control::{
    ControlPortError, RuntimeAuthorityIssueRequest, RuntimeAuthorityIssuer,
};

use crate::{ExecutionAuthority, HmacResultsAuthority};

/// Stable authority namespace consumed by the GitHub job executor.
pub const GITHUB_RESULTS_RUNTIME_AUTHORITY: &str = "github-actions-results";

/// Server-side adapter that issues one deterministic, per-attempt Results JWT.
pub struct GithubResultsRuntimeAuthorityIssuer {
    authority: Arc<HmacResultsAuthority>,
    valid_for_seconds: u64,
}

impl GithubResultsRuntimeAuthorityIssuer {
    /// Binds lease-offer issuance to one configured Results authority.
    ///
    /// # Errors
    ///
    /// Rejects a zero validity interval. The authority enforces its configured
    /// maximum during every issuance.
    pub fn new(
        authority: Arc<HmacResultsAuthority>,
        valid_for_seconds: u64,
    ) -> Result<Self, ControlPortError> {
        if valid_for_seconds == 0 {
            return Err(ControlPortError::Corrupt);
        }
        Ok(Self {
            authority,
            valid_for_seconds,
        })
    }
}

impl fmt::Debug for GithubResultsRuntimeAuthorityIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubResultsRuntimeAuthorityIssuer")
            .field("authority", &self.authority)
            .field("valid_for_seconds", &self.valid_for_seconds)
            .finish()
    }
}

#[async_trait]
impl RuntimeAuthorityIssuer for GithubResultsRuntimeAuthorityIssuer {
    async fn issue(
        &self,
        request: RuntimeAuthorityIssueRequest<'_>,
    ) -> Result<JobRuntimeAuthorities, ControlPortError> {
        let issued_at_millis =
            u64::try_from(request.issued_at().get()).map_err(|_| ControlPortError::Corrupt)?;
        let issued_at_seconds = issued_at_millis / 1_000;
        let expires_at_seconds = issued_at_seconds
            .checked_add(self.valid_for_seconds)
            .ok_or(ControlPortError::Corrupt)?;
        let issued_at = i64::try_from(issued_at_seconds)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000))
            .map(automata_core::UnixMillis::new)
            .ok_or(ControlPortError::Corrupt)?;
        let expires_at = i64::try_from(expires_at_seconds)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000))
            .map(automata_core::UnixMillis::new)
            .ok_or(ControlPortError::Corrupt)?;
        let job = request.job();
        let lease = request.lease();
        let execution = ExecutionAuthority::new(
            job.job().run_id(),
            job.job().job_id(),
            lease.attempt_id(),
            lease.fencing_token(),
        );
        let token = self
            .authority
            .issue_at(execution, issued_at_seconds, self.valid_for_seconds)
            .map_err(|_| ControlPortError::Corrupt)?;
        let authority = JobRuntimeAuthority::new(
            RuntimeAuthorityName::new(GITHUB_RESULTS_RUNTIME_AUTHORITY)
                .map_err(|_| ControlPortError::Corrupt)?,
            execution.run_id(),
            execution.job_id(),
            execution.attempt_id(),
            execution.fencing_token(),
            self.authority.runtime_authority_endpoint().clone(),
            RuntimeAuthorityCredential::new(token.expose_secret().to_owned())
                .map_err(|_| ControlPortError::Corrupt)?,
            issued_at,
            expires_at,
        )
        .map_err(|_| ControlPortError::Corrupt)?;
        JobRuntimeAuthorities::new(vec![authority], job, lease)
            .map_err(|_| ControlPortError::Corrupt)
    }
}
