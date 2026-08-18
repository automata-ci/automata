use std::{collections::BTreeMap, fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_control::runner_control::{
    ControlPortError, RuntimeAuthorityIssueRequest, RuntimeAuthorityIssuer,
};
use automata_ci_core::{TrustCacheAuthority, TrustResultsAuthority};
use automata_ci_protocol::{
    JobRuntimeAuthorities, JobRuntimeAuthority, RuntimeAuthorityCredential, RuntimeAuthorityName,
};

use crate::{
    CacheAccessScope, CacheAuthority, CachePermission, CacheRepositoryMetadata, ExecutionAuthority,
    HmacResultsAuthority, derive_cache_authority,
};

const MAX_CACHE_AUTHORITY_REPOSITORIES: usize = 1_024;

/// Stable authority namespace consumed by the Actions-compatible job executor.
pub const RUNNER_RESULTS_RUNTIME_AUTHORITY: &str = "runner-results";

/// Server-side adapter that issues one deterministic, per-attempt Results JWT.
pub struct RunnerResultsRuntimeAuthorityIssuer {
    authority: Arc<HmacResultsAuthority>,
    valid_for_seconds: u64,
    repositories: BTreeMap<String, CacheRepositoryMetadata>,
}

impl RunnerResultsRuntimeAuthorityIssuer {
    /// Binds lease-offer issuance to one configured Results authority.
    ///
    /// # Errors
    ///
    /// Rejects a zero validity interval or a duplicate/excessive repository
    /// metadata registry. The authority enforces its configured token maximum
    /// during every issuance.
    pub fn new(
        authority: Arc<HmacResultsAuthority>,
        valid_for_seconds: u64,
        repositories: impl IntoIterator<Item = CacheRepositoryMetadata>,
    ) -> Result<Self, ControlPortError> {
        if valid_for_seconds == 0 {
            return Err(ControlPortError::Corrupt);
        }
        let mut repository_registry = BTreeMap::new();
        for repository in repositories {
            if repository_registry.len() >= MAX_CACHE_AUTHORITY_REPOSITORIES
                || repository_registry
                    .insert(repository.repository().to_owned(), repository)
                    .is_some()
            {
                return Err(ControlPortError::Corrupt);
            }
        }
        Ok(Self {
            authority,
            valid_for_seconds,
            repositories: repository_registry,
        })
    }
}

impl fmt::Debug for RunnerResultsRuntimeAuthorityIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunnerResultsRuntimeAuthorityIssuer")
            .field("authority", &self.authority)
            .field("valid_for_seconds", &self.valid_for_seconds)
            .field("repository_count", &self.repositories.len())
            .finish()
    }
}

#[async_trait]
impl RuntimeAuthorityIssuer for RunnerResultsRuntimeAuthorityIssuer {
    async fn issue(
        &self,
        request: RuntimeAuthorityIssueRequest<'_>,
    ) -> Result<JobRuntimeAuthorities, ControlPortError> {
        let trust = request.job().job().trust_snapshot().authority();
        match (trust.results(), trust.cache()) {
            (TrustResultsAuthority::Denied, TrustCacheAuthority::Denied) => {
                return JobRuntimeAuthorities::new(Vec::new(), request.job(), request.lease())
                    .map_err(|_| ControlPortError::Corrupt);
            }
            (TrustResultsAuthority::Standard, TrustCacheAuthority::ReadWrite)
            | (TrustResultsAuthority::Untrusted, TrustCacheAuthority::ReadOnly) => {}
            _ => return Err(ControlPortError::Corrupt),
        }
        let issued_at_millis =
            u64::try_from(request.issued_at().get()).map_err(|_| ControlPortError::Corrupt)?;
        let issued_at_seconds = issued_at_millis / 1_000;
        let expires_at_seconds = issued_at_seconds
            .checked_add(self.valid_for_seconds)
            .ok_or(ControlPortError::Corrupt)?;
        let issued_at = i64::try_from(issued_at_seconds)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000))
            .map(automata_ci_core::UnixMillis::new)
            .ok_or(ControlPortError::Corrupt)?;
        let expires_at = i64::try_from(expires_at_seconds)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000))
            .map(automata_ci_core::UnixMillis::new)
            .ok_or(ControlPortError::Corrupt)?;
        let job = request.job();
        let lease = request.lease();
        let execution = ExecutionAuthority::new(
            job.job().run_id(),
            job.job().job_id(),
            lease.attempt_id(),
            lease.fencing_token(),
        );
        let repository_metadata = self
            .repositories
            .get(&job.source().repository().to_ascii_lowercase());
        let cache = derive_cache_authority(
            job.source().provider(),
            job.source().repository(),
            job.execution().git_ref(),
            job.source().event_name(),
            repository_metadata,
        )
        .map_err(|_| ControlPortError::Corrupt)?;
        let cache = match trust.cache() {
            TrustCacheAuthority::ReadWrite => cache,
            TrustCacheAuthority::ReadOnly => read_only_cache(&cache)?,
            TrustCacheAuthority::Denied => return Err(ControlPortError::Corrupt),
        };
        let token = self
            .authority
            .issue_at(execution, &cache, issued_at_seconds, self.valid_for_seconds)
            .map_err(|_| ControlPortError::Corrupt)?;
        let authority = JobRuntimeAuthority::new(
            RuntimeAuthorityName::new(RUNNER_RESULTS_RUNTIME_AUTHORITY)
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

fn read_only_cache(cache: &CacheAuthority) -> Result<CacheAuthority, ControlPortError> {
    let scopes = cache
        .scopes()
        .iter()
        .filter(|scope| scope.permission().can_read())
        .map(|scope| CacheAccessScope::new(scope.scope(), CachePermission::Read))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ControlPortError::Corrupt)?;
    CacheAuthority::new(cache.repository(), scopes).map_err(|_| ControlPortError::Corrupt)
}
