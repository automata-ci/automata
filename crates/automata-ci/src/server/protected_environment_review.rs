//! Product adapter for authenticated protected-environment review.

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_store::{
    JobEnvironmentGateState, ProtectedEnvironmentRepository, ProtectedEnvironmentStoreError,
    ReviewJobEnvironment, StoreError, TenantScope,
};

use crate::app::protected_environment_review_api::{
    ProtectedEnvironmentReviewApiBackend, ProtectedEnvironmentReviewApiBackendError,
    ProtectedEnvironmentReviewApiRequest,
};

/// Authenticates and advances one exact protected-environment gate.
pub(crate) struct OperationalProtectedEnvironmentReviewBackend {
    repository: Arc<dyn ProtectedEnvironmentRepository>,
}

impl OperationalProtectedEnvironmentReviewBackend {
    #[must_use]
    pub(crate) const fn new(repository: Arc<dyn ProtectedEnvironmentRepository>) -> Self {
        Self { repository }
    }
}

impl fmt::Debug for OperationalProtectedEnvironmentReviewBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationalProtectedEnvironmentReviewBackend")
            .field("repository", &"ProtectedEnvironmentRepository(..)")
            .finish()
    }
}

#[async_trait]
impl ProtectedEnvironmentReviewApiBackend for OperationalProtectedEnvironmentReviewBackend {
    async fn review(
        &self,
        request: ProtectedEnvironmentReviewApiRequest,
    ) -> Result<JobEnvironmentGateState, ProtectedEnvironmentReviewApiBackendError> {
        let tenant =
            TenantScope::from_authenticated_tenant_id(request.actor().tenant_id().as_str())
                .map_err(|_| ProtectedEnvironmentReviewApiBackendError::Invariant)?;
        let review = ReviewJobEnvironment::new(
            request.actor().clone(),
            request.repository_id(),
            request.attempt_id(),
            request.decision(),
        )
        .map_err(|_| ProtectedEnvironmentReviewApiBackendError::Invariant)?;
        let state = self
            .repository
            .review_job_environment(review)
            .await
            .map_err(|error| classify_review_error(&error))?;
        if state != JobEnvironmentGateState::Resolving {
            return Ok(state);
        }
        self.repository
            .resolve_job_credentials(&tenant, request.attempt_id())
            .await
            .map_err(|error| classify_review_error(&error))
    }
}

fn classify_review_error(
    error: &ProtectedEnvironmentStoreError,
) -> ProtectedEnvironmentReviewApiBackendError {
    match error {
        ProtectedEnvironmentStoreError::AuthorityRejected => {
            ProtectedEnvironmentReviewApiBackendError::Forbidden
        }
        ProtectedEnvironmentStoreError::NotFound => {
            ProtectedEnvironmentReviewApiBackendError::NotFound
        }
        ProtectedEnvironmentStoreError::Conflict => {
            ProtectedEnvironmentReviewApiBackendError::Conflict
        }
        ProtectedEnvironmentStoreError::Operation(StoreError::Operation(_)) => {
            ProtectedEnvironmentReviewApiBackendError::Unavailable
        }
        ProtectedEnvironmentStoreError::Operation(_)
        | ProtectedEnvironmentStoreError::CorruptData => {
            ProtectedEnvironmentReviewApiBackendError::Invariant
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_failures_map_to_closed_http_classes() {
        for (error, expected) in [
            (
                ProtectedEnvironmentStoreError::AuthorityRejected,
                ProtectedEnvironmentReviewApiBackendError::Forbidden,
            ),
            (
                ProtectedEnvironmentStoreError::NotFound,
                ProtectedEnvironmentReviewApiBackendError::NotFound,
            ),
            (
                ProtectedEnvironmentStoreError::Conflict,
                ProtectedEnvironmentReviewApiBackendError::Conflict,
            ),
            (
                ProtectedEnvironmentStoreError::Operation(StoreError::operation(
                    std::io::Error::other("neutral dependency"),
                )),
                ProtectedEnvironmentReviewApiBackendError::Unavailable,
            ),
            (
                ProtectedEnvironmentStoreError::CorruptData,
                ProtectedEnvironmentReviewApiBackendError::Invariant,
            ),
        ] {
            assert_eq!(classify_review_error(&error), expected);
        }
    }
}
