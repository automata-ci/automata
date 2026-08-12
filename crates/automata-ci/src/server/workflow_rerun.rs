use std::fmt;

use async_trait::async_trait;
use automata_ci_store::{RerunWorkflowByName, StoreError, WorkflowRerunStoreError};
use automata_ci_workflow_service::WorkflowRerunService;

use crate::app::workflow_rerun_api::{
    WorkflowRerunApiBackend, WorkflowRerunApiBackendError, WorkflowRerunApiOutcome,
    WorkflowRerunApiRequest,
};

/// Product adapter from authenticated CLI input to durable rerun admission.
pub(crate) struct OperationalWorkflowRerunBackend {
    service: WorkflowRerunService,
}

impl OperationalWorkflowRerunBackend {
    pub(crate) const fn new(service: WorkflowRerunService) -> Self {
        Self { service }
    }
}

impl fmt::Debug for OperationalWorkflowRerunBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationalWorkflowRerunBackend")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl WorkflowRerunApiBackend for OperationalWorkflowRerunBackend {
    async fn rerun(
        &self,
        request: WorkflowRerunApiRequest,
    ) -> Result<WorkflowRerunApiOutcome, WorkflowRerunApiBackendError> {
        let rerun = RerunWorkflowByName::new(
            request.actor().clone(),
            request.repository_owner(),
            request.repository_name(),
            request.source_run_id(),
            request.selection(),
            request.operation_id(),
        )
        .map_err(|_| WorkflowRerunApiBackendError::Invariant)?;
        let receipt = self
            .service
            .rerun_by_name(rerun)
            .await
            .map_err(|error| classify_rerun_error(&error))?;
        WorkflowRerunApiOutcome::new(
            receipt.source_run_id(),
            receipt.run_id(),
            receipt.public_run_id(),
            receipt.run_number(),
            receipt.run_attempt(),
            receipt.is_replay(),
        )
    }
}

fn classify_rerun_error(error: &WorkflowRerunStoreError) -> WorkflowRerunApiBackendError {
    match error {
        WorkflowRerunStoreError::AuthorityRejected => WorkflowRerunApiBackendError::Forbidden,
        WorkflowRerunStoreError::NotFound => WorkflowRerunApiBackendError::NotFound,
        WorkflowRerunStoreError::SourceNotTerminal
        | WorkflowRerunStoreError::SourceExpired
        | WorkflowRerunStoreError::AttemptLimitReached
        | WorkflowRerunStoreError::UnsupportedSelection
        | WorkflowRerunStoreError::ConcurrencyQueueFull
        | WorkflowRerunStoreError::IdempotencyConflict => WorkflowRerunApiBackendError::Conflict,
        WorkflowRerunStoreError::Store(StoreError::Operation(_)) => {
            WorkflowRerunApiBackendError::Unavailable
        }
        WorkflowRerunStoreError::Store(_) => WorkflowRerunApiBackendError::Invariant,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_failures_map_to_closed_http_classes() {
        for (error, expected) in [
            (
                WorkflowRerunStoreError::AuthorityRejected,
                WorkflowRerunApiBackendError::Forbidden,
            ),
            (
                WorkflowRerunStoreError::NotFound,
                WorkflowRerunApiBackendError::NotFound,
            ),
            (
                WorkflowRerunStoreError::SourceNotTerminal,
                WorkflowRerunApiBackendError::Conflict,
            ),
            (
                WorkflowRerunStoreError::SourceExpired,
                WorkflowRerunApiBackendError::Conflict,
            ),
            (
                WorkflowRerunStoreError::AttemptLimitReached,
                WorkflowRerunApiBackendError::Conflict,
            ),
            (
                WorkflowRerunStoreError::UnsupportedSelection,
                WorkflowRerunApiBackendError::Conflict,
            ),
            (
                WorkflowRerunStoreError::ConcurrencyQueueFull,
                WorkflowRerunApiBackendError::Conflict,
            ),
            (
                WorkflowRerunStoreError::IdempotencyConflict,
                WorkflowRerunApiBackendError::Conflict,
            ),
            (
                WorkflowRerunStoreError::Store(StoreError::operation(std::io::Error::other(
                    "neutral dependency",
                ))),
                WorkflowRerunApiBackendError::Unavailable,
            ),
            (
                WorkflowRerunStoreError::Store(StoreError::corrupt_data("neutral invariant")),
                WorkflowRerunApiBackendError::Invariant,
            ),
        ] {
            assert_eq!(classify_rerun_error(&error), expected);
        }
    }
}
