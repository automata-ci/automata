use std::fmt;

use async_trait::async_trait;
use automata_ci_blob::BlobStoreErrorKind;
use automata_ci_store::{LogicalWorkflowAdmissionStoreError, StoreError};
use automata_ci_workflow_service::{
    DurableGithubWorkflowDispatchRequest, GithubWorkflowDispatchError,
    GithubWorkflowDispatchInputValue, GithubWorkflowDispatchInputs, GithubWorkflowDispatchService,
    WorkflowAdmissionError, WorkflowDispatchAuthorization,
};

use crate::app::workflow_dispatch_api::{
    WorkflowDispatchApiBackend, WorkflowDispatchApiBackendError, WorkflowDispatchApiInputValue,
    WorkflowDispatchApiOutcome, WorkflowDispatchApiRequest,
};

/// Product adapter from authenticated CLI input to exact durable-source dispatch.
pub(crate) struct OperationalWorkflowDispatchBackend {
    service: GithubWorkflowDispatchService,
}

impl OperationalWorkflowDispatchBackend {
    pub(crate) const fn new(service: GithubWorkflowDispatchService) -> Self {
        Self { service }
    }
}

impl fmt::Debug for OperationalWorkflowDispatchBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationalWorkflowDispatchBackend")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl WorkflowDispatchApiBackend for OperationalWorkflowDispatchBackend {
    async fn dispatch(
        &self,
        request: WorkflowDispatchApiRequest,
    ) -> Result<WorkflowDispatchApiOutcome, WorkflowDispatchApiBackendError> {
        let authorization = WorkflowDispatchAuthorization::new(
            request.actor().clone(),
            request.repository_id(),
            request.workflow_id(),
        )
        .map_err(|_| WorkflowDispatchApiBackendError::Invariant)?;
        let inputs = request
            .inputs()
            .iter()
            .map(|(key, value)| {
                let value = match value {
                    WorkflowDispatchApiInputValue::Boolean(value) => {
                        GithubWorkflowDispatchInputValue::Boolean(*value)
                    }
                    WorkflowDispatchApiInputValue::String(value) => {
                        GithubWorkflowDispatchInputValue::String(value.clone())
                    }
                };
                (key.as_str().to_owned(), value)
            })
            .collect::<Vec<_>>();
        let inputs = GithubWorkflowDispatchInputs::try_new(inputs)
            .map_err(|_| WorkflowDispatchApiBackendError::InvalidRequest)?;
        let dispatch = DurableGithubWorkflowDispatchRequest::new(
            authorization,
            request.git_ref(),
            request.commit_sha(),
            inputs,
            request.operation_id(),
        );
        let result = self
            .service
            .dispatch_from_durable_source(dispatch)
            .await
            .map_err(|error| classify_dispatch_error(&error))?;
        WorkflowDispatchApiOutcome::new(
            result.receipt().run_id(),
            result.receipt().run_number(),
            result.receipt().is_replay(),
        )
    }
}

fn classify_dispatch_error(error: &GithubWorkflowDispatchError) -> WorkflowDispatchApiBackendError {
    match error {
        GithubWorkflowDispatchError::DurableSourceNotFound => {
            WorkflowDispatchApiBackendError::NotFound
        }
        GithubWorkflowDispatchError::CompilationRejected(_) => {
            WorkflowDispatchApiBackendError::InvalidRequest
        }
        GithubWorkflowDispatchError::Admission(WorkflowAdmissionError::Store(
            LogicalWorkflowAdmissionStoreError::WorkflowDispatchAuthorityRejected,
        )) => WorkflowDispatchApiBackendError::Forbidden,
        GithubWorkflowDispatchError::Admission(WorkflowAdmissionError::Store(
            LogicalWorkflowAdmissionStoreError::IdempotencyConflict,
        )) => WorkflowDispatchApiBackendError::Conflict,
        GithubWorkflowDispatchError::Admission(WorkflowAdmissionError::Store(
            LogicalWorkflowAdmissionStoreError::Store(StoreError::Operation(_)),
        )) => WorkflowDispatchApiBackendError::Unavailable,
        GithubWorkflowDispatchError::Admission(WorkflowAdmissionError::Blob(error))
            if matches!(
                error.kind(),
                BlobStoreErrorKind::Unauthorized | BlobStoreErrorKind::Unavailable
            ) =>
        {
            WorkflowDispatchApiBackendError::Unavailable
        }
        GithubWorkflowDispatchError::Request(_)
        | GithubWorkflowDispatchError::InvalidSourceEncoding
        | GithubWorkflowDispatchError::FrontendRejected(_)
        | GithubWorkflowDispatchError::InvalidSourcePlan
        | GithubWorkflowDispatchError::DurableSourceMismatch
        | GithubWorkflowDispatchError::InvalidBaseContext
        | GithubWorkflowDispatchError::Evidence(_)
        | GithubWorkflowDispatchError::AdmissionRequest(_)
        | GithubWorkflowDispatchError::Admission(_) => WorkflowDispatchApiBackendError::Invariant,
    }
}
