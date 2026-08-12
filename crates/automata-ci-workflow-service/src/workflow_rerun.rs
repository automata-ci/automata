//! Thin application service for authenticated durable workflow reruns.

use std::{fmt, sync::Arc};

use automata_ci_store::{
    RerunWorkflow, RerunWorkflowByName, WorkflowRerunReceipt, WorkflowRerunRepository,
    WorkflowRerunStoreError,
};

/// Delegates one already-validated rerun request to durable admission.
#[derive(Clone)]
pub struct WorkflowRerunService {
    repository: Arc<dyn WorkflowRerunRepository>,
}

impl fmt::Debug for WorkflowRerunService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WorkflowRerunService")
    }
}

impl WorkflowRerunService {
    /// Composes the service over its durable repository.
    #[must_use]
    pub const fn new(repository: Arc<dyn WorkflowRerunRepository>) -> Self {
        Self { repository }
    }

    /// Admits or exactly replays one authenticated workflow rerun.
    ///
    /// # Errors
    ///
    /// Returns the repository's closed, sanitized failure unchanged.
    pub async fn rerun(
        &self,
        request: RerunWorkflow,
    ) -> Result<WorkflowRerunReceipt, WorkflowRerunStoreError> {
        self.repository.rerun_workflow(request).await
    }

    /// Resolves a human-facing repository coordinate and admits its rerun.
    ///
    /// # Errors
    ///
    /// Returns the repository's closed, sanitized failure unchanged.
    pub async fn rerun_by_name(
        &self,
        request: RerunWorkflowByName,
    ) -> Result<WorkflowRerunReceipt, WorkflowRerunStoreError> {
        self.repository.rerun_workflow_by_name(request).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use automata_ci_auth::{
        human::{PrincipalId, TenantId},
        management::{ManagementActor, ManagementRevision},
        session::SessionId,
        time::UnixTimestamp,
    };
    use automata_ci_core::{OperationId, RunId};
    use automata_ci_store::{RepositoryId, WorkflowRerunSelection};
    use uuid::Uuid;

    use super::*;

    #[derive(Debug)]
    struct RecordingRepository {
        request: Mutex<Option<RerunWorkflow>>,
        named_request: Mutex<Option<RerunWorkflowByName>>,
        result: Mutex<Option<Result<WorkflowRerunReceipt, WorkflowRerunStoreError>>>,
    }

    #[async_trait]
    impl WorkflowRerunRepository for RecordingRepository {
        async fn rerun_workflow(
            &self,
            request: RerunWorkflow,
        ) -> Result<WorkflowRerunReceipt, WorkflowRerunStoreError> {
            *self.request.lock().expect("request lock") = Some(request);
            self.result
                .lock()
                .expect("result lock")
                .take()
                .expect("one configured result")
        }

        async fn rerun_workflow_by_name(
            &self,
            request: RerunWorkflowByName,
        ) -> Result<WorkflowRerunReceipt, WorkflowRerunStoreError> {
            *self.named_request.lock().expect("named request lock") = Some(request);
            self.result
                .lock()
                .expect("result lock")
                .take()
                .expect("one configured result")
        }
    }

    #[tokio::test]
    async fn forwards_the_exact_request_and_receipt() {
        let request = request();
        let receipt = WorkflowRerunReceipt::new(
            request.source_run_id(),
            RunId::from_uuid(Uuid::from_u128(20)),
            41,
            17,
            2,
            false,
        )
        .expect("receipt");
        let repository = Arc::new(RecordingRepository {
            request: Mutex::new(None),
            named_request: Mutex::new(None),
            result: Mutex::new(Some(Ok(receipt))),
        });
        let service = WorkflowRerunService::new(repository.clone());

        assert_eq!(format!("{service:?}"), "WorkflowRerunService");

        assert_eq!(
            service.rerun(request.clone()).await.expect("rerun"),
            receipt
        );
        assert_eq!(
            repository.request.lock().expect("request lock").as_ref(),
            Some(&request)
        );
    }

    #[tokio::test]
    async fn preserves_repository_errors_without_manufacturing_a_receipt() {
        let request = request();
        let repository = Arc::new(RecordingRepository {
            request: Mutex::new(None),
            named_request: Mutex::new(None),
            result: Mutex::new(Some(Err(WorkflowRerunStoreError::SourceNotTerminal))),
        });
        let error = WorkflowRerunService::new(repository.clone())
            .rerun(request.clone())
            .await
            .expect_err("repository error");

        assert!(matches!(error, WorkflowRerunStoreError::SourceNotTerminal));
        assert_eq!(
            repository.request.lock().expect("request lock").as_ref(),
            Some(&request)
        );
    }

    #[tokio::test]
    async fn forwards_human_facing_repository_coordinates_without_resolving_them() {
        let request = named_request();
        let receipt = WorkflowRerunReceipt::new(
            request.source_run_id(),
            RunId::from_uuid(Uuid::from_u128(20)),
            41,
            17,
            2,
            false,
        )
        .expect("receipt");
        let repository = Arc::new(RecordingRepository {
            request: Mutex::new(None),
            named_request: Mutex::new(None),
            result: Mutex::new(Some(Ok(receipt))),
        });

        assert_eq!(
            WorkflowRerunService::new(repository.clone())
                .rerun_by_name(request.clone())
                .await
                .expect("named rerun"),
            receipt
        );
        assert_eq!(
            repository
                .named_request
                .lock()
                .expect("named request lock")
                .as_ref(),
            Some(&request)
        );
        assert!(repository.request.lock().expect("request lock").is_none());
    }

    fn request() -> RerunWorkflow {
        let actor = ManagementActor::new(
            TenantId::new("tenant").expect("tenant"),
            PrincipalId::new(Uuid::from_u128(10).hyphenated().to_string()).expect("principal"),
            SessionId::new(Uuid::from_u128(11).hyphenated().to_string()).expect("session"),
            ManagementRevision::new(1).expect("revision"),
            None,
            UnixTimestamp::from_seconds(12),
        );
        RerunWorkflow::new(
            actor,
            RepositoryId::from_uuid(Uuid::from_u128(13)),
            RunId::from_uuid(Uuid::from_u128(14)),
            WorkflowRerunSelection::EntireWorkflow,
            OperationId::from_uuid(Uuid::from_u128(15)),
        )
        .expect("request")
    }

    fn named_request() -> RerunWorkflowByName {
        RerunWorkflowByName::new(
            request().actor().clone(),
            "Automata-CI",
            "automata",
            RunId::from_uuid(Uuid::from_u128(14)),
            WorkflowRerunSelection::EntireWorkflow,
            OperationId::from_uuid(Uuid::from_u128(15)),
        )
        .expect("named request")
    }
}
