//! Provider-neutral desired-result production for workflow application.

use std::{fmt, sync::Arc};

use automata_ci_core::{GitObjectId, UnixMillis};
use automata_ci_provider::{
    ProviderConnectionManifest, ProviderRepositoryPath, ProviderResultConclusion,
    ProviderResultDetailsUrl, ProviderResultModelError, ProviderResultName, ProviderResultPhase,
    ProviderResultProjection, ProviderResultRepository, ProviderResultRepositoryError,
    ProviderResultSaveOutcome, ProviderResultSubject, ProviderResultSubjectId,
    ProviderResultSubjectKind, ProviderResultSummary, ProviderResultTitle,
    SaveDesiredProviderResult, VerifiedProviderTriggerDelivery,
};
use thiserror::Error;
use url::Url;

use crate::ProviderWorkflowDisposition;

const RESULT_NAME_PREFIX: &str = "Automata CI / ";

pub(crate) struct ProviderWorkflowResultRequest<'a> {
    pub(crate) connection: &'a ProviderConnectionManifest,
    pub(crate) delivery: &'a VerifiedProviderTriggerDelivery,
    pub(crate) object: GitObjectId,
    pub(crate) workflow_path: &'a str,
    pub(crate) attempt: u32,
    pub(crate) created_at: UnixMillis,
    pub(crate) disposition: ProviderWorkflowDisposition,
}

/// Provider-neutral producer for initial workflow result state.
#[derive(Clone)]
pub struct ProviderWorkflowResultService {
    results: Arc<dyn ProviderResultRepository>,
    dashboard_origin: Url,
}

impl ProviderWorkflowResultService {
    /// Composes the canonical outbox and credential-free dashboard origin.
    ///
    /// # Errors
    ///
    /// Rejects anything other than an exact HTTPS origin URL.
    pub fn new(
        results: Arc<dyn ProviderResultRepository>,
        dashboard_origin: Url,
    ) -> Result<Self, ProviderWorkflowResultServiceError> {
        if dashboard_origin.scheme() != "https"
            || dashboard_origin.host().is_none()
            || !dashboard_origin.username().is_empty()
            || dashboard_origin.password().is_some()
            || dashboard_origin.query().is_some()
            || dashboard_origin.fragment().is_some()
            || dashboard_origin.path() != "/"
        {
            return Err(ProviderWorkflowResultServiceError::InvalidConfiguration);
        }
        Ok(Self {
            results,
            dashboard_origin,
        })
    }

    pub(crate) async fn project(
        &self,
        request: ProviderWorkflowResultRequest<'_>,
    ) -> Result<ProviderResultSaveOutcome, ProviderWorkflowResultServiceError> {
        let ProviderWorkflowResultRequest {
            connection,
            delivery,
            object,
            workflow_path,
            attempt,
            created_at,
            disposition,
        } = request;
        let path = ProviderRepositoryPath::new(workflow_path)
            .map_err(|_| ProviderWorkflowResultServiceError::InvalidEvidence)?;
        let kind = match disposition {
            ProviderWorkflowDisposition::Admitted(admission) => {
                ProviderResultSubjectKind::WorkflowRun {
                    run_id: admission.receipt().run_id(),
                }
            }
            ProviderWorkflowDisposition::NotSelected(_)
            | ProviderWorkflowDisposition::Rejected(_) => {
                ProviderResultSubjectKind::PendingWorkflow {
                    delivery_id: delivery.evidence().delivery_id(),
                    workflow_path: path,
                }
            }
        };
        let name = bounded_name(workflow_path);
        let details_url = self.details_url(
            delivery.trigger().trigger().target_repository().path(),
            &kind,
        )?;
        let subject = ProviderResultSubject::new(
            ProviderResultSubjectId::derive(connection.connection_id(), &kind),
            connection,
            object,
            ProviderResultName::new(name.clone()).map_err(model_error)?,
            details_url,
            kind,
            attempt,
            created_at,
        )
        .map_err(model_error)?;
        let (phase, conclusion, summary) = match disposition {
            ProviderWorkflowDisposition::Admitted(_) => {
                (ProviderResultPhase::Queued, None, "Workflow run queued.")
            }
            ProviderWorkflowDisposition::NotSelected(_) => (
                ProviderResultPhase::Completed,
                Some(ProviderResultConclusion::Skipped),
                "Workflow was not selected for this event.",
            ),
            ProviderWorkflowDisposition::Rejected(_) => (
                ProviderResultPhase::Completed,
                Some(ProviderResultConclusion::Failure),
                "Workflow could not be admitted.",
            ),
        };
        let projection = ProviderResultProjection::new(
            phase,
            conclusion,
            ProviderResultTitle::new(name).map_err(model_error)?,
            ProviderResultSummary::new(summary).map_err(model_error)?,
            Vec::new(),
            created_at,
        )
        .map_err(model_error)?;
        self.results
            .save_desired(SaveDesiredProviderResult::new(subject, projection).map_err(model_error)?)
            .await
            .map_err(repository_error)
    }

    fn details_url(
        &self,
        repository: &ProviderRepositoryPath,
        kind: &ProviderResultSubjectKind,
    ) -> Result<ProviderResultDetailsUrl, ProviderWorkflowResultServiceError> {
        let mut url = self.dashboard_origin.clone();
        let mut segments = url
            .path_segments_mut()
            .map_err(|()| ProviderWorkflowResultServiceError::InvalidConfiguration)?;
        segments.pop_if_empty();
        for segment in repository.as_str().split('/') {
            if segment.is_empty() {
                return Err(ProviderWorkflowResultServiceError::InvalidEvidence);
            }
            segments.push(segment);
        }
        segments.push("actions");
        if let ProviderResultSubjectKind::WorkflowRun { run_id } = kind {
            segments.push("runs");
            segments.push(&run_id.to_string());
        }
        drop(segments);
        ProviderResultDetailsUrl::new(url).map_err(model_error)
    }
}

impl fmt::Debug for ProviderWorkflowResultService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderWorkflowResultService")
            .field("results", &self.results)
            .field("dashboard_origin", &"[configured]")
            .finish()
    }
}

fn bounded_name(path: &str) -> String {
    let mut name = format!("{RESULT_NAME_PREFIX}{path}");
    if name.len() <= automata_ci_provider::MAX_PROVIDER_RESULT_NAME_BYTES {
        return name;
    }
    let maximum = automata_ci_provider::MAX_PROVIDER_RESULT_NAME_BYTES - 3;
    let mut boundary = maximum;
    while !name.is_char_boundary(boundary) {
        boundary -= 1;
    }
    name.truncate(boundary);
    name.push_str("...");
    name
}

const fn model_error(_: ProviderResultModelError) -> ProviderWorkflowResultServiceError {
    ProviderWorkflowResultServiceError::InvalidEvidence
}

const fn repository_error(
    error: ProviderResultRepositoryError,
) -> ProviderWorkflowResultServiceError {
    match error {
        ProviderResultRepositoryError::Unavailable => {
            ProviderWorkflowResultServiceError::Unavailable
        }
        ProviderResultRepositoryError::Conflict
        | ProviderResultRepositoryError::StaleClaim
        | ProviderResultRepositoryError::NotFound
        | ProviderResultRepositoryError::Corrupt => {
            ProviderWorkflowResultServiceError::Inconsistent
        }
    }
}

/// Sanitized initial workflow-result projection failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderWorkflowResultServiceError {
    /// Dashboard or service configuration is invalid.
    #[error("provider workflow result configuration is invalid")]
    InvalidConfiguration,
    /// Workflow or provider evidence cannot form one exact result subject.
    #[error("provider workflow result evidence is invalid")]
    InvalidEvidence,
    /// Result storage is temporarily unavailable.
    #[error("provider workflow result storage is unavailable")]
    Unavailable,
    /// Durable result state contradicted the exact workflow projection.
    #[error("provider workflow result state is inconsistent")]
    Inconsistent,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use automata_ci_core::RunId;
    use automata_ci_provider::{
        ProviderRepositoryPath, ProviderResultFuture, ProviderResultRepository,
        ProviderResultRepositoryError, ProviderResultSubjectKind, SaveDesiredProviderResult,
    };
    use url::Url;
    use uuid::Uuid;

    use super::{ProviderWorkflowResultService, ProviderWorkflowResultServiceError, bounded_name};

    #[derive(Debug)]
    struct UnusedResults;

    impl ProviderResultRepository for UnusedResults {
        fn load_workflow_subject(
            &self,
            _run_id: RunId,
        ) -> ProviderResultFuture<'_, Option<automata_ci_provider::ProviderResultSubject>> {
            Box::pin(async { Ok(None) })
        }

        fn save_desired(
            &self,
            _request: SaveDesiredProviderResult,
        ) -> ProviderResultFuture<'_, automata_ci_provider::ProviderResultSaveOutcome> {
            Box::pin(async { Err(ProviderResultRepositoryError::Unavailable) })
        }

        fn claim_result(
            &self,
            _request: automata_ci_provider::ClaimProviderResult,
        ) -> ProviderResultFuture<'_, Option<automata_ci_provider::ClaimedProviderResult>> {
            Box::pin(async { Ok(None) })
        }

        fn complete_result(
            &self,
            _request: automata_ci_provider::CompleteProviderResult,
        ) -> ProviderResultFuture<'_, ()> {
            Box::pin(async { Ok(()) })
        }

        fn retry_result(
            &self,
            _request: automata_ci_provider::RetryProviderResult,
        ) -> ProviderResultFuture<'_, ()> {
            Box::pin(async { Ok(()) })
        }

        fn fail_result(
            &self,
            _request: automata_ci_provider::FailProviderResult,
        ) -> ProviderResultFuture<'_, ()> {
            Box::pin(async { Ok(()) })
        }
    }

    fn service(
        origin: &str,
    ) -> Result<ProviderWorkflowResultService, ProviderWorkflowResultServiceError> {
        ProviderWorkflowResultService::new(Arc::new(UnusedResults), Url::parse(origin).unwrap())
    }

    #[test]
    fn dashboard_origin_is_an_exact_https_origin() {
        assert!(service("https://ci.example/").is_ok());
        for invalid in [
            "http://ci.example/",
            "https://ci.example/root",
            "https://user@ci.example/",
            "https://ci.example/?tenant=one",
            "https://ci.example/#fragment",
        ] {
            assert_eq!(
                service(invalid).unwrap_err(),
                ProviderWorkflowResultServiceError::InvalidConfiguration
            );
        }
    }

    #[test]
    fn result_names_are_utf8_safe_and_bounded() {
        let name = bounded_name(&"workflow-🚀".repeat(100));
        assert!(name.len() <= automata_ci_provider::MAX_PROVIDER_RESULT_NAME_BYTES);
        assert!(name.ends_with("..."));
        assert!(name.is_char_boundary(name.len()));
    }

    #[test]
    fn details_urls_preserve_nested_repository_paths() {
        let service = service("https://ci.example/").unwrap();
        let repository = ProviderRepositoryPath::new("group/subgroup/repository").unwrap();
        let pending = service
            .details_url(
                &repository,
                &ProviderResultSubjectKind::PendingWorkflow {
                    delivery_id: automata_ci_provider::ProviderDeliveryId::new(),
                    workflow_path: ProviderRepositoryPath::new(".ci/workflows/build.yml").unwrap(),
                },
            )
            .unwrap();
        assert_eq!(
            pending.as_url().as_str(),
            "https://ci.example/group/subgroup/repository/actions"
        );

        let run_id = RunId::from_uuid(Uuid::from_u128(42));
        let run = service
            .details_url(
                &repository,
                &ProviderResultSubjectKind::WorkflowRun { run_id },
            )
            .unwrap();
        assert_eq!(
            run.as_url().as_str(),
            format!("https://ci.example/group/subgroup/repository/actions/runs/{run_id}")
        );
    }
}
