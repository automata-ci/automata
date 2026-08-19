//! Provider-neutral desired-result production for workflow application.

use std::{fmt, sync::Arc};

use automata_ci_core::{GitObjectId, RunId, UnixMillis};
use automata_ci_provider::{
    ProviderConnectionManifest, ProviderRepositoryPath, ProviderResultConclusion,
    ProviderResultDetailsUrl, ProviderResultModelError, ProviderResultName, ProviderResultPhase,
    ProviderResultProjection, ProviderResultRepository, ProviderResultRepositoryError,
    ProviderResultSaveOutcome, ProviderResultSubject, ProviderResultSubjectId,
    ProviderResultSubjectKind, ProviderResultSummary, ProviderResultTitle,
    ProviderWorkflowInvocationId, ProviderWorkflowRunState, SaveDesiredProviderResult,
};
use automata_ci_store::WorkflowRerunReceipt;
use thiserror::Error;
use url::Url;

use crate::WorkflowAdmissionResult;

const RESULT_NAME_PREFIX: &str = "Automata CI / ";

/// Exact provider-neutral inputs for an invocation's initial desired result.
#[derive(Debug)]
pub struct ProviderWorkflowResultRequest<'a> {
    connection: &'a ProviderConnectionManifest,
    invocation_id: ProviderWorkflowInvocationId,
    repository_path: ProviderRepositoryPath,
    object: GitObjectId,
    workflow_path: ProviderRepositoryPath,
    attempt: u32,
    created_at: UnixMillis,
    disposition: ProviderWorkflowResultDisposition,
}

impl<'a> ProviderWorkflowResultRequest<'a> {
    /// Creates one provider-neutral initial workflow-result projection.
    ///
    /// # Errors
    ///
    /// Rejects invalid repository coordinates, workflow paths, attempts, or timestamps.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        connection: &'a ProviderConnectionManifest,
        invocation_id: ProviderWorkflowInvocationId,
        repository_path: impl Into<String>,
        object: GitObjectId,
        workflow_path: impl Into<String>,
        attempt: u32,
        created_at: UnixMillis,
        disposition: ProviderWorkflowResultDisposition,
    ) -> Result<Self, ProviderWorkflowResultServiceError> {
        if attempt == 0 || created_at.get() < 0 {
            return Err(ProviderWorkflowResultServiceError::InvalidEvidence);
        }
        Ok(Self {
            connection,
            invocation_id,
            repository_path: ProviderRepositoryPath::new(repository_path)
                .map_err(|_| ProviderWorkflowResultServiceError::InvalidEvidence)?,
            object,
            workflow_path: ProviderRepositoryPath::new(workflow_path)
                .map_err(|_| ProviderWorkflowResultServiceError::InvalidEvidence)?,
            attempt,
            created_at,
            disposition,
        })
    }
}

/// Closed provider-facing outcome of one workflow invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderWorkflowResultDisposition {
    /// A logical workflow run exists, including an exact idempotent replay.
    Admitted(WorkflowAdmissionResult),
    /// The valid workflow did not select the invocation.
    Skipped,
    /// The invocation reached a deterministic terminal rejection.
    Failed,
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

    /// Creates or exactly replays the initial desired result for one invocation.
    ///
    /// # Errors
    ///
    /// Returns a closed error when immutable invocation evidence is invalid or
    /// contradicts the durable result subject.
    pub async fn project_invocation(
        &self,
        request: ProviderWorkflowResultRequest<'_>,
    ) -> Result<ProviderResultSaveOutcome, ProviderWorkflowResultServiceError> {
        let ProviderWorkflowResultRequest {
            connection,
            invocation_id,
            repository_path,
            object,
            workflow_path,
            attempt,
            created_at,
            disposition,
        } = request;
        let kind = match disposition {
            ProviderWorkflowResultDisposition::Admitted(admission) => {
                ProviderResultSubjectKind::WorkflowRun {
                    run_id: admission.receipt().run_id(),
                }
            }
            ProviderWorkflowResultDisposition::Skipped
            | ProviderWorkflowResultDisposition::Failed => {
                ProviderResultSubjectKind::WorkflowInvocation {
                    invocation_id,
                    workflow_path: workflow_path.clone(),
                }
            }
        };
        let name = bounded_name(workflow_path.as_str());
        let details_url = self.details_url(&repository_path, &kind)?;
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
            ProviderWorkflowResultDisposition::Admitted(_) => {
                (ProviderResultPhase::Queued, None, "Workflow run queued.")
            }
            ProviderWorkflowResultDisposition::Skipped => (
                ProviderResultPhase::Completed,
                Some(ProviderResultConclusion::Skipped),
                "Workflow was not selected for this event.",
            ),
            ProviderWorkflowResultDisposition::Failed => (
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

    /// Reconciles one durable workflow-run lifecycle observation into the
    /// provider result outbox.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the initial immutable subject is not yet
    /// visible, the lifecycle evidence is invalid, or result storage fails.
    pub async fn reconcile_workflow_run(
        &self,
        run_id: RunId,
        lifecycle: ProviderWorkflowRunState,
        updated_at: UnixMillis,
    ) -> Result<ProviderResultSaveOutcome, ProviderWorkflowResultServiceError> {
        let subject = self
            .results
            .load_workflow_subject(run_id)
            .await
            .map_err(repository_error)?
            .ok_or(ProviderWorkflowResultServiceError::SubjectNotReady)?;
        if subject.subject() != &(ProviderResultSubjectKind::WorkflowRun { run_id }) {
            return Err(ProviderWorkflowResultServiceError::Inconsistent);
        }
        let projection = lifecycle_projection(subject.name().as_str(), lifecycle, updated_at)?;
        self.results
            .save_desired(SaveDesiredProviderResult::new(subject, projection).map_err(model_error)?)
            .await
            .map_err(repository_error)
    }

    /// Creates or exactly replays the queued result for one durable rerun.
    ///
    /// # Errors
    ///
    /// Returns a closed error when source evidence is absent, the current
    /// connection no longer owns that source, or result storage fails.
    pub async fn project_rerun(
        &self,
        connection: &ProviderConnectionManifest,
        receipt: WorkflowRerunReceipt,
        created_at: UnixMillis,
    ) -> Result<ProviderResultSaveOutcome, ProviderWorkflowResultServiceError> {
        let source = self
            .results
            .load_workflow_subject(receipt.source_run_id())
            .await
            .map_err(repository_error)?
            .ok_or(ProviderWorkflowResultServiceError::SubjectNotReady)?;
        if source.connection_id() != connection.connection_id()
            || source.repository() != connection.configuration().repository()
            || source.subject()
                != &(ProviderResultSubjectKind::WorkflowRun {
                    run_id: receipt.source_run_id(),
                })
        {
            return Err(ProviderWorkflowResultServiceError::Inconsistent);
        }
        let kind = ProviderResultSubjectKind::WorkflowRun {
            run_id: receipt.run_id(),
        };
        let subject = ProviderResultSubject::new(
            ProviderResultSubjectId::derive(connection.connection_id(), &kind),
            connection,
            source.object(),
            source.name().clone(),
            rerun_details_url(
                source.details_url(),
                receipt.source_run_id(),
                receipt.run_id(),
            )?,
            kind,
            receipt.run_attempt(),
            created_at,
        )
        .map_err(model_error)?;
        if let Some(current) = self
            .results
            .load_workflow_subject(receipt.run_id())
            .await
            .map_err(repository_error)?
        {
            return if current == subject {
                Ok(ProviderResultSaveOutcome::Unchanged)
            } else {
                Err(ProviderWorkflowResultServiceError::Inconsistent)
            };
        }
        let projection = lifecycle_projection(
            subject.name().as_str(),
            ProviderWorkflowRunState::Queued,
            created_at,
        )?;
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

fn lifecycle_projection(
    name: &str,
    lifecycle: ProviderWorkflowRunState,
    updated_at: UnixMillis,
) -> Result<ProviderResultProjection, ProviderWorkflowResultServiceError> {
    let (phase, conclusion, summary) = match lifecycle {
        ProviderWorkflowRunState::Queued => {
            (ProviderResultPhase::Queued, None, "Workflow run queued.")
        }
        ProviderWorkflowRunState::Running => (
            ProviderResultPhase::Running,
            None,
            "Workflow run in progress.",
        ),
        ProviderWorkflowRunState::Completed(conclusion) => (
            ProviderResultPhase::Completed,
            Some(conclusion),
            "Workflow run completed.",
        ),
    };
    ProviderResultProjection::new(
        phase,
        conclusion,
        ProviderResultTitle::new(name.to_owned()).map_err(model_error)?,
        ProviderResultSummary::new(summary).map_err(model_error)?,
        Vec::new(),
        updated_at,
    )
    .map_err(model_error)
}

fn rerun_details_url(
    source: &ProviderResultDetailsUrl,
    source_run_id: RunId,
    run_id: RunId,
) -> Result<ProviderResultDetailsUrl, ProviderWorkflowResultServiceError> {
    let mut url = source.as_url().clone();
    let segments = url
        .path_segments()
        .ok_or(ProviderWorkflowResultServiceError::InvalidEvidence)?
        .collect::<Vec<_>>();
    let expected_source = source_run_id.to_string();
    if segments.len() < 3
        || segments[segments.len() - 3] != "actions"
        || segments[segments.len() - 2] != "runs"
        || segments.last().copied() != Some(expected_source.as_str())
    {
        return Err(ProviderWorkflowResultServiceError::InvalidEvidence);
    }
    let mut path = url
        .path_segments_mut()
        .map_err(|()| ProviderWorkflowResultServiceError::InvalidEvidence)?;
    path.pop();
    path.push(&run_id.to_string());
    drop(path);
    ProviderResultDetailsUrl::new(url).map_err(model_error)
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
    /// The workflow was observed before its immutable provider result subject.
    #[error("provider workflow result subject is not ready")]
    SubjectNotReady,
    /// Result storage is temporarily unavailable.
    #[error("provider workflow result storage is unavailable")]
    Unavailable,
    /// Durable result state contradicted the exact workflow projection.
    #[error("provider workflow result state is inconsistent")]
    Inconsistent,
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };

    use automata_ci_core::{GitObjectId, RunId, Sha256Digest, UnixMillis, WorkspaceId};
    use automata_ci_provider::{
        ExternalRepositoryId, ExternalRepositoryIdentity, ProviderArchiveLimits,
        ProviderConfigurationRevision, ProviderConnectionConfiguration, ProviderConnectionId,
        ProviderConnectionManifest, ProviderConnectionPolicyDocument, ProviderConnectionRevision,
        ProviderDefaultBranch, ProviderLifecycleState, ProviderRepositoryPath,
        ProviderResultClaimFence, ProviderResultDetailsUrl, ProviderResultFuture,
        ProviderResultName, ProviderResultRepository, ProviderResultRepositoryError,
        ProviderResultSubject, ProviderResultSubjectId, ProviderResultSubjectKind,
        ProviderRunnerPolicyBinding, ProviderSchemaVersion, ProviderWorkflowSource,
        RenewProviderResult, RepositoryVisibility, SaveDesiredProviderResult,
    };
    use automata_ci_store::WorkflowRerunReceipt;
    use url::Url;
    use uuid::Uuid;

    use super::{
        ProviderWorkflowResultService, ProviderWorkflowResultServiceError, bounded_name,
        lifecycle_projection, rerun_details_url,
    };

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

        fn renew_result(
            &self,
            _request: RenewProviderResult,
        ) -> ProviderResultFuture<'_, ProviderResultClaimFence> {
            Box::pin(async { Err(ProviderResultRepositoryError::Corrupt) })
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

    #[derive(Debug, Default)]
    struct MemoryResults(Mutex<BTreeMap<RunId, ProviderResultSubject>>);

    impl ProviderResultRepository for MemoryResults {
        fn load_workflow_subject(
            &self,
            run_id: RunId,
        ) -> ProviderResultFuture<'_, Option<ProviderResultSubject>> {
            Box::pin(async move { Ok(self.0.lock().unwrap().get(&run_id).cloned()) })
        }

        fn save_desired(
            &self,
            request: SaveDesiredProviderResult,
        ) -> ProviderResultFuture<'_, automata_ci_provider::ProviderResultSaveOutcome> {
            Box::pin(async move {
                let (subject, _projection) = request.into_parts();
                let ProviderResultSubjectKind::WorkflowRun { run_id } = subject.subject() else {
                    return Err(ProviderResultRepositoryError::Corrupt);
                };
                let outcome = if self.0.lock().unwrap().insert(*run_id, subject).is_none() {
                    automata_ci_provider::ProviderResultSaveOutcome::Inserted
                } else {
                    automata_ci_provider::ProviderResultSaveOutcome::Superseded
                };
                Ok(outcome)
            })
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

        fn renew_result(
            &self,
            _request: RenewProviderResult,
        ) -> ProviderResultFuture<'_, ProviderResultClaimFence> {
            Box::pin(async { Err(ProviderResultRepositoryError::Corrupt) })
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

    fn connection() -> ProviderConnectionManifest {
        let configuration = ProviderConnectionConfiguration::new(
            WorkspaceId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
            ExternalRepositoryIdentity::new(
                "22222222-2222-4222-8222-222222222222".parse().unwrap(),
                ExternalRepositoryId::new("repository-42").unwrap(),
            ),
            ProviderConfigurationRevision::new(3).unwrap(),
            Sha256Digest::from_bytes([3; 32]),
            Sha256Digest::from_bytes([4; 32]),
            RepositoryVisibility::Private,
            ProviderDefaultBranch::new("main").unwrap(),
            ProviderWorkflowSource::Directory(
                ProviderRepositoryPath::new(".ci/workflows").unwrap(),
            ),
            ProviderRunnerPolicyBinding::new(
                ProviderSchemaVersion::new(1).unwrap(),
                Sha256Digest::from_bytes([5; 32]),
            ),
            ProviderArchiveLimits::new(1_024, 8_192, 100, 1_024, 10, 1_024).unwrap(),
            ProviderConnectionPolicyDocument::new(
                ProviderSchemaVersion::new(1).unwrap(),
                b"{}".to_vec(),
            )
            .unwrap(),
        );
        ProviderConnectionManifest::new(
            ProviderConnectionId::from_uuid(Uuid::from_u128(3)).unwrap(),
            ProviderConnectionRevision::new(7).unwrap(),
            ProviderLifecycleState::Active,
            configuration,
            UnixMillis::new(1_000),
            Some(UnixMillis::new(1_001)),
            None,
        )
        .unwrap()
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
                &ProviderResultSubjectKind::WorkflowInvocation {
                    invocation_id: automata_ci_provider::ProviderWorkflowInvocationId::new(),
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
        let rerun_id = RunId::from_uuid(Uuid::from_u128(43));
        assert_eq!(
            rerun_details_url(&run, run_id, rerun_id)
                .unwrap()
                .as_url()
                .as_str(),
            format!("https://ci.example/group/subgroup/repository/actions/runs/{rerun_id}")
        );
    }

    #[test]
    fn lifecycle_projection_is_provider_independent_and_closed() {
        let cases = [
            (
                automata_ci_provider::ProviderWorkflowRunState::Queued,
                automata_ci_provider::ProviderResultPhase::Queued,
                None,
            ),
            (
                automata_ci_provider::ProviderWorkflowRunState::Running,
                automata_ci_provider::ProviderResultPhase::Running,
                None,
            ),
            (
                automata_ci_provider::ProviderWorkflowRunState::Completed(
                    automata_ci_provider::ProviderResultConclusion::Success,
                ),
                automata_ci_provider::ProviderResultPhase::Completed,
                Some(automata_ci_provider::ProviderResultConclusion::Success),
            ),
            (
                automata_ci_provider::ProviderWorkflowRunState::Completed(
                    automata_ci_provider::ProviderResultConclusion::TimedOut,
                ),
                automata_ci_provider::ProviderResultPhase::Completed,
                Some(automata_ci_provider::ProviderResultConclusion::TimedOut),
            ),
            (
                automata_ci_provider::ProviderWorkflowRunState::Completed(
                    automata_ci_provider::ProviderResultConclusion::Cancelled,
                ),
                automata_ci_provider::ProviderResultPhase::Completed,
                Some(automata_ci_provider::ProviderResultConclusion::Cancelled),
            ),
        ];
        for (lifecycle, phase, conclusion) in cases {
            let projection =
                lifecycle_projection("Automata CI / build", lifecycle, UnixMillis::new(42))
                    .unwrap();
            assert_eq!(projection.phase(), phase);
            assert_eq!(projection.conclusion(), conclusion);
            assert_eq!(projection.updated_at(), UnixMillis::new(42));
        }
    }

    #[tokio::test]
    async fn lifecycle_waits_for_the_initial_subject() {
        assert_eq!(
            service("https://ci.example/")
                .unwrap()
                .reconcile_workflow_run(
                    RunId::from_uuid(Uuid::from_u128(42)),
                    automata_ci_provider::ProviderWorkflowRunState::Running,
                    UnixMillis::new(42),
                )
                .await,
            Err(ProviderWorkflowResultServiceError::SubjectNotReady)
        );
    }

    #[tokio::test]
    async fn rerun_projection_creates_once_and_exact_replay_never_regresses() {
        let connection = connection();
        let source_run = RunId::from_uuid(Uuid::from_u128(42));
        let rerun = RunId::from_uuid(Uuid::from_u128(43));
        let source_kind = ProviderResultSubjectKind::WorkflowRun { run_id: source_run };
        let source = ProviderResultSubject::new(
            ProviderResultSubjectId::derive(connection.connection_id(), &source_kind),
            &connection,
            GitObjectId::from_provider_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            ProviderResultName::new("Automata CI / build").unwrap(),
            ProviderResultDetailsUrl::new(
                format!("https://ci.example/owner/repository/actions/runs/{source_run}")
                    .parse()
                    .unwrap(),
            )
            .unwrap(),
            source_kind,
            1,
            UnixMillis::new(2_000),
        )
        .unwrap();
        let results = Arc::new(MemoryResults::default());
        results.0.lock().unwrap().insert(source_run, source);
        let service = ProviderWorkflowResultService::new(
            results.clone(),
            Url::parse("https://ci.example/").unwrap(),
        )
        .unwrap();
        let receipt = WorkflowRerunReceipt::new(source_run, rerun, 7, 5, 2, false).unwrap();
        assert_eq!(
            service
                .project_rerun(&connection, receipt, UnixMillis::new(3_000))
                .await
                .unwrap(),
            automata_ci_provider::ProviderResultSaveOutcome::Inserted
        );
        let projected = results.0.lock().unwrap().get(&rerun).cloned().unwrap();
        assert_eq!(projected.attempt(), 2);
        assert_eq!(
            projected.details_url().as_url().as_str(),
            format!("https://ci.example/owner/repository/actions/runs/{rerun}")
        );
        assert_eq!(
            service
                .project_rerun(&connection, receipt, UnixMillis::new(3_000))
                .await
                .unwrap(),
            automata_ci_provider::ProviderResultSaveOutcome::Unchanged
        );
    }
}
