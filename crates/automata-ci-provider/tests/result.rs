use std::sync::Mutex;

use automata_ci_core::{GitObjectId, RunId, Sha256Digest, UnixMillis, WorkspaceId};
use automata_ci_provider::{
    ClaimProviderResult, ClaimedProviderResult, CommitStatusCapability, CommitStatusState,
    CompleteProviderResult, DesiredProviderResult, ExternalRepositoryId,
    ExternalRepositoryIdentity, ExternalResultId, FailProviderResult,
    MAX_PROVIDER_RESULT_PUBLICATION_ATTEMPTS, ProviderArchiveLimits, ProviderCapabilities,
    ProviderCapability, ProviderConfigurationRevision, ProviderConnectionConfiguration,
    ProviderConnectionId, ProviderConnectionManifest, ProviderConnectionPolicyDocument,
    ProviderConnectionRevision, ProviderDefaultBranch, ProviderLifecycleState,
    ProviderRepositoryPath, ProviderResultAnnotation, ProviderResultAnnotationLevel,
    ProviderResultAnnotationMessage, ProviderResultAnnotationTitle, ProviderResultClaimFence,
    ProviderResultConclusion, ProviderResultContinuation, ProviderResultDetailsUrl,
    ProviderResultFailureKind, ProviderResultFuture, ProviderResultModelError, ProviderResultName,
    ProviderResultPhase, ProviderResultProjection, ProviderResultPublicationEvidence,
    ProviderResultPublicationModel, ProviderResultRepository, ProviderResultRepositoryError,
    ProviderResultRetryAfter, ProviderResultSaveOutcome, ProviderResultSubject,
    ProviderResultSubjectId, ProviderResultSubjectKind, ProviderResultSummary, ProviderResultTitle,
    ProviderResultWorkerId, ProviderRunnerPolicyBinding, ProviderSchemaVersion,
    ProviderWorkflowSource, RenewProviderResult, RepositoryVisibility, RetryProviderResult,
    RichCheckCapability, SaveDesiredProviderResult, StatusHistoryModel,
};
use url::Url;
use uuid::Uuid;

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
        ProviderWorkflowSource::Directory(ProviderRepositoryPath::new(".ci/workflows").unwrap()),
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

fn subject() -> ProviderResultSubject {
    ProviderResultSubject::new(
        ProviderResultSubjectId::from_uuid(Uuid::from_u128(4)).unwrap(),
        &connection(),
        GitObjectId::from_provider_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
        ProviderResultName::new("build").unwrap(),
        ProviderResultDetailsUrl::new(Url::parse("https://ci.example/runs/5").unwrap()).unwrap(),
        ProviderResultSubjectKind::WorkflowRun {
            run_id: RunId::from_uuid(Uuid::from_u128(5)),
        },
        1,
        UnixMillis::new(2_000),
    )
    .unwrap()
}

fn projection(updated_at: i64) -> ProviderResultProjection {
    ProviderResultProjection::new(
        ProviderResultPhase::Running,
        None,
        ProviderResultTitle::new("build").unwrap(),
        ProviderResultSummary::new("running").unwrap(),
        Vec::new(),
        UnixMillis::new(updated_at),
    )
    .unwrap()
}

fn desired(generation: u64, updated_at: i64) -> DesiredProviderResult {
    DesiredProviderResult::new(generation, projection(updated_at)).unwrap()
}

fn claim(generation: u64, claimed_at: i64) -> ProviderResultClaimFence {
    ProviderResultClaimFence::new(
        subject().subject_id(),
        generation,
        ProviderResultWorkerId::from_uuid(Uuid::from_u128(9)).unwrap(),
        generation,
        UnixMillis::new(claimed_at),
        UnixMillis::new(claimed_at + 1_000),
    )
    .unwrap()
}

#[derive(Debug)]
struct MemoryOutbox(Mutex<MemoryState>);

#[derive(Debug, Default)]
struct MemoryState {
    value: Option<MemoryValue>,
    fence: u64,
}

#[derive(Debug)]
struct MemoryValue {
    subject: ProviderResultSubject,
    desired: DesiredProviderResult,
    attempts: u16,
    available_at: UnixMillis,
    claim: Option<ProviderResultClaimFence>,
    completed: bool,
    failed: bool,
}

impl Default for MemoryOutbox {
    fn default() -> Self {
        Self(Mutex::new(MemoryState::default()))
    }
}

impl ProviderResultRepository for MemoryOutbox {
    fn load_workflow_subject(
        &self,
        run_id: RunId,
    ) -> ProviderResultFuture<'_, Option<ProviderResultSubject>> {
        Box::pin(async move {
            Ok(self
                .0
                .lock()
                .unwrap()
                .value
                .as_ref()
                .filter(|value| {
                    value.subject.subject() == &ProviderResultSubjectKind::WorkflowRun { run_id }
                })
                .map(|value| value.subject.clone()))
        })
    }

    fn save_desired(
        &self,
        request: SaveDesiredProviderResult,
    ) -> ProviderResultFuture<'_, ProviderResultSaveOutcome> {
        Box::pin(async move {
            let (subject, projection) = request.into_parts();
            let mut state = self.0.lock().unwrap();
            let outcome = match &state.value {
                None => ProviderResultSaveOutcome::Inserted,
                Some(current) if current.subject != subject => {
                    return Err(ProviderResultRepositoryError::Conflict);
                }
                Some(current) if current.desired.projection() == &projection => {
                    return Ok(ProviderResultSaveOutcome::Unchanged);
                }
                Some(current) if current.desired.updated_at() >= projection.updated_at() => {
                    return Err(ProviderResultRepositoryError::Conflict);
                }
                Some(_) => ProviderResultSaveOutcome::Superseded,
            };
            let generation = state
                .value
                .as_ref()
                .map_or(1, |current| current.desired.generation() + 1);
            let desired = DesiredProviderResult::new(generation, projection)
                .map_err(|_| ProviderResultRepositoryError::Corrupt)?;
            let available_at = desired.updated_at();
            state.value = Some(MemoryValue {
                subject,
                desired,
                attempts: 0,
                available_at,
                claim: None,
                completed: false,
                failed: false,
            });
            Ok(outcome)
        })
    }

    fn claim_result(
        &self,
        request: ClaimProviderResult,
    ) -> ProviderResultFuture<'_, Option<ClaimedProviderResult>> {
        Box::pin(async move {
            let mut state = self.0.lock().unwrap();
            let eligible = state.value.as_ref().is_some_and(|value| {
                value.subject.connection_id() == request.connection_id()
                    && !value.completed
                    && !value.failed
                    && value.attempts < MAX_PROVIDER_RESULT_PUBLICATION_ATTEMPTS
                    && value.available_at <= request.claimed_at()
                    && value
                        .claim
                        .is_none_or(|claim| claim.expires_at() <= request.claimed_at())
            });
            if !eligible {
                return Ok(None);
            }
            state.fence += 1;
            let fence = state.fence;
            let value = state.value.as_mut().unwrap();
            value.attempts += 1;
            let expires_at = UnixMillis::new(
                request.claimed_at().get() + i64::try_from(request.lease_millis()).unwrap(),
            );
            let claim = ProviderResultClaimFence::new(
                value.subject.subject_id(),
                value.desired.generation(),
                request.worker_id(),
                fence,
                request.claimed_at(),
                expires_at,
            )
            .unwrap();
            value.claim = Some(claim);
            ClaimedProviderResult::new(
                value.subject.clone(),
                value.desired.clone(),
                claim,
                value.attempts,
                None,
                None,
            )
            .map(Some)
            .map_err(|_| ProviderResultRepositoryError::Corrupt)
        })
    }

    fn complete_result(&self, request: CompleteProviderResult) -> ProviderResultFuture<'_, ()> {
        Box::pin(async move {
            let mut state = self.0.lock().unwrap();
            let value = state
                .value
                .as_mut()
                .ok_or(ProviderResultRepositoryError::NotFound)?;
            if value.claim != Some(request.claim())
                || request.evidence().generation() != value.desired.generation()
            {
                return Err(ProviderResultRepositoryError::StaleClaim);
            }
            value.completed = true;
            value.claim = None;
            Ok(())
        })
    }

    fn renew_result(
        &self,
        request: RenewProviderResult,
    ) -> ProviderResultFuture<'_, ProviderResultClaimFence> {
        Box::pin(async move {
            let mut state = self.0.lock().unwrap();
            let value = state
                .value
                .as_mut()
                .ok_or(ProviderResultRepositoryError::NotFound)?;
            if value.claim != Some(request.claim()) {
                return Err(ProviderResultRepositoryError::StaleClaim);
            }
            let renewed = ProviderResultClaimFence::new(
                request.claim().subject_id(),
                request.claim().generation(),
                request.claim().worker_id(),
                request.claim().fence(),
                request.claim().claimed_at(),
                UnixMillis::new(
                    request.renewed_at().get() + i64::try_from(request.lease_millis()).unwrap(),
                ),
            )
            .map_err(|_| ProviderResultRepositoryError::Corrupt)?;
            value.claim = Some(renewed);
            Ok(renewed)
        })
    }

    fn retry_result(&self, request: RetryProviderResult) -> ProviderResultFuture<'_, ()> {
        Box::pin(async move {
            let mut state = self.0.lock().unwrap();
            let value = state
                .value
                .as_mut()
                .ok_or(ProviderResultRepositoryError::NotFound)?;
            if value.claim != Some(request.claim()) {
                return Err(ProviderResultRepositoryError::StaleClaim);
            }
            value.available_at = request.retry_at();
            value.claim = None;
            Ok(())
        })
    }

    fn fail_result(&self, request: FailProviderResult) -> ProviderResultFuture<'_, ()> {
        Box::pin(async move {
            let mut state = self.0.lock().unwrap();
            let value = state
                .value
                .as_mut()
                .ok_or(ProviderResultRepositoryError::NotFound)?;
            if value.claim != Some(request.claim()) {
                return Err(ProviderResultRepositoryError::StaleClaim);
            }
            value.failed = true;
            value.claim = None;
            Ok(())
        })
    }
}

#[test]
fn mutable_result_marker_is_stable_across_generations() {
    let first =
        ClaimedProviderResult::new(subject(), desired(1, 2_001), claim(1, 2_002), 1, None, None)
            .unwrap();
    let second =
        ClaimedProviderResult::new(subject(), desired(2, 2_003), claim(2, 2_004), 1, None, None)
            .unwrap();

    assert_eq!(first.marker(), second.marker());
    assert_eq!(
        first.marker().as_str(),
        "automata-result:00000000-0000-0000-0000-000000000004"
    );
}

#[test]
fn continuation_is_bounded_digest_bound_and_debug_redacted() {
    let first = ProviderResultContinuation::new(
        ProviderSchemaVersion::new(1).unwrap(),
        b"secret adapter cursor".to_vec(),
    )
    .unwrap();
    let second = ProviderResultContinuation::new(
        ProviderSchemaVersion::new(2).unwrap(),
        b"secret adapter cursor".to_vec(),
    )
    .unwrap();

    assert_ne!(first.digest(), second.digest());
    assert!(!format!("{first:?}").contains("secret adapter cursor"));
    assert!(
        ProviderResultContinuation::new(ProviderSchemaVersion::new(1).unwrap(), Vec::new())
            .is_err()
    );
    assert!(
        ProviderResultContinuation::new(
            ProviderSchemaVersion::new(1).unwrap(),
            vec![0; automata_ci_provider::MAX_PROVIDER_RESULT_CONTINUATION_BYTES + 1],
        )
        .is_err()
    );
}

#[test]
fn mutable_publication_requires_and_preserves_one_native_binding() {
    let external_id = ExternalResultId::new("check-1").unwrap();
    let first =
        ClaimedProviderResult::new(subject(), desired(1, 2_001), claim(1, 2_002), 1, None, None)
            .unwrap();
    assert_eq!(
        ProviderResultPublicationEvidence::new(
            &first,
            ProviderResultPublicationModel::MutableRichCheck,
            None,
            first.desired().digest(),
            UnixMillis::new(2_003),
        ),
        Err(ProviderResultModelError::InvalidPublicationBinding)
    );

    let later = ClaimedProviderResult::new(
        subject(),
        desired(2, 3_003),
        claim(2, 3_004),
        1,
        Some(automata_ci_provider::ProviderResultBinding::new(
            external_id.clone(),
        )),
        None,
    )
    .unwrap();
    assert!(
        ProviderResultPublicationEvidence::new(
            &later,
            ProviderResultPublicationModel::MutableRichCheck,
            Some(external_id),
            later.desired().digest(),
            UnixMillis::new(3_005),
        )
        .is_ok()
    );
    assert_eq!(
        ProviderResultPublicationEvidence::new(
            &later,
            ProviderResultPublicationModel::MutableRichCheck,
            Some(ExternalResultId::new("check-2").unwrap()),
            later.desired().digest(),
            UnixMillis::new(3_005),
        ),
        Err(ProviderResultModelError::InvalidPublicationBinding)
    );
    assert_eq!(
        ProviderResultPublicationEvidence::new(
            &later,
            ProviderResultPublicationModel::AppendOnlyCommitStatus,
            None,
            later.desired().digest(),
            UnixMillis::new(3_005),
        ),
        Err(ProviderResultModelError::InvalidPublicationBinding)
    );
}

#[tokio::test]
async fn newer_generation_supersedes_and_fences_old_claim_without_a_bridge() {
    let outbox = MemoryOutbox::default();
    assert_eq!(
        outbox
            .save_desired(SaveDesiredProviderResult::new(subject(), projection(2_001)).unwrap())
            .await
            .unwrap(),
        ProviderResultSaveOutcome::Inserted
    );
    assert_eq!(
        outbox
            .load_workflow_subject(RunId::from_uuid(Uuid::from_u128(5)))
            .await
            .unwrap(),
        Some(subject())
    );
    assert!(
        outbox
            .load_workflow_subject(RunId::from_uuid(Uuid::from_u128(6)))
            .await
            .unwrap()
            .is_none()
    );
    let first = outbox
        .claim_result(
            ClaimProviderResult::new(
                subject().connection_id(),
                ProviderResultWorkerId::from_uuid(Uuid::from_u128(9)).unwrap(),
                UnixMillis::new(2_002),
                1_000,
            )
            .unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        outbox
            .save_desired(SaveDesiredProviderResult::new(subject(), projection(2_003)).unwrap())
            .await
            .unwrap(),
        ProviderResultSaveOutcome::Superseded
    );
    let stale_evidence = ProviderResultPublicationEvidence::new(
        &first,
        ProviderResultPublicationModel::MutableRichCheck,
        Some(ExternalResultId::new("check-1").unwrap()),
        first.desired().digest(),
        first.claimed_at(),
    )
    .unwrap();
    assert_eq!(
        outbox
            .complete_result(CompleteProviderResult::new(first.claim(), stale_evidence).unwrap())
            .await,
        Err(ProviderResultRepositoryError::StaleClaim)
    );
    let second = outbox
        .claim_result(
            ClaimProviderResult::new(
                subject().connection_id(),
                ProviderResultWorkerId::from_uuid(Uuid::from_u128(9)).unwrap(),
                UnixMillis::new(2_004),
                1_000,
            )
            .unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second.desired().generation(), 2);
    assert_eq!(second.marker(), first.marker());
}

#[tokio::test]
async fn changed_projections_must_advance_durable_time() {
    let outbox = MemoryOutbox::default();
    outbox
        .save_desired(SaveDesiredProviderResult::new(subject(), projection(2_001)).unwrap())
        .await
        .unwrap();
    let changed_at_same_time = ProviderResultProjection::new(
        ProviderResultPhase::Running,
        None,
        ProviderResultTitle::new("build").unwrap(),
        ProviderResultSummary::new("different").unwrap(),
        Vec::new(),
        UnixMillis::new(2_001),
    )
    .unwrap();
    assert_eq!(
        outbox
            .save_desired(SaveDesiredProviderResult::new(subject(), changed_at_same_time).unwrap())
            .await,
        Err(ProviderResultRepositoryError::Conflict)
    );
    assert_eq!(
        outbox
            .save_desired(SaveDesiredProviderResult::new(subject(), projection(2_000)).unwrap())
            .await,
        Err(ProviderResultRepositoryError::Conflict)
    );
}

#[tokio::test]
async fn retries_and_terminal_failures_consume_only_the_exact_fence() {
    let outbox = MemoryOutbox::default();
    outbox
        .save_desired(SaveDesiredProviderResult::new(subject(), projection(2_001)).unwrap())
        .await
        .unwrap();
    let worker = ProviderResultWorkerId::from_uuid(Uuid::from_u128(9)).unwrap();
    let first = outbox
        .claim_result(
            ClaimProviderResult::new(
                subject().connection_id(),
                worker,
                UnixMillis::new(2_002),
                1_000,
            )
            .unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    let retry = RetryProviderResult::new(
        first.claim(),
        UnixMillis::new(2_003),
        UnixMillis::new(2_100),
        None,
    )
    .unwrap();
    outbox.retry_result(retry).await.unwrap();
    assert!(
        outbox
            .claim_result(
                ClaimProviderResult::new(
                    subject().connection_id(),
                    worker,
                    UnixMillis::new(2_099),
                    1_000,
                )
                .unwrap(),
            )
            .await
            .unwrap()
            .is_none()
    );
    let second = outbox
        .claim_result(
            ClaimProviderResult::new(
                subject().connection_id(),
                worker,
                UnixMillis::new(2_100),
                1_000,
            )
            .unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_ne!(second.claim().fence(), first.claim().fence());
    assert!(
        outbox
            .fail_result(
                FailProviderResult::new(
                    first.claim(),
                    UnixMillis::new(2_101),
                    ProviderResultFailureKind::Conflict,
                )
                .unwrap(),
            )
            .await
            .is_err()
    );
    outbox
        .fail_result(
            FailProviderResult::new(
                second.claim(),
                UnixMillis::new(2_101),
                ProviderResultFailureKind::Conflict,
            )
            .unwrap(),
        )
        .await
        .unwrap();
}

#[test]
fn presentation_is_canonical_bounded_and_independent_of_provider_features() {
    let annotation = ProviderResultAnnotation::new(
        ProviderRepositoryPath::new("src/main.rs").unwrap(),
        7,
        9,
        ProviderResultAnnotationLevel::Warning,
        ProviderResultAnnotationTitle::new("lint").unwrap(),
        ProviderResultAnnotationMessage::new("first line\nsecond line").unwrap(),
    )
    .unwrap();
    let completed = DesiredProviderResult::new(
        1,
        ProviderResultProjection::new(
            ProviderResultPhase::Completed,
            Some(ProviderResultConclusion::Success),
            ProviderResultTitle::new("build").unwrap(),
            ProviderResultSummary::new("complete").unwrap(),
            vec![annotation.clone()],
            UnixMillis::new(2_001),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(completed.annotations(), std::slice::from_ref(&annotation));
    assert_eq!(
        completed.conclusion(),
        Some(ProviderResultConclusion::Success)
    );
    assert!(
        ProviderResultProjection::new(
            ProviderResultPhase::Running,
            Some(ProviderResultConclusion::Success),
            ProviderResultTitle::new("build").unwrap(),
            ProviderResultSummary::new("running").unwrap(),
            Vec::new(),
            UnixMillis::new(2_001),
        )
        .is_err()
    );
    assert!(
        ProviderResultProjection::new(
            ProviderResultPhase::Completed,
            Some(ProviderResultConclusion::Failure),
            ProviderResultTitle::new("build").unwrap(),
            ProviderResultSummary::new("failed").unwrap(),
            vec![annotation.clone(), annotation],
            UnixMillis::new(2_001),
        )
        .is_err()
    );
    assert!(
        ProviderResultDetailsUrl::new(
            Url::parse("https://ci.example/runs/5?credential=secret").unwrap()
        )
        .is_err()
    );
    assert!(ProviderResultRetryAfter::new(0).is_err());
    assert!(ProviderResultRetryAfter::new(24 * 60 * 60 * 1_000).is_ok());
    assert!(ProviderResultRetryAfter::new(24 * 60 * 60 * 1_000 + 1).is_err());

    let first = ProviderResultAnnotation::new(
        ProviderRepositoryPath::new("src/main.rs").unwrap(),
        1,
        1,
        ProviderResultAnnotationLevel::Notice,
        ProviderResultAnnotationTitle::new("a").unwrap(),
        ProviderResultAnnotationMessage::new("first").unwrap(),
    )
    .unwrap();
    let second = ProviderResultAnnotation::new(
        ProviderRepositoryPath::new("src/main.rs").unwrap(),
        1,
        1,
        ProviderResultAnnotationLevel::Notice,
        ProviderResultAnnotationTitle::new("b").unwrap(),
        ProviderResultAnnotationMessage::new("second").unwrap(),
    )
    .unwrap();
    let projection = |annotations| {
        DesiredProviderResult::new(
            1,
            ProviderResultProjection::new(
                ProviderResultPhase::Running,
                None,
                ProviderResultTitle::new("build").unwrap(),
                ProviderResultSummary::new("running").unwrap(),
                annotations,
                UnixMillis::new(2_001),
            )
            .unwrap(),
        )
        .unwrap()
    };
    assert_eq!(
        projection(vec![first.clone(), second.clone()]).digest(),
        projection(vec![second, first]).digest()
    );
}

#[test]
fn result_subject_ids_are_deterministic_connection_scoped_version_eight() {
    let kind = ProviderResultSubjectKind::WorkflowRun {
        run_id: RunId::from_uuid(Uuid::from_u128(42)),
    };
    let first = ProviderResultSubjectId::derive(connection().connection_id(), &kind);
    assert_eq!(
        first,
        ProviderResultSubjectId::derive(connection().connection_id(), &kind)
    );
    assert_eq!(first.as_uuid().get_version_num(), 8);
    assert_ne!(
        first,
        ProviderResultSubjectId::derive(
            ProviderConnectionId::from_uuid(Uuid::from_u128(99)).unwrap(),
            &kind,
        )
    );
    assert_ne!(
        first,
        ProviderResultSubjectId::derive(
            connection().connection_id(),
            &ProviderResultSubjectKind::WorkflowRun {
                run_id: RunId::from_uuid(Uuid::from_u128(43)),
            },
        )
    );
}

#[test]
fn workflow_result_observations_are_exact_and_non_nil() {
    let run_id = RunId::from_uuid(Uuid::from_u128(42));
    let observation = automata_ci_provider::ProviderWorkflowResultObservation::new(
        run_id,
        automata_ci_provider::ProviderWorkflowRunState::Completed(
            ProviderResultConclusion::Success,
        ),
        UnixMillis::new(2_000),
    )
    .unwrap();
    assert_eq!(observation.run_id(), run_id);
    assert_eq!(
        observation.state(),
        automata_ci_provider::ProviderWorkflowRunState::Completed(
            ProviderResultConclusion::Success
        )
    );
    assert_eq!(observation.updated_at(), UnixMillis::new(2_000));
    assert_eq!(
        automata_ci_provider::ProviderWorkflowResultObservation::new(
            RunId::from_uuid(Uuid::nil()),
            automata_ci_provider::ProviderWorkflowRunState::Queued,
            UnixMillis::new(2_000),
        ),
        Err(ProviderResultModelError::InvalidRun)
    );
    assert_eq!(
        automata_ci_provider::ProviderWorkflowResultObservation::new(
            run_id,
            automata_ci_provider::ProviderWorkflowRunState::Running,
            UnixMillis::new(-1),
        ),
        Err(ProviderResultModelError::InvalidTimestamp)
    );
}

#[test]
fn evidence_is_bound_to_the_exact_claim_fence() {
    let claimed = ClaimedProviderResult::new(
        subject(),
        desired(1, 2_001),
        ProviderResultClaimFence::new(
            subject().subject_id(),
            1,
            ProviderResultWorkerId::from_uuid(Uuid::from_u128(9)).unwrap(),
            1,
            UnixMillis::new(2_002),
            UnixMillis::new(3_002),
        )
        .unwrap(),
        1,
        None,
        None,
    )
    .unwrap();
    let evidence = ProviderResultPublicationEvidence::new(
        &claimed,
        ProviderResultPublicationModel::MutableRichCheck,
        Some(ExternalResultId::new("check-1").unwrap()),
        claimed.desired().digest(),
        UnixMillis::new(2_003),
    )
    .unwrap();
    let later_claim = ProviderResultClaimFence::new(
        claimed.subject().subject_id(),
        1,
        ProviderResultWorkerId::from_uuid(Uuid::from_u128(9)).unwrap(),
        2,
        UnixMillis::new(3_003),
        UnixMillis::new(4_003),
    )
    .unwrap();
    assert!(CompleteProviderResult::new(later_claim, evidence).is_err());
}

#[test]
fn publication_commands_reject_the_exclusive_deadline() {
    let claimed =
        ClaimedProviderResult::new(subject(), desired(1, 2_001), claim(1, 2_002), 1, None, None)
            .unwrap();
    let deadline = claimed.claim().expires_at();

    assert!(
        ProviderResultPublicationEvidence::new(
            &claimed,
            ProviderResultPublicationModel::MutableRichCheck,
            None,
            claimed.desired().digest(),
            deadline,
        )
        .is_err()
    );
    assert!(
        RetryProviderResult::new(
            claimed.claim(),
            deadline,
            UnixMillis::new(deadline.get() + 1),
            None,
        )
        .is_err()
    );
    assert!(
        FailProviderResult::new(
            claimed.claim(),
            deadline,
            ProviderResultFailureKind::Conflict,
        )
        .is_err()
    );
}

#[test]
fn result_claim_renewal_strictly_extends_one_live_fence() {
    let current = claim(1, 2_002);
    let renewal = RenewProviderResult::new(current, UnixMillis::new(2_500), 1_000).unwrap();
    assert_eq!(renewal.claim(), current);
    assert_eq!(renewal.renewed_at(), UnixMillis::new(2_500));
    assert!(RenewProviderResult::new(current, current.expires_at(), 1_000).is_err());
    assert!(RenewProviderResult::new(current, UnixMillis::new(2_500), 500).is_err());
}

#[test]
fn publication_models_require_their_exact_declared_capability() {
    let statuses = ProviderCapabilities::new([ProviderCapability::CommitStatus(
        CommitStatusCapability::new(
            [CommitStatusState::Pending, CommitStatusState::Success],
            StatusHistoryModel::AppendOnly,
        )
        .unwrap(),
    )])
    .unwrap();
    assert!(ProviderResultPublicationModel::AppendOnlyCommitStatus.is_declared_by(&statuses));
    assert!(!ProviderResultPublicationModel::MutableRichCheck.is_declared_by(&statuses));

    let rich = ProviderCapabilities::new([ProviderCapability::RichChecks(
        RichCheckCapability::new(true, false, false).unwrap(),
    )])
    .unwrap();
    assert!(ProviderResultPublicationModel::MutableRichCheck.is_declared_by(&rich));
    assert!(!ProviderResultPublicationModel::AppendOnlyCommitStatus.is_declared_by(&rich));
    assert!(RichCheckCapability::new(false, false, true).is_ok());
    assert!(RichCheckCapability::new(false, false, false).is_err());
}
