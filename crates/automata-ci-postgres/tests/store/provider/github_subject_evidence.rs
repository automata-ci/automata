use crate::github_manifest_fixture;

use automata_ci_core::{RunId, Sha256Digest, UnixMillis, WorkflowId, WorkflowJobKey};
use automata_ci_store::{
    AcceptManifestPinnedGithubDelivery, AcceptManifestPinnedGithubRepositoryDispatch,
    AcceptProviderDelivery, AdmissionObject, AdmissionRepository, AdmitLogicalWorkflowRun,
    AdmittedLogicalWorkflowJob, AuthenticatedGithubDeliveryClaim, BeginGithubCheckRunCreate,
    BindGithubCheckRun, BindGithubCheckSuite, ClaimGithubCheckProjection, ClaimProviderDelivery,
    ClaimedGithubCheckProjection, CompleteGithubCheckProjection, CompleteProviderDelivery,
    EnsureGithubServerServiceAuthority, GithubAuthenticatedEvent, GithubAuthenticatedEventKind,
    GithubCheckDesiredProjection, GithubCheckDetailsTarget, GithubCheckHeadSha, GithubCheckName,
    GithubCheckProjectionAction, GithubCheckProjectionOutbox as _, GithubCheckProjectionWorkerId,
    GithubCheckRunBindingFence, GithubCheckRunId, GithubCheckSubjectId,
    GithubCheckSubjectRepository as _, GithubCheckSubjectTarget, GithubCheckSuiteId,
    GithubCheckTerminalCause, GithubProviderManifest, GithubProviderManifestLimits,
    GithubProviderManifestRepository as _, GithubProviderManifestRevision, GithubProviderOrigins,
    GithubProviderWebhookVerifierFingerprint, GithubProviderWorkflowSelection,
    GithubRepositoryDispatchEvidenceRepository as _, GithubRepositoryDispatchResolution,
    GithubRepositoryDispatchResolutionAuthority, GithubRepositoryName,
    GithubServerServiceAppClientId, GithubServerServiceAppId, GithubServerServiceAuthorityId,
    GithubServerServiceAuthorityIdentity, GithubServerServiceAuthorityRepository as _,
    GithubServerServiceJwtIssuer, GithubServerServiceRevision, GithubServerServiceScope,
    GithubSubjectEvidenceRepository as _, GithubSubjectEvidenceStoreError,
    LogicalWorkflowAdmissionRepository as _, LogicalWorkflowAdmissionStoreError,
    LogicalWorkflowInvocationId, LogicalWorkflowJobId, LogicalWorkflowJobKind,
    ManifestPinnedGithubDeliveryReceipt, ObjectKey, ProviderConnectionId,
    ProviderDeliveryClaimOwnerId, ProviderDeliveryFailureKind, ProviderDeliveryId,
    ProviderDeliveryIdentity, ProviderDeliveryRepository as _, ProviderDeliveryState,
    ProviderDeliveryStoreError, ProviderDeliveryWorkflowConclusion,
    ProviderDeliveryWorkflowInventory, ProviderDeliveryWorkflowInventoryEntry,
    ProviderDeliveryWorkflowOutcome, ProviderDeliveryWorkflowSourceState, ProviderInstallationId,
    ProviderRepositoryCoordinates, ProviderRepositoryId, ProviderRepositoryOwnerId,
    ProviderRepositoryVisibility, RecordProviderDeliveryWorkflowProgress,
    RegisterProviderDeliveryWorkflowInventory, RejectProviderDelivery,
    ResolveGithubRepositoryDispatch, StartGithubCheckProjection, StoreError, TenantScope,
    WorkflowAdmissionIdempotency, WorkflowSnapshotId,
};
use uuid::Uuid;

use crate::support::{TestDatabase, TestResult, run_with_database};

const INSTALLATION_ID: u64 = 101;
const REPOSITORY_ID: u64 = 202;
const APP_ID: u64 = 303;
const OWNER_ID: u64 = 404;
const HEAD_SHA: [u8; 20] = [9; 20];
const CREATE_BEFORE_ADMISSION_WORKFLOW_PATH: &str = ".ci/workflows/build.yml";

#[derive(Debug, Eq, PartialEq, sqlx::FromRow)]
struct AcceptedDeliveryState {
    github_repository_owner_id: i64,
    provider_manifest_revision: i64,
    checks_authority_id: Uuid,
    checks_authority_identity_digest: Vec<u8>,
    github_check_subject_id: Uuid,
    github_check_head_sha: Vec<u8>,
    desired_state: String,
    outbox_state: String,
    outbox_attempt_count: i16,
    outbox_claim_fence: i64,
}

#[derive(Debug, Eq, PartialEq, sqlx::FromRow)]
struct CheckProjectionState {
    workflow_run_id: Option<Uuid>,
    linked_at_ms: Option<i64>,
    desired_state: String,
    desired_conclusion: Option<String>,
    terminal_cause: Option<String>,
    desired_revision: i64,
    desired_updated_at_ms: i64,
    outbox_state: String,
    attempted_revision: Option<i64>,
    attempt_count: i16,
    claim_fence: i64,
    projected_revision: i64,
    external_suite_id: Option<i64>,
    external_run_id: Option<i64>,
    provider_state: Option<String>,
    provider_conclusion: Option<String>,
    provider_observed_at_ms: Option<i64>,
    state_updated_at_ms: i64,
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn atomic_acceptance_pins_owner_manifest_authority_check_and_exact_replay() -> TestResult {
    run_with_database(|database| async move {
        let fixture = bootstrap(
            &database,
            "subject-evidence-main",
            0x100,
            ProviderRepositoryVisibility::Public,
            100,
        )
        .await?;
        let accepted_at = database
            .store()
            .load_current_github_provider_manifest(&fixture.tenant, fixture.connection)
            .await?
            .activated_at()
            .expect("bootstrapped manifest is current");
        let request = acceptance(
            &fixture,
            "delivery-main",
            OWNER_ID,
            OWNER_ID,
            HEAD_SHA,
            accepted_at.get(),
            7,
        );
        let accepted = database
            .store()
            .accept_manifest_pinned_github_delivery(request.clone())
            .await?;
        assert_eq!(accepted.repository_id(), fixture.manifest.repository_id());
        assert_eq!(accepted.repository_owner_id().get(), OWNER_ID);
        assert_eq!(accepted.manifest_revision().get(), 1);
        assert_eq!(accepted.manifest_digest(), fixture.manifest.digest());
        assert_eq!(
            accepted.evidence().manifest().github_repository_owner_id(),
            Some(ProviderRepositoryOwnerId::new(OWNER_ID)?)
        );
        assert_eq!(accepted.accepted_at(), accepted_at);
        assert_eq!(accepted.evidence().manifest(), &fixture.manifest);
        assert_eq!(
            accepted.evidence().checks_authority().authority_id(),
            fixture.checks_authority.authority_id()
        );
        assert!(accepted.evidence().private_source_authority().is_none());
        assert_eq!(accepted.evidence().check_head_sha().as_bytes(), HEAD_SHA);

        let row: AcceptedDeliveryState = sqlx::query_as(
            r"
                SELECT evidence.github_repository_owner_id,
                       evidence.provider_manifest_revision,
                       evidence.checks_authority_id,
                       evidence.checks_authority_identity_digest,
                       evidence.github_check_subject_id,
                       evidence.github_check_head_sha,
                       subject.desired_state, outbox.state AS outbox_state,
                       outbox.attempt_count AS outbox_attempt_count,
                       outbox.claim_fence AS outbox_claim_fence
                FROM github_provider_delivery_evidence AS evidence
                JOIN github_check_subjects AS subject
                  ON subject.id = evidence.github_check_subject_id
                JOIN github_check_projection_outbox AS outbox
                  ON outbox.subject_id = subject.id
                WHERE evidence.provider_delivery_id = $1
                ",
        )
        .bind(accepted.delivery_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(row.github_repository_owner_id, 404);
        assert_eq!(row.provider_manifest_revision, 1);
        assert_eq!(
            row.checks_authority_id,
            fixture.checks_authority.authority_id().as_uuid()
        );
        assert_eq!(
            row.checks_authority_identity_digest.as_slice(),
            fixture.checks_authority.identity_digest().as_bytes()
        );
        assert_eq!(
            row.github_check_subject_id,
            accepted.check_subject_id().as_uuid()
        );
        assert_eq!(row.github_check_head_sha, HEAD_SHA);
        assert_eq!(
            (
                row.desired_state.as_str(),
                row.outbox_state.as_str(),
                row.outbox_attempt_count,
                row.outbox_claim_fence,
            ),
            ("queued", "pending", 0, 0)
        );

        let lookup = database
            .store()
            .load_manifest_pinned_github_delivery_evidence(&fixture.tenant, accepted.delivery_id())
            .await?;
        assert_eq!(lookup, *accepted.evidence());
        assert_eq!(
            format!("{lookup:?}"),
            "ManifestPinnedGithubDeliveryEvidence([REDACTED])"
        );

        let replay = database
            .store()
            .accept_manifest_pinned_github_delivery(request.clone())
            .await?;
        assert_eq!(replay, accepted);

        let different_owner = acceptance(
            &fixture,
            "delivery-main",
            OWNER_ID + 1,
            OWNER_ID + 1,
            HEAD_SHA,
            accepted_at.get(),
            7,
        );
        assert!(matches!(
            database
                .store()
                .accept_manifest_pinned_github_delivery(different_owner)
                .await,
            Err(GithubSubjectEvidenceStoreError::ReplayConflict)
        ));
        let different_head = acceptance(
            &fixture,
            "delivery-main",
            OWNER_ID,
            OWNER_ID,
            [8; 20],
            accepted_at.get(),
            7,
        );
        assert!(matches!(
            database
                .store()
                .accept_manifest_pinned_github_delivery(different_head)
                .await,
            Err(GithubSubjectEvidenceStoreError::ReplayConflict)
        ));

        // Rotate verifier evidence only. The historical delivery retains the
        // old full manifest while both revisions keep the same exact service
        // authority selectors.
        let rotated = manifest(
            fixture.tenant.clone(),
            fixture.connection,
            ProviderRepositoryVisibility::Public,
            ManifestRevisions::new(2, 1, 2, 1),
            [7; 32],
            [8; 32],
        );
        database
            .store()
            .bootstrap_github_provider_repository(
                github_manifest_fixture::fixture_github_repository_bootstrap(
                    rotated.clone(),
                    UnixMillis::new(300),
                ),
            )
            .await?;
        let rotated_activated_at = database
            .store()
            .load_current_github_provider_manifest(&fixture.tenant, fixture.connection)
            .await?
            .activated_at()
            .expect("rotated manifest is current");
        let historical_replay = database
            .store()
            .accept_manifest_pinned_github_delivery(request)
            .await?;
        assert_eq!(historical_replay, accepted);
        assert_eq!(historical_replay.evidence().manifest(), &fixture.manifest);
        let next = database
            .store()
            .accept_manifest_pinned_github_delivery(acceptance_for_manifest(
                &fixture,
                &rotated,
                "delivery-next",
                OWNER_ID,
                OWNER_ID,
                HEAD_SHA,
                rotated_activated_at.get(),
                8,
            ))
            .await?;
        assert_eq!(next.manifest_revision().get(), 2);
        assert_eq!(next.evidence().manifest(), &rotated);

        assert_constraint(
            &sqlx::query(
                "UPDATE github_provider_delivery_evidence \
                 SET github_repository_owner_id = github_repository_owner_id + 1 \
                 WHERE provider_delivery_id = $1",
            )
            .bind(accepted.delivery_id().as_uuid())
            .execute(database.pool())
            .await
            .expect_err("delivery evidence must be immutable"),
            "github_provider_delivery_evidence_immutable",
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn repository_dispatch_resolution_is_claim_fenced_atomic_and_exactly_replayed() -> TestResult
{
    run_with_database(|database| async move {
        let fixture = bootstrap(
            &database,
            "subject-evidence-repository-dispatch",
            0x180,
            ProviderRepositoryVisibility::Private,
            100,
        )
        .await?;
        let request = repository_dispatch_acceptance(
            &fixture,
            "delivery-repository-dispatch",
            fixture.activated_at.get(),
            0x31,
        );
        let accepted = database
            .store()
            .accept_manifest_pinned_github_repository_dispatch(request)
            .await?;
        assert_eq!(
            accepted.evidence().event(),
            &GithubAuthenticatedEvent::new(
                GithubAuthenticatedEventKind::RepositoryDispatch,
                "refs/heads/main",
            )?
        );
        assert!(accepted.evidence().private_source_authority().is_some());
        let before_resolution: (i64, i64, i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM provider_delivery_inbox),
                (SELECT count(*) FROM github_repository_dispatch_pending_evidence),
                (SELECT count(*) FROM github_provider_delivery_evidence),
                (SELECT count(*) FROM github_check_subjects),
                (SELECT count(*) FROM github_check_projection_outbox)
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(before_resolution, (1, 1, 0, 0, 0));

        let exact_replay = database
            .store()
            .accept_manifest_pinned_github_repository_dispatch(repository_dispatch_acceptance(
                &fixture,
                "delivery-repository-dispatch",
                fixture.activated_at.get(),
                0x31,
            ))
            .await?;
        assert_eq!(exact_replay, accepted);

        let claim = claim_delivery(&database, accepted.delivery_id(), 0x181, 60_000).await?;
        let resolution = GithubRepositoryDispatchResolution::new(
            GithubCheckHeadSha::new(HEAD_SHA)?,
            GithubRepositoryDispatchResolutionAuthority::PrivateSourceAuthority,
        );
        let resolve = ResolveGithubRepositoryDispatch::new(
            accepted.evidence().clone(),
            claim,
            resolution,
            claim.claimed_at(),
        )?;
        let resolved = database
            .store()
            .resolve_github_repository_dispatch(resolve)
            .await?;
        assert_eq!(resolved.repository_dispatch_resolution(), Some(resolution));
        assert_eq!(resolved.check_head_sha().as_bytes(), HEAD_SHA);
        assert_eq!(
            resolved.private_source_authority(),
            accepted.evidence().private_source_authority()
        );
        let after_resolution: (i64, i64, i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM provider_delivery_inbox),
                (SELECT count(*) FROM github_repository_dispatch_pending_evidence),
                (SELECT count(*) FROM github_provider_delivery_evidence),
                (SELECT count(*) FROM github_check_subjects),
                (SELECT count(*) FROM github_check_projection_outbox)
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(after_resolution, (1, 1, 1, 1, 1));
        assert_eq!(
            database
                .store()
                .load_manifest_pinned_github_delivery_evidence(
                    &fixture.tenant,
                    accepted.delivery_id(),
                )
                .await?,
            resolved
        );

        let resolution_replay = database
            .store()
            .resolve_github_repository_dispatch(ResolveGithubRepositoryDispatch::new(
                accepted.evidence().clone(),
                claim,
                resolution,
                claim.claimed_at(),
            )?)
            .await?;
        assert_eq!(resolution_replay, resolved);
        assert_eq!(
            sqlx::query_as::<_, (i64, i64)>(
                "SELECT (SELECT count(*) FROM github_check_subjects), \
                        (SELECT count(*) FROM github_check_projection_outbox)",
            )
            .fetch_one(database.pool())
            .await?,
            (1, 1)
        );

        let changed_resolution = GithubRepositoryDispatchResolution::new(
            GithubCheckHeadSha::new([8; 20])?,
            GithubRepositoryDispatchResolutionAuthority::PrivateSourceAuthority,
        );
        assert!(matches!(
            database
                .store()
                .resolve_github_repository_dispatch(ResolveGithubRepositoryDispatch::new(
                    accepted.evidence().clone(),
                    claim,
                    changed_resolution,
                    claim.claimed_at(),
                )?)
                .await,
            Err(GithubSubjectEvidenceStoreError::ReplayConflict)
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn authenticated_event_readers_reject_forward_envelope_schemas() -> TestResult {
    run_with_database(|database| async move {
        let fixture = bootstrap(
            &database,
            "subject-evidence-forward-event-envelope",
            0x182,
            ProviderRepositoryVisibility::Private,
            100,
        )
        .await?;
        sqlx::query(
            "ALTER TABLE github_repository_dispatch_pending_evidence \
             DISABLE TRIGGER github_repository_dispatch_pending_no_update_delete",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            "ALTER TABLE github_repository_dispatch_pending_evidence \
             DROP CONSTRAINT github_repository_dispatch_pending_shape",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            "ALTER TABLE github_provider_delivery_evidence \
             DISABLE TRIGGER github_provider_delivery_evidence_no_update_delete",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            "ALTER TABLE github_provider_delivery_evidence \
             DROP CONSTRAINT github_provider_delivery_evidence_authenticated_event",
        )
        .execute(database.pool())
        .await?;

        let pending_request = repository_dispatch_acceptance(
            &fixture,
            "delivery-forward-pending-event-envelope",
            fixture.activated_at.get(),
            0x32,
        );
        let pending = database
            .store()
            .accept_manifest_pinned_github_repository_dispatch(pending_request)
            .await?;
        sqlx::query(
            "UPDATE github_repository_dispatch_pending_evidence \
             SET authenticated_event_envelope_version = 2 \
             WHERE provider_delivery_id = $1",
        )
        .bind(pending.delivery_id().as_uuid())
        .execute(database.pool())
        .await?;
        assert!(matches!(
            database
                .store()
                .accept_manifest_pinned_github_repository_dispatch(repository_dispatch_acceptance(
                    &fixture,
                    "delivery-forward-pending-event-envelope",
                    fixture.activated_at.get(),
                    0x32,
                ),)
                .await,
            Err(GithubSubjectEvidenceStoreError::CorruptData)
        ));

        let resolved_request = repository_dispatch_acceptance(
            &fixture,
            "delivery-forward-resolved-event-envelope",
            fixture.activated_at.get(),
            0x33,
        );
        let accepted = database
            .store()
            .accept_manifest_pinned_github_repository_dispatch(resolved_request)
            .await?;
        let claim = claim_delivery(&database, accepted.delivery_id(), 0x183, 60_000).await?;
        let resolution = GithubRepositoryDispatchResolution::new(
            GithubCheckHeadSha::new(HEAD_SHA)?,
            GithubRepositoryDispatchResolutionAuthority::PrivateSourceAuthority,
        );
        database
            .store()
            .resolve_github_repository_dispatch(ResolveGithubRepositoryDispatch::new(
                accepted.evidence().clone(),
                claim,
                resolution,
                claim.claimed_at(),
            )?)
            .await?;
        sqlx::query(
            "UPDATE github_provider_delivery_evidence \
             SET authenticated_event_envelope_version = 2 \
             WHERE provider_delivery_id = $1",
        )
        .bind(accepted.delivery_id().as_uuid())
        .execute(database.pool())
        .await?;
        assert!(matches!(
            database
                .store()
                .load_manifest_pinned_github_delivery_evidence(
                    &fixture.tenant,
                    accepted.delivery_id(),
                )
                .await,
            Err(GithubSubjectEvidenceStoreError::CorruptData)
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn rejected_pre_admission_delivery_terminalizes_check_as_failure() -> TestResult {
    run_with_database(|database| async move {
        let fixture = bootstrap(
            &database,
            "subject-evidence-rejected-check",
            0x230,
            ProviderRepositoryVisibility::Public,
            100,
        )
        .await?;
        let accepted = database
            .store()
            .accept_manifest_pinned_github_delivery(acceptance(
                &fixture,
                "delivery-rejected-check",
                OWNER_ID,
                OWNER_ID,
                HEAD_SHA,
                fixture.activated_at.get(),
                13,
            ))
            .await?;
        let claim = claim_delivery(&database, accepted.delivery_id(), 0x231, 60_000).await?;
        let receipt = database
            .store()
            .reject_provider_delivery(RejectProviderDelivery::new(
                claim.claim(),
                ProviderDeliveryFailureKind::new("github.subject_evidence.mismatch")?,
                claim.claimed_at(),
            )?)
            .await?;
        assert_eq!(receipt.state(), ProviderDeliveryState::Rejected);
        assert_pre_admission_terminal_check(
            &database,
            accepted.check_subject_id().as_uuid(),
            claim.claimed_at(),
            "failure",
            "system_unknown",
        )
        .await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn noncanonical_check_state_rolls_back_delivery_completion() -> TestResult {
    run_with_database(|database| async move {
        let fixture = bootstrap(
            &database,
            "subject-evidence-terminal-rollback",
            0x238,
            ProviderRepositoryVisibility::Public,
            100,
        )
        .await?;
        let accepted = database
            .store()
            .accept_manifest_pinned_github_delivery(acceptance(
                &fixture,
                "delivery-terminal-rollback",
                OWNER_ID,
                OWNER_ID,
                HEAD_SHA,
                fixture.activated_at.get(),
                13,
            ))
            .await?;
        let claim = claim_delivery(&database, accepted.delivery_id(), 0x239, 60_000).await?;
        database
            .store()
            .start_github_check_projection(StartGithubCheckProjection::new(
                GithubCheckSubjectTarget::new(fixture.tenant.clone(), accepted.check_subject_id()),
                claim.claimed_at(),
            )?)
            .await?;
        let check_before =
            load_check_projection(&database, accepted.check_subject_id().as_uuid()).await?;
        let completion =
            CompleteProviderDelivery::new(claim.claim(), Vec::new(), claim.claimed_at())?;

        assert!(matches!(
            database
                .store()
                .complete_provider_delivery(completion)
                .await,
            Err(ProviderDeliveryStoreError::CorruptData)
        ));
        let inbox_state: String =
            sqlx::query_scalar("SELECT state FROM provider_delivery_inbox WHERE id = $1")
                .bind(accepted.delivery_id().as_uuid())
                .fetch_one(database.pool())
                .await?;
        let outcome_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM provider_delivery_workflow_outcomes WHERE inbox_id = $1",
        )
        .bind(accepted.delivery_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(inbox_state, "claimed");
        assert_eq!(outcome_count, 0);
        assert_eq!(
            load_check_projection(&database, accepted.check_subject_id().as_uuid()).await?,
            check_before
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn all_direct_inventory_fans_out_with_durable_partial_progress() -> TestResult {
    run_with_database(|database| async move {
        const BUILD_PATH: &str = ".ci/workflows/build.yml";
        const BROKEN_PATH: &str = ".ci/workflows/broken.yaml";
        const SKIPPED_PATH: &str = ".ci/workflows/docs.yml";
        let fixture = bootstrap_all_direct(
            &database,
            "subject-evidence-all-direct",
            0x248,
            ProviderRepositoryVisibility::Public,
            100,
        )
        .await?;
        let accepted = database
            .store()
            .accept_manifest_pinned_github_delivery(acceptance(
                &fixture,
                "delivery-all-direct",
                OWNER_ID,
                OWNER_ID,
                HEAD_SHA,
                fixture.activated_at.get(),
                20,
            ))
            .await?;
        let claim = claim_delivery(&database, accepted.delivery_id(), 0x249, 60_000).await?;
        let inventory = ProviderDeliveryWorkflowInventory::new(
            fixture.manifest.digest(),
            "0909090909090909090909090909090909090909",
            Sha256Digest::from_bytes([0x55; 32]),
            vec![
                ProviderDeliveryWorkflowInventoryEntry::new(
                    SKIPPED_PATH,
                    ProviderDeliveryWorkflowSourceState::Ready(Sha256Digest::from_bytes(
                        [0x33; 32],
                    )),
                )?,
                ProviderDeliveryWorkflowInventoryEntry::new(
                    BUILD_PATH,
                    ProviderDeliveryWorkflowSourceState::Ready(Sha256Digest::from_bytes(
                        [0x31; 32],
                    )),
                )?,
                ProviderDeliveryWorkflowInventoryEntry::new(
                    BROKEN_PATH,
                    ProviderDeliveryWorkflowSourceState::Oversized,
                )?,
            ],
        )?;
        let registered = database
            .store()
            .register_provider_delivery_workflow_inventory(
                RegisterProviderDeliveryWorkflowInventory::new(
                    claim.claim(),
                    inventory.clone(),
                    claim.claimed_at(),
                )?,
            )
            .await?;
        assert_eq!(registered.inventory(), &inventory);
        assert!(registered.outcomes().is_empty());

        let command = logical_command_at_path(
            &fixture,
            "logical-all-direct-build",
            0x62,
            21,
            0x2_800,
            claim.claimed_at(),
            BUILD_PATH,
            [0x31; 32],
        );
        let run_id = command.run_id();
        database
            .store()
            .admit_authenticated_github_delivery(command, claim, claim.claimed_at())
            .await?;

        let admitted = ProviderDeliveryWorkflowOutcome::new(
            BUILD_PATH,
            ProviderDeliveryWorkflowConclusion::Admitted { run_id },
        )?;
        let failed = ProviderDeliveryWorkflowOutcome::new(
            BROKEN_PATH,
            ProviderDeliveryWorkflowConclusion::Failed {
                failure_kind: ProviderDeliveryFailureKind::new("github.workflow.source_oversized")?,
            },
        )?;
        let skipped = ProviderDeliveryWorkflowOutcome::new(
            SKIPPED_PATH,
            ProviderDeliveryWorkflowConclusion::Skipped {
                reason: ProviderDeliveryFailureKind::new("github.workflow.not_selected")?,
            },
        )?;
        for outcome in [&admitted, &failed] {
            assert_eq!(
                database
                    .store()
                    .record_provider_delivery_workflow_progress(
                        RecordProviderDeliveryWorkflowProgress::new(
                            claim.claim(),
                            inventory.digest(),
                            outcome.clone(),
                            claim.claimed_at(),
                        )?,
                    )
                    .await?,
                *outcome
            );
        }

        let incomplete = CompleteProviderDelivery::new(
            claim.claim(),
            vec![admitted.clone(), failed.clone()],
            claim.claimed_at(),
        )?;
        assert!(
            database
                .store()
                .complete_provider_delivery(incomplete)
                .await
                .is_err(),
            "completion must wait for every durable inventory path"
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT state FROM provider_delivery_inbox WHERE id = $1"
            )
            .bind(accepted.delivery_id().as_uuid())
            .fetch_one(database.pool())
            .await?,
            "claimed"
        );

        database
            .store()
            .record_provider_delivery_workflow_progress(
                RecordProviderDeliveryWorkflowProgress::new(
                    claim.claim(),
                    inventory.digest(),
                    skipped.clone(),
                    claim.claimed_at(),
                )?,
            )
            .await?;

        let unsealed_subject_id = Uuid::new_v4();
        let unsealed_external_id = format!("automata-check:{unsealed_subject_id}");
        let inserted = sqlx::query(
            r"
            INSERT INTO github_check_subjects (
                id, tenant_id, repository_id, provider_delivery_id, subject_key,
                provider_connection_id, provider_installation_id,
                github_repository_id, github_app_id, head_sha, check_name,
                external_id, created_at_ms, desired_updated_at_ms,
                github_repository_name
            )
            SELECT $1, tenant_id, repository_id, provider_delivery_id, $2,
                   provider_connection_id, provider_installation_id,
                   github_repository_id, github_app_id, head_sha, check_name,
                   $3, created_at_ms, desired_updated_at_ms,
                   github_repository_name
            FROM github_check_subjects
            WHERE id = $4
            ",
        )
        .bind(unsealed_subject_id)
        .bind(SKIPPED_PATH)
        .bind(unsealed_external_id)
        .bind(accepted.check_subject_id().as_uuid())
        .execute(database.pool())
        .await?;
        assert_eq!(inserted.rows_affected(), 1);

        let replay = database
            .store()
            .register_provider_delivery_workflow_inventory(
                RegisterProviderDeliveryWorkflowInventory::new(
                    claim.claim(),
                    inventory,
                    claim.claimed_at(),
                )?,
            )
            .await?;
        assert_eq!(replay.outcomes().len(), 3);
        let completion = CompleteProviderDelivery::new(
            claim.claim(),
            replay.outcomes().to_vec(),
            claim.claimed_at(),
        )?;
        assert_eq!(
            database
                .store()
                .complete_provider_delivery(completion)
                .await?
                .state(),
            ProviderDeliveryState::Completed
        );

        assert_pre_admission_terminal_check(
            &database,
            accepted.check_subject_id().as_uuid(),
            claim.claimed_at(),
            "failure",
            "workflow_failure",
        )
        .await?;
        let failed_subject_id: Uuid = sqlx::query_scalar(
            r"
            SELECT id
            FROM github_check_subjects
            WHERE provider_delivery_id = $1
              AND subject_key = $2
            ",
        )
        .bind(accepted.delivery_id().as_uuid())
        .bind(BROKEN_PATH)
        .fetch_one(database.pool())
        .await?;
        assert_pre_admission_terminal_check(
            &database,
            failed_subject_id,
            claim.claimed_at(),
            "failure",
            "workflow_failure",
        )
        .await?;
        let checks: Vec<(String, Option<Uuid>, String, Option<String>)> = sqlx::query_as(
            r"
            SELECT subject_key, workflow_run_id, desired_state, desired_conclusion
            FROM github_check_subjects
            WHERE provider_delivery_id = $1
              AND subject_key <> '.ci/workflows'
            ORDER BY subject_key
            ",
        )
        .bind(accepted.delivery_id().as_uuid())
        .fetch_all(database.pool())
        .await?;
        assert_eq!(
            checks,
            vec![
                (
                    BROKEN_PATH.to_owned(),
                    None,
                    "completed".to_owned(),
                    Some("failure".to_owned()),
                ),
                (
                    BUILD_PATH.to_owned(),
                    Some(run_id.as_uuid()),
                    "in_progress".to_owned(),
                    None,
                ),
                (SKIPPED_PATH.to_owned(), None, "queued".to_owned(), None,),
            ]
        );

        let expected_claimable: std::collections::BTreeSet<Uuid> = sqlx::query_scalar(
            r"
                SELECT id
                FROM github_check_subjects
                WHERE provider_delivery_id = $1
                  AND (
                    id = $2
                    OR subject_key = $3
                    OR subject_key = $4
                  )
                ",
        )
        .bind(accepted.delivery_id().as_uuid())
        .bind(accepted.check_subject_id().as_uuid())
        .bind(BUILD_PATH)
        .bind(BROKEN_PATH)
        .fetch_all(database.pool())
        .await?
        .into_iter()
        .collect();
        assert_eq!(
            expected_claimable.len(),
            3,
            "aggregate plus two workflow Checks"
        );
        assert!(!expected_claimable.contains(&unsealed_subject_id));
        let observed_at = database_now(database.pool()).await?;
        let expires_at = checked_add_millis(observed_at, 30_000)?;
        let mut claimed = std::collections::BTreeSet::new();
        let mut projections = Vec::new();
        for _ in 0..expected_claimable.len() {
            let projection = database
                .store()
                .claim_github_check_projection(ClaimGithubCheckProjection::new(
                    fixture.connection,
                    GithubCheckProjectionWorkerId::from_uuid(Uuid::new_v4())?,
                    observed_at,
                    expires_at,
                )?)
                .await?
                .expect("every sealed delivery Check must be claimable");
            claimed.insert(projection.claim().subject_id().as_uuid());
            projections.push(projection);
        }
        assert_eq!(claimed, expected_claimable);
        let failed_projection_index = projections
            .iter()
            .position(|projection| projection.claim().subject_id().as_uuid() == failed_subject_id)
            .expect("failed workflow Check claim");
        let failed_projection = projections.swap_remove(failed_projection_index);
        let delivered =
            deliver_terminal_check_projection(&database, fixture.connection, failed_projection)
                .await?;
        assert_eq!(delivered.outbox_state, "delivered");
        assert_eq!(delivered.projected_revision, 2);
        assert_eq!(delivered.provider_state.as_deref(), Some("completed"));
        assert_eq!(delivered.provider_conclusion.as_deref(), Some("failure"));
        assert!(delivered.provider_observed_at_ms.is_some());
        assert!(
            database
                .store()
                .claim_github_check_projection(ClaimGithubCheckProjection::new(
                    fixture.connection,
                    GithubCheckProjectionWorkerId::from_uuid(Uuid::new_v4())?,
                    observed_at,
                    expires_at,
                )?)
                .await?
                .is_none(),
            "inventory-valid but evidence-unsealed Check must not be claimable"
        );
        assert_fanout_evidence_is_sealed_after_completion(&database, accepted.delivery_id())
            .await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn webhook_aggregate_create_before_admission_reconciles_with_stable_target() -> TestResult {
    run_with_database(|database| async move {
        let scenario = setup_create_before_admission(&database).await?;
        let pending_create = begin_aggregate_create(&database, &scenario).await?;
        let admitted = admit_create_before_admission_workflow(&database, &scenario).await?;
        reconcile_aggregate_create(&database, &scenario, pending_create, admitted).await?;
        Ok(())
    })
    .await
}

struct CreateBeforeAdmissionScenario {
    fixture: Fixture,
    accepted: ManifestPinnedGithubDeliveryReceipt,
    delivery_claim: AuthenticatedGithubDeliveryClaim,
}

struct PendingAggregateCreate {
    worker: GithubCheckProjectionWorkerId,
    suite_id: GithubCheckSuiteId,
    reconcile_not_before: UnixMillis,
}

#[derive(Clone, Copy)]
struct AdmittedWorkflowCheck {
    run_id: RunId,
    subject_id: GithubCheckSubjectId,
}

async fn setup_create_before_admission(
    database: &TestDatabase,
) -> TestResult<CreateBeforeAdmissionScenario> {
    let fixture = bootstrap_all_direct(
        database,
        "subject-evidence-create-before-link",
        0x28a,
        ProviderRepositoryVisibility::Public,
        100,
    )
    .await?;
    let accepted = database
        .store()
        .accept_manifest_pinned_github_delivery(acceptance(
            &fixture,
            "delivery-create-before-link",
            OWNER_ID,
            OWNER_ID,
            HEAD_SHA,
            fixture.activated_at.get(),
            24,
        ))
        .await?;
    let delivery_claim = claim_delivery(database, accepted.delivery_id(), 0x28b, 60_000).await?;
    let inventory = ProviderDeliveryWorkflowInventory::new(
        fixture.manifest.digest(),
        "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
        Sha256Digest::from_bytes([0x56; 32]),
        vec![ProviderDeliveryWorkflowInventoryEntry::new(
            CREATE_BEFORE_ADMISSION_WORKFLOW_PATH,
            ProviderDeliveryWorkflowSourceState::Ready(Sha256Digest::from_bytes([0x36; 32])),
        )?],
    )?;
    database
        .store()
        .register_provider_delivery_workflow_inventory(
            RegisterProviderDeliveryWorkflowInventory::new(
                delivery_claim.claim(),
                inventory,
                delivery_claim.claimed_at(),
            )?,
        )
        .await?;
    Ok(CreateBeforeAdmissionScenario {
        fixture,
        accepted,
        delivery_claim,
    })
}

async fn begin_aggregate_create(
    database: &TestDatabase,
    scenario: &CreateBeforeAdmissionScenario,
) -> TestResult<PendingAggregateCreate> {
    let worker = GithubCheckProjectionWorkerId::from_uuid(Uuid::from_u128(0x28c))?;
    let subject_id = scenario.accepted.check_subject_id();
    let ensure_suite = claim_projection(
        database,
        scenario.fixture.connection,
        worker,
        60_000,
        "accepted webhook Check suite projection",
    )
    .await?;
    assert_projection(
        &ensure_suite,
        subject_id,
        GithubCheckProjectionAction::EnsureSuite,
        GithubCheckDetailsTarget::Repository,
    );
    let suite_id = GithubCheckSuiteId::new(28_001)?;
    database
        .store()
        .bind_github_check_suite(BindGithubCheckSuite::new(
            ensure_suite.claim(),
            suite_id,
            ensure_suite.claimed_at(),
        )?)
        .await?;

    let prepare = claim_projection(
        database,
        scenario.fixture.connection,
        worker,
        25,
        "accepted webhook Check create projection",
    )
    .await?;
    assert_projection(
        &prepare,
        subject_id,
        GithubCheckProjectionAction::PrepareRunCreate,
        GithubCheckDetailsTarget::Repository,
    );
    let reconcile_not_before = checked_add_millis(prepare.expires_at(), 1)?;
    database
        .store()
        .begin_github_check_run_create(BeginGithubCheckRunCreate::new(
            &prepare,
            prepare.claimed_at(),
            reconcile_not_before,
        )?)
        .await?;
    Ok(PendingAggregateCreate {
        worker,
        suite_id,
        reconcile_not_before,
    })
}

async fn admit_create_before_admission_workflow(
    database: &TestDatabase,
    scenario: &CreateBeforeAdmissionScenario,
) -> TestResult<AdmittedWorkflowCheck> {
    let admitted_at = database_now(database.pool()).await?;
    let command = logical_command_at_path(
        &scenario.fixture,
        "logical-create-before-link",
        0x66,
        25,
        0x2_8a0,
        admitted_at,
        CREATE_BEFORE_ADMISSION_WORKFLOW_PATH,
        [0x36; 32],
    );
    let run_id = command.run_id();
    database
        .store()
        .admit_authenticated_github_delivery(command, scenario.delivery_claim, admitted_at)
        .await?;
    let workflow_subject: (Uuid, Option<Uuid>) = sqlx::query_as(
        r"
        SELECT id, workflow_run_id
          FROM github_check_subjects
         WHERE provider_delivery_id = $1
           AND subject_key = $2
           AND subject_kind = 'workflow'
        ",
    )
    .bind(scenario.accepted.delivery_id().as_uuid())
    .bind(CREATE_BEFORE_ADMISSION_WORKFLOW_PATH)
    .fetch_one(database.pool())
    .await?;
    assert_eq!(workflow_subject.1, Some(run_id.as_uuid()));
    let aggregate_run: Option<Uuid> =
        sqlx::query_scalar("SELECT workflow_run_id FROM github_check_subjects WHERE id = $1")
            .bind(scenario.accepted.check_subject_id().as_uuid())
            .fetch_one(database.pool())
            .await?;
    assert_eq!(
        aggregate_run, None,
        "the delivery aggregate is not a run parent"
    );
    Ok(AdmittedWorkflowCheck {
        run_id,
        subject_id: GithubCheckSubjectId::from_uuid(workflow_subject.0)?,
    })
}

async fn reconcile_aggregate_create(
    database: &TestDatabase,
    scenario: &CreateBeforeAdmissionScenario,
    pending: PendingAggregateCreate,
    admitted: AdmittedWorkflowCheck,
) -> TestResult {
    // The admitted per-workflow root is independently claimable. Lock its
    // outbox so this proof deterministically reconciles the older aggregate.
    let mut workflow_projection_lock = database.pool().begin().await?;
    let locked: Vec<Uuid> = sqlx::query_scalar(
        "SELECT subject_id FROM github_check_projection_outbox \
         WHERE subject_id = $1 FOR UPDATE",
    )
    .bind(admitted.subject_id.as_uuid())
    .fetch_all(&mut *workflow_projection_lock)
    .await?;
    assert_eq!(locked, vec![admitted.subject_id.as_uuid()]);

    wait_until_database_at_or_after(database.pool(), pending.reconcile_not_before.get()).await?;
    let aggregate_id = scenario.accepted.check_subject_id();
    let reconcile = claim_projection(
        database,
        scenario.fixture.connection,
        pending.worker,
        60_000,
        "webhook aggregate Check create reconciliation",
    )
    .await?;
    assert_projection(
        &reconcile,
        aggregate_id,
        GithubCheckProjectionAction::ReconcileRunCreate,
        GithubCheckDetailsTarget::Repository,
    );
    database
        .store()
        .bind_github_check_run(BindGithubCheckRun::new(
            GithubCheckRunBindingFence::Reconciliation(reconcile.claim()),
            pending.suite_id,
            GithubCheckRunId::new(28_002)?,
            reconcile.claimed_at(),
        )?)
        .await?;
    workflow_projection_lock.rollback().await?;

    let workflow_ensure = claim_projection(
        database,
        scenario.fixture.connection,
        pending.worker,
        60_000,
        "admitted workflow Check suite projection",
    )
    .await?;
    assert_projection(
        &workflow_ensure,
        admitted.subject_id,
        GithubCheckProjectionAction::EnsureSuite,
        GithubCheckDetailsTarget::WorkflowRun(admitted.run_id),
    );
    Ok(())
}

async fn claim_projection(
    database: &TestDatabase,
    connection: ProviderConnectionId,
    worker: GithubCheckProjectionWorkerId,
    lease_millis: i64,
    expected: &'static str,
) -> TestResult<ClaimedGithubCheckProjection> {
    let now = database_now(database.pool()).await?;
    Ok(database
        .store()
        .claim_github_check_projection(ClaimGithubCheckProjection::new(
            connection,
            worker,
            now,
            checked_add_millis(now, lease_millis)?,
        )?)
        .await?
        .expect(expected))
}

fn assert_projection(
    projection: &ClaimedGithubCheckProjection,
    subject_id: GithubCheckSubjectId,
    action: GithubCheckProjectionAction,
    details_target: GithubCheckDetailsTarget,
) {
    assert_eq!(projection.claim().subject_id(), subject_id);
    assert_eq!(projection.action(), action);
    assert_eq!(projection.details_target(), details_target);
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn public_api_decodes_historical_manifest_profile_and_runner_policy() -> TestResult {
    run_with_database(|database| async move {
        let fixture = bootstrap(
            &database,
            "subject-evidence-main",
            0x100,
            ProviderRepositoryVisibility::Public,
            100,
        )
        .await?;
        let activated_at = database
            .store()
            .load_current_github_provider_manifest(&fixture.tenant, fixture.connection)
            .await?
            .activated_at()
            .expect("bootstrapped manifest is current");
        let accepted = database
            .store()
            .accept_manifest_pinned_github_delivery(acceptance(
                &fixture,
                "delivery-main",
                OWNER_ID,
                OWNER_ID,
                HEAD_SHA,
                activated_at.get(),
                7,
            ))
            .await?;
        let expected_manifest = fixture.manifest.clone();
        let expected_policy = expected_manifest.runner_policy().object();

        let evidence = database
            .store()
            .load_manifest_pinned_github_delivery_evidence(&fixture.tenant, accepted.delivery_id())
            .await?;
        let loaded_manifest = evidence.manifest();
        let loaded_policy = loaded_manifest.runner_policy().object();
        assert_eq!(
            loaded_manifest.authority_profile(),
            automata_ci_core::JobAuthorityProfile::Standard
        );
        assert_eq!(loaded_manifest.revision(), expected_manifest.revision());
        assert_eq!(loaded_policy.digest(), expected_policy.digest());
        assert_eq!(loaded_policy.object_key(), expected_policy.object_key());
        assert_eq!(loaded_policy.encoded_size(), expected_policy.encoded_size());
        assert_eq!(loaded_policy.media_type(), expected_policy.media_type());
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn concurrent_private_acceptance_pins_both_disjoint_authorities_once() -> TestResult {
    run_with_database(|database| async move {
        let fixture = bootstrap(
            &database,
            "subject-evidence-race",
            0x200,
            ProviderRepositoryVisibility::Private,
            100,
        )
        .await?;
        let request = acceptance(
            &fixture,
            "delivery-race",
            OWNER_ID,
            OWNER_ID,
            HEAD_SHA,
            fixture.activated_at.get(),
            11,
        );
        let store_a = database.store().clone();
        let store_b = database.store().clone();
        let request_b = request.clone();
        let (first, second) = tokio::join!(
            store_a.accept_manifest_pinned_github_delivery(request),
            store_b.accept_manifest_pinned_github_delivery(request_b),
        );
        let first = first?;
        let second = second?;
        assert_eq!(first, second);
        let private = first
            .evidence()
            .private_source_authority()
            .expect("private selector");
        assert_eq!(
            private.authority_id(),
            fixture
                .private_source_authority
                .as_ref()
                .expect("fixture private selector")
                .authority_id()
        );
        assert_ne!(
            private.authority_id(),
            first.evidence().checks_authority().authority_id()
        );
        let counts: (i64, i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM provider_delivery_inbox),
                (SELECT count(*) FROM github_provider_delivery_evidence),
                (SELECT count(*) FROM github_check_subjects),
                (SELECT count(*) FROM github_check_projection_outbox)
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(counts, (1, 1, 1, 1));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn missing_exact_service_authority_rejects_without_any_partial_write() -> TestResult {
    run_with_database(|database| async move {
        let fixture = bootstrap_manifest_only(
            &database,
            "subject-evidence-no-authority",
            0x250,
            ProviderRepositoryVisibility::Public,
            100,
        )
        .await?;
        let result = database
            .store()
            .accept_manifest_pinned_github_delivery(acceptance(
                &fixture,
                "delivery-no-authority",
                OWNER_ID,
                OWNER_ID,
                HEAD_SHA,
                fixture.activated_at.get(),
                12,
            ))
            .await;
        assert!(matches!(
            result,
            Err(GithubSubjectEvidenceStoreError::AuthorityRejected)
        ));
        let counts: (i64, i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM provider_delivery_inbox),
                (SELECT count(*) FROM github_provider_delivery_evidence),
                (SELECT count(*) FROM github_check_subjects),
                (SELECT count(*) FROM github_check_projection_outbox)
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(counts, (0, 0, 0, 0));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn expired_claim_and_unsupported_local_admission_leave_no_partial_state() -> TestResult {
    run_with_database(|database| async move {
        let fixture = bootstrap(
            &database,
            "subject-evidence-expired-local",
            0x2a0,
            ProviderRepositoryVisibility::Public,
            100,
        )
        .await?;
        let accepted = database
            .store()
            .accept_manifest_pinned_github_delivery(acceptance(
                &fixture,
                "delivery-expired-local",
                OWNER_ID,
                OWNER_ID,
                HEAD_SHA,
                fixture.activated_at.get(),
                60,
            ))
            .await?;
        let expired_claim =
            claim_delivery(&database, accepted.delivery_id(), 0x501, 60_000).await?;
        let expired_at = expired_claim.expires_at();
        let command = logical_command(
            &fixture,
            "logical-expired-local",
            0x80,
            61,
            0x4_000,
            expired_at,
        );
        let run_id = command.run_id();

        assert!(matches!(
            database
                .store()
                .admit_authenticated_github_delivery(command.clone(), expired_claim, expired_at,)
                .await,
            Err(LogicalWorkflowAdmissionStoreError::Store(
                StoreError::CorruptData(_)
            ))
        ));
        let rolled_back = admission_counts(&database, run_id).await?;
        assert_eq!(rolled_back, (0, 0, 0));

        assert!(matches!(
            database.store().admit_logical_workflow(command).await,
            Err(LogicalWorkflowAdmissionStoreError::UnsupportedAdmissionSource)
        ));
        assert_eq!(admission_counts(&database, run_id).await?, (0, 0, 0));

        let durable: (Option<Uuid>, Option<i64>, String, i64) = sqlx::query_as(
            "SELECT workflow_run_id, linked_at_ms, desired_state, desired_revision \
             FROM github_check_subjects WHERE id = $1",
        )
        .bind(accepted.check_subject_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(durable, (None, None, "queued".to_owned(), 1));
        Ok(())
    })
    .await
}
struct Fixture {
    tenant: TenantScope,
    connection: ProviderConnectionId,
    manifest: GithubProviderManifest,
    activated_at: UnixMillis,
    checks_authority: GithubServerServiceAuthorityIdentity,
    private_source_authority: Option<GithubServerServiceAuthorityIdentity>,
}

async fn bootstrap(
    database: &TestDatabase,
    tenant_id: &str,
    connection_id: u128,
    visibility: ProviderRepositoryVisibility,
    at: i64,
) -> TestResult<Fixture> {
    let fixture =
        bootstrap_manifest_only(database, tenant_id, connection_id, visibility, at).await?;
    ensure_fixture_authorities(database, fixture, at).await
}

async fn bootstrap_all_direct(
    database: &TestDatabase,
    tenant_id: &str,
    connection_id: u128,
    visibility: ProviderRepositoryVisibility,
    at: i64,
) -> TestResult<Fixture> {
    let fixture = bootstrap_manifest_only_with_selection(
        database,
        tenant_id,
        connection_id,
        visibility,
        at,
        GithubProviderWorkflowSelection::all_direct(),
    )
    .await?;
    ensure_fixture_authorities(database, fixture, at).await
}

async fn ensure_fixture_authorities(
    database: &TestDatabase,
    fixture: Fixture,
    at: i64,
) -> TestResult<Fixture> {
    database
        .store()
        .ensure_github_server_service_authority(EnsureGithubServerServiceAuthority::new(
            fixture.checks_authority.clone(),
            UnixMillis::new(at),
        )?)
        .await?;
    if let Some(private) = fixture.private_source_authority.as_ref() {
        database
            .store()
            .ensure_github_server_service_authority(EnsureGithubServerServiceAuthority::new(
                private.clone(),
                UnixMillis::new(at),
            )?)
            .await?;
    }
    Ok(fixture)
}

async fn bootstrap_manifest_only(
    database: &TestDatabase,
    tenant_id: &str,
    connection_id: u128,
    visibility: ProviderRepositoryVisibility,
    at: i64,
) -> TestResult<Fixture> {
    bootstrap_manifest_only_with_selection(
        database,
        tenant_id,
        connection_id,
        visibility,
        at,
        GithubProviderWorkflowSelection::all_direct(),
    )
    .await
}

async fn bootstrap_manifest_only_with_selection(
    database: &TestDatabase,
    tenant_id: &str,
    connection_id: u128,
    visibility: ProviderRepositoryVisibility,
    at: i64,
    selection: GithubProviderWorkflowSelection,
) -> TestResult<Fixture> {
    let tenant = TenantScope::from_authenticated_tenant_id(tenant_id)?;
    let connection = ProviderConnectionId::from_uuid(Uuid::from_u128(connection_id))?;
    let manifest = manifest_with_selection(
        tenant.clone(),
        connection,
        visibility,
        ManifestRevisions::new(1, 1, 1, 1),
        [7; 32],
        [6; 32],
        selection,
    );
    let bootstrapped = database
        .store()
        .bootstrap_github_provider_repository(
            github_manifest_fixture::fixture_github_repository_bootstrap(
                manifest.clone(),
                UnixMillis::new(at),
            ),
        )
        .await?;
    let activated_at = bootstrapped
        .manifest()
        .current()
        .activated_at()
        .expect("bootstrapped manifest is current");
    let checks_authority = authority(
        &manifest,
        GithubServerServiceScope::ChecksWrite,
        Uuid::new_v4(),
        [11; 32],
    )?;
    let private_source_authority = match visibility {
        ProviderRepositoryVisibility::Public => None,
        ProviderRepositoryVisibility::Private => Some(authority(
            &manifest,
            GithubServerServiceScope::PrivateRepositorySourceRead,
            Uuid::new_v4(),
            [12; 32],
        )?),
    };
    Ok(Fixture {
        tenant,
        connection,
        manifest,
        activated_at,
        checks_authority,
        private_source_authority,
    })
}

#[derive(Clone, Copy)]
struct ManifestRevisions {
    manifest: u64,
    app: u64,
    verifier: u64,
    policy: u64,
}

impl ManifestRevisions {
    const fn new(manifest: u64, app: u64, verifier: u64, policy: u64) -> Self {
        Self {
            manifest,
            app,
            verifier,
            policy,
        }
    }
}

fn manifest(
    tenant: TenantScope,
    connection: ProviderConnectionId,
    visibility: ProviderRepositoryVisibility,
    revisions: ManifestRevisions,
    spki: [u8; 32],
    verifier: [u8; 32],
) -> GithubProviderManifest {
    manifest_with_selection(
        tenant,
        connection,
        visibility,
        revisions,
        spki,
        verifier,
        GithubProviderWorkflowSelection::all_direct(),
    )
}

fn manifest_with_selection(
    tenant: TenantScope,
    connection: ProviderConnectionId,
    visibility: ProviderRepositoryVisibility,
    revisions: ManifestRevisions,
    spki: [u8; 32],
    verifier: [u8; 32],
    selection: GithubProviderWorkflowSelection,
) -> GithubProviderManifest {
    let runtime_policy = github_manifest_fixture::fixture_github_runtime_policy(revisions.policy);
    GithubProviderManifest::new_with_workflow_selection(
        tenant,
        connection,
        ProviderInstallationId::new(INSTALLATION_ID).expect("installation"),
        ProviderRepositoryId::new(REPOSITORY_ID).expect("repository"),
        GithubRepositoryName::new("automata-ci/automata").expect("repository name"),
        visibility,
        GithubServerServiceAppId::new(APP_ID).expect("App"),
        GithubServerServiceAppClientId::new("Iv1.8a61f9b3a7aba766").expect("client ID"),
        GithubServerServiceJwtIssuer::AppClientId,
        Sha256Digest::from_bytes(spki),
        GithubServerServiceRevision::new(revisions.app).expect("App revision"),
        GithubProviderWebhookVerifierFingerprint::from_sha256(Sha256Digest::from_bytes(verifier))
            .expect("verifier fingerprint"),
        GithubServerServiceRevision::new(revisions.verifier).expect("verifier revision"),
        GithubServerServiceRevision::new(revisions.policy).expect("policy revision"),
        automata_ci_core::JobAuthorityProfile::Standard,
        runtime_policy.runner_policy,
        runtime_policy.revision,
        runtime_policy.semantic_digest,
        selection,
        GithubCheckName::new("Automata CI").expect("Check name"),
        GithubProviderOrigins::github_dot_com(),
        GithubProviderManifestLimits::github_dot_com_ci(),
        GithubProviderManifestRevision::new(revisions.manifest).expect("manifest revision"),
    )
    .with_repository_owner_id(ProviderRepositoryOwnerId::new(OWNER_ID).expect("repository owner"))
}

fn authority(
    manifest: &GithubProviderManifest,
    scope: GithubServerServiceScope,
    id: Uuid,
    fingerprint: [u8; 32],
) -> TestResult<GithubServerServiceAuthorityIdentity> {
    Ok(GithubServerServiceAuthorityIdentity::new(
        manifest.tenant().clone(),
        GithubServerServiceAuthorityId::from_uuid(id)?,
        manifest.repository_id(),
        manifest.connection_id(),
        manifest.installation_id(),
        manifest.github_app_id(),
        manifest.github_repository_id(),
        manifest.github_repository_name().clone(),
        scope,
        manifest.app_client_id().clone(),
        manifest.jwt_issuer(),
        manifest.app_key_spki_sha256(),
        manifest.app_configuration_revision(),
        manifest.policy_revision(),
        Sha256Digest::from_bytes(fingerprint),
    )?)
}

fn acceptance(
    fixture: &Fixture,
    delivery_key: &str,
    signed_owner_id: u64,
    configured_owner_id: u64,
    head_sha: [u8; 20],
    accepted_at: i64,
    digest_byte: u8,
) -> AcceptManifestPinnedGithubDelivery {
    acceptance_for_manifest(
        fixture,
        &fixture.manifest,
        delivery_key,
        signed_owner_id,
        configured_owner_id,
        head_sha,
        accepted_at,
        digest_byte,
    )
}

fn repository_dispatch_acceptance(
    fixture: &Fixture,
    delivery_key: &str,
    accepted_at: i64,
    digest_byte: u8,
) -> AcceptManifestPinnedGithubRepositoryDispatch {
    let identity = ProviderDeliveryIdentity::new(
        fixture.tenant.clone(),
        "github",
        fixture.connection,
        ProviderInstallationId::new(INSTALLATION_ID).expect("installation"),
        ProviderRepositoryCoordinates::new(
            ProviderRepositoryId::new(REPOSITORY_ID).expect("repository"),
            fixture.manifest.repository_visibility(),
            "automata-ci/automata",
        )
        .expect("repository coordinates"),
        delivery_key,
    )
    .expect("delivery identity");
    AcceptManifestPinnedGithubRepositoryDispatch::new(
        AcceptProviderDelivery::new(
            identity,
            Sha256Digest::from_bytes([digest_byte; 32]),
            AdmissionObject::new_event(
                Sha256Digest::from_bytes([digest_byte.wrapping_add(1); 32]),
                ObjectKey::new(format!("github/events/{delivery_key}")).expect("event object key"),
                512,
                "application/vnd.automata.github-authenticated-event+json",
            )
            .expect("event object"),
            UnixMillis::new(accepted_at),
        )
        .expect("delivery"),
        ProviderRepositoryOwnerId::new(OWNER_ID).expect("signed owner"),
        ProviderRepositoryOwnerId::new(OWNER_ID).expect("configured owner"),
        GithubAuthenticatedEvent::new(
            GithubAuthenticatedEventKind::RepositoryDispatch,
            "refs/heads/main",
        )
        .expect("repository dispatch event"),
        fixture.manifest.webhook_verifier_fingerprint(),
        fixture.manifest.webhook_verifier_revision(),
    )
    .expect("repository dispatch acceptance")
}

#[allow(clippy::too_many_arguments)]
fn acceptance_for_manifest(
    fixture: &Fixture,
    manifest: &GithubProviderManifest,
    delivery_key: &str,
    signed_owner_id: u64,
    configured_owner_id: u64,
    head_sha: [u8; 20],
    accepted_at: i64,
    digest_byte: u8,
) -> AcceptManifestPinnedGithubDelivery {
    let identity = ProviderDeliveryIdentity::new(
        fixture.tenant.clone(),
        "github",
        fixture.connection,
        ProviderInstallationId::new(INSTALLATION_ID).expect("installation"),
        ProviderRepositoryCoordinates::new(
            ProviderRepositoryId::new(REPOSITORY_ID).expect("repository"),
            fixture.manifest.repository_visibility(),
            "automata-ci/automata",
        )
        .expect("repository coordinates"),
        delivery_key,
    )
    .expect("delivery identity");
    AcceptManifestPinnedGithubDelivery::new(
        AcceptProviderDelivery::new(
            identity,
            Sha256Digest::from_bytes([digest_byte; 32]),
            AdmissionObject::new_event(
                Sha256Digest::from_bytes([digest_byte.wrapping_add(1); 32]),
                ObjectKey::new(format!("github/events/{delivery_key}")).expect("event object key"),
                512,
                "application/vnd.automata.github-authenticated-event+json",
            )
            .expect("event object"),
            UnixMillis::new(accepted_at),
        )
        .expect("delivery"),
        ProviderRepositoryOwnerId::new(signed_owner_id).expect("signed owner"),
        ProviderRepositoryOwnerId::new(configured_owner_id).expect("configured owner"),
        automata_ci_store::GithubAuthenticatedEvent::new(
            automata_ci_store::GithubAuthenticatedEventKind::Push,
            "refs/heads/main",
        )
        .expect("authenticated event"),
        GithubCheckHeadSha::new(head_sha).expect("head SHA"),
        manifest.webhook_verifier_fingerprint(),
        manifest.webhook_verifier_revision(),
    )
    .expect("GitHub acceptance")
}

async fn claim_delivery(
    database: &TestDatabase,
    delivery_id: ProviderDeliveryId,
    owner_seed: u128,
    duration_millis: i64,
) -> TestResult<AuthenticatedGithubDeliveryClaim> {
    let owner = ProviderDeliveryClaimOwnerId::from_uuid(Uuid::from_u128(owner_seed))?;
    let observed_at = database_now(database.pool()).await?;
    let expires_at = checked_add_millis(observed_at, duration_millis)?;
    let claimed = database
        .store()
        .claim_provider_delivery(ClaimProviderDelivery::new(owner, observed_at, expires_at)?)
        .await?
        .expect("accepted delivery must be claimable");
    assert_eq!(claimed.claim().delivery_id(), delivery_id);
    Ok(AuthenticatedGithubDeliveryClaim::new(
        claimed.claim(),
        claimed.attempt(),
        claimed.claimed_at(),
        claimed.expires_at(),
    )?)
}

async fn database_now(pool: &sqlx::PgPool) -> TestResult<UnixMillis> {
    Ok(UnixMillis::new(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(pool)
            .await?,
    ))
}

async fn wait_until_database_at_or_after(pool: &sqlx::PgPool, target: i64) -> TestResult {
    for _ in 0..5_000 {
        if database_now(pool).await?.get() >= target {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    Err("database clock did not reach Check reconciliation time".into())
}

fn checked_add_millis(base: UnixMillis, duration_millis: i64) -> TestResult<UnixMillis> {
    Ok(UnixMillis::new(
        base.get()
            .checked_add(duration_millis)
            .ok_or("test timestamp overflow")?,
    ))
}

async fn load_check_projection(
    database: &TestDatabase,
    subject_id: Uuid,
) -> TestResult<CheckProjectionState> {
    Ok(sqlx::query_as(
        r"
        SELECT subject.workflow_run_id, subject.linked_at_ms,
               subject.desired_state, subject.desired_conclusion,
               subject.terminal_cause, subject.desired_revision,
               subject.desired_updated_at_ms, outbox.state AS outbox_state,
               outbox.attempted_revision, outbox.attempt_count,
               outbox.claim_fence, outbox.projected_revision,
               outbox.external_suite_id, outbox.external_run_id,
               outbox.provider_state, outbox.provider_conclusion,
               outbox.provider_observed_at_ms,
               outbox.state_updated_at_ms
        FROM github_check_subjects AS subject
        JOIN github_check_projection_outbox AS outbox
          ON outbox.subject_id = subject.id
        WHERE subject.id = $1
        ",
    )
    .bind(subject_id)
    .fetch_one(database.pool())
    .await?)
}

async fn assert_pre_admission_terminal_check(
    database: &TestDatabase,
    subject_id: Uuid,
    terminal_at: UnixMillis,
    conclusion: &str,
    cause: &str,
) -> TestResult<CheckProjectionState> {
    let state = load_check_projection(database, subject_id).await?;
    assert_eq!(state.workflow_run_id, None);
    assert_eq!(state.linked_at_ms, None);
    assert_eq!(state.desired_state, "completed");
    assert_eq!(state.desired_conclusion.as_deref(), Some(conclusion));
    assert_eq!(state.terminal_cause.as_deref(), Some(cause));
    assert_eq!(state.desired_revision, 2);
    assert_eq!(state.desired_updated_at_ms, terminal_at.get());
    assert_eq!(state.outbox_state, "pending");
    assert_eq!(state.attempted_revision, None);
    assert_eq!(state.attempt_count, 0);
    assert_eq!(state.claim_fence, 0);
    assert_eq!(state.projected_revision, 0);
    assert_eq!(state.external_suite_id, None);
    assert_eq!(state.external_run_id, None);
    assert_eq!(state.provider_state, None);
    assert_eq!(state.provider_conclusion, None);
    assert_eq!(state.provider_observed_at_ms, None);
    assert_eq!(state.state_updated_at_ms, terminal_at.get());
    Ok(state)
}

async fn claim_check_projection(
    database: &TestDatabase,
    connection_id: ProviderConnectionId,
) -> TestResult<ClaimedGithubCheckProjection> {
    let observed_at = database_now(database.pool()).await?;
    let expires_at = checked_add_millis(observed_at, 30_000)?;
    Ok(database
        .store()
        .claim_github_check_projection(ClaimGithubCheckProjection::new(
            connection_id,
            GithubCheckProjectionWorkerId::from_uuid(Uuid::new_v4())?,
            observed_at,
            expires_at,
        )?)
        .await?
        .expect("failed workflow Check must remain claimable through delivery"))
}

async fn deliver_terminal_check_projection(
    database: &TestDatabase,
    connection_id: ProviderConnectionId,
    ensure_suite: ClaimedGithubCheckProjection,
) -> TestResult<CheckProjectionState> {
    let expected =
        GithubCheckDesiredProjection::terminal(GithubCheckTerminalCause::WorkflowFailure);
    let subject_id = ensure_suite.claim().subject_id().as_uuid();
    assert_eq!(
        ensure_suite.action(),
        GithubCheckProjectionAction::EnsureSuite
    );
    assert_eq!(ensure_suite.desired(), expected);
    assert_eq!(ensure_suite.desired_revision(), 2);

    let suite_id = GithubCheckSuiteId::new(70_001)?;
    database
        .store()
        .bind_github_check_suite(BindGithubCheckSuite::new(
            ensure_suite.claim(),
            suite_id,
            ensure_suite.claimed_at(),
        )?)
        .await?;

    let create = claim_check_projection(database, connection_id).await?;
    assert_eq!(create.claim().subject_id().as_uuid(), subject_id);
    assert_eq!(
        create.action(),
        GithubCheckProjectionAction::PrepareRunCreate
    );
    assert_eq!(create.desired(), expected);
    assert_eq!(create.desired_revision(), 2);
    let reconcile_not_before = checked_add_millis(create.expires_at(), 1)?;
    let create_fence = database
        .store()
        .begin_github_check_run_create(BeginGithubCheckRunCreate::new(
            &create,
            create.claimed_at(),
            reconcile_not_before,
        )?)
        .await?;

    let run_id = GithubCheckRunId::new(80_001)?;
    database
        .store()
        .bind_github_check_run(BindGithubCheckRun::new(
            GithubCheckRunBindingFence::Create(create_fence),
            suite_id,
            run_id,
            create.claimed_at(),
        )?)
        .await?;

    let publish = claim_check_projection(database, connection_id).await?;
    assert_eq!(publish.claim().subject_id().as_uuid(), subject_id);
    assert_eq!(publish.action(), GithubCheckProjectionAction::Publish);
    assert_eq!(publish.suite_id(), Some(suite_id));
    assert_eq!(publish.run_id(), Some(run_id));
    assert_eq!(publish.desired(), expected);
    assert_eq!(publish.desired_revision(), 2);
    let delivered_at = publish.claimed_at();
    database
        .store()
        .complete_github_check_projection(CompleteGithubCheckProjection::new(
            publish.claim(),
            publish.desired(),
            delivered_at,
        )?)
        .await?;

    let delivered = load_check_projection(database, subject_id).await?;
    assert_eq!(delivered.external_suite_id, Some(70_001));
    assert_eq!(delivered.external_run_id, Some(80_001));
    assert_eq!(delivered.provider_observed_at_ms, Some(delivered_at.get()));
    Ok(delivered)
}

async fn assert_fanout_evidence_is_sealed_after_completion(
    database: &TestDatabase,
    delivery_id: ProviderDeliveryId,
) -> TestResult {
    for statement in [
        "UPDATE provider_delivery_workflow_inventories \
         SET registered_at_ms = registered_at_ms WHERE inbox_id = $1",
        "UPDATE provider_delivery_workflow_inventory_entries \
         SET ordinal = ordinal WHERE inbox_id = $1",
        "UPDATE provider_delivery_workflow_progress \
         SET recorded_at_ms = recorded_at_ms WHERE inbox_id = $1",
        "DELETE FROM provider_delivery_workflow_progress WHERE inbox_id = $1",
    ] {
        let error = sqlx::query(statement)
            .bind(delivery_id.as_uuid())
            .execute(database.pool())
            .await
            .expect_err("fan-out evidence is append-only");
        assert_constraint(&error, "provider_delivery_workflow_progress_immutable");
    }

    let late_inventory = sqlx::query(
        r"
        INSERT INTO provider_delivery_workflow_inventories
        SELECT * FROM provider_delivery_workflow_inventories WHERE inbox_id = $1
        ",
    )
    .bind(delivery_id.as_uuid())
    .execute(database.pool())
    .await
    .expect_err("completed delivery rejects a late inventory");
    assert_constraint(
        &late_inventory,
        "provider_delivery_workflow_inventory_live_authority",
    );

    let late_entry = sqlx::query(
        r"
        INSERT INTO provider_delivery_workflow_inventory_entries (
            inbox_id, tenant_id, ordinal, workflow_path, source_state, source_digest
        )
        SELECT inbox_id, tenant_id, 4, '.ci/workflows/late.yml', 'empty', NULL
        FROM provider_delivery_workflow_inventories WHERE inbox_id = $1
        ",
    )
    .bind(delivery_id.as_uuid())
    .execute(database.pool())
    .await
    .expect_err("completed delivery rejects a late inventory entry");
    assert_constraint(
        &late_entry,
        "provider_delivery_workflow_inventory_entry_live_authority",
    );

    let late_progress = sqlx::query(
        r"
        INSERT INTO provider_delivery_workflow_progress (
            inbox_id, tenant_id, workflow_path, inventory_digest,
            outcome_kind, run_id, failure_kind, recorded_at_ms
        )
        SELECT inbox_id, tenant_id, '.ci/workflows/late.yml', inventory_digest,
               'skipped', NULL, 'github.workflow.not_selected', registered_at_ms
        FROM provider_delivery_workflow_inventories WHERE inbox_id = $1
        ",
    )
    .bind(delivery_id.as_uuid())
    .execute(database.pool())
    .await
    .expect_err("completed delivery rejects late workflow progress");
    assert_constraint(
        &late_progress,
        "provider_delivery_workflow_progress_live_authority",
    );

    let truncate = sqlx::query("TRUNCATE provider_delivery_workflow_progress")
        .execute(database.pool())
        .await
        .expect_err("fan-out evidence rejects truncation");
    assert_constraint(&truncate, "provider_delivery_workflow_progress_immutable");
    Ok(())
}

async fn admission_counts(database: &TestDatabase, run_id: RunId) -> TestResult<(i64, i64, i64)> {
    Ok(sqlx::query_as(
        r"
        SELECT
            (SELECT count(*) FROM workflow_admission_receipts WHERE run_id = $1),
            (SELECT count(*) FROM workflow_runs WHERE id = $1),
            (SELECT count(*) FROM github_workflow_run_subject_evidence WHERE run_id = $1)
        ",
    )
    .bind(run_id.as_uuid())
    .fetch_one(database.pool())
    .await?)
}

fn logical_command(
    fixture: &Fixture,
    idempotency_key: &str,
    request_digest_byte: u8,
    event_digest_byte: u8,
    namespace: u128,
    admitted_at: UnixMillis,
) -> AdmitLogicalWorkflowRun {
    logical_command_at_path(
        fixture,
        idempotency_key,
        request_digest_byte,
        event_digest_byte,
        namespace,
        admitted_at,
        ".ci/workflows/ci.yml",
        [0x31; 32],
    )
}

#[allow(clippy::too_many_arguments)]
fn logical_command_at_path(
    fixture: &Fixture,
    idempotency_key: &str,
    request_digest_byte: u8,
    event_digest_byte: u8,
    namespace: u128,
    admitted_at: UnixMillis,
    workflow_path: &str,
    source_digest: [u8; 32],
) -> AdmitLogicalWorkflowRun {
    let workflow_id = WorkflowId::from_uuid(Uuid::from_u128(namespace + 1));
    let snapshot_id = WorkflowSnapshotId::from_uuid(Uuid::from_u128(namespace + 2));
    let run_id = RunId::from_uuid(Uuid::from_u128(namespace + 3));
    let root_invocation_id = LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(namespace + 4))
        .expect("root invocation ID");
    let job_id =
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(namespace + 5)).expect("logical job ID");
    let job = AdmittedLogicalWorkflowJob::new(
        job_id,
        WorkflowJobKey::new("verify").expect("logical job key"),
        0,
        LogicalWorkflowJobKind::Steps,
        Vec::new(),
    )
    .expect("logical job");
    let source = AdmissionObject::new(
        Sha256Digest::from_bytes(source_digest),
        ObjectKey::new(format!("logical/{namespace}/source")).expect("source object key"),
        768,
        "application/yaml",
    )
    .expect("source object");
    let plan = AdmissionObject::new(
        Sha256Digest::from_bytes([0x32; 32]),
        ObjectKey::new(format!("logical/{namespace}/plan-v1")).expect("plan object key"),
        768,
        "application/json",
    )
    .expect("plan object");
    let event = AdmissionObject::new_event(
        Sha256Digest::from_bytes([event_digest_byte; 32]),
        ObjectKey::new(format!("logical/{namespace}/event")).expect("event object key"),
        512,
        "application/json",
    )
    .expect("event object");
    AdmitLogicalWorkflowRun::builder(
        fixture.tenant.clone(),
        WorkflowAdmissionIdempotency::provider_delivery(idempotency_key).expect("idempotency"),
        Sha256Digest::from_bytes([request_digest_byte; 32]),
        AdmissionRepository::new(
            fixture.manifest.repository_id(),
            "github",
            REPOSITORY_ID.to_string(),
            "automata-ci",
            "automata",
        )
        .expect("repository"),
        workflow_id,
        workflow_path,
        "Automata CI",
        "refs/heads/main",
        snapshot_id,
        source,
        plan,
        run_id,
        1,
        root_invocation_id,
        "push",
        event,
        HEAD_SHA.to_vec(),
        vec![job],
        admitted_at,
    )
    .actor("octocat")
    .build()
    .expect("logical admission command")
}

fn assert_constraint(error: &sqlx::Error, expected: &str) {
    assert_eq!(
        error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::constraint),
        Some(expected)
    );
}
