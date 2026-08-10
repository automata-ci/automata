#[allow(dead_code)]
mod common;
mod github_manifest_fixture;

use automata_ci_core::{RunId, Sha256Digest, UnixMillis, WorkflowId, WorkflowJobKey};
use automata_ci_store::{
    AcceptManifestPinnedGithubDelivery, AcceptProviderDelivery, AdmissionObject,
    AdmissionRepository, AdmitLogicalWorkflowRun, AdmittedLogicalWorkflowJob,
    AuthenticatedGithubDeliveryClaim, ClaimProviderDelivery, EnsureGithubServerServiceAuthority,
    GithubCheckHeadSha, GithubCheckName, GithubProviderManifest, GithubProviderManifestLimits,
    GithubProviderManifestRepository as _, GithubProviderManifestRevision, GithubProviderOrigins,
    GithubProviderWebhookVerifierFingerprint, GithubRepositoryName, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceAuthorityId, GithubServerServiceAuthorityIdentity,
    GithubServerServiceAuthorityRepository as _, GithubServerServiceJwtIssuer,
    GithubServerServiceRevision, GithubServerServiceScope, GithubSubjectEvidenceRepository as _,
    GithubSubjectEvidenceStoreError, LogicalWorkflowAdmissionRepository as _,
    LogicalWorkflowAdmissionStoreError, LogicalWorkflowInvocationId, LogicalWorkflowJobId,
    LogicalWorkflowJobKind, ManifestPinnedGithubDeliveryReceipt, ObjectKey, ProviderConnectionId,
    ProviderDeliveryClaimOwnerId, ProviderDeliveryId, ProviderDeliveryIdentity,
    ProviderDeliveryRepository as _, ProviderInstallationId, ProviderRepositoryCoordinates,
    ProviderRepositoryId, ProviderRepositoryOwnerId, ProviderRepositoryVisibility, StoreError,
    TenantScope, WorkflowAdmissionIdempotency, WorkflowSnapshotId,
};
use uuid::Uuid;

use common::{TestDatabase, TestResult, run_with_database};

const INSTALLATION_ID: u64 = 101;
const REPOSITORY_ID: u64 = 202;
const APP_ID: u64 = 303;
const OWNER_ID: u64 = 404;
const HEAD_SHA: [u8; 20] = [9; 20];

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
    desired_revision: i64,
    desired_updated_at_ms: i64,
    outbox_state: String,
    attempted_revision: Option<i64>,
    attempt_count: i16,
    claim_fence: i64,
    projected_revision: i64,
    state_updated_at_ms: i64,
}

#[derive(Debug, Eq, PartialEq, sqlx::FromRow)]
struct LocalAdmissionState {
    github_subject_evidence_required: bool,
    run_count: i64,
    evidence_count: i64,
    workflow_run_id: Option<Uuid>,
    linked_at_ms: Option<i64>,
    desired_state: String,
    desired_revision: i64,
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
            200,
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
                200,
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
async fn logical_admission_records_once_and_replay_uses_durable_run_time() -> TestResult {
    run_with_database(|database| async move {
        let fixture = bootstrap(
            &database,
            "subject-evidence-admission",
            0x280,
            ProviderRepositoryVisibility::Public,
            100,
        )
        .await?;
        let accepted = database
            .store()
            .accept_manifest_pinned_github_delivery(acceptance(
                &fixture,
                "delivery-admission",
                OWNER_ID,
                OWNER_ID,
                HEAD_SHA,
                200,
                30,
            ))
            .await?;
        let initial_claim = claim_delivery(
            &database,
            accepted.delivery_id(),
            0x301,
            UnixMillis::new(220),
            UnixMillis::new(300),
        )
        .await?;
        let command = logical_command(
            &fixture,
            "logical-admission-main",
            0x61,
            31,
            0x1_000,
            UnixMillis::new(250),
        );
        let run_id = command.run_id();
        let first = database
            .store()
            .admit_authenticated_github_delivery(command, initial_claim, UnixMillis::new(250))
            .await?;
        assert!(!first.is_replay());
        let check_after_initial =
            load_check_projection(&database, accepted.check_subject_id().as_uuid()).await?;
        assert_eq!(
            check_after_initial,
            CheckProjectionState {
                workflow_run_id: Some(run_id.as_uuid()),
                linked_at_ms: Some(250),
                desired_state: "in_progress".to_owned(),
                desired_revision: 2,
                desired_updated_at_ms: 250,
                outbox_state: "pending".to_owned(),
                attempted_revision: None,
                attempt_count: 0,
                claim_fence: 0,
                projected_revision: 0,
                state_updated_at_ms: 250,
            }
        );

        let replay_claim = claim_delivery(
            &database,
            accepted.delivery_id(),
            0x302,
            UnixMillis::new(300),
            UnixMillis::new(1_300),
        )
        .await?;
        assert_ne!(replay_claim.claim(), initial_claim.claim());
        assert_eq!(replay_claim.attempt(), initial_claim.attempt());
        assert_eq!(
            replay_claim.claim().fence(),
            initial_claim.claim().fence() + 1
        );
        let replay = database
            .store()
            .admit_authenticated_github_delivery(
                logical_command(
                    &fixture,
                    "logical-admission-main",
                    0x61,
                    31,
                    0x1_000,
                    UnixMillis::new(900),
                ),
                replay_claim,
                UnixMillis::new(900),
            )
            .await?;
        assert!(replay.is_replay());
        assert_eq!(first.run_id(), replay.run_id());
        assert_eq!(first.run_number(), replay.run_number());

        let check_after_replay =
            load_check_projection(&database, accepted.check_subject_id().as_uuid()).await?;
        assert_eq!(check_after_replay, check_after_initial);

        assert_run_evidence(&database, &fixture, &accepted, run_id, initial_claim).await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn changed_or_foreign_delivery_cannot_relink_or_leave_partial_admission() -> TestResult {
    run_with_database(|database| async move {
        let fixture = bootstrap(
            &database,
            "subject-evidence-conflict",
            0x290,
            ProviderRepositoryVisibility::Public,
            100,
        )
        .await?;
        let accepted_a = database
            .store()
            .accept_manifest_pinned_github_delivery(acceptance(
                &fixture,
                "delivery-conflict-a",
                OWNER_ID,
                OWNER_ID,
                HEAD_SHA,
                200,
                40,
            ))
            .await?;
        let claim_a = claim_delivery(
            &database,
            accepted_a.delivery_id(),
            0x401,
            UnixMillis::new(220),
            UnixMillis::new(1_220),
        )
        .await?;
        let accepted_b = database
            .store()
            .accept_manifest_pinned_github_delivery(acceptance(
                &fixture,
                "delivery-conflict-b",
                OWNER_ID,
                OWNER_ID,
                HEAD_SHA,
                201,
                40,
            ))
            .await?;
        let claim_b = claim_delivery(
            &database,
            accepted_b.delivery_id(),
            0x402,
            UnixMillis::new(221),
            UnixMillis::new(1_221),
        )
        .await?;
        let command = logical_command(
            &fixture,
            "logical-delivery-switch",
            0x70,
            41,
            0x2_000,
            UnixMillis::new(250),
        );
        let run_id = command.run_id();
        database
            .store()
            .admit_authenticated_github_delivery(
                command.clone(),
                claim_a,
                UnixMillis::new(250),
            )
            .await?;

        assert!(matches!(
            database
                .store()
                .admit_authenticated_github_delivery(command, claim_b, UnixMillis::new(250))
                .await,
            Err(LogicalWorkflowAdmissionStoreError::Store(
                StoreError::CorruptData(_)
            ))
        ));
        assert!(matches!(
            database
                .store()
                .admit_authenticated_github_delivery(
                    logical_command(
                        &fixture,
                        "logical-delivery-switch",
                        0x71,
                        41,
                        0x2_000,
                        UnixMillis::new(260),
                    ),
                    claim_b,
                    UnixMillis::new(260),
                )
                .await,
            Err(LogicalWorkflowAdmissionStoreError::IdempotencyConflict)
        ));
        let second_subject: (Option<Uuid>, Option<i64>) = sqlx::query_as(
            "SELECT workflow_run_id, linked_at_ms FROM github_check_subjects WHERE id = $1",
        )
        .bind(accepted_b.check_subject_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(second_subject, (None, None));
        let durable_delivery: Uuid = sqlx::query_scalar(
            "SELECT provider_delivery_id FROM github_workflow_run_subject_evidence WHERE run_id = $1",
        )
        .bind(run_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(durable_delivery, accepted_a.delivery_id().as_uuid());

        let foreign = bootstrap(
            &database,
            "subject-evidence-foreign",
            0x291,
            ProviderRepositoryVisibility::Public,
            100,
        )
        .await?;
        let foreign_delivery = database
            .store()
            .accept_manifest_pinned_github_delivery(acceptance(
                &foreign,
                "delivery-foreign",
                OWNER_ID,
                OWNER_ID,
                HEAD_SHA,
                200,
                50,
            ))
            .await?;
        let foreign_claim = claim_delivery(
            &database,
            foreign_delivery.delivery_id(),
            0x403,
            UnixMillis::new(220),
            UnixMillis::new(1_220),
        )
        .await?;
        let target = bootstrap(
            &database,
            "subject-evidence-foreign-target",
            0x292,
            ProviderRepositoryVisibility::Public,
            100,
        )
        .await?;
        let foreign_command = logical_command(
            &target,
            "logical-foreign-delivery",
            0x72,
            51,
            0x3_000,
            UnixMillis::new(250),
        );
        let foreign_run_id = foreign_command.run_id();
        let foreign_workflow_id = foreign_command.workflow_id();
        let foreign_snapshot_id = foreign_command.snapshot_id();
        let foreign_result = database
            .store()
            .admit_authenticated_github_delivery(
                foreign_command,
                foreign_claim,
                UnixMillis::new(250),
            )
            .await;
        assert!(
            matches!(
                foreign_result,
            Err(LogicalWorkflowAdmissionStoreError::Store(
                StoreError::CorruptData(_)
            ))
            ),
            "foreign delivery returned {foreign_result:?}"
        );
        let partial_counts: (i64, i64, i64, i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM workflow_admission_receipts
                  WHERE tenant_id = $1 AND idempotency_kind = 'provider_delivery'
                    AND idempotency_key = 'logical-foreign-delivery'),
                (SELECT count(*) FROM workflow_definitions WHERE id = $2),
                (SELECT count(*) FROM workflow_snapshots WHERE id = $3),
                (SELECT count(*) FROM workflow_runs WHERE id = $4),
                (SELECT count(*) FROM workflow_plan_v2_runs WHERE run_id = $4),
                (SELECT count(*) FROM github_workflow_run_subject_evidence WHERE run_id = $4)
            ",
        )
        .bind(target.tenant.as_str())
        .bind(foreign_workflow_id.as_uuid())
        .bind(foreign_snapshot_id.as_uuid())
        .bind(foreign_run_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(partial_counts, (0, 0, 0, 0, 0, 0));
        let foreign_subject: (Option<Uuid>, Option<i64>) = sqlx::query_as(
            "SELECT workflow_run_id, linked_at_ms FROM github_check_subjects WHERE id = $1",
        )
        .bind(foreign_delivery.check_subject_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(foreign_subject, (None, None));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn expired_claim_rolls_back_and_ordinary_admission_cannot_be_backfilled() -> TestResult {
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
                200,
                60,
            ))
            .await?;
        let expired_claim = claim_delivery(
            &database,
            accepted.delivery_id(),
            0x501,
            UnixMillis::new(220),
            UnixMillis::new(300),
        )
        .await?;
        let command = logical_command(
            &fixture,
            "logical-expired-local",
            0x80,
            61,
            0x4_000,
            UnixMillis::new(300),
        );
        let run_id = command.run_id();

        assert!(matches!(
            database
                .store()
                .admit_authenticated_github_delivery(
                    command.clone(),
                    expired_claim,
                    UnixMillis::new(300),
                )
                .await,
            Err(LogicalWorkflowAdmissionStoreError::Store(
                StoreError::CorruptData(_)
            ))
        ));
        let rolled_back = admission_counts(&database, run_id).await?;
        assert_eq!(rolled_back, (0, 0, 0));

        let ordinary = database
            .store()
            .admit_logical_workflow(command.clone())
            .await?;
        assert!(!ordinary.is_replay());
        let successor = claim_delivery(
            &database,
            accepted.delivery_id(),
            0x502,
            UnixMillis::new(300),
            UnixMillis::new(1_300),
        )
        .await?;
        assert!(matches!(
            database
                .store()
                .admit_authenticated_github_delivery(command, successor, UnixMillis::new(300),)
                .await,
            Err(LogicalWorkflowAdmissionStoreError::Store(
                StoreError::CorruptData(_)
            ))
        ));

        let durable =
            load_local_admission_state(&database, run_id, accepted.check_subject_id().as_uuid())
                .await?;
        assert_eq!(
            durable,
            LocalAdmissionState {
                github_subject_evidence_required: false,
                run_count: 1,
                evidence_count: 0,
                workflow_run_id: None,
                linked_at_ms: None,
                desired_state: "queued".to_owned(),
                desired_revision: 1,
            }
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn direct_sql_cannot_commit_bare_delivery_evidence_or_unpinned_check() -> TestResult {
    run_with_database(|database| async move {
        let fixture = bootstrap(
            &database,
            "subject-evidence-sql",
            0x300,
            ProviderRepositoryVisibility::Public,
            100,
        )
        .await?;
        let bare_id = Uuid::new_v4();
        let bare_error = insert_inbox(database.pool(), &fixture, bare_id, "bare-delivery", 200, 20)
            .await
            .expect_err("a bare GitHub inbox must fail at statement commit");
        assert_constraint(&bare_error, "github_delivery_atomic_queued_check_required");

        let mut no_check = database.pool().begin().await?;
        let no_check_id = Uuid::new_v4();
        insert_inbox(
            &mut *no_check,
            &fixture,
            no_check_id,
            "evidence-without-check",
            210,
            21,
        )
        .await?;
        insert_extension(
            &mut no_check,
            &fixture,
            no_check_id,
            Uuid::new_v4(),
            OWNER_ID,
        )
        .await?;
        let commit_error = no_check
            .commit()
            .await
            .expect_err("evidence without an atomic Check must not commit");
        assert_constraint_one_of(
            &commit_error,
            &[
                "github_delivery_atomic_queued_check_required",
                "github_provider_delivery_evidence_check_subject",
            ],
        );

        let mut no_evidence = database.pool().begin().await?;
        let no_evidence_id = Uuid::new_v4();
        insert_inbox(
            &mut *no_evidence,
            &fixture,
            no_evidence_id,
            "check-without-evidence",
            220,
            22,
        )
        .await?;
        let subject_id = Uuid::new_v4();
        let check_error = sqlx::query(
            r"
            INSERT INTO github_check_subjects (
                id, tenant_id, repository_id, provider_delivery_id, subject_key,
                provider_connection_id, provider_installation_id,
                github_repository_id, github_app_id, head_sha, check_name,
                external_id, created_at_ms, desired_updated_at_ms
            ) VALUES (
                $1, $2, $3, $4, '.github/workflows/ci.yml',
                $5, $6, $7, $8, $9, 'Automata CI',
                'automata-check:' || $1::TEXT, 220, 220
            )
            ",
        )
        .bind(subject_id)
        .bind(fixture.tenant.as_str())
        .bind(fixture.manifest.repository_id().as_uuid())
        .bind(no_evidence_id)
        .bind(fixture.connection.as_uuid())
        .bind(i64::try_from(INSTALLATION_ID)?)
        .bind(i64::try_from(REPOSITORY_ID)?)
        .bind(i64::try_from(APP_ID)?)
        .bind(HEAD_SHA.as_slice())
        .execute(&mut *no_evidence)
        .await
        .expect_err("a Check without the immutable extension must fail");
        assert_constraint(
            &check_error,
            "github_check_subjects_delivery_evidence_exact",
        );
        no_evidence.rollback().await?;
        Ok(())
    })
    .await
}

struct Fixture {
    tenant: TenantScope,
    connection: ProviderConnectionId,
    manifest: GithubProviderManifest,
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
    let tenant = TenantScope::from_authenticated_tenant_id(tenant_id)?;
    let connection = ProviderConnectionId::from_uuid(Uuid::from_u128(connection_id))?;
    let manifest = manifest(
        tenant.clone(),
        connection,
        visibility,
        ManifestRevisions::new(1, 1, 1, 1),
        [7; 32],
        [6; 32],
    );
    database
        .store()
        .bootstrap_github_provider_repository(
            github_manifest_fixture::fixture_github_repository_bootstrap(
                manifest.clone(),
                UnixMillis::new(at),
            ),
        )
        .await?;
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
    let runtime_policy = github_manifest_fixture::fixture_github_runtime_policy(revisions.policy);
    GithubProviderManifest::new(
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
        GithubCheckName::new("Automata CI").expect("Check name"),
        GithubProviderOrigins::github_dot_com(),
        GithubProviderManifestLimits::github_dot_com_ci(),
        GithubProviderManifestRevision::new(revisions.manifest).expect("manifest revision"),
    )
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
                "application/json",
            )
            .expect("event object"),
            UnixMillis::new(accepted_at),
        )
        .expect("delivery"),
        ProviderRepositoryOwnerId::new(signed_owner_id).expect("signed owner"),
        ProviderRepositoryOwnerId::new(configured_owner_id).expect("configured owner"),
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
    observed_at: UnixMillis,
    expires_at: UnixMillis,
) -> TestResult<AuthenticatedGithubDeliveryClaim> {
    let owner = ProviderDeliveryClaimOwnerId::from_uuid(Uuid::from_u128(owner_seed))?;
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

async fn load_check_projection(
    database: &TestDatabase,
    subject_id: Uuid,
) -> TestResult<CheckProjectionState> {
    Ok(sqlx::query_as(
        r"
        SELECT subject.workflow_run_id, subject.linked_at_ms,
               subject.desired_state, subject.desired_revision,
               subject.desired_updated_at_ms, outbox.state AS outbox_state,
               outbox.attempted_revision, outbox.attempt_count,
               outbox.claim_fence, outbox.projected_revision,
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

async fn assert_run_evidence(
    database: &TestDatabase,
    fixture: &Fixture,
    accepted: &ManifestPinnedGithubDeliveryReceipt,
    run_id: RunId,
    initial_claim: AuthenticatedGithubDeliveryClaim,
) -> TestResult {
    let evidence = database
        .store()
        .load_github_workflow_run_subject_evidence(
            &fixture.tenant,
            fixture.manifest.repository_id(),
            run_id,
        )
        .await?;
    assert_eq!(evidence.delivery_id(), accepted.delivery_id());
    assert_eq!(evidence.admission_claim(), initial_claim);
    assert_eq!(evidence.check_subject_id(), accepted.check_subject_id());
    assert_eq!(evidence.admitted_at(), UnixMillis::new(250));
    assert_eq!(evidence.request().head_sha().as_bytes(), HEAD_SHA);
    assert_eq!(
        evidence.request().workflow_path().as_str(),
        ".github/workflows/ci.yml"
    );
    assert_eq!(evidence.request().event_name(), "push");
    assert_eq!(
        evidence.request().event_digest(),
        Sha256Digest::from_bytes([31; 32])
    );
    assert_eq!(evidence.request().git_ref(), "refs/heads/main");
    assert_eq!(evidence.request().plan_schema(), 2);

    let counts: (i64, i64, i64) = sqlx::query_as(
        r"
        SELECT
            (SELECT count(*) FROM workflow_runs WHERE id = $1),
            (SELECT count(*) FROM workflow_plan_v2_runs WHERE run_id = $1),
            (SELECT count(*) FROM github_workflow_run_subject_evidence WHERE run_id = $1)
        ",
    )
    .bind(run_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert_eq!(counts, (1, 1, 1));
    let evidence_required: bool = sqlx::query_scalar(
        "SELECT github_subject_evidence_required FROM workflow_admission_receipts WHERE run_id = $1",
    )
    .bind(run_id.as_uuid())
    .fetch_one(database.pool())
    .await?;
    assert!(evidence_required);
    Ok(())
}

async fn load_local_admission_state(
    database: &TestDatabase,
    run_id: RunId,
    subject_id: Uuid,
) -> TestResult<LocalAdmissionState> {
    Ok(sqlx::query_as(
        r"
        SELECT receipt.github_subject_evidence_required,
               (SELECT count(*) FROM workflow_runs WHERE id = $1) AS run_count,
               (SELECT count(*) FROM github_workflow_run_subject_evidence WHERE run_id = $1)
                   AS evidence_count,
               subject.workflow_run_id, subject.linked_at_ms,
               subject.desired_state, subject.desired_revision
        FROM workflow_admission_receipts AS receipt
        JOIN github_check_subjects AS subject ON subject.id = $2
        WHERE receipt.run_id = $1
        ",
    )
    .bind(run_id.as_uuid())
    .bind(subject_id)
    .fetch_one(database.pool())
    .await?)
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
        Sha256Digest::from_bytes([0x31; 32]),
        ObjectKey::new(format!("logical/{namespace}/source")).expect("source object key"),
        768,
        "application/yaml",
    )
    .expect("source object");
    let plan = AdmissionObject::new(
        Sha256Digest::from_bytes([0x32; 32]),
        ObjectKey::new(format!("logical/{namespace}/plan-v2")).expect("plan object key"),
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
        ".github/workflows/ci.yml",
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

async fn insert_inbox<'e, E>(
    executor: E,
    fixture: &Fixture,
    id: Uuid,
    delivery_key: &str,
    accepted_at: i64,
    digest_byte: u8,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query(
        r"
        INSERT INTO provider_delivery_inbox (
            id, tenant_id, provider, connection_id, installation_id,
            provider_repository_id, repository_visibility,
            repository_identity, delivery_id, request_digest,
            raw_event_digest, raw_event_object_key, raw_event_size_bytes,
            raw_event_media_type, accepted_at_ms, state_updated_at_ms
        ) VALUES (
            $1, $2, 'github', $3, $4, $5, $6,
            'automata-ci/automata', $7, $8, $9, $10,
            512, 'application/json', $11, $11
        )
        ",
    )
    .bind(id)
    .bind(fixture.tenant.as_str())
    .bind(fixture.connection.as_uuid())
    .bind(i64::try_from(INSTALLATION_ID).expect("installation fits"))
    .bind(i64::try_from(REPOSITORY_ID).expect("repository fits"))
    .bind(match fixture.manifest.repository_visibility() {
        ProviderRepositoryVisibility::Public => "public",
        ProviderRepositoryVisibility::Private => "private",
    })
    .bind(delivery_key)
    .bind(vec![digest_byte; 32])
    .bind(vec![digest_byte.wrapping_add(1); 32])
    .bind(format!("github/events/{delivery_key}"))
    .bind(accepted_at)
    .execute(executor)
    .await
}

async fn insert_extension(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    fixture: &Fixture,
    delivery_id: Uuid,
    subject_id: Uuid,
    owner_id: u64,
) -> TestResult {
    let checks = &fixture.checks_authority;
    sqlx::query(
        r"
        INSERT INTO github_provider_delivery_evidence (
            provider_delivery_id, tenant_id, repository_id,
            provider_connection_id, provider_installation_id,
            github_repository_id, github_repository_owner_id,
            github_repository_name, repository_visibility,
            provider_manifest_revision, provider_manifest_digest,
            authenticated_webhook_verifier_fingerprint_sha256,
            authenticated_webhook_verifier_revision,
            checks_authority_id, checks_authority_identity_digest,
            checks_authority_app_configuration_revision,
            checks_authority_policy_revision,
            github_check_subject_id, github_check_head_sha
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,'automata-ci/automata','public',1,$8,
            $9,$10,$11,$12,$13,$14,$15,$16
        )
        ",
    )
    .bind(delivery_id)
    .bind(fixture.tenant.as_str())
    .bind(fixture.manifest.repository_id().as_uuid())
    .bind(fixture.connection.as_uuid())
    .bind(i64::try_from(INSTALLATION_ID)?)
    .bind(i64::try_from(REPOSITORY_ID)?)
    .bind(i64::try_from(owner_id)?)
    .bind(fixture.manifest.digest().as_bytes().as_slice())
    .bind(
        fixture
            .manifest
            .webhook_verifier_fingerprint()
            .sha256()
            .as_bytes()
            .as_slice(),
    )
    .bind(i64::try_from(
        fixture.manifest.webhook_verifier_revision().get(),
    )?)
    .bind(checks.authority_id().as_uuid())
    .bind(checks.identity_digest().as_bytes().as_slice())
    .bind(i64::try_from(checks.app_configuration_revision().get())?)
    .bind(i64::try_from(checks.policy_revision().get())?)
    .bind(subject_id)
    .bind(HEAD_SHA.as_slice())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn assert_constraint(error: &sqlx::Error, expected: &str) {
    assert_eq!(
        error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::constraint),
        Some(expected)
    );
}

fn assert_constraint_one_of(error: &sqlx::Error, expected: &[&str]) {
    let actual = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint);
    assert!(
        expected
            .iter()
            .copied()
            .any(|candidate| Some(candidate) == actual),
        "unexpected constraint: {actual:?}"
    );
}
