use std::time::{Duration, SystemTime, UNIX_EPOCH};

use automata_ci_core::{RunId, Sha256Digest, UnixMillis};
use automata_ci_store::{
    AcceptProviderDelivery, AdmissionObject, ClaimProviderDelivery, ClaimedProviderDelivery,
    CompleteProviderDelivery, MAX_ADMISSION_EVENT_BYTES, MAX_PROVIDER_DELIVERY_CLAIM_MILLIS,
    MAX_PROVIDER_DELIVERY_TOTAL_CLAIM_MILLIS, ObjectKey, ProviderConnectionId,
    ProviderDeliveryClaimFence, ProviderDeliveryClaimOwnerId,
    ProviderDeliveryClaimRenewalRepository as _, ProviderDeliveryEventEnvelope,
    ProviderDeliveryFailureKind, ProviderDeliveryIdentity, ProviderDeliveryRenewalTiming,
    ProviderDeliveryRepository as _, ProviderDeliveryState, ProviderDeliveryStoreError,
    ProviderDeliveryValueError, ProviderDeliveryWorkflowConclusion,
    ProviderDeliveryWorkflowOutcome, ProviderInstallationId, ProviderRepositoryCoordinates,
    ProviderRepositoryId, ProviderRepositoryVisibility, RejectProviderDelivery,
    RenewProviderDeliveryClaim, RetryProviderDelivery, TenantScope,
};
use uuid::Uuid;

use crate::support::{
    TestClock, TestDatabase, TestResult, provider_delivery_event_envelope, run_with_database,
};

async fn seed_tenant(database: &TestDatabase, tenant: &str) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms)
        VALUES ($1, $1, 1, 1)
        ",
    )
    .bind(tenant)
    .execute(database.pool())
    .await?;
    Ok(())
}

async fn seed_workflow_run(
    database: &TestDatabase,
    tenant: &str,
    suffix: &str,
    provider_repository_id: u64,
) -> TestResult<RunId> {
    let repository_id = Uuid::new_v4();
    let workflow_id = Uuid::new_v4();
    let snapshot_id = Uuid::new_v4();
    let run_id = Uuid::new_v4();
    sqlx::query(
        r"
        INSERT INTO repositories (
            id, tenant_id, scm_provider, provider_repository_id, owner, name,
            created_at_ms, updated_at_ms
        )
        VALUES ($1, $2, 'synthetic', $3, 'automata-ci', $4, 1, 1)
        ",
    )
    .bind(repository_id)
    .bind(tenant)
    .bind(provider_repository_id.to_string())
    .bind(format!("provider-delivery-{suffix}"))
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_definitions (
            id, repository_id, path, created_at_ms, updated_at_ms
        )
        VALUES ($1, $2, $3, 1, 1)
        ",
    )
    .bind(workflow_id)
    .bind(repository_id)
    .bind(format!(".ci/workflows/{suffix}.yml"))
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_snapshots (
            id, workflow_id, source_digest, source_object_key,
            frontend_schema, created_at_ms
        )
        VALUES ($1, $2, $3, $4, 1, 1)
        ",
    )
    .bind(snapshot_id)
    .bind(workflow_id)
    .bind([7_u8; 32].as_slice())
    .bind(format!("provider-delivery-tests/{suffix}/source"))
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_runs (
            id, repository_id, workflow_id, snapshot_id, run_number,
            event_name, event_object_key, event_digest, event_size_bytes,
            event_media_type, plan_digest, plan_object_key, plan_size_bytes,
            plan_media_type, plan_schema, workflow_name, head_sha, status,
            created_at_ms, updated_at_ms, runner_requirements_schema
        )
        VALUES (
            $1, $2, $3, $4, 1, 'push', $5,
            decode(repeat('31', 32), 'hex'), 1, 'application/json',
            decode(repeat('32', 32), 'hex'), 'test/provider-delivery-plan', 1,
            'application/vnd.automata.workflow-plan.protobuf', 1,
            'Provider delivery', $6, 'queued', 1, 1, 1
        )
        ",
    )
    .bind(run_id)
    .bind(repository_id)
    .bind(workflow_id)
    .bind(snapshot_id)
    .bind(format!("provider-delivery-tests/{suffix}/event"))
    .bind([9_u8; 20].as_slice())
    .execute(database.pool())
    .await?;
    Ok(RunId::from_uuid(run_id))
}

fn acceptance(
    tenant: &str,
    connection_id: ProviderConnectionId,
    delivery_id: &str,
    digest_byte: u8,
    accepted_at: i64,
) -> AcceptProviderDelivery {
    acceptance_with_visibility(
        tenant,
        connection_id,
        delivery_id,
        digest_byte,
        accepted_at,
        ProviderRepositoryVisibility::Private,
    )
}

fn acceptance_with_visibility(
    tenant: &str,
    connection_id: ProviderConnectionId,
    delivery_id: &str,
    digest_byte: u8,
    accepted_at: i64,
    visibility: ProviderRepositoryVisibility,
) -> AcceptProviderDelivery {
    acceptance_with_visibility_and_envelope(
        tenant,
        connection_id,
        delivery_id,
        digest_byte,
        accepted_at,
        visibility,
        provider_delivery_event_envelope(digest_byte.wrapping_add(2)),
    )
}

#[allow(clippy::too_many_arguments)]
fn acceptance_with_visibility_and_envelope(
    tenant: &str,
    connection_id: ProviderConnectionId,
    delivery_id: &str,
    digest_byte: u8,
    accepted_at: i64,
    visibility: ProviderRepositoryVisibility,
    event_envelope: ProviderDeliveryEventEnvelope,
) -> AcceptProviderDelivery {
    let identity = ProviderDeliveryIdentity::new(
        TenantScope::from_authenticated_tenant_id(tenant).expect("tenant"),
        "synthetic",
        connection_id,
        ProviderInstallationId::new(101).expect("installation"),
        ProviderRepositoryCoordinates::new(
            ProviderRepositoryId::new(202).expect("repository"),
            visibility,
            "automata-ci/automata",
        )
        .expect("repository coordinates"),
        delivery_id,
    )
    .expect("delivery identity");
    let raw_event = AdmissionObject::new_event(
        Sha256Digest::from_bytes([digest_byte.wrapping_add(1); 32]),
        ObjectKey::new(format!("provider-events/{delivery_id}/{digest_byte}")).expect("object key"),
        256,
        "application/json",
    )
    .expect("raw event");
    AcceptProviderDelivery::new(
        identity,
        Sha256Digest::from_bytes([digest_byte; 32]),
        raw_event,
        event_envelope,
        UnixMillis::new(accepted_at),
    )
    .expect("acceptance")
}

fn owner() -> ProviderDeliveryClaimOwnerId {
    ProviderDeliveryClaimOwnerId::from_uuid(Uuid::new_v4()).expect("owner")
}

fn wall_time_millis() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test wall time follows the Unix epoch")
            .as_millis(),
    )
    .expect("test wall time fits in signed milliseconds")
}

fn normalize_test_interval(observed_at: i64, expires_at: i64) -> (i64, i64) {
    if observed_at >= 1_000_000_000_000 {
        return (observed_at, expires_at);
    }
    let duration = expires_at
        .checked_sub(observed_at)
        .expect("test interval is representable");
    let observed_at = wall_time_millis();
    (
        observed_at,
        observed_at
            .checked_add(duration)
            .expect("normalized test interval is representable"),
    )
}

fn future_test_time(offset_millis: i64) -> UnixMillis {
    UnixMillis::new(
        wall_time_millis()
            .checked_add(offset_millis)
            .expect("test timestamp is representable"),
    )
}

async fn database_now(database: &TestDatabase) -> TestResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(database.pool())
            .await?,
    )
}

async fn database_time_after(
    database: &TestDatabase,
    offset_millis: i64,
) -> TestResult<UnixMillis> {
    Ok(UnixMillis::new(
        database_now(database)
            .await?
            .checked_add(offset_millis)
            .expect("future database timestamp is representable"),
    ))
}

fn claim(owner: ProviderDeliveryClaimOwnerId, requested_observed_at: i64) -> ClaimProviderDelivery {
    let observed_at = if requested_observed_at >= 1_000_000_000_000 {
        requested_observed_at
    } else {
        wall_time_millis()
    };
    ClaimProviderDelivery::new(
        owner,
        UnixMillis::new(observed_at),
        UnixMillis::new(observed_at + 1_000),
    )
    .expect("claim")
}

fn renewal_request(
    claim: ProviderDeliveryClaimFence,
    attempt: u16,
    claimed_at: UnixMillis,
    predecessor_expires_at: UnixMillis,
    observed_at: i64,
    expires_at: i64,
) -> Result<RenewProviderDeliveryClaim, ProviderDeliveryValueError> {
    let normalize = observed_at < 1_000_000_000_000;
    let (mut observed_at, mut expires_at) = normalize_test_interval(observed_at, expires_at);
    if normalize && observed_at <= claimed_at.get() {
        let duration = expires_at - observed_at;
        observed_at = claimed_at.get() + 1;
        expires_at = observed_at + duration;
    }
    let monotonic_observed_at = tokio::time::Instant::now();
    let predecessor_remaining = u64::try_from(predecessor_expires_at.get() - observed_at)
        .map_err(|_| ProviderDeliveryValueError::InvalidClaimInterval)?;
    let confirmed_predecessor_deadline = monotonic_observed_at
        .checked_add(Duration::from_millis(predecessor_remaining))
        .ok_or(ProviderDeliveryValueError::InvalidClaimInterval)?;
    let timing = ProviderDeliveryRenewalTiming::new(
        confirmed_predecessor_deadline,
        monotonic_observed_at,
        UnixMillis::new(observed_at),
        predecessor_expires_at,
    )?;
    RenewProviderDeliveryClaim::new(
        claim,
        attempt,
        claimed_at,
        timing,
        UnixMillis::new(expires_at),
    )
}

async fn accept_and_claim(
    database: &TestDatabase,
    tenant: &str,
    connection: ProviderConnectionId,
    delivery_id: &str,
    digest_byte: u8,
    observed_at: i64,
) -> TestResult<ClaimedProviderDelivery> {
    database
        .store()
        .accept_provider_delivery(acceptance(
            tenant,
            connection,
            delivery_id,
            digest_byte,
            observed_at - 10,
        ))
        .await?;
    Ok(database
        .store()
        .claim_provider_delivery(claim(owner(), observed_at))
        .await?
        .expect("accepted delivery must be claimable"))
}

async fn directly_rotate_claim_window(
    database: &TestDatabase,
    delivery_id: Uuid,
    renewed_fence: i64,
    observed_at: i64,
    expires_at: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r"
        UPDATE provider_delivery_inbox
        SET claim_fence = $2,
            renewal_predecessor_expires_at_ms = claim_expires_at_ms,
            state_updated_at_ms = $3,
            claim_expires_at_ms = $4
        WHERE id = $1
        ",
    )
    .bind(delivery_id)
    .bind(renewed_fence)
    .bind(observed_at)
    .bind(expires_at)
    .execute(database.pool())
    .await
    .map(|_| ())
}

async fn wait_for_renewal_lock_wait(
    database: &TestDatabase,
    blocking_backend_pid: i32,
) -> TestResult {
    for _ in 0..200 {
        let waiting: bool = sqlx::query_scalar(
            r"
            SELECT EXISTS (
                SELECT 1
                FROM pg_stat_activity
                WHERE datname = current_database()
                  AND pid <> $1
                  AND state = 'active'
                  AND $1 = ANY(pg_blocking_pids(pid))
                  AND query LIKE '%renewal_predecessor_expires_at_ms%'
                  AND query LIKE '%FOR UPDATE%'
            )
            ",
        )
        .bind(blocking_backend_pid)
        .fetch_one(database.pool())
        .await?;
        if waiting {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Err("provider-delivery renewal never reached the expected row lock".into())
}

async fn advance_past_monotonic_deadline(deadline: tokio::time::Instant) {
    tokio::time::pause();
    tokio::time::advance(
        deadline.saturating_duration_since(tokio::time::Instant::now()) + Duration::from_millis(20),
    )
    .await;
    tokio::time::resume();
}

fn assert_database_constraint(error: &sqlx::Error, expected: &str) {
    let constraint = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint);
    assert_eq!(constraint, Some(expected));
}

async fn assert_partial_event_envelope_is_rejected(
    database: &TestDatabase,
    connection: &ProviderConnectionId,
) -> TestResult {
    let partial = sqlx::query(
        r"
        INSERT INTO provider_delivery_inbox (
            id, tenant_id, provider, connection_id, installation_id,
            provider_repository_id, repository_visibility,
            repository_identity, delivery_id,
            request_digest, raw_event_digest, raw_event_object_key,
            raw_event_size_bytes, raw_event_media_type,
            event_envelope_schema,
            accepted_at_ms, state_updated_at_ms
        )
        VALUES (
            $1, 'delivery-envelope-legacy', 'synthetic', $2, 101,
            202, 'private', 'automata-ci/automata', 'delivery-partial-envelope',
            $3, $4, 'provider-events/delivery-partial-envelope/1',
            256, 'application/json', 1, 100, 100
        )
        ",
    )
    .bind(Uuid::new_v4())
    .bind(connection.as_uuid())
    .bind([41_u8; 32].as_slice())
    .bind([42_u8; 32].as_slice())
    .execute(database.pool())
    .await
    .expect_err("partially populated event envelopes must fail closed");
    assert_database_constraint(&partial, "provider_delivery_inbox_event_envelope_complete");
    Ok(())
}

async fn seed_legacy_unsealed_deliveries(
    database: &TestDatabase,
    connection: &ProviderConnectionId,
) -> TestResult {
    sqlx::query(
        r"
        INSERT INTO provider_delivery_inbox (
            id, tenant_id, provider, connection_id, installation_id,
            provider_repository_id, repository_visibility,
            repository_identity, delivery_id,
            request_digest, raw_event_digest, raw_event_object_key,
            raw_event_size_bytes, raw_event_media_type,
            accepted_at_ms, state_updated_at_ms
        )
        SELECT
            md5('delivery-envelope-legacy-' || legacy.ordinal::text)::uuid,
            'delivery-envelope-legacy', 'synthetic', $1, 101,
            202, 'private', 'automata-ci/automata',
            'delivery-legacy-unsealed-' || legacy.ordinal::text,
            decode(repeat('2b', 32), 'hex'),
            decode(repeat('2c', 32), 'hex'),
            'provider-events/delivery-legacy-unsealed/' || legacy.ordinal::text,
            256, 'application/json', 100, 100
        FROM generate_series(1, 65) AS legacy(ordinal)
        ",
    )
    .bind(connection.as_uuid())
    .execute(database.pool())
    .await?;
    Ok(())
}

async fn legacy_delivery_state_counts(
    database: &TestDatabase,
    claim_owner: ProviderDeliveryClaimOwnerId,
) -> TestResult<(i64, i64, i64)> {
    let counts = sqlx::query_as(
        r"
        SELECT
            count(*) FILTER (WHERE state = 'rejected'),
            count(*) FILTER (WHERE state = 'pending'),
            count(*) FILTER (
                WHERE state = 'rejected'
                  AND attempt_count = 1
                  AND claim_fence = 1
                  AND claim_owner_id IS NULL
                  AND last_failure_kind = 'provider_delivery.legacy_unsealed'
                  AND terminal_claim_owner_id = $1
                  AND terminal_claim_fence = 1
            )
        FROM provider_delivery_inbox
        WHERE delivery_id LIKE 'delivery-legacy-unsealed-%'
        ",
    )
    .bind(claim_owner.as_uuid())
    .fetch_one(database.pool())
    .await?;
    Ok(counts)
}

fn failure(value: &str) -> ProviderDeliveryFailureKind {
    ProviderDeliveryFailureKind::new(value).expect("failure kind")
}

async fn assert_visibility_is_immutable(database: &TestDatabase, delivery_id: Uuid) -> TestResult {
    let mutation = sqlx::query(
        "UPDATE provider_delivery_inbox SET repository_visibility = 'public' WHERE id = $1",
    )
    .bind(delivery_id)
    .execute(database.pool())
    .await
    .expect_err("authenticated repository visibility is immutable");
    assert_database_constraint(&mutation, "provider_delivery_inbox_evidence_immutable");
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM provider_delivery_inbox")
        .fetch_one(database.pool())
        .await?;
    assert_eq!(count, 1);
    Ok(())
}

async fn assert_stale_renewal_evidence_is_rejected(
    database: &TestDatabase,
    claimed: &ClaimedProviderDelivery,
) -> TestResult {
    let claimed_at = claimed.claimed_at().get();
    let predecessor_expires_at = claimed.expires_at();
    let observed_at = claimed_at + 500;
    let exhausted = ProviderDeliveryClaimFence::from_durable_parts(
        claimed.claim().delivery_id(),
        claimed.claim().owner(),
        u64::try_from(i64::MAX)?,
    )?;
    assert!(matches!(
        database
            .store()
            .renew_provider_delivery_claim(renewal_request(
                exhausted,
                claimed.attempt(),
                claimed.claimed_at(),
                predecessor_expires_at,
                observed_at,
                observed_at + 1_000,
            )?)
            .await,
        Err(ProviderDeliveryStoreError::FenceExhausted)
    ));
    for stale in [
        renewal_request(
            claimed.claim(),
            claimed.attempt(),
            claimed.claimed_at(),
            UnixMillis::new(predecessor_expires_at.get() - 10),
            claimed_at + 400,
            claimed_at + 1_400,
        )?,
        renewal_request(
            claimed.claim(),
            claimed.attempt(),
            claimed.claimed_at(),
            predecessor_expires_at,
            observed_at,
            observed_at + 1_100,
        )?,
        renewal_request(
            claimed.claim(),
            claimed.attempt(),
            claimed.claimed_at(),
            predecessor_expires_at,
            observed_at + 1,
            observed_at + 951,
        )?,
        renewal_request(
            claimed.claim(),
            claimed.attempt(),
            claimed.claimed_at(),
            predecessor_expires_at,
            observed_at + 1,
            observed_at + 1_000,
        )?,
    ] {
        assert!(matches!(
            database.store().renew_provider_delivery_claim(stale).await,
            Err(ProviderDeliveryStoreError::ClaimRejected)
        ));
    }
    Ok(())
}

async fn assert_invalid_direct_renewals(database: &TestDatabase, delivery_id: Uuid) -> TestResult {
    let (fence, state_updated_at, expires_at): (i64, i64, i64) = sqlx::query_as(
        "SELECT claim_fence, state_updated_at_ms, claim_expires_at_ms \
         FROM provider_delivery_inbox WHERE id = $1",
    )
    .bind(delivery_id)
    .fetch_one(database.pool())
    .await?;
    for (renewed_fence, observed_at, renewed_expires_at, expected_constraint) in [
        (
            fence,
            state_updated_at,
            expires_at,
            "provider_delivery_inbox_claimed_fence_transition",
        ),
        (
            fence + 1,
            state_updated_at,
            expires_at + 100,
            "provider_delivery_inbox_renewal_transition",
        ),
        (
            fence + 1,
            state_updated_at + 1,
            expires_at,
            "provider_delivery_inbox_renewal_transition",
        ),
    ] {
        let error = directly_rotate_claim_window(
            database,
            delivery_id,
            renewed_fence,
            observed_at,
            renewed_expires_at,
        )
        .await
        .expect_err("non-monotonic renewal must fail in PostgreSQL");
        assert_database_constraint(&error, expected_constraint);
    }
    let error = directly_rotate_claim_window(
        database,
        delivery_id,
        fence + 1,
        state_updated_at + 1,
        state_updated_at + 2 + MAX_PROVIDER_DELIVERY_CLAIM_MILLIS,
    )
    .await
    .expect_err("oversized renewal window must fail in PostgreSQL");
    assert_database_constraint(&error, "provider_delivery_inbox_state_shape");
    Ok(())
}

async fn durable_workflow_paths(
    database: &TestDatabase,
    delivery_id: Uuid,
) -> TestResult<Vec<String>> {
    Ok(sqlx::query_scalar(
        r"
        SELECT workflow_path
        FROM provider_delivery_workflow_outcomes
        WHERE inbox_id = $1
        ORDER BY ordinal
        ",
    )
    .bind(delivery_id)
    .fetch_all(database.pool())
    .await?)
}

fn completion_for_admitted_run(
    claim: ProviderDeliveryClaimFence,
    run_id: RunId,
    completed_at: i64,
) -> CompleteProviderDelivery {
    let completed_at = if completed_at >= 1_000_000_000_000 {
        UnixMillis::new(completed_at)
    } else {
        future_test_time(0)
    };
    CompleteProviderDelivery::new(
        claim,
        vec![
            ProviderDeliveryWorkflowOutcome::new(
                ".ci/workflows/a.yml",
                ProviderDeliveryWorkflowConclusion::Skipped {
                    reason: failure("event_not_selected"),
                },
            )
            .expect("outcome"),
            ProviderDeliveryWorkflowOutcome::new(
                ".ci/workflows/z.yml",
                ProviderDeliveryWorkflowConclusion::Admitted { run_id },
            )
            .expect("outcome"),
        ],
        completed_at,
    )
    .expect("completion")
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn provider_inbox_accepts_the_exact_event_ceiling_and_rejects_one_more_byte() -> TestResult {
    run_with_database(|database| async move {
        seed_tenant(&database, "delivery-event-limit").await?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        let identity = ProviderDeliveryIdentity::new(
            TenantScope::from_authenticated_tenant_id("delivery-event-limit")?,
            "synthetic",
            connection,
            ProviderInstallationId::new(101)?,
            ProviderRepositoryCoordinates::new(
                ProviderRepositoryId::new(202)?,
                ProviderRepositoryVisibility::Public,
                "automata-ci/automata",
            )?,
            "delivery-exact-limit",
        )?;
        let raw_event = AdmissionObject::new_event(
            Sha256Digest::from_bytes([12; 32]),
            ObjectKey::new("provider-events/delivery-exact-limit/12")?,
            MAX_ADMISSION_EVENT_BYTES,
            "application/json",
        )?;
        let accepted = AcceptProviderDelivery::new(
            identity,
            Sha256Digest::from_bytes([13; 32]),
            raw_event,
            provider_delivery_event_envelope(14),
            UnixMillis::new(100),
        )?;
        let receipt = database.store().accept_provider_delivery(accepted).await?;
        let stored_size: i64 = sqlx::query_scalar(
            "SELECT raw_event_size_bytes FROM provider_delivery_inbox WHERE id = $1",
        )
        .bind(receipt.id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(stored_size, i64::try_from(MAX_ADMISSION_EVENT_BYTES)?);

        let oversized = sqlx::query(
            r"
            INSERT INTO provider_delivery_inbox (
                id, tenant_id, provider, connection_id, installation_id,
                provider_repository_id, repository_visibility,
                repository_identity, delivery_id,
                request_digest, raw_event_digest, raw_event_object_key,
                raw_event_size_bytes, raw_event_media_type,
                accepted_at_ms, state_updated_at_ms
            )
            VALUES (
                $1, 'delivery-event-limit', 'synthetic', $2, 101,
                202, 'public', 'automata-ci/automata', 'delivery-over-limit',
                $3, $4, 'provider-events/delivery-over-limit/14',
                $5, 'application/json', 101, 101
            )
            ",
        )
        .bind(Uuid::new_v4())
        .bind(connection.as_uuid())
        .bind([14_u8; 32].as_slice())
        .bind([15_u8; 32].as_slice())
        .bind(i64::try_from(MAX_ADMISSION_EVENT_BYTES)? + 1)
        .execute(database.pool())
        .await
        .expect_err("one byte above the provider-event ceiling must fail");
        assert_database_constraint(&oversized, "provider_delivery_inbox_raw_size_bounded");
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn concurrent_accept_is_exact_and_changed_evidence_conflicts() -> TestResult {
    run_with_database(|database| async move {
        seed_tenant(&database, "delivery-accept").await?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        let first = acceptance("delivery-accept", connection, "delivery-1", 7, 100);
        let replay = acceptance("delivery-accept", connection, "delivery-1", 7, 100);
        let left_store = database.store().clone();
        let right_store = database.store().clone();
        let (left, right) = tokio::join!(
            left_store.accept_provider_delivery(first),
            right_store.accept_provider_delivery(replay)
        );
        let left = left?;
        let right = right?;
        assert_eq!(left, right);
        assert_eq!(left.state(), ProviderDeliveryState::Pending);
        assert_eq!(left.accepted_at(), UnixMillis::new(100));
        let later_exact = acceptance("delivery-accept", connection, "delivery-1", 7, 101);
        assert_eq!(
            database
                .store()
                .accept_provider_delivery(later_exact)
                .await?,
            left
        );

        let changed = acceptance("delivery-accept", connection, "delivery-1", 8, 102);
        assert!(matches!(
            database.store().accept_provider_delivery(changed).await,
            Err(ProviderDeliveryStoreError::ReplayConflict)
        ));
        let visibility_rebind = acceptance_with_visibility(
            "delivery-accept",
            connection,
            "delivery-1",
            7,
            103,
            ProviderRepositoryVisibility::Public,
        );
        assert!(matches!(
            database
                .store()
                .accept_provider_delivery(visibility_rebind)
                .await,
            Err(ProviderDeliveryStoreError::ReplayConflict)
        ));
        let durable_visibility: String = sqlx::query_scalar(
            "SELECT repository_visibility FROM provider_delivery_inbox WHERE id = $1",
        )
        .bind(left.id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(durable_visibility, "private");

        assert_visibility_is_immutable(&database, left.id().as_uuid()).await?;

        let conflicting_left = acceptance(
            "delivery-accept",
            connection,
            "delivery-race-conflict",
            11,
            200,
        );
        let conflicting_right = acceptance(
            "delivery-accept",
            connection,
            "delivery-race-conflict",
            12,
            200,
        );
        let left_store = database.store().clone();
        let right_store = database.store().clone();
        let (left_result, right_result) = tokio::join!(
            left_store.accept_provider_delivery(conflicting_left.clone()),
            right_store.accept_provider_delivery(conflicting_right.clone())
        );
        let (winner, winner_request) = match (left_result, right_result) {
            (Ok(receipt), Err(ProviderDeliveryStoreError::ReplayConflict)) => {
                (receipt, conflicting_left)
            }
            (Err(ProviderDeliveryStoreError::ReplayConflict), Ok(receipt)) => {
                (receipt, conflicting_right)
            }
            outcomes => panic!("expected one accept and one replay conflict, got {outcomes:?}"),
        };
        assert_eq!(
            database
                .store()
                .accept_provider_delivery(winner_request)
                .await?,
            winner
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn changing_only_the_event_envelope_is_a_replay_conflict() -> TestResult {
    run_with_database(|database| async move {
        seed_tenant(&database, "delivery-envelope-replay").await?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        let accepted = acceptance(
            "delivery-envelope-replay",
            connection,
            "delivery-envelope-replay-1",
            7,
            100,
        );
        database.store().accept_provider_delivery(accepted).await?;

        let changed_envelope = acceptance_with_visibility_and_envelope(
            "delivery-envelope-replay",
            connection,
            "delivery-envelope-replay-1",
            7,
            101,
            ProviderRepositoryVisibility::Private,
            provider_delivery_event_envelope(99),
        );
        assert!(matches!(
            database
                .store()
                .accept_provider_delivery(changed_envelope)
                .await,
            Err(ProviderDeliveryStoreError::ReplayConflict)
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn claim_rehydrates_the_exact_persisted_event_envelope() -> TestResult {
    run_with_database(|database| async move {
        seed_tenant(&database, "delivery-envelope-claim").await?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        let shortest_media_type_envelope = ProviderDeliveryEventEnvelope::new(
            1,
            1,
            Sha256Digest::from_bytes([33; 32]),
            br"{}".to_vec(),
            "/",
        )?;
        let accepted = acceptance_with_visibility_and_envelope(
            "delivery-envelope-claim",
            connection,
            "delivery-envelope-1",
            31,
            100,
            ProviderRepositoryVisibility::Private,
            shortest_media_type_envelope,
        );
        let expected_envelope = accepted.event_envelope().clone();
        assert_eq!(expected_envelope.media_type(), "/");
        let receipt = database.store().accept_provider_delivery(accepted).await?;

        let durable: (i16, i16, Vec<u8>, Vec<u8>, String) = sqlx::query_as(
            r"
            SELECT event_envelope_schema, event_registry_schema,
                   event_envelope_digest, event_envelope_bytes,
                   event_envelope_media_type
            FROM provider_delivery_inbox
            WHERE id = $1
            ",
        )
        .bind(receipt.id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(durable.0, i16::try_from(expected_envelope.schema())?);
        assert_eq!(
            durable.1,
            i16::try_from(expected_envelope.registry_schema())?
        );
        assert_eq!(durable.2, expected_envelope.digest().as_bytes());
        assert_eq!(durable.3, expected_envelope.canonical_bytes());
        assert_eq!(durable.4, expected_envelope.media_type());

        let claimed = database
            .store()
            .claim_provider_delivery(claim(owner(), 110))
            .await?
            .expect("sealed delivery is claimable");
        assert_eq!(claimed.receipt().id(), receipt.id());
        assert_eq!(claimed.event_envelope(), &expected_envelope);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn claim_quarantines_legacy_unsealed_rows_without_poisoning_sealed_work() -> TestResult {
    run_with_database(|database| async move {
        seed_tenant(&database, "delivery-envelope-legacy").await?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        assert_partial_event_envelope_is_rejected(&database, &connection).await?;
        seed_legacy_unsealed_deliveries(&database, &connection).await?;

        let sealed = database
            .store()
            .accept_provider_delivery(acceptance(
                "delivery-envelope-legacy",
                connection,
                "delivery-sealed",
                45,
                101,
            ))
            .await?;
        let claim_owner = owner();
        let first_observed_at = database_now(&database).await?;
        let claimed = database
            .store()
            .claim_provider_delivery(ClaimProviderDelivery::new(
                claim_owner,
                UnixMillis::new(first_observed_at),
                UnixMillis::new(first_observed_at + 60_000),
            )?)
            .await?
            .expect("sealed work remains claimable");
        assert_eq!(claimed.receipt().id(), sealed.id());
        assert_eq!(
            legacy_delivery_state_counts(&database, claim_owner).await?,
            (64, 1, 64),
            "the first claim commits one bounded quarantine batch"
        );

        let final_claim_owner = owner();
        let final_observed_at = database_now(&database).await?;
        assert!(
            database
                .store()
                .claim_provider_delivery(ClaimProviderDelivery::new(
                    final_claim_owner,
                    UnixMillis::new(final_observed_at),
                    UnixMillis::new(final_observed_at + 60_000),
                )?)
                .await?
                .is_none(),
            "the next claim drains remaining legacy work without decoding it"
        );
        assert_eq!(
            legacy_delivery_state_counts(&database, claim_owner).await?,
            (65, 0, 64)
        );
        assert_eq!(
            legacy_delivery_state_counts(&database, final_claim_owner).await?,
            (65, 0, 1)
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn caller_clock_skew_cannot_issue_or_take_over_a_claim_horizon() -> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        seed_tenant(&database, "delivery-claim-db-time").await?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        database
            .store()
            .accept_provider_delivery(acceptance(
                "delivery-claim-db-time",
                connection,
                "delivery-db-time",
                41,
                100,
            ))
            .await?;

        let first_owner = owner();
        let database_before = database_now(&database).await?;
        let fast_observation = database_before + 50_000;
        let first = database
            .store()
            .claim_provider_delivery(ClaimProviderDelivery::new(
                first_owner,
                UnixMillis::new(fast_observation),
                UnixMillis::new(fast_observation + 321),
            )?)
            .await?
            .expect("bounded fast caller can claim");
        let database_after = database_now(&database).await?;
        assert_eq!(first.claim().owner(), first_owner);
        assert_ne!(first.claimed_at(), UnixMillis::new(fast_observation));
        assert!((database_before..=database_after).contains(&first.claimed_at().get()));
        assert_eq!(first.expires_at().get() - first.claimed_at().get(), 321);

        let slow_observation = database_after - 50_000;
        assert!(
            database
                .store()
                .claim_provider_delivery(ClaimProviderDelivery::new(
                    owner(),
                    UnixMillis::new(slow_observation),
                    UnixMillis::new(slow_observation + 321),
                )?)
                .await?
                .is_none(),
            "a caller jump cannot take over a DB-live claim",
        );
        let before_rejected_clock: (i64, Uuid, i64) = sqlx::query_as(
            "SELECT claim_fence, claim_owner_id, claim_expires_at_ms \
             FROM provider_delivery_inbox WHERE id = $1",
        )
        .bind(first.receipt().id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert!(matches!(
            database
                .store()
                .claim_provider_delivery(ClaimProviderDelivery::new(
                    owner(),
                    UnixMillis::new(database_after + 61_000),
                    UnixMillis::new(database_after + 61_321),
                )?)
                .await,
            Err(ProviderDeliveryStoreError::ClaimRejected)
        ));
        let after_rejected_clock: (i64, Uuid, i64) = sqlx::query_as(
            "SELECT claim_fence, claim_owner_id, claim_expires_at_ms \
             FROM provider_delivery_inbox WHERE id = $1",
        )
        .bind(first.receipt().id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(after_rejected_clock, before_rejected_clock);

        clock.set(first.expires_at().get() + 1).await?;
        let takeover_database_before = database_now(&database).await?;
        let slow_takeover_observation = takeover_database_before - 50_000;
        let takeover_owner = owner();
        let takeover = database
            .store()
            .claim_provider_delivery(ClaimProviderDelivery::new(
                takeover_owner,
                UnixMillis::new(slow_takeover_observation),
                UnixMillis::new(slow_takeover_observation + 321),
            )?)
            .await?
            .expect("DB-expired claim can be taken over by a bounded slow caller");
        assert_eq!(takeover.claim().owner(), takeover_owner);
        assert_eq!(takeover.claim().fence(), first.claim().fence() + 1);
        assert_eq!(takeover.attempt(), first.attempt());
        assert_eq!(
            takeover.expires_at().get() - takeover.claimed_at().get(),
            321
        );
        assert!(takeover.claimed_at().get() >= takeover_database_before);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn concurrent_claim_has_one_winner_and_expiry_reclaims_with_a_new_fence() -> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        seed_tenant(&database, "delivery-claim").await?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        database
            .store()
            .accept_provider_delivery(acceptance(
                "delivery-claim",
                connection,
                "delivery-1",
                7,
                100,
            ))
            .await?;

        let first_owner = owner();
        let second_owner = owner();
        let left_store = database.store().clone();
        let right_store = database.store().clone();
        let (left, right) = tokio::join!(
            left_store.claim_provider_delivery(claim(first_owner, 110)),
            right_store.claim_provider_delivery(claim(second_owner, 110))
        );
        let mut winners = [left?, right?].into_iter().flatten().collect::<Vec<_>>();
        assert_eq!(winners.len(), 1);
        let first_claim = winners.pop().expect("one claim");
        assert_eq!(first_claim.attempt(), 1);
        assert_eq!(first_claim.claim().fence(), 1);

        assert!(
            database
                .store()
                .claim_provider_delivery(claim(owner(), 1_109))
                .await?
                .is_none()
        );
        clock.set(first_claim.expires_at().get() + 1).await?;
        let reclaimed = database
            .store()
            .claim_provider_delivery(claim(owner(), 1_110))
            .await?
            .expect("expired claim is reclaimable");
        assert_eq!(reclaimed.receipt().id(), first_claim.receipt().id());
        assert_eq!(reclaimed.attempt(), 1, "crash reclaim is the same attempt");
        assert_eq!(reclaimed.claim().fence(), 2);
        let transition_at = UnixMillis::new(reclaimed.claimed_at().get() + 1);

        let stale = RejectProviderDelivery::new(
            first_claim.claim(),
            failure("stale_worker"),
            transition_at,
        )?;
        assert!(matches!(
            database.store().reject_provider_delivery(stale).await,
            Err(ProviderDeliveryStoreError::ClaimRejected)
        ));
        let stale_retry = RetryProviderDelivery::new(
            first_claim.claim(),
            failure("provider_unavailable"),
            transition_at,
            UnixMillis::new(transition_at.get() + 10),
        )?;
        assert!(matches!(
            database.store().retry_provider_delivery(stale_retry).await,
            Err(ProviderDeliveryStoreError::ClaimRejected)
        ));
        let stale_completion =
            CompleteProviderDelivery::new(first_claim.claim(), Vec::new(), transition_at)?;
        assert!(matches!(
            database
                .store()
                .complete_provider_delivery(stale_completion)
                .await,
            Err(ProviderDeliveryStoreError::ClaimRejected)
        ));

        let retry = RetryProviderDelivery::new(
            reclaimed.claim(),
            failure("provider_unavailable"),
            transition_at,
            database_time_after(&database, 5_000).await?,
        )?;
        let retry_at = retry.retry_at();
        let receipt = database.store().retry_provider_delivery(retry).await?;
        assert_eq!(receipt.state(), ProviderDeliveryState::RetryPending);
        assert_eq!(receipt.attempts(), 1);
        assert!(
            database
                .store()
                .claim_provider_delivery(claim(owner(), 1_199))
                .await?
                .is_none()
        );
        clock.set(retry_at.get() + 1).await?;
        let second_attempt = database
            .store()
            .claim_provider_delivery(claim(owner(), 1_200))
            .await?
            .expect("retry is eligible");
        assert_eq!(second_attempt.attempt(), 2);
        assert_eq!(second_attempt.claim().fence(), 3);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn claim_renewal_rotates_the_fence_and_is_exactly_idempotent() -> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        seed_tenant(&database, "delivery-renew-basic").await?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        let claimed = accept_and_claim(
            &database,
            "delivery-renew-basic",
            connection,
            "renew-complete",
            7,
            110,
        )
        .await?;
        assert!(matches!(
            renewal_request(
                claimed.claim(),
                claimed.attempt(),
                claimed.claimed_at(),
                claimed.expires_at(),
                claimed.claimed_at().get(),
                claimed.expires_at().get(),
            ),
            Err(ProviderDeliveryValueError::InvalidClaimInterval)
        ));
        clock.advance(1).await?;
        let renewal_observed_at = claimed.claimed_at().get() + 500;
        let renewal = renewal_request(
            claimed.claim(),
            claimed.attempt(),
            claimed.claimed_at(),
            claimed.expires_at(),
            renewal_observed_at,
            renewal_observed_at + 1_000,
        )?;
        let (renewed, duplicate) = tokio::join!(
            database.store().renew_provider_delivery_claim(renewal),
            database.store().renew_provider_delivery_claim(renewal),
        );
        let renewed = renewed?;
        assert_eq!(
            duplicate?, renewed,
            "concurrent identical renewal must replay from a fresh snapshot",
        );
        assert_eq!(renewed.claim().delivery_id(), claimed.claim().delivery_id());
        assert_eq!(renewed.claim().owner(), claimed.claim().owner());
        assert_eq!(renewed.claim().fence(), claimed.claim().fence() + 1);
        assert_eq!(renewed.attempt(), claimed.attempt());
        assert_eq!(renewed.claimed_at(), claimed.claimed_at());
        assert!(renewed.renewed_at() > claimed.claimed_at());
        assert_eq!(
            renewed.expires_at().get() - renewed.renewed_at().get(),
            1_000
        );
        assert_eq!(
            database
                .store()
                .renew_provider_delivery_claim(renewal)
                .await?,
            renewed,
            "an exact lost-response retry must replay the committed renewal",
        );
        assert_stale_renewal_evidence_is_rejected(&database, &claimed).await?;
        assert!(
            database
                .store()
                .claim_provider_delivery(claim(owner(), 1_110))
                .await?
                .is_none(),
            "the original expiry no longer permits takeover",
        );
        assert!(matches!(
            database
                .store()
                .complete_provider_delivery(CompleteProviderDelivery::new(
                    claimed.claim(),
                    Vec::new(),
                    UnixMillis::new(renewed.renewed_at().get() + 1),
                )?)
                .await,
            Err(ProviderDeliveryStoreError::ClaimRejected)
        ));
        let completed = database
            .store()
            .complete_provider_delivery(CompleteProviderDelivery::new(
                renewed.claim(),
                Vec::new(),
                UnixMillis::new(renewed.renewed_at().get() + 1),
            )?)
            .await?;
        assert_eq!(completed.state(), ProviderDeliveryState::Completed);
        assert!(matches!(
            database
                .store()
                .renew_provider_delivery_claim(renewal)
                .await,
            Err(ProviderDeliveryStoreError::ClaimRejected)
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn renewal_caller_clock_only_admits_a_database_time_extension() -> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        seed_tenant(&database, "delivery-renew-clock-admission").await?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        database
            .store()
            .accept_provider_delivery(acceptance(
                "delivery-renew-clock-admission",
                connection,
                "renew-clock-admission",
                43,
                100,
            ))
            .await?;
        let initial_observation = database_now(&database).await?;
        let claimed = database
            .store()
            .claim_provider_delivery(ClaimProviderDelivery::new(
                owner(),
                UnixMillis::new(initial_observation),
                UnixMillis::new(initial_observation + 120_000),
            )?)
            .await?
            .expect("long test claim");

        let fast_database_now = database_now(&database).await?;
        let fast_observation = fast_database_now + 50_000;
        let apparent_extension = renewal_request(
            claimed.claim(),
            claimed.attempt(),
            claimed.claimed_at(),
            claimed.expires_at(),
            fast_observation,
            fast_observation + 80_000,
        )?;
        assert!(apparent_extension.expires_at() > claimed.expires_at());
        assert!(matches!(
            database
                .store()
                .renew_provider_delivery_claim(apparent_extension)
                .await,
            Err(ProviderDeliveryStoreError::ClaimRejected)
        ));

        clock.advance(1).await?;
        let ordinary_observation = database_now(&database).await?;
        let ordinary = renewal_request(
            claimed.claim(),
            claimed.attempt(),
            claimed.claimed_at(),
            claimed.expires_at(),
            ordinary_observation,
            ordinary_observation + 120_000,
        )?;
        let renewed = database
            .store()
            .renew_provider_delivery_claim(ordinary)
            .await?;
        assert_eq!(
            renewed.expires_at().get() - renewed.renewed_at().get(),
            120_000
        );
        assert_eq!(renewed.claim().fence(), claimed.claim().fence() + 1);

        clock.set(claimed.claimed_at().get() + 50_001).await?;
        let slow_database_now = database_now(&database).await?;
        let slow_observation = slow_database_now - 50_000;
        let slow_request = renewal_request(
            renewed.claim(),
            renewed.attempt(),
            renewed.claimed_at(),
            renewed.expires_at(),
            slow_observation,
            slow_observation + 180_000,
        )?;
        let slow_renewed = database
            .store()
            .renew_provider_delivery_claim(slow_request)
            .await?;
        assert_ne!(slow_renewed.renewed_at(), slow_request.observed_at());
        assert_eq!(
            slow_renewed.expires_at().get() - slow_renewed.renewed_at().get(),
            180_000,
        );
        assert_eq!(slow_renewed.claim().fence(), renewed.claim().fence() + 1);
        assert_eq!(
            database
                .store()
                .renew_provider_delivery_claim(slow_request)
                .await?,
            slow_renewed,
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn renewal_issues_post_lock_database_time_and_exact_requested_duration() -> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        seed_tenant(&database, "delivery-renew-post-lock-time").await?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        database
            .store()
            .accept_provider_delivery(acceptance(
                "delivery-renew-post-lock-time",
                connection,
                "renew-post-lock-time",
                42,
                100,
            ))
            .await?;
        let claim_observed_at = database_now(&database).await?;
        let claimed = database
            .store()
            .claim_provider_delivery(ClaimProviderDelivery::new(
                owner(),
                UnixMillis::new(claim_observed_at),
                UnixMillis::new(claim_observed_at + 2_000),
            )?)
            .await?
            .expect("delivery claim");

        clock.advance(1).await?;
        let mut blocker = database.pool().begin().await?;
        let blocking_backend_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await?;
        sqlx::query("SELECT id FROM provider_delivery_inbox WHERE id = $1 FOR UPDATE")
            .bind(claimed.receipt().id().as_uuid())
            .fetch_one(&mut *blocker)
            .await?;
        let renewal_observed_at = database_now(&database).await?;
        let request = renewal_request(
            claimed.claim(),
            claimed.attempt(),
            claimed.claimed_at(),
            claimed.expires_at(),
            renewal_observed_at,
            renewal_observed_at + 2_000,
        )?;
        let store = database.store().clone();
        let renewal =
            tokio::spawn(async move { store.renew_provider_delivery_claim(request).await });
        wait_for_renewal_lock_wait(&database, blocking_backend_pid).await?;
        let immediately_before_release = clock.advance(100).await?;
        blocker.commit().await?;

        let renewed = renewal.await??;
        assert!(renewed.renewed_at().get() >= immediately_before_release);
        assert_ne!(renewed.renewed_at(), request.observed_at());
        assert_eq!(
            renewed.expires_at().get() - renewed.renewed_at().get(),
            2_000
        );
        assert_eq!(renewed.claim().fence(), claimed.claim().fence() + 1);
        assert_eq!(
            database
                .store()
                .renew_provider_delivery_claim(request)
                .await?,
            renewed,
            "the DB-issued successor remains an exact replay",
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn renewal_requires_predeadline_row_lock_but_replays_a_late_exact_successor() -> TestResult {
    run_with_database(|database| async move {
        seed_tenant(&database, "delivery-renew-deadline").await?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        let claimed = accept_and_claim(
            &database,
            "delivery-renew-deadline",
            connection,
            "renew-deadline",
            29,
            110,
        )
        .await?;

        let mut blocker = database.pool().begin().await?;
        let blocking_backend_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await?;
        sqlx::query("SELECT id FROM provider_delivery_inbox WHERE id = $1 FOR UPDATE")
            .bind(claimed.receipt().id().as_uuid())
            .fetch_one(&mut *blocker)
            .await?;
        let blocked_request = renewal_request(
            claimed.claim(),
            claimed.attempt(),
            claimed.claimed_at(),
            claimed.expires_at(),
            claimed.expires_at().get() - 800,
            claimed.expires_at().get() + 200,
        )?;
        let deadline = blocked_request.deadline();
        let store = database.store().clone();
        let renewal_task =
            tokio::spawn(async move { store.renew_provider_delivery_claim(blocked_request).await });
        wait_for_renewal_lock_wait(&database, blocking_backend_pid).await?;
        advance_past_monotonic_deadline(deadline).await;
        blocker.commit().await?;
        let blocked_result = renewal_task.await?;
        assert!(matches!(
            blocked_result,
            Err(ProviderDeliveryStoreError::ClaimRejected)
        ));
        let unchanged_fence: i64 =
            sqlx::query_scalar("SELECT claim_fence FROM provider_delivery_inbox WHERE id = $1")
                .bind(claimed.receipt().id().as_uuid())
                .fetch_one(database.pool())
                .await?;
        assert_eq!(unchanged_fence, i64::try_from(claimed.claim().fence())?);

        let replay_claimed = accept_and_claim(
            &database,
            "delivery-renew-deadline",
            connection,
            "renew-deadline-replay",
            30,
            110,
        )
        .await?;
        let replay_request = renewal_request(
            replay_claimed.claim(),
            replay_claimed.attempt(),
            replay_claimed.claimed_at(),
            replay_claimed.expires_at(),
            replay_claimed.expires_at().get() - 800,
            replay_claimed.expires_at().get() + 200,
        )?;
        let renewed = database
            .store()
            .renew_provider_delivery_claim(replay_request)
            .await?;
        advance_past_monotonic_deadline(replay_request.deadline()).await;
        assert_eq!(
            database
                .store()
                .renew_provider_delivery_claim(replay_request)
                .await?,
            renewed,
            "a committed exact successor remains replayable after its predecessor deadline",
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn renewal_and_terminal_transition_allow_only_one_exact_fence() -> TestResult {
    run_with_database(|database| async move {
        seed_tenant(&database, "delivery-renew-terminal-race").await?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        let claimed = accept_and_claim(
            &database,
            "delivery-renew-terminal-race",
            connection,
            "renew-terminal-race",
            17,
            110,
        )
        .await?;
        let renewal = renewal_request(
            claimed.claim(),
            claimed.attempt(),
            claimed.claimed_at(),
            claimed.expires_at(),
            200,
            1_200,
        )?;
        let completion =
            CompleteProviderDelivery::new(claimed.claim(), Vec::new(), future_test_time(0))?;

        let (renewed, completed) = tokio::join!(
            database.store().renew_provider_delivery_claim(renewal),
            database.store().complete_provider_delivery(completion),
        );
        match (renewed, completed) {
            (Ok(renewed), Err(ProviderDeliveryStoreError::ClaimRejected)) => {
                assert_eq!(renewed.claim().fence(), claimed.claim().fence() + 1);
            }
            (Err(ProviderDeliveryStoreError::ClaimRejected), Ok(completed)) => {
                assert_eq!(completed.state(), ProviderDeliveryState::Completed);
            }
            (renewed, completed) => {
                panic!(
                    "renewal and completion must serialize on one fence: {renewed:?}, {completed:?}"
                );
            }
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn renewal_and_expiry_reclaim_allow_only_one_fence_successor() -> TestResult {
    run_with_database(|database| async move {
        seed_tenant(&database, "delivery-renew-reclaim-race").await?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        let claimed = accept_and_claim(
            &database,
            "delivery-renew-reclaim-race",
            connection,
            "renew-reclaim-race",
            18,
            110,
        )
        .await?;
        let expired_at = claimed.expires_at().get();
        let renewal = renewal_request(
            claimed.claim(),
            claimed.attempt(),
            claimed.claimed_at(),
            claimed.expires_at(),
            expired_at - 500,
            expired_at + 999,
        )?;
        let reclaim_owner = owner();
        let reclaim = claim(reclaim_owner, expired_at);

        let (renewed, reclaimed) = tokio::join!(
            database.store().renew_provider_delivery_claim(renewal),
            database.store().claim_provider_delivery(reclaim),
        );
        match (renewed, reclaimed?) {
            (Ok(renewed), None) => {
                assert_eq!(renewed.claim().fence(), claimed.claim().fence() + 1);
                assert_eq!(renewed.claim().owner(), claimed.claim().owner());
            }
            (Err(ProviderDeliveryStoreError::ClaimRejected), Some(reclaimed)) => {
                assert_eq!(reclaimed.claim().fence(), claimed.claim().fence() + 1);
                assert_eq!(reclaimed.claim().owner(), reclaim_owner);
                assert!(reclaimed.claimed_at().get() >= expired_at);
            }
            (renewed, reclaimed) => {
                panic!(
                    "renewal and reclaim must serialize on one fence successor: {renewed:?}, {reclaimed:?}"
                );
            }
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn renewal_cannot_acquire_the_predecessor_row_after_its_deadline() -> TestResult {
    run_with_database(|database| async move {
        seed_tenant(&database, "delivery-renew-lock-deadline").await?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        let claimed = accept_and_claim(
            &database,
            "delivery-renew-lock-deadline",
            connection,
            "renew-lock-deadline",
            19,
            110,
        )
        .await?;
        let observed_at = claimed.expires_at().get() - 800;
        let monotonic_observed_at = tokio::time::Instant::now();
        let confirmed_predecessor_deadline = monotonic_observed_at + Duration::from_millis(400);
        let timing = ProviderDeliveryRenewalTiming::new(
            confirmed_predecessor_deadline,
            monotonic_observed_at,
            UnixMillis::new(observed_at),
            claimed.expires_at(),
        )?;
        let request = RenewProviderDeliveryClaim::new(
            claimed.claim(),
            claimed.attempt(),
            claimed.claimed_at(),
            timing,
            UnixMillis::new(claimed.expires_at().get() + 100),
        )?;
        let deadline = request.deadline();

        let mut blocker = database.pool().begin().await?;
        let blocking_backend_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await?;
        sqlx::query("SELECT id FROM provider_delivery_inbox WHERE id = $1 FOR UPDATE")
            .bind(claimed.receipt().id().as_uuid())
            .fetch_one(&mut *blocker)
            .await?;

        let store = database.store().clone();
        let renewal =
            tokio::spawn(async move { store.renew_provider_delivery_claim(request).await });
        wait_for_renewal_lock_wait(&database, blocking_backend_pid).await?;
        assert!(
            tokio::time::Instant::now() < deadline,
            "the renewal must reach the predecessor lock before its confirmed deadline"
        );
        advance_past_monotonic_deadline(deadline).await;
        blocker.rollback().await?;

        assert!(matches!(
            renewal.await?,
            Err(ProviderDeliveryStoreError::ClaimRejected)
        ));
        let durable: (i64, i64, i64) = sqlx::query_as(
            r"
            SELECT claim_fence, state_updated_at_ms, claim_expires_at_ms
            FROM provider_delivery_inbox
            WHERE id = $1
            ",
        )
        .bind(claimed.receipt().id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            durable,
            (
                i64::try_from(claimed.claim().fence())?,
                claimed.claimed_at().get(),
                claimed.expires_at().get(),
            )
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn late_exact_replay_waits_for_an_uncommitted_successor() -> TestResult {
    run_with_database(|database| async move {
        seed_tenant(&database, "delivery-renew-uncommitted-successor").await?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        let claimed = accept_and_claim(
            &database,
            "delivery-renew-uncommitted-successor",
            connection,
            "renew-uncommitted-successor",
            20,
            110,
        )
        .await?;
        let observed_at = claimed.expires_at().get() - 200;
        let expires_at = claimed.expires_at().get() + 200;
        let request = renewal_request(
            claimed.claim(),
            claimed.attempt(),
            claimed.claimed_at(),
            claimed.expires_at(),
            observed_at,
            expires_at,
        )?;

        let mut winner = database.pool().begin().await?;
        let winning_backend_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *winner)
            .await?;
        sqlx::query(
            r"
            UPDATE provider_delivery_inbox
            SET claim_fence = $2,
                renewal_predecessor_expires_at_ms = claim_expires_at_ms,
                state_updated_at_ms = $3,
                claim_expires_at_ms = $4
            WHERE id = $1
            ",
        )
        .bind(claimed.receipt().id().as_uuid())
        .bind(i64::try_from(claimed.claim().fence() + 1)?)
        .bind(observed_at)
        .bind(expires_at)
        .execute(&mut *winner)
        .await?;
        advance_past_monotonic_deadline(request.deadline()).await;

        let store = database.store().clone();
        let replay =
            tokio::spawn(async move { store.renew_provider_delivery_claim(request).await });
        wait_for_renewal_lock_wait(&database, winning_backend_pid).await?;
        winner.commit().await?;

        let renewed = replay.await??;
        assert_eq!(renewed.claim().delivery_id(), claimed.claim().delivery_id());
        assert_eq!(renewed.claim().owner(), claimed.claim().owner());
        assert_eq!(renewed.claim().fence(), claimed.claim().fence() + 1);
        assert_eq!(renewed.attempt(), claimed.attempt());
        assert_eq!(renewed.claimed_at(), claimed.claimed_at());
        assert_eq!(renewed.renewed_at(), UnixMillis::new(observed_at));
        assert_eq!(renewed.expires_at(), UnixMillis::new(expires_at));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn renewal_observation_fences_older_claim_transitions() -> TestResult {
    run_with_database(|database| async move {
        seed_tenant(&database, "delivery-renew-transition-time").await?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        let claimed = accept_and_claim(
            &database,
            "delivery-renew-transition-time",
            connection,
            "renew-transition-time",
            8,
            110,
        )
        .await?;
        let renewed = database
            .store()
            .renew_provider_delivery_claim(renewal_request(
                claimed.claim(),
                claimed.attempt(),
                claimed.claimed_at(),
                claimed.expires_at(),
                200,
                1_200,
            )?)
            .await?;

        let stale_completion = CompleteProviderDelivery::new(
            renewed.claim(),
            Vec::new(),
            UnixMillis::new(renewed.renewed_at().get() - 1),
        )?;
        assert!(matches!(
            database
                .store()
                .complete_provider_delivery(stale_completion)
                .await,
            Err(ProviderDeliveryStoreError::ClaimRejected)
        ));
        let stale_retry = RetryProviderDelivery::new(
            renewed.claim(),
            failure("provider_unavailable"),
            UnixMillis::new(renewed.renewed_at().get() - 1),
            UnixMillis::new(renewed.renewed_at().get() + 50),
        )?;
        assert!(matches!(
            database.store().retry_provider_delivery(stale_retry).await,
            Err(ProviderDeliveryStoreError::ClaimRejected)
        ));
        let stale_rejection = RejectProviderDelivery::new(
            renewed.claim(),
            failure("stale_observation"),
            UnixMillis::new(renewed.renewed_at().get() - 1),
        )?;
        assert!(matches!(
            database
                .store()
                .reject_provider_delivery(stale_rejection)
                .await,
            Err(ProviderDeliveryStoreError::ClaimRejected)
        ));

        let durable: (String, i64, i64) = sqlx::query_as(
            "SELECT state, state_updated_at_ms, claim_expires_at_ms FROM provider_delivery_inbox WHERE id = $1",
        )
        .bind(claimed.receipt().id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            durable,
            (
                "claimed".to_owned(),
                renewed.renewed_at().get(),
                renewed.expires_at().get(),
            )
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn claim_renewal_total_lifetime_is_absolutely_bounded() -> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        seed_tenant(&database, "delivery-renew-total").await?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        let total_claim = accept_and_claim(
            &database,
            "delivery-renew-total",
            connection,
            "renew-total-bound",
            9,
            2_100,
        )
        .await?;
        let database_now: i64 = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
        )
        .fetch_one(database.pool())
        .await?;
        let original_claimed_at = database_now - MAX_PROVIDER_DELIVERY_TOTAL_CLAIM_MILLIS + 3_000;
        let predecessor_expires_at = database_now + 1_000;
        sqlx::query(
            "ALTER TABLE provider_delivery_inbox DISABLE TRIGGER \
             provider_delivery_inbox_lifecycle_guard",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            UPDATE provider_delivery_inbox
            SET claimed_at_ms = $2,
                state_updated_at_ms = $3,
                renewal_predecessor_expires_at_ms = $4,
                claim_expires_at_ms = $5
            WHERE id = $1
            ",
        )
        .bind(total_claim.receipt().id().as_uuid())
        .bind(original_claimed_at)
        .bind(database_now - 100)
        .bind(database_now + 500)
        .bind(predecessor_expires_at)
        .execute(database.pool())
        .await?;
        sqlx::query(
            "ALTER TABLE provider_delivery_inbox ENABLE TRIGGER \
             provider_delivery_inbox_lifecycle_guard",
        )
        .execute(database.pool())
        .await?;

        let renewed = database
            .store()
            .renew_provider_delivery_claim(renewal_request(
                total_claim.claim(),
                total_claim.attempt(),
                UnixMillis::new(original_claimed_at),
                UnixMillis::new(predecessor_expires_at),
                database_now,
                database_now + 2_000,
            )?)
            .await?;
        clock.advance(1_500).await?;
        let slow_observation = renewed.renewed_at().get() + 1;
        let over_horizon = renewal_request(
            renewed.claim(),
            renewed.attempt(),
            renewed.claimed_at(),
            renewed.expires_at(),
            slow_observation,
            slow_observation + 2_000,
        )?;
        assert!(matches!(
            database
                .store()
                .renew_provider_delivery_claim(over_horizon)
                .await,
            Err(ProviderDeliveryStoreError::ClaimRejected)
        ));
        let (attempts, fence): (i16, i64) = sqlx::query_as(
            "SELECT attempt_count, claim_fence FROM provider_delivery_inbox WHERE id = $1",
        )
        .bind(total_claim.receipt().id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(attempts, 1);
        assert_eq!(fence, i64::try_from(renewed.claim().fence())?);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn expired_or_reclaimed_fence_cannot_be_renewed() -> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        seed_tenant(&database, "delivery-renew-expired").await?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        let expired_claim = accept_and_claim(
            &database,
            "delivery-renew-expired",
            connection,
            "renew-expired-fence",
            11,
            4_000_100,
        )
        .await?;
        let expired_at = expired_claim.expires_at().get();
        assert!(matches!(
            renewal_request(
                expired_claim.claim(),
                expired_claim.attempt(),
                expired_claim.claimed_at(),
                expired_claim.expires_at(),
                expired_at,
                expired_at + 1_000,
            ),
            Err(ProviderDeliveryValueError::InvalidClaimInterval)
        ));
        clock.set(expired_claim.expires_at().get() + 1).await?;
        let reclaimed = database
            .store()
            .claim_provider_delivery(claim(owner(), expired_at))
            .await?
            .expect("expired claim must be reclaimed with a new fence");
        assert_eq!(reclaimed.attempt(), expired_claim.attempt());
        assert_eq!(reclaimed.claim().fence(), expired_claim.claim().fence() + 1);
        assert!(matches!(
            renewal_request(
                expired_claim.claim(),
                expired_claim.attempt(),
                expired_claim.claimed_at(),
                expired_claim.expires_at(),
                expired_at + 1,
                expired_at + 1_001,
            ),
            Err(ProviderDeliveryValueError::InvalidClaimInterval)
        ));
        let renewal_observed_at = reclaimed.claimed_at().get() + 1;
        clock.set(renewal_observed_at).await?;
        let reclaimed_renewal = database
            .store()
            .renew_provider_delivery_claim(renewal_request(
                reclaimed.claim(),
                reclaimed.attempt(),
                reclaimed.claimed_at(),
                reclaimed.expires_at(),
                renewal_observed_at,
                renewal_observed_at + 1_000,
            )?)
            .await?;
        assert_eq!(
            reclaimed_renewal.claim().fence(),
            reclaimed.claim().fence() + 1
        );
        assert_eq!(
            reclaimed_renewal.expires_at().get() - reclaimed_renewal.renewed_at().get(),
            1_000
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn database_guards_renewal_windows_independently_of_the_adapter() -> TestResult {
    run_with_database(|database| async move {
        seed_tenant(&database, "delivery-renew-sql").await?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        let claimed = accept_and_claim(
            &database,
            "delivery-renew-sql",
            connection,
            "renew-sql-guard",
            13,
            110,
        )
        .await?;
        let delivery_id = claimed.receipt().id().as_uuid();
        let claim_start = claimed.claimed_at().get();
        let valid_observed_at = claim_start + 100;
        let valid_expires_at = claimed.expires_at().get() + 100;

        directly_rotate_claim_window(
            &database,
            delivery_id,
            2,
            valid_observed_at,
            valid_expires_at,
        )
        .await?;
        assert_invalid_direct_renewals(&database, delivery_id).await?;

        let error = sqlx::query(
            r"
            UPDATE provider_delivery_inbox
            SET claim_fence = claim_fence + 1,
                claimed_at_ms = $2,
                state_updated_at_ms = $2,
                claim_expires_at_ms = $3
            WHERE id = $1
            ",
        )
        .bind(delivery_id)
        .bind(valid_observed_at + 1)
        .bind(valid_expires_at + 100)
        .execute(database.pool())
        .await
        .expect_err("a live claim cannot be reclaimed under a different fence");
        assert_database_constraint(&error, "provider_delivery_inbox_reclaim_transition");

        for (renewed_fence, observed_at, expires_at) in [
            (3, claim_start + 1_099, claim_start + 901_099),
            (4, claim_start + 901_098, claim_start + 1_801_098),
            (5, claim_start + 1_801_097, claim_start + 2_701_097),
            (6, claim_start + 2_701_096, claim_start + 3_600_000),
        ] {
            directly_rotate_claim_window(
                &database,
                delivery_id,
                renewed_fence,
                observed_at,
                expires_at,
            )
            .await?;
        }
        let error = directly_rotate_claim_window(
            &database,
            delivery_id,
            7,
            claim_start + 3_599_999,
            claim_start + 3_600_001,
        )
        .await
        .expect_err("total claim lifetime overflow must fail in PostgreSQL");
        assert_database_constraint(&error, "provider_delivery_inbox_state_shape");
        let error = directly_rotate_claim_window(
            &database,
            delivery_id,
            7,
            claim_start + 3_600_000,
            claim_start + 3_601_000,
        )
        .await
        .expect_err("post-expiry renewal must fail in PostgreSQL");
        assert_database_constraint(&error, "provider_delivery_inbox_renewal_transition");

        let durable: (i16, i64, i64) = sqlx::query_as(
            "SELECT attempt_count, claim_fence, claim_expires_at_ms FROM provider_delivery_inbox WHERE id = $1",
        )
        .bind(delivery_id)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(durable, (1, 6, claim_start + 3_600_000));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn zero_outcome_completion_is_idempotent_for_the_exact_terminal_fence() -> TestResult {
    run_with_database(|database| async move {
        seed_tenant(&database, "delivery-complete").await?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        database
            .store()
            .accept_provider_delivery(acceptance("delivery-complete", connection, "zero", 7, 100))
            .await?;
        let zero_claim = database
            .store()
            .claim_provider_delivery(claim(owner(), 110))
            .await?
            .expect("zero claim");
        let zero =
            CompleteProviderDelivery::new(zero_claim.claim(), Vec::new(), future_test_time(0))?;
        let completed = database
            .store()
            .complete_provider_delivery(zero.clone())
            .await?;
        assert_eq!(completed.state(), ProviderDeliveryState::Completed);
        assert_eq!(
            database.store().complete_provider_delivery(zero).await?,
            completed,
            "same claim and outcome digest is an exact terminal replay"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn many_completion_is_sorted_idempotent_and_rejects_changed_replay() -> TestResult {
    run_with_database(|database| async move {
        seed_tenant(&database, "delivery-complete-many").await?;
        let admitted_run =
            seed_workflow_run(&database, "delivery-complete-many", "admitted", 202).await?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        database
            .store()
            .accept_provider_delivery(acceptance(
                "delivery-complete-many",
                connection,
                "many",
                8,
                200,
            ))
            .await?;
        let many_claim = database
            .store()
            .claim_provider_delivery(claim(owner(), 210))
            .await?
            .expect("many claim");
        let outcomes = vec![
            ProviderDeliveryWorkflowOutcome::new(
                ".ci/workflows/z.yml",
                ProviderDeliveryWorkflowConclusion::Failed {
                    failure_kind: failure("workflow_invalid"),
                },
            )?,
            ProviderDeliveryWorkflowOutcome::new(
                ".ci/workflows/a.yml",
                ProviderDeliveryWorkflowConclusion::Admitted {
                    run_id: admitted_run,
                },
            )?,
            ProviderDeliveryWorkflowOutcome::new(
                ".ci/workflows/m.yml",
                ProviderDeliveryWorkflowConclusion::Skipped {
                    reason: failure("event_not_selected"),
                },
            )?,
        ];
        let many =
            CompleteProviderDelivery::new(many_claim.claim(), outcomes, future_test_time(0))?;
        assert_eq!(
            many.outcomes()
                .iter()
                .map(ProviderDeliveryWorkflowOutcome::workflow_path)
                .collect::<Vec<_>>(),
            vec![
                ".ci/workflows/a.yml",
                ".ci/workflows/m.yml",
                ".ci/workflows/z.yml"
            ]
        );
        let many_receipt = database
            .store()
            .complete_provider_delivery(many.clone())
            .await?;
        assert_eq!(many_receipt.state(), ProviderDeliveryState::Completed);
        assert_eq!(
            database
                .store()
                .complete_provider_delivery(many.clone())
                .await?,
            many_receipt
        );
        let durable_paths = durable_workflow_paths(&database, many_receipt.id().as_uuid()).await?;
        assert_eq!(
            durable_paths,
            vec![
                ".ci/workflows/a.yml",
                ".ci/workflows/m.yml",
                ".ci/workflows/z.yml"
            ]
        );

        let changed_time = CompleteProviderDelivery::new(
            many_claim.claim(),
            many.outcomes().to_vec(),
            UnixMillis::new(many.completed_at().get() + 1),
        )?;
        assert!(matches!(
            database
                .store()
                .complete_provider_delivery(changed_time)
                .await,
            Err(ProviderDeliveryStoreError::ClaimRejected)
        ));

        let changed = CompleteProviderDelivery::new(
            many_claim.claim(),
            Vec::new(),
            UnixMillis::new(many.completed_at().get() + 1),
        )?;
        assert!(matches!(
            database.store().complete_provider_delivery(changed).await,
            Err(ProviderDeliveryStoreError::ClaimRejected)
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn admitted_outcomes_require_the_exact_inbox_repository() -> TestResult {
    run_with_database(|database| async move {
        seed_tenant(&database, "delivery-run-authority").await?;
        seed_tenant(&database, "delivery-run-other").await?;
        let same_tenant_run =
            seed_workflow_run(&database, "delivery-run-authority", "same-tenant", 202).await?;
        let sibling_repository_run =
            seed_workflow_run(&database, "delivery-run-authority", "sibling", 303).await?;
        let cross_tenant_run =
            seed_workflow_run(&database, "delivery-run-other", "cross-tenant", 202).await?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        let receipt = database
            .store()
            .accept_provider_delivery(acceptance(
                "delivery-run-authority",
                connection,
                "delivery-1",
                7,
                100,
            ))
            .await?;
        let claimed = database
            .store()
            .claim_provider_delivery(claim(owner(), 110))
            .await?
            .expect("claim");
        let nonexistent_run = RunId::from_uuid(Uuid::new_v4());
        assert_ne!(nonexistent_run, same_tenant_run);
        assert_ne!(nonexistent_run, sibling_repository_run);
        assert_ne!(nonexistent_run, cross_tenant_run);

        for invalid in [
            completion_for_admitted_run(claimed.claim(), nonexistent_run, 111),
            completion_for_admitted_run(claimed.claim(), sibling_repository_run, 112),
            completion_for_admitted_run(claimed.claim(), cross_tenant_run, 113),
        ] {
            assert!(matches!(
                database.store().complete_provider_delivery(invalid).await,
                Err(ProviderDeliveryStoreError::OutcomeRunRejected)
            ));
            let state: String =
                sqlx::query_scalar("SELECT state FROM provider_delivery_inbox WHERE id = $1")
                    .bind(receipt.id().as_uuid())
                    .fetch_one(database.pool())
                    .await?;
            let outcome_count: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM provider_delivery_workflow_outcomes WHERE inbox_id = $1",
            )
            .bind(receipt.id().as_uuid())
            .fetch_one(database.pool())
            .await?;
            assert_eq!(state, "claimed", "invalid run rolls back terminal state");
            assert_eq!(
                outcome_count, 0,
                "invalid run rolls back earlier outcome inserts"
            );
        }

        let valid_completion = completion_for_admitted_run(claimed.claim(), same_tenant_run, 114);
        let completed = database
            .store()
            .complete_provider_delivery(valid_completion.clone())
            .await?;
        assert_eq!(completed.state(), ProviderDeliveryState::Completed);
        assert_eq!(
            database
                .store()
                .complete_provider_delivery(valid_completion)
                .await?,
            completed
        );
        let durable_tenants: Vec<String> = sqlx::query_scalar(
            "SELECT tenant_id FROM provider_delivery_workflow_outcomes \
             WHERE inbox_id = $1 ORDER BY ordinal",
        )
        .bind(receipt.id().as_uuid())
        .fetch_all(database.pool())
        .await?;
        assert_eq!(
            durable_tenants,
            vec!["delivery-run-authority".to_owned(); 2]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn duplicate_outcomes_fail_before_io_and_transaction_errors_roll_back_completion()
-> TestResult {
    run_with_database(|database| async move {
        seed_tenant(&database, "delivery-atomic").await?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        let receipt = database
            .store()
            .accept_provider_delivery(acceptance(
                "delivery-atomic",
                connection,
                "delivery-1",
                7,
                100,
            ))
            .await?;
        let claimed = database
            .store()
            .claim_provider_delivery(claim(owner(), 110))
            .await?
            .expect("claim");
        let duplicate = || {
            ProviderDeliveryWorkflowOutcome::new(
                ".ci/workflows/ci.yml",
                ProviderDeliveryWorkflowConclusion::Skipped {
                    reason: failure("not_selected"),
                },
            )
            .expect("outcome")
        };
        assert!(matches!(
            CompleteProviderDelivery::new(
                claimed.claim(),
                vec![duplicate(), duplicate()],
                future_test_time(0),
            ),
            Err(ProviderDeliveryValueError::DuplicateWorkflowPath)
        ));

        sqlx::query(
            "ALTER TABLE provider_delivery_workflow_outcomes \
             DISABLE TRIGGER provider_delivery_workflow_outcomes_insert_guard",
        )
        .execute(database.pool())
        .await?;
        sqlx::query(
            r"
            INSERT INTO provider_delivery_workflow_outcomes (
                inbox_id, tenant_id, ordinal, workflow_path, outcome_kind,
                repository_id, run_id, failure_kind, created_at_ms
            )
            VALUES ($1, 'delivery-atomic', 0, '.ci/workflows/ci.yml',
                    'skipped', NULL, NULL, 'preexisting_collision', 111)
            ",
        )
        .bind(receipt.id().as_uuid())
        .execute(database.pool())
        .await?;
        sqlx::query(
            "ALTER TABLE provider_delivery_workflow_outcomes \
             ENABLE TRIGGER provider_delivery_workflow_outcomes_insert_guard",
        )
        .execute(database.pool())
        .await?;

        let completion =
            CompleteProviderDelivery::new(claimed.claim(), vec![duplicate()], future_test_time(0))?;
        assert!(matches!(
            database
                .store()
                .complete_provider_delivery(completion)
                .await,
            Err(ProviderDeliveryStoreError::Operation(_))
        ));
        let state: String =
            sqlx::query_scalar("SELECT state FROM provider_delivery_inbox WHERE id = $1")
                .bind(receipt.id().as_uuid())
                .fetch_one(database.pool())
                .await?;
        assert_eq!(state, "claimed", "parent completion update rolled back");
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn retry_attempt_limit_requires_terminal_rejection() -> TestResult {
    run_with_database(|database| async move {
        let clock = TestClock::freeze_at_database_now(database.pool()).await?;
        seed_tenant(&database, "delivery-retry-limit").await?;
        let connection = ProviderConnectionId::from_uuid(Uuid::new_v4())?;
        database
            .store()
            .accept_provider_delivery(acceptance(
                "delivery-retry-limit",
                connection,
                "delivery-1",
                7,
                100,
            ))
            .await?;

        let mut claimed = database
            .store()
            .claim_provider_delivery(claim(owner(), 110))
            .await?
            .expect("first attempt");
        for expected_attempt in 1..16 {
            assert_eq!(claimed.attempt(), expected_attempt);
            let observed_at = wall_time_millis().max(claimed.claimed_at().get());
            let retry_at = observed_at + 2;
            database
                .store()
                .retry_provider_delivery(RetryProviderDelivery::new(
                    claimed.claim(),
                    failure("provider_unavailable"),
                    UnixMillis::new(observed_at),
                    UnixMillis::new(retry_at),
                )?)
                .await?;
            clock.set(retry_at + 1).await?;
            claimed = database
                .store()
                .claim_provider_delivery(claim(owner(), 110))
                .await?
                .expect("next attempt");
        }
        assert_eq!(claimed.attempt(), 16);
        let final_observation = wall_time_millis().max(claimed.claimed_at().get());
        let final_retry = RetryProviderDelivery::new(
            claimed.claim(),
            failure("provider_unavailable"),
            UnixMillis::new(final_observation),
            UnixMillis::new(final_observation + 1),
        )?;
        assert!(matches!(
            database.store().retry_provider_delivery(final_retry).await,
            Err(ProviderDeliveryStoreError::RetryLimitReached)
        ));
        let rejected = database
            .store()
            .reject_provider_delivery(RejectProviderDelivery::new(
                claimed.claim(),
                failure("attempt_limit_exhausted"),
                UnixMillis::new(final_observation),
            )?)
            .await?;
        assert_eq!(rejected.state(), ProviderDeliveryState::Rejected);
        assert_eq!(rejected.attempts(), 16);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires AUTOMATA_TEST_DATABASE_URL and creates a temporary schema"]
async fn database_constraints_reject_unbounded_or_ambiguous_evidence() -> TestResult {
    run_with_database(|database| async move {
        seed_tenant(&database, "delivery-constraints").await?;
        let result = sqlx::query(
            r"
            INSERT INTO provider_delivery_inbox (
                id, tenant_id, provider, connection_id, installation_id,
                provider_repository_id, repository_visibility,
                repository_identity, delivery_id,
                request_digest, raw_event_digest, raw_event_object_key,
                raw_event_size_bytes, raw_event_media_type,
                accepted_at_ms, state_updated_at_ms
            )
            VALUES (
                $1, 'delivery-constraints', 'synthetic', $2, 0,
                2, 'unknown', 'automata-ci/automata', 'bad', $3, $3,
                '../event', 26214401, 'application/json; charset=utf-8', 1, 1
            )
            ",
        )
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4())
        .bind([7_u8; 32].as_slice())
        .execute(database.pool())
        .await;
        assert!(result.is_err());
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM provider_delivery_inbox")
            .fetch_one(database.pool())
            .await?;
        assert_eq!(count, 0);
        Ok(())
    })
    .await
}
