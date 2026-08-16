use std::{error::Error, future::Future, sync::Arc};

use automata_ci_control::runner_control::repository::RunnerSessionRepository as _;
use automata_ci_core::{
    Architecture, JobId, JobIrVersion, OperatingSystem, RunId, RunnerCapabilities, RunnerId,
    RunnerPlatform, RunnerRequirements, RunnerSessionId, Sha256Digest, TrustActorEvidence,
    TrustActorKind, TrustAutomationKind, TrustEventKind, TrustEvidence, TrustOriginKind,
    TrustPolicy, TrustRepositoryEvidence, TrustSnapshot, TrustTokenRecursion, UnixMillis,
};
use automata_ci_key_management::{
    EncryptedEnvelope, KeyEncryptionProvider, KeyId, LocalAes256GcmKeyring, LocalKeyMaterial,
    SecretBytes, WrappedDataKey,
};
#[allow(unused_imports)] // Consolidated binaries consume different fixture subsets.
pub use automata_ci_postgres::test_support::{
    PostgresTestDatabase as TestDatabase, TestClock, TestResult,
};
use automata_ci_store::{
    AcquireGithubServerServiceHandoff, AdmissionRepository, AdmitLogicalWorkflowRun,
    BeginGithubServerServiceMint, BootstrapGithubProviderRepository,
    ClaimNextGithubServerServiceMaintenance, EnsureGithubServerServiceAuthority,
    FinalizeGithubWorkflowPermissionObservation, FinishGithubServerServiceMint,
    GithubProviderManifest, GithubServerServiceAuthorityId, GithubServerServiceAuthorityIdentity,
    GithubServerServiceAuthorityRepository as _, GithubServerServiceAuthoritySelector,
    GithubServerServiceAuthorityState, GithubServerServiceEnvelopeMetadata,
    GithubServerServiceHandoffId, GithubServerServiceIssuanceState,
    GithubServerServiceMaintenanceOutcome, GithubServerServiceScope, GithubServerServiceWorkerId,
    GithubWorkflowPermissionDefaultsObservation,
    GithubWorkflowPermissionDefaultsObservationRepository as _,
    MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS, OpenRunnerSession,
    ProtectedGithubServerServiceCredential, ProviderDeliveryClaimFence,
    ProviderDeliveryRepository as _, ProviderDeliveryWorkflowInventory,
    ProviderDeliveryWorkflowInventoryEntry, ProviderDeliveryWorkflowSourceState,
    RegisterProviderDeliveryWorkflowInventory, ReleaseGithubServerServiceHandoff, RoutingDocument,
    RunnerGeneration, RunnerProtocolVersion, RunnerSessionFence,
};
use automata_ci_store_postgres::PostgresStore;
use sqlx::PgPool;
use uuid::Uuid;

pub type TestError = Box<dyn Error + Send + Sync>;

#[allow(dead_code)] // Consolidated binaries consume different fixture subsets.
pub fn provider_delivery_event_envelope(
    digest_byte: u8,
) -> automata_ci_store::ProviderDeliveryEventEnvelope {
    automata_ci_store::ProviderDeliveryEventEnvelope::new(
        1,
        1,
        Sha256Digest::from_bytes([digest_byte; 32]),
        format!(r#"{{"schema":1,"fixture":{digest_byte}}}"#).into_bytes(),
        "application/vnd.automata.provider-event-envelope.v1+json",
    )
    .expect("provider delivery event envelope")
}

#[allow(dead_code)]
pub fn authenticated_github_event_object(
    event: &automata_ci_store::AdmissionObject,
) -> TestResult<automata_ci_store::AdmissionObject> {
    Ok(automata_ci_store::AdmissionObject::new_event(
        event.digest(),
        event.object_key().clone(),
        event.encoded_size(),
        "application/vnd.automata.github-authenticated-event+json",
    )?)
}

#[allow(dead_code)] // Consolidated binaries consume different fixture subsets.
pub async fn register_provider_delivery_workflow_inventory(
    database: &TestDatabase,
    manifest: &GithubProviderManifest,
    command: &AdmitLogicalWorkflowRun,
    claim: ProviderDeliveryClaimFence,
    observed_at: UnixMillis,
) -> TestResult {
    database
        .store()
        .register_provider_delivery_workflow_inventory(
            RegisterProviderDeliveryWorkflowInventory::new(
                claim,
                ProviderDeliveryWorkflowInventory::new(
                    manifest.digest(),
                    lower_hex(command.head_sha()),
                    automata_ci_core::Sha256Digest::from_bytes([0x90; 32]),
                    vec![ProviderDeliveryWorkflowInventoryEntry::new(
                        command.workflow_path(),
                        ProviderDeliveryWorkflowSourceState::Ready(command.source().digest()),
                    )?],
                )?,
                observed_at,
            )?,
        )
        .await?;
    Ok(())
}

/// Builds a sealed same-repository push trust snapshot for the admitted coordinates.
#[allow(dead_code)] // Consolidated integration modules consume different fixture subsets.
pub fn authenticated_github_trust_snapshot(
    repository: &AdmissionRepository,
    git_ref: &str,
    head_sha: &[u8],
) -> TestResult<TrustSnapshot> {
    authenticated_github_trust_snapshot_for_actor(
        repository,
        git_ref,
        head_sha,
        "authenticated-github-fixture-actor",
    )
}

/// Builds a sealed same-repository push trust snapshot for exact coordinates and actor.
#[allow(dead_code)] // Consolidated integration modules consume different fixture subsets.
pub fn authenticated_github_trust_snapshot_for_actor(
    repository: &AdmissionRepository,
    git_ref: &str,
    head_sha: &[u8],
    actor_id: &str,
) -> TestResult<TrustSnapshot> {
    let actor = TrustActorEvidence::new(actor_id, TrustActorKind::User, TrustAutomationKind::None)?;
    let repository = TrustRepositoryEvidence::new(
        repository.provider_repository_id(),
        "authenticated-github-fixture-owner",
    )?;
    Ok(TrustPolicy::current().evaluate(
        TrustEvidence::new(TrustOriginKind::ProviderWebhook, TrustEventKind::Push)
            .with_original_actor(actor.clone())
            .with_triggering_actor(actor)
            .with_repositories(repository.clone(), repository)
            .with_refs(git_ref, git_ref, git_ref)
            .with_revisions(
                lower_hex(head_sha),
                lower_hex(head_sha),
                lower_hex(head_sha),
            )
            .with_fork(false)
            .with_token_recursion(TrustTokenRecursion::Suppressed),
    )?)
}

/// Establishes the exact fresh workflow-permission observation required by
/// authenticated GitHub logical admission.
#[allow(dead_code)] // Consolidated integration modules consume different fixture subsets.
#[allow(clippy::too_many_lines)] // Mirrors the complete production claim/handoff/finalize flow.
pub async fn seed_fresh_github_workflow_permission_defaults(
    database: &TestDatabase,
    bootstrap: &BootstrapGithubProviderRepository,
) -> TestResult {
    let manifest = bootstrap.manifest().manifest();
    database
        .store()
        .prepare_github_workflow_permission_target(manifest)
        .await?;
    let mut authority_id_bytes = [0_u8; 16];
    authority_id_bytes.copy_from_slice(&manifest.digest().as_bytes()[..16]);
    authority_id_bytes[0] ^= 0xa7;
    let authority = GithubServerServiceAuthorityIdentity::new(
        manifest.tenant().clone(),
        GithubServerServiceAuthorityId::from_uuid(Uuid::from_bytes(authority_id_bytes))?,
        manifest.repository_id(),
        manifest.connection_id(),
        manifest.installation_id(),
        manifest.github_app_id(),
        manifest.github_repository_id(),
        manifest.github_repository_name().clone(),
        GithubServerServiceScope::WorkflowPermissionsRead,
        manifest.app_client_id().clone(),
        manifest.jwt_issuer(),
        manifest.app_key_spki_sha256(),
        manifest.app_configuration_revision(),
        manifest.policy_revision(),
        Sha256Digest::from_bytes([0x7a; 32]),
    )?;
    database
        .store()
        .ensure_github_server_service_authority(EnsureGithubServerServiceAuthority::new(
            authority.clone(),
            bootstrap.manifest().applied_at(),
        )?)
        .await?;

    ensure_workflow_permission_credential(database, &authority).await?;
    let selector = GithubServerServiceAuthoritySelector::from_identity(&authority);

    let observation_started_at = UnixMillis::new(database_now_ms(database).await?);
    let candidate = automata_ci_store::GithubWorkflowPermissionObservationCandidate::new(
        bootstrap,
        &authority,
        automata_ci_store::GithubServerServiceConsumerId::from_uuid(Uuid::new_v4())?,
        GithubServerServiceWorkerId::from_uuid(Uuid::new_v4())?,
        observation_started_at,
    )?;
    database
        .store()
        .claim_github_workflow_permission_observation(candidate.clone())
        .await?;
    let expected_default = candidate.expected_default();
    let handoff_id = GithubServerServiceHandoffId::from_uuid(Uuid::new_v4())?;
    let handoff_observed_at = candidate.claimed_at();
    let handoff = database
        .store()
        .acquire_github_server_service_handoff(AcquireGithubServerServiceHandoff::new(
            selector.clone(),
            handoff_id,
            candidate.consumer(),
            handoff_observed_at,
            UnixMillis::new(handoff_observed_at.get() + MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS),
        )?)
        .await?;
    let observed_at = UnixMillis::new(database_now_ms(database).await?);
    let release = ReleaseGithubServerServiceHandoff::new(
        selector,
        handoff.handoff_id(),
        candidate.consumer(),
        observed_at,
    )?;
    let observation = GithubWorkflowPermissionDefaultsObservation::new(
        bootstrap,
        candidate,
        &release,
        handoff.receipt().key().generation(),
        expected_default,
        false,
        observed_at,
    )?;
    let finalized = database
        .store()
        .finalize_github_workflow_permission_observation(
            FinalizeGithubWorkflowPermissionObservation::new(
                bootstrap.clone(),
                release,
                observation,
            )?,
        )
        .await?;
    if !finalized {
        return Err("workflow-permission observation did not activate".into());
    }
    Ok(())
}

async fn ensure_workflow_permission_credential(
    database: &TestDatabase,
    authority: &GithubServerServiceAuthorityIdentity,
) -> TestResult {
    let wait_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let now_ms = database_now_ms(database).await?;
        let minimum_usable_until = now_ms
            .checked_add(MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS)
            .and_then(|value| value.checked_add(60_000))
            .ok_or("workflow-permission credential horizon overflow")?;
        let descriptor = database
            .store()
            .inspect_github_server_service_authority(authority.tenant(), authority.authority_id())
            .await?;
        let current = database
            .store()
            .inspect_current_github_server_service_issuance(
                authority.tenant(),
                authority.authority_id(),
            )
            .await?;
        if descriptor.identity() != authority
            || descriptor.state() != GithubServerServiceAuthorityState::Active
        {
            return Err("workflow-permission authority is not active and exact".into());
        }
        if current.is_some_and(|receipt| {
            descriptor.current_generation() == Some(receipt.key().generation())
                && receipt.state() == GithubServerServiceIssuanceState::Ready
                && receipt
                    .usable_until()
                    .is_some_and(|until| until.get() >= minimum_usable_until)
        }) {
            return Ok(());
        }
        if tokio::time::Instant::now() >= wait_deadline {
            return Err("workflow-permission credential did not become ready".into());
        }

        let selector = GithubServerServiceAuthoritySelector::from_identity(authority);
        let outcome = database
            .store()
            .claim_next_github_server_service_maintenance(
                ClaimNextGithubServerServiceMaintenance::for_authority(
                    selector,
                    GithubServerServiceWorkerId::from_uuid(Uuid::new_v4())?,
                    UnixMillis::new(now_ms),
                    UnixMillis::new(now_ms + 60_000),
                )?,
            )
            .await?;
        match outcome {
            Some(GithubServerServiceMaintenanceOutcome::Mint(claimed)) => {
                let claimed = *claimed;
                let started_at = UnixMillis::new(database_now_ms(database).await?);
                database
                    .store()
                    .begin_github_server_service_mint(BeginGithubServerServiceMint::new(
                        &claimed, started_at,
                    )?)
                    .await?;
                let committed_at_ms = database_now_ms(database).await?;
                let receipt = claimed.receipt();
                let metadata = GithubServerServiceEnvelopeMetadata::new(
                    authority.clone(),
                    receipt.key().generation(),
                    receipt.requested_at(),
                    receipt.request_deadline(),
                    UnixMillis::new(committed_at_ms + 3_600_000),
                    32,
                    Sha256Digest::from_bytes([0x7b; 32]),
                )?;
                let credential = ProtectedGithubServerServiceCredential::new(
                    metadata,
                    EncryptedEnvelope::from_parts(
                        1,
                        WrappedDataKey::new(
                            KeyId::new("authenticated-fixture-workflow-permission-v1")?,
                            vec![0x7c; 48],
                        )?,
                        [0x7d; 12],
                        vec![0x7e; 48],
                    )?,
                )?;
                database
                    .store()
                    .finish_github_server_service_mint(&FinishGithubServerServiceMint::ready(
                        claimed.claim().clone(),
                        credential,
                        UnixMillis::new(committed_at_ms),
                    )?)
                    .await?;
            }
            Some(GithubServerServiceMaintenanceOutcome::Reduced { .. }) | None => {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            Some(GithubServerServiceMaintenanceOutcome::Revocation(_)) => {
                return Err("unexpected workflow-permission revocation work".into());
            }
        }
    }
}

pub(crate) fn lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

async fn database_now_ms(database: &TestDatabase) -> TestResult<i64> {
    Ok(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(database.pool())
            .await?,
    )
}

pub fn test_runner_payload_key_provider() -> Arc<dyn KeyEncryptionProvider> {
    let active = LocalKeyMaterial::new(
        KeyId::new("store-test-runner-payload-v1").expect("canonical test key ID"),
        SecretBytes::new(vec![0x6d; 32]).expect("exact test wrapping key length"),
    )
    .expect("valid test wrapping key");
    Arc::new(
        LocalAes256GcmKeyring::new(active, Vec::new(), Vec::<KeyId>::new())
            .expect("valid deterministic test keyring"),
    )
}

pub async fn run_with_database<Test, TestFuture>(test: Test) -> TestResult
where
    Test: FnOnce(Arc<TestDatabase>) -> TestFuture + Send + 'static,
    TestFuture: Future<Output = TestResult> + Send + 'static,
{
    automata_ci_postgres::test_support::run_with_configured_database(
        |store| store.with_runner_payload_encryption(test_runner_payload_key_provider()),
        test,
    )
    .await
}

#[allow(dead_code)] // Only integration tests that control migration application use this fixture.
pub async fn run_with_unmigrated_database<Test, TestFuture>(test: Test) -> TestResult
where
    Test: FnOnce(Arc<TestDatabase>) -> TestFuture + Send + 'static,
    TestFuture: Future<Output = TestResult> + Send + 'static,
{
    automata_ci_postgres::test_support::run_with_unmigrated_database(
        |store| store.with_runner_payload_encryption(test_runner_payload_key_provider()),
        test,
    )
    .await
}

#[derive(Debug)]
#[allow(dead_code)] // Each integration-test crate consumes a different fixture subset.
pub struct SeedData {
    pub tenant_id: String,
    pub repository_id: Uuid,
    pub workflow_id: Uuid,
    pub run_id: RunId,
    pub job_id: JobId,
    pub runner_ids: Vec<RunnerId>,
    pub session_fences: Vec<RunnerSessionFence>,
}

#[allow(clippy::too_many_lines, dead_code)] // Shared fixture; integration targets consume subsets.
pub async fn seed_control_plane(pool: &PgPool, runner_count: usize) -> TestResult<SeedData> {
    seed_control_plane_with_optional_concurrency(pool, runner_count, None).await
}

#[allow(dead_code)] // Only concurrency-focused integration targets consume this fixture variant.
pub async fn seed_control_plane_with_concurrency(
    pool: &PgPool,
    runner_count: usize,
    group: &str,
    queue_policy: &str,
) -> TestResult<SeedData> {
    seed_control_plane_with_optional_concurrency(pool, runner_count, Some((group, queue_policy)))
        .await
}

#[allow(clippy::too_many_lines)] // Shared relational fixture with one optional concurrency pin.
async fn seed_control_plane_with_optional_concurrency(
    pool: &PgPool,
    runner_count: usize,
    concurrency: Option<(&str, &str)>,
) -> TestResult<SeedData> {
    let repository_id = Uuid::new_v4();
    let workflow_id = Uuid::new_v4();
    let snapshot_id = Uuid::new_v4();
    let run_id = Uuid::new_v4();
    let job_id = JobId::new();
    let tenant_id = format!("tenant-{}", Uuid::new_v4().simple());
    let (admission_epoch, job_ir_schema, runner_requirements_schema): (i32, i32, i32) =
        sqlx::query_as(
            r"
        SELECT minimum_admission_epoch, job_ir_schema, runner_requirements_schema
        FROM automata_cluster_compatibility
        WHERE singleton
        ",
        )
        .fetch_one(pool)
        .await?;
    let job_ir_version = JobIrVersion::new(u16::try_from(job_ir_schema)?)?;

    let requirements = serde_json::to_value(RunnerRequirements::default())?;

    sqlx::query(
        r"
        INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms)
        VALUES ($1, 'Store test tenant', 1, 1)
        ",
    )
    .bind(&tenant_id)
    .execute(pool)
    .await?;

    sqlx::query(
        r"
        INSERT INTO repositories (
            id, tenant_id, scm_provider, provider_repository_id, owner, name,
            created_at_ms, updated_at_ms
        )
        VALUES ($1, $2, 'test', $3, 'automata', 'store-test', 1, 1)
        ",
    )
    .bind(repository_id)
    .bind(&tenant_id)
    .bind(repository_id.to_string())
    .execute(pool)
    .await?;
    if let Some((group, _)) = concurrency {
        sqlx::query(
            r"
            INSERT INTO concurrency_groups (
                repository_id, normalized_key, display_key, updated_at_ms
            ) VALUES ($1, $2, $2, 1)
            ",
        )
        .bind(repository_id)
        .bind(group)
        .execute(pool)
        .await?;
    }
    sqlx::query(
        r"
        INSERT INTO workflow_definitions (
            id, repository_id, path, created_at_ms, updated_at_ms
        )
        VALUES ($1, $2, '.ci/workflows/test.yml', 1, 1)
        ",
    )
    .bind(workflow_id)
    .bind(repository_id)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_snapshots (
            id, workflow_id, source_digest, source_object_key,
            frontend_schema, created_at_ms
        )
        VALUES ($1, $2, $3, 'test/workflow', 1, 1)
        ",
    )
    .bind(snapshot_id)
    .bind(workflow_id)
    .bind(vec![7_u8; 32])
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO workflow_runs (
            id, repository_id, workflow_id, snapshot_id, run_number, event_name,
            event_object_key, event_digest, event_size_bytes, event_media_type,
            plan_digest, plan_object_key, plan_size_bytes, plan_media_type,
            plan_schema, workflow_name, head_sha, status, created_at_ms, updated_at_ms,
            concurrency_group_key, concurrency_queue_policy,
            runner_requirements_schema
        ) VALUES (
            $1, $2, $3, $4, 1, 'push', 'test/event',
            decode(repeat('09', 32), 'hex'), 1, 'application/json',
            decode(repeat('0a', 32), 'hex'), 'test/plan', 1,
            'application/vnd.automata.workflow-plan.protobuf', 1, 'Store test',
            $5, 'queued', 1, 1, $6, $7, $8
        )
        ",
    )
    .bind(run_id)
    .bind(repository_id)
    .bind(workflow_id)
    .bind(snapshot_id)
    .bind(vec![9_u8; 20])
    .bind(concurrency.map(|(group, _)| group))
    .bind(concurrency.map(|(_, queue_policy)| queue_policy))
    .bind(i16::try_from(runner_requirements_schema)?)
    .execute(pool)
    .await?;
    sqlx::query(
        r"
        INSERT INTO jobs (
            id, run_id, job_key, display_name, job_ir_digest,
            job_ir_object_key, requirements, admission_epoch,
            job_ir_schema, job_ir_size_bytes, created_at_ms
        )
        VALUES (
            $1, $2, 'test', 'Store test', $3,
            'test/job-ir', $4::jsonb, $5, $6, 128, 1
        )
        ",
    )
    .bind(job_id.as_uuid())
    .bind(run_id)
    .bind(vec![11_u8; 32])
    .bind(requirements)
    .bind(admission_epoch)
    .bind(job_ir_schema)
    .execute(pool)
    .await?;

    let runner_ids = seed_runners(pool, &tenant_id, runner_count).await?;
    let mut session_fences = Vec::with_capacity(runner_ids.len());
    let store = PostgresStore::from_postgres_pool(pool.clone())
        .with_runner_payload_encryption(test_runner_payload_key_provider());
    for runner_id in &runner_ids {
        let capabilities = runner_capability_document(pool, *runner_id).await?;
        let session = store
            .open_session(OpenRunnerSession::new(
                RunnerSessionId::new(),
                *runner_id,
                RunnerGeneration::new(1)?,
                RunnerProtocolVersion::new(1)?,
                job_ir_version,
                capabilities,
                UnixMillis::new(2),
            ))
            .await?;
        session_fences.push(session.fence());
    }

    Ok(SeedData {
        tenant_id,
        repository_id,
        workflow_id,
        run_id: RunId::from_uuid(run_id),
        job_id,
        runner_ids,
        session_fences,
    })
}

#[allow(dead_code)] // Shared fixture; integration targets consume subsets.
pub async fn runner_capability_document(
    pool: &PgPool,
    runner_id: RunnerId,
) -> TestResult<RoutingDocument> {
    let capabilities: serde_json::Value =
        sqlx::query_scalar("SELECT capabilities FROM runners WHERE id = $1")
            .bind(runner_id.as_uuid())
            .fetch_one(pool)
            .await?;
    Ok(RoutingDocument::new(serde_json::to_string(&capabilities)?)?)
}

#[allow(dead_code)] // Used transitively only by integration targets that seed control-plane state.
async fn seed_runners(
    pool: &PgPool,
    tenant_id: &str,
    runner_count: usize,
) -> TestResult<Vec<RunnerId>> {
    let mut runner_ids = Vec::with_capacity(runner_count);
    for index in 0..runner_count {
        let runner_id = RunnerId::new();
        let capabilities = RunnerCapabilities::new(
            runner_id,
            RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
        );
        sqlx::query(
            r"
            INSERT INTO runners (
                id, tenant_id, name, normalized_name, capabilities, slots, status,
                desired_state, created_at_ms, updated_at_ms
            )
            VALUES ($1, $2, $3, $3, $4::jsonb, 65535, 'online', 'active', 1, 1)
            ",
        )
        .bind(runner_id.as_uuid())
        .bind(tenant_id)
        .bind(format!("test-runner-{index}"))
        .bind(serde_json::to_value(capabilities)?)
        .execute(pool)
        .await?;
        runner_ids.push(runner_id);
    }
    Ok(runner_ids)
}
