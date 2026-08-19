use std::time::Duration;

use automata_ci_core::{Sha256Digest, UnixMillis, WorkspaceId};
use automata_ci_key_management::{EncryptedEnvelope, KeyId, WrappedDataKey};
use automata_ci_provider::{
    ControlCredentialClaim, ControlCredentialRequest, ExternalRepositoryId,
    ExternalRepositoryIdentity, ProviderArchiveLimits, ProviderConfigurationRevision,
    ProviderConnectionConfiguration, ProviderConnectionManifest, ProviderConnectionPolicyDocument,
    ProviderConnectionRevision, ProviderControlCredentialId, ProviderControlCredentialWorkerId,
    ProviderControlOperation, ProviderControlOperationSet, ProviderCredentialGeneration,
    ProviderDefaultBranch, ProviderInstanceId, ProviderLifecycleState, ProviderRepositoryPath,
    ProviderRunnerPolicyBinding, ProviderSchemaVersion, ProviderWorkflowSource,
    RepositoryVisibility,
};
use automata_ci_store::{
    AcquireGithubServerServiceHandoff, BeginGithubServerServiceMint,
    BootstrapGithubProviderRepository, ClaimNextGithubServerServiceMaintenance,
    ClaimedGithubServerServiceMint, EnsureGithubServerServiceAuthority,
    FinalizeGithubWorkflowPermissionObservation, FinishGithubServerServiceMint,
    GithubServerServiceAuthorityIdentity, GithubServerServiceAuthorityRepository as _,
    GithubServerServiceAuthoritySelector, GithubServerServiceAuthorityState,
    GithubServerServiceConsumerId, GithubServerServiceEnvelopeMetadata,
    GithubServerServiceHandoffId, GithubServerServiceIssuanceState,
    GithubServerServiceMaintenanceOutcome, GithubServerServiceWorkerId,
    GithubWorkflowPermissionDefaultsObservation,
    GithubWorkflowPermissionDefaultsObservationRepository as _,
    MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS, ProtectedGithubServerServiceCredential,
    ReleaseGithubServerServiceHandoff,
};
use uuid::Uuid;

use super::{PostgresTestDatabase, TestResult};

/// Activates one fresh, authenticated GitHub workflow-permission observation.
///
/// The helper follows the production authority, issuance, handoff, observation,
/// and finalization contracts. The caller must first persist the bootstrap's
/// runtime-policy and provider-manifest revisions so finalization can make the
/// matching pair current.
///
/// # Errors
///
/// Returns an error when any durable transition rejects the exact fixture or
/// the scoped credential cannot become ready within five seconds.
pub async fn activate_github_workflow_permission_defaults(
    database: &PostgresTestDatabase,
    bootstrap: &BootstrapGithubProviderRepository,
    authority: &GithubServerServiceAuthorityIdentity,
) -> TestResult {
    let manifest = bootstrap.manifest().manifest();
    database
        .store()
        .prepare_github_workflow_permission_target(manifest)
        .await?;
    database
        .store()
        .ensure_github_server_service_authority(EnsureGithubServerServiceAuthority::new(
            authority.clone(),
            bootstrap.manifest().applied_at(),
        )?)
        .await?;
    ensure_workflow_permission_credential(database, authority).await?;

    let started_at = database_now(database).await?;
    let candidate = automata_ci_store::GithubWorkflowPermissionObservationCandidate::new(
        bootstrap,
        authority,
        GithubServerServiceConsumerId::from_uuid(Uuid::new_v4())?,
        GithubServerServiceWorkerId::from_uuid(Uuid::new_v4())?,
        started_at,
    )?;
    database
        .store()
        .claim_github_workflow_permission_observation(candidate.clone())
        .await?;
    let selector = GithubServerServiceAuthoritySelector::from_identity(authority);
    let handoff = database
        .store()
        .acquire_github_server_service_handoff(AcquireGithubServerServiceHandoff::new(
            selector.clone(),
            GithubServerServiceHandoffId::from_uuid(Uuid::new_v4())?,
            candidate.consumer(),
            candidate.claimed_at(),
            UnixMillis::new(
                candidate
                    .claimed_at()
                    .get()
                    .checked_add(MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS)
                    .ok_or("workflow-permission handoff deadline overflow")?,
            ),
        )?)
        .await?;
    let observed_at = database_now(database).await?;
    let release = ReleaseGithubServerServiceHandoff::new(
        selector,
        handoff.handoff_id(),
        candidate.consumer(),
        observed_at,
    )?;
    database
        .store()
        .release_github_server_service_handoff(release)
        .await?;
    let request = workflow_permission_credential_request(&candidate)?;
    let generation = ProviderCredentialGeneration::new(handoff.receipt().key().generation().get())?;
    let observation = GithubWorkflowPermissionDefaultsObservation::new(
        bootstrap,
        candidate.clone(),
        &request,
        generation,
        candidate.expected_default(),
        false,
        observed_at,
    )?;
    if !database
        .store()
        .finalize_github_workflow_permission_observation(
            FinalizeGithubWorkflowPermissionObservation::new(bootstrap.clone(), observation)?,
        )
        .await?
    {
        return Err("workflow-permission observation did not activate".into());
    }
    Ok(())
}

fn workflow_permission_credential_request(
    candidate: &automata_ci_store::GithubWorkflowPermissionObservationCandidate,
) -> TestResult<ControlCredentialRequest> {
    let validity_millis = MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS.cast_unsigned();
    let expires_at = UnixMillis::new(
        candidate
            .claimed_at()
            .get()
            .checked_add(MAX_GITHUB_SERVICE_CONSUMER_REQUEST_MILLIS)
            .ok_or("workflow-permission claim horizon overflow")?,
    );
    let claim = ControlCredentialClaim::new(
        ProviderControlCredentialId::from_uuid(candidate.observation_id().as_uuid())?,
        ProviderControlCredentialWorkerId::from_uuid(candidate.consumer().owner().as_uuid())?,
        candidate.consumer().fence().get(),
        candidate.consumer().revision().get(),
        expires_at,
    )?;
    let configuration = ProviderConnectionConfiguration::new(
        WorkspaceId::parse("11111111-1111-4111-8111-111111111111")?,
        ExternalRepositoryIdentity::new(
            ProviderInstanceId::from_uuid(Uuid::new_v4())?,
            ExternalRepositoryId::new(candidate.github_repository_id().get().to_string())?,
        ),
        ProviderConfigurationRevision::new(1)?,
        Sha256Digest::from_bytes([0x71; 32]),
        Sha256Digest::from_bytes([0x72; 32]),
        RepositoryVisibility::Private,
        ProviderDefaultBranch::new("main")?,
        ProviderWorkflowSource::Directory(ProviderRepositoryPath::new(".github/workflows")?),
        ProviderRunnerPolicyBinding::new(
            ProviderSchemaVersion::new(1)?,
            Sha256Digest::from_bytes([0x73; 32]),
        ),
        ProviderArchiveLimits::new(1_024, 8_192, 100, 1_024, 10, 1_024)?,
        ProviderConnectionPolicyDocument::new(ProviderSchemaVersion::new(1)?, b"{}".to_vec())?,
    );
    let connection = ProviderConnectionManifest::new(
        candidate.connection_id(),
        ProviderConnectionRevision::new(1)?,
        ProviderLifecycleState::Active,
        configuration,
        UnixMillis::new(1),
        Some(UnixMillis::new(1)),
        None,
    )?;
    Ok(ControlCredentialRequest::new(
        claim,
        &connection,
        ProviderControlOperationSet::new([ProviderControlOperation::WorkflowPermissionRead])?,
        candidate.claimed_at(),
        validity_millis,
    )?)
}

async fn ensure_workflow_permission_credential(
    database: &PostgresTestDatabase,
    authority: &GithubServerServiceAuthorityIdentity,
) -> TestResult {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let now = database_now(database).await?;
        let minimum_usable_until = now
            .get()
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
        if tokio::time::Instant::now() >= deadline {
            return Err("workflow-permission credential did not become ready".into());
        }

        let selector = GithubServerServiceAuthoritySelector::from_identity(authority);
        match database
            .store()
            .claim_next_github_server_service_maintenance(
                ClaimNextGithubServerServiceMaintenance::for_authority(
                    selector,
                    GithubServerServiceWorkerId::from_uuid(Uuid::new_v4())?,
                    now,
                    UnixMillis::new(
                        now.get()
                            .checked_add(60_000)
                            .ok_or("workflow-permission maintenance deadline overflow")?,
                    ),
                )?,
            )
            .await?
        {
            Some(GithubServerServiceMaintenanceOutcome::Mint(claimed)) => {
                mint_workflow_permission_credential(database, authority, *claimed).await?;
            }
            Some(GithubServerServiceMaintenanceOutcome::Reduced { .. }) | None => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Some(GithubServerServiceMaintenanceOutcome::Revocation(_)) => {
                return Err("unexpected workflow-permission revocation work".into());
            }
        }
    }
}

async fn mint_workflow_permission_credential(
    database: &PostgresTestDatabase,
    authority: &GithubServerServiceAuthorityIdentity,
    claimed: ClaimedGithubServerServiceMint,
) -> TestResult {
    let started_at = database_now(database).await?;
    database
        .store()
        .begin_github_server_service_mint(BeginGithubServerServiceMint::new(&claimed, started_at)?)
        .await?;
    let committed_at = database_now(database).await?;
    let receipt = claimed.receipt();
    let usable_until = committed_at
        .get()
        .checked_add(3_600_000)
        .ok_or("workflow-permission credential expiry overflow")?;
    let metadata = GithubServerServiceEnvelopeMetadata::new(
        authority.clone(),
        receipt.key().generation(),
        receipt.requested_at(),
        receipt.request_deadline(),
        UnixMillis::new(usable_until),
        32,
        Sha256Digest::from_bytes([0x7b; 32]),
    )?;
    let credential = ProtectedGithubServerServiceCredential::new(
        metadata,
        EncryptedEnvelope::from_parts(
            1,
            WrappedDataKey::new(
                KeyId::new("postgres-test-workflow-permission-key")?,
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
            committed_at,
        )?)
        .await?;
    Ok(())
}

async fn database_now(database: &PostgresTestDatabase) -> TestResult<UnixMillis> {
    Ok(UnixMillis::new(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(database.pool())
            .await?,
    ))
}
