use async_trait::async_trait;
use automata_ci_core::{
    JobAuthorityProfile, JobId, JobIrVersion, LeaseId, RunId, RunnerId, RunnerSessionId,
    Sha256Digest, UnixMillis, WorkflowId,
};
use sqlx::{Postgres, Row as _, Transaction};
use uuid::Uuid;

use super::{
    PostgresStore, durable_schema::current_durable_schemas,
    runtime_authority::github_manifest_origin_is_closed,
};
use automata_ci_provider::ProviderConnectionId;
use automata_ci_store::{
    GITHUB_PROVIDER_API_ORIGIN, GITHUB_PROVIDER_REST_API_VERSION,
    GITHUB_PROVIDER_RUNNER_POLICY_MEDIA_TYPE, GITHUB_PROVIDER_WEB_ORIGIN,
    GithubJobRuntimeAuthorityEvidence, GithubJobRuntimeAuthorityExecution,
    GithubJobRuntimeAuthorityRepository, GithubJobRuntimeAuthorityResolution,
    GithubJobRuntimeAuthorityStoreError, GithubRepositoryId, GithubRepositoryName,
    GithubRuntimeAuthorityActivationSelectionTail, GithubRuntimeAuthorityIdentity,
    GithubRuntimeAuthorityMaterializationSelectionTail, GithubRuntimeAuthorityNamespace,
    GithubRuntimeAuthorityPreparationSelectionTail, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceJwtIssuer, JobIrMetadata,
    LOGICAL_ACTIVATION_JOB_IR_MEDIA_TYPE, LogicalActivationGeneration,
    LogicalActivationPreparationGeneration, LogicalActivationWorkerId,
    LogicalMaterializationGeneration, LogicalMaterializationWorkerId, LogicalWorkSelectionId,
    MAX_GITHUB_AUTHORITY_REQUEST_MILLIS, ObjectKey, ProviderInstallationId, RepositoryId,
    RunnerGeneration, SessionEpoch, StableRunnerSlot, TenantScope,
};

const GITHUB_REPOSITORY_AUTHORITY_NAMESPACE: &str = "github.repository";

#[derive(Debug)]
struct ExactExecutionSelector {
    workflow_id: Option<WorkflowId>,
    github_repository_name: GithubRepositoryName,
    authority_profile: JobAuthorityProfile,
    policy_digest: Sha256Digest,
    attempt_id: Uuid,
    fencing_token: i64,
    lease_id: LeaseId,
    lease_issued_at: UnixMillis,
    lease_expires_at: UnixMillis,
    run_id: RunId,
    job_id: JobId,
    runner_id: RunnerId,
    runner_session_id: RunnerSessionId,
    runner_session_epoch: SessionEpoch,
    runner_generation: RunnerGeneration,
    runner_slot: StableRunnerSlot,
    job_ir_version: JobIrVersion,
    job_ir_size_bytes: u64,
    job_ir_digest: Sha256Digest,
    job_ir_object_key: Option<String>,
    repository_id: Option<RepositoryId>,
    provider_connection_id: Option<ProviderConnectionId>,
    provider_installation_id: Option<ProviderInstallationId>,
    github_repository_id: Option<GithubRepositoryId>,
}

#[derive(Debug)]
struct ExactExecutionRow {
    workflow_id: Uuid,
    invocation_id: Uuid,
    logical_job_id: Uuid,
    instance_id: Uuid,
    tenant_id: String,
    repository_id: Uuid,
    provider_connection_id: Uuid,
    provider_installation_id: i64,
    github_repository_id: i64,
    github_repository_name: String,
    repository_visibility: String,
    origin_kind: String,
    origin_id: Uuid,
    repository_contents_authority_id: Uuid,
    github_app_id: i64,
    github_app_client_id: String,
    github_app_jwt_issuer_kind: String,
    app_key_spki_sha256: Vec<u8>,
    configuration_fingerprint: Vec<u8>,
    runtime_policy_revision: i64,
    runtime_policy_digest: Vec<u8>,
    authority_profile: String,
    job_ir_object_key: String,
    preparation_selection_tail: GithubRuntimeAuthorityPreparationSelectionTail,
    activation_selection_tail: GithubRuntimeAuthorityActivationSelectionTail,
    materialization_selection_tail: GithubRuntimeAuthorityMaterializationSelectionTail,
}

impl ExactExecutionSelector {
    fn from_execution(
        execution: &GithubJobRuntimeAuthorityExecution,
    ) -> Result<Self, GithubJobRuntimeAuthorityStoreError> {
        let lease = execution.lease();
        let session = execution.session();
        Ok(Self {
            workflow_id: Some(execution.workflow_id()),
            github_repository_name: execution.github_repository_name().clone(),
            authority_profile: execution.authority_profile(),
            policy_digest: execution.permission_policy_sha256(),
            attempt_id: lease.attempt_id().as_uuid(),
            fencing_token: positive_i64(lease.fencing_token().get())?,
            lease_id: lease.lease_id(),
            lease_issued_at: lease.issued_at(),
            lease_expires_at: lease.expires_at(),
            run_id: execution.run_id(),
            job_id: execution.job_id(),
            runner_id: execution.runner_id(),
            runner_session_id: execution.runner_session_id(),
            runner_session_epoch: session.session_epoch(),
            runner_generation: execution.runner_generation(),
            runner_slot: execution.slot(),
            job_ir_version: execution.job_ir().version(),
            job_ir_size_bytes: execution.job_ir().encoded_size(),
            job_ir_digest: execution.job_ir().digest(),
            job_ir_object_key: Some(execution.job_ir().object_key().as_str().to_owned()),
            repository_id: None,
            provider_connection_id: None,
            provider_installation_id: None,
            github_repository_id: None,
        })
    }

    fn from_identity(
        identity: &GithubRuntimeAuthorityIdentity,
    ) -> Result<Self, GithubJobRuntimeAuthorityStoreError> {
        let expected_deadline =
            request_deadline(identity.lease_issued_at(), identity.lease_expires_at())?;
        if identity.namespace().as_str() != GITHUB_REPOSITORY_AUTHORITY_NAMESPACE
            || identity.requested_at() != identity.lease_issued_at()
            || identity.request_deadline() != expected_deadline
        {
            return Err(GithubJobRuntimeAuthorityStoreError::Unauthorized);
        }
        Ok(Self {
            workflow_id: None,
            github_repository_name: identity.github_repository_name().clone(),
            authority_profile: JobAuthorityProfile::Standard,
            policy_digest: identity.policy_digest(),
            attempt_id: identity.key().attempt_id().as_uuid(),
            fencing_token: positive_i64(identity.key().fencing_token().get())?,
            lease_id: identity.lease_id(),
            lease_issued_at: identity.lease_issued_at(),
            lease_expires_at: identity.lease_expires_at(),
            run_id: identity.run_id(),
            job_id: identity.job_id(),
            runner_id: identity.runner_id(),
            runner_session_id: identity.runner_session_id(),
            runner_session_epoch: identity.runner_session_epoch(),
            runner_generation: identity.runner_generation(),
            runner_slot: identity.runner_slot(),
            job_ir_version: identity.job_ir_version(),
            job_ir_size_bytes: identity.job_ir_size_bytes(),
            job_ir_digest: identity.job_ir_digest(),
            job_ir_object_key: None,
            repository_id: Some(identity.repository_id()),
            provider_connection_id: Some(identity.provider_connection_id()),
            provider_installation_id: Some(identity.provider_installation_id()),
            github_repository_id: Some(identity.github_repository_id()),
        })
    }
}

#[async_trait]
impl GithubJobRuntimeAuthorityRepository for PostgresStore {
    async fn resolve_github_job_runtime_authority(
        &self,
        execution: &GithubJobRuntimeAuthorityExecution,
    ) -> Result<GithubJobRuntimeAuthorityResolution, GithubJobRuntimeAuthorityStoreError> {
        let selector = ExactExecutionSelector::from_execution(execution)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(GithubJobRuntimeAuthorityStoreError::operation)?;
        let row = lock_exact_execution(&mut transaction, &selector)
            .await
            .inspect_err(|error| observe_resolution_failure("exact_execution", error))?;
        lock_exact_selection_lineage(&mut transaction, &selector, &row)
            .await
            .inspect_err(|error| observe_resolution_failure("selection_lineage", error))?;
        lock_exact_repository_contents_authority(&mut transaction, &row)
            .await
            .inspect_err(|error| observe_resolution_failure("repository_source", error))?;
        ensure_database_live_lease(&mut transaction, &selector)
            .await
            .inspect_err(|error| observe_resolution_failure("live_lease", error))?;
        let evidence = decode_evidence(&selector, &row)
            .inspect_err(|error| observe_resolution_failure("evidence_decode", error))?;
        transaction
            .commit()
            .await
            .map_err(GithubJobRuntimeAuthorityStoreError::operation)?;
        match execution.authority_profile() {
            JobAuthorityProfile::CredentialFree => {
                Ok(GithubJobRuntimeAuthorityResolution::CredentialFree)
            }
            JobAuthorityProfile::Standard => Ok(GithubJobRuntimeAuthorityResolution::Standard(
                Box::new(evidence),
            )),
        }
    }

    async fn revalidate_github_job_runtime_authority(
        &self,
        identity: &GithubRuntimeAuthorityIdentity,
    ) -> Result<GithubJobRuntimeAuthorityEvidence, GithubJobRuntimeAuthorityStoreError> {
        let selector = ExactExecutionSelector::from_identity(identity)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(GithubJobRuntimeAuthorityStoreError::operation)?;
        let row = lock_exact_execution(&mut transaction, &selector).await?;
        lock_exact_selection_lineage(&mut transaction, &selector, &row).await?;
        lock_exact_repository_contents_authority(&mut transaction, &row).await?;
        ensure_database_live_lease(&mut transaction, &selector).await?;
        let evidence = decode_evidence(&selector, &row)?;
        if evidence.identity() != identity {
            return Err(GithubJobRuntimeAuthorityStoreError::Unauthorized);
        }
        transaction
            .commit()
            .await
            .map_err(GithubJobRuntimeAuthorityStoreError::operation)?;
        Ok(evidence)
    }
}

fn observe_resolution_failure(stage: &'static str, error: &GithubJobRuntimeAuthorityStoreError) {
    let failure = match error {
        GithubJobRuntimeAuthorityStoreError::Operation(_) => "operation",
        GithubJobRuntimeAuthorityStoreError::Unauthorized => "unauthorized",
        GithubJobRuntimeAuthorityStoreError::CorruptData => "corrupt_data",
    };
    tracing::warn!(
        stage,
        failure,
        "GitHub job runtime-authority resolution failed"
    );
}

// Every mutable execution dependency and every immutable historical authority
// edge is locked in this one auditable query. Deliberately absent: the current
// provider-manifest pointer.
#[allow(clippy::too_many_lines)]
async fn lock_exact_execution(
    transaction: &mut Transaction<'_, Postgres>,
    selector: &ExactExecutionSelector,
) -> Result<ExactExecutionRow, GithubJobRuntimeAuthorityStoreError> {
    let schemas = current_durable_schemas();
    let profile = authority_profile_name(selector.authority_profile);
    let rows = sqlx::query(
        r"
        SELECT run.workflow_id, concrete.invocation_id, concrete.logical_job_id,
               concrete.instance_id, repository.tenant_id,
               repository.id AS repository_id,
               origin.provider_connection_id,
               origin.provider_installation_id,
               origin.github_repository_id,
               origin.github_repository_name,
               origin.repository_visibility,
               origin.origin_kind,
               origin.origin_id,
               origin.repository_contents_authority_id,
               manifest.github_app_id,
               manifest.github_app_client_id,
               manifest.github_app_jwt_issuer_kind,
               manifest.app_key_spki_sha256,
               checks_authority.configuration_fingerprint,
               runtime_policy_pin.policy_revision AS runtime_policy_revision,
               runtime_policy_pin.policy_digest AS runtime_policy_digest,
               manifest.authority_profile,
               job.job_ir_object_key,
               preparation_claim.origin_selection_id AS preparation_selection_id,
               preparation_claim.owner_id AS preparation_owner_id,
               preparation_claim.generation AS preparation_generation,
               preparation_claim.descriptor_digest AS preparation_descriptor_digest,
               preparation_claim.claimed_at_ms AS preparation_claimed_at_ms,
               preparation_claim.expires_at_ms AS preparation_expires_at_ms,
               logical_job.activation_origin_selection_id AS activation_selection_id,
               publication.activation_owner_id AS activation_owner_id,
               publication.activation_generation AS activation_generation,
               publication.activation_input_digest AS activation_input_digest,
               publication.activation_claimed_at_ms AS activation_claimed_at_ms,
               publication.activation_expires_at_ms AS activation_expires_at_ms,
               materialization.origin_selection_id AS materialization_selection_id,
               materialization.owner_id AS materialization_owner_id,
               materialization.generation AS materialization_generation,
               materialization.descriptor_digest AS materialization_descriptor_digest,
               materialization.claimed_at_ms AS materialization_claimed_at_ms,
               materialization.expires_at_ms AS materialization_expires_at_ms
        FROM job_attempts AS attempt
        JOIN jobs AS job ON job.id = attempt.job_id
        JOIN workflow_runs AS run ON run.id = job.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        JOIN workflow_definitions AS workflow
          ON workflow.id = run.workflow_id
         AND workflow.repository_id = run.repository_id
        JOIN workflow_snapshots AS snapshot
          ON snapshot.id = run.snapshot_id
         AND snapshot.workflow_id = run.workflow_id
        JOIN logical_workflow_runs AS marker ON marker.run_id = run.id
        JOIN logical_workflow_runtime_policy_pins AS runtime_policy_pin
          ON runtime_policy_pin.run_id = run.id
         AND runtime_policy_pin.tenant_id = repository.tenant_id
         AND runtime_policy_pin.repository_id = repository.id
        JOIN workflow_runtime_policy_revisions AS runtime_policy
          ON runtime_policy.tenant_id = runtime_policy_pin.tenant_id
         AND runtime_policy.repository_id = runtime_policy_pin.repository_id
         AND runtime_policy.policy_revision = runtime_policy_pin.policy_revision
         AND runtime_policy.policy_digest = runtime_policy_pin.policy_digest
         AND runtime_policy.state = 'sealed'
        JOIN logical_workflow_concrete_jobs AS concrete ON concrete.job_id = job.id
        JOIN logical_workflow_materialization_claims AS materialization
          ON materialization.instance_id = concrete.instance_id
         AND materialization.run_id = concrete.run_id
         AND materialization.invocation_id = concrete.invocation_id
         AND materialization.logical_job_id = concrete.logical_job_id
         AND materialization.descriptor_digest = concrete.descriptor_digest
         AND materialization.expected_job_id = concrete.job_id
         AND materialization.expected_attempt_id = concrete.initial_attempt_id
         AND materialization.owner_id = concrete.claim_owner_id
         AND materialization.generation = concrete.claim_generation
         AND materialization.claimed_at_ms = concrete.claim_started_at_ms
         AND materialization.expires_at_ms = concrete.claim_expires_at_ms
         AND materialization.updated_at_ms = concrete.committed_at_ms
        JOIN logical_workflow_instances AS instance
          ON instance.id = concrete.instance_id
         AND instance.run_id = concrete.run_id
         AND instance.invocation_id = concrete.invocation_id
         AND instance.logical_job_id = concrete.logical_job_id
        JOIN logical_workflow_activation_publications AS publication
          ON publication.run_id = instance.run_id
         AND publication.invocation_id = instance.invocation_id
         AND publication.logical_job_id = instance.logical_job_id
        JOIN logical_workflow_activation_preparations AS preparation
          ON preparation.run_id = publication.run_id
         AND preparation.invocation_id = publication.invocation_id
         AND preparation.logical_job_id = publication.logical_job_id
         AND preparation.activation_input_digest = publication.activation_input_digest
        JOIN logical_workflow_activation_preparation_claims AS preparation_claim
          ON preparation_claim.run_id = preparation.run_id
         AND preparation_claim.invocation_id = preparation.invocation_id
         AND preparation_claim.logical_job_id = preparation.logical_job_id
         AND preparation_claim.descriptor_digest = preparation.descriptor_digest
        JOIN logical_workflow_jobs AS logical_job
          ON logical_job.run_id = concrete.run_id
         AND logical_job.invocation_id = concrete.invocation_id
         AND logical_job.id = concrete.logical_job_id
        JOIN logical_workflow_invocations AS invocation
          ON invocation.run_id = concrete.run_id
         AND invocation.id = concrete.invocation_id
        JOIN runners AS runner ON runner.id = attempt.runner_id
        JOIN runner_sessions AS session
          ON session.id = attempt.runner_session_id
         AND session.runner_id = attempt.runner_id
        JOIN github_workflow_run_manifest_origins AS origin
          ON origin.tenant_id = repository.tenant_id
         AND origin.repository_id = repository.id
         AND origin.workflow_id = run.workflow_id
         AND origin.run_id = run.id
         AND origin.root_invocation_id = marker.root_invocation_id
        JOIN workflow_admission_receipts AS admission_receipt
          ON admission_receipt.tenant_id = origin.tenant_id
         AND admission_receipt.idempotency_kind = origin.admission_idempotency_kind
         AND admission_receipt.idempotency_key = origin.admission_idempotency_key
         AND admission_receipt.request_digest = origin.logical_admission_digest
         AND admission_receipt.repository_id = origin.repository_id
         AND admission_receipt.run_id = origin.run_id
         AND admission_receipt.committed_at_ms = origin.admitted_at_ms
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = origin.tenant_id
         AND manifest.repository_id = origin.repository_id
         AND manifest.provider_connection_id = origin.provider_connection_id
         AND manifest.manifest_revision = origin.provider_manifest_revision
         AND manifest.manifest_digest = origin.provider_manifest_digest
        JOIN github_server_service_authorities AS checks_authority
          ON checks_authority.tenant_id = origin.tenant_id
         AND checks_authority.id = origin.checks_authority_id
         AND checks_authority.repository_id = origin.repository_id
         AND checks_authority.provider_connection_id = origin.provider_connection_id
         AND checks_authority.provider_installation_id = origin.provider_installation_id
         AND checks_authority.github_repository_id = origin.github_repository_id
         AND checks_authority.github_repository_name = origin.github_repository_name
         AND checks_authority.service_scope = 'checks_write'
         AND checks_authority.identity_digest = origin.checks_authority_identity_digest
         AND checks_authority.app_configuration_revision =
             origin.checks_authority_app_configuration_revision
         AND checks_authority.policy_revision = origin.checks_authority_policy_revision
         AND checks_authority.state = 'active'
        WHERE attempt.id = $1
          AND attempt.job_id = $2
          AND attempt.fencing_token = $3
          AND attempt.lease_id = $4
          AND attempt.lease_issued_at_ms = $5
          AND attempt.lease_expires_at_ms = $6
          AND attempt.runner_id = $7
          AND attempt.runner_session_id = $8
          AND attempt.runner_session_epoch = $9
          AND attempt.runner_generation = $10
          AND attempt.runner_slot = $11
          AND attempt.lifecycle IN ('leased', 'preparing', 'running')
          AND job.id = $2
          AND job.run_id = $12
          AND job.admission_epoch = $36
          AND job.job_ir_schema = $28
          AND job.job_ir_schema = $13
          AND job.job_ir_size_bytes = $14
          AND job.job_ir_digest = $15
          AND job.job_ir_digest = $27
          AND ($16::TEXT IS NULL OR job.job_ir_object_key = $16)
          AND run.id = $12
          AND ($17::UUID IS NULL OR run.workflow_id = $17)
          AND run.admission_epoch = $36
          AND run.plan_schema = $29
          AND run.status IN ('queued', 'in_progress')
          AND (
              concrete.invocation_id <> marker.root_invocation_id
              OR run.plan_digest = invocation.plan_digest
          )
          AND run.plan_digest = origin.plan_digest
          AND run.event_digest = origin.event_digest
          AND run.head_sha = origin.github_check_head_sha
          AND run.event_name = origin.event_name
          AND run.git_ref = origin.git_ref
          AND repository.scm_provider = 'github'
          AND repository.owner || '/' || repository.name = $18
          AND repository.provider_repository_id = origin.github_repository_id::TEXT
          AND ($19::UUID IS NULL OR repository.id = $19)
          AND origin.github_repository_name = $18
          AND workflow.path = origin.workflow_path
          AND snapshot.source_digest = origin.source_digest
          AND marker.root_invocation_id = origin.root_invocation_id
          AND marker.admission_digest = origin.logical_admission_digest
          AND marker.admitted_at_ms = origin.admitted_at_ms
          AND automata_logical_workflow_invocation_published(
              run.id, concrete.invocation_id
          )
          AND manifest.webhook_verifier_fingerprint_sha256 =
              origin.authenticated_webhook_verifier_fingerprint_sha256
          AND manifest.webhook_verifier_revision =
              origin.authenticated_webhook_verifier_revision
          AND manifest.provider_installation_id = origin.provider_installation_id
          AND manifest.github_repository_id = origin.github_repository_id
          AND manifest.github_repository_name = origin.github_repository_name
          AND manifest.repository_visibility = origin.repository_visibility
          AND manifest.github_app_id = checks_authority.github_app_id
          AND manifest.github_app_client_id = checks_authority.github_app_client_id
          AND manifest.github_app_jwt_issuer_kind =
              checks_authority.github_app_jwt_issuer_kind
          AND manifest.app_key_spki_sha256 = checks_authority.app_key_spki_sha256
          AND manifest.app_configuration_revision =
              checks_authority.app_configuration_revision
          AND manifest.policy_revision = checks_authority.policy_revision
          AND manifest.runtime_policy_revision = runtime_policy_pin.policy_revision
          AND manifest.runtime_policy_digest = runtime_policy_pin.policy_digest
          AND manifest.runner_policy_digest = pg_catalog.sha256(runtime_policy.canonical_policy)
          AND manifest.runner_policy_object_key = 'github/runner-policy/v1/'
              || pg_catalog.encode(manifest.runner_policy_digest, 'hex') || '.json'
          AND manifest.runner_policy_size_bytes =
              pg_catalog.octet_length(runtime_policy.canonical_policy)
          AND manifest.runner_policy_media_type = $34
          AND manifest.github_web_origin = $20
          AND manifest.github_api_origin = $21
          AND manifest.github_rest_api_version = $22
          AND origin.repository_contents_authority_id IS NOT NULL
          AND manifest.authority_profile = $23
          AND logical_job.authority_profile = $23
          AND preparation_claim.authority_profile = $23
          AND preparation.authority_profile = $23
          AND publication.authority_profile = $23
          AND materialization.authority_profile = $23
          AND concrete.authority_profile = $23
          AND logical_job.runtime_policy_revision = runtime_policy_pin.policy_revision
          AND logical_job.runtime_policy_digest = runtime_policy_pin.policy_digest
          AND preparation_claim.runtime_policy_revision = runtime_policy_pin.policy_revision
          AND preparation_claim.runtime_policy_digest = runtime_policy_pin.policy_digest
          AND preparation_claim.runner_policy_digest = manifest.runner_policy_digest
          AND preparation_claim.runner_policy_object_key = manifest.runner_policy_object_key
          AND preparation_claim.runner_policy_size_bytes = manifest.runner_policy_size_bytes
          AND preparation_claim.runner_policy_media_type = manifest.runner_policy_media_type
          AND preparation.runtime_policy_revision = runtime_policy_pin.policy_revision
          AND preparation.runtime_policy_digest = runtime_policy_pin.policy_digest
          AND publication.runtime_policy_revision = runtime_policy_pin.policy_revision
          AND publication.runtime_policy_digest = runtime_policy_pin.policy_digest
          AND instance.runtime_policy_revision = runtime_policy_pin.policy_revision
          AND instance.runtime_policy_digest = runtime_policy_pin.policy_digest
          AND materialization.runtime_policy_revision = runtime_policy_pin.policy_revision
          AND materialization.runtime_policy_digest = runtime_policy_pin.policy_digest
          AND concrete.runtime_policy_revision = runtime_policy_pin.policy_revision
          AND concrete.runtime_policy_digest = runtime_policy_pin.policy_digest
          AND marker.orchestration_schema = $30
          AND marker.state IN ('pending', 'active')
          AND invocation.plan_schema = $31
          AND invocation.state IN ('pending', 'active')
          AND logical_job.execution_kind = 'steps'
          AND logical_job.state = 'activated'
          AND preparation_claim.state = 'prepared'
          AND publication.condition_matched
          AND publication.activation_generation = logical_job.activation_fence
          AND publication.activation_input_digest = logical_job.activation_input_digest
          AND publication.job_ir_version = $32
          AND publication.runtime_context_schema = $33
          AND instance.job_ir_version = $32
          AND instance.job_ir_digest = job.job_ir_digest
          AND instance.job_ir_object_key = job.job_ir_object_key
          AND instance.job_ir_size_bytes = job.job_ir_size_bytes
          AND instance.job_ir_media_type = $35
          AND concrete.runtime_context_schema = $33
          AND concrete.requirements = job.requirements
          AND materialization.state = 'materialized'
          AND runner.id = $7
          AND runner.tenant_id = repository.tenant_id
          AND runner.status = 'online'
          AND runner.desired_state IN ('active', 'draining')
          AND runner.generation = $10
          AND runner.session_epoch = $9
          AND session.id = $8
          AND session.session_epoch = $9
          AND session.runner_generation = $10
          AND session.job_ir_schema = $28
          AND session.disconnected_at_ms IS NULL
          AND ($24::UUID IS NULL OR origin.provider_connection_id = $24)
          AND ($25::BIGINT IS NULL OR origin.provider_installation_id = $25)
          AND ($26::BIGINT IS NULL OR origin.github_repository_id = $26)
        FOR SHARE OF attempt, job, run, repository, workflow, snapshot, marker,
                     runtime_policy_pin, runtime_policy, concrete, materialization, instance, publication,
                     preparation, preparation_claim, logical_job, invocation,
                     runner, session, admission_receipt, manifest, checks_authority
        ",
    )
    .bind(selector.attempt_id)
    .bind(selector.job_id.as_uuid())
    .bind(selector.fencing_token)
    .bind(selector.lease_id.as_uuid())
    .bind(selector.lease_issued_at.get())
    .bind(selector.lease_expires_at.get())
    .bind(selector.runner_id.as_uuid())
    .bind(selector.runner_session_id.as_uuid())
    .bind(positive_i64(selector.runner_session_epoch.get())?)
    .bind(positive_i64(selector.runner_generation.get())?)
    .bind(i32::from(selector.runner_slot.ordinal()))
    .bind(selector.run_id.as_uuid())
    .bind(i32::from(selector.job_ir_version.get()))
    .bind(positive_i64(selector.job_ir_size_bytes)?)
    .bind(selector.job_ir_digest.as_bytes().as_slice())
    .bind(selector.job_ir_object_key.as_deref())
    .bind(selector.workflow_id.map(WorkflowId::as_uuid))
    .bind(selector.github_repository_name.as_str())
    .bind(selector.repository_id.map(RepositoryId::as_uuid))
    .bind(GITHUB_PROVIDER_WEB_ORIGIN)
    .bind(GITHUB_PROVIDER_API_ORIGIN)
    .bind(GITHUB_PROVIDER_REST_API_VERSION)
    .bind(profile)
    .bind(
        selector
            .provider_connection_id
            .map(ProviderConnectionId::as_uuid),
    )
    .bind(
        selector
            .provider_installation_id
            .map(|value| i64::try_from(value.get()).expect("validated provider ID fits BIGINT")),
    )
    .bind(
        selector
            .github_repository_id
            .map(|value| i64::try_from(value.get()).expect("validated GitHub ID fits BIGINT")),
    )
    .bind(selector.policy_digest.as_bytes().as_slice())
    .bind(schemas.job_ir_i32)
    .bind(schemas.workflow_plan_i32)
    .bind(schemas.logical_orchestration_i16)
    .bind(schemas.workflow_plan_i16)
    .bind(schemas.job_ir_i16)
    .bind(schemas.runtime_context_i16)
    .bind(GITHUB_PROVIDER_RUNNER_POLICY_MEDIA_TYPE)
    .bind(LOGICAL_ACTIVATION_JOB_IR_MEDIA_TYPE)
    .bind(schemas.admission_epoch_i32)
    .fetch_all(&mut **transaction)
    .await
    .map_err(GithubJobRuntimeAuthorityStoreError::operation)?;
    match rows.as_slice() {
        [row] => decode_exact_execution_row(row),
        [] => Err(GithubJobRuntimeAuthorityStoreError::Unauthorized),
        _ => Err(GithubJobRuntimeAuthorityStoreError::CorruptData),
    }
}

async fn lock_exact_selection_lineage(
    transaction: &mut Transaction<'_, Postgres>,
    selector: &ExactExecutionSelector,
    current: &ExactExecutionRow,
) -> Result<(), GithubJobRuntimeAuthorityStoreError> {
    lock_exact_preparation_selection_lineage(transaction, selector, current).await?;
    lock_exact_activation_selection_lineage(transaction, selector, current).await?;
    lock_exact_materialization_selection_lineage(transaction, selector, current).await
}

// Only these six public arms exist: each phase keeps a compile-time SQL shape.
#[rustfmt::skip]
macro_rules! selection_lineage_sql {
    (preparation_base) => { selection_lineage_sql!(@orchestration_base "preparation") };
    (preparation_renewal) => { selection_lineage_sql!(@orchestration_renewal "preparation") };
    (activation_base) => { selection_lineage_sql!(@orchestration_base "activation") };
    (activation_renewal) => { selection_lineage_sql!(@orchestration_renewal "activation") };
    (materialization_base) => { concat!(
        "\n        SELECT selection.generation = $9\n           AND selection.claimed_at_ms = $10\n           AND selection.expires_at_ms = $11\n",
        "        FROM logical_workflow_materialization_work_selections AS selection\n        WHERE selection.selection_id = $1\n          AND selection.outcome = 'claimed'\n",
        "          AND selection.tenant_id = $2\n          AND selection.run_id = $3\n          AND selection.invocation_id = $4\n          AND selection.logical_job_id = $5\n",
        "          AND selection.instance_id = $6\n          AND selection.owner_id = $7\n          AND selection.authority_digest = $8\n        FOR SHARE OF selection\n        ") };
    (materialization_renewal) => { concat!(
        "\n        SELECT TRUE\n        FROM logical_workflow_materialization_renewal_receipts AS renewal\n        WHERE renewal.selection_id = $1\n",
        "          AND renewal.tenant_id = $2\n          AND renewal.run_id = $3\n          AND renewal.invocation_id = $4\n          AND renewal.logical_job_id = $5\n",
        "          AND renewal.instance_id = $6\n          AND renewal.owner_id = $7\n          AND renewal.runtime_policy_revision = $8\n          AND renewal.runtime_policy_digest = $9\n",
        "          AND renewal.authority_digest = $10\n          AND renewal.expected_job_id = $11\n          AND renewal.expected_attempt_id = $12\n",
        "          AND renewal.successor_generation = $13\n          AND renewal.successor_claimed_at_ms = $14\n          AND renewal.successor_expires_at_ms = $15\n        FOR SHARE OF renewal\n        ") };
    (@orchestration_base $kind:literal) => { concat!(
        "\n        SELECT selection.generation = $8\n           AND selection.claimed_at_ms = $9\n           AND selection.expires_at_ms = $10\n",
        "        FROM logical_workflow_activation_work_selections AS selection\n        WHERE selection.selection_id = $1\n          AND selection.outcome = 'claimed'\n          AND selection.authority_kind = '", $kind, "'\n",
        "          AND selection.tenant_id = $2\n          AND selection.run_id = $3\n          AND selection.invocation_id = $4\n          AND selection.logical_job_id = $5\n",
        "          AND selection.owner_id = $6\n          AND selection.authority_digest = $7\n        FOR SHARE OF selection\n        ") };
    (@orchestration_renewal $kind:literal) => { concat!(
        "\n        SELECT TRUE\n        FROM logical_workflow_activation_renewal_receipts AS renewal\n        WHERE renewal.selection_id = $1\n          AND renewal.authority_kind = '", $kind, "'\n",
        "          AND renewal.tenant_id = $2\n          AND renewal.run_id = $3\n          AND renewal.invocation_id = $4\n          AND renewal.logical_job_id = $5\n",
        "          AND renewal.owner_id = $6\n          AND renewal.runtime_policy_revision = $7\n          AND renewal.runtime_policy_digest = $8\n          AND renewal.authority_digest = $9\n",
        "          AND renewal.successor_generation = $10\n          AND renewal.successor_claimed_at_ms = $11\n          AND renewal.successor_expires_at_ms = $12\n        FOR SHARE OF renewal\n        ") };
}

const PREPARATION_SELECTION_BASE_SQL: &str = selection_lineage_sql!(preparation_base);
const PREPARATION_SELECTION_RENEWAL_SQL: &str = selection_lineage_sql!(preparation_renewal);
const ACTIVATION_SELECTION_BASE_SQL: &str = selection_lineage_sql!(activation_base);
const ACTIVATION_SELECTION_RENEWAL_SQL: &str = selection_lineage_sql!(activation_renewal);
const MATERIALIZATION_SELECTION_BASE_SQL: &str = selection_lineage_sql!(materialization_base);
const MATERIALIZATION_SELECTION_RENEWAL_SQL: &str = selection_lineage_sql!(materialization_renewal);

// Public phase arms are closed; internal arms own every bind and its position.
#[rustfmt::skip]
macro_rules! selection_lineage_query {
    (preparation_base, $transaction:ident, $selector:ident, $current:ident, $tail:ident, $generation:ident) => {
        selection_lineage_query!(@orchestration_base PREPARATION_SELECTION_BASE_SQL, descriptor_digest, $transaction, $selector, $current, $tail, $generation) };
    (preparation_renewal, $transaction:ident, $selector:ident, $current:ident, $tail:ident, $generation:ident) => {
        selection_lineage_query!(@orchestration_renewal PREPARATION_SELECTION_RENEWAL_SQL, descriptor_digest, $transaction, $selector, $current, $tail, $generation) };
    (activation_base, $transaction:ident, $selector:ident, $current:ident, $tail:ident, $generation:ident) => {
        selection_lineage_query!(@orchestration_base ACTIVATION_SELECTION_BASE_SQL, activation_input_digest, $transaction, $selector, $current, $tail, $generation) };
    (activation_renewal, $transaction:ident, $selector:ident, $current:ident, $tail:ident, $generation:ident) => {
        selection_lineage_query!(@orchestration_renewal ACTIVATION_SELECTION_RENEWAL_SQL, activation_input_digest, $transaction, $selector, $current, $tail, $generation) };
    (materialization_base, $transaction:ident, $selector:ident, $current:ident, $tail:ident, $generation:ident) => { sqlx::query_scalar(MATERIALIZATION_SELECTION_BASE_SQL)
        .bind($tail.selection_id().as_uuid()).bind(&$current.tenant_id).bind($selector.run_id.as_uuid())
        .bind($current.invocation_id).bind($current.logical_job_id).bind($current.instance_id).bind($tail.owner().as_uuid())
        .bind($tail.descriptor_digest().as_bytes().as_slice()).bind($generation).bind($tail.claimed_at().get()).bind($tail.expires_at().get()) };
    (materialization_renewal, $transaction:ident, $selector:ident, $current:ident, $tail:ident, $generation:ident) => { sqlx::query_scalar::<_, bool>(MATERIALIZATION_SELECTION_RENEWAL_SQL)
        .bind($tail.selection_id().as_uuid()).bind(&$current.tenant_id).bind($selector.run_id.as_uuid())
        .bind($current.invocation_id).bind($current.logical_job_id).bind($current.instance_id).bind($tail.owner().as_uuid())
        .bind($current.runtime_policy_revision).bind(&$current.runtime_policy_digest).bind($tail.descriptor_digest().as_bytes().as_slice())
        .bind($selector.job_id.as_uuid()).bind($selector.attempt_id).bind($generation).bind($tail.claimed_at().get()).bind($tail.expires_at().get()) };
    (@orchestration_base $sql:ident, $digest:ident, $transaction:ident, $selector:ident, $current:ident, $tail:ident, $generation:ident) => { sqlx::query_scalar($sql)
        .bind($tail.selection_id().as_uuid()).bind(&$current.tenant_id).bind($selector.run_id.as_uuid())
        .bind($current.invocation_id).bind($current.logical_job_id).bind($tail.owner().as_uuid())
        .bind($tail.$digest().as_bytes().as_slice()).bind($generation).bind($tail.claimed_at().get()).bind($tail.expires_at().get()) };
    (@orchestration_renewal $sql:ident, $digest:ident, $transaction:ident, $selector:ident, $current:ident, $tail:ident, $generation:ident) => { sqlx::query_scalar::<_, bool>($sql)
        .bind($tail.selection_id().as_uuid()).bind(&$current.tenant_id).bind($selector.run_id.as_uuid())
        .bind($current.invocation_id).bind($current.logical_job_id).bind($tail.owner().as_uuid())
        .bind($current.runtime_policy_revision).bind(&$current.runtime_policy_digest).bind($tail.$digest().as_bytes().as_slice())
        .bind($generation).bind($tail.claimed_at().get()).bind($tail.expires_at().get()) };
}

macro_rules! define_selection_lineage_lock {
    (preparation) => { define_selection_lineage_lock!(@one lock_exact_preparation_selection_lineage, preparation_selection_tail, preparation_base, preparation_renewal); };
    (activation) => { define_selection_lineage_lock!(@one lock_exact_activation_selection_lineage, activation_selection_tail, activation_base, activation_renewal); };
    (materialization) => { define_selection_lineage_lock!(@one lock_exact_materialization_selection_lineage, materialization_selection_tail, materialization_base, materialization_renewal); };
    (@one $name:ident, $tail_field:ident, $base:ident, $renewal:ident) => {
        async fn $name(
            transaction: &mut Transaction<'_, Postgres>,
            selector: &ExactExecutionSelector,
            current: &ExactExecutionRow,
        ) -> Result<(), GithubJobRuntimeAuthorityStoreError> {
            let tail = current.$tail_field;
            let generation = positive_i64(tail.generation().get())?;
            let base_exact: Option<bool> = selection_lineage_query!(
                $base, transaction, selector, current, tail, generation
            )
            .fetch_optional(&mut **transaction)
            .await
            .map_err(GithubJobRuntimeAuthorityStoreError::operation)?;
            match base_exact {
                Some(true) => return Ok(()),
                Some(false) => {}
                None => return Err(GithubJobRuntimeAuthorityStoreError::CorruptData),
            }
            let renewal_exact = selection_lineage_query!(
                $renewal, transaction, selector, current, tail, generation
            )
            .fetch_optional(&mut **transaction)
            .await
            .map_err(GithubJobRuntimeAuthorityStoreError::operation)?
            .unwrap_or(false);
            renewal_exact
                .then_some(())
                .ok_or(GithubJobRuntimeAuthorityStoreError::CorruptData)
        }
    };
}

define_selection_lineage_lock!(preparation);
define_selection_lineage_lock!(activation);
define_selection_lineage_lock!(materialization);

async fn lock_exact_repository_contents_authority(
    transaction: &mut Transaction<'_, Postgres>,
    current: &ExactExecutionRow,
) -> Result<(), GithubJobRuntimeAuthorityStoreError> {
    if !matches!(current.repository_visibility.as_str(), "public" | "private") {
        return Err(GithubJobRuntimeAuthorityStoreError::CorruptData);
    }
    let exact: bool = sqlx::query_scalar(
        r"
                SELECT TRUE
                FROM github_workflow_run_manifest_origins AS evidence
                JOIN github_provider_manifest_revisions AS manifest
                  ON manifest.tenant_id = evidence.tenant_id
                 AND manifest.repository_id = evidence.repository_id
                 AND manifest.provider_connection_id = evidence.provider_connection_id
                 AND manifest.manifest_revision = evidence.provider_manifest_revision
                 AND manifest.manifest_digest = evidence.provider_manifest_digest
                JOIN github_server_service_authorities AS authority
                  ON authority.tenant_id = evidence.tenant_id
                 AND authority.id = evidence.repository_contents_authority_id
                 AND authority.repository_id = evidence.repository_id
                 AND authority.provider_connection_id = evidence.provider_connection_id
                 AND authority.provider_installation_id = evidence.provider_installation_id
                 AND authority.github_repository_id = evidence.github_repository_id
                 AND authority.github_repository_name = evidence.github_repository_name
                 AND authority.service_scope = 'repository_contents_read'
                 AND authority.github_app_id = manifest.github_app_id
                 AND authority.github_app_client_id = manifest.github_app_client_id
                 AND authority.github_app_jwt_issuer_kind =
                     manifest.github_app_jwt_issuer_kind
                 AND authority.app_key_spki_sha256 = manifest.app_key_spki_sha256
                 AND authority.app_configuration_revision =
                     evidence.repository_contents_authority_app_configuration_revision
                 AND authority.app_configuration_revision =
                     manifest.app_configuration_revision
                 AND authority.policy_revision =
                     evidence.repository_contents_authority_policy_revision
                 AND authority.policy_revision = manifest.policy_revision
                 AND authority.identity_digest =
                     evidence.repository_contents_authority_identity_digest
                 AND authority.state = 'active'
                WHERE evidence.origin_kind = $1
                  AND evidence.origin_id = $2
                  AND evidence.tenant_id = $3
                  AND evidence.repository_id = $4
                  AND evidence.repository_contents_authority_id = $5
                FOR SHARE OF authority, manifest
                ",
    )
    .bind(&current.origin_kind)
    .bind(current.origin_id)
    .bind(&current.tenant_id)
    .bind(current.repository_id)
    .bind(current.repository_contents_authority_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(GithubJobRuntimeAuthorityStoreError::operation)?
    .unwrap_or(false);
    if exact {
        Ok(())
    } else {
        Err(GithubJobRuntimeAuthorityStoreError::Unauthorized)
    }
}

async fn ensure_database_live_lease(
    transaction: &mut Transaction<'_, Postgres>,
    selector: &ExactExecutionSelector,
) -> Result<(), GithubJobRuntimeAuthorityStoreError> {
    let database_now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(&mut **transaction)
            .await
            .map_err(GithubJobRuntimeAuthorityStoreError::operation)?;
    if database_now < 0 || selector.lease_expires_at.get() <= database_now {
        return Err(GithubJobRuntimeAuthorityStoreError::Unauthorized);
    }
    Ok(())
}

#[rustfmt::skip]
macro_rules! define_selection_tail_decoder {
    ($name:ident, $tail:ty, $owner:ty, $generation:ty, $digest:ident, $mapping:ident,
     $selection_column:literal, $owner_column:literal, $generation_column:literal,
     $digest_column:literal, $claimed_column:literal, $expires_column:literal) => {
        #[cfg(test)]
        const $mapping: (&str, [(&str, &str); 6]) = (
            stringify!($name),
            [
                ("selection_id", $selection_column), ("owner_id", $owner_column),
                ("generation", $generation_column), ("digest", $digest_column),
                ("claimed_at_ms", $claimed_column), ("expires_at_ms", $expires_column),
            ],
        );
        fn $name(
            row: &sqlx::postgres::PgRow,
        ) -> Result<$tail, GithubJobRuntimeAuthorityStoreError> {
            let selection_id: Uuid = row.try_get($selection_column)
                .map_err(|_| GithubJobRuntimeAuthorityStoreError::CorruptData)?;
            let owner_id: Uuid = row.try_get($owner_column)
                .map_err(|_| GithubJobRuntimeAuthorityStoreError::CorruptData)?;
            let generation: i64 = row.try_get($generation_column)
                .map_err(|_| GithubJobRuntimeAuthorityStoreError::CorruptData)?;
            let $digest: Vec<u8> = row.try_get($digest_column)
                .map_err(|_| GithubJobRuntimeAuthorityStoreError::CorruptData)?;
            let claimed_at_ms: i64 = row.try_get($claimed_column)
                .map_err(|_| GithubJobRuntimeAuthorityStoreError::CorruptData)?;
            let expires_at_ms: i64 = row.try_get($expires_column)
                .map_err(|_| GithubJobRuntimeAuthorityStoreError::CorruptData)?;
            <$tail>::new(
                LogicalWorkSelectionId::from_uuid(selection_id)
                    .map_err(|_| GithubJobRuntimeAuthorityStoreError::CorruptData)?,
                <$owner>::from_uuid(owner_id)
                    .map_err(|_| GithubJobRuntimeAuthorityStoreError::CorruptData)?,
                <$generation>::new(positive_u64(generation)?)
                    .map_err(|_| GithubJobRuntimeAuthorityStoreError::CorruptData)?,
                digest(&$digest)?, UnixMillis::new(claimed_at_ms), UnixMillis::new(expires_at_ms),
            )
            .map_err(|_| GithubJobRuntimeAuthorityStoreError::CorruptData)
        }
    };
}

#[rustfmt::skip]
define_selection_tail_decoder!(decode_preparation_selection_tail, GithubRuntimeAuthorityPreparationSelectionTail,
    LogicalActivationWorkerId, LogicalActivationPreparationGeneration, descriptor_digest,
    PREPARATION_DECODER_MAPPING, "preparation_selection_id", "preparation_owner_id", "preparation_generation",
    "preparation_descriptor_digest", "preparation_claimed_at_ms", "preparation_expires_at_ms");
#[rustfmt::skip]
define_selection_tail_decoder!(decode_activation_selection_tail, GithubRuntimeAuthorityActivationSelectionTail,
    LogicalActivationWorkerId, LogicalActivationGeneration, activation_input_digest,
    ACTIVATION_DECODER_MAPPING, "activation_selection_id", "activation_owner_id", "activation_generation",
    "activation_input_digest", "activation_claimed_at_ms", "activation_expires_at_ms");
#[rustfmt::skip]
define_selection_tail_decoder!(decode_materialization_selection_tail, GithubRuntimeAuthorityMaterializationSelectionTail,
    LogicalMaterializationWorkerId, LogicalMaterializationGeneration, descriptor_digest,
    MATERIALIZATION_DECODER_MAPPING, "materialization_selection_id", "materialization_owner_id", "materialization_generation",
    "materialization_descriptor_digest", "materialization_claimed_at_ms", "materialization_expires_at_ms");

fn decode_exact_execution_row(
    row: &sqlx::postgres::PgRow,
) -> Result<ExactExecutionRow, GithubJobRuntimeAuthorityStoreError> {
    macro_rules! field {
        ($name:literal) => {
            row.try_get($name)
                .map_err(|_| GithubJobRuntimeAuthorityStoreError::CorruptData)?
        };
    }
    let runtime_policy_digest: Vec<u8> = field!("runtime_policy_digest");
    digest(&runtime_policy_digest)?;
    let origin_kind: String = field!("origin_kind");
    let origin_id: Uuid = field!("origin_id");
    if !github_manifest_origin_is_closed(&origin_kind) || origin_id.is_nil() {
        return Err(GithubJobRuntimeAuthorityStoreError::CorruptData);
    }
    Ok(ExactExecutionRow {
        workflow_id: field!("workflow_id"),
        invocation_id: field!("invocation_id"),
        logical_job_id: field!("logical_job_id"),
        instance_id: field!("instance_id"),
        tenant_id: field!("tenant_id"),
        repository_id: field!("repository_id"),
        provider_connection_id: field!("provider_connection_id"),
        provider_installation_id: field!("provider_installation_id"),
        github_repository_id: field!("github_repository_id"),
        github_repository_name: field!("github_repository_name"),
        repository_visibility: field!("repository_visibility"),
        origin_kind,
        origin_id,
        repository_contents_authority_id: field!("repository_contents_authority_id"),
        github_app_id: field!("github_app_id"),
        github_app_client_id: field!("github_app_client_id"),
        github_app_jwt_issuer_kind: field!("github_app_jwt_issuer_kind"),
        app_key_spki_sha256: field!("app_key_spki_sha256"),
        configuration_fingerprint: field!("configuration_fingerprint"),
        runtime_policy_revision: field!("runtime_policy_revision"),
        runtime_policy_digest,
        authority_profile: field!("authority_profile"),
        job_ir_object_key: field!("job_ir_object_key"),
        preparation_selection_tail: decode_preparation_selection_tail(row)?,
        activation_selection_tail: decode_activation_selection_tail(row)?,
        materialization_selection_tail: decode_materialization_selection_tail(row)?,
    })
}

fn decode_evidence(
    selector: &ExactExecutionSelector,
    row: &ExactExecutionRow,
) -> Result<GithubJobRuntimeAuthorityEvidence, GithubJobRuntimeAuthorityStoreError> {
    if row.authority_profile != authority_profile_name(selector.authority_profile)
        || row.github_repository_name != selector.github_repository_name.as_str()
    {
        return Err(GithubJobRuntimeAuthorityStoreError::CorruptData);
    }
    let tenant = TenantScope::from_authenticated_tenant_id(row.tenant_id.clone())
        .map_err(|_| GithubJobRuntimeAuthorityStoreError::CorruptData)?;
    let repository_id = RepositoryId::from_uuid(row.repository_id);
    let provider_connection_id = ProviderConnectionId::from_uuid(row.provider_connection_id)
        .map_err(|_| GithubJobRuntimeAuthorityStoreError::CorruptData)?;
    let provider_installation_id =
        ProviderInstallationId::new(positive_u64(row.provider_installation_id)?)
            .map_err(|_| GithubJobRuntimeAuthorityStoreError::CorruptData)?;
    let github_repository_id = GithubRepositoryId::new(positive_u64(row.github_repository_id)?)
        .map_err(|_| GithubJobRuntimeAuthorityStoreError::CorruptData)?;
    let github_repository_name = GithubRepositoryName::new(row.github_repository_name.clone())
        .map_err(|_| GithubJobRuntimeAuthorityStoreError::CorruptData)?;
    let namespace =
        GithubRuntimeAuthorityNamespace::new(GITHUB_REPOSITORY_AUTHORITY_NAMESPACE.to_owned())
            .map_err(|_| GithubJobRuntimeAuthorityStoreError::CorruptData)?;
    let github_app_id = GithubServerServiceAppId::new(positive_u64(row.github_app_id)?)
        .map_err(|_| GithubJobRuntimeAuthorityStoreError::CorruptData)?;
    let github_app_client_id =
        GithubServerServiceAppClientId::new(row.github_app_client_id.clone())
            .map_err(|_| GithubJobRuntimeAuthorityStoreError::CorruptData)?;
    let github_app_jwt_issuer_kind =
        decode_github_server_service_jwt_issuer(&row.github_app_jwt_issuer_kind)
            .ok_or(GithubJobRuntimeAuthorityStoreError::CorruptData)?;
    let app_key_spki_sha256 = digest(&row.app_key_spki_sha256)?;
    let configuration_fingerprint = digest(&row.configuration_fingerprint)?;
    let request_deadline = request_deadline(selector.lease_issued_at, selector.lease_expires_at)?;
    let identity = GithubRuntimeAuthorityIdentity::new(
        tenant,
        automata_ci_core::AttemptId::from_uuid(selector.attempt_id),
        automata_ci_core::FencingToken::new(
            u64::try_from(selector.fencing_token)
                .map_err(|_| GithubJobRuntimeAuthorityStoreError::CorruptData)?,
        )
        .map_err(|_| GithubJobRuntimeAuthorityStoreError::CorruptData)?,
        selector.lease_id,
        selector.lease_issued_at,
        selector.lease_expires_at,
        selector.run_id,
        selector.job_id,
        selector.runner_id,
        selector.runner_session_id,
        selector.runner_session_epoch,
        selector.runner_generation,
        selector.runner_slot,
        selector.job_ir_version,
        selector.job_ir_size_bytes,
        selector.job_ir_digest,
        repository_id,
        provider_connection_id,
        provider_installation_id,
        github_app_id,
        github_app_client_id,
        github_app_jwt_issuer_kind,
        github_repository_id,
        github_repository_name,
        namespace,
        selector.policy_digest,
        app_key_spki_sha256,
        configuration_fingerprint,
        row.preparation_selection_tail,
        row.activation_selection_tail,
        row.materialization_selection_tail,
        selector.lease_issued_at,
        request_deadline,
    )
    .map_err(|_| GithubJobRuntimeAuthorityStoreError::CorruptData)?;
    let job_ir = JobIrMetadata::new(
        selector.job_id,
        selector.run_id,
        selector.job_ir_version,
        selector.job_ir_size_bytes,
        selector.job_ir_digest,
        ObjectKey::new(row.job_ir_object_key.clone())
            .map_err(|_| GithubJobRuntimeAuthorityStoreError::CorruptData)?,
    )
    .map_err(|_| GithubJobRuntimeAuthorityStoreError::CorruptData)?;
    let workflow_id = WorkflowId::from_uuid(row.workflow_id);
    if workflow_id.as_uuid().is_nil() {
        return Err(GithubJobRuntimeAuthorityStoreError::CorruptData);
    }
    Ok(GithubJobRuntimeAuthorityEvidence::new(
        identity,
        workflow_id,
        job_ir,
    ))
}

fn request_deadline(
    lease_issued_at: UnixMillis,
    lease_expires_at: UnixMillis,
) -> Result<UnixMillis, GithubJobRuntimeAuthorityStoreError> {
    let maximum = lease_issued_at
        .get()
        .checked_add(MAX_GITHUB_AUTHORITY_REQUEST_MILLIS)
        .ok_or(GithubJobRuntimeAuthorityStoreError::CorruptData)?;
    let deadline = UnixMillis::new(maximum.min(lease_expires_at.get()));
    if deadline <= lease_issued_at {
        return Err(GithubJobRuntimeAuthorityStoreError::CorruptData);
    }
    Ok(deadline)
}

const fn authority_profile_name(profile: JobAuthorityProfile) -> &'static str {
    match profile {
        JobAuthorityProfile::Standard => "standard",
        JobAuthorityProfile::CredentialFree => "credential_free",
    }
}

fn decode_github_server_service_jwt_issuer(value: &str) -> Option<GithubServerServiceJwtIssuer> {
    match value {
        "app_client_id" => Some(GithubServerServiceJwtIssuer::AppClientId),
        "app_id" => Some(GithubServerServiceJwtIssuer::AppId),
        _ => None,
    }
}

fn digest(bytes: &[u8]) -> Result<Sha256Digest, GithubJobRuntimeAuthorityStoreError> {
    let value: [u8; 32] = bytes
        .try_into()
        .map_err(|_| GithubJobRuntimeAuthorityStoreError::CorruptData)?;
    if value.iter().all(|byte| *byte == 0) {
        return Err(GithubJobRuntimeAuthorityStoreError::CorruptData);
    }
    Ok(Sha256Digest::from_bytes(value))
}

fn positive_i64(value: u64) -> Result<i64, GithubJobRuntimeAuthorityStoreError> {
    i64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(GithubJobRuntimeAuthorityStoreError::CorruptData)
}

fn positive_u64(value: i64) -> Result<u64, GithubJobRuntimeAuthorityStoreError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(GithubJobRuntimeAuthorityStoreError::CorruptData)
}

#[cfg(test)]
#[rustfmt::skip] // Contract matrices stay compact enough to compare all six shapes at once.
mod tests {
    use sha2::{Digest as _, Sha256};

    use super::*;

    #[rustfmt::skip]
    const LINEAGE_SQL: [&str; 6] = [
        PREPARATION_SELECTION_BASE_SQL, PREPARATION_SELECTION_RENEWAL_SQL,
        ACTIVATION_SELECTION_BASE_SQL, ACTIVATION_SELECTION_RENEWAL_SQL,
        MATERIALIZATION_SELECTION_BASE_SQL, MATERIALIZATION_SELECTION_RENEWAL_SQL,
    ];
    #[rustfmt::skip]
    const FINGERPRINTS: [(usize, &str, usize, &str); 6] = [
        (627, "2923f6d7c4352dd06c66b824490522c45cdb3c1cffd95aac56cc42173ba2406c", 483, "b85f2c5b85a4d82c08b3a53bb075ffe398ad7e71173ce8e8675295cb7b16a35d"),
        (707, "ae5b47603441c6e1f3fe8e40a4472cea585dd1affc717207f6e11609dfa7a6e1", 545, "4f94ddfb86f4054d8d08708711c98682b2384684107c0f70a2435f709679ddef"),
        (626, "c4d7991ce5c9d95925daf7c4655f96d81b2d8e7a4a1bf57a4fbb7c64d94097d5", 482, "7c54b608aa3541ad590816d8ffa0e74d894dd3428bdad3a5bce94a74710ec571"),
        (706, "34191bd0a7b8e1c46416e8b8960d8f0981b007ced5420a9463b4403ede32336a", 544, "d21cc8c6f0f54291ce8796208516c726744657eb049d5d06d8b0ca38ef68a513"),
        (619, "616910a4eea26286e67d8120f8a1082134bb3d368f0ab2fa316cd3117309cea3", 475, "eeda1985e5ac1143c498005c67014dbf7d7fb482a99804fa155a28bbe1258526"),
        (791, "f4287f6bcc5b81ae76136e00fc77af9d4edf1e06b312a8a80ecfe8b13b859200", 609, "c91c910c8ea94423f905d5d3ce8b6ce7bedd8f0ddd7cb7a36fcd1bfbbb92d700"),
    ];

    #[test]
    fn selection_lineage_sql_fingerprints_and_placeholders_are_stable() {
        #[rustfmt::skip]
        let placeholders: [&[u8]; 6] = [
            &[8, 9, 10, 1, 2, 3, 4, 5, 6, 7], &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            &[8, 9, 10, 1, 2, 3, 4, 5, 6, 7], &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            &[9, 10, 11, 1, 2, 3, 4, 5, 6, 7, 8], &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        ];
        for ((sql, fingerprint), placeholders) in LINEAGE_SQL
            .into_iter().zip(FINGERPRINTS).zip(placeholders)
        {
            let canonical = canonical_sql(sql);
            assert_eq!((sql.len(), sha256(sql)), (fingerprint.0, fingerprint.1.to_owned()));
            assert_eq!((canonical.len(), sha256(&canonical)), (fingerprint.2, fingerprint.3.to_owned()));
            assert_eq!(placeholder_sequence(sql), placeholders);
        }
    }

    #[test]
    fn selection_lineage_queries_keep_their_closed_relational_shapes() {
        #[rustfmt::skip]
        let shapes = [
            (LINEAGE_SQL[0], "logical_workflow_activation_work_selections", "selection", Some("preparation"), false, false, false),
            (LINEAGE_SQL[1], "logical_workflow_activation_renewal_receipts", "renewal", Some("preparation"), false, false, true),
            (LINEAGE_SQL[2], "logical_workflow_activation_work_selections", "selection", Some("activation"), false, false, false),
            (LINEAGE_SQL[3], "logical_workflow_activation_renewal_receipts", "renewal", Some("activation"), false, false, true),
            (LINEAGE_SQL[4], "logical_workflow_materialization_work_selections", "selection", None, true, false, false),
            (LINEAGE_SQL[5], "logical_workflow_materialization_renewal_receipts", "renewal", None, true, true, true),
        ];
        for (sql, table, alias, kind, instance, job_attempt, renewal) in shapes {
            assert!(sql.contains(&format!("FROM {table} AS {alias}")));
            for column in ["tenant_id", "run_id", "invocation_id", "logical_job_id", "owner_id", "authority_digest"] {
                assert!(sql.contains(&format!("{alias}.{column} =")), "{table}.{column}");
            }
            assert_eq!(sql.contains(&format!("{alias}.instance_id =")), instance);
            assert_eq!(sql.contains("expected_job_id =") && sql.contains("expected_attempt_id ="), job_attempt);
            assert_eq!(sql.contains("runtime_policy_revision =") && sql.contains("runtime_policy_digest ="), renewal);
            assert!(sql.contains(&format!("FOR SHARE OF {alias}")));
            assert_eq!(sql.contains("authority_kind ="), kind.is_some());
            if let Some(kind) = kind {
                assert!(sql.contains(&format!("{alias}.authority_kind = '{kind}'")));
            }
        }
    }

    #[test]
    fn selection_tail_decoder_aliases_are_closed() {
        #[rustfmt::skip]
        let expected = [
            ("decode_preparation_selection_tail", [("selection_id", "preparation_selection_id"), ("owner_id", "preparation_owner_id"), ("generation", "preparation_generation"), ("digest", "preparation_descriptor_digest"), ("claimed_at_ms", "preparation_claimed_at_ms"), ("expires_at_ms", "preparation_expires_at_ms")]),
            ("decode_activation_selection_tail", [("selection_id", "activation_selection_id"), ("owner_id", "activation_owner_id"), ("generation", "activation_generation"), ("digest", "activation_input_digest"), ("claimed_at_ms", "activation_claimed_at_ms"), ("expires_at_ms", "activation_expires_at_ms")]),
            ("decode_materialization_selection_tail", [("selection_id", "materialization_selection_id"), ("owner_id", "materialization_owner_id"), ("generation", "materialization_generation"), ("digest", "materialization_descriptor_digest"), ("claimed_at_ms", "materialization_claimed_at_ms"), ("expires_at_ms", "materialization_expires_at_ms")]),
        ];
        assert_eq!([PREPARATION_DECODER_MAPPING, ACTIVATION_DECODER_MAPPING, MATERIALIZATION_DECODER_MAPPING], expected);
    }

    fn sha256(value: &str) -> String {
        Sha256Digest::from_bytes(Sha256::digest(value.as_bytes()).into()).to_string()
    }

    fn canonical_sql(sql: &str) -> String {
        sql.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn placeholder_sequence(sql: &str) -> Vec<u8> {
        let bytes = sql.as_bytes();
        let mut sequence = Vec::new();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'$' {
                let start = index + 1;
                index = start;
                while index < bytes.len() && bytes[index].is_ascii_digit() { index += 1; }
                if start != index {
                    sequence.push(std::str::from_utf8(&bytes[start..index]).expect("placeholder digits").parse().expect("placeholder number"));
                    continue;
                }
            }
            index += 1;
        }
        sequence
    }
}
