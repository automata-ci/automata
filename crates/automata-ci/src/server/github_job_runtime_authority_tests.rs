use std::{
    collections::VecDeque,
    fmt,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use automata_ci_core::{
    AttemptId, FencingToken, JobAuthorityProfile, JobContentReference, JobExecutionContext, JobId,
    JobInstanceIdentity, JobIr, JobIrEnvelope, JobPermissionGrant, JobPermissionRequest, JobSource,
    Lease, LeaseId, PermissionLevel, RunId, RunValueTemplates, RunnerId, RunnerRequirements,
    RunnerSessionId, RuntimeBoolean, SemanticStep, Sha256Digest, ShellTemplate, StepId, StepIr,
    UnixMillis, ValueTemplate, WorkflowId,
};
use automata_ci_credential_github::{
    GITHUB_REPOSITORY_AUTHORITY_NAMESPACE, GithubRuntimeAuthorityIdentityResolver as _,
    GithubRuntimeAuthorityRequestResolver as _,
};
use automata_ci_protocol::ProtocolLimits;
use automata_ci_protocol_protobuf::encode_job_ir;
use automata_ci_runner_control::{
    ControlPortError, JobIrObjectReader, OptionalRuntimeAuthorityIssuer as _,
    RuntimeAuthorityIssueRequest,
};
use automata_ci_store::{
    GithubJobRuntimeAuthorityEvidence, GithubJobRuntimeAuthorityExecution,
    GithubJobRuntimeAuthorityRepository, GithubJobRuntimeAuthorityResolution,
    GithubJobRuntimeAuthorityStoreError, GithubRepositoryId, GithubRepositoryName,
    GithubRuntimeAuthorityActivationSelectionTail, GithubRuntimeAuthorityIdentity,
    GithubRuntimeAuthorityMaterializationSelectionTail, GithubRuntimeAuthorityNamespace,
    GithubRuntimeAuthorityPreparationSelectionTail, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceJwtIssuer, JobIrMetadata,
    LogicalActivationGeneration, LogicalActivationPreparationGeneration, LogicalActivationWorkerId,
    LogicalMaterializationGeneration, LogicalMaterializationWorkerId, LogicalWorkSelectionId,
    ObjectKey, ProviderConnectionId, ProviderInstallationId, RepositoryId, RunnerGeneration,
    RunnerSessionFence, SessionEpoch, StableRunnerSlot, TenantScope,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use super::{GithubJobRuntimeAuthorityResolver, UnavailableGithubJobRuntimeAuthorityIssuer};

const ISSUED_AT: i64 = 1_800_000_000_000;

struct Fixture {
    job: JobIrEnvelope,
    encoded: Vec<u8>,
    metadata: JobIrMetadata,
    lease: Lease,
    session: RunnerSessionFence,
    slot: StableRunnerSlot,
    evidence: GithubJobRuntimeAuthorityEvidence,
}

impl Fixture {
    fn github_standard() -> Self {
        Self::new("github", JobAuthorityProfile::Standard)
    }

    fn new(provider: &str, profile: JobAuthorityProfile) -> Self {
        let runner_id = RunnerId::new();
        let permissions = match profile {
            JobAuthorityProfile::Standard => JobPermissionRequest::mapping([
                JobPermissionGrant::new("contents", PermissionLevel::Read),
                JobPermissionGrant::new("issues", PermissionLevel::Write),
            ]),
            JobAuthorityProfile::CredentialFree => JobPermissionRequest::mapping([]),
        };
        let job = JobIrEnvelope::new(
            WorkflowId::new(),
            JobSource::new(
                provider,
                "automata-ci/automata",
                "0123456789abcdef0123456789abcdef01234567",
                ".github/workflows/ci.yml",
                "push",
            ),
            JobExecutionContext::new(
                "CI",
                "refs/heads/main",
                "/__w/automata/automata",
                JobContentReference::new(
                    "events/push.json",
                    Sha256Digest::from_bytes([7; 32]),
                    2,
                    "application/json",
                ),
                JobContentReference::new(
                    "contexts/verify.pb",
                    Sha256Digest::from_bytes([8; 32]),
                    2,
                    "application/vnd.automata.job-runtime-context.protobuf",
                ),
            ),
            JobIr::new(
                JobId::new(),
                RunId::new(),
                "verify",
                RunnerRequirements::default(),
                JobInstanceIdentity::new("verify", 0, 1, Sha256Digest::from_bytes([9; 32]))
                    .expect("job instance"),
                false,
                vec![StepIr::new(
                    StepId::new("verify").expect("step ID"),
                    ValueTemplate::literal("Verify").expect("step name"),
                    RuntimeBoolean::literal(false),
                    SemanticStep::run(RunValueTemplates::new(
                        ValueTemplate::literal("cargo test").expect("command"),
                        ShellTemplate::default_shell(),
                    )),
                )],
            )
            .with_permission_request(permissions)
            .with_authority_profile(profile),
        );
        job.validate().expect("current JobIR");
        let encoded = encode_job_ir(&job, &ProtocolLimits::default()).expect("canonical JobIR");
        let metadata = JobIrMetadata::new(
            job.job().job_id(),
            job.job().run_id(),
            job.version(),
            u64::try_from(encoded.len()).expect("encoded size"),
            Sha256Digest::from_bytes(Sha256::digest(&encoded).into()),
            ObjectKey::new("job-ir/github-authority.pb").expect("object key"),
        )
        .expect("metadata");
        let lease = Lease::new(
            LeaseId::new(),
            AttemptId::new(),
            runner_id,
            FencingToken::new(1).expect("fence"),
            UnixMillis::new(ISSUED_AT),
            UnixMillis::new(ISSUED_AT + 600_000),
        )
        .expect("lease");
        let session = RunnerSessionFence::new(
            RunnerSessionId::new(),
            runner_id,
            RunnerGeneration::new(2).expect("generation"),
            SessionEpoch::new(3).expect("epoch"),
        );
        let slot = StableRunnerSlot::new(1).expect("slot");
        let identity = identity(&job, &metadata, &lease, session, slot);
        let evidence =
            GithubJobRuntimeAuthorityEvidence::new(identity, job.workflow_id(), metadata.clone());
        Self {
            job,
            encoded,
            metadata,
            lease,
            session,
            slot,
            evidence,
        }
    }

    fn request(&self) -> RuntimeAuthorityIssueRequest<'_> {
        RuntimeAuthorityIssueRequest::new(
            &self.job,
            &self.metadata,
            &self.lease,
            self.lease.issued_at(),
            self.session,
            self.slot,
        )
        .expect("authority request")
    }
}

fn identity(
    job: &JobIrEnvelope,
    metadata: &JobIrMetadata,
    lease: &Lease,
    session: RunnerSessionFence,
    slot: StableRunnerSlot,
) -> GithubRuntimeAuthorityIdentity {
    let activation_owner =
        LogicalActivationWorkerId::from_uuid(Uuid::from_u128(100)).expect("activation owner");
    let tail_claimed_at = lease.issued_at();
    let tail_expires_at = UnixMillis::new(lease.issued_at().get() + 10_000);
    let preparation_tail = GithubRuntimeAuthorityPreparationSelectionTail::new(
        LogicalWorkSelectionId::from_uuid(Uuid::from_u128(101)).expect("preparation selection"),
        activation_owner,
        LogicalActivationPreparationGeneration::new(1).expect("preparation generation"),
        Sha256Digest::from_bytes([31; 32]),
        tail_claimed_at,
        tail_expires_at,
    )
    .expect("preparation tail");
    let activation_tail = GithubRuntimeAuthorityActivationSelectionTail::new(
        LogicalWorkSelectionId::from_uuid(Uuid::from_u128(102)).expect("activation selection"),
        activation_owner,
        LogicalActivationGeneration::new(2).expect("activation generation"),
        Sha256Digest::from_bytes([32; 32]),
        tail_claimed_at,
        tail_expires_at,
    )
    .expect("activation tail");
    let materialization_tail = GithubRuntimeAuthorityMaterializationSelectionTail::new(
        LogicalWorkSelectionId::from_uuid(Uuid::from_u128(103)).expect("materialization selection"),
        LogicalMaterializationWorkerId::from_uuid(Uuid::from_u128(104))
            .expect("materialization owner"),
        LogicalMaterializationGeneration::new(3).expect("materialization generation"),
        Sha256Digest::from_bytes([33; 32]),
        tail_claimed_at,
        tail_expires_at,
    )
    .expect("materialization tail");
    GithubRuntimeAuthorityIdentity::new(
        TenantScope::from_authenticated_tenant_id("tenant-a").expect("tenant"),
        lease.attempt_id(),
        lease.fencing_token(),
        lease.lease_id(),
        lease.issued_at(),
        lease.expires_at(),
        job.job().run_id(),
        job.job().job_id(),
        lease.runner_id(),
        session.session_id(),
        session.session_epoch(),
        session.runner_generation(),
        slot,
        metadata.version(),
        metadata.encoded_size(),
        metadata.digest(),
        RepositoryId::from_uuid(Uuid::from_u128(11)),
        ProviderConnectionId::from_uuid(Uuid::from_u128(12)).expect("connection"),
        ProviderInstallationId::new(17).expect("installation"),
        GithubServerServiceAppId::new(19).expect("App ID"),
        GithubServerServiceAppClientId::new("Iv1.automata-runtime").expect("App client ID"),
        GithubServerServiceJwtIssuer::AppClientId,
        GithubRepositoryId::new(18).expect("repository ID"),
        GithubRepositoryName::new(job.source().repository()).expect("repository name"),
        GithubRuntimeAuthorityNamespace::new(GITHUB_REPOSITORY_AUTHORITY_NAMESPACE)
            .expect("namespace"),
        metadata.digest(),
        Sha256Digest::from_bytes([20; 32]),
        Sha256Digest::from_bytes([21; 32]),
        preparation_tail,
        activation_tail,
        materialization_tail,
        lease.issued_at(),
        UnixMillis::new(lease.issued_at().get() + 120_000),
    )
    .expect("identity")
}

#[tokio::test]
async fn exact_standard_identity_and_request_are_resolved_twice_without_guessing() {
    let fixture = Fixture::github_standard();
    let repository = Arc::new(EvidenceRepository::new(
        GithubJobRuntimeAuthorityResolution::Standard(Box::new(fixture.evidence.clone())),
        [fixture.evidence.clone(), fixture.evidence.clone()],
    ));
    let reader = Arc::new(Objects::ready(fixture.encoded.clone()));
    let resolver = GithubJobRuntimeAuthorityResolver::new(repository.clone(), reader);

    let identity = resolver
        .resolve_github_runtime_authority_identity(fixture.request())
        .await
        .expect("identity resolution")
        .expect("Standard identity");
    assert_eq!(identity.identity(), fixture.evidence.identity());

    let request = resolver
        .resolve_github_runtime_authority_request(identity.identity())
        .await
        .expect("request resolution")
        .expect("exact request");
    assert_eq!(request.identity(), fixture.evidence.identity());
    assert_eq!(
        request.request().repository().stable_id().as_str(),
        fixture
            .evidence
            .identity()
            .github_repository_id()
            .get()
            .to_string()
    );
    assert_eq!(repository.remaining_revalidations(), 0);
}

#[tokio::test]
async fn changed_historical_workflow_or_repository_is_inconsistent() {
    let fixture = Fixture::github_standard();
    let wrong_workflow = GithubJobRuntimeAuthorityEvidence::new(
        fixture.evidence.identity().clone(),
        WorkflowId::new(),
        fixture.metadata.clone(),
    );
    let resolver = GithubJobRuntimeAuthorityResolver::new(
        Arc::new(EvidenceRepository::new(
            GithubJobRuntimeAuthorityResolution::Standard(Box::new(wrong_workflow)),
            [],
        )),
        Arc::new(Objects::ready(fixture.encoded.clone())),
    );
    assert_eq!(
        resolver
            .resolve_github_runtime_authority_identity(fixture.request())
            .await
            .expect_err("foreign workflow must fail"),
        automata_ci_credential_github::GithubRuntimeAuthorityIdentityResolutionError::Inconsistent
    );

    let mut wrong_identity = fixture.evidence.identity().clone();
    wrong_identity = GithubRuntimeAuthorityIdentity::new(
        wrong_identity.tenant().clone(),
        wrong_identity.key().attempt_id(),
        wrong_identity.key().fencing_token(),
        wrong_identity.lease_id(),
        wrong_identity.lease_issued_at(),
        wrong_identity.lease_expires_at(),
        wrong_identity.run_id(),
        wrong_identity.job_id(),
        wrong_identity.runner_id(),
        wrong_identity.runner_session_id(),
        wrong_identity.runner_session_epoch(),
        wrong_identity.runner_generation(),
        wrong_identity.runner_slot(),
        wrong_identity.job_ir_version(),
        wrong_identity.job_ir_size_bytes(),
        wrong_identity.job_ir_digest(),
        wrong_identity.repository_id(),
        wrong_identity.provider_connection_id(),
        wrong_identity.provider_installation_id(),
        wrong_identity.github_app_id(),
        wrong_identity.github_app_client_id().clone(),
        wrong_identity.github_app_jwt_issuer_kind(),
        wrong_identity.github_repository_id(),
        GithubRepositoryName::new("other/repository").expect("foreign repository"),
        wrong_identity.namespace().clone(),
        wrong_identity.policy_digest(),
        wrong_identity.app_key_spki_sha256(),
        wrong_identity.configuration_fingerprint(),
        wrong_identity.preparation_selection_tail(),
        wrong_identity.activation_selection_tail(),
        wrong_identity.materialization_selection_tail(),
        wrong_identity.requested_at(),
        wrong_identity.request_deadline(),
    )
    .expect("foreign identity shape");
    let wrong_repository = GithubJobRuntimeAuthorityEvidence::new(
        wrong_identity,
        fixture.job.workflow_id(),
        fixture.metadata.clone(),
    );
    let resolver = GithubJobRuntimeAuthorityResolver::new(
        Arc::new(EvidenceRepository::new(
            GithubJobRuntimeAuthorityResolution::Standard(Box::new(wrong_repository)),
            [],
        )),
        Arc::new(Objects::ready(fixture.encoded.clone())),
    );
    assert_eq!(
        resolver
            .resolve_github_runtime_authority_identity(fixture.request())
            .await
            .expect_err("foreign repository must fail"),
        automata_ci_credential_github::GithubRuntimeAuthorityIdentityResolutionError::Inconsistent
    );
}

#[tokio::test]
async fn corrupt_object_or_changed_second_revalidation_fails_closed() {
    let fixture = Fixture::github_standard();
    let repository = Arc::new(EvidenceRepository::new(
        GithubJobRuntimeAuthorityResolution::Standard(Box::new(fixture.evidence.clone())),
        [fixture.evidence.clone(), fixture.evidence.clone()],
    ));
    let resolver = GithubJobRuntimeAuthorityResolver::new(
        repository,
        Arc::new(Objects::ready(vec![0_u8; fixture.encoded.len()])),
    );
    assert_eq!(
        resolver
            .resolve_github_runtime_authority_request(fixture.evidence.identity())
            .await
            .expect_err("corrupt immutable bytes must fail"),
        automata_ci_credential_github::GithubRuntimeAuthorityResolutionError::Inconsistent
    );

    let changed = GithubJobRuntimeAuthorityEvidence::new(
        fixture.evidence.identity().clone(),
        WorkflowId::new(),
        fixture.metadata.clone(),
    );
    let resolver = GithubJobRuntimeAuthorityResolver::new(
        Arc::new(EvidenceRepository::new(
            GithubJobRuntimeAuthorityResolution::Standard(Box::new(fixture.evidence.clone())),
            [fixture.evidence.clone(), changed],
        )),
        Arc::new(Objects::ready(fixture.encoded)),
    );
    assert_eq!(
        resolver
            .resolve_github_runtime_authority_request(fixture.evidence.identity())
            .await
            .expect_err("live evidence changed during resolution"),
        automata_ci_credential_github::GithubRuntimeAuthorityResolutionError::Inconsistent
    );
}

#[tokio::test]
async fn credential_free_and_foreign_jobs_decline_but_disabled_github_standard_is_unavailable() {
    let credential_free = Fixture::new("github", JobAuthorityProfile::CredentialFree);
    let guard = UnavailableGithubJobRuntimeAuthorityIssuer;
    assert!(
        guard
            .issue_optional(credential_free.request())
            .await
            .expect("CredentialFree decline")
            .is_none()
    );
    let foreign = Fixture::new("gitlab", JobAuthorityProfile::Standard);
    assert!(
        guard
            .issue_optional(foreign.request())
            .await
            .expect("foreign decline")
            .is_none()
    );
    let standard = Fixture::github_standard();
    assert_eq!(
        guard
            .issue_optional(standard.request())
            .await
            .expect_err("disabled GitHub Standard must fail"),
        ControlPortError::Unavailable
    );
}

struct EvidenceRepository {
    resolution: GithubJobRuntimeAuthorityResolution,
    revalidations: Mutex<VecDeque<GithubJobRuntimeAuthorityEvidence>>,
}

impl EvidenceRepository {
    fn new(
        resolution: GithubJobRuntimeAuthorityResolution,
        revalidations: impl IntoIterator<Item = GithubJobRuntimeAuthorityEvidence>,
    ) -> Self {
        Self {
            resolution,
            revalidations: Mutex::new(revalidations.into_iter().collect()),
        }
    }

    fn remaining_revalidations(&self) -> usize {
        self.revalidations.lock().expect("lock").len()
    }
}

#[async_trait]
impl GithubJobRuntimeAuthorityRepository for EvidenceRepository {
    async fn resolve_github_job_runtime_authority(
        &self,
        _execution: &GithubJobRuntimeAuthorityExecution,
    ) -> Result<GithubJobRuntimeAuthorityResolution, GithubJobRuntimeAuthorityStoreError> {
        Ok(self.resolution.clone())
    }

    async fn revalidate_github_job_runtime_authority(
        &self,
        _identity: &GithubRuntimeAuthorityIdentity,
    ) -> Result<GithubJobRuntimeAuthorityEvidence, GithubJobRuntimeAuthorityStoreError> {
        self.revalidations
            .lock()
            .expect("lock")
            .pop_front()
            .ok_or(GithubJobRuntimeAuthorityStoreError::Unauthorized)
    }
}

struct Objects {
    result: Result<Vec<u8>, ControlPortError>,
}

impl Objects {
    fn ready(bytes: Vec<u8>) -> Self {
        Self { result: Ok(bytes) }
    }
}

impl fmt::Debug for Objects {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Objects([IMMUTABLE JOBIR])")
    }
}

#[async_trait]
impl JobIrObjectReader for Objects {
    async fn read_job_ir(
        &self,
        _metadata: &JobIrMetadata,
        _maximum_bytes: u64,
    ) -> Result<Vec<u8>, ControlPortError> {
        self.result.clone()
    }
}
