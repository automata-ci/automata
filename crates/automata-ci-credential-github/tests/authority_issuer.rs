use std::{
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use automata_ci_control::runner_control::{
    ControlPortError, RuntimeAuthorityIssueRequest, RuntimeAuthorityIssuer as _,
};
use automata_ci_core::{
    AttemptId, FencingToken, JobContentReference, JobExecutionContext, JobId, JobInstanceIdentity,
    JobIr, JobIrEnvelope, JobSource, Lease, LeaseId, RunId, RunValueTemplates, RunnerId,
    RunnerRequirements, RunnerSessionId, RuntimeBoolean, SemanticStep, Sha256Digest, ShellTemplate,
    StepId, StepIr, TrustActorEvidence, TrustActorKind, TrustAutomationKind, TrustEventKind,
    TrustEvidence, TrustOriginKind, TrustPolicy, TrustRepositoryEvidence, TrustSnapshot,
    TrustTokenRecursion, UnixMillis, ValueTemplate, WorkflowId,
};
use automata_ci_credential_github::{
    GITHUB_REPOSITORY_AUTHORITY_NAMESPACE, GITHUB_REPOSITORY_RUNTIME_AUTHORITY,
    GithubInstallationTokenMintOutcome, GithubRepositoryRuntimeAuthorityIssuer,
    GithubRuntimeAuthorityCommitSupervisor, GithubRuntimeAuthorityCoordinatorClock,
    GithubRuntimeAuthorityIdentityResolutionError, GithubRuntimeAuthorityIdentityResolver,
    GithubRuntimeAuthorityIssuerConfigurationError, GithubRuntimeAuthorityMintBroker,
    GithubRuntimeAuthorityMintCoordinator, GithubRuntimeAuthorityRequestResolver,
    GithubRuntimeAuthorityResolutionError, ResolvedGithubRuntimeAuthorityIdentity,
    ResolvedGithubRuntimeAuthorityRequest, github_runtime_authority_workload_identity,
};
use automata_ci_key_management::{
    ENVELOPE_SCHEMA_V1, EncryptedEnvelope, EnvelopeCodec, KeyEncryptionContext, KeyEncryptionError,
    KeyEncryptionProvider, KeyId, LocalAes256GcmKeyring, LocalKeyMaterial, SecretBytes,
    WrappedDataKey,
};
use automata_ci_protocol::{ProtocolLimits, RuntimeAuthorityEndpoint};
use automata_ci_protocol_protobuf::encode_job_ir;
use automata_ci_provider::ProviderConnectionId;
use automata_ci_scm::credential::{
    CredentialError, CredentialErrorKind, MinimumValidity, PermissionLevel, PermissionName,
    PermissionSet, ProviderResourceId, RepositoryCredentialRequest, RepositoryScope,
};
use automata_ci_scm::{RepositoryId as ScmRepositoryId, ScmProviderId};
use automata_ci_store::{
    AuthenticateGithubRuntimeAuthorityUnprotectedErasure, BeginGithubRuntimeAuthorityMint,
    BeginGithubRuntimeAuthorityMintOutcome, ClaimGithubRuntimeAuthorityMint,
    ClaimGithubRuntimeAuthorityRevocation, ClaimedGithubRuntimeAuthorityMint,
    ClaimedGithubRuntimeAuthorityRevocation, CommitGithubRuntimeAuthority,
    ConfirmGithubRuntimeAuthorityRevocation, DeferGithubRuntimeAuthorityRevocation,
    GithubInstallationId, GithubRepositoryId, GithubRepositoryName,
    GithubRuntimeAuthorityActivationSelectionTail, GithubRuntimeAuthorityClaimFence,
    GithubRuntimeAuthorityCommitDisposition, GithubRuntimeAuthorityCorruptionKind,
    GithubRuntimeAuthorityEnvelopeMetadata, GithubRuntimeAuthorityIdentity,
    GithubRuntimeAuthorityInspection, GithubRuntimeAuthorityMaterializationSelectionTail,
    GithubRuntimeAuthorityNamespace, GithubRuntimeAuthorityPreparationSelectionTail,
    GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityReconciliationReport,
    GithubRuntimeAuthorityRepository, GithubRuntimeAuthorityState,
    GithubRuntimeAuthorityStoreError, GithubRuntimeAuthorityTerminalReason,
    GithubRuntimeAuthorityWorkerId, GithubServerServiceAppClientId, GithubServerServiceAppId,
    GithubServerServiceJwtIssuer, InspectGithubRuntimeAuthority, JobIrMetadata,
    LoadGithubRuntimeAuthority, LogicalActivationGeneration,
    LogicalActivationPreparationGeneration, LogicalActivationWorkerId,
    LogicalMaterializationGeneration, LogicalMaterializationWorkerId, LogicalWorkSelectionId,
    MarkGithubRuntimeAuthorityIndeterminate, ObjectKey, ProtectedGithubRuntimeAuthority,
    QuarantineGithubRuntimeAuthority, ReadyGithubRuntimeAuthority,
    ReconcileGithubRuntimeAuthorities, RejectGithubRuntimeAuthorityMint, RepositoryId,
    RetryGithubRuntimeAuthorityMint, RetryGithubRuntimeAuthorityRevocation, RunnerGeneration,
    RunnerSessionFence, SessionEpoch, StableRunnerSlot, TenantScope,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

const TOKEN: &str = "ghs_durable-ready-token_123";
const ISSUED_AT: i64 = 1_800_000_000_000;

#[tokio::test]
async fn durable_ready_replays_byte_identically_without_another_mint() {
    let fixture = Fixture::new();
    let codec = test_codec();
    let snapshot = ready_snapshot(&fixture.identity, codec.as_ref(), TOKEN).await;
    let store = Arc::new(FakeStore::ready(fixture.identity.clone(), snapshot));
    let broker = Arc::new(RejectingBroker::default());
    let issuer = fixture.issuer(&store, codec, broker.clone());

    let first = issuer
        .issue(fixture.request())
        .await
        .expect("first ready load");
    let second = issuer
        .issue(fixture.request())
        .await
        .expect("byte-identical ready replay");

    assert_eq!(first, second);
    let authority = first
        .get(GITHUB_REPOSITORY_RUNTIME_AUTHORITY)
        .expect("repository authority");
    assert_eq!(authority.credential().expose_secret(), TOKEN);
    assert_eq!(authority.endpoint().as_str(), "https://github.com/");
    assert_eq!(authority.issued_at(), UnixMillis::new(ISSUED_AT + 1_000));
    assert_eq!(
        authority.expires_at(),
        UnixMillis::new(ISSUED_AT + 3_540_000)
    );
    assert_eq!(broker.calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.load_calls(), 4);
    assert!(!format!("{first:?}").contains(TOKEN));
}

#[tokio::test]
async fn authenticated_envelope_failure_is_durably_quarantined_without_delivery() {
    let fixture = Fixture::new();
    let codec = test_codec();
    let mut snapshot = ready_snapshot(&fixture.identity, codec.as_ref(), TOKEN).await;
    snapshot.ciphertext[0] ^= 0x80;
    let store = Arc::new(FakeStore::ready(fixture.identity.clone(), snapshot));
    let issuer = fixture.issuer(&store, codec, Arc::new(RejectingBroker::default()));

    assert_eq!(
        issuer.issue(fixture.request()).await.unwrap_err(),
        ControlPortError::Corrupt
    );
    assert_eq!(
        store.quarantine_kind(),
        Some(GithubRuntimeAuthorityCorruptionKind::EnvelopeAuthenticationFailed)
    );
    assert_eq!(store.state(), GithubRuntimeAuthorityState::Quarantined);
}

#[tokio::test]
async fn key_provider_unavailability_is_retryable_and_never_quarantines() {
    let fixture = Fixture::new();
    let snapshot = ready_snapshot(&fixture.identity, test_codec().as_ref(), TOKEN).await;
    let store = Arc::new(FakeStore::ready(fixture.identity.clone(), snapshot));
    let unavailable_codec = Arc::new(EnvelopeCodec::new(Arc::new(UnavailableKeyProvider)));
    let issuer = fixture.issuer(
        &store,
        unavailable_codec,
        Arc::new(RejectingBroker::default()),
    );

    assert_eq!(
        issuer.issue(fixture.request()).await.unwrap_err(),
        ControlPortError::Unavailable
    );
    assert_eq!(store.quarantine_kind(), None);
    assert_eq!(store.state(), GithubRuntimeAuthorityState::Ready);
}

#[tokio::test]
async fn ready_expiry_while_kms_is_blocked_never_returns_a_bearer() {
    let fixture = Arc::new(Fixture::new());
    let codec = test_codec();
    let snapshot = ready_snapshot(&fixture.identity, codec.as_ref(), TOKEN).await;
    let store = Arc::new(FakeStore::ready(fixture.identity.clone(), snapshot));
    let gate = Arc::new(GatedKeyProvider::new(test_key_provider()));
    let issuer = fixture.issuer(
        &store,
        Arc::new(EnvelopeCodec::new(gate.clone())),
        Arc::new(RejectingBroker::default()),
    );
    let issue_fixture = fixture.clone();
    let issue = tokio::spawn(async move { issuer.issue(issue_fixture.request()).await });

    gate.wait_until_blocked().await;
    store.expire_ready();
    gate.release();

    assert_eq!(
        issue.await.expect("issuer task").unwrap_err(),
        ControlPortError::Unavailable
    );
    assert_eq!(store.load_calls(), 2);
}

#[tokio::test]
async fn ready_supersession_while_kms_is_blocked_never_returns_a_bearer() {
    let fixture = Arc::new(Fixture::new());
    let codec = test_codec();
    let snapshot = ready_snapshot(&fixture.identity, codec.as_ref(), TOKEN).await;
    let store = Arc::new(FakeStore::ready(fixture.identity.clone(), snapshot));
    let gate = Arc::new(GatedKeyProvider::new(test_key_provider()));
    let issuer = fixture.issuer(
        &store,
        Arc::new(EnvelopeCodec::new(gate.clone())),
        Arc::new(RejectingBroker::default()),
    );
    let issue_fixture = fixture.clone();
    let issue = tokio::spawn(async move { issuer.issue(issue_fixture.request()).await });

    gate.wait_until_blocked().await;
    store.supersede_ready();
    gate.release();

    assert_eq!(
        issue.await.expect("issuer task").unwrap_err(),
        ControlPortError::Unavailable
    );
    assert_eq!(store.load_calls(), 2);
}

#[tokio::test]
async fn definitive_no_token_state_never_publishes_or_remints() {
    let fixture = Fixture::new();
    let store = Arc::new(FakeStore::empty());
    let broker = Arc::new(RejectingBroker::default());
    let issuer = fixture.issuer(&store, test_codec(), broker.clone());

    for _ in 0..2 {
        assert_eq!(
            issuer.issue(fixture.request()).await.unwrap_err(),
            ControlPortError::Unavailable
        );
    }
    assert_eq!(broker.calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.state(), GithubRuntimeAuthorityState::Rejected);
}

#[tokio::test]
async fn restarted_minting_state_is_unavailable_and_never_calls_provider_again() {
    let fixture = Fixture::new();
    let store = Arc::new(FakeStore::already_started());
    let broker = Arc::new(RejectingBroker::default());
    let issuer = fixture.issuer(&store, test_codec(), broker.clone());

    for _ in 0..2 {
        assert_eq!(
            issuer.issue(fixture.request()).await.unwrap_err(),
            ControlPortError::Unavailable
        );
    }
    assert_eq!(broker.calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.state(), GithubRuntimeAuthorityState::Minting);
}

#[test]
fn resolved_identity_rejects_a_changed_deterministic_issuance_anchor() {
    let fixture = Fixture::new();
    let changed = identity_for(&fixture, UnixMillis::new(ISSUED_AT + 1));
    assert!(ResolvedGithubRuntimeAuthorityIdentity::new(fixture.request(), changed).is_err());
}

struct Fixture {
    job: JobIrEnvelope,
    metadata: JobIrMetadata,
    lease: Lease,
    session: RunnerSessionFence,
    slot: StableRunnerSlot,
    identity: GithubRuntimeAuthorityIdentity,
}

impl Fixture {
    fn new() -> Self {
        let runner_id = RunnerId::new();
        let job = JobIrEnvelope::new(
            WorkflowId::new(),
            JobSource::new(
                "github",
                "automata-ci/automata",
                automata_ci_core::GitObjectId::from_provider_hex(
                    "0123456789abcdef0123456789abcdef01234567",
                )
                .expect("revision"),
                ".ci/workflows/ci.yml",
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
            .with_trust_snapshot(trusted_snapshot()),
        );
        let lease = Lease::new(
            LeaseId::new(),
            AttemptId::new(),
            runner_id,
            FencingToken::new(1).expect("fence"),
            UnixMillis::new(ISSUED_AT),
            UnixMillis::new(ISSUED_AT + 600_000),
        )
        .expect("lease");
        let encoded = encode_job_ir(&job, &ProtocolLimits::default()).expect("canonical JobIR");
        let metadata = JobIrMetadata::new(
            job.job().job_id(),
            job.job().run_id(),
            job.version(),
            u64::try_from(encoded.len()).expect("size"),
            Sha256Digest::from_bytes(Sha256::digest(encoded).into()),
            ObjectKey::new("job-ir/github-authority.pb").expect("object key"),
        )
        .expect("metadata");
        let session = RunnerSessionFence::new(
            RunnerSessionId::new(),
            runner_id,
            RunnerGeneration::new(2).expect("generation"),
            SessionEpoch::new(3).expect("epoch"),
        );
        let slot = StableRunnerSlot::new(1).expect("slot");
        let mut fixture = Self {
            job,
            metadata,
            lease,
            session,
            slot,
            identity: placeholder_identity(),
        };
        fixture.identity = identity_for(&fixture, fixture.lease.issued_at());
        fixture
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

    fn issuer(
        &self,
        repository: &Arc<FakeStore>,
        codec: Arc<EnvelopeCodec>,
        broker: Arc<RejectingBroker>,
    ) -> GithubRepositoryRuntimeAuthorityIssuer {
        let clock: Arc<dyn GithubRuntimeAuthorityCoordinatorClock> =
            Arc::new(FixedClock(UnixMillis::new(ISSUED_AT + 2_000)));
        let credential_request = credential_request(&self.identity);
        let request_resolver = Arc::new(ExactRequestResolver {
            identity: self.identity.clone(),
            request: credential_request,
        });
        let repository_port: Arc<dyn GithubRuntimeAuthorityRepository> = repository.clone();
        let supervisor = Arc::new(
            GithubRuntimeAuthorityCommitSupervisor::new(
                repository_port.clone(),
                tokio::runtime::Handle::current(),
                4,
                Duration::from_millis(1),
            )
            .expect("supervisor"),
        );
        let coordinator = Arc::new(GithubRuntimeAuthorityMintCoordinator::new(
            repository_port.clone(),
            request_resolver,
            broker,
            codec.clone(),
            clock.clone(),
            GithubRuntimeAuthorityWorkerId::from_uuid(Uuid::new_v4()).expect("worker"),
            supervisor,
        ));
        GithubRepositoryRuntimeAuthorityIssuer::new(
            Arc::new(ExactIdentityResolver {
                identity: self.identity.clone(),
            }),
            coordinator,
            repository_port,
            codec,
            clock,
            RuntimeAuthorityEndpoint::new("https://github.com/").expect("GitHub origin"),
        )
        .expect("TLS GitHub issuer")
    }
}

#[tokio::test]
async fn issuer_constructors_enforce_the_selected_transport_security() {
    let fixture = Fixture::new();
    let codec = test_codec();
    let store = Arc::new(FakeStore::empty());
    let clock: Arc<dyn GithubRuntimeAuthorityCoordinatorClock> =
        Arc::new(FixedClock(UnixMillis::new(ISSUED_AT + 2_000)));
    let repository: Arc<dyn GithubRuntimeAuthorityRepository> = store;
    let supervisor = Arc::new(
        GithubRuntimeAuthorityCommitSupervisor::new(
            Arc::clone(&repository),
            tokio::runtime::Handle::current(),
            1,
            Duration::from_millis(1),
        )
        .expect("supervisor"),
    );
    let coordinator = Arc::new(GithubRuntimeAuthorityMintCoordinator::new(
        Arc::clone(&repository),
        Arc::new(ExactRequestResolver {
            identity: fixture.identity.clone(),
            request: credential_request(&fixture.identity),
        }),
        Arc::new(RejectingBroker::default()),
        Arc::clone(&codec),
        Arc::clone(&clock),
        GithubRuntimeAuthorityWorkerId::from_uuid(Uuid::new_v4()).expect("worker"),
        supervisor,
    ));
    let result = GithubRepositoryRuntimeAuthorityIssuer::new(
        Arc::new(ExactIdentityResolver {
            identity: fixture.identity.clone(),
        }),
        Arc::clone(&coordinator),
        Arc::clone(&repository),
        Arc::clone(&codec),
        Arc::clone(&clock),
        RuntimeAuthorityEndpoint::loopback_development("http://127.0.0.1/")
            .expect("loopback endpoint"),
    );
    assert!(matches!(
        result,
        Err(GithubRuntimeAuthorityIssuerConfigurationError::InvalidEndpointSecurity)
    ));
    assert!(
        GithubRepositoryRuntimeAuthorityIssuer::new_for_loopback_emulator(
            Arc::new(ExactIdentityResolver {
                identity: fixture.identity.clone(),
            }),
            Arc::clone(&coordinator),
            Arc::clone(&repository),
            Arc::clone(&codec),
            Arc::clone(&clock),
            RuntimeAuthorityEndpoint::loopback_development("http://127.0.0.1/")
                .expect("loopback endpoint"),
        )
        .is_ok()
    );
    assert!(matches!(
        GithubRepositoryRuntimeAuthorityIssuer::new_for_mapped_emulator(
            Arc::new(ExactIdentityResolver {
                identity: fixture.identity.clone(),
            }),
            Arc::clone(&coordinator),
            Arc::clone(&repository),
            Arc::clone(&codec),
            Arc::clone(&clock),
            RuntimeAuthorityEndpoint::trusted_private_development(
                "http://github.example.test:18088/",
            )
            .expect("private endpoint"),
        ),
        Err(GithubRuntimeAuthorityIssuerConfigurationError::InvalidEndpointSecurity)
    ));
    assert!(
        GithubRepositoryRuntimeAuthorityIssuer::new_for_mapped_emulator(
            Arc::new(ExactIdentityResolver {
                identity: fixture.identity,
            }),
            coordinator,
            repository,
            codec,
            clock,
            RuntimeAuthorityEndpoint::trusted_private_development(
                "http://automata-git.invalid:18088/",
            )
            .expect("mapped endpoint"),
        )
        .is_ok()
    );
}

fn identity_for(fixture: &Fixture, requested_at: UnixMillis) -> GithubRuntimeAuthorityIdentity {
    let (preparation_tail, activation_tail, materialization_tail) = selection_tails(
        fixture.lease.issued_at(),
        UnixMillis::new(fixture.lease.issued_at().get() + 10_000),
    );
    GithubRuntimeAuthorityIdentity::new(
        TenantScope::from_authenticated_tenant_id("tenant-a").expect("tenant"),
        fixture.lease.attempt_id(),
        fixture.lease.fencing_token(),
        fixture.lease.lease_id(),
        fixture.lease.issued_at(),
        fixture.lease.expires_at(),
        fixture.job.job().run_id(),
        fixture.job.job().job_id(),
        fixture.lease.runner_id(),
        fixture.session.session_id(),
        fixture.session.session_epoch(),
        fixture.session.runner_generation(),
        fixture.slot,
        fixture.metadata.version(),
        fixture.metadata.encoded_size(),
        fixture.metadata.digest(),
        RepositoryId::from_uuid(Uuid::from_u128(11)),
        ProviderConnectionId::from_uuid(Uuid::from_u128(12)).expect("connection"),
        GithubInstallationId::new(17).expect("installation"),
        GithubServerServiceAppId::new(19).expect("App ID"),
        GithubServerServiceAppClientId::new("Iv1.automata-runtime").expect("App client ID"),
        GithubServerServiceJwtIssuer::AppClientId,
        GithubRepositoryId::new(18).expect("repository ID"),
        GithubRepositoryName::new(fixture.job.source().repository()).expect("repository name"),
        GithubRuntimeAuthorityNamespace::new(GITHUB_REPOSITORY_AUTHORITY_NAMESPACE)
            .expect("namespace"),
        fixture.metadata.digest(),
        Sha256Digest::from_bytes([20; 32]),
        Sha256Digest::from_bytes([21; 32]),
        preparation_tail,
        activation_tail,
        materialization_tail,
        requested_at,
        UnixMillis::new(requested_at.get() + 120_000),
    )
    .expect("identity")
}

fn placeholder_identity() -> GithubRuntimeAuthorityIdentity {
    let runner_id = RunnerId::new();
    let (preparation_tail, activation_tail, materialization_tail) =
        selection_tails(UnixMillis::new(0), UnixMillis::new(1));
    GithubRuntimeAuthorityIdentity::new(
        TenantScope::from_authenticated_tenant_id("placeholder").expect("tenant"),
        AttemptId::new(),
        FencingToken::new(1).expect("fence"),
        LeaseId::new(),
        UnixMillis::new(0),
        UnixMillis::new(2),
        RunId::new(),
        JobId::new(),
        runner_id,
        RunnerSessionId::new(),
        SessionEpoch::new(1).expect("epoch"),
        RunnerGeneration::new(1).expect("generation"),
        StableRunnerSlot::new(1).expect("slot"),
        automata_ci_core::JobIrVersion::current(),
        1,
        Sha256Digest::from_bytes([1; 32]),
        RepositoryId::from_uuid(Uuid::new_v4()),
        ProviderConnectionId::from_uuid(Uuid::new_v4()).expect("connection"),
        GithubInstallationId::new(1).expect("installation"),
        GithubServerServiceAppId::new(1).expect("App ID"),
        GithubServerServiceAppClientId::new("Iv1.placeholder").expect("App client ID"),
        GithubServerServiceJwtIssuer::AppClientId,
        GithubRepositoryId::new(1).expect("repository ID"),
        GithubRepositoryName::new("a/b").expect("name"),
        GithubRuntimeAuthorityNamespace::new(GITHUB_REPOSITORY_AUTHORITY_NAMESPACE)
            .expect("namespace"),
        Sha256Digest::from_bytes([1; 32]),
        Sha256Digest::from_bytes([3; 32]),
        Sha256Digest::from_bytes([4; 32]),
        preparation_tail,
        activation_tail,
        materialization_tail,
        UnixMillis::new(0),
        UnixMillis::new(1),
    )
    .expect("placeholder")
}

fn selection_tails(
    claimed_at: UnixMillis,
    expires_at: UnixMillis,
) -> (
    GithubRuntimeAuthorityPreparationSelectionTail,
    GithubRuntimeAuthorityActivationSelectionTail,
    GithubRuntimeAuthorityMaterializationSelectionTail,
) {
    let activation_owner =
        LogicalActivationWorkerId::from_uuid(Uuid::from_u128(100)).expect("activation owner");
    (
        GithubRuntimeAuthorityPreparationSelectionTail::new(
            LogicalWorkSelectionId::from_uuid(Uuid::from_u128(101)).expect("preparation selection"),
            activation_owner,
            LogicalActivationPreparationGeneration::new(1).expect("preparation generation"),
            Sha256Digest::from_bytes([31; 32]),
            claimed_at,
            expires_at,
        )
        .expect("preparation tail"),
        GithubRuntimeAuthorityActivationSelectionTail::new(
            LogicalWorkSelectionId::from_uuid(Uuid::from_u128(102)).expect("activation selection"),
            activation_owner,
            LogicalActivationGeneration::new(2).expect("activation generation"),
            Sha256Digest::from_bytes([32; 32]),
            claimed_at,
            expires_at,
        )
        .expect("activation tail"),
        GithubRuntimeAuthorityMaterializationSelectionTail::new(
            LogicalWorkSelectionId::from_uuid(Uuid::from_u128(103))
                .expect("materialization selection"),
            LogicalMaterializationWorkerId::from_uuid(Uuid::from_u128(104))
                .expect("materialization owner"),
            LogicalMaterializationGeneration::new(3).expect("materialization generation"),
            Sha256Digest::from_bytes([33; 32]),
            claimed_at,
            expires_at,
        )
        .expect("materialization tail"),
    )
}

fn credential_request(identity: &GithubRuntimeAuthorityIdentity) -> RepositoryCredentialRequest {
    RepositoryCredentialRequest::new(
        github_runtime_authority_workload_identity(identity),
        RepositoryScope::new(
            ScmProviderId::new("github").expect("provider"),
            ScmRepositoryId::new(identity.github_repository_name().as_str()).expect("repository"),
            ProviderResourceId::new(identity.github_repository_id().get().to_string())
                .expect("repository ID"),
        ),
        PermissionSet::new([(
            PermissionName::new("contents").expect("permission"),
            PermissionLevel::Read,
        )])
        .expect("permissions"),
        MinimumValidity::default(),
    )
}

#[derive(Debug)]
struct ExactIdentityResolver {
    identity: GithubRuntimeAuthorityIdentity,
}

#[async_trait]
impl GithubRuntimeAuthorityIdentityResolver for ExactIdentityResolver {
    async fn resolve_github_runtime_authority_identity(
        &self,
        request: RuntimeAuthorityIssueRequest<'_>,
    ) -> Result<
        Option<ResolvedGithubRuntimeAuthorityIdentity>,
        GithubRuntimeAuthorityIdentityResolutionError,
    > {
        ResolvedGithubRuntimeAuthorityIdentity::new(request, self.identity.clone())
            .map(Some)
            .map_err(|_| GithubRuntimeAuthorityIdentityResolutionError::Inconsistent)
    }
}

struct ExactRequestResolver {
    identity: GithubRuntimeAuthorityIdentity,
    request: RepositoryCredentialRequest,
}

#[async_trait]
impl GithubRuntimeAuthorityRequestResolver for ExactRequestResolver {
    async fn resolve_github_runtime_authority_request(
        &self,
        identity: &GithubRuntimeAuthorityIdentity,
    ) -> Result<Option<ResolvedGithubRuntimeAuthorityRequest>, GithubRuntimeAuthorityResolutionError>
    {
        if identity != &self.identity {
            return Err(GithubRuntimeAuthorityResolutionError::Inconsistent);
        }
        ResolvedGithubRuntimeAuthorityRequest::new(identity.clone(), self.request.clone())
            .map(Some)
            .map_err(|_| GithubRuntimeAuthorityResolutionError::Inconsistent)
    }
}

#[derive(Default)]
struct RejectingBroker {
    calls: AtomicUsize,
}

impl fmt::Debug for RejectingBroker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RejectingBroker([REDACTED])")
    }
}

#[async_trait]
impl GithubRuntimeAuthorityMintBroker for RejectingBroker {
    fn installation_id(&self) -> u64 {
        17
    }

    fn github_app_id(&self) -> GithubServerServiceAppId {
        GithubServerServiceAppId::new(19).expect("App ID")
    }

    fn github_app_client_id(&self) -> &GithubServerServiceAppClientId {
        static CLIENT_ID: std::sync::OnceLock<GithubServerServiceAppClientId> =
            std::sync::OnceLock::new();
        CLIENT_ID.get_or_init(|| {
            GithubServerServiceAppClientId::new("Iv1.automata-runtime").expect("App client ID")
        })
    }

    fn github_app_jwt_issuer_kind(&self) -> GithubServerServiceJwtIssuer {
        GithubServerServiceJwtIssuer::AppClientId
    }

    fn github_app_jwt_issuer_value(&self) -> &'static str {
        "Iv1.automata-runtime"
    }

    fn app_key_spki_sha256(&self) -> Sha256Digest {
        Sha256Digest::from_bytes([20; 32])
    }

    fn configuration_fingerprint(&self) -> Sha256Digest {
        Sha256Digest::from_bytes([21; 32])
    }

    fn maximum_mint_duration(&self) -> Duration {
        Duration::from_secs(1)
    }

    async fn mint_once(
        &self,
        _request: &RepositoryCredentialRequest,
    ) -> GithubInstallationTokenMintOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        GithubInstallationTokenMintOutcome::Rejected(CredentialError::new(
            CredentialErrorKind::InvalidRequest,
        ))
    }
}

#[derive(Clone, Copy, Debug)]
struct FixedClock(UnixMillis);

impl GithubRuntimeAuthorityCoordinatorClock for FixedClock {
    fn now(&self) -> UnixMillis {
        self.0
    }
}

#[derive(Clone)]
struct ProtectedSnapshot {
    metadata: GithubRuntimeAuthorityEnvelopeMetadata,
    key_id: KeyId,
    wrapped_data_key: Vec<u8>,
    nonce: [u8; automata_ci_key_management::ENVELOPE_NONCE_BYTES],
    ciphertext: Vec<u8>,
    ready_at: UnixMillis,
}

impl ProtectedSnapshot {
    fn protected(&self) -> ProtectedGithubRuntimeAuthority {
        let wrapped = WrappedDataKey::new(self.key_id.clone(), self.wrapped_data_key.clone())
            .expect("wrapped key");
        let envelope = EncryptedEnvelope::from_parts(
            ENVELOPE_SCHEMA_V1,
            wrapped,
            self.nonce,
            self.ciphertext.clone(),
        )
        .expect("envelope");
        ProtectedGithubRuntimeAuthority::new(self.metadata.clone(), envelope).expect("protected")
    }
}

async fn ready_snapshot(
    identity: &GithubRuntimeAuthorityIdentity,
    codec: &EnvelopeCodec,
    token: &str,
) -> ProtectedSnapshot {
    let mut frame = Vec::from(b"automata-ci/github-installation-token/v1\0".as_slice());
    frame.extend_from_slice(
        &u32::try_from(token.len())
            .expect("token length")
            .to_be_bytes(),
    );
    frame.extend_from_slice(token.as_bytes());
    let metadata = GithubRuntimeAuthorityEnvelopeMetadata::new(
        identity.clone(),
        Some(UnixMillis::new(ISSUED_AT + 3_600_000)),
        u64::try_from(frame.len()).expect("frame length"),
        Sha256Digest::from_bytes(Sha256::digest(&frame).into()),
    )
    .expect("metadata");
    let wrapping_context = identity
        .wrapping_encryption_context()
        .expect("wrapping context");
    let payload_context = metadata.encryption_context().expect("payload context");
    let envelope = codec
        .prepare(&wrapping_context)
        .await
        .expect("prepare")
        .seal_prepared(
            &payload_context,
            SecretBytes::new(frame).expect("secret frame"),
        );
    ProtectedSnapshot {
        metadata,
        key_id: envelope.wrapping_key_id().clone(),
        wrapped_data_key: envelope.wrapped_data_key().ciphertext().to_vec(),
        nonce: *envelope.nonce(),
        ciphertext: envelope.ciphertext().to_vec(),
        ready_at: UnixMillis::new(ISSUED_AT + 1_000),
    }
}

fn test_codec() -> Arc<EnvelopeCodec> {
    Arc::new(EnvelopeCodec::new(test_key_provider()))
}

fn test_key_provider() -> Arc<dyn KeyEncryptionProvider> {
    let material = LocalKeyMaterial::new(
        KeyId::new("github-authority-test-v1").expect("key ID"),
        SecretBytes::new(vec![0x42; 32]).expect("key material"),
    )
    .expect("local material");
    Arc::new(LocalAes256GcmKeyring::new(material, Vec::new(), Vec::new()).expect("keyring"))
}

struct GatedKeyProvider {
    inner: Arc<dyn KeyEncryptionProvider>,
    blocked: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl GatedKeyProvider {
    fn new(inner: Arc<dyn KeyEncryptionProvider>) -> Self {
        Self {
            inner,
            blocked: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        }
    }

    async fn wait_until_blocked(&self) {
        tokio::time::timeout(Duration::from_secs(5), self.blocked.notified())
            .await
            .expect("key provider reached its blocking point");
    }

    fn release(&self) {
        self.release.notify_one();
    }
}

fn trusted_snapshot() -> TrustSnapshot {
    TrustPolicy::current()
        .evaluate(
            TrustEvidence::new(TrustOriginKind::ProviderWebhook, TrustEventKind::Push)
                .with_original_actor(
                    TrustActorEvidence::new(
                        "actor-1",
                        TrustActorKind::User,
                        TrustAutomationKind::None,
                    )
                    .expect("actor evidence"),
                )
                .with_repositories(
                    TrustRepositoryEvidence::new("automata-ci/automata", "automata-ci")
                        .expect("source repository"),
                    TrustRepositoryEvidence::new("automata-ci/automata", "automata-ci")
                        .expect("target repository"),
                )
                .with_refs("refs/heads/main", "refs/heads/main", "refs/heads/main")
                .with_revisions("source-sha", "target-sha", "execution-sha")
                .with_fork(false)
                .with_token_recursion(TrustTokenRecursion::Suppressed),
        )
        .expect("trusted snapshot")
}

impl fmt::Debug for GatedKeyProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GatedKeyProvider([REDACTED])")
    }
}

#[async_trait]
impl KeyEncryptionProvider for GatedKeyProvider {
    async fn wrap_data_key(
        &self,
        plaintext_key: &SecretBytes,
        context: &KeyEncryptionContext,
    ) -> Result<WrappedDataKey, KeyEncryptionError> {
        self.inner.wrap_data_key(plaintext_key, context).await
    }

    async fn unwrap_data_key(
        &self,
        wrapped_key: &WrappedDataKey,
        context: &KeyEncryptionContext,
    ) -> Result<SecretBytes, KeyEncryptionError> {
        self.blocked.notify_one();
        self.release.notified().await;
        self.inner.unwrap_data_key(wrapped_key, context).await
    }
}

struct UnavailableKeyProvider;

impl fmt::Debug for UnavailableKeyProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UnavailableKeyProvider([REDACTED])")
    }
}

#[async_trait]
impl KeyEncryptionProvider for UnavailableKeyProvider {
    async fn wrap_data_key(
        &self,
        _plaintext_key: &SecretBytes,
        _context: &KeyEncryptionContext,
    ) -> Result<WrappedDataKey, KeyEncryptionError> {
        Err(KeyEncryptionError::Unavailable)
    }

    async fn unwrap_data_key(
        &self,
        _wrapped_key: &WrappedDataKey,
        _context: &KeyEncryptionContext,
    ) -> Result<SecretBytes, KeyEncryptionError> {
        Err(KeyEncryptionError::Unavailable)
    }
}

struct FakeStoreState {
    identity: Option<GithubRuntimeAuthorityIdentity>,
    claim: Option<ClaimedGithubRuntimeAuthorityMint>,
    state: Option<GithubRuntimeAuthorityState>,
    snapshot: Option<ProtectedSnapshot>,
    quarantine: Option<GithubRuntimeAuthorityCorruptionKind>,
    load_calls: usize,
    force_already_started: bool,
    current: bool,
}

struct FakeStore {
    state: Mutex<FakeStoreState>,
}

impl FakeStore {
    fn empty() -> Self {
        Self {
            state: Mutex::new(FakeStoreState {
                identity: None,
                claim: None,
                state: None,
                snapshot: None,
                quarantine: None,
                load_calls: 0,
                force_already_started: false,
                current: true,
            }),
        }
    }

    fn already_started() -> Self {
        let store = Self::empty();
        store
            .state
            .lock()
            .expect("store lock")
            .force_already_started = true;
        store
    }

    fn ready(identity: GithubRuntimeAuthorityIdentity, snapshot: ProtectedSnapshot) -> Self {
        let store = Self::empty();
        {
            let mut state = store.state.lock().expect("store lock");
            state.identity = Some(identity);
            state.state = Some(GithubRuntimeAuthorityState::Ready);
            state.snapshot = Some(snapshot);
        }
        store
    }

    fn state(&self) -> GithubRuntimeAuthorityState {
        self.state.lock().expect("store lock").state.expect("state")
    }

    fn load_calls(&self) -> usize {
        self.state.lock().expect("store lock").load_calls
    }

    fn quarantine_kind(&self) -> Option<GithubRuntimeAuthorityCorruptionKind> {
        self.state.lock().expect("store lock").quarantine
    }

    fn expire_ready(&self) {
        self.state.lock().expect("store lock").state = Some(GithubRuntimeAuthorityState::Revoked);
    }

    fn supersede_ready(&self) {
        self.state.lock().expect("store lock").current = false;
    }

    fn receipt(
        state: &FakeStoreState,
        lifecycle: GithubRuntimeAuthorityState,
        updated_at: UnixMillis,
    ) -> GithubRuntimeAuthorityReceipt {
        let terminal = (lifecycle == GithubRuntimeAuthorityState::Rejected)
            .then_some(GithubRuntimeAuthorityTerminalReason::ProviderMintRejected);
        GithubRuntimeAuthorityReceipt::from_repository_parts(
            state.identity.as_ref().expect("identity").key(),
            lifecycle,
            updated_at,
            terminal,
        )
        .expect("receipt")
    }
}

#[async_trait]
impl GithubRuntimeAuthorityRepository for FakeStore {
    async fn inspect_github_runtime_authority(
        &self,
        _request: InspectGithubRuntimeAuthority,
    ) -> Result<Option<GithubRuntimeAuthorityInspection>, GithubRuntimeAuthorityStoreError> {
        Ok(None)
    }

    async fn claim_github_runtime_authority_mint(
        &self,
        request: ClaimGithubRuntimeAuthorityMint,
    ) -> Result<Option<ClaimedGithubRuntimeAuthorityMint>, GithubRuntimeAuthorityStoreError> {
        let mut state = self.state.lock().expect("store lock");
        if state.state.is_some() {
            return Ok(None);
        }
        let claim = ClaimedGithubRuntimeAuthorityMint::from_repository_parts(
            request.identity().clone(),
            request.owner(),
            GithubRuntimeAuthorityClaimFence::new(1).expect("claim fence"),
            1,
            request.observed_at(),
            request.expires_at(),
        )
        .expect("claim");
        state.identity = Some(request.identity().clone());
        state.claim = Some(claim.clone());
        state.state = Some(GithubRuntimeAuthorityState::Claimed);
        Ok(Some(claim))
    }

    async fn begin_github_runtime_authority_mint(
        &self,
        request: BeginGithubRuntimeAuthorityMint,
    ) -> Result<BeginGithubRuntimeAuthorityMintOutcome, GithubRuntimeAuthorityStoreError> {
        let mut state = self.state.lock().expect("store lock");
        state.state = Some(GithubRuntimeAuthorityState::Minting);
        let receipt = Self::receipt(
            &state,
            GithubRuntimeAuthorityState::Minting,
            request.observed_at(),
        );
        if state.force_already_started {
            Ok(BeginGithubRuntimeAuthorityMintOutcome::AlreadyStarted(
                receipt,
            ))
        } else {
            Ok(BeginGithubRuntimeAuthorityMintOutcome::Started(receipt))
        }
    }

    async fn authenticate_github_runtime_authority_unprotected_erasure(
        &self,
        _request: AuthenticateGithubRuntimeAuthorityUnprotectedErasure,
    ) -> Result<Option<GithubRuntimeAuthorityReceipt>, GithubRuntimeAuthorityStoreError> {
        unreachable!("unprotected erasure is outside issuer integration coverage")
    }

    async fn mark_github_runtime_authority_indeterminate(
        &self,
        request: MarkGithubRuntimeAuthorityIndeterminate,
    ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
        let mut state = self.state.lock().expect("store lock");
        state.state = Some(GithubRuntimeAuthorityState::Indeterminate);
        Ok(Self::receipt(
            &state,
            GithubRuntimeAuthorityState::Indeterminate,
            request.observed_at(),
        ))
    }

    async fn retry_github_runtime_authority_mint(
        &self,
        _request: RetryGithubRuntimeAuthorityMint,
    ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
        Err(GithubRuntimeAuthorityStoreError::MintClaimRejected)
    }

    async fn reject_github_runtime_authority_mint(
        &self,
        request: RejectGithubRuntimeAuthorityMint,
    ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
        let mut state = self.state.lock().expect("store lock");
        state.state = Some(GithubRuntimeAuthorityState::Rejected);
        Ok(Self::receipt(
            &state,
            GithubRuntimeAuthorityState::Rejected,
            request.observed_at(),
        ))
    }

    async fn commit_github_runtime_authority(
        &self,
        _request: &CommitGithubRuntimeAuthority,
    ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
        Err(GithubRuntimeAuthorityStoreError::MintClaimRejected)
    }

    async fn load_ready_github_runtime_authority(
        &self,
        request: LoadGithubRuntimeAuthority,
    ) -> Result<Option<ReadyGithubRuntimeAuthority>, GithubRuntimeAuthorityStoreError> {
        let mut state = self.state.lock().expect("store lock");
        state.load_calls += 1;
        if !state.current {
            return Ok(None);
        }
        if state.identity.as_ref() != Some(request.identity()) {
            return if state.identity.is_some() {
                Err(GithubRuntimeAuthorityStoreError::IdentityConflict)
            } else {
                Ok(None)
            };
        }
        if state.state != Some(GithubRuntimeAuthorityState::Ready) {
            return Ok(None);
        }
        let snapshot = state
            .snapshot
            .as_ref()
            .ok_or(GithubRuntimeAuthorityStoreError::CorruptData)?;
        ReadyGithubRuntimeAuthority::from_repository_parts(
            snapshot.protected(),
            GithubRuntimeAuthorityCommitDisposition::Deliverable,
            snapshot.ready_at,
        )
        .map(Some)
        .map_err(|_| GithubRuntimeAuthorityStoreError::CorruptData)
    }

    async fn quarantine_github_runtime_authority(
        &self,
        request: QuarantineGithubRuntimeAuthority,
    ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
        let mut state = self.state.lock().expect("store lock");
        state.quarantine = Some(request.kind());
        state.state = Some(GithubRuntimeAuthorityState::Quarantined);
        Ok(Self::receipt(
            &state,
            GithubRuntimeAuthorityState::Quarantined,
            request.observed_at(),
        ))
    }

    async fn reconcile_github_runtime_authorities(
        &self,
        _request: ReconcileGithubRuntimeAuthorities,
    ) -> Result<GithubRuntimeAuthorityReconciliationReport, GithubRuntimeAuthorityStoreError> {
        Ok(GithubRuntimeAuthorityReconciliationReport::default())
    }

    async fn claim_github_runtime_authority_revocation(
        &self,
        _request: ClaimGithubRuntimeAuthorityRevocation,
    ) -> Result<Option<ClaimedGithubRuntimeAuthorityRevocation>, GithubRuntimeAuthorityStoreError>
    {
        Ok(None)
    }

    async fn revalidate_github_runtime_authority_revocation(
        &self,
        _request: automata_ci_store::RevalidateGithubRuntimeAuthorityRevocation,
    ) -> Result<
        Option<automata_ci_store::RevalidatedGithubRuntimeAuthorityRevocation>,
        GithubRuntimeAuthorityStoreError,
    > {
        unreachable!("revocation is outside issuance")
    }

    async fn retry_github_runtime_authority_revocation(
        &self,
        _request: RetryGithubRuntimeAuthorityRevocation,
    ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
        Err(GithubRuntimeAuthorityStoreError::RevocationClaimRejected)
    }

    async fn defer_github_runtime_authority_revocation(
        &self,
        _request: DeferGithubRuntimeAuthorityRevocation,
    ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
        Err(GithubRuntimeAuthorityStoreError::RevocationClaimRejected)
    }

    async fn confirm_github_runtime_authority_revocation(
        &self,
        _request: ConfirmGithubRuntimeAuthorityRevocation,
    ) -> Result<GithubRuntimeAuthorityReceipt, GithubRuntimeAuthorityStoreError> {
        Err(GithubRuntimeAuthorityStoreError::RevocationClaimRejected)
    }
}
