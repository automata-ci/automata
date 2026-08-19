use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use automata_ci_core::{
    Architecture, EnvironmentProfile, EnvironmentProfileId, JobResourceAllocation,
    JobResourcePolicy, OperatingSystem, ResourceCapacity, RunnerLabel, WorkspaceId,
};
use automata_ci_credential_github::GithubServerServiceMintCutoffOutcome;
use automata_ci_key_management::{
    EnvelopeCodec, KeyId, LocalAes256GcmKeyring, LocalKeyMaterial, SecretBytes,
};
use automata_ci_provider::{
    ControlCredentialClaim, ControlCredentialProvider, ControlCredentialRequest,
    ExternalRepositoryId, ExternalRepositoryIdentity, ProviderArchiveLimits,
    ProviderConfigurationRevision, ProviderConnectionConfiguration, ProviderConnectionId,
    ProviderConnectionManifest, ProviderConnectionRevision, ProviderControlCredentialId,
    ProviderControlCredentialWorkerId, ProviderControlOperation, ProviderControlOperationSet,
    ProviderDefaultBranch, ProviderInstanceId, ProviderLifecycleState, ProviderRepositoryPath,
    ProviderRunnerPolicyBinding, ProviderSchemaVersion, ProviderWorkflowSource,
    RepositoryVisibility,
};
use automata_ci_provider_github::GithubConnectionPolicy;
use automata_ci_scm::RepositoryId as ScmRepositoryId;
use automata_ci_store::{
    AdmissionObject, BeginGithubServerServiceMint, BootstrapGithubProviderManifest,
    BootstrapGithubProviderRepository, ClaimNextGithubServerServiceMaintenance,
    FinishGithubServerServiceMint, FinishGithubServerServiceRevocation,
    GITHUB_PROVIDER_RUNNER_POLICY_MEDIA_TYPE, GITHUB_SERVICE_SAFE_ERASE_SKEW_MILLIS,
    GITHUB_SERVICE_TOKEN_LIFETIME_MILLIS, GithubCheckName, GithubInstallationId,
    GithubProviderGitRef, GithubProviderManifest, GithubProviderManifestLimits,
    GithubProviderManifestRevision, GithubProviderOrigins, GithubProviderRunnerPolicyObject,
    GithubProviderWebhookVerifierFingerprint, GithubProviderWorkflowSelection, GithubRepositoryId,
    GithubRepositoryName, GithubRepositoryOwnerId, GithubRepositoryVisibility,
    GithubScheduleClaimFence, GithubScheduleDiscoveryClaim, GithubScheduleRegistryId,
    GithubScheduleWorkerId, GithubServerServiceAppClientId, GithubServerServiceAppId,
    GithubServerServiceAuthorityId, GithubServerServiceAuthorityIdentity,
    GithubServerServiceAuthoritySelector, GithubServerServiceClaimFence,
    GithubServerServiceConsumerClaim, GithubServerServiceConsumerId,
    GithubServerServiceCredentialHandoff, GithubServerServiceEnvelopeMetadata,
    GithubServerServiceGeneration, GithubServerServiceHandoffId, GithubServerServiceIssuanceKey,
    GithubServerServiceIssuanceReceipt, GithubServerServiceIssuanceState,
    GithubServerServiceJwtIssuer, GithubServerServiceMaintenanceOutcome,
    GithubServerServiceRevision, GithubServerServiceScope, GithubServerServiceStoreError,
    GithubServerServiceWorkerId, ObjectKey, ProtectedGithubServerServiceCredential,
    QuarantineGithubServerServiceCredential, RegisterWorkflowRuntimePolicy,
    ReleaseGithubServerServiceHandoff, RepositoryId, Sha256Digest, TenantScope,
    WorkflowPermissionPolicy, WorkflowRunnerFeaturePolicy, WorkflowRuntimePolicy,
    WorkflowRuntimePolicyMapping, WorkflowRuntimePolicyRevision, github_provider_repository_id,
};
use sha2::{Digest as _, Sha256};
use tokio_util::sync::CancellationToken;

use super::*;

#[test]
fn common_control_operations_map_to_exact_least_authority_actions() {
    assert_eq!(
        common_control_action(ProviderControlOperation::ResultResolve),
        Some(GithubServerServiceAction::EnsureCheckSuite)
    );
    assert_eq!(
        common_control_action(ProviderControlOperation::ResultCreate),
        Some(GithubServerServiceAction::CreateCheckRun)
    );
    assert_eq!(
        common_control_action(ProviderControlOperation::ResultReconcile),
        Some(GithubServerServiceAction::ReconcileCheckRun)
    );
    for operation in [
        ProviderControlOperation::ResultRead,
        ProviderControlOperation::ResultWrite,
    ] {
        assert_eq!(
            common_control_action(operation),
            Some(GithubServerServiceAction::PublishCheckRun)
        );
    }
    for (operation, action, scope) in [
        (
            ProviderControlOperation::RepositoryRead,
            GithubServerServiceAction::FetchRepositoryRevision,
            GithubServerServiceScope::RepositoryContentsRead,
        ),
        (
            ProviderControlOperation::CommitChangedFilesRead,
            GithubServerServiceAction::FetchRepositoryChangedFiles,
            GithubServerServiceScope::RepositoryContentsRead,
        ),
        (
            ProviderControlOperation::MergeRequestChangedFilesRead,
            GithubServerServiceAction::FetchPullRequestFiles,
            GithubServerServiceScope::PullRequestsRead,
        ),
    ] {
        assert_eq!(common_control_action(operation), Some(action));
        assert_eq!(action.required_scope(), scope);
    }
    assert_eq!(
        common_control_action(ProviderControlOperation::ScheduleRead),
        None
    );
}

const OBSERVED_AT: i64 = 1_000;
const REQUIRED_THROUGH: i64 = 2_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FakeHandoffMode {
    Exact,
    Rejected,
}

struct FakeHandoffs {
    mode: FakeHandoffMode,
    calls: AtomicUsize,
    requests: Mutex<Vec<AcquireGithubServerServiceHandoff>>,
    releases: Arc<AtomicUsize>,
}

impl FakeHandoffs {
    fn new(mode: FakeHandoffMode) -> Self {
        Self {
            mode,
            calls: AtomicUsize::new(0),
            requests: Mutex::new(Vec::new()),
            releases: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn requests(&self) -> Vec<AcquireGithubServerServiceHandoff> {
        self.requests.lock().expect("request lock").clone()
    }
}

impl fmt::Debug for FakeHandoffs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeHandoffs")
            .field("mode", &self.mode)
            .field("calls", &self.calls.load(Ordering::SeqCst))
            .field("requests", &"[REDACTED]")
            .field("releases", &self.releases.load(Ordering::SeqCst))
            .finish()
    }
}

#[async_trait]
impl GithubProviderCredentialHandoffIssuer for FakeHandoffs {
    async fn acquire(
        &self,
        request: AcquireGithubServerServiceHandoff,
    ) -> Result<GithubProviderCredentialHandoff, GithubProviderCredentialHandoffError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.requests
            .lock()
            .expect("request lock")
            .push(request.clone());
        if self.mode == FakeHandoffMode::Rejected {
            return Err(GithubProviderCredentialHandoffError::Rejected);
        }
        Ok(GithubProviderCredentialHandoff {
            selector: request.selector().clone(),
            consumer: request.consumer(),
            key: GithubServerServiceIssuanceKey::new(
                request.authority_id(),
                GithubServerServiceGeneration::new(1).expect("generation"),
            ),
            required_through: request.required_through(),
            acquired_at: request.observed_at(),
            usable_until: UnixMillis::new(request.required_through().get() + 10_000),
            token: SecretString::new("github-provider-adapter-test-token")
                .expect("fixture credential"),
            release: Box::new(FakeDeliveryRelease {
                calls: Arc::clone(&self.releases),
            }),
            drop_release_arm: None,
        })
    }
}

#[derive(Debug)]
struct FakeDeliveryRelease {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl GithubServerServiceCredentialRelease for FakeDeliveryRelease {
    async fn release(self: Box<Self>) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Debug)]
struct FakeClock(AtomicI64);

impl FakeClock {
    fn new(now: i64) -> Self {
        Self(AtomicI64::new(now))
    }

    fn set(&self, now: i64) {
        self.0.store(now, Ordering::SeqCst);
    }
}

impl GithubServerServiceCoordinatorClock for FakeClock {
    fn now(&self) -> UnixMillis {
        UnixMillis::new(self.0.load(Ordering::SeqCst))
    }
}

struct FakeExactRelease {
    attempts: Arc<AtomicUsize>,
    pending: Mutex<Option<Arc<dyn GithubProviderPendingHandoffRelease>>>,
}

impl fmt::Debug for FakeExactRelease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeExactRelease")
            .field("attempts", &self.attempts.load(Ordering::SeqCst))
            .field("pending", &"[EXACT PENDING RELEASE]")
            .finish()
    }
}

impl GithubProviderExactHandoffRelease for FakeExactRelease {
    fn freeze(&self) -> Arc<dyn GithubProviderPendingHandoffRelease> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        self.pending
            .lock()
            .expect("pending release lock")
            .take()
            .expect("one exact release freeze")
    }
}

#[derive(Debug)]
struct FakePendingRelease {
    attempts: Arc<AtomicUsize>,
    confirm_on: usize,
}

#[derive(Debug)]
struct GatedExactRelease {
    attempts: Arc<AtomicUsize>,
    finish: Arc<Semaphore>,
}

impl GithubProviderExactHandoffRelease for GatedExactRelease {
    fn freeze(&self) -> Arc<dyn GithubProviderPendingHandoffRelease> {
        Arc::new(GatedPendingRelease {
            attempts: Arc::clone(&self.attempts),
            finish: Arc::clone(&self.finish),
        })
    }
}

#[derive(Debug)]
struct GatedPendingRelease {
    attempts: Arc<AtomicUsize>,
    finish: Arc<Semaphore>,
}

#[async_trait]
impl GithubProviderPendingHandoffRelease for GatedPendingRelease {
    async fn replay(&self) -> bool {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        let permit = self.finish.acquire().await.expect("test gate remains open");
        permit.forget();
        true
    }
}

struct ConcreteIssuerReleaseRepository {
    handoff: Mutex<Option<GithubServerServiceCredentialHandoff>>,
    releases: Mutex<Vec<ReleaseGithubServerServiceHandoff>>,
    entered: Semaphore,
    finish: Semaphore,
}

impl ConcreteIssuerReleaseRepository {
    fn new(handoff: GithubServerServiceCredentialHandoff) -> Self {
        Self {
            handoff: Mutex::new(Some(handoff)),
            releases: Mutex::new(Vec::new()),
            entered: Semaphore::new(0),
            finish: Semaphore::new(0),
        }
    }

    async fn wait_until_release_entered(&self) {
        self.entered
            .acquire()
            .await
            .expect("concrete release entry semaphore")
            .forget();
    }

    fn release_requests(&self) -> Vec<ReleaseGithubServerServiceHandoff> {
        self.releases.lock().expect("release request lock").clone()
    }
}

#[async_trait]
impl GithubServerServiceCredentialRepository for ConcreteIssuerReleaseRepository {
    async fn claim_next_github_server_service_maintenance(
        &self,
        _request: ClaimNextGithubServerServiceMaintenance,
    ) -> Result<Option<GithubServerServiceMaintenanceOutcome>, GithubServerServiceStoreError> {
        unreachable!("maintenance is outside the concrete release test")
    }

    async fn begin_github_server_service_mint(
        &self,
        _request: BeginGithubServerServiceMint,
    ) -> Result<GithubServerServiceMintCutoffOutcome, GithubServerServiceStoreError> {
        unreachable!("mint is outside the concrete release test")
    }

    async fn finish_github_server_service_mint(
        &self,
        _request: &FinishGithubServerServiceMint,
    ) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError> {
        unreachable!("mint is outside the concrete release test")
    }

    async fn finish_github_server_service_revocation(
        &self,
        _request: FinishGithubServerServiceRevocation,
    ) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError> {
        unreachable!("revocation is outside the concrete release test")
    }

    async fn acquire_github_server_service_handoff(
        &self,
        _request: AcquireGithubServerServiceHandoff,
    ) -> Result<GithubServerServiceCredentialHandoff, GithubServerServiceStoreError> {
        Ok(self
            .handoff
            .lock()
            .expect("concrete handoff lock")
            .take()
            .expect("one concrete handoff"))
    }

    async fn release_github_server_service_handoff(
        &self,
        request: ReleaseGithubServerServiceHandoff,
    ) -> Result<(), GithubServerServiceStoreError> {
        self.releases
            .lock()
            .expect("release request lock")
            .push(request);
        self.entered.add_permits(1);
        self.finish
            .acquire()
            .await
            .expect("concrete release finish semaphore")
            .forget();
        Ok(())
    }

    async fn quarantine_github_server_service_credential(
        &self,
        _request: QuarantineGithubServerServiceCredential,
    ) -> Result<GithubServerServiceIssuanceReceipt, GithubServerServiceStoreError> {
        unreachable!("quarantine is outside the concrete release test")
    }
}

#[async_trait]
impl GithubProviderPendingHandoffRelease for FakePendingRelease {
    async fn replay(&self) -> bool {
        self.attempts.fetch_add(1, Ordering::SeqCst) + 1 >= self.confirm_on
    }
}

#[derive(Debug)]
struct SwitchablePendingRelease {
    attempts: Arc<AtomicUsize>,
    confirmed: Arc<AtomicBool>,
}

#[async_trait]
impl GithubProviderPendingHandoffRelease for SwitchablePendingRelease {
    async fn replay(&self) -> bool {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        self.confirmed.load(Ordering::SeqCst)
    }
}

fn tenant() -> TenantScope {
    TenantScope::from_authenticated_tenant_id("tenant").expect("tenant")
}

fn authority_id(value: u128) -> GithubServerServiceAuthorityId {
    GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(value)).expect("authority ID")
}

fn connection_id() -> ProviderConnectionId {
    ProviderConnectionId::from_uuid(Uuid::from_u128(0x20)).expect("connection ID")
}

fn repository_id() -> RepositoryId {
    github_provider_repository_id(
        &tenant(),
        GithubRepositoryId::new(13).expect("provider repository ID"),
    )
}

fn authority(scope: GithubServerServiceScope, id: u128) -> GithubServerServiceAuthorityIdentity {
    GithubServerServiceAuthorityIdentity::new(
        tenant(),
        authority_id(id),
        repository_id(),
        connection_id(),
        GithubInstallationId::new(11).expect("installation ID"),
        GithubServerServiceAppId::new(17).expect("App ID"),
        GithubRepositoryId::new(13).expect("provider repository ID"),
        GithubRepositoryName::new("automata-ci/automata").expect("repository name"),
        scope,
        GithubServerServiceAppClientId::new("Iv1.automata-test").expect("App client ID"),
        GithubServerServiceJwtIssuer::AppClientId,
        Sha256Digest::from_bytes([0x51; 32]),
        GithubServerServiceRevision::new(3).expect("App revision"),
        GithubServerServiceRevision::new(5).expect("policy revision"),
        Sha256Digest::from_bytes([0x61; 32]),
    )
    .expect("authority")
}

fn control_connection() -> ProviderConnectionManifest {
    let workspace =
        WorkspaceId::parse("11111111-1111-4111-8111-111111111111").expect("control workspace");
    let instance_id = ProviderInstanceId::from_uuid(Uuid::from_u128(0x21)).expect("instance ID");
    let provider_revision = ProviderConfigurationRevision::new(3).expect("provider revision");
    let policy = GithubConnectionPolicy::new(
        11,
        ScmRepositoryId::new("automata-ci/automata").expect("repository route"),
    )
    .expect("connection policy")
    .document()
    .expect("connection policy document");
    let configuration = ProviderConnectionConfiguration::new(
        workspace,
        ExternalRepositoryIdentity::new(
            instance_id,
            ExternalRepositoryId::new("13").expect("external repository ID"),
        ),
        provider_revision,
        Sha256Digest::from_bytes([0x41; 32]),
        Sha256Digest::from_bytes([0x42; 32]),
        RepositoryVisibility::Private,
        ProviderDefaultBranch::new("main").expect("default branch"),
        ProviderWorkflowSource::Directory(
            ProviderRepositoryPath::new(".ci/workflows").expect("workflow root"),
        ),
        ProviderRunnerPolicyBinding::new(
            ProviderSchemaVersion::new(1).expect("runner policy schema"),
            Sha256Digest::from_bytes([0x43; 32]),
        ),
        ProviderArchiveLimits::new(1_024, 8_192, 100, 1_024, 10, 1_024).expect("archive limits"),
        policy,
    );
    ProviderConnectionManifest::new(
        connection_id(),
        ProviderConnectionRevision::new(5).expect("connection revision"),
        ProviderLifecycleState::Active,
        configuration,
        UnixMillis::new(100),
        Some(UnixMillis::new(100)),
        None,
    )
    .expect("control connection")
}

fn control_authority(
    id: u128,
    scope: GithubServerServiceScope,
) -> GithubServerServiceAuthorityIdentity {
    let connection = control_connection();
    GithubServerServiceAuthorityIdentity::new(
        TenantScope::from_authenticated_tenant_id(
            connection.configuration().workspace_id().to_string(),
        )
        .expect("control tenant"),
        authority_id(id),
        repository_id(),
        connection.connection_id(),
        GithubInstallationId::new(11).expect("installation ID"),
        GithubServerServiceAppId::new(17).expect("App ID"),
        GithubRepositoryId::new(13).expect("provider repository ID"),
        GithubRepositoryName::new("automata-ci/automata").expect("repository name"),
        scope,
        GithubServerServiceAppClientId::new("Iv1.automata-test").expect("App client ID"),
        GithubServerServiceJwtIssuer::AppClientId,
        Sha256Digest::from_bytes([0x51; 32]),
        GithubServerServiceRevision::new(3).expect("App revision"),
        GithubServerServiceRevision::new(5).expect("policy revision"),
        Sha256Digest::from_bytes([0x61; 32]),
    )
    .expect("control authority")
}

fn schedule_manifest(visibility: GithubRepositoryVisibility) -> GithubProviderManifest {
    let policy = test_runtime_policy();
    let runner_policy_digest = policy.canonical_digest();
    let runner_policy_size = u64::try_from(
        policy
            .canonical_bytes()
            .expect("canonical runtime policy")
            .len(),
    )
    .expect("policy size");
    let runner_policy = GithubProviderRunnerPolicyObject::new(
        AdmissionObject::new(
            runner_policy_digest,
            ObjectKey::new(format!(
                "github/runner-policy/v1/{runner_policy_digest}.json"
            ))
            .expect("runner policy key"),
            runner_policy_size,
            GITHUB_PROVIDER_RUNNER_POLICY_MEDIA_TYPE,
        )
        .expect("runner policy object"),
    )
    .expect("runner policy descriptor");
    GithubProviderManifest::new_with_workflow_selection_and_git_ref(
        tenant(),
        connection_id(),
        GithubInstallationId::new(11).expect("installation ID"),
        GithubRepositoryId::new(13).expect("provider repository ID"),
        GithubRepositoryName::new("automata-ci/automata").expect("repository name"),
        visibility,
        GithubServerServiceAppId::new(17).expect("App ID"),
        GithubServerServiceAppClientId::new("Iv1.automata-test").expect("App client ID"),
        GithubServerServiceJwtIssuer::AppClientId,
        Sha256Digest::from_bytes([0x51; 32]),
        GithubServerServiceRevision::new(3).expect("App revision"),
        GithubProviderWebhookVerifierFingerprint::from_sha256(Sha256Digest::from_bytes([0x72; 32]))
            .expect("webhook verifier fingerprint"),
        GithubServerServiceRevision::new(3).expect("webhook revision"),
        GithubServerServiceRevision::new(5).expect("policy revision"),
        automata_ci_core::JobAuthorityProfile::Standard,
        runner_policy,
        WorkflowRuntimePolicyRevision::new(1).expect("runtime policy revision"),
        policy.digest(),
        GithubProviderWorkflowSelection::all_direct(),
        GithubProviderGitRef::main(),
        GithubCheckName::new("Automata CI").expect("Check name"),
        GithubProviderOrigins::github_dot_com(),
        GithubProviderManifestLimits::github_dot_com_ci(),
        GithubProviderManifestRevision::new(3).expect("manifest revision"),
    )
    .with_repository_owner_id(GithubRepositoryOwnerId::new(19).expect("owner ID"))
}

fn test_runtime_policy() -> WorkflowRuntimePolicy {
    let mapping = WorkflowRuntimePolicyMapping::new(
        RunnerLabel::new("ubuntu-latest").expect("runner label"),
        EnvironmentProfile::new(
            EnvironmentProfileId::new("automata.test/ubuntu-24.04").expect("profile ID"),
            Sha256Digest::from_bytes([0x22; 32]),
        ),
        OperatingSystem::Linux,
        Architecture::X86_64,
        WorkflowRunnerFeaturePolicy::new([]).expect("empty runner feature policy"),
        [],
    )
    .expect("runtime mapping");
    let defaults = JobResourceAllocation::new(
        ResourceCapacity::new(100, 256 * 1024 * 1024, 0, 0),
        ResourceCapacity::new(1_000, 1024 * 1024 * 1024, 0, 0),
    )
    .expect("resource defaults");
    let resources = JobResourcePolicy::new(
        defaults,
        ResourceCapacity::new(100, 128 * 1024 * 1024, 0, 0),
        ResourceCapacity::new(4_000, 8 * 1024 * 1024 * 1024, 0, 0),
    )
    .expect("resource policy");
    WorkflowRuntimePolicy::new(
        "/__w",
        [mapping],
        WorkflowPermissionPolicy::from_github_default(
            automata_ci_provider_github::ActionsDefaultWorkflowPermission::Read,
        )
        .expect("permission policy"),
        resources,
    )
    .expect("runtime policy")
}

fn observation_bootstrap(
    visibility: GithubRepositoryVisibility,
) -> BootstrapGithubProviderRepository {
    let manifest = schedule_manifest(visibility);
    let policy = test_runtime_policy();
    let policy = RegisterWorkflowRuntimePolicy::new(
        manifest.tenant().clone(),
        manifest.repository_id(),
        manifest.runtime_policy_revision(),
        policy,
        UnixMillis::new(OBSERVED_AT),
    )
    .expect("policy registration");
    let manifest = BootstrapGithubProviderManifest::new(manifest, UnixMillis::new(OBSERVED_AT))
        .expect("manifest bootstrap");
    BootstrapGithubProviderRepository::new(policy, manifest).expect("repository bootstrap")
}

fn schedule_discovery_claim() -> GithubScheduleDiscoveryClaim {
    GithubScheduleDiscoveryClaim::from_durable_parts(
        GithubScheduleRegistryId::from_uuid(Uuid::from_u128(0x7a)).expect("schedule registry ID"),
        GithubScheduleWorkerId::from_uuid(Uuid::from_u128(0x7b)).expect("schedule worker ID"),
        GithubScheduleClaimFence::new(9).expect("schedule fence"),
        UnixMillis::new(OBSERVED_AT),
        UnixMillis::new(OBSERVED_AT + 300_000),
    )
    .expect("schedule discovery claim")
}

fn concrete_release_codec() -> Arc<EnvelopeCodec> {
    let key = LocalKeyMaterial::new(
        KeyId::new("product-release-test-key-v1").expect("key ID"),
        SecretBytes::new(vec![0x5a; 32]).expect("key material"),
    )
    .expect("local key material");
    let keys = LocalAes256GcmKeyring::new(key, Vec::new(), Vec::new()).expect("local keyring");
    Arc::new(EnvelopeCodec::new(Arc::new(keys)))
}

async fn concrete_release_handoff(
    codec: &Arc<EnvelopeCodec>,
    identity: GithubServerServiceAuthorityIdentity,
    request: &AcquireGithubServerServiceHandoff,
) -> GithubServerServiceCredentialHandoff {
    const REQUESTED_AT: i64 = 1_000_000;
    const REQUEST_DEADLINE: i64 = 1_120_000;
    const PROVIDER_EXPIRES_AT: i64 = 4_600_000;
    const TOKEN: &[u8] = b"ghs_product-release-test-token";
    const FRAME_DOMAIN: &[u8] = b"automata-ci/github-server-service-installation-token/v1\0";

    let mut frame =
        Vec::with_capacity(FRAME_DOMAIN.len() + std::mem::size_of::<u32>() + TOKEN.len());
    frame.extend_from_slice(FRAME_DOMAIN);
    frame.extend_from_slice(
        &u32::try_from(TOKEN.len())
            .expect("bounded token")
            .to_be_bytes(),
    );
    frame.extend_from_slice(TOKEN);
    let generation = GithubServerServiceGeneration::new(1).expect("generation");
    let metadata = GithubServerServiceEnvelopeMetadata::new(
        identity.clone(),
        generation,
        UnixMillis::new(REQUESTED_AT),
        UnixMillis::new(REQUEST_DEADLINE),
        UnixMillis::new(PROVIDER_EXPIRES_AT),
        u64::try_from(frame.len()).expect("frame length"),
        Sha256Digest::from_bytes(Sha256::digest(&frame).into()),
    )
    .expect("envelope metadata");
    let wrapping_context = identity
        .wrapping_encryption_context(generation)
        .expect("wrapping context");
    let payload_context = metadata.encryption_context().expect("payload context");
    let envelope = codec
        .prepare(&wrapping_context)
        .await
        .expect("prepared envelope")
        .seal_prepared(
            &payload_context,
            SecretBytes::new(frame).expect("token frame"),
        );
    let protected = ProtectedGithubServerServiceCredential::new(metadata.clone(), envelope)
        .expect("protected credential");
    let conservative_expiry = REQUEST_DEADLINE
        + GITHUB_SERVICE_TOKEN_LIFETIME_MILLIS
        + 60_000
        + GITHUB_SERVICE_SAFE_ERASE_SKEW_MILLIS;
    let receipt = GithubServerServiceIssuanceReceipt::from_durable_parts(
        GithubServerServiceIssuanceKey::new(identity.authority_id(), generation),
        GithubServerServiceIssuanceState::Ready,
        1,
        0,
        UnixMillis::new(REQUESTED_AT),
        UnixMillis::new(REQUEST_DEADLINE),
        UnixMillis::new(conservative_expiry),
        Some(UnixMillis::new(PROVIDER_EXPIRES_AT)),
        metadata.safe_erase_after(),
        Some(UnixMillis::new(1_005_000)),
        UnixMillis::new(1_005_000),
    )
    .expect("ready receipt");
    GithubServerServiceCredentialHandoff::from_durable_parts(
        request.proposed_handoff_id(),
        request.consumer(),
        identity,
        receipt,
        request.required_through(),
        UnixMillis::new(1_010_000),
        request.observed_at(),
        protected,
    )
    .expect("concrete handoff")
}

fn consumer(action: GithubServerServiceAction) -> GithubServerServiceConsumerClaim {
    GithubServerServiceConsumerClaim::new(
        GithubServerServiceConsumerId::from_uuid(Uuid::from_u128(0x50)).expect("consumer ID"),
        GithubServerServiceWorkerId::from_uuid(Uuid::from_u128(0x51)).expect("worker ID"),
        GithubServerServiceClaimFence::new(7).expect("claim fence"),
        action,
        GithubServerServiceRevision::new(2).expect("consumer revision"),
    )
}

fn adapters(
    handoffs: Arc<FakeHandoffs>,
    authorities: &[GithubServerServiceAuthorityIdentity],
) -> GithubProviderCredentialAdapters {
    GithubProviderCredentialAdapters::with_handoffs(handoffs, authorities).expect("adapters")
}

#[test]
fn registry_is_bounded_unique_and_implements_live_provider_ports() {
    fn assert_ports<T: ControlCredentialProvider + GithubScheduleSourceCredentialProvider>() {}
    assert_ports::<GithubProviderCredentialAdapters>();

    let checks = authority(GithubServerServiceScope::ChecksWrite, 0x60);
    let private = authority(GithubServerServiceScope::RepositoryContentsRead, 0x61);
    let fake = Arc::new(FakeHandoffs::new(FakeHandoffMode::Rejected));
    let configured = adapters(Arc::clone(&fake), &[checks.clone(), private]);
    assert_eq!(configured.authorities.len(), 2);
    assert!(matches!(
        GithubProviderCredentialAdapters::with_handoffs(fake.clone(), &[]),
        Err(GithubProviderCredentialAdapterConfigurationError::InvalidAuthorityRegistry)
    ));
    assert!(matches!(
        GithubProviderCredentialAdapters::with_handoffs(fake, &[checks.clone(), checks]),
        Err(GithubProviderCredentialAdapterConfigurationError::InvalidAuthorityRegistry)
    ));
}

#[tokio::test]
async fn common_credentials_preserve_exact_github_handoffs_and_release() {
    for (operation, action, scope, authority_id) in [
        (
            ProviderControlOperation::RepositoryRead,
            GithubServerServiceAction::FetchRepositoryRevision,
            GithubServerServiceScope::RepositoryContentsRead,
            0x62,
        ),
        (
            ProviderControlOperation::CommitChangedFilesRead,
            GithubServerServiceAction::FetchRepositoryChangedFiles,
            GithubServerServiceScope::RepositoryContentsRead,
            0x63,
        ),
        (
            ProviderControlOperation::MergeRequestChangedFilesRead,
            GithubServerServiceAction::FetchPullRequestFiles,
            GithubServerServiceScope::PullRequestsRead,
            0x64,
        ),
        (
            ProviderControlOperation::ResultCreate,
            GithubServerServiceAction::CreateCheckRun,
            GithubServerServiceScope::ChecksWrite,
            0x65,
        ),
    ] {
        assert_common_control_handoff(operation, action, scope, authority_id).await;
    }
}

async fn assert_common_control_handoff(
    operation: ProviderControlOperation,
    action: GithubServerServiceAction,
    scope: GithubServerServiceScope,
    authority_id: u128,
) {
    let handoffs = Arc::new(FakeHandoffs::new(FakeHandoffMode::Exact));
    let authority = control_authority(authority_id, scope);
    let mut adapters = adapters(Arc::clone(&handoffs), std::slice::from_ref(&authority));
    adapters.observation_clock = Some(Arc::new(FakeClock::new(1_200)));
    let claim = ControlCredentialClaim::new(
        ProviderControlCredentialId::from_uuid(Uuid::from_u128(0x70)).expect("credential ID"),
        ProviderControlCredentialWorkerId::from_uuid(Uuid::from_u128(0x71))
            .expect("credential worker ID"),
        7,
        9,
        UnixMillis::new(1_500),
    )
    .expect("control claim");
    let operations = ProviderControlOperationSet::new([operation]).expect("control operation");
    let request = ControlCredentialRequest::new(
        claim,
        &control_connection(),
        operations,
        UnixMillis::new(1_000),
        1_000,
    )
    .expect("control request");

    let credential = ControlCredentialProvider::acquire(&adapters, &request)
        .await
        .expect("credential");
    assert_eq!(credential.request_digest(), request.digest());
    assert!(credential.permits(operation));
    assert_eq!(
        credential.expose_secret(),
        b"github-provider-adapter-test-token"
    );
    let requests = handoffs.requests();
    let [handoff] = requests.as_slice() else {
        panic!("one exact handoff must be acquired");
    };
    assert_eq!(handoff.selector().authority_id(), authority.authority_id());
    assert_eq!(handoff.observed_at(), UnixMillis::new(1_200));
    assert_eq!(handoff.required_through(), UnixMillis::new(2_200));
    assert_eq!(
        handoff.consumer(),
        GithubServerServiceConsumerClaim::new(
            GithubServerServiceConsumerId::from_uuid(claim.credential_id().as_uuid())
                .expect("consumer ID"),
            GithubServerServiceWorkerId::from_uuid(claim.worker_id().as_uuid()).expect("worker ID"),
            GithubServerServiceClaimFence::new(claim.fence()).expect("claim fence"),
            action,
            GithubServerServiceRevision::new(claim.revision()).expect("consumer revision"),
        )
    );
    credential.release().await;
    assert_eq!(handoffs.releases.load(Ordering::SeqCst), 1);
}

#[test]
fn workflow_permission_observation_is_manifest_and_authority_bound() {
    let workflow_permissions = authority(GithubServerServiceScope::WorkflowPermissionsRead, 0x69);
    let bootstrap = observation_bootstrap(GithubRepositoryVisibility::Public);
    let manifest = bootstrap.manifest().manifest();
    assert!(workflow_permission_identity_matches(
        &workflow_permissions,
        manifest
    ));

    let owner =
        GithubServerServiceWorkerId::from_uuid(Uuid::from_u128(0x6b)).expect("observation owner");
    let candidate = automata_ci_store::GithubWorkflowPermissionObservationCandidate::new(
        &bootstrap,
        &workflow_permissions,
        GithubServerServiceConsumerId::from_uuid(Uuid::from_u128(0x6c)).expect("observation ID"),
        owner,
        UnixMillis::new(OBSERVED_AT),
    )
    .expect("manifest-bound candidate");
    let consumer = candidate.consumer();
    assert_eq!(consumer.consumer_id(), candidate.observation_id());
    assert_eq!(consumer.owner(), owner);
    assert_eq!(consumer.fence().get(), manifest.revision().get());
    assert_eq!(
        consumer.action(),
        GithubServerServiceAction::ObserveWorkflowPermissionDefaults
    );
    assert_eq!(
        consumer.revision().get(),
        manifest.runtime_policy_revision().get()
    );

    let release = ReleaseGithubServerServiceHandoff::new(
        candidate.authority_selector().clone(),
        GithubServerServiceHandoffId::from_uuid(Uuid::from_u128(0x6d)).expect("handoff ID"),
        candidate.consumer(),
        UnixMillis::new(OBSERVED_AT + 20),
    )
    .expect("release");
    let read = automata_ci_store::GithubWorkflowPermissionDefaultsObservation::new(
        &bootstrap,
        candidate.clone(),
        &release,
        GithubServerServiceGeneration::new(1).expect("generation"),
        automata_ci_provider_github::ActionsDefaultWorkflowPermission::Read,
        false,
        UnixMillis::new(OBSERVED_AT + 10),
    )
    .expect("exact observation");
    let review_enabled = automata_ci_store::GithubWorkflowPermissionDefaultsObservation::new(
        &bootstrap,
        candidate.clone(),
        &release,
        GithubServerServiceGeneration::new(1).expect("generation"),
        automata_ci_provider_github::ActionsDefaultWorkflowPermission::Read,
        true,
        UnixMillis::new(OBSERVED_AT + 10),
    )
    .expect("changed effective setting");
    assert_eq!(read.candidate().manifest_digest(), manifest.digest());
    assert_eq!(
        read.candidate().runtime_policy_revision(),
        manifest.runtime_policy_revision()
    );
    assert_eq!(
        read.candidate().authority_selector().authority_id(),
        workflow_permissions.authority_id()
    );
    assert_ne!(read.digest(), review_enabled.digest());

    let second_candidate = automata_ci_store::GithubWorkflowPermissionObservationCandidate::new(
        &bootstrap,
        &workflow_permissions,
        GithubServerServiceConsumerId::from_uuid(Uuid::from_u128(0x6e))
            .expect("second observation ID"),
        owner,
        UnixMillis::new(OBSERVED_AT),
    )
    .expect("second candidate");
    assert_ne!(
        candidate.observation_id(),
        second_candidate.observation_id()
    );
    assert_ne!(candidate.digest(), second_candidate.digest());

    let checks = authority(GithubServerServiceScope::ChecksWrite, 0x6a);
    assert!(!workflow_permission_identity_matches(&checks, manifest));
    assert!(
        automata_ci_store::GithubWorkflowPermissionObservationCandidate::new(
            &bootstrap,
            &checks,
            GithubServerServiceConsumerId::from_uuid(Uuid::from_u128(0x6f))
                .expect("wrong-scope observation ID"),
            owner,
            UnixMillis::new(OBSERVED_AT),
        )
        .is_err()
    );
}

#[tokio::test]
async fn scheduled_discovery_uses_its_own_oidc_consumer_action_for_every_visibility() {
    let contents = authority(GithubServerServiceScope::RepositoryContentsRead, 0x67);
    let fake = Arc::new(FakeHandoffs::new(FakeHandoffMode::Rejected));
    let adapters = adapters(Arc::clone(&fake), std::slice::from_ref(&contents));
    let selector = GithubServerServiceAuthoritySelector::from_identity(&contents);
    for visibility in [
        GithubRepositoryVisibility::Public,
        GithubRepositoryVisibility::Private,
    ] {
        let manifest = schedule_manifest(visibility);
        let request = GithubScheduleSourceCredentialRequest::new(
            schedule_discovery_claim(),
            &manifest,
            &selector,
            UnixMillis::new(OBSERVED_AT),
        )
        .expect("scheduled discovery request");
        assert_eq!(
            adapters
                .acquire_schedule_source(request)
                .await
                .expect_err("the fake authority rejects after recording the exact request"),
            GithubScheduleSourceCredentialProviderError::Rejected
        );
    }
    let requests = fake.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().all(|request| {
        request.consumer().action() == GithubServerServiceAction::DiscoverRepositorySchedules
            && request.consumer().action() != GithubServerServiceAction::FetchRepositoryRevision
    }));
}

#[tokio::test]
async fn unrepresentable_dispatch_request_releases_acquired_handoff() {
    let private = authority(GithubServerServiceScope::RepositoryContentsRead, 0x661);
    let fake = Arc::new(FakeHandoffs::new(FakeHandoffMode::Exact));
    let selector = GithubServerServiceAuthoritySelector::from_identity(&private);
    let consumer = consumer(GithubServerServiceAction::ResolveWorkflowDispatchSource);
    let request = acquire_request(
        selector,
        consumer,
        UnixMillis::new(OBSERVED_AT),
        UnixMillis::new(REQUIRED_THROUGH),
    )
    .expect("valid workflow dispatch handoff request");
    let handoff = fake.acquire(request).await.expect("fake handoff");

    let result =
        validate_workflow_dispatch_source_repository(handoff, None, "automata-ci/automata").await;
    assert!(matches!(
        result,
        Err(GithubWorkflowDispatchSourceCredentialError::Inconsistent)
    ));
    assert_eq!(fake.releases.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn pending_release_is_replayed_exactly_and_drain_waits_for_confirmation() {
    let clock = Arc::new(FakeClock::new(OBSERVED_AT));
    let supervisor = Arc::new(
        GithubProviderCredentialReleaseSupervisor::new(
            clock,
            Handle::current(),
            1,
            Duration::from_millis(1),
        )
        .expect("release supervisor"),
    );
    let release_attempts = Arc::new(AtomicUsize::new(0));
    let replay_attempts = Arc::new(AtomicUsize::new(0));
    let reservation = supervisor.try_reserve().expect("release reservation");
    let initial_attempt = supervisor.supervise(
        reservation,
        Box::new(FakeExactRelease {
            attempts: Arc::clone(&release_attempts),
            pending: Mutex::new(Some(Arc::new(FakePendingRelease {
                attempts: Arc::clone(&replay_attempts),
                confirm_on: 2,
            }))),
        }),
        UnixMillis::new(REQUIRED_THROUGH),
    );
    initial_attempt.await.expect("initial release classified");

    tokio::time::timeout(Duration::from_secs(1), supervisor.wait_for_idle())
        .await
        .expect("release drain completes");
    assert_eq!(release_attempts.load(Ordering::SeqCst), 1);
    assert_eq!(replay_attempts.load(Ordering::SeqCst), 2);
    assert_eq!(supervisor.pending_release_count(), 0);
    assert_eq!(supervisor.available_capacity(), 1);
    assert_eq!(supervisor.expired_unconfirmed_release_count(), 0);
}

#[tokio::test]
async fn delivery_release_awaits_the_first_exact_attempt_without_owning_the_task() {
    let supervisor = Arc::new(
        GithubProviderCredentialReleaseSupervisor::new(
            Arc::new(FakeClock::new(OBSERVED_AT)),
            Handle::current(),
            1,
            Duration::from_millis(1),
        )
        .expect("release supervisor"),
    );
    let attempts = Arc::new(AtomicUsize::new(0));
    let finish = Arc::new(Semaphore::new(0));
    let capability: Box<dyn GithubServerServiceCredentialRelease> =
        Box::new(SupervisedCredentialRelease {
            supervisor: Arc::clone(&supervisor),
            reservation: Some(supervisor.try_reserve().expect("release reservation")),
            operation: Some(Box::new(GatedExactRelease {
                attempts: Arc::clone(&attempts),
                finish: Arc::clone(&finish),
            })),
            required_through: UnixMillis::new(REQUIRED_THROUGH),
            drop_release_armed: Arc::new(AtomicBool::new(true)),
        });
    let release = tokio::spawn(async move { capability.release().await });
    while attempts.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    assert!(!release.is_finished());
    finish.add_permits(1);
    release.await.expect("delivery release task");
    supervisor.wait_for_idle().await;
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn release_watchdog_task_loss_retains_exact_custody_and_never_false_drains() {
    let supervisor = GithubProviderCredentialReleaseSupervisor::new(
        Arc::new(FakeClock::new(OBSERVED_AT)),
        Handle::current(),
        1,
        Duration::from_millis(1),
    )
    .expect("release supervisor");
    let attempts = Arc::new(AtomicUsize::new(0));
    let finish = Arc::new(Semaphore::new(0));
    let reservation = supervisor.try_reserve().expect("release reservation");
    let initial_attempt = supervisor.supervise(
        reservation,
        Box::new(GatedExactRelease {
            attempts: Arc::clone(&attempts),
            finish: Arc::clone(&finish),
        }),
        UnixMillis::new(REQUIRED_THROUGH),
    );
    while attempts.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }

    assert!(supervisor.abort_pending_task(), "release watchdog exists");
    assert!(
        initial_attempt.await.is_err(),
        "watchdog loss must be visible before initial classification"
    );
    assert!(!supervisor.drain(Duration::from_millis(5)).await);
    assert_eq!(supervisor.available_capacity(), 0);
    assert_eq!(supervisor.pending_release_count(), 1);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    for _ in 0..32 {
        supervisor.redrive_retained();
        tokio::task::yield_now().await;
    }
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        2,
        "one active release driver must serialize concurrent recovery attempts"
    );
    finish.add_permits(1);
    assert!(supervisor.drain(Duration::from_secs(1)).await);
    assert_eq!(supervisor.available_capacity(), 1);
    for _ in 0..32 {
        supervisor.redrive_retained();
        tokio::task::yield_now().await;
    }
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        2,
        "confirmed release custody must never restart after removal"
    );
}

#[tokio::test]
async fn removed_release_custody_rejects_its_exact_stale_driver() {
    let supervisor = GithubProviderCredentialReleaseSupervisor::new(
        Arc::new(FakeClock::new(OBSERVED_AT)),
        Handle::current(),
        1,
        Duration::from_millis(1),
    )
    .expect("release supervisor");
    let attempts = Arc::new(AtomicUsize::new(0));
    let finish = Arc::new(Semaphore::new(0));
    let reservation = supervisor.try_reserve().expect("release reservation");
    let initial_attempt = supervisor.supervise(
        reservation,
        Box::new(GatedExactRelease {
            attempts: Arc::clone(&attempts),
            finish: Arc::clone(&finish),
        }),
        UnixMillis::new(REQUIRED_THROUGH),
    );

    while attempts.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    let stale_custody = supervisor
        .custody
        .lock()
        .expect("provider credential release custody lock")
        .first()
        .cloned()
        .expect("release custody retained before confirmation");
    finish.add_permits(1);
    initial_attempt.await.expect("confirmed exact release");
    tokio::time::timeout(Duration::from_secs(1), async {
        while !stale_custody.removed.load(Ordering::Acquire)
            || stale_custody.driver_active.load(Ordering::Acquire)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("release custody removed with no active driver");

    let confirmed_calls = attempts.load(Ordering::SeqCst);
    assert_eq!(confirmed_calls, 1);
    assert!(!supervisor.start_driver(&stale_custody, None));
    tokio::task::yield_now().await;
    assert_eq!(attempts.load(Ordering::SeqCst), confirmed_calls);
    assert!(!supervisor.drain(Duration::from_millis(5)).await);
    assert_eq!(supervisor.available_capacity(), 0);

    drop(stale_custody);
    assert!(supervisor.drain(Duration::from_secs(1)).await);
    assert_eq!(supervisor.pending_release_count(), 0);
    assert_eq!(supervisor.available_capacity(), 1);
    assert!(supervisor.try_reserve().is_some());
}

#[tokio::test]
async fn concrete_issuer_release_clamps_negative_clock_and_replays_exactly() {
    let codec = concrete_release_codec();
    let identity = authority(GithubServerServiceScope::RepositoryContentsRead, 0x6f0);
    let request = AcquireGithubServerServiceHandoff::new(
        GithubServerServiceAuthoritySelector::from_identity(&identity),
        GithubServerServiceHandoffId::from_uuid(Uuid::from_u128(0x6f1)).expect("handoff ID"),
        consumer(GithubServerServiceAction::FetchRepositoryRevision),
        UnixMillis::new(1_020_000),
        UnixMillis::new(2_000_000),
    )
    .expect("acquire request");
    let handoff = concrete_release_handoff(&codec, identity, &request).await;
    let repository = Arc::new(ConcreteIssuerReleaseRepository::new(handoff));
    let repository_port: Arc<dyn GithubServerServiceCredentialRepository> = repository.clone();
    let clock = Arc::new(FakeClock::new(-1));
    let clock_port: Arc<dyn GithubServerServiceCoordinatorClock> = clock.clone();
    let issuer = Arc::new(GithubServerServiceCredentialIssuer::new(
        repository_port.clone(),
        codec,
        clock_port.clone(),
    ));
    let credential = issuer.acquire(request).await.expect("concrete credential");
    let (secret, binding) = credential.into_secret_and_binding();
    drop(secret);
    let required_through = binding.required_through();
    let supervisor = Arc::new(
        GithubProviderCredentialReleaseSupervisor::new(
            clock_port,
            Handle::current(),
            1,
            Duration::from_millis(1),
        )
        .expect("release supervisor"),
    );
    let reservation = supervisor.try_reserve().expect("release reservation");
    let initial_attempt = supervisor.supervise(
        reservation,
        Box::new(IssuerHandoffRelease {
            issuer,
            repository: repository_port,
            binding,
        }),
        required_through,
    );

    repository.wait_until_release_entered().await;
    assert!(supervisor.abort_pending_task(), "release driver exists");
    assert!(
        initial_attempt.await.is_err(),
        "outer task loss is visible to the first observer"
    );
    clock.set(-2);
    assert!(!supervisor.drain(Duration::from_millis(5)).await);
    repository.wait_until_release_entered().await;
    let requests = repository.release_requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0], requests[1]);
    assert_eq!(requests[0].released_at(), UnixMillis::new(1_020_000));

    let hammer_started = CancellationToken::new();
    let stop_hammer = CancellationToken::new();
    let hammer = tokio::spawn({
        let supervisor = Arc::clone(&supervisor);
        let hammer_started = hammer_started.clone();
        let stop_hammer = stop_hammer.clone();
        async move {
            hammer_started.cancel();
            while !stop_hammer.is_cancelled() {
                supervisor.redrive_retained();
                tokio::task::yield_now().await;
            }
        }
    });
    hammer_started.cancelled().await;
    repository.finish.add_permits(1);
    assert!(supervisor.drain(Duration::from_secs(1)).await);
    stop_hammer.cancel();
    hammer.await.expect("redrive hammer");
    assert_eq!(repository.release_requests(), requests);
    assert_eq!(supervisor.pending_release_count(), 0);
    assert_eq!(supervisor.available_capacity(), 1);
    drop(
        supervisor
            .try_reserve()
            .expect("confirmed exact erasure returns capacity for reuse"),
    );
}

#[tokio::test]
async fn dropped_delivery_release_capability_keeps_exact_binding_supervised() {
    let supervisor = Arc::new(
        GithubProviderCredentialReleaseSupervisor::new(
            Arc::new(FakeClock::new(OBSERVED_AT)),
            Handle::current(),
            1,
            Duration::from_millis(1),
        )
        .expect("release supervisor"),
    );
    let attempts = Arc::new(AtomicUsize::new(0));
    let capability: Box<dyn GithubServerServiceCredentialRelease> =
        Box::new(SupervisedCredentialRelease {
            supervisor: Arc::clone(&supervisor),
            reservation: Some(supervisor.try_reserve().expect("release reservation")),
            operation: Some(Box::new(FakeExactRelease {
                attempts: Arc::clone(&attempts),
                pending: Mutex::new(Some(Arc::new(FakePendingRelease {
                    attempts: Arc::new(AtomicUsize::new(0)),
                    confirm_on: 1,
                }))),
            })),
            required_through: UnixMillis::new(REQUIRED_THROUGH),
            drop_release_armed: Arc::new(AtomicBool::new(true)),
        });
    drop(capability);
    supervisor.wait_for_idle().await;
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn unconfirmed_release_remains_observable_when_its_horizon_closes() {
    let clock = Arc::new(FakeClock::new(OBSERVED_AT));
    let supervisor = Arc::new(
        GithubProviderCredentialReleaseSupervisor::new(
            Arc::clone(&clock) as Arc<dyn GithubServerServiceCoordinatorClock>,
            Handle::current(),
            1,
            Duration::from_millis(1),
        )
        .expect("release supervisor"),
    );
    let replay_attempts = Arc::new(AtomicUsize::new(0));
    let confirmed = Arc::new(AtomicBool::new(false));
    let reservation = supervisor.try_reserve().expect("release reservation");
    let initial_attempt = supervisor.supervise(
        reservation,
        Box::new(FakeExactRelease {
            attempts: Arc::new(AtomicUsize::new(0)),
            pending: Mutex::new(Some(Arc::new(SwitchablePendingRelease {
                attempts: Arc::clone(&replay_attempts),
                confirmed: Arc::clone(&confirmed),
            }))),
        }),
        UnixMillis::new(REQUIRED_THROUGH),
    );
    initial_attempt.await.expect("initial release classified");
    while supervisor.pending_release_count() == 0 {
        tokio::task::yield_now().await;
    }
    clock.set(REQUIRED_THROUGH);
    tokio::time::timeout(Duration::from_secs(1), async {
        while supervisor.expired_unconfirmed_release_count() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("expired release remains observable");
    assert!(!supervisor.drain(Duration::from_millis(5)).await);
    assert_eq!(supervisor.pending_release_count(), 1);
    assert_eq!(supervisor.expired_unconfirmed_release_count(), 1);
    assert_eq!(supervisor.available_capacity(), 0);
    confirmed.store(true, Ordering::SeqCst);
    assert!(supervisor.drain(Duration::from_secs(1)).await);
    assert_eq!(supervisor.pending_release_count(), 0);
    assert_eq!(supervisor.expired_unconfirmed_release_count(), 0);
    assert_eq!(supervisor.available_capacity(), 1);
}

#[tokio::test]
async fn release_supervision_configuration_is_hard_bounded() {
    let runtime = Handle::current();
    let clock: Arc<dyn GithubServerServiceCoordinatorClock> = Arc::new(FakeClock::new(OBSERVED_AT));
    assert!(matches!(
        GithubProviderCredentialReleaseSupervisor::new(
            Arc::clone(&clock),
            runtime.clone(),
            0,
            Duration::from_millis(1),
        ),
        Err(GithubProviderCredentialAdapterConfigurationError::InvalidReleaseCapacity)
    ));
    assert!(matches!(
        GithubProviderCredentialReleaseSupervisor::new(clock, runtime, 1, Duration::ZERO,),
        Err(GithubProviderCredentialAdapterConfigurationError::InvalidReleaseRetryInterval)
    ));
}
