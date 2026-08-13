use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use automata_ci_credential_github::GithubServerServiceMintCutoffOutcome;
use automata_ci_key_management::{
    EnvelopeCodec, KeyId, LocalAes256GcmKeyring, LocalKeyMaterial, SecretBytes,
};
use automata_ci_store::{
    AdmissionObject, BeginGithubServerServiceMint, ClaimNextGithubServerServiceMaintenance,
    FinishGithubServerServiceMint, FinishGithubServerServiceRevocation,
    GITHUB_PROVIDER_RUNNER_POLICY_MEDIA_TYPE, GITHUB_SERVICE_SAFE_ERASE_SKEW_MILLIS,
    GITHUB_SERVICE_TOKEN_LIFETIME_MILLIS, GithubCheckAppId, GithubCheckHeadSha, GithubCheckName,
    GithubCheckSubjectIdentity, GithubCheckSubjectKey, GithubProviderGitRef,
    GithubProviderManifest, GithubProviderManifestLimits, GithubProviderManifestRevision,
    GithubProviderOrigins, GithubProviderRunnerPolicyObject,
    GithubProviderWebhookVerifierFingerprint, GithubProviderWorkflowSelection,
    GithubRepositoryName, GithubScheduleClaimFence, GithubScheduleDiscoveryClaim,
    GithubScheduleRegistryId, GithubScheduleWorkerId, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceAuthorityId, GithubServerServiceAuthorityIdentity,
    GithubServerServiceAuthoritySelector, GithubServerServiceClaimFence,
    GithubServerServiceConsumerClaim, GithubServerServiceConsumerId,
    GithubServerServiceCredentialHandoff, GithubServerServiceEnvelopeMetadata,
    GithubServerServiceGeneration, GithubServerServiceHandoffId, GithubServerServiceIssuanceKey,
    GithubServerServiceIssuanceReceipt, GithubServerServiceIssuanceState,
    GithubServerServiceJwtIssuer, GithubServerServiceMaintenanceOutcome,
    GithubServerServiceRevision, GithubServerServiceScope, GithubServerServiceStoreError,
    GithubServerServiceWorkerId, ObjectKey, ProtectedGithubServerServiceCredential,
    ProviderConnectionId, ProviderDeliveryId, ProviderDeliveryIdentity, ProviderInstallationId,
    ProviderRepositoryCoordinates, ProviderRepositoryId, ProviderRepositoryOwnerId,
    ProviderRepositoryVisibility, QuarantineGithubServerServiceCredential,
    ReleaseGithubServerServiceHandoff, RepositoryId, Sha256Digest, TenantScope,
    WorkflowRuntimePolicyRevision, github_provider_repository_id,
};
use sha2::{Digest as _, Sha256};
use tokio_util::sync::CancellationToken;

use super::*;

const OBSERVED_AT: i64 = 1_000;
const REQUIRED_THROUGH: i64 = 2_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FakeHandoffMode {
    Exact,
    Rejected,
    WrongSelector,
    WrongConsumer,
    WrongHorizon,
    WrongAcquiredAt,
    WrongIssuanceAuthority,
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
        let selector = if self.mode == FakeHandoffMode::WrongSelector {
            GithubServerServiceAuthoritySelector::from_durable_parts(
                request.selector().tenant().clone(),
                authority_id(0xff),
                request.selector().identity_digest(),
                request.selector().app_configuration_revision(),
                request.selector().policy_revision(),
            )
        } else {
            request.selector().clone()
        };
        let requested_consumer = request.consumer();
        let consumer = if self.mode == FakeHandoffMode::WrongConsumer {
            GithubServerServiceConsumerClaim::new(
                requested_consumer.consumer_id(),
                requested_consumer.owner(),
                requested_consumer.fence(),
                requested_consumer.action(),
                GithubServerServiceRevision::new(requested_consumer.revision().get() + 1)
                    .expect("different revision"),
            )
        } else {
            requested_consumer
        };
        let key_authority = if self.mode == FakeHandoffMode::WrongIssuanceAuthority {
            authority_id(0xfe)
        } else {
            request.authority_id()
        };
        Ok(GithubProviderCredentialHandoff {
            selector,
            handoff_id: GithubServerServiceHandoffId::from_uuid(Uuid::from_u128(0x70))
                .expect("handoff ID"),
            consumer,
            key: GithubServerServiceIssuanceKey::new(
                key_authority,
                GithubServerServiceGeneration::new(1).expect("generation"),
            ),
            required_through: if self.mode == FakeHandoffMode::WrongHorizon {
                UnixMillis::new(request.required_through().get() + 1)
            } else {
                request.required_through()
            },
            acquired_at: if self.mode == FakeHandoffMode::WrongAcquiredAt {
                UnixMillis::new(request.observed_at().get() + 1)
            } else {
                request.observed_at()
            },
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

struct FakeAuthorityLookup {
    descriptors: Mutex<
        BTreeMap<
            GithubServerServiceAuthorityId,
            automata_ci_store::GithubServerServiceAuthorityDescriptor,
        >,
    >,
    calls: AtomicUsize,
}

impl FakeAuthorityLookup {
    fn new(
        descriptors: impl IntoIterator<Item = automata_ci_store::GithubServerServiceAuthorityDescriptor>,
    ) -> Self {
        Self {
            descriptors: Mutex::new(
                descriptors
                    .into_iter()
                    .map(|descriptor| (descriptor.identity().authority_id(), descriptor))
                    .collect(),
            ),
            calls: AtomicUsize::new(0),
        }
    }
}

impl fmt::Debug for FakeAuthorityLookup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeAuthorityLookup")
            .field("descriptors", &"[AUTHORITY DESCRIPTORS]")
            .field("calls", &self.calls.load(Ordering::SeqCst))
            .finish()
    }
}

#[async_trait]
impl GithubProviderAuthorityLookup for FakeAuthorityLookup {
    async fn inspect(
        &self,
        selector: &GithubServerServiceAuthoritySelector,
    ) -> Result<
        automata_ci_store::GithubServerServiceAuthorityDescriptor,
        GithubServerServiceStoreError,
    > {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.descriptors
            .lock()
            .expect("descriptor lock")
            .get(&selector.authority_id())
            .cloned()
            .ok_or(GithubServerServiceStoreError::NotFound)
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
        ProviderRepositoryId::new(13).expect("provider repository ID"),
    )
}

fn authority(scope: GithubServerServiceScope, id: u128) -> GithubServerServiceAuthorityIdentity {
    GithubServerServiceAuthorityIdentity::new(
        tenant(),
        authority_id(id),
        repository_id(),
        connection_id(),
        ProviderInstallationId::new(11).expect("installation ID"),
        GithubServerServiceAppId::new(17).expect("App ID"),
        ProviderRepositoryId::new(13).expect("provider repository ID"),
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

fn historical_authority(
    current: &GithubServerServiceAuthorityIdentity,
    id: u128,
    app_key_spki_sha256: Sha256Digest,
) -> GithubServerServiceAuthorityIdentity {
    historical_authority_with_fingerprint(
        current,
        id,
        app_key_spki_sha256,
        current.configuration_fingerprint(),
    )
}

fn historical_authority_with_fingerprint(
    current: &GithubServerServiceAuthorityIdentity,
    id: u128,
    app_key_spki_sha256: Sha256Digest,
    configuration_fingerprint: Sha256Digest,
) -> GithubServerServiceAuthorityIdentity {
    GithubServerServiceAuthorityIdentity::new(
        current.tenant().clone(),
        authority_id(id),
        current.repository_id(),
        current.connection_id(),
        current.installation_id(),
        current.github_app_id(),
        current.github_repository_id(),
        current.github_repository_name().clone(),
        current.scope(),
        current.app_client_id().clone(),
        current.jwt_issuer(),
        app_key_spki_sha256,
        GithubServerServiceRevision::new(2).expect("historical App revision"),
        GithubServerServiceRevision::new(4).expect("historical policy revision"),
        configuration_fingerprint,
    )
    .expect("historical authority")
}

fn authority_descriptor(
    identity: GithubServerServiceAuthorityIdentity,
    state: GithubServerServiceAuthorityState,
) -> automata_ci_store::GithubServerServiceAuthorityDescriptor {
    automata_ci_store::GithubServerServiceAuthorityDescriptor::from_durable_parts(
        identity,
        state,
        None,
        None,
        GithubServerServiceGeneration::new(1).expect("next generation"),
        0,
        None,
        None,
        None,
        UnixMillis::new(0),
        UnixMillis::new(0),
    )
    .expect("authority descriptor")
}

fn schedule_manifest(visibility: ProviderRepositoryVisibility) -> GithubProviderManifest {
    let runner_policy_digest = Sha256Digest::from_bytes([0x71; 32]);
    let runner_policy = GithubProviderRunnerPolicyObject::new(
        AdmissionObject::new(
            runner_policy_digest,
            ObjectKey::new(format!(
                "github/runner-policy/v1/{runner_policy_digest}.json"
            ))
            .expect("runner policy key"),
            1,
            GITHUB_PROVIDER_RUNNER_POLICY_MEDIA_TYPE,
        )
        .expect("runner policy object"),
    )
    .expect("runner policy descriptor");
    GithubProviderManifest::new_with_workflow_selection_and_git_ref(
        tenant(),
        connection_id(),
        ProviderInstallationId::new(11).expect("installation ID"),
        ProviderRepositoryId::new(13).expect("provider repository ID"),
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
        Sha256Digest::from_bytes([0x73; 32]),
        GithubProviderWorkflowSelection::all_direct(),
        GithubProviderGitRef::main(),
        GithubCheckName::new("Automata CI").expect("Check name"),
        GithubProviderOrigins::github_dot_com(),
        GithubProviderManifestLimits::github_dot_com_ci(),
        GithubProviderManifestRevision::new(3).expect("manifest revision"),
    )
    .with_repository_owner_id(ProviderRepositoryOwnerId::new(19).expect("owner ID"))
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

#[derive(Clone, Copy)]
enum ChecksIdentityDrift {
    Exact,
    Tenant,
    InternalRepository,
    Connection,
    Installation,
    ProviderRepository,
    RepositoryName,
    App,
}

fn checks_identity(drift: ChecksIdentityDrift) -> GithubCheckSubjectIdentity {
    GithubCheckSubjectIdentity::new(
        if matches!(drift, ChecksIdentityDrift::Tenant) {
            TenantScope::from_authenticated_tenant_id("other-tenant").expect("other tenant")
        } else {
            tenant()
        },
        if matches!(drift, ChecksIdentityDrift::InternalRepository) {
            RepositoryId::from_uuid(Uuid::from_u128(0x31))
        } else {
            repository_id()
        },
        ProviderDeliveryId::from_uuid(Uuid::from_u128(0x40)).expect("delivery ID"),
        GithubCheckSubjectKey::new(".ci/workflows/ci.yml").expect("subject key"),
        if matches!(drift, ChecksIdentityDrift::Connection) {
            ProviderConnectionId::from_uuid(Uuid::from_u128(0x21)).expect("other connection")
        } else {
            connection_id()
        },
        ProviderInstallationId::new(if matches!(drift, ChecksIdentityDrift::Installation) {
            12
        } else {
            11
        })
        .expect("installation ID"),
        ProviderRepositoryId::new(
            if matches!(drift, ChecksIdentityDrift::ProviderRepository) {
                14
            } else {
                13
            },
        )
        .expect("provider repository ID"),
        GithubRepositoryName::new(if matches!(drift, ChecksIdentityDrift::RepositoryName) {
            "automata-ci/other"
        } else {
            "automata-ci/automata"
        })
        .expect("repository name"),
        GithubCheckAppId::new(if matches!(drift, ChecksIdentityDrift::App) {
            18
        } else {
            17
        })
        .expect("App ID"),
        GithubCheckHeadSha::new([0x11; 20]).expect("head SHA"),
        GithubCheckName::new("Automata CI").expect("Check name"),
    )
    .expect("Checks identity")
}

#[derive(Clone, Copy)]
enum PrivateIdentityDrift {
    Exact,
    Provider,
    Visibility,
    Tenant,
    Connection,
    Installation,
    ProviderRepository,
    RepositoryName,
}

fn private_identity(drift: PrivateIdentityDrift) -> ProviderDeliveryIdentity {
    let coordinates = ProviderRepositoryCoordinates::new(
        ProviderRepositoryId::new(
            if matches!(drift, PrivateIdentityDrift::ProviderRepository) {
                14
            } else {
                13
            },
        )
        .expect("provider repository ID"),
        if matches!(drift, PrivateIdentityDrift::Visibility) {
            ProviderRepositoryVisibility::Public
        } else {
            ProviderRepositoryVisibility::Private
        },
        if matches!(drift, PrivateIdentityDrift::RepositoryName) {
            "automata-ci/other"
        } else {
            "automata-ci/automata"
        },
    )
    .expect("repository coordinates");
    ProviderDeliveryIdentity::new(
        if matches!(drift, PrivateIdentityDrift::Tenant) {
            TenantScope::from_authenticated_tenant_id("other-tenant").expect("other tenant")
        } else {
            tenant()
        },
        if matches!(drift, PrivateIdentityDrift::Provider) {
            "gitlab"
        } else {
            "github"
        },
        if matches!(drift, PrivateIdentityDrift::Connection) {
            ProviderConnectionId::from_uuid(Uuid::from_u128(0x21)).expect("other connection")
        } else {
            connection_id()
        },
        ProviderInstallationId::new(if matches!(drift, PrivateIdentityDrift::Installation) {
            12
        } else {
            11
        })
        .expect("installation ID"),
        coordinates,
        "delivery-1",
    )
    .expect("delivery identity")
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

fn checks_context(authority: &GithubServerServiceAuthorityIdentity) -> ChecksCredentialContext {
    ChecksCredentialContext {
        identity: checks_identity(ChecksIdentityDrift::Exact),
        selector: GithubServerServiceAuthoritySelector::from_identity(authority),
        consumer: consumer(GithubServerServiceAction::CreateCheckRun),
        observed_at: UnixMillis::new(OBSERVED_AT),
        required_through: UnixMillis::new(REQUIRED_THROUGH),
    }
}

fn private_context(
    authority: &GithubServerServiceAuthorityIdentity,
    drift: PrivateIdentityDrift,
    action: GithubDeliveryPrivateRepositoryAction,
) -> PrivateSourceCredentialContext {
    PrivateSourceCredentialContext {
        identity: private_identity(drift),
        repository_owner_id: ProviderRepositoryOwnerId::new(19).expect("repository owner ID"),
        selector: GithubServerServiceAuthoritySelector::from_identity(authority),
        action,
        consumer: consumer(private_action(action)),
        observed_at: UnixMillis::new(OBSERVED_AT),
        required_through: UnixMillis::new(REQUIRED_THROUGH),
    }
}

fn adapters(
    handoffs: Arc<FakeHandoffs>,
    authorities: &[GithubServerServiceAuthorityIdentity],
) -> GithubProviderCredentialAdapters {
    GithubProviderCredentialAdapters::with_handoffs(handoffs, authorities).expect("adapters")
}

fn durable_adapters(
    handoffs: Arc<FakeHandoffs>,
    authorities: &[GithubServerServiceAuthorityIdentity],
    lookup: Arc<FakeAuthorityLookup>,
) -> GithubProviderCredentialAdapters {
    let lookup: Arc<dyn GithubProviderAuthorityLookup> = lookup;
    let routes =
        GithubProviderCredentialRequestResolver::new(authorities).expect("strict durable routes");
    GithubProviderCredentialAdapters::with_durable_handoffs(handoffs, authorities, lookup, routes)
        .expect("durable adapters")
}

#[test]
fn registry_is_bounded_unique_and_implements_both_delivery_ports() {
    fn assert_ports<
        T: GithubChecksCredentialProvider
            + GithubDeliverySourceCredentialProvider
            + GithubScheduleSourceCredentialProvider,
    >() {
    }
    assert_ports::<GithubProviderCredentialAdapters>();

    let checks = authority(GithubServerServiceScope::ChecksWrite, 0x60);
    let private = authority(GithubServerServiceScope::PrivateRepositorySourceRead, 0x61);
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
async fn scheduled_private_discovery_uses_its_own_oidc_consumer_action() {
    let private = authority(GithubServerServiceScope::PrivateRepositorySourceRead, 0x67);
    let fake = Arc::new(FakeHandoffs::new(FakeHandoffMode::Rejected));
    let adapters = adapters(Arc::clone(&fake), std::slice::from_ref(&private));
    let manifest = schedule_manifest(ProviderRepositoryVisibility::Private);
    let selector = GithubServerServiceAuthoritySelector::from_identity(&private);
    let request = GithubScheduleSourceCredentialRequest::new(
        schedule_discovery_claim(),
        &manifest,
        &selector,
        UnixMillis::new(OBSERVED_AT),
    )
    .expect("private scheduled discovery request");
    assert_eq!(
        adapters
            .acquire_private_schedule_source(request)
            .await
            .expect_err("the fake authority rejects after recording the exact request"),
        GithubScheduleSourceCredentialProviderError::Rejected
    );
    let requests = fake.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].consumer().action(),
        GithubServerServiceAction::DiscoverPrivateRepositorySchedules
    );
    assert_ne!(
        requests[0].consumer().action(),
        GithubServerServiceAction::FetchPrivateRepositoryRevision
    );
}

#[test]
fn public_scheduled_discovery_cannot_construct_a_private_oidc_handoff() {
    let private = authority(GithubServerServiceScope::PrivateRepositorySourceRead, 0x68);
    let manifest = schedule_manifest(ProviderRepositoryVisibility::Public);
    assert!(
        GithubScheduleSourceCredentialRequest::new(
            schedule_discovery_claim(),
            &manifest,
            &GithubServerServiceAuthoritySelector::from_identity(&private),
            UnixMillis::new(OBSERVED_AT),
        )
        .is_err()
    );
}

#[tokio::test]
async fn full_checks_coordinates_are_rejected_before_handoff_io() {
    let checks = authority(GithubServerServiceScope::ChecksWrite, 0x60);
    let fake = Arc::new(FakeHandoffs::new(FakeHandoffMode::Exact));
    let adapters = adapters(Arc::clone(&fake), std::slice::from_ref(&checks));
    for drift in [
        ChecksIdentityDrift::Tenant,
        ChecksIdentityDrift::InternalRepository,
        ChecksIdentityDrift::Connection,
        ChecksIdentityDrift::Installation,
        ChecksIdentityDrift::ProviderRepository,
        ChecksIdentityDrift::RepositoryName,
        ChecksIdentityDrift::App,
    ] {
        let mut context = checks_context(&checks);
        context.identity = checks_identity(drift);
        assert_eq!(
            adapters
                .acquire_checks(context)
                .await
                .expect_err("reject coordinate drift"),
            GithubChecksCredentialProviderError::Rejected
        );
    }
    let mut changed_selector = checks_context(&checks);
    changed_selector.selector = GithubServerServiceAuthoritySelector::from_durable_parts(
        tenant(),
        checks.authority_id(),
        Sha256Digest::from_bytes([0x7f; 32]),
        checks.app_configuration_revision(),
        checks.policy_revision(),
    );
    assert_eq!(
        adapters
            .acquire_checks(changed_selector)
            .await
            .expect_err("reject selector drift"),
        GithubChecksCredentialProviderError::Rejected
    );
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn retired_unknown_and_route_drifted_authorities_never_enter_handoff_io() {
    let current = authority(GithubServerServiceScope::ChecksWrite, 0x60);
    let retired = historical_authority(&current, 0x62, current.app_key_spki_sha256());
    let drifted = historical_authority(&current, 0x63, Sha256Digest::from_bytes([0x77; 32]));
    let fingerprint_drifted = historical_authority_with_fingerprint(
        &current,
        0x65,
        current.app_key_spki_sha256(),
        Sha256Digest::from_bytes([0x78; 32]),
    );
    let lookup = Arc::new(FakeAuthorityLookup::new([
        authority_descriptor(retired.clone(), GithubServerServiceAuthorityState::Retired),
        authority_descriptor(drifted.clone(), GithubServerServiceAuthorityState::Active),
        authority_descriptor(
            fingerprint_drifted.clone(),
            GithubServerServiceAuthorityState::Active,
        ),
    ]));
    let handoffs = Arc::new(FakeHandoffs::new(FakeHandoffMode::Exact));
    let adapters = durable_adapters(
        Arc::clone(&handoffs),
        std::slice::from_ref(&current),
        Arc::clone(&lookup),
    );
    let unknown = historical_authority(&current, 0x64, current.app_key_spki_sha256());

    for rejected in [&retired, &drifted, &fingerprint_drifted, &unknown] {
        assert_eq!(
            adapters
                .acquire_checks(checks_context(rejected))
                .await
                .expect_err("historical route must fail closed"),
            GithubChecksCredentialProviderError::Rejected
        );
    }
    assert_eq!(lookup.calls.load(Ordering::SeqCst), 4);
    assert_eq!(handoffs.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn public_source_and_wrong_scope_never_enter_handoff_io() {
    let private = authority(GithubServerServiceScope::PrivateRepositorySourceRead, 0x61);
    let fake = Arc::new(FakeHandoffs::new(FakeHandoffMode::Exact));
    let adapters = adapters(Arc::clone(&fake), std::slice::from_ref(&private));
    for drift in [
        PrivateIdentityDrift::Provider,
        PrivateIdentityDrift::Visibility,
        PrivateIdentityDrift::Tenant,
        PrivateIdentityDrift::Connection,
        PrivateIdentityDrift::Installation,
        PrivateIdentityDrift::ProviderRepository,
        PrivateIdentityDrift::RepositoryName,
    ] {
        assert_eq!(
            adapters
                .acquire_private_source(private_context(
                    &private,
                    drift,
                    GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryRevision,
                ))
                .await
                .expect_err("source coordinate drift"),
            GithubDeliverySourceCredentialProviderError::Rejected
        );
    }

    let mut wrong_action = private_context(
        &private,
        PrivateIdentityDrift::Exact,
        GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryRevision,
    );
    wrong_action.consumer = consumer(GithubServerServiceAction::CreateCheckRun);
    assert_eq!(
        adapters
            .acquire_private_source(wrong_action)
            .await
            .expect_err("Checks action cannot authorize source"),
        GithubDeliverySourceCredentialProviderError::Rejected
    );
    let mut changed_selector = private_context(
        &private,
        PrivateIdentityDrift::Exact,
        GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryRevision,
    );
    changed_selector.selector = GithubServerServiceAuthoritySelector::from_durable_parts(
        tenant(),
        private.authority_id(),
        Sha256Digest::from_bytes([0x7f; 32]),
        private.app_configuration_revision(),
        private.policy_revision(),
    );
    assert_eq!(
        adapters
            .acquire_private_source(changed_selector)
            .await
            .expect_err("App-bound selector drift"),
        GithubDeliverySourceCredentialProviderError::Rejected
    );
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn private_revision_and_changed_files_use_distinct_exact_consumers() {
    let private = authority(GithubServerServiceScope::PrivateRepositorySourceRead, 0x61);
    let fake = Arc::new(FakeHandoffs::new(FakeHandoffMode::Rejected));
    let adapters = adapters(Arc::clone(&fake), std::slice::from_ref(&private));
    for action in [
        GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryRevision,
        GithubDeliveryPrivateRepositoryAction::FetchPrivateRepositoryChangedFiles,
    ] {
        let error = adapters
            .acquire_private_source(private_context(
                &private,
                PrivateIdentityDrift::Exact,
                action,
            ))
            .await
            .expect_err("fake rejects after recording exact request");
        assert_eq!(error, GithubDeliverySourceCredentialProviderError::Rejected);
    }
    let requests = fake.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].consumer().action(),
        GithubServerServiceAction::FetchPrivateRepositoryRevision
    );
    assert_eq!(
        requests[1].consumer().action(),
        GithubServerServiceAction::FetchPrivateRepositoryChangedFiles
    );
    assert_ne!(requests[0].consumer(), requests[1].consumer());
    assert_eq!(requests[0].observed_at(), UnixMillis::new(OBSERVED_AT));
    assert_eq!(
        requests[0].required_through(),
        UnixMillis::new(REQUIRED_THROUGH)
    );
}

#[tokio::test]
async fn inconsistent_returned_binding_is_released_and_never_delivered() {
    let checks = authority(GithubServerServiceScope::ChecksWrite, 0x60);
    for mode in [
        FakeHandoffMode::WrongSelector,
        FakeHandoffMode::WrongConsumer,
        FakeHandoffMode::WrongHorizon,
        FakeHandoffMode::WrongAcquiredAt,
        FakeHandoffMode::WrongIssuanceAuthority,
    ] {
        let fake = Arc::new(FakeHandoffs::new(mode));
        let adapters = adapters(Arc::clone(&fake), std::slice::from_ref(&checks));
        assert_eq!(
            adapters
                .acquire_checks(checks_context(&checks))
                .await
                .expect_err("inconsistent handoff"),
            GithubChecksCredentialProviderError::InvariantViolation
        );
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fake.releases.load(Ordering::SeqCst), 1);
    }
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
    let identity = authority(GithubServerServiceScope::PrivateRepositorySourceRead, 0x6f0);
    let request = AcquireGithubServerServiceHandoff::new(
        GithubServerServiceAuthoritySelector::from_identity(&identity),
        GithubServerServiceHandoffId::from_uuid(Uuid::from_u128(0x6f1)).expect("handoff ID"),
        consumer(GithubServerServiceAction::FetchPrivateRepositoryRevision),
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
