#[allow(dead_code)]
mod common;
mod github_manifest_fixture;

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::Duration,
};

use automata_ci_core::{
    Architecture, ContextValue, FencingToken, JobContentReference, JobExecutionContext, JobId,
    JobInstanceIdentity, JobIr, JobIrEnvelope, JobIrVersion, JobPermissionRequest,
    JobRuntimeContext, JobSource, Lease, LeaseId, OperatingSystem, RunId, RunValueTemplates,
    RunnerCapabilities, RunnerFeature, RunnerId, RunnerPlatform, RunnerRequirements,
    RunnerSessionId, RuntimeBoolean, SemanticStep, Sha256Digest, ShellTemplate, StepId, StepIr,
    StrategyContext, UnixMillis, ValueTemplate, WorkflowJobKey,
};
use automata_ci_oidc_github::{
    OidcAudience, OidcAuthorityId, OidcIssuer, OidcKeyId, OidcRequestBearer, OidcService,
    OidcServiceErrorKind, OidcSupportedClaims, OidcTokenLifetime, RequestBearerConfig,
    RequestBearerKey, RequestBearerKeyring, Rs256Keyring, Rs256SigningKey, RsaPublicJwk,
};
use automata_ci_store::{
    AcceptManifestPinnedGithubDelivery, AcceptProviderDelivery, ActivatedLogicalInstanceDescriptor,
    AdmissionObject, AdmissionRepository, AdmitLogicalWorkflowRun, AdmittedLogicalWorkflowJob,
    AuthenticatedGithubDeliveryClaim, BindLogicalActivationPreparation,
    ClaimNextLogicalInstanceMaterialization, ClaimNextLogicalJobOrchestration,
    ClaimProviderDelivery, ClaimedLogicalInstanceMaterialization, ClaimedLogicalJobActivation,
    CommitLogicalInstanceMaterialization, ConsumeSelectedLogicalInstanceMaterialization,
    ConsumeSelectedLogicalJobOrchestration, ConsumedLogicalJobOrchestrationAuthority,
    EnsureGithubServerServiceAuthority, GITHUB_OIDC_REQUEST_BEARER_KEY_FINGERPRINT_DOMAIN,
    GithubCheckHeadSha, GithubCheckName, GithubOidcAuthorityProposal,
    GithubOidcAuthorityRepository as _, GithubOidcCurrentPolicy, GithubOidcCurrentnessClock,
    GithubOidcCurrentnessClockError, GithubOidcExecutionIdentity,
    GithubOidcKeyRetentionRepository as _, GithubOidcKeyUse, GithubOidcLoadedKey,
    GithubOidcStoreError, GithubOidcSubjectPolicyMode, GithubOidcSubjectPolicyRevision,
    GithubProviderManifest, GithubProviderManifestLimits, GithubProviderManifestRepository as _,
    GithubProviderManifestRevision, GithubProviderOrigins,
    GithubProviderWebhookVerifierFingerprint, GithubRepositoryName, GithubServerServiceAppClientId,
    GithubServerServiceAppId, GithubServerServiceAuthorityId, GithubServerServiceAuthorityIdentity,
    GithubServerServiceAuthorityRepository as _, GithubServerServiceJwtIssuer,
    GithubServerServiceRevision, GithubServerServiceScope, GithubSubjectEvidenceRepository as _,
    JobEnvironmentActivationEvidence, JobEventTrust, JobSourceKind, LogicalActivationObject,
    LogicalActivationPreparationStore as _, LogicalActivationPreparationTarget,
    LogicalActivationRepository as _, LogicalActivationWorkerId,
    LogicalInstanceMaterializationSelectionOutcome, LogicalInstanceMaterializationTarget,
    LogicalJobOrchestrationSelectionOutcome, LogicalMaterializationRepository as _,
    LogicalMaterializationWorkerId, LogicalWorkSelectionId, LogicalWorkSelectionRepository as _,
    LogicalWorkSelectionStoreError, LogicalWorkflowAdmissionRepository as _,
    LogicalWorkflowInvocationId, LogicalWorkflowJobId, LogicalWorkflowJobKind, ObjectKey,
    OpenRunnerSession, PostgresGithubOidcAuthorityRepository, PostgresGithubOidcIssuanceRepository,
    ProviderConnectionId, ProviderDeliveryClaimOwnerId, ProviderDeliveryIdentity,
    ProviderDeliveryRepository as _, ProviderInstallationId, ProviderRepositoryCoordinates,
    ProviderRepositoryId, ProviderRepositoryOwnerId, ProviderRepositoryVisibility,
    PublishLogicalJobActivation, ReserveGithubOidcAuthority, RetainGithubOidcKey,
    ReusableSecretPermission, RoutingDocument, RunnerGeneration, RunnerProtocolVersion,
    RunnerSessionRepository as _, StableRunnerSlot, StoreError, TenantScope,
    WorkflowAdmissionIdempotency, WorkflowPlanRepository as _, WorkflowSnapshotId,
    github_oidc_rs256_public_key_fingerprint,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use common::{TestDatabase, TestResult, run_with_database};

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

const TEST_RSA_KEY_ID: &str = "store-live-rs256";
const TEST_RSA_MODULUS: &str = "3EB2d40ghnbyGr9du8XI5MMt_dHBRJlGaIQzk_fgMxwAxiToz5Ck540SPVcosHkRC-YjGIXjhwDSOlSJ9kxsoQRM5venRhsZeQWeuo_82S95k6CFguafVLvOSmFKltf5obDHo6DBxum_C_1jc4ZTJGEi1K7AV33qhJ_qZfAMI8K8a6xIpkXtcpTDU-yxTrdFQF5yzW7cVqyoXjHbcxIIS2UMVZTMJ3Hv5pgDxe9eYhVlxkBO0oZn89jVVMSfKnThlsj02cd9N5doFuJEKB5NTYGG9E7uWnOEq_jddN-NNa8hU1PTSqpzwIdDs1ZBet2wmNl5Wr1KI981Rkp2FTvPkw";
const TEST_RSA_EXPONENT: &str = "AQAB";
const TEST_PRIVATE_KEY_BODY: &str = r"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDcQHZ3jSCGdvIa
v127xcjkwy390cFEmUZohDOT9+AzHADGJOjPkKTnjRI9VyiweREL5iMYheOHANI6
VIn2TGyhBEzm96dGGxl5BZ66j/zZL3mToIWC5p9Uu85KYUqW1/mhsMejoMHG6b8L
/WNzhlMkYSLUrsBXfeqEn+pl8AwjwrxrrEimRe1ylMNT7LFOt0VAXnLNbtxWrKhe
MdtzEghLZQxVlMwnce/mmAPF715iFWXGQE7Shmfz2NVUxJ8qdOGWyPTZx303l2gW
4kQoHk1NgYb0Tu5ac4Sr+N103401ryFTU9NKqnPAh0OzVkF63bCY2XlavUoj3zVG
SnYVO8+TAgMBAAECggEAWtLWR0xR+kD4ayE4tOLFidgWkhE6AmC2UQka/8x6jnjg
tNSpkFZUOgvJVrQnWkZCSkbXeBhWD+i9yEHuNjujm+5bC+9Z8iXgpjA0GTihCqpy
FvddtvIFB/r+AVwHVxauoQd1+7qhzbW8C2Ss6wmcJWdM5qk9NZb96zzKesi3KNMz
t0zGmdm8frIppxnP2U/S5+Tu/3uHdG7TqJdFWX1qx6FKSi3oQdSrhKhCzCxEZO/A
slb9OJZPvPBAO9/BIJQiMPgLq1cIAj8q1uK8DAYIbYFNkzpVNYyVBk1E2KSJxUCg
zC3QgJ1XzHcEpDTAmv1o+yYAX58+DgAM0jvJYnp3cQKBgQD4hWRMC4c2L7lkP+fy
VHl6jNXKLSzonlOlVqJnz+D4EJI94hTHlkFLHKZKZLcKekokjtuohZuS7x9hZcIP
EVs5w+NPOIfhEk+s5UmRRxeojl86f1TrLhvkUqvkwPSuWR0zmNyEzh1OYNdoEM/G
CzxOzhczp6mOuH7A2CFnS8dhSwKBgQDi4UjP0i+BEE3nE02+QaPqP4N6Z5sXQKq0
IJtcBjZMm79g8TN5ZYWBpFlhNCOHn+AxYvh5tPq+QM9XuQQDHzxum5CRCFVWSCDu
IMR7dNs3Y3gXnPY4G5siCAWj/TuLs+GG/6iMezoE3+4j19zHxQRrYfGJQMOYlgMw
LT9jeG+l2QKBgCinoaWzCRZ7LifRMH97BDhhC6Q8SalwJRzaFE1JO3M5OsM21dFk
qh/Aew+WdD8ZjEF4wURLPw0FYyvKurk+TJ8hhXDzPX87QJ93DtbeO2eOitOF+v1S
GKv8PjR4wE45M8a6DfEHytGElBhpD6RFOENoAXGoztsTIWEouiYsxlwLAoGBAKpj
rS4+2WRhnVAUpEdlvrfXOWP9WXGuJEWhU2xaUf9Y3PLuUs0yHIEPr/ybjq91t4b/
oEKvU7z8qXtlPQknNViQRpNVodlp1ClivI1HZreDYZbCT/w1Z124jpvpPAYgcxjS
+n9+sEUm9A9BN9NkOHx5E1AULpFy4DQXV0raEWeJAoGBAJN+ZF4n+c+pzlUObvtC
H3N4m86U0TUSWCXJe4Kv/5eNdkdjztyUJ8diHOK530A0wWAc7zK9L2NJh/qHC+cY
XTlo/WPBMPJ3JOYlcxCXVn4sCBlRlPIccmoS6vGKQiWadCgwxLaBZNWctfKOQAdm
tPlzul2Px6cR3krgeRjgAs0j";
const TEST_HMAC_SECRET: &[u8] = b"synthetic-store-live-request-bearer-key-material";

struct LogicalOidcFixture {
    tenant: String,
    manifest: GithubProviderManifest,
    command: AdmitLogicalWorkflowRun,
    logical_job_id: LogicalWorkflowJobId,
}

struct PreparedOidcInstance {
    activated: ActivatedLogicalInstanceDescriptor,
    envelope: JobIrEnvelope,
    encoded: Vec<u8>,
    runtime_context: JobRuntimeContext,
    runtime_encoded: Vec<u8>,
}

type ActivationClaimSnapshot = (
    String,
    i64,
    Option<Uuid>,
    Option<i64>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<Uuid>,
);

struct DurableOidcFixture {
    manifest: GithubProviderManifest,
    execution: GithubOidcExecutionIdentity,
    current_policy: GithubOidcCurrentPolicy,
    clock: Arc<TestCurrentnessClock>,
    default_audience: OidcAudience,
    proposal: GithubOidcAuthorityProposal,
    bearer: OidcRequestBearer,
    request_keyring: Arc<RequestBearerKeyring>,
    request_key: GithubOidcLoadedKey,
    signing_keyring: Arc<Rs256Keyring>,
    signing_key: GithubOidcLoadedKey,
    private_key_pem: String,
}

impl DurableOidcFixture {
    fn millis(&self, offset: i64) -> i64 {
        self.execution.lease().issued_at().get() + offset
    }

    fn seconds(&self, offset: u64) -> u64 {
        u64::try_from(self.execution.lease().issued_at().get())
            .expect("test lease begins after the Unix epoch")
            / 1_000
            + offset
    }
}

#[derive(Debug)]
struct TestCurrentnessClock(AtomicI64);

impl TestCurrentnessClock {
    fn new(now_millis: i64) -> Self {
        Self(AtomicI64::new(now_millis))
    }

    fn set(&self, now_millis: i64) {
        self.0.store(now_millis, Ordering::SeqCst);
    }
}

impl GithubOidcCurrentnessClock for TestCurrentnessClock {
    fn now_millis(&self) -> Result<UnixMillis, GithubOidcCurrentnessClockError> {
        Ok(UnixMillis::new(self.0.load(Ordering::SeqCst)))
    }
}

fn test_private_key_pem() -> String {
    let label = ["PRIVATE", "KEY"].join(" ");
    format!("-----BEGIN {label}-----\n{TEST_PRIVATE_KEY_BODY}\n-----END {label}-----\n")
}

fn hmac_fingerprint(secret: &[u8]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(GITHUB_OIDC_REQUEST_BEARER_KEY_FINGERPRINT_DOMAIN);
    hasher.update(
        u64::try_from(secret.len())
            .expect("test HMAC material is bounded")
            .to_be_bytes(),
    );
    hasher.update(secret);
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn secret_digest(secret: &str) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(secret.as_bytes()).into())
}

fn admission_object(key: String, byte: u8, media_type: &str) -> AdmissionObject {
    AdmissionObject::new(
        digest(byte),
        ObjectKey::new(key).expect("test object key"),
        512,
        media_type,
    )
    .expect("test admission object")
}

fn logical_oidc_fixture(namespace: u128) -> LogicalOidcFixture {
    logical_oidc_fixture_with_profile(namespace, automata_ci_core::JobAuthorityProfile::Standard)
}

fn logical_oidc_fixture_with_profile(
    namespace: u128,
    authority_profile: automata_ci_core::JobAuthorityProfile,
) -> LogicalOidcFixture {
    let tenant = format!("oidc-live-{}", Uuid::new_v4().simple());
    let tenant_scope =
        TenantScope::from_authenticated_tenant_id(&tenant).expect("test tenant scope");
    let manifest = oidc_manifest(tenant_scope.clone(), authority_profile);
    let repository_id = manifest.repository_id();
    let workflow_id = automata_ci_core::WorkflowId::from_uuid(Uuid::from_u128(namespace + 2));
    let snapshot_id = WorkflowSnapshotId::from_uuid(Uuid::from_u128(namespace + 3));
    let run_id = RunId::from_uuid(Uuid::from_u128(namespace + 4));
    let invocation_id = LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(namespace + 5))
        .expect("test invocation");
    let logical_job_id =
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(namespace + 6)).expect("test logical job");
    let logical_job = AdmittedLogicalWorkflowJob::new(
        logical_job_id,
        WorkflowJobKey::new("oidc").expect("test logical key"),
        0,
        LogicalWorkflowJobKind::Steps,
        Vec::new(),
    )
    .expect("test logical job");
    let command = AdmitLogicalWorkflowRun::builder(
        tenant_scope,
        WorkflowAdmissionIdempotency::provider_delivery(format!("oidc-live-{namespace}"))
            .expect("test idempotency"),
        digest(0x40),
        AdmissionRepository::new(repository_id, "github", "4242", "example", "project")
            .expect("test repository"),
        workflow_id,
        manifest.workflow_path(),
        "OIDC",
        "refs/heads/main",
        snapshot_id,
        admission_object(format!("oidc/{namespace}/source"), 0x11, "application/yaml"),
        admission_object(
            format!("oidc/{namespace}/plan"),
            0x12,
            "application/vnd.automata.workflow-plan+json",
        ),
        run_id,
        1,
        invocation_id,
        "push",
        admission_object(format!("oidc/{namespace}/event"), 0x13, "application/json"),
        vec![0x14; 20],
        vec![logical_job],
        UnixMillis::new(1_000),
    )
    .base_context(admission_object(
        format!("oidc/{namespace}/base-context"),
        0x15,
        "application/vnd.automata.job-runtime-context.protobuf",
    ))
    .build()
    .expect("test logical admission");
    LogicalOidcFixture {
        tenant,
        manifest,
        command,
        logical_job_id,
    }
}

fn oidc_manifest(
    tenant: TenantScope,
    authority_profile: automata_ci_core::JobAuthorityProfile,
) -> GithubProviderManifest {
    let runtime_policy = github_manifest_fixture::fixture_github_runtime_policy(1);
    GithubProviderManifest::new(
        tenant,
        ProviderConnectionId::from_uuid(Uuid::from_u128(40_010)).expect("connection"),
        ProviderInstallationId::new(101).expect("installation"),
        ProviderRepositoryId::new(4_242).expect("provider repository"),
        GithubRepositoryName::new("example/project").expect("repository name"),
        ProviderRepositoryVisibility::Public,
        GithubServerServiceAppId::new(303).expect("App"),
        GithubServerServiceAppClientId::new("Iv1.8a61f9b3a7aba766").expect("client ID"),
        GithubServerServiceJwtIssuer::AppClientId,
        digest(0x71),
        GithubServerServiceRevision::new(1).expect("App revision"),
        GithubProviderWebhookVerifierFingerprint::from_sha256(digest(0x72))
            .expect("verifier fingerprint"),
        GithubServerServiceRevision::new(1).expect("verifier revision"),
        GithubServerServiceRevision::new(1).expect("policy revision"),
        authority_profile,
        runtime_policy.runner_policy,
        runtime_policy.revision,
        runtime_policy.semantic_digest,
        GithubCheckName::new("Automata CI").expect("check name"),
        GithubProviderOrigins::github_dot_com(),
        GithubProviderManifestLimits::github_dot_com_ci(),
        GithubProviderManifestRevision::new(1).expect("manifest revision"),
    )
}

fn rotated_credential_free_manifest(prior: &GithubProviderManifest) -> GithubProviderManifest {
    GithubProviderManifest::new(
        prior.tenant().clone(),
        prior.connection_id(),
        prior.installation_id(),
        prior.github_repository_id(),
        prior.github_repository_name().clone(),
        prior.repository_visibility(),
        prior.github_app_id(),
        prior.app_client_id().clone(),
        prior.jwt_issuer(),
        prior.app_key_spki_sha256(),
        prior.app_configuration_revision(),
        prior.webhook_verifier_fingerprint(),
        prior.webhook_verifier_revision(),
        GithubServerServiceRevision::new(prior.policy_revision().get() + 1)
            .expect("rotated policy revision"),
        automata_ci_core::JobAuthorityProfile::CredentialFree,
        prior.runner_policy().clone(),
        prior.runtime_policy_revision(),
        prior.runtime_policy_digest(),
        prior.check_name().clone(),
        prior.origins(),
        prior.limits(),
        GithubProviderManifestRevision::new(prior.revision().get() + 1)
            .expect("rotated manifest revision"),
    )
}

async fn seed_oidc_tenant(database: &TestDatabase, tenant: &str) -> TestResult {
    sqlx::query(
        "INSERT INTO tenants (id, display_name, created_at_ms, updated_at_ms) VALUES ($1, 'OIDC live test', 1, 1)",
    )
    .bind(tenant)
    .execute(database.pool())
    .await?;
    Ok(())
}

async fn database_now(database: &TestDatabase) -> TestResult<UnixMillis> {
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
            .fetch_one(database.pool())
            .await?;
    Ok(UnixMillis::new(now))
}

fn retime_logical_admission(
    command: &AdmitLogicalWorkflowRun,
    admitted_at: UnixMillis,
) -> TestResult<AdmitLogicalWorkflowRun> {
    let mut builder = AdmitLogicalWorkflowRun::builder(
        command.tenant().clone(),
        command.idempotency().clone(),
        command.request_digest(),
        command.repository().clone(),
        command.workflow_id(),
        command.workflow_path(),
        command.workflow_name(),
        command.git_ref(),
        command.snapshot_id(),
        command.source().clone(),
        command.plan().clone(),
        command.run_id(),
        command.run_attempt(),
        command.root_invocation_id(),
        command.event_name(),
        command.event().clone(),
        command.head_sha().to_vec(),
        command.jobs().to_vec(),
        admitted_at,
    );
    if let Some(base_context) = command.base_context() {
        builder = builder.base_context(base_context.clone());
    }
    Ok(builder.build()?)
}

#[allow(clippy::too_many_lines)] // Keep the canonical signed OIDC admission transaction contiguous.
async fn admit_signed_oidc_workflow(
    database: &TestDatabase,
    fixture: &mut LogicalOidcFixture,
) -> TestResult {
    let tenant = TenantScope::from_authenticated_tenant_id(&fixture.tenant)?;
    let manifest = fixture.manifest.clone();
    let connection = manifest.connection_id();
    let installation = manifest.installation_id();
    let provider_repository_id = manifest.github_repository_id();
    let bootstrap_at = database_now(database).await?;
    database
        .store()
        .bootstrap_github_provider_repository(
            github_manifest_fixture::fixture_github_repository_bootstrap(
                manifest.clone(),
                bootstrap_at,
            ),
        )
        .await?;
    let checks_authority = GithubServerServiceAuthorityIdentity::new(
        tenant.clone(),
        GithubServerServiceAuthorityId::from_uuid(Uuid::from_u128(40_011))?,
        manifest.repository_id(),
        manifest.connection_id(),
        manifest.installation_id(),
        manifest.github_app_id(),
        manifest.github_repository_id(),
        manifest.github_repository_name().clone(),
        GithubServerServiceScope::ChecksWrite,
        manifest.app_client_id().clone(),
        manifest.jwt_issuer(),
        manifest.app_key_spki_sha256(),
        manifest.app_configuration_revision(),
        manifest.policy_revision(),
        digest(0x73),
    )?;
    database
        .store()
        .ensure_github_server_service_authority(EnsureGithubServerServiceAuthority::new(
            checks_authority.clone(),
            bootstrap_at,
        )?)
        .await?;
    let delivery_key = fixture.command.idempotency().key();
    let identity = ProviderDeliveryIdentity::new(
        tenant,
        "github",
        connection,
        installation,
        ProviderRepositoryCoordinates::new(
            provider_repository_id,
            ProviderRepositoryVisibility::Public,
            "example/project",
        )?,
        delivery_key,
    )?;
    let head_sha: [u8; 20] = fixture
        .command
        .head_sha()
        .try_into()
        .map_err(|_| "test head SHA is not exact")?;
    let delivery_observed_at = database_now(database).await?;
    let accepted = database
        .store()
        .accept_manifest_pinned_github_delivery(AcceptManifestPinnedGithubDelivery::new(
            AcceptProviderDelivery::new(
                identity,
                fixture.command.request_digest(),
                fixture.command.event().clone(),
                delivery_observed_at,
            )?,
            ProviderRepositoryOwnerId::new(404)?,
            ProviderRepositoryOwnerId::new(404)?,
            GithubCheckHeadSha::new(head_sha)?,
            manifest.webhook_verifier_fingerprint(),
            manifest.webhook_verifier_revision(),
        )?)
        .await?;
    let claim_owner = ProviderDeliveryClaimOwnerId::from_uuid(Uuid::from_u128(40_012))?;
    let claim_observed_at = database_now(database).await?;
    let claimed = database
        .store()
        .claim_provider_delivery(ClaimProviderDelivery::new(
            claim_owner,
            claim_observed_at,
            UnixMillis::new(
                claim_observed_at
                    .get()
                    .checked_add(60_000)
                    .ok_or("database time")?,
            ),
        )?)
        .await?
        .ok_or("accepted OIDC delivery was not claimable")?;
    if claimed.claim().delivery_id() != accepted.delivery_id() {
        return Err("a foreign provider delivery was claimed".into());
    }
    let authenticated = AuthenticatedGithubDeliveryClaim::new(
        claimed.claim(),
        claimed.attempt(),
        claimed.claimed_at(),
        claimed.expires_at(),
    )?;
    fixture.command = retime_logical_admission(&fixture.command, claimed.claimed_at())?;
    database
        .store()
        .admit_authenticated_github_delivery(
            fixture.command.clone(),
            authenticated,
            fixture.command.admitted_at(),
        )
        .await?;
    Ok(())
}

async fn claim_oidc_activation(
    database: &TestDatabase,
    fixture: &LogicalOidcFixture,
    owner: u128,
) -> TestResult<ClaimedLogicalJobActivation> {
    let target = LogicalActivationPreparationTarget::new(
        TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
        fixture.command.run_id(),
        fixture.command.root_invocation_id(),
        fixture.logical_job_id,
    )?;
    let preparation = match select_oidc_orchestration(database, &target, owner + 1).await? {
        ConsumedLogicalJobOrchestrationAuthority::Preparation(claimed) => claimed,
        authority @ ConsumedLogicalJobOrchestrationAuthority::Activation(_) => {
            return Err(format!("expected OIDC preparation authority, got {authority:?}").into());
        }
    };
    let bound_at = database_now(database).await?;
    let prepared = database
        .store()
        .bind_logical_activation_preparation(BindLogicalActivationPreparation::new(
            preparation.descriptor().clone(),
            preparation.claim().clone(),
            preparation.descriptor().base_context().clone(),
            admission_object(
                format!("oidc/{owner}/needs-context"),
                0x52,
                "application/vnd.automata.job-runtime-context.protobuf",
            ),
            bound_at,
        )?)
        .await?;
    match select_oidc_orchestration(database, &target, owner).await? {
        ConsumedLogicalJobOrchestrationAuthority::Activation(claimed) => {
            if claimed.claim().input_digest() != prepared.input_digest() {
                return Err("selected OIDC activation carried foreign prepared evidence".into());
            }
            Ok(claimed)
        }
        authority @ ConsumedLogicalJobOrchestrationAuthority::Preparation(_) => {
            Err(format!("expected OIDC activation authority, got {authority:?}").into())
        }
    }
}

async fn select_oidc_orchestration(
    database: &TestDatabase,
    expected_target: &LogicalActivationPreparationTarget,
    owner: u128,
) -> TestResult<ConsumedLogicalJobOrchestrationAuthority> {
    let observed_at = database_now(database).await?;
    let selected = match database
        .store()
        .claim_next_logical_job_orchestration(ClaimNextLogicalJobOrchestration::new(
            LogicalWorkSelectionId::from_uuid(Uuid::new_v4())?,
            LogicalActivationWorkerId::from_uuid(Uuid::from_u128(owner))?,
            observed_at,
            60_000,
        )?)
        .await?
    {
        LogicalJobOrchestrationSelectionOutcome::Selected(selected) => selected,
        outcome => return Err(format!("expected OIDC selection, got {outcome:?}").into()),
    };
    if selected.target() != expected_target {
        return Err("OIDC selector returned a foreign target".into());
    }
    Ok(database
        .store()
        .consume_selected_logical_job_orchestration(ConsumeSelectedLogicalJobOrchestration::new(
            selected,
        ))
        .await?
        .authority()
        .clone())
}

async fn select_oidc_materialization(
    database: &TestDatabase,
    expected_target: &LogicalInstanceMaterializationTarget,
    owner: u128,
) -> TestResult<ClaimedLogicalInstanceMaterialization> {
    let observed_at = database_now(database).await?;
    let selected = match database
        .store()
        .claim_next_logical_instance_materialization(ClaimNextLogicalInstanceMaterialization::new(
            LogicalWorkSelectionId::from_uuid(Uuid::new_v4())?,
            LogicalMaterializationWorkerId::from_uuid(Uuid::from_u128(owner))?,
            observed_at,
            60_000,
        )?)
        .await?
    {
        LogicalInstanceMaterializationSelectionOutcome::Selected(selected) => selected,
        outcome => return Err(format!("expected OIDC materialization, got {outcome:?}").into()),
    };
    if selected.target() != expected_target {
        return Err("OIDC materialization selector returned a foreign target".into());
    }
    Ok(database
        .store()
        .consume_selected_logical_instance_materialization(
            ConsumeSelectedLogicalInstanceMaterialization::new(selected),
        )
        .await?
        .authority()
        .clone())
}

fn oidc_job_id(
    run_id: RunId,
    invocation_id: LogicalWorkflowInvocationId,
    logical_job_id: LogicalWorkflowJobId,
    matrix_digest: Sha256Digest,
) -> JobId {
    let mut hasher = Sha256::new();
    hasher.update(b"automata.workflow-service.logical-job-id.v1\0");
    hasher.update(run_id.as_uuid().as_bytes());
    hasher.update(invocation_id.as_uuid().as_bytes());
    hasher.update(logical_job_id.as_uuid().as_bytes());
    hasher.update(0_u32.to_be_bytes());
    hasher.update(1_u32.to_be_bytes());
    hasher.update(matrix_digest.as_bytes());
    let output: [u8; 32] = hasher.finalize().into();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&output[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    JobId::from_uuid(Uuid::from_bytes(bytes))
}

fn content_reference(object: &AdmissionObject) -> JobContentReference {
    JobContentReference::new(
        object.object_key().as_str(),
        object.digest(),
        object.encoded_size(),
        object.media_type(),
    )
}

fn activation_reference(object: &LogicalActivationObject) -> JobContentReference {
    JobContentReference::new(
        object.object_key().as_str(),
        object.digest(),
        object.encoded_size(),
        object.media_type(),
    )
}

#[allow(clippy::too_many_lines)] // The fixture constructs one complete authenticated runtime context.
fn prepare_oidc_instance(
    fixture: &LogicalOidcFixture,
    claimed: &ClaimedLogicalJobActivation,
) -> PreparedOidcInstance {
    let matrix_digest = digest(0x61);
    let identity =
        JobInstanceIdentity::new("oidc", 0, 1, matrix_digest).expect("test matrix identity");
    let empty = ContextValue::object(BTreeMap::new()).expect("test empty context");
    let runtime_context = JobRuntimeContext::new(
        empty.clone(),
        empty.clone(),
        empty,
        StrategyContext::new(false, 0, 1, 1).expect("test strategy"),
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .expect("test runtime context");
    let runtime_encoded =
        serde_json::to_vec(&runtime_context).expect("encode test runtime context");
    let runtime = LogicalActivationObject::runtime_context(
        Sha256Digest::from_bytes(Sha256::digest(&runtime_encoded).into()),
        ObjectKey::new("oidc/runtime-context").expect("test runtime key"),
        u64::try_from(runtime_encoded.len()).expect("test runtime size"),
    )
    .expect("test runtime descriptor");
    let workspace = "/srv/work/oidc";
    let step = StepIr::new_literal_name(
        StepId::new("run").expect("test step ID"),
        "Run",
        RuntimeBoolean::literal(false),
        SemanticStep::run(RunValueTemplates::new(
            ValueTemplate::literal("true").expect("test command"),
            ShellTemplate::default_shell(),
        )),
    )
    .expect("test step");
    let authority_profile = fixture.manifest.authority_profile();
    let requirements = if authority_profile == automata_ci_core::JobAuthorityProfile::CredentialFree
    {
        RunnerRequirements::default()
    } else {
        RunnerRequirements::default().with_features([RunnerFeature::OIDC_TOKENS])
    };
    let job = JobIr::new(
        oidc_job_id(
            fixture.command.run_id(),
            fixture.command.root_invocation_id(),
            fixture.logical_job_id,
            matrix_digest,
        ),
        fixture.command.run_id(),
        "OIDC",
        requirements,
        identity.clone(),
        false,
        vec![step],
    )
    .with_authority_profile(authority_profile);
    let job = if authority_profile == automata_ci_core::JobAuthorityProfile::CredentialFree {
        job.with_permission_request(JobPermissionRequest::mapping([]))
    } else {
        job
    };
    let execution = claimed.execution();
    let mut job_execution = JobExecutionContext::new(
        execution.workflow_name(),
        execution.git_ref(),
        workspace,
        content_reference(claimed.event()),
        activation_reference(&runtime),
    )
    .with_run_id_alias(execution.run_id_alias())
    .with_run_number(execution.run_number())
    .with_run_attempt(execution.run_attempt());
    if let Some(actor) = execution.actor() {
        job_execution = job_execution.with_actor(actor);
    }
    let envelope = JobIrEnvelope::new(
        execution.workflow_id(),
        JobSource::new(
            "github",
            "example/project",
            "0123456789abcdef",
            fixture.manifest.workflow_path(),
            "push",
        ),
        job_execution,
        job,
    );
    envelope.validate().expect("current test JobIR");
    let encoded = serde_json::to_vec(&envelope).expect("encode test JobIR");
    let activated = ActivatedLogicalInstanceDescriptor::new(
        claimed,
        &identity,
        workspace,
        LogicalActivationObject::job_ir(
            Sha256Digest::from_bytes(Sha256::digest(&encoded).into()),
            ObjectKey::new("oidc/job-ir").expect("test JobIR key"),
            u64::try_from(encoded.len()).expect("test JobIR size"),
        )
        .expect("test JobIR descriptor"),
        runtime,
        JobEnvironmentActivationEvidence::new(
            None,
            JobEventTrust::Trusted,
            JobSourceKind::SameRepository,
            ReusableSecretPermission::None,
        ),
    )
    .expect("test activated instance");
    PreparedOidcInstance {
        activated,
        envelope,
        encoded,
        runtime_context,
        runtime_encoded,
    }
}

#[allow(clippy::too_many_lines)]
async fn seed_current_oidc_execution(
    database: &TestDatabase,
    signed_github_admission: bool,
) -> TestResult<(GithubOidcExecutionIdentity, GithubProviderManifest)> {
    seed_current_profiled_execution(
        database,
        signed_github_admission,
        automata_ci_core::JobAuthorityProfile::Standard,
    )
    .await
}

#[allow(clippy::too_many_lines)]
async fn seed_current_profiled_execution(
    database: &TestDatabase,
    signed_github_admission: bool,
    authority_profile: automata_ci_core::JobAuthorityProfile,
) -> TestResult<(GithubOidcExecutionIdentity, GithubProviderManifest)> {
    let mut fixture = logical_oidc_fixture_with_profile(40_000, authority_profile);
    seed_oidc_tenant(database, &fixture.tenant).await?;
    if signed_github_admission {
        admit_signed_oidc_workflow(database, &mut fixture).await?;
    } else {
        let error = database
            .store()
            .admit_logical_workflow(fixture.command.clone())
            .await
            .expect_err("generic GitHub admission must be rejected before durable work exists");
        assert!(matches!(
            error,
            automata_ci_store::LogicalWorkflowAdmissionStoreError::UnsupportedAdmissionSource
        ));
    }
    let claimed = claim_oidc_activation(database, &fixture, 40_100).await?;
    let prepared = prepare_oidc_instance(&fixture, &claimed);
    let published_at = database_now(database).await?;
    database
        .store()
        .publish_logical_job_activation(PublishLogicalJobActivation::new(
            claimed.claim().clone(),
            true,
            vec![prepared.activated.clone()],
            published_at,
        )?)
        .await?;
    let target = LogicalInstanceMaterializationTarget::new(
        TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
        fixture.command.run_id(),
        fixture.command.root_invocation_id(),
        fixture.logical_job_id,
        prepared.activated.id(),
    )?;
    let materialization = select_oidc_materialization(database, &target, 40_200).await?;
    let materialized_at = database_now(database).await?;
    let materialized = database
        .store()
        .commit_logical_instance_materialization(CommitLogicalInstanceMaterialization::new(
            &materialization,
            &prepared.encoded,
            &prepared.envelope,
            &prepared.runtime_encoded,
            &prepared.runtime_context,
            materialized_at,
        )?)
        .await?;

    let runner_id = RunnerId::from_uuid(Uuid::from_u128(40_300));
    let capabilities = RunnerCapabilities::new(
        runner_id,
        RunnerPlatform::new(OperatingSystem::Linux, Architecture::X86_64),
    )
    .with_features([RunnerFeature::OIDC_TOKENS]);
    let runner_epoch = database_now(database).await?;
    sqlx::query(
        r"
        INSERT INTO runners (
            id, tenant_id, name, normalized_name, capabilities, slots, status,
            desired_state, created_at_ms, updated_at_ms
        ) VALUES (
            $1, $2, 'oidc-live-runner', 'oidc-live-runner', $3::jsonb, 1,
            'online', 'active', $4, $4
        )
        ",
    )
    .bind(runner_id.as_uuid())
    .bind(&fixture.tenant)
    .bind(serde_json::to_value(&capabilities)?)
    .bind(runner_epoch.get())
    .execute(database.pool())
    .await?;
    let session = database
        .store()
        .open_session(OpenRunnerSession::new(
            RunnerSessionId::new(),
            runner_id,
            RunnerGeneration::new(1)?,
            RunnerProtocolVersion::new(4)?,
            JobIrVersion::current(),
            RoutingDocument::new(serde_json::to_string(&capabilities)?)?,
            runner_epoch,
        ))
        .await?;
    let lease_id = LeaseId::new();
    let fence = FencingToken::new(7)?;
    let lease_database_now = database_now(database).await?.get();
    let lease_issued_at =
        lease_database_now.checked_add(999).ok_or("database time")? / 1_000 * 1_000;
    let lease_expires_at = lease_issued_at.checked_add(33_500).ok_or("database time")?;
    let changed = sqlx::query(
        r"
        UPDATE job_attempts
        SET lifecycle = 'leased', fencing_token = $2, lease_id = $3,
            runner_id = $4, lease_issued_at_ms = $8,
            lease_expires_at_ms = $9, runner_session_id = $5,
            runner_session_epoch = $6, runner_generation = $7,
            runner_slot = 1, changed_at_ms = $8
        WHERE id = $1 AND lifecycle = 'queued'
        ",
    )
    .bind(materialized.attempt_id().as_uuid())
    .bind(i64::try_from(fence.get())?)
    .bind(lease_id.as_uuid())
    .bind(runner_id.as_uuid())
    .bind(session.fence().session_id().as_uuid())
    .bind(i64::try_from(session.fence().session_epoch().get())?)
    .bind(i64::try_from(session.fence().runner_generation().get())?)
    .bind(lease_issued_at)
    .bind(lease_expires_at)
    .execute(database.pool())
    .await?;
    if changed.rows_affected() != 1 {
        return Err("OIDC initial attempt was not queued".into());
    }
    let metadata = database
        .store()
        .get_job_ir_metadata(materialized.job_id())
        .await?;
    let execution = GithubOidcExecutionIdentity::new(
        fixture.command.workflow_id(),
        GithubRepositoryName::new("example/project")?,
        fixture.command.run_id(),
        materialized.job_id(),
        Lease::new(
            lease_id,
            materialized.attempt_id(),
            runner_id,
            fence,
            UnixMillis::new(lease_issued_at),
            UnixMillis::new(lease_expires_at),
        )?,
        session.fence(),
        StableRunnerSlot::new(1)?,
        metadata,
    )?;
    Ok((execution, fixture.manifest))
}

const INSERT_RUNTIME_AUTHORITY_CANDIDATE_SQL: &str = r"
        INSERT INTO github_runtime_authority_issuances (
            tenant_id, attempt_id, fencing_token, lease_id,
            lease_issued_at_ms, lease_expires_at_ms, run_id, job_id,
            runner_id, runner_session_id, runner_session_epoch,
            runner_generation, runner_slot, job_ir_schema,
            job_ir_size_bytes, job_ir_digest, repository_id,
            provider_connection_id, provider_installation_id,
            github_app_id, github_app_client_id,
            github_app_jwt_issuer_kind, github_app_jwt_issuer_value,
            github_repository_id, github_repository_name,
            authority_namespace, policy_digest, issuer_fingerprint,
            configuration_fingerprint,
            preparation_selection_id, preparation_selection_owner_id,
            preparation_selection_generation,
            preparation_selection_descriptor_digest,
            preparation_selection_claimed_at_ms,
            preparation_selection_expires_at_ms,
            activation_selection_id, activation_selection_owner_id,
            activation_selection_generation, activation_selection_input_digest,
            activation_selection_claimed_at_ms, activation_selection_expires_at_ms,
            materialization_selection_id, materialization_selection_owner_id,
            materialization_selection_generation,
            materialization_selection_descriptor_digest,
            materialization_selection_claimed_at_ms,
            materialization_selection_expires_at_ms,
            requested_at_ms,
            request_deadline_at_ms, conservative_expiry_at_ms,
            mint_claim_owner_id, mint_claimed_at_ms,
            mint_claim_expires_at_ms, state_updated_at_ms
        )
        SELECT repository.tenant_id, attempt.id, attempt.fencing_token,
               attempt.lease_id, attempt.lease_issued_at_ms,
               attempt.lease_expires_at_ms, run.id, job.id,
               attempt.runner_id, attempt.runner_session_id,
               attempt.runner_session_epoch, attempt.runner_generation,
               attempt.runner_slot, job.job_ir_schema, job.job_ir_size_bytes,
               job.job_ir_digest, repository.id,
               CASE WHEN $2 = 'provider_connection'
                    THEN 'ffffffff-ffff-4fff-8fff-ffffffffffff'::UUID
                    ELSE delivery.provider_connection_id END,
               CASE WHEN $2 = 'provider_installation'
                    THEN delivery.provider_installation_id + 1
                    ELSE delivery.provider_installation_id END,
               manifest.github_app_id, manifest.github_app_client_id,
               manifest.github_app_jwt_issuer_kind,
               CASE manifest.github_app_jwt_issuer_kind
                   WHEN 'app_client_id' THEN manifest.github_app_client_id
                   WHEN 'app_id' THEN manifest.github_app_id::TEXT
               END,
               delivery.github_repository_id, delivery.github_repository_name,
               'github.repository',
               CASE WHEN $2 = 'policy_digest'
                    THEN decode(repeat('fa', 32), 'hex')
                    ELSE job.job_ir_digest END,
               CASE WHEN $2 = 'issuer_fingerprint'
                    THEN decode(repeat('fb', 32), 'hex')
                    ELSE manifest.app_key_spki_sha256 END,
               CASE WHEN $2 = 'configuration_fingerprint'
                    THEN decode(repeat('fc', 32), 'hex')
                    ELSE checks_authority.configuration_fingerprint END,
               preparation.origin_selection_id, preparation.owner_id,
               preparation.generation, preparation.descriptor_digest,
               preparation.claimed_at_ms, preparation.expires_at_ms,
               logical_job.activation_origin_selection_id,
               publication.activation_owner_id, publication.activation_generation,
               publication.activation_input_digest,
               publication.activation_claimed_at_ms,
               publication.activation_expires_at_ms,
               materialization.origin_selection_id, materialization.owner_id,
               materialization.generation, materialization.descriptor_digest,
               materialization.claimed_at_ms, materialization.expires_at_ms,
               attempt.lease_issued_at_ms,
               LEAST(attempt.lease_expires_at_ms,
                     attempt.lease_issued_at_ms + 120000),
               LEAST(attempt.lease_expires_at_ms,
                     attempt.lease_issued_at_ms + 120000) + 3780000,
               'ffffffff-ffff-4fff-9fff-ffffffffffff'::UUID,
               attempt.lease_issued_at_ms,
               attempt.lease_issued_at_ms + 30000,
               attempt.lease_issued_at_ms
        FROM job_attempts AS attempt
        JOIN jobs AS job ON job.id = attempt.job_id
        JOIN workflow_runs AS run ON run.id = job.run_id
        JOIN repositories AS repository ON repository.id = run.repository_id
        JOIN workflow_plan_v2_concrete_jobs AS concrete
          ON concrete.job_id = job.id
         AND concrete.initial_attempt_id = attempt.id
        JOIN workflow_plan_v2_activation_preparation_claims AS preparation
          ON preparation.run_id = concrete.run_id
         AND preparation.invocation_id = concrete.invocation_id
         AND preparation.logical_job_id = concrete.logical_job_id
        JOIN workflow_plan_v2_jobs AS logical_job
          ON logical_job.run_id = concrete.run_id
         AND logical_job.invocation_id = concrete.invocation_id
         AND logical_job.id = concrete.logical_job_id
        JOIN workflow_plan_v2_activation_publications AS publication
          ON publication.run_id = concrete.run_id
         AND publication.invocation_id = concrete.invocation_id
         AND publication.logical_job_id = concrete.logical_job_id
        JOIN workflow_plan_v2_materialization_claims AS materialization
          ON materialization.instance_id = concrete.instance_id
         AND materialization.expected_job_id = concrete.job_id
         AND materialization.expected_attempt_id = concrete.initial_attempt_id
        JOIN github_workflow_run_subject_evidence AS subject
          ON subject.tenant_id = repository.tenant_id
         AND subject.repository_id = repository.id
         AND subject.workflow_id = run.workflow_id
         AND subject.run_id = run.id
        JOIN github_provider_delivery_evidence AS delivery
          ON delivery.tenant_id = subject.tenant_id
         AND delivery.repository_id = subject.repository_id
         AND delivery.provider_delivery_id = subject.provider_delivery_id
        JOIN github_provider_manifest_revisions AS manifest
          ON manifest.tenant_id = delivery.tenant_id
         AND manifest.repository_id = delivery.repository_id
         AND manifest.provider_connection_id = delivery.provider_connection_id
         AND manifest.manifest_revision = delivery.provider_manifest_revision
         AND manifest.manifest_digest = delivery.provider_manifest_digest
        JOIN github_server_service_authorities AS checks_authority
          ON checks_authority.tenant_id = delivery.tenant_id
         AND checks_authority.id = delivery.checks_authority_id
        WHERE attempt.id = $1
        ";

async fn insert_runtime_authority_candidate(
    database: &TestDatabase,
    execution: &GithubOidcExecutionIdentity,
    substitution: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(INSERT_RUNTIME_AUTHORITY_CANDIDATE_SQL)
        .bind(execution.attempt_id().as_uuid())
        .bind(substitution)
        .execute(database.pool())
        .await
        .map(|_| ())
}

async fn rebase_runtime_authority_lease_to_database_time(
    database: &TestDatabase,
    execution: GithubOidcExecutionIdentity,
) -> TestResult<GithubOidcExecutionIdentity> {
    let started_at: i64 =
        sqlx::query_scalar("SELECT started_at_ms FROM job_attempts WHERE id = $1")
            .bind(execution.attempt_id().as_uuid())
            .fetch_one(database.pool())
            .await?;
    let first_observation = database_now(database).await?.get();
    if started_at > first_observation {
        let wait_millis = u64::try_from(started_at - first_observation)?;
        if wait_millis > 1_000 {
            return Err("OIDC attempt start is too far ahead of PostgreSQL time".into());
        }
        tokio::time::sleep(Duration::from_millis(wait_millis.saturating_add(1))).await;
    }
    let database_now = database_now(database).await?.get();
    if database_now < started_at {
        return Err("PostgreSQL time did not reach the OIDC attempt start".into());
    }
    let lease_expires_at = database_now.checked_add(300_000).ok_or("database time")?;
    let changed = sqlx::query(
        r"
        UPDATE job_attempts
        SET lease_issued_at_ms = $2, lease_expires_at_ms = $3, changed_at_ms = $2
        WHERE id = $1 AND lease_id = $4 AND fencing_token = $5
        ",
    )
    .bind(execution.attempt_id().as_uuid())
    .bind(database_now)
    .bind(lease_expires_at)
    .bind(execution.lease().lease_id().as_uuid())
    .bind(i64::try_from(execution.fencing_token().get())?)
    .execute(database.pool())
    .await?;
    if changed.rows_affected() != 1 {
        return Err("OIDC runtime-authority lease was not current".into());
    }
    sqlx::query(
        r"
        UPDATE runner_sessions
        SET connected_at_ms = $3, heartbeat_at_ms = $3
        WHERE id = $1 AND runner_id = $2 AND disconnected_at_ms IS NULL
        ",
    )
    .bind(execution.session().session_id().as_uuid())
    .bind(execution.runner_id().as_uuid())
    .bind(database_now)
    .execute(database.pool())
    .await?;
    sqlx::query(
        r"
        UPDATE runners
        SET last_seen_at_ms = $2, updated_at_ms = $2
        WHERE id = $1
        ",
    )
    .bind(execution.runner_id().as_uuid())
    .bind(database_now)
    .execute(database.pool())
    .await?;
    Ok(GithubOidcExecutionIdentity::new(
        execution.workflow_id(),
        execution.github_repository_name().clone(),
        execution.run_id(),
        execution.job_id(),
        Lease::new(
            execution.lease().lease_id(),
            execution.attempt_id(),
            execution.runner_id(),
            execution.fencing_token(),
            UnixMillis::new(database_now),
            UnixMillis::new(lease_expires_at),
        )?,
        execution.session(),
        execution.slot(),
        execution.job_ir().clone(),
    )?)
}

fn assert_runtime_authority_insert_rejected(error: &sqlx::Error, expected_constraint: &str) {
    let constraint = error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint);
    assert_eq!(
        constraint,
        Some(expected_constraint),
        "unexpected runtime-authority insertion error: {error}"
    );
}

async fn durable_oidc_fixture(database: &TestDatabase) -> TestResult<DurableOidcFixture> {
    let (execution, manifest) = seed_current_oidc_execution(database, true).await?;
    let base_millis = execution.lease().issued_at().get();
    let base_seconds = u64::try_from(base_millis)? / 1_000;
    let current_policy = GithubOidcCurrentPolicy::new(
        GithubOidcSubjectPolicyMode::StableOwnerEvidence,
        GithubOidcSubjectPolicyRevision::new(1)?,
        digest(0x31),
        digest(0x32),
        30,
        25,
    )?;
    let clock = Arc::new(TestCurrentnessClock::new(
        base_millis.checked_add(500).ok_or("database time")?,
    ));
    let default_audience = OidcAudience::new("https://github.com/example")?;
    let request_key_id = OidcKeyId::new("store-live-hmac")?;
    let request_key_fingerprint = hmac_fingerprint(TEST_HMAC_SECRET);
    let request_keyring = Arc::new(RequestBearerKeyring::new(
        RequestBearerConfig::new("store-live-request/v1", "store-live-mint/v1", 3_600, 30)?,
        request_key_id.clone(),
        [RequestBearerKey::new(
            request_key_id.clone(),
            TEST_HMAC_SECRET,
        )?],
    )?);
    let authority_id = OidcAuthorityId::from_uuid(Uuid::new_v4())?;
    let bearer = request_keyring.issue(authority_id, base_seconds, base_seconds + 88)?;
    let proposal = GithubOidcAuthorityProposal::new(
        authority_id,
        request_key_id.clone(),
        request_key_fingerprint,
        30,
        base_seconds,
        base_seconds + 88,
        secret_digest(bearer.expose_secret()),
    )?;
    let public_key = RsaPublicJwk::new(
        OidcKeyId::new(TEST_RSA_KEY_ID)?,
        TEST_RSA_MODULUS,
        TEST_RSA_EXPONENT,
    )?;
    let private_key_pem = test_private_key_pem();
    let signing_key = Rs256SigningKey::from_pem(&private_key_pem, public_key.clone())?;
    let signing_keyring = Arc::new(Rs256Keyring::new(
        public_key.key_id().clone(),
        [signing_key],
    )?);
    Ok(DurableOidcFixture {
        manifest,
        execution,
        current_policy,
        clock,
        default_audience,
        proposal,
        bearer,
        request_keyring,
        request_key: GithubOidcLoadedKey::new(
            GithubOidcKeyUse::RequestBearer,
            request_key_id,
            request_key_fingerprint,
        ),
        signing_keyring,
        signing_key: GithubOidcLoadedKey::new(
            GithubOidcKeyUse::IdTokenSigning,
            public_key.key_id().clone(),
            github_oidc_rs256_public_key_fingerprint(&public_key),
        ),
        private_key_pem,
    })
}

fn oidc_service(
    database: &TestDatabase,
    fixture: &DurableOidcFixture,
    current_policy: GithubOidcCurrentPolicy,
) -> TestResult<OidcService> {
    let repository = Arc::new(PostgresGithubOidcIssuanceRepository::new(
        database.store().clone(),
        current_policy,
        [fixture.signing_key.clone()],
        fixture.clock.clone(),
    )?);
    Ok(OidcService::new(
        OidcIssuer::https("https://oidc.example.invalid/".parse()?)?,
        OidcSupportedClaims::new([
            "event_name".to_owned(),
            "ref".to_owned(),
            "repository".to_owned(),
            "repository_owner".to_owned(),
            "run_attempt".to_owned(),
            "run_number".to_owned(),
            "runner_environment".to_owned(),
            "sha".to_owned(),
            "workflow".to_owned(),
            "workflow_ref".to_owned(),
            "workflow_sha".to_owned(),
        ])?,
        OidcTokenLifetime::from_seconds(30)?,
        Arc::clone(&fixture.request_keyring),
        Arc::clone(&fixture.signing_keyring),
        repository,
    ))
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn rotation_deadlines_readiness_and_per_use_bound_are_durable() -> TestResult {
    run_with_database(|database| async move {
        let old_id = OidcKeyId::new("rsa-old")?;
        let new_id = OidcKeyId::new("rsa-new")?;
        let old = database
            .store()
            .retain_github_oidc_key(RetainGithubOidcKey::id_token_signing(
                old_id.clone(),
                digest(1),
                1_000,
                0,
                500,
            )?)
            .await?;
        let new = database
            .store()
            .retain_github_oidc_key(RetainGithubOidcKey::id_token_signing(
                new_id.clone(),
                digest(2),
                1_100,
                0,
                500,
            )?)
            .await?;
        assert_eq!(old.not_after_seconds(), 1_300);
        assert_eq!(new.not_after_seconds(), 1_400);

        let required = database.store().required_github_oidc_keys(999).await?;
        assert_eq!(required.len(), 2);
        assert_eq!(required[0].key_id(), &new_id);
        assert_eq!(required[1].key_id(), &old_id);

        let new_only = [GithubOidcLoadedKey::new(
            GithubOidcKeyUse::IdTokenSigning,
            new_id.clone(),
            digest(2),
        )];
        assert_eq!(
            database
                .store()
                .verify_github_oidc_key_readiness(999, &new_only)
                .await,
            Err(GithubOidcStoreError::Conflict)
        );
        let both = [
            new_only[0].clone(),
            GithubOidcLoadedKey::new(GithubOidcKeyUse::IdTokenSigning, old_id.clone(), digest(1)),
        ];
        database
            .store()
            .verify_github_oidc_key_readiness(999, &both)
            .await?;
        database
            .store()
            .verify_github_oidc_key_readiness(old.not_after_seconds(), &new_only)
            .await?;

        let retained = database
            .store()
            .retain_github_oidc_key(RetainGithubOidcKey::id_token_signing(
                old_id.clone(),
                digest(1),
                900,
                0,
                500,
            )?)
            .await?;
        assert_eq!(retained.not_after_seconds(), old.not_after_seconds());
        assert_eq!(
            database
                .store()
                .retain_github_oidc_key(RetainGithubOidcKey::id_token_signing(
                    old_id,
                    digest(9),
                    1_200,
                    0,
                    500,
                )?)
                .await,
            Err(GithubOidcStoreError::Conflict)
        );

        let race_id = OidcKeyId::new("rsa-race")?;
        let first = database
            .store()
            .retain_github_oidc_key(RetainGithubOidcKey::id_token_signing(
                race_id.clone(),
                digest(3),
                2_000,
                0,
                500,
            )?);
        let second =
            database
                .store()
                .retain_github_oidc_key(RetainGithubOidcKey::id_token_signing(
                    race_id.clone(),
                    digest(3),
                    2_500,
                    0,
                    500,
                )?);
        let (first, second) = tokio::join!(first, second);
        first?;
        second?;
        let race = database
            .store()
            .github_oidc_key_deadline(GithubOidcKeyUse::IdTokenSigning, &race_id)
            .await?
            .ok_or("race deadline missing")?;
        assert_eq!(race.not_after_seconds(), 2_800);

        for index in 0_u8..16 {
            database
                .store()
                .retain_github_oidc_key(RetainGithubOidcKey::request_bearer(
                    OidcKeyId::new(format!("hmac-{index:02}"))?,
                    digest(index.saturating_add(20)),
                    5_000,
                    0,
                    500,
                )?)
                .await?;
        }
        assert_eq!(
            database
                .store()
                .retain_github_oidc_key(RetainGithubOidcKey::request_bearer(
                    OidcKeyId::new("hmac-16")?,
                    digest(50),
                    5_000,
                    0,
                    500,
                )?)
                .await,
            Err(GithubOidcStoreError::ResourceExhausted)
        );
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM github_oidc_key_deadlines WHERE key_use = 'request_bearer'",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(count, 16);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn active_key_extensions_do_not_take_a_global_table_mutex() -> TestResult {
    run_with_database(|database| async move {
        let blocked_id = OidcKeyId::new("rsa-row-blocked")?;
        let independent_id = OidcKeyId::new("rsa-row-independent")?;
        for (key_id, fingerprint) in [
            (blocked_id.clone(), digest(61)),
            (independent_id.clone(), digest(62)),
        ] {
            database
                .store()
                .retain_github_oidc_key(RetainGithubOidcKey::id_token_signing(
                    key_id,
                    fingerprint,
                    5_000,
                    0,
                    1_000,
                )?)
                .await?;
        }

        let mut blocker = database.pool().begin().await?;
        sqlx::query(
            r"
            SELECT 1 FROM github_oidc_key_deadlines
            WHERE key_use = 'id_token_signing' AND key_id = $1
            FOR UPDATE
            ",
        )
        .bind(blocked_id.as_str())
        .fetch_one(&mut *blocker)
        .await?;

        let blocked_store = database.store().clone();
        let blocked_request =
            RetainGithubOidcKey::id_token_signing(blocked_id.clone(), digest(61), 5_500, 0, 1_001)?;
        let blocked_extension =
            tokio::spawn(
                async move { blocked_store.retain_github_oidc_key(blocked_request).await },
            );
        let mut observed_waiter = false;
        for _ in 0..200 {
            let waiters: i64 = sqlx::query_scalar(
                r"
                SELECT count(*) FROM pg_stat_activity
                WHERE datname = current_database()
                  AND pid <> pg_backend_pid()
                  AND wait_event_type = 'Lock'
                  AND query LIKE '%github_oidc_key_deadlines%'
                ",
            )
            .fetch_one(database.pool())
            .await?;
            if waiters > 0 {
                observed_waiter = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        if !observed_waiter {
            return Err("blocked key extension never reached its row lock".into());
        }

        let store = database.store().clone();
        let independent = tokio::time::timeout(
            Duration::from_secs(2),
            store.retain_github_oidc_key(RetainGithubOidcKey::id_token_signing(
                independent_id,
                digest(62),
                6_000,
                0,
                1_001,
            )?),
        )
        .await
        .map_err(|_| "independent active-key extension waited on another key row")??;
        assert_eq!(independent.not_after_seconds(), 6_300);
        blocker.rollback().await?;
        assert_eq!(blocked_extension.await??.not_after_seconds(), 5_800);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn concurrent_distinct_keys_cannot_overrun_the_per_use_bound() -> TestResult {
    const KEY_RETENTION_LOCK_NAMESPACE: i64 = 5_554_449_119_617_405_696;

    run_with_database(|database| async move {
        for index in 0_u8..15 {
            database
                .store()
                .retain_github_oidc_key(RetainGithubOidcKey::request_bearer(
                    OidcKeyId::new(format!("hmac-bound-{index:02}"))?,
                    digest(index.saturating_add(70)),
                    5_000,
                    0,
                    1_000,
                )?)
                .await?;
        }

        let mut mutex = database.pool().begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, $2))")
            .bind("request_bearer")
            .bind(KEY_RETENTION_LOCK_NAMESPACE)
            .execute(&mut *mutex)
            .await?;

        let first_request = RetainGithubOidcKey::request_bearer(
            OidcKeyId::new("hmac-bound-first")?,
            digest(90),
            5_000,
            0,
            1_000,
        )?;
        let first_store = database.store().clone();
        let first =
            tokio::spawn(async move { first_store.retain_github_oidc_key(first_request).await });
        let second_request = RetainGithubOidcKey::request_bearer(
            OidcKeyId::new("hmac-bound-second")?,
            digest(91),
            5_000,
            0,
            1_000,
        )?;
        let second_store = database.store().clone();
        let second =
            tokio::spawn(async move { second_store.retain_github_oidc_key(second_request).await });

        let mut observed_both_waiters = false;
        for _ in 0..200 {
            let waiters: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted",
            )
            .fetch_one(database.pool())
            .await?;
            if waiters >= 2 {
                observed_both_waiters = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        if !observed_both_waiters {
            return Err("distinct new keys did not serialize on the per-use mutex".into());
        }
        mutex.rollback().await?;

        let outcomes = [first.await?, second.await?];
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| {
                    matches!(outcome, Err(GithubOidcStoreError::ResourceExhausted))
                })
                .count(),
            1
        );
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM github_oidc_key_deadlines WHERE key_use = 'request_bearer'",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(count, 16);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn stale_extension_cannot_overrun_a_newer_observation_bound() -> TestResult {
    run_with_database(|database| async move {
        let stale_id = OidcKeyId::new("hmac-stale-extension")?;
        database
            .store()
            .retain_github_oidc_key(RetainGithubOidcKey::request_bearer(
                stale_id.clone(),
                digest(101),
                105,
                0,
                100,
            )?)
            .await?;
        for index in 0_u8..15 {
            database
                .store()
                .retain_github_oidc_key(RetainGithubOidcKey::request_bearer(
                    OidcKeyId::new(format!("hmac-stale-peer-{index:02}"))?,
                    digest(index.saturating_add(102)),
                    500,
                    0,
                    100,
                )?)
                .await?;
        }

        let mut blocker = database.pool().begin().await?;
        sqlx::query(
            r"
            SELECT 1 FROM github_oidc_key_deadlines
            WHERE key_use = 'request_bearer' AND key_id = $1
            FOR UPDATE
            ",
        )
        .bind(stale_id.as_str())
        .fetch_one(&mut *blocker)
        .await?;

        let stale_store = database.store().clone();
        let stale_request =
            RetainGithubOidcKey::request_bearer(stale_id, digest(101), 500, 0, 100)?;
        let stale_extension =
            tokio::spawn(async move { stale_store.retain_github_oidc_key(stale_request).await });
        let mut observed_waiter = false;
        for _ in 0..200 {
            let waiters: i64 = sqlx::query_scalar(
                r"
                SELECT count(*) FROM pg_stat_activity
                WHERE datname = current_database()
                  AND pid <> pg_backend_pid()
                  AND wait_event_type = 'Lock'
                  AND query LIKE '%github_oidc_key_deadlines%'
                ",
            )
            .fetch_one(database.pool())
            .await?;
            if waiters > 0 {
                observed_waiter = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        if !observed_waiter {
            return Err("stale key extension never reached its row lock".into());
        }

        database
            .store()
            .retain_github_oidc_key(RetainGithubOidcKey::request_bearer(
                OidcKeyId::new("hmac-newer-admission")?,
                digest(120),
                500,
                0,
                110,
            )?)
            .await?;
        blocker.rollback().await?;
        assert_eq!(
            stale_extension.await?,
            Err(GithubOidcStoreError::ResourceExhausted)
        );

        let active_at_newer_observation: i64 = sqlx::query_scalar(
            r"
            SELECT count(*) FROM github_oidc_key_deadlines
            WHERE key_use = 'request_bearer' AND max_not_after_seconds > 110
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(active_at_newer_observation, 16);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)] // One fault-injection proof checks the whole atomic boundary.
async fn corrupt_activation_evidence_rolls_back_selection_claim_and_oidc_authority() -> TestResult {
    run_with_database(|database| async move {
        let mut fixture = logical_oidc_fixture(40_000);
        seed_oidc_tenant(&database, &fixture.tenant).await?;
        admit_signed_oidc_workflow(&database, &mut fixture).await?;

        let target = LogicalActivationPreparationTarget::new(
            TenantScope::from_authenticated_tenant_id(&fixture.tenant)?,
            fixture.command.run_id(),
            fixture.command.root_invocation_id(),
            fixture.logical_job_id,
        )?;
        let preparation = match select_oidc_orchestration(&database, &target, 40_101).await? {
            ConsumedLogicalJobOrchestrationAuthority::Preparation(claimed) => claimed,
            authority @ ConsumedLogicalJobOrchestrationAuthority::Activation(_) => {
                return Err(
                    format!("expected OIDC preparation authority, got {authority:?}").into(),
                );
            }
        };
        let bound_at = database_now(&database).await?;
        database
            .store()
            .bind_logical_activation_preparation(BindLogicalActivationPreparation::new(
                preparation.descriptor().clone(),
                preparation.claim().clone(),
                preparation.descriptor().base_context().clone(),
                admission_object(
                    "oidc/corrupt/needs-context".to_owned(),
                    0x52,
                    "application/vnd.automata.job-runtime-context.protobuf",
                ),
                bound_at,
            )?)
            .await?;

        let activation_before: ActivationClaimSnapshot = sqlx::query_as(
            r"
            SELECT state, activation_fence, activation_owner_id,
                   activation_claimed_at_ms, activation_expires_at_ms,
                   activation_input_digest, activation_origin_selection_id
            FROM workflow_plan_v2_jobs
            WHERE id = $1
            ",
        )
        .bind(fixture.logical_job_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(activation_before.0, "pending");

        // Simulate on-disk corruption below the public immutable boundary. The
        // altered value remains structurally valid, so discovery reaches the
        // post-claim exact descriptor check inside the selector transaction.
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_activation_preparation_claims DISABLE TRIGGER USER",
        )
        .execute(database.pool())
        .await?;
        let corrupted = sqlx::query(
            r"
            UPDATE workflow_plan_v2_activation_preparation_claims
            SET logical_key = logical_key || '-corrupt'
            WHERE logical_job_id = $1
            ",
        )
        .bind(fixture.logical_job_id.as_uuid())
        .execute(database.pool())
        .await?;
        assert_eq!(corrupted.rows_affected(), 1);
        sqlx::query(
            "ALTER TABLE workflow_plan_v2_activation_preparation_claims ENABLE TRIGGER USER",
        )
        .execute(database.pool())
        .await?;

        let selection_id = LogicalWorkSelectionId::from_uuid(Uuid::new_v4())?;
        let observed_at = database_now(&database).await?;
        let error = database
            .store()
            .claim_next_logical_job_orchestration(ClaimNextLogicalJobOrchestration::new(
                selection_id,
                LogicalActivationWorkerId::from_uuid(Uuid::from_u128(40_102))?,
                observed_at,
                60_000,
            )?)
            .await
            .expect_err("corrupt activation evidence must fail the closed selector");
        let message = match error {
            LogicalWorkSelectionStoreError::Store(StoreError::CorruptData(message)) => message,
            error => return Err(format!("unexpected selector error: {error:?}").into()),
        };
        assert!(!message.contains("workflow_plan_v2"));
        assert!(!message.contains(&fixture.tenant));

        let selection_count: i64 = sqlx::query_scalar(
            r"
            SELECT count(*)
            FROM workflow_plan_v2_activation_work_selections
            WHERE selection_id = $1
            ",
        )
        .bind(selection_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(selection_count, 0, "the reserved selection must roll back");

        let activation_after: ActivationClaimSnapshot = sqlx::query_as(
            r"
            SELECT state, activation_fence, activation_owner_id,
                   activation_claimed_at_ms, activation_expires_at_ms,
                   activation_input_digest, activation_origin_selection_id
            FROM workflow_plan_v2_jobs
            WHERE id = $1
            ",
        )
        .bind(fixture.logical_job_id.as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            activation_after, activation_before,
            "phase claim must roll back"
        );

        let partial_authority: (i64, i64, i64) = sqlx::query_as(
            r"
            SELECT
                (SELECT count(*) FROM github_oidc_authorities),
                (SELECT count(*) FROM github_oidc_issuance_slots),
                (SELECT count(*) FROM github_runtime_authority_issuances)
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            partial_authority,
            (0, 0, 0),
            "failed selector retained partial OIDC authority"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn generic_admission_can_never_reserve_oidc_authority() -> TestResult {
    run_with_database(|database| async move {
        let fixture = logical_oidc_fixture(40_000);
        seed_oidc_tenant(&database, &fixture.tenant).await?;
        let error = database
            .store()
            .admit_logical_workflow(fixture.command.clone())
            .await
            .expect_err("generic GitHub admission must fail closed");
        assert!(matches!(
            error,
            automata_ci_store::LogicalWorkflowAdmissionStoreError::UnsupportedAdmissionSource
        ));
        let evidence_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM github_workflow_run_subject_evidence WHERE run_id = $1",
        )
        .bind(fixture.command.run_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(evidence_count, 0);
        let admission_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM workflow_admission_receipts WHERE run_id = $1",
        )
        .bind(fixture.command.run_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(admission_count, 0);
        let phase_claims: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM workflow_plan_v2_activation_preparation_claims",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(phase_claims, 0);
        let authority_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM github_oidc_authorities")
                .fetch_one(database.pool())
                .await?;
        assert_eq!(authority_count, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn authority_key_contention_crossing_lease_expiry_rolls_back_every_write() -> TestResult {
    run_with_database(|database| async move {
        let fixture = durable_oidc_fixture(&database).await?;
        database
            .store()
            .retain_github_oidc_key(RetainGithubOidcKey::request_bearer(
                fixture.request_key.key_id().clone(),
                fixture.request_key.key_sha256(),
                fixture.seconds(88),
                30,
                fixture.seconds(0),
            )?)
            .await?;
        let mut blocker = database.pool().begin().await?;
        sqlx::query(
            "SELECT 1 FROM github_oidc_key_deadlines WHERE key_use = 'request_bearer' AND key_id = $1 FOR UPDATE",
        )
        .bind(fixture.request_key.key_id().as_str())
        .execute(&mut *blocker)
        .await?;
        let repository = PostgresGithubOidcAuthorityRepository::new(
            database.store().clone(),
            fixture.clock.clone(),
        );
        let request = ReserveGithubOidcAuthority::new(
            fixture.execution.clone(),
            fixture.current_policy,
            fixture.proposal.clone(),
            UnixMillis::new(fixture.millis(500)),
        )?;
        let mut reserve = tokio::spawn(async move {
            repository.reserve_github_oidc_authority(request).await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut reserve)
                .await
                .is_err(),
            "authority reservation did not block on the held key row"
        );
        fixture.clock.set(fixture.millis(33_500));
        blocker.commit().await?;
        assert_eq!(reserve.await?, Err(GithubOidcStoreError::Unauthorized));
        let authority_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM github_oidc_authorities")
                .fetch_one(database.pool())
                .await?;
        assert_eq!(authority_count, 0);
        let deadline: (i64, i64) = sqlx::query_as(
            "SELECT max_not_after_seconds, updated_at_seconds FROM github_oidc_key_deadlines WHERE key_use = 'request_bearer' AND key_id = $1",
        )
        .bind(fixture.request_key.key_id().as_str())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(
            deadline,
            (
                i64::try_from(fixture.seconds(118))?,
                i64::try_from(fixture.seconds(0))?,
            )
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn mint_key_contention_crossing_lease_expiry_rolls_back_slot_and_extension() -> TestResult {
    run_with_database(|database| async move {
        let fixture = durable_oidc_fixture(&database).await?;
        let authority_repository = PostgresGithubOidcAuthorityRepository::new(
            database.store().clone(),
            fixture.clock.clone(),
        );
        authority_repository
            .reserve_github_oidc_authority(ReserveGithubOidcAuthority::new(
                fixture.execution.clone(),
                fixture.current_policy,
                fixture.proposal.clone(),
                UnixMillis::new(fixture.millis(500)),
            )?)
            .await?;
        database
            .store()
            .retain_github_oidc_key(RetainGithubOidcKey::id_token_signing(
                fixture.signing_key.key_id().clone(),
                fixture.signing_key.key_sha256(),
                fixture.seconds(8),
                25,
                fixture.seconds(1),
            )?)
            .await?;
        let original_deadline: (i64, i64) = sqlx::query_as(
            "SELECT max_not_after_seconds, updated_at_seconds FROM github_oidc_key_deadlines WHERE key_use = 'id_token_signing' AND key_id = $1",
        )
        .bind(fixture.signing_key.key_id().as_str())
        .fetch_one(database.pool())
        .await?;
        let mut blocker = database.pool().begin().await?;
        sqlx::query(
            "SELECT 1 FROM github_oidc_key_deadlines WHERE key_use = 'id_token_signing' AND key_id = $1 FOR UPDATE",
        )
        .bind(fixture.signing_key.key_id().as_str())
        .execute(&mut *blocker)
        .await?;
        fixture.clock.set(fixture.millis(1_000));
        let service = Arc::new(oidc_service(&database, &fixture, fixture.current_policy)?);
        let bearer = fixture.bearer.expose_secret().to_owned();
        let mint_at = fixture.seconds(1);
        let mut mint = tokio::spawn(async move { service.mint(&bearer, None, mint_at).await });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut mint)
                .await
                .is_err(),
            "mint did not block on the held signing-key row"
        );
        fixture.clock.set(fixture.millis(33_500));
        blocker.commit().await?;
        let error = mint.await?.expect_err("expired mint must roll back");
        assert_eq!(error.kind(), OidcServiceErrorKind::Unauthorized);
        let slot_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM github_oidc_issuance_slots")
                .fetch_one(database.pool())
                .await?;
        assert_eq!(slot_count, 0);
        let final_deadline: (i64, i64) = sqlx::query_as(
            "SELECT max_not_after_seconds, updated_at_seconds FROM github_oidc_key_deadlines WHERE key_use = 'id_token_signing' AND key_id = $1",
        )
        .bind(fixture.signing_key.key_id().as_str())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(final_deadline, original_deadline);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn mint_slot_contention_crossing_lease_expiry_preserves_immutable_replay() -> TestResult {
    run_with_database(|database| async move {
        let fixture = durable_oidc_fixture(&database).await?;
        let authority_repository = PostgresGithubOidcAuthorityRepository::new(
            database.store().clone(),
            fixture.clock.clone(),
        );
        let authority = authority_repository
            .reserve_github_oidc_authority(ReserveGithubOidcAuthority::new(
                fixture.execution.clone(),
                fixture.current_policy,
                fixture.proposal.clone(),
                UnixMillis::new(fixture.millis(500)),
            )?)
            .await?;
        fixture.clock.set(fixture.millis(1_000));
        let service = Arc::new(oidc_service(&database, &fixture, fixture.current_policy)?);
        service
            .mint(fixture.bearer.expose_secret(), None, fixture.seconds(1))
            .await?;
        let original_slot: (i64, Uuid, i64) = sqlx::query_as(
            "SELECT generation, token_id, expires_at_seconds FROM github_oidc_issuance_slots WHERE authority_id = $1 AND requested_audience IS NULL",
        )
        .bind(authority.authority_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(original_slot.0, 1);
        assert_eq!(original_slot.2, i64::try_from(fixture.seconds(31))?);

        let mut blocker = database.pool().begin().await?;
        sqlx::query(
            "SELECT 1 FROM github_oidc_issuance_slots WHERE authority_id = $1 AND requested_audience IS NULL FOR UPDATE",
        )
        .bind(authority.authority_id().as_uuid())
        .execute(&mut *blocker)
        .await?;
        fixture.clock.set(fixture.millis(32_000));
        let bearer = fixture.bearer.expose_secret().to_owned();
        let replacement_at = fixture.seconds(32);
        let mut replacement = tokio::spawn(async move {
            service.mint(&bearer, None, replacement_at).await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut replacement)
                .await
                .is_err(),
            "replacement mint did not block on the held slot"
        );
        fixture.clock.set(fixture.millis(33_500));
        blocker.commit().await?;
        let error = replacement
            .await?
            .expect_err("expired replacement must roll back");
        assert_eq!(error.kind(), OidcServiceErrorKind::Unauthorized);
        let final_slot: (i64, Uuid, i64) = sqlx::query_as(
            "SELECT generation, token_id, expires_at_seconds FROM github_oidc_issuance_slots WHERE authority_id = $1 AND requested_audience IS NULL",
        )
        .bind(authority.authority_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(final_slot, original_slot);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn runtime_authority_insert_requires_exact_historical_standard_profile_and_pins() -> TestResult
{
    run_with_database(|database| async move {
        let (execution, manifest) = seed_current_oidc_execution(&database, true).await?;
        let execution =
            rebase_runtime_authority_lease_to_database_time(&database, execution).await?;
        let rotated_at = database_now(&database).await?;
        database
            .store()
            .bootstrap_github_provider_repository(
                github_manifest_fixture::fixture_github_repository_bootstrap(
                    rotated_credential_free_manifest(&manifest),
                    rotated_at,
                ),
            )
            .await?;

        for substitution in [
            "provider_connection",
            "provider_installation",
            "issuer_fingerprint",
            "configuration_fingerprint",
            "policy_digest",
        ] {
            let error = insert_runtime_authority_candidate(&database, &execution, substitution)
                .await
                .expect_err("a forged runtime-authority pin must be rejected");
            let constraint = if substitution == "policy_digest" {
                "github_runtime_authority_v3_execution_provenance"
            } else {
                "github_runtime_authority_v3_historical_provenance"
            };
            assert_runtime_authority_insert_rejected(&error, constraint);
            let occupied: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM github_runtime_authority_issuances \
                 WHERE attempt_id = $1 AND fencing_token = $2",
            )
            .bind(execution.attempt_id().as_uuid())
            .bind(i64::try_from(execution.fencing_token().get())?)
            .fetch_one(database.pool())
            .await?;
            assert_eq!(
                occupied, 0,
                "a rejected {substitution} substitution occupied the attempt/fence key"
            );
        }

        insert_runtime_authority_candidate(&database, &execution, "exact").await?;
        let exact: (Uuid, i64, Vec<u8>, Vec<u8>, Vec<u8>) = sqlx::query_as(
            r"
            SELECT provider_connection_id, provider_installation_id,
                   issuer_fingerprint, configuration_fingerprint, policy_digest
            FROM github_runtime_authority_issuances
            WHERE attempt_id = $1 AND fencing_token = $2
            ",
        )
        .bind(execution.attempt_id().as_uuid())
        .bind(i64::try_from(execution.fencing_token().get())?)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(exact.0, manifest.connection_id().as_uuid());
        assert_eq!(exact.1, i64::try_from(manifest.installation_id().get())?);
        assert_eq!(exact.2, manifest.app_key_spki_sha256().as_bytes());
        assert_eq!(exact.4, execution.job_ir().digest().as_bytes());
        assert_ne!(
            exact.3, exact.2,
            "configuration and issuer pins are distinct"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
async fn runtime_authority_insert_rejects_credential_free_chain_without_key_occupancy() -> TestResult
{
    run_with_database(|database| async move {
        let (execution, manifest) = seed_current_profiled_execution(
            &database,
            true,
            automata_ci_core::JobAuthorityProfile::CredentialFree,
        )
        .await?;
        let execution =
            rebase_runtime_authority_lease_to_database_time(&database, execution).await?;
        assert_eq!(
            manifest.authority_profile(),
            automata_ci_core::JobAuthorityProfile::CredentialFree
        );
        let error = insert_runtime_authority_candidate(&database, &execution, "exact")
            .await
            .expect_err("CredentialFree execution must not acquire GitHub runtime authority");
        assert_runtime_authority_insert_rejected(
            &error,
            "github_runtime_authority_v3_historical_provenance",
        );
        let occupied: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM github_runtime_authority_issuances \
             WHERE attempt_id = $1 AND fencing_token = $2",
        )
        .bind(execution.attempt_id().as_uuid())
        .bind(i64::try_from(execution.fencing_token().get())?)
        .fetch_one(database.pool())
        .await?;
        assert_eq!(occupied, 0);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL 18 and AUTOMATA_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn authority_and_issuance_are_exact_current_and_durable() -> TestResult {
    run_with_database(|database| async move {
        let fixture = durable_oidc_fixture(&database).await?;
        let rotated_at = database_now(&database).await?;
        database
            .store()
            .bootstrap_github_provider_repository(
                github_manifest_fixture::fixture_github_repository_bootstrap(
                    rotated_credential_free_manifest(&fixture.manifest),
                    rotated_at,
                ),
            )
            .await?;
        let current = database
            .store()
            .load_current_github_provider_manifest(
                fixture.manifest.tenant(),
                fixture.manifest.connection_id(),
            )
            .await?;
        assert_eq!(
            current.manifest().authority_profile(),
            automata_ci_core::JobAuthorityProfile::CredentialFree
        );
        let initial_request = ReserveGithubOidcAuthority::new(
            fixture.execution.clone(),
            fixture.current_policy,
            fixture.proposal.clone(),
            UnixMillis::new(fixture.millis(500)),
        )?;
        let left_store = PostgresGithubOidcAuthorityRepository::new(
            database.store().clone(),
            fixture.clock.clone(),
        );
        let right_store = left_store.clone();
        let (left, right) = tokio::join!(
            left_store.reserve_github_oidc_authority(initial_request.clone()),
            right_store.reserve_github_oidc_authority(initial_request),
        );
        let left = left?;
        let right = right?;
        assert_eq!(left, right);
        assert_eq!(left.authority_id(), fixture.proposal.authority_id());
        assert_eq!(
            left.request_bearer_sha256(),
            fixture.proposal.request_bearer_sha256()
        );
        let authority_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM github_oidc_authorities")
                .fetch_one(database.pool())
                .await?;
        assert_eq!(authority_count, 1);
        let (owner_id, run_evidence, permission_evidence, claims): (
            i64,
            Vec<u8>,
            Vec<u8>,
            serde_json::Value,
        ) = sqlx::query_as(
            r"
            SELECT github_owner_id, github_run_subject_evidence_sha256,
                   permission_evidence_sha256, additional_claims
            FROM github_oidc_authorities
            ",
        )
        .fetch_one(database.pool())
        .await?;
        assert_eq!(owner_id, 404);
        assert_ne!(run_evidence, permission_evidence);
        assert_eq!(
            claims,
            serde_json::json!({
                "event_name": "push",
                "ref": "refs/heads/main",
                "repository": "example/project",
                "repository_owner": "example",
                "run_attempt": "1",
                "run_number": "1",
                "runner_environment": "self-hosted",
                "sha": "1414141414141414141414141414141414141414",
                "workflow": "OIDC",
                "workflow_ref":
                    "example/project/.github/workflows/ci.yml@refs/heads/main",
                "workflow_sha": "1414141414141414141414141414141414141414"
            })
        );

        let replacement_authority_id = OidcAuthorityId::from_uuid(Uuid::new_v4())?;
        let replacement_candidate = fixture.request_keyring.issue(
            replacement_authority_id,
            fixture.seconds(0),
            fixture.seconds(98),
        )?;
        let replacement_proposal = GithubOidcAuthorityProposal::new(
            replacement_authority_id,
            fixture.request_key.key_id().clone(),
            fixture.request_key.key_sha256(),
            30,
            fixture.seconds(0),
            fixture.seconds(98),
            secret_digest(replacement_candidate.expose_secret()),
        )?;
        fixture.clock.set(fixture.millis(1_000));
        let replayed = left_store
            .reserve_github_oidc_authority(ReserveGithubOidcAuthority::new(
                fixture.execution.clone(),
                fixture.current_policy,
                replacement_proposal,
                UnixMillis::new(fixture.millis(1_000)),
            )?)
            .await?;
        assert_eq!(
            replayed, left,
            "replay must return the prior pinned tuple, not reinterpret the proposal"
        );

        let foreign_execution = GithubOidcExecutionIdentity::new(
            fixture.execution.workflow_id(),
            GithubRepositoryName::new("example/foreign")?,
            fixture.execution.run_id(),
            fixture.execution.job_id(),
            fixture.execution.lease().clone(),
            fixture.execution.session(),
            fixture.execution.slot(),
            fixture.execution.job_ir().clone(),
        )?;
        fixture.clock.set(fixture.millis(1_100));
        assert_eq!(
            left_store
                .reserve_github_oidc_authority(ReserveGithubOidcAuthority::new(
                    foreign_execution,
                    fixture.current_policy,
                    fixture.proposal.clone(),
                    UnixMillis::new(fixture.millis(1_100)),
                )?)
                .await,
            Err(GithubOidcStoreError::Conflict)
        );

        let stale_execution = GithubOidcExecutionIdentity::new(
            fixture.execution.workflow_id(),
            fixture.execution.github_repository_name().clone(),
            fixture.execution.run_id(),
            fixture.execution.job_id(),
            Lease::new(
                fixture.execution.lease().lease_id(),
                fixture.execution.attempt_id(),
                fixture.execution.runner_id(),
                FencingToken::new(8)?,
                fixture.execution.lease().issued_at(),
                fixture.execution.lease().expires_at(),
            )?,
            fixture.execution.session(),
            fixture.execution.slot(),
            fixture.execution.job_ir().clone(),
        )?;
        fixture.clock.set(fixture.millis(1_200));
        assert_eq!(
            left_store
                .reserve_github_oidc_authority(ReserveGithubOidcAuthority::new(
                    stale_execution,
                    fixture.current_policy,
                    fixture.proposal.clone(),
                    UnixMillis::new(fixture.millis(1_200)),
                )?)
                .await,
            Err(GithubOidcStoreError::Unauthorized)
        );

        let forged_lease_execution = GithubOidcExecutionIdentity::new(
            fixture.execution.workflow_id(),
            fixture.execution.github_repository_name().clone(),
            fixture.execution.run_id(),
            fixture.execution.job_id(),
            Lease::new(
                fixture.execution.lease().lease_id(),
                fixture.execution.attempt_id(),
                fixture.execution.runner_id(),
                fixture.execution.fencing_token(),
                fixture.execution.lease().issued_at(),
                UnixMillis::new(fixture.millis(34_000)),
            )?,
            fixture.execution.session(),
            fixture.execution.slot(),
            fixture.execution.job_ir().clone(),
        )?;
        fixture.clock.set(fixture.millis(1_250));
        assert_eq!(
            left_store
                .reserve_github_oidc_authority(ReserveGithubOidcAuthority::new(
                    forged_lease_execution,
                    fixture.current_policy,
                    fixture.proposal.clone(),
                    UnixMillis::new(fixture.millis(1_250)),
                )?)
                .await,
            Err(GithubOidcStoreError::Unauthorized)
        );

        let drifted_current_policy = GithubOidcCurrentPolicy::new(
            GithubOidcSubjectPolicyMode::StableOwnerEvidence,
            fixture.current_policy.subject_policy_revision(),
            fixture.current_policy.subject_policy_sha256(),
            digest(0x99),
            30,
            25,
        )?;
        fixture.clock.set(fixture.millis(1_300));
        assert_eq!(
            left_store
                .reserve_github_oidc_authority(ReserveGithubOidcAuthority::new(
                    fixture.execution.clone(),
                    drifted_current_policy,
                    fixture.proposal.clone(),
                    UnixMillis::new(fixture.millis(1_300)),
                )?)
                .await,
            Err(GithubOidcStoreError::Conflict)
        );

        let issuance_repository = PostgresGithubOidcIssuanceRepository::new(
            database.store().clone(),
            fixture.current_policy,
            [fixture.signing_key.clone()],
            fixture.clock.clone(),
        )?;
        issuance_repository
            .verify_github_oidc_key_readiness(
                fixture.seconds(1),
                std::slice::from_ref(&fixture.request_key),
            )
            .await?;
        let service = oidc_service(&database, &fixture, fixture.current_policy)?;
        fixture.clock.set(fixture.millis(1_500));
        let first = service
            .mint(fixture.bearer.expose_secret(), None, fixture.seconds(1))
            .await?;
        let first_token = first.expose_secret().to_owned();
        fixture.clock.set(fixture.millis(2_000));
        let replay = service
            .mint(fixture.bearer.expose_secret(), None, fixture.seconds(2))
            .await?;
        let replay_token = replay.expose_secret().to_owned();
        assert!(
            first_token == replay_token,
            "live issuance replay was not byte-exact"
        );

        fixture.clock.set(fixture.millis(32_000));
        let replacement = service
            .mint(fixture.bearer.expose_secret(), None, fixture.seconds(32))
            .await?;
        let replacement_token = replacement.expose_secret().to_owned();
        assert!(
            first_token != replacement_token,
            "expired issuance was not replaced"
        );
        let default_generation: i64 = sqlx::query_scalar(
            r"
            SELECT generation FROM github_oidc_issuance_slots
            WHERE authority_id = $1 AND requested_audience IS NULL
            ",
        )
        .bind(left.authority_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(default_generation, 2);

        let explicit_default = service
            .mint(
                fixture.bearer.expose_secret(),
                Some(fixture.default_audience.clone()),
                fixture.seconds(32),
            )
            .await?;
        let explicit_default_token = explicit_default.expose_secret().to_owned();
        assert!(
            replacement_token != explicit_default_token,
            "None and explicit-default audiences shared one issuance"
        );
        for index in 0_u8..62 {
            service
                .mint(
                    fixture.bearer.expose_secret(),
                    Some(OidcAudience::new(format!(
                        "store-live-audience-{index:02}"
                    ))?),
                    fixture.seconds(32),
                )
                .await?;
        }
        let slot_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM github_oidc_issuance_slots WHERE authority_id = $1",
        )
        .bind(left.authority_id().as_uuid())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(slot_count, 64);
        let default_audience_slots: i64 = sqlx::query_scalar(
            r"
            SELECT count(*) FROM github_oidc_issuance_slots
            WHERE authority_id = $1 AND resolved_audience = $2
            ",
        )
        .bind(left.authority_id().as_uuid())
        .bind(fixture.default_audience.as_str())
        .fetch_one(database.pool())
        .await?;
        assert_eq!(default_audience_slots, 2);
        let Err(exhausted) = service
            .mint(
                fixture.bearer.expose_secret(),
                Some(OidcAudience::new("store-live-audience-overflow")?),
                fixture.seconds(32),
            )
            .await
        else {
            return Err("a 65th OIDC audience slot was admitted".into());
        };
        assert_eq!(exhausted.kind(), OidcServiceErrorKind::ResourceExhausted);

        let drifted_service = oidc_service(&database, &fixture, drifted_current_policy)?;
        let Err(drifted) = drifted_service
            .mint(fixture.bearer.expose_secret(), None, fixture.seconds(32))
            .await
        else {
            return Err("configuration drift minted an OIDC token".into());
        };
        assert_eq!(drifted.kind(), OidcServiceErrorKind::Unauthorized);

        fixture.clock.set(fixture.millis(33_000));
        left_store
            .reserve_github_oidc_authority(ReserveGithubOidcAuthority::new(
                fixture.execution.clone(),
                fixture.current_policy,
                fixture.proposal.clone(),
                UnixMillis::new(fixture.millis(33_000)),
            )?)
            .await?;
        let Err(partial_second) = service
            .mint(fixture.bearer.expose_secret(), None, fixture.seconds(33))
            .await
        else {
            return Err("a lease expiring mid-second authorized that whole second".into());
        };
        assert_eq!(partial_second.kind(), OidcServiceErrorKind::Unauthorized);

        let disabled = sqlx::query(
            "UPDATE runners SET desired_state = 'disabled', updated_at_ms = $2 WHERE id = $1",
        )
        .bind(fixture.execution.runner_id().as_uuid())
        .bind(fixture.millis(33_100))
        .execute(database.pool())
        .await?;
        assert_eq!(disabled.rows_affected(), 1);
        fixture.clock.set(fixture.millis(33_100));
        assert_eq!(
            left_store
                .reserve_github_oidc_authority(ReserveGithubOidcAuthority::new(
                    fixture.execution.clone(),
                    fixture.current_policy,
                    fixture.proposal.clone(),
                    UnixMillis::new(fixture.millis(33_100)),
                )?)
                .await,
            Err(GithubOidcStoreError::Unauthorized)
        );

        let durable_rows: String = sqlx::query_scalar(
            r"
            SELECT concat(
                COALESCE((SELECT jsonb_agg(to_jsonb(authority))::TEXT
                          FROM github_oidc_authorities AS authority), ''),
                COALESCE((SELECT jsonb_agg(to_jsonb(slot))::TEXT
                          FROM github_oidc_issuance_slots AS slot), ''),
                COALESCE((SELECT jsonb_agg(to_jsonb(deadline))::TEXT
                          FROM github_oidc_key_deadlines AS deadline), '')
            )
            ",
        )
        .fetch_one(database.pool())
        .await?;
        for credential in [
            fixture.bearer.expose_secret(),
            replacement_candidate.expose_secret(),
            first_token.as_str(),
            replay_token.as_str(),
            replacement_token.as_str(),
            explicit_default_token.as_str(),
            fixture.private_key_pem.as_str(),
            TEST_PRIVATE_KEY_BODY,
            std::str::from_utf8(TEST_HMAC_SECRET)?,
        ] {
            assert!(
                !durable_rows.contains(credential),
                "OIDC credential bytes crossed the durable boundary"
            );
        }
        Ok(())
    })
    .await
}
