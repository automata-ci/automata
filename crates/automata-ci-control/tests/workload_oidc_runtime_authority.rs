use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use async_trait::async_trait;
use automata_ci_control::runner_control::{
    CompositeRuntimeAuthorityIssuer, ControlPortError, OptionalRuntimeAuthorityIssuer,
    RuntimeAuthorityIssueRequest, RuntimeAuthorityIssuer,
};
use automata_ci_control::workload_oidc::{
    ReserveWorkloadOidcRuntimeAuthority, ReservedWorkloadOidcRuntimeAuthority,
    UnavailableWorkloadOidcRuntimeAuthorityIssuer, WorkloadOidcAuthorityIdGenerator,
    WorkloadOidcAuthorityProvisioner, WorkloadOidcRuntimeAuthorityIssuer,
};
use automata_ci_core::{
    AttemptId, FencingToken, JobContentReference, JobExecutionContext, JobId, JobInstanceIdentity,
    JobIr, JobIrEnvelope, JobPermissionGrant, JobPermissionRequest, JobSource, Lease, LeaseId,
    PermissionLevel, RunId, RunValueTemplates, RunnerId, RunnerRequirements, RunnerSessionId,
    RuntimeBoolean, SemanticStep, Sha256Digest, ShellTemplate, StepId, StepIr, UnixMillis,
    ValueTemplate, WorkflowId,
};
use automata_ci_protocol::{
    JobRuntimeAuthorities, JobRuntimeAuthority, ProtocolLimits, RuntimeAuthorityCredential,
    RuntimeAuthorityEndpoint, RuntimeAuthorityName,
};
use automata_ci_protocol_protobuf::encode_job_ir;
use automata_ci_store::{
    JobIrMetadata, ObjectKey, RunnerGeneration, RunnerSessionFence, SessionEpoch, StableRunnerSlot,
};
use automata_ci_workload_oidc::{
    OidcAuthorityId, OidcIssuer, OidcKeyId, RequestBearerConfig, RequestBearerKey,
    RequestBearerKeyring, WORKLOAD_OIDC_RUNTIME_AUTHORITY_NAMESPACE,
};
use sha2::{Digest as _, Sha256};
use static_assertions::assert_obj_safe;

const ISSUED_AT_MILLIS: i64 = 1_800_000_000_999;
const ISSUED_AT_SECONDS: u64 = 1_800_000_000;
const OIDC_ISSUER: &str = "https://oidc.example.test/";
const OLD_SECRET: &[u8] = b"synthetic-old-request-key-material-at-least-thirty-two-bytes";
const NEW_SECRET: &[u8] = b"synthetic-new-request-key-material-at-least-thirty-two-bytes";

assert_obj_safe!(WorkloadOidcAuthorityIdGenerator);
assert_obj_safe!(WorkloadOidcAuthorityProvisioner);

#[tokio::test]
async fn denied_permission_matrix_declines_without_ids_or_durable_calls() {
    let authority_id = oidc_authority_id();
    let authority_ids = Arc::new(FixedAuthorityIds::new(authority_id));
    let provisioner = Arc::new(TestProvisioner::accept_proposal());
    let keyring = request_keyring(
        "request-old",
        &[("request-old", OLD_SECRET)],
        600,
        "request-issuer",
        "request-audience",
    );
    let issuer = oidc_issuer(keyring, authority_ids.clone(), provisioner.clone());

    let denied = [
        JobPermissionRequest::ProviderDefault,
        JobPermissionRequest::ReadAll,
        JobPermissionRequest::mapping([]),
        JobPermissionRequest::mapping([JobPermissionGrant::new("id-token", PermissionLevel::None)]),
        JobPermissionRequest::mapping([JobPermissionGrant::new(
            "contents",
            PermissionLevel::Write,
        )]),
        JobPermissionRequest::mapping([
            JobPermissionGrant::new("contents", PermissionLevel::Read),
            JobPermissionGrant::new("id-token", PermissionLevel::None),
        ]),
    ];
    for permission in denied {
        let fixture = Fixture::new("github", permission, Some(120));
        assert!(
            issuer
                .issue_optional(fixture.request())
                .await
                .expect("permission denial is not an error")
                .is_none()
        );
    }
    let foreign = Fixture::new("gitlab", JobPermissionRequest::WriteAll, Some(120));
    assert!(
        issuer
            .issue_optional(foreign.request())
            .await
            .expect("foreign provider denial is not an error")
            .is_none()
    );

    assert_eq!(authority_ids.calls.load(Ordering::SeqCst), 0);
    assert_eq!(provisioner.calls.load(Ordering::SeqCst), 0);
    assert!(provisioner.observations().is_empty());
}

#[tokio::test]
async fn unavailable_guard_declines_other_jobs_and_blocks_entitled_jobs() {
    let guard = UnavailableWorkloadOidcRuntimeAuthorityIssuer;
    let denied = Fixture::new("github", JobPermissionRequest::ProviderDefault, Some(120));
    assert!(
        guard
            .issue_optional(denied.request())
            .await
            .expect("an unentitled job is not an availability failure")
            .is_none()
    );

    let foreign = Fixture::new("gitlab", JobPermissionRequest::WriteAll, Some(120));
    assert!(
        guard
            .issue_optional(foreign.request())
            .await
            .expect("a foreign job is not a workload OIDC availability failure")
            .is_none()
    );

    let entitled = Fixture::new("github", JobPermissionRequest::WriteAll, Some(120));
    assert_eq!(
        guard
            .issue_optional(entitled.request())
            .await
            .expect_err("an entitled job must not run without OIDC authority"),
        ControlPortError::Unavailable
    );
}

#[tokio::test]
async fn write_permissions_emit_exact_bound_tls_authority_and_verified_bearer() {
    let permissions = [
        JobPermissionRequest::WriteAll,
        JobPermissionRequest::mapping([JobPermissionGrant::new(
            "id-token",
            PermissionLevel::Write,
        )]),
    ];

    for permission in permissions {
        let fixture = Fixture::new("github", permission, Some(120));
        let authority_id = oidc_authority_id();
        let authority_ids = Arc::new(FixedAuthorityIds::new(authority_id));
        let provisioner = Arc::new(TestProvisioner::accept_proposal());
        let keyring = request_keyring(
            "request-old",
            &[("request-old", OLD_SECRET)],
            600,
            "request-issuer",
            "request-audience",
        );
        let issuer = oidc_issuer(keyring.clone(), authority_ids.clone(), provisioner.clone());

        let bundle = issuer
            .issue_optional(fixture.request())
            .await
            .expect("issue")
            .expect("permitted authority");
        let authority = bundle
            .get(WORKLOAD_OIDC_RUNTIME_AUTHORITY_NAMESPACE)
            .expect("OIDC authority");
        let observation = provisioner.only_observation();

        assert_eq!(authority_ids.calls.load(Ordering::SeqCst), 1);
        assert_eq!(provisioner.calls.load(Ordering::SeqCst), 1);
        assert_eq!(observation.job, fixture.job);
        assert_eq!(observation.job_ir_metadata, fixture.metadata);
        assert_eq!(observation.lease, fixture.lease);
        assert_eq!(observation.issued_at, fixture.lease.issued_at());
        assert_eq!(observation.session, fixture.session);
        assert_eq!(observation.slot, fixture.slot);
        assert_eq!(observation.proposed_authority_id, authority_id);
        assert_eq!(observation.proposed_key_id.as_str(), "request-old");
        assert_eq!(observation.proposed_issued_at_seconds, ISSUED_AT_SECONDS);
        assert_eq!(
            observation.proposed_expires_at_seconds,
            ISSUED_AT_SECONDS + 120
        );
        assert_eq!(
            authority.name().as_str(),
            WORKLOAD_OIDC_RUNTIME_AUTHORITY_NAMESPACE
        );
        assert_eq!(authority.run_id(), fixture.job.job().run_id());
        assert_eq!(authority.job_id(), fixture.job.job().job_id());
        assert_eq!(authority.attempt_id(), fixture.lease.attempt_id());
        assert_eq!(authority.fencing_token(), fixture.lease.fencing_token());
        assert_eq!(authority.endpoint().as_str(), OIDC_ISSUER);
        assert_eq!(authority.issued_at(), UnixMillis::new(1_800_000_000_000));
        assert_eq!(authority.expires_at(), UnixMillis::new(1_800_000_120_000));
        assert!(authority.expires_at() > fixture.lease.expires_at());

        let credential = authority.credential().expose_secret();
        let verified = keyring
            .verify(credential, ISSUED_AT_SECONDS + 1)
            .expect("verify request bearer");
        assert_eq!(verified.authority_id(), authority_id);
        assert_eq!(verified.issued_at_seconds(), ISSUED_AT_SECONDS);
        assert_eq!(verified.expires_at_seconds(), ISSUED_AT_SECONDS + 120);
        assert_eq!(
            observation.proposed_bearer_sha256,
            digest(credential.as_bytes())
        );
        assert!(!format!("{authority:?}").contains(credential));
        assert!(!format!("{bundle:?}").contains(credential));
    }
}

#[tokio::test]
async fn horizon_uses_job_timeout_or_keyring_ceiling_never_initial_lease_expiry() {
    for (timeout, expected_lifetime) in [(Some(30), 30_u64), (Some(1_200), 600), (None, 600)] {
        let fixture = Fixture::new("github", JobPermissionRequest::WriteAll, timeout);
        let provisioner = Arc::new(TestProvisioner::accept_proposal());
        let issuer = oidc_issuer(
            request_keyring(
                "request-old",
                &[("request-old", OLD_SECRET)],
                600,
                "request-issuer",
                "request-audience",
            ),
            Arc::new(FixedAuthorityIds::new(oidc_authority_id())),
            provisioner.clone(),
        );

        let bundle = issuer
            .issue_optional(fixture.request())
            .await
            .expect("issue")
            .expect("authority");
        let authority = bundle
            .get(WORKLOAD_OIDC_RUNTIME_AUTHORITY_NAMESPACE)
            .expect("OIDC authority");
        let observation = provisioner.only_observation();

        assert_eq!(
            observation.proposed_expires_at_seconds,
            ISSUED_AT_SECONDS + expected_lifetime
        );
        assert_eq!(
            authority.expires_at(),
            UnixMillis::new(
                i64::try_from((ISSUED_AT_SECONDS + expected_lifetime) * 1_000)
                    .expect("test timestamp")
            )
        );
        assert!(authority.expires_at() > fixture.lease.expires_at());
    }
}

#[tokio::test]
async fn replay_uses_retained_key_and_digest_across_active_rotation() {
    let fixture = Fixture::new("github", JobPermissionRequest::WriteAll, Some(300));
    let durable_authority_id = oidc_authority_id();
    let first_ids = Arc::new(FixedAuthorityIds::new(durable_authority_id));
    let first_provisioner = Arc::new(TestProvisioner::accept_proposal());
    let old_keyring = request_keyring(
        "request-old",
        &[("request-old", OLD_SECRET)],
        600,
        "request-issuer",
        "request-audience",
    );
    let first = oidc_issuer(old_keyring, first_ids, first_provisioner.clone())
        .issue_optional(fixture.request())
        .await
        .expect("first issue")
        .expect("first authority");
    let first_credential = first
        .get(WORKLOAD_OIDC_RUNTIME_AUTHORITY_NAMESPACE)
        .expect("first OIDC authority")
        .credential()
        .expose_secret()
        .to_owned();
    let persisted = first_provisioner.only_observation().as_reserved();

    let replay_provisioner = Arc::new(TestProvisioner::fixed(persisted.clone()));
    let rotated = oidc_issuer(
        request_keyring(
            "request-new",
            &[("request-old", OLD_SECRET), ("request-new", NEW_SECRET)],
            600,
            "request-issuer",
            "request-audience",
        ),
        Arc::new(FixedAuthorityIds::new(oidc_authority_id())),
        replay_provisioner.clone(),
    )
    .issue_optional(fixture.request())
    .await
    .expect("rotated replay")
    .expect("rotated authority");
    let rotated_credential = rotated
        .get(WORKLOAD_OIDC_RUNTIME_AUTHORITY_NAMESPACE)
        .expect("rotated OIDC authority")
        .credential()
        .expose_secret();
    assert_eq!(rotated_credential, first_credential);
    assert_eq!(
        replay_provisioner
            .only_observation()
            .proposed_key_id
            .as_str(),
        "request-new"
    );

    let retired = oidc_issuer(
        request_keyring(
            "request-new",
            &[("request-new", NEW_SECRET)],
            600,
            "request-issuer",
            "request-audience",
        ),
        Arc::new(FixedAuthorityIds::new(oidc_authority_id())),
        Arc::new(TestProvisioner::fixed(persisted)),
    );
    assert_eq!(
        retired
            .issue_optional(fixture.request())
            .await
            .expect_err("retired replay key must fail"),
        ControlPortError::Corrupt
    );
}

#[tokio::test]
async fn replay_digest_detects_request_bearer_configuration_drift() {
    let fixture = Fixture::new("github", JobPermissionRequest::WriteAll, Some(300));
    let first_provisioner = Arc::new(TestProvisioner::accept_proposal());
    oidc_issuer(
        request_keyring(
            "request-old",
            &[("request-old", OLD_SECRET)],
            600,
            "request-issuer-a",
            "request-audience-a",
        ),
        Arc::new(FixedAuthorityIds::new(oidc_authority_id())),
        first_provisioner.clone(),
    )
    .issue_optional(fixture.request())
    .await
    .expect("first issue")
    .expect("first authority");
    let persisted = first_provisioner.only_observation().as_reserved();

    let drifted = oidc_issuer(
        request_keyring(
            "request-old",
            &[("request-old", OLD_SECRET)],
            600,
            "request-issuer-b",
            "request-audience-b",
        ),
        Arc::new(FixedAuthorityIds::new(oidc_authority_id())),
        Arc::new(TestProvisioner::fixed(persisted)),
    );
    assert_eq!(
        drifted
            .issue_optional(fixture.request())
            .await
            .expect_err("configuration drift must fail"),
        ControlPortError::Corrupt
    );
}

#[tokio::test]
async fn forged_reservations_and_provisioner_errors_fail_closed() {
    let fixture = Fixture::new("github", JobPermissionRequest::WriteAll, Some(30));
    let keyring = request_keyring(
        "request-old",
        &[("request-old", OLD_SECRET)],
        600,
        "request-issuer",
        "request-audience",
    );
    let authority_id = oidc_authority_id();
    let key_id = OidcKeyId::new("request-old").expect("key ID");
    let valid = reserved_for(
        &keyring,
        authority_id,
        key_id.clone(),
        ISSUED_AT_SECONDS,
        ISSUED_AT_SECONDS + 30,
    );
    let forged = [
        ReservedWorkloadOidcRuntimeAuthority::new(
            authority_id,
            key_id.clone(),
            ISSUED_AT_SECONDS + 1,
            ISSUED_AT_SECONDS + 30,
            valid.request_bearer_sha256(),
        ),
        ReservedWorkloadOidcRuntimeAuthority::new(
            authority_id,
            key_id.clone(),
            ISSUED_AT_SECONDS,
            ISSUED_AT_SECONDS,
            Sha256Digest::from_bytes([0; 32]),
        ),
        reserved_for(
            &keyring,
            authority_id,
            key_id.clone(),
            ISSUED_AT_SECONDS,
            ISSUED_AT_SECONDS + 31,
        ),
        ReservedWorkloadOidcRuntimeAuthority::new(
            authority_id,
            OidcKeyId::new("request-unknown").expect("unknown key ID"),
            ISSUED_AT_SECONDS,
            ISSUED_AT_SECONDS + 30,
            Sha256Digest::from_bytes([0; 32]),
        ),
        ReservedWorkloadOidcRuntimeAuthority::new(
            authority_id,
            key_id,
            ISSUED_AT_SECONDS,
            ISSUED_AT_SECONDS + 30,
            Sha256Digest::from_bytes([0x55; 32]),
        ),
    ];
    for reservation in forged {
        let issuer = oidc_issuer(
            keyring.clone(),
            Arc::new(FixedAuthorityIds::new(oidc_authority_id())),
            Arc::new(TestProvisioner::fixed(reservation)),
        );
        assert_eq!(
            issuer
                .issue_optional(fixture.request())
                .await
                .expect_err("forged reservation must fail"),
            ControlPortError::Corrupt
        );
    }

    for expected in [ControlPortError::Unavailable, ControlPortError::Conflict] {
        let issuer = oidc_issuer(
            keyring.clone(),
            Arc::new(FixedAuthorityIds::new(oidc_authority_id())),
            Arc::new(TestProvisioner::error(expected)),
        );
        assert_eq!(
            issuer
                .issue_optional(fixture.request())
                .await
                .expect_err("provisioner errors are not permission denial"),
            expected
        );
    }
}

#[tokio::test]
async fn issuer_composes_as_an_optional_authority_without_placeholder() {
    let provisioner = Arc::new(TestProvisioner::accept_proposal());
    let optional: Arc<dyn OptionalRuntimeAuthorityIssuer> = Arc::new(oidc_issuer(
        request_keyring(
            "request-old",
            &[("request-old", OLD_SECRET)],
            600,
            "request-issuer",
            "request-audience",
        ),
        Arc::new(FixedAuthorityIds::new(oidc_authority_id())),
        provisioner.clone(),
    ));
    let required: Arc<dyn RuntimeAuthorityIssuer> = Arc::new(RequiredAuthorityIssuer);
    let composite = CompositeRuntimeAuthorityIssuer::new(vec![required])
        .expect("required composite")
        .with_optional_issuers(vec![optional])
        .expect("optional composition");

    let permitted = Fixture::new("github", JobPermissionRequest::WriteAll, Some(120));
    let issued = composite
        .issue(permitted.request())
        .await
        .expect("permitted composite");
    assert_eq!(
        issued
            .as_slice()
            .iter()
            .map(|authority| authority.name().as_str())
            .collect::<Vec<_>>(),
        ["base", WORKLOAD_OIDC_RUNTIME_AUTHORITY_NAMESPACE]
    );

    let denied = Fixture::new("github", JobPermissionRequest::ProviderDefault, Some(120));
    let issued = composite
        .issue(denied.request())
        .await
        .expect("denied composite");
    assert_eq!(issued.as_slice().len(), 1);
    assert_eq!(issued.as_slice()[0].name().as_str(), "base");
    assert_eq!(provisioner.calls.load(Ordering::SeqCst), 1);
}

fn oidc_issuer(
    keyring: Arc<RequestBearerKeyring>,
    authority_ids: Arc<dyn WorkloadOidcAuthorityIdGenerator>,
    provisioner: Arc<dyn WorkloadOidcAuthorityProvisioner>,
) -> WorkloadOidcRuntimeAuthorityIssuer {
    WorkloadOidcRuntimeAuthorityIssuer::new(
        OidcIssuer::https(OIDC_ISSUER.parse().expect("OIDC issuer URL")).expect("OIDC issuer"),
        keyring,
        authority_ids,
        provisioner,
    )
    .expect("OIDC runtime-authority issuer")
}

fn request_keyring(
    active_key_id: &str,
    keys: &[(&str, &[u8])],
    maximum_lifetime_seconds: u64,
    request_issuer: &str,
    request_audience: &str,
) -> Arc<RequestBearerKeyring> {
    let active_key_id = OidcKeyId::new(active_key_id).expect("active key ID");
    let keys = keys.iter().map(|(key_id, secret)| {
        RequestBearerKey::new(OidcKeyId::new(*key_id).expect("request key ID"), secret)
            .expect("request key")
    });
    Arc::new(
        RequestBearerKeyring::new(
            RequestBearerConfig::new(
                request_issuer,
                request_audience,
                maximum_lifetime_seconds,
                0,
            )
            .expect("request bearer config"),
            active_key_id,
            keys,
        )
        .expect("request keyring"),
    )
}

fn oidc_authority_id() -> OidcAuthorityId {
    OidcAuthorityId::from_uuid(RunId::new().as_uuid()).expect("non-nil authority ID")
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn reserved_for(
    keyring: &RequestBearerKeyring,
    authority_id: OidcAuthorityId,
    key_id: OidcKeyId,
    issued_at_seconds: u64,
    expires_at_seconds: u64,
) -> ReservedWorkloadOidcRuntimeAuthority {
    let bearer = keyring
        .issue_with_key_id(&key_id, authority_id, issued_at_seconds, expires_at_seconds)
        .expect("synthetic request bearer");
    ReservedWorkloadOidcRuntimeAuthority::new(
        authority_id,
        key_id,
        issued_at_seconds,
        expires_at_seconds,
        digest(bearer.expose_secret().as_bytes()),
    )
}

#[derive(Debug)]
struct FixedAuthorityIds {
    authority_id: OidcAuthorityId,
    calls: AtomicUsize,
}

impl FixedAuthorityIds {
    const fn new(authority_id: OidcAuthorityId) -> Self {
        Self {
            authority_id,
            calls: AtomicUsize::new(0),
        }
    }
}

impl WorkloadOidcAuthorityIdGenerator for FixedAuthorityIds {
    fn next_workload_oidc_authority_id(&self) -> OidcAuthorityId {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.authority_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReservationObservation {
    job: JobIrEnvelope,
    job_ir_metadata: JobIrMetadata,
    lease: Lease,
    issued_at: UnixMillis,
    session: RunnerSessionFence,
    slot: StableRunnerSlot,
    proposed_authority_id: OidcAuthorityId,
    proposed_key_id: OidcKeyId,
    proposed_issued_at_seconds: u64,
    proposed_expires_at_seconds: u64,
    proposed_bearer_sha256: Sha256Digest,
}

impl ReservationObservation {
    fn as_reserved(&self) -> ReservedWorkloadOidcRuntimeAuthority {
        ReservedWorkloadOidcRuntimeAuthority::new(
            self.proposed_authority_id,
            self.proposed_key_id.clone(),
            self.proposed_issued_at_seconds,
            self.proposed_expires_at_seconds,
            self.proposed_bearer_sha256,
        )
    }
}

#[derive(Clone, Debug)]
enum ProvisionerResponse {
    AcceptProposal,
    Fixed(ReservedWorkloadOidcRuntimeAuthority),
    Error(ControlPortError),
}

#[derive(Debug)]
struct TestProvisioner {
    response: ProvisionerResponse,
    calls: AtomicUsize,
    observations: Mutex<Vec<ReservationObservation>>,
}

impl TestProvisioner {
    fn accept_proposal() -> Self {
        Self::new(ProvisionerResponse::AcceptProposal)
    }

    fn fixed(reservation: ReservedWorkloadOidcRuntimeAuthority) -> Self {
        Self::new(ProvisionerResponse::Fixed(reservation))
    }

    fn error(error: ControlPortError) -> Self {
        Self::new(ProvisionerResponse::Error(error))
    }

    fn new(response: ProvisionerResponse) -> Self {
        Self {
            response,
            calls: AtomicUsize::new(0),
            observations: Mutex::new(Vec::new()),
        }
    }

    fn observations(&self) -> Vec<ReservationObservation> {
        self.observations.lock().expect("observation lock").clone()
    }

    fn only_observation(&self) -> ReservationObservation {
        let observations = self.observations();
        assert_eq!(observations.len(), 1);
        observations.into_iter().next().expect("one observation")
    }
}

#[async_trait]
impl WorkloadOidcAuthorityProvisioner for TestProvisioner {
    async fn reserve_workload_oidc_runtime_authority(
        &self,
        request: ReserveWorkloadOidcRuntimeAuthority<'_>,
    ) -> Result<ReservedWorkloadOidcRuntimeAuthority, ControlPortError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let runtime = request.runtime_authority_request();
        let observation = ReservationObservation {
            job: runtime.job().clone(),
            job_ir_metadata: runtime.job_ir_metadata().clone(),
            lease: runtime.lease().clone(),
            issued_at: runtime.issued_at(),
            session: runtime.session(),
            slot: runtime.slot(),
            proposed_authority_id: request.proposed_authority_id(),
            proposed_key_id: request.proposed_request_bearer_key_id().clone(),
            proposed_issued_at_seconds: request.proposed_issued_at_seconds(),
            proposed_expires_at_seconds: request.proposed_expires_at_seconds(),
            proposed_bearer_sha256: request.proposed_request_bearer_sha256(),
        };
        self.observations
            .lock()
            .expect("observation lock")
            .push(observation.clone());
        match &self.response {
            ProvisionerResponse::AcceptProposal => Ok(observation.as_reserved()),
            ProvisionerResponse::Fixed(reservation) => Ok(reservation.clone()),
            ProvisionerResponse::Error(error) => Err(*error),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct RequiredAuthorityIssuer;

#[async_trait]
impl RuntimeAuthorityIssuer for RequiredAuthorityIssuer {
    async fn issue(
        &self,
        request: RuntimeAuthorityIssueRequest<'_>,
    ) -> Result<JobRuntimeAuthorities, ControlPortError> {
        let authority = JobRuntimeAuthority::new(
            RuntimeAuthorityName::new("base").map_err(|_| ControlPortError::Corrupt)?,
            request.job().job().run_id(),
            request.job().job().job_id(),
            request.lease().attempt_id(),
            request.lease().fencing_token(),
            RuntimeAuthorityEndpoint::new("https://base.example.test/")
                .map_err(|_| ControlPortError::Corrupt)?,
            RuntimeAuthorityCredential::new("synthetic-base-token")
                .map_err(|_| ControlPortError::Corrupt)?,
            request.lease().issued_at(),
            request.lease().expires_at(),
        )
        .map_err(|_| ControlPortError::Corrupt)?;
        JobRuntimeAuthorities::new(
            vec![authority],
            automata_ci_core::SandboxAuthorizations::empty(),
            request.job(),
            request.lease(),
        )
        .map_err(|_| ControlPortError::Corrupt)
    }
}

struct Fixture {
    job: JobIrEnvelope,
    metadata: JobIrMetadata,
    lease: Lease,
    session: RunnerSessionFence,
    slot: StableRunnerSlot,
}

impl Fixture {
    fn new(
        provider: &str,
        permission_request: JobPermissionRequest,
        timeout_seconds: Option<u32>,
    ) -> Self {
        let runner_id = RunnerId::new();
        let mut job = JobIr::new(
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
        .with_permission_request(permission_request)
        .with_trust_snapshot(crate::runner_control_support::trusted_snapshot());
        if let Some(timeout_seconds) = timeout_seconds {
            job = job.with_timeout_seconds(timeout_seconds);
        }
        let job = JobIrEnvelope::new(
            WorkflowId::new(),
            JobSource::new(
                provider,
                "example/repository",
                automata_ci_core::GitObjectId::from_provider_hex(
                    "0123456789abcdef0123456789abcdef01234567",
                )
                .expect("revision"),
                ".ci/workflows/verify.yml",
                "push",
            ),
            JobExecutionContext::new(
                "CI",
                "refs/heads/main",
                "/__w/repository/repository",
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
            job,
        );
        job.validate().expect("valid current JobIR");
        let lease = Lease::new(
            LeaseId::new(),
            AttemptId::new(),
            runner_id,
            FencingToken::new(7).expect("fence"),
            UnixMillis::new(ISSUED_AT_MILLIS),
            UnixMillis::new(ISSUED_AT_MILLIS + 6_000),
        )
        .expect("lease");
        let encoded = encode_job_ir(&job, &ProtocolLimits::default()).expect("canonical JobIR");
        let metadata = JobIrMetadata::new(
            job.job().job_id(),
            job.job().run_id(),
            job.version(),
            u64::try_from(encoded.len()).expect("bounded JobIR size"),
            digest(&encoded),
            ObjectKey::new("job-ir/oidc-control.pb").expect("object key"),
        )
        .expect("metadata");
        let session = RunnerSessionFence::new(
            RunnerSessionId::new(),
            runner_id,
            RunnerGeneration::new(2).expect("runner generation"),
            SessionEpoch::new(3).expect("session epoch"),
        );
        Self {
            job,
            metadata,
            lease,
            session,
            slot: StableRunnerSlot::new(1).expect("runner slot"),
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
        .expect("runtime-authority request")
    }
}
