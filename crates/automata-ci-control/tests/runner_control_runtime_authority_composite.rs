use std::{fmt, sync::Arc};

use async_trait::async_trait;
use automata_ci_control::runner_control::{
    CompositeRuntimeAuthorityIssuer, ControlPortError, OptionalRuntimeAuthorityIssuer,
    RuntimeAuthorityIssueRequest, RuntimeAuthorityIssueRequestError, RuntimeAuthorityIssuer,
};
use automata_ci_core::{
    AttemptId, FencingToken, JobContentReference, JobExecutionContext, JobId, JobInstanceIdentity,
    JobIr, JobIrEnvelope, JobSource, Lease, LeaseId, RunId, RunValueTemplates, RunnerId,
    RunnerRequirements, RunnerSessionId, RuntimeBoolean, SemanticStep, Sha256Digest, ShellTemplate,
    StepId, StepIr, UnixMillis, ValueTemplate, WorkflowId,
};
use automata_ci_protocol::{
    JobRuntimeAuthorities, JobRuntimeAuthority, MAX_RUNTIME_AUTHORITIES, ProtocolLimits,
    RuntimeAuthorityCredential, RuntimeAuthorityEndpoint, RuntimeAuthorityName,
};
use automata_ci_protocol_protobuf::encode_job_ir;
use automata_ci_store::{
    JobIrMetadata, ObjectKey, RunnerGeneration, RunnerSessionFence, SessionEpoch, StableRunnerSlot,
};
use sha2::{Digest as _, Sha256};

#[tokio::test]
async fn merge_is_canonical_and_independent_of_composition_order() {
    let fixture = Fixture::new();
    let alpha: Arc<dyn RuntimeAuthorityIssuer> = Arc::new(DerivedIssuer::new("alpha", "token-a"));
    let zulu: Arc<dyn RuntimeAuthorityIssuer> = Arc::new(DerivedIssuer::new("zulu", "token-z"));
    let forward =
        CompositeRuntimeAuthorityIssuer::new(vec![zulu.clone(), alpha.clone()]).expect("composite");
    let reverse =
        CompositeRuntimeAuthorityIssuer::new(vec![alpha, zulu]).expect("reverse composite");

    let request = fixture.request();
    let forward = forward.issue(request).await.expect("forward issue");
    let reverse = reverse.issue(request).await.expect("reverse issue");

    assert_eq!(forward, reverse);
    assert_eq!(
        forward
            .as_slice()
            .iter()
            .map(|authority| authority.name().as_str())
            .collect::<Vec<_>>(),
        ["alpha", "zulu"]
    );
    assert!(!format!("{forward:?}").contains("token-a"));
    assert!(!format!("{forward:?}").contains("token-z"));
}

#[tokio::test]
async fn optional_issuers_can_decline_without_placeholder_authority() {
    let fixture = Fixture::new();
    let required: Arc<dyn RuntimeAuthorityIssuer> =
        Arc::new(DerivedIssuer::new("required", "required-token"));
    let optional: Arc<dyn OptionalRuntimeAuthorityIssuer> = Arc::new(DecliningIssuer);
    let composite = CompositeRuntimeAuthorityIssuer::new(vec![required])
        .expect("composite")
        .with_optional_issuers(vec![optional])
        .expect("optional composition");

    let issued = composite.issue(fixture.request()).await.expect("issue");
    assert_eq!(issued.as_slice().len(), 1);
    assert_eq!(issued.as_slice()[0].name().as_str(), "required");
}

#[tokio::test]
async fn optional_contributions_are_revalidated_and_merged_canonically() {
    let fixture = Fixture::new();
    let required: Arc<dyn RuntimeAuthorityIssuer> =
        Arc::new(DerivedIssuer::new("zulu", "required-token"));
    let optional: Arc<dyn OptionalRuntimeAuthorityIssuer> = Arc::new(OptionalDerivedIssuer(
        DerivedIssuer::new("alpha", "optional-token"),
    ));
    let composite = CompositeRuntimeAuthorityIssuer::new(vec![required])
        .expect("composite")
        .with_optional_issuers(vec![optional])
        .expect("optional composition");

    let issued = composite.issue(fixture.request()).await.expect("issue");
    assert_eq!(
        issued
            .as_slice()
            .iter()
            .map(|authority| authority.name().as_str())
            .collect::<Vec<_>>(),
        ["alpha", "zulu"]
    );
}

#[tokio::test]
async fn optional_duplicate_and_foreign_bundles_fail_closed() {
    let fixture = Fixture::new();
    let required: Arc<dyn RuntimeAuthorityIssuer> =
        Arc::new(DerivedIssuer::new("shared", "required-token"));
    let duplicate: Arc<dyn OptionalRuntimeAuthorityIssuer> = Arc::new(OptionalDerivedIssuer(
        DerivedIssuer::new("shared", "optional-token"),
    ));
    let duplicate_composite = CompositeRuntimeAuthorityIssuer::new(vec![required])
        .expect("composite")
        .with_optional_issuers(vec![duplicate])
        .expect("optional composition");
    assert_eq!(
        duplicate_composite
            .issue(fixture.request())
            .await
            .unwrap_err(),
        ControlPortError::Corrupt
    );

    let foreign = Fixture::new();
    let foreign_request = fixture
        .request_with(
            &foreign.job,
            &foreign.metadata,
            &fixture.lease,
            fixture.lease.issued_at(),
            fixture.session,
        )
        .expect("foreign job request on the same lease");
    let foreign_bundle = DerivedIssuer::new("optional", "foreign-token")
        .issue(foreign_request)
        .await
        .expect("foreign bundle");
    let required: Arc<dyn RuntimeAuthorityIssuer> =
        Arc::new(DerivedIssuer::new("required", "required-token"));
    let optional: Arc<dyn OptionalRuntimeAuthorityIssuer> =
        Arc::new(FixedOptionalIssuer(foreign_bundle));
    let foreign_composite = CompositeRuntimeAuthorityIssuer::new(vec![required])
        .expect("composite")
        .with_optional_issuers(vec![optional])
        .expect("optional composition");
    assert_eq!(
        foreign_composite
            .issue(fixture.request())
            .await
            .unwrap_err(),
        ControlPortError::Corrupt
    );
}

#[tokio::test]
async fn optional_stale_lease_bundle_fails_closed() {
    let fixture = Fixture::new();
    let stale_lease = Lease::new(
        fixture.lease.lease_id(),
        fixture.lease.attempt_id(),
        fixture.lease.runner_id(),
        FencingToken::new(fixture.lease.fencing_token().get() + 1).expect("stale fence"),
        fixture.lease.issued_at(),
        fixture.lease.expires_at(),
    )
    .expect("stale lease");
    let stale_bundle = DerivedIssuer::new("optional", "stale-token")
        .issue(fixture.request_for(&stale_lease))
        .await
        .expect("stale bundle");
    let required: Arc<dyn RuntimeAuthorityIssuer> =
        Arc::new(DerivedIssuer::new("required", "required-token"));
    let optional: Arc<dyn OptionalRuntimeAuthorityIssuer> =
        Arc::new(FixedOptionalIssuer(stale_bundle));
    let composite = CompositeRuntimeAuthorityIssuer::new(vec![required])
        .expect("composite")
        .with_optional_issuers(vec![optional])
        .expect("optional composition");

    assert_eq!(
        composite.issue(fixture.request()).await.unwrap_err(),
        ControlPortError::Corrupt
    );
}

#[tokio::test]
async fn optional_oversized_merge_fails_closed() {
    let fixture = Fixture::new();
    let request = fixture.request();
    let optional_authorities = (0..MAX_RUNTIME_AUTHORITIES)
        .map(|index| {
            JobRuntimeAuthority::new(
                RuntimeAuthorityName::new(format!("optional-{index:02}")).expect("authority name"),
                request.job().job().run_id(),
                request.job().job().job_id(),
                request.lease().attempt_id(),
                request.lease().fencing_token(),
                RuntimeAuthorityEndpoint::new("https://authority.example.test/")
                    .expect("authority endpoint"),
                RuntimeAuthorityCredential::new(format!("optional-token-{index:02}"))
                    .expect("authority credential"),
                request.lease().issued_at(),
                request.lease().expires_at(),
            )
            .expect("authority")
        })
        .collect::<Vec<_>>();
    let optional_bundle =
        JobRuntimeAuthorities::new(optional_authorities, request.job(), request.lease())
            .expect("maximum-sized optional bundle");
    let required: Arc<dyn RuntimeAuthorityIssuer> =
        Arc::new(DerivedIssuer::new("required", "required-token"));
    let optional: Arc<dyn OptionalRuntimeAuthorityIssuer> =
        Arc::new(FixedOptionalIssuer(optional_bundle));
    let composite = CompositeRuntimeAuthorityIssuer::new(vec![required])
        .expect("composite")
        .with_optional_issuers(vec![optional])
        .expect("optional composition");

    assert_eq!(
        composite.issue(fixture.request()).await.unwrap_err(),
        ControlPortError::Corrupt
    );
}

#[tokio::test]
async fn optional_issuer_errors_are_not_treated_as_denial() {
    let fixture = Fixture::new();
    let required: Arc<dyn RuntimeAuthorityIssuer> =
        Arc::new(DerivedIssuer::new("required", "required-token"));
    let optional: Arc<dyn OptionalRuntimeAuthorityIssuer> = Arc::new(FailingOptionalIssuer);
    let composite = CompositeRuntimeAuthorityIssuer::new(vec![required])
        .expect("composite")
        .with_optional_issuers(vec![optional])
        .expect("optional composition");

    assert_eq!(
        composite.issue(fixture.request()).await.unwrap_err(),
        ControlPortError::Unavailable
    );
}

#[tokio::test]
async fn duplicate_authority_names_fail_closed() {
    let fixture = Fixture::new();
    let left: Arc<dyn RuntimeAuthorityIssuer> =
        Arc::new(DerivedIssuer::new("repository", "left-token"));
    let right: Arc<dyn RuntimeAuthorityIssuer> =
        Arc::new(DerivedIssuer::new("repository", "right-token"));
    let composite = CompositeRuntimeAuthorityIssuer::new(vec![left, right]).expect("composite");

    assert_eq!(
        composite.issue(fixture.request()).await.unwrap_err(),
        ControlPortError::Corrupt
    );
}

#[tokio::test]
async fn child_bundle_is_revalidated_against_the_exact_job_and_fence() {
    let expected = Fixture::new();
    let foreign_job = Fixture::new();
    let foreign_bundle = DerivedIssuer::new("foreign", "foreign-token")
        .issue(foreign_job.request())
        .await
        .expect("foreign bundle");
    let foreign: Arc<dyn RuntimeAuthorityIssuer> = Arc::new(FixedIssuer(foreign_bundle));
    let composite = CompositeRuntimeAuthorityIssuer::new(vec![foreign]).expect("composite");
    assert_eq!(
        composite.issue(expected.request()).await.unwrap_err(),
        ControlPortError::Corrupt
    );

    let stale_fence =
        FencingToken::new(expected.lease.fencing_token().get() + 1).expect("different fence");
    let stale_lease = Lease::new(
        expected.lease.lease_id(),
        expected.lease.attempt_id(),
        expected.lease.runner_id(),
        stale_fence,
        expected.lease.issued_at(),
        expected.lease.expires_at(),
    )
    .expect("stale lease");
    let stale_bundle = DerivedIssuer::new("stale", "stale-token")
        .issue(expected.request_for(&stale_lease))
        .await
        .expect("stale bundle");
    let stale: Arc<dyn RuntimeAuthorityIssuer> = Arc::new(FixedIssuer(stale_bundle));
    let composite = CompositeRuntimeAuthorityIssuer::new(vec![stale]).expect("composite");
    assert_eq!(
        composite.issue(expected.request()).await.unwrap_err(),
        ControlPortError::Corrupt
    );
}

#[test]
fn request_is_current_only_and_cross_binds_every_execution_coordinate() {
    let fixture = Fixture::new();
    let request = fixture.request();
    assert_eq!(request.job(), &fixture.job);
    assert_eq!(request.job_ir_metadata(), &fixture.metadata);
    assert_eq!(request.lease(), &fixture.lease);
    assert_eq!(request.issued_at(), fixture.lease.issued_at());
    assert_eq!(request.session(), fixture.session);
    assert_eq!(request.slot(), fixture.slot);

    let mismatched_metadata = JobIrMetadata::new(
        JobId::new(),
        fixture.job.job().run_id(),
        fixture.job.version(),
        fixture.metadata.encoded_size(),
        fixture.metadata.digest(),
        fixture.metadata.object_key().clone(),
    )
    .expect("bounded mismatched metadata");
    assert_eq!(
        fixture.request_with(
            &fixture.job,
            &mismatched_metadata,
            &fixture.lease,
            fixture.lease.issued_at(),
            fixture.session,
        ),
        Err(RuntimeAuthorityIssueRequestError::JobIrMetadataMismatch)
    );

    let mismatched_digest = JobIrMetadata::new(
        fixture.job.job().job_id(),
        fixture.job.job().run_id(),
        fixture.job.version(),
        fixture.metadata.encoded_size(),
        Sha256Digest::from_bytes([0x99; 32]),
        fixture.metadata.object_key().clone(),
    )
    .expect("bounded mismatched digest metadata");
    assert_eq!(
        fixture.request_with(
            &fixture.job,
            &mismatched_digest,
            &fixture.lease,
            fixture.lease.issued_at(),
            fixture.session,
        ),
        Err(RuntimeAuthorityIssueRequestError::JobIrMetadataMismatch)
    );

    let foreign_session = RunnerSessionFence::new(
        fixture.session.session_id(),
        RunnerId::new(),
        fixture.session.runner_generation(),
        fixture.session.session_epoch(),
    );
    assert_eq!(
        fixture.request_with(
            &fixture.job,
            &fixture.metadata,
            &fixture.lease,
            fixture.lease.issued_at(),
            foreign_session,
        ),
        Err(RuntimeAuthorityIssueRequestError::LeaseRunnerMismatch)
    );
    assert_eq!(
        fixture.request_with(
            &fixture.job,
            &fixture.metadata,
            &fixture.lease,
            UnixMillis::new(fixture.lease.issued_at().get() + 1),
            fixture.session,
        ),
        Err(RuntimeAuthorityIssueRequestError::InvalidIssuanceAnchor)
    );

    let mut noncurrent = serde_json::to_value(&fixture.job).expect("serialize JobIR");
    noncurrent["schema_version"] = serde_json::json!(4);
    let noncurrent: JobIrEnvelope =
        serde_json::from_value(noncurrent).expect("deserialize historical envelope");
    assert_eq!(
        fixture.request_with(
            &noncurrent,
            &fixture.metadata,
            &fixture.lease,
            fixture.lease.issued_at(),
            fixture.session,
        ),
        Err(RuntimeAuthorityIssueRequestError::UnsupportedJobIr)
    );
}

#[derive(Clone, Debug)]
struct DerivedIssuer {
    name: &'static str,
    token: &'static str,
}

impl DerivedIssuer {
    const fn new(name: &'static str, token: &'static str) -> Self {
        Self { name, token }
    }
}

#[async_trait]
impl RuntimeAuthorityIssuer for DerivedIssuer {
    async fn issue(
        &self,
        request: RuntimeAuthorityIssueRequest<'_>,
    ) -> Result<JobRuntimeAuthorities, ControlPortError> {
        let authority = JobRuntimeAuthority::new(
            RuntimeAuthorityName::new(self.name).map_err(|_| ControlPortError::Corrupt)?,
            request.job().job().run_id(),
            request.job().job().job_id(),
            request.lease().attempt_id(),
            request.lease().fencing_token(),
            RuntimeAuthorityEndpoint::new("https://authority.example.test/")
                .map_err(|_| ControlPortError::Corrupt)?,
            RuntimeAuthorityCredential::new(self.token).map_err(|_| ControlPortError::Corrupt)?,
            request.lease().issued_at(),
            request.lease().expires_at(),
        )
        .map_err(|_| ControlPortError::Corrupt)?;
        JobRuntimeAuthorities::new(vec![authority], request.job(), request.lease())
            .map_err(|_| ControlPortError::Corrupt)
    }
}

#[derive(Clone)]
struct FixedIssuer(JobRuntimeAuthorities);

impl fmt::Debug for FixedIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FixedIssuer([REDACTED])")
    }
}

#[async_trait]
impl RuntimeAuthorityIssuer for FixedIssuer {
    async fn issue(
        &self,
        _request: RuntimeAuthorityIssueRequest<'_>,
    ) -> Result<JobRuntimeAuthorities, ControlPortError> {
        Ok(self.0.clone())
    }
}

#[derive(Clone, Copy, Debug)]
struct DecliningIssuer;

#[async_trait]
impl OptionalRuntimeAuthorityIssuer for DecliningIssuer {
    async fn issue_optional(
        &self,
        _request: RuntimeAuthorityIssueRequest<'_>,
    ) -> Result<Option<JobRuntimeAuthorities>, ControlPortError> {
        Ok(None)
    }
}

#[derive(Clone, Debug)]
struct OptionalDerivedIssuer(DerivedIssuer);

#[async_trait]
impl OptionalRuntimeAuthorityIssuer for OptionalDerivedIssuer {
    async fn issue_optional(
        &self,
        request: RuntimeAuthorityIssueRequest<'_>,
    ) -> Result<Option<JobRuntimeAuthorities>, ControlPortError> {
        self.0.issue(request).await.map(Some)
    }
}

#[derive(Clone)]
struct FixedOptionalIssuer(JobRuntimeAuthorities);

impl fmt::Debug for FixedOptionalIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FixedOptionalIssuer([REDACTED])")
    }
}

#[async_trait]
impl OptionalRuntimeAuthorityIssuer for FixedOptionalIssuer {
    async fn issue_optional(
        &self,
        _request: RuntimeAuthorityIssueRequest<'_>,
    ) -> Result<Option<JobRuntimeAuthorities>, ControlPortError> {
        Ok(Some(self.0.clone()))
    }
}

#[derive(Clone, Copy, Debug)]
struct FailingOptionalIssuer;

#[async_trait]
impl OptionalRuntimeAuthorityIssuer for FailingOptionalIssuer {
    async fn issue_optional(
        &self,
        _request: RuntimeAuthorityIssueRequest<'_>,
    ) -> Result<Option<JobRuntimeAuthorities>, ControlPortError> {
        Err(ControlPortError::Unavailable)
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
    fn new() -> Self {
        let runner_id = RunnerId::new();
        let job = JobIrEnvelope::new(
            WorkflowId::new(),
            JobSource::new(
                "github",
                "automata-ci/automata",
                "0123456789abcdef0123456789abcdef01234567",
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
                    ValueTemplate::literal("Verify").expect("step name template"),
                    RuntimeBoolean::literal(false),
                    SemanticStep::run(RunValueTemplates::new(
                        ValueTemplate::literal("cargo test").expect("command template"),
                        ShellTemplate::default_shell(),
                    )),
                )],
            )
            .with_trust_snapshot(crate::runner_control_support::trusted_snapshot()),
        );
        let lease = Lease::new(
            LeaseId::new(),
            AttemptId::new(),
            runner_id,
            FencingToken::new(1).expect("fence"),
            UnixMillis::new(1_800_000_000_000),
            UnixMillis::new(1_800_000_600_000),
        )
        .expect("lease");
        let encoded = encode_job_ir(&job, &ProtocolLimits::default()).expect("canonical JobIR");
        let metadata = JobIrMetadata::new(
            job.job().job_id(),
            job.job().run_id(),
            job.version(),
            u64::try_from(encoded.len()).expect("bounded JobIR size"),
            Sha256Digest::from_bytes(Sha256::digest(encoded).into()),
            ObjectKey::new("job-ir/runtime-authority.pb").expect("object key"),
        )
        .expect("metadata");
        let session = RunnerSessionFence::new(
            RunnerSessionId::new(),
            runner_id,
            RunnerGeneration::new(2).expect("runner generation"),
            SessionEpoch::new(3).expect("session epoch"),
        );
        let slot = StableRunnerSlot::new(1).expect("runner slot");
        Self {
            job,
            metadata,
            lease,
            session,
            slot,
        }
    }

    fn request(&self) -> RuntimeAuthorityIssueRequest<'_> {
        self.request_for(&self.lease)
    }

    fn request_for<'a>(&'a self, lease: &'a Lease) -> RuntimeAuthorityIssueRequest<'a> {
        self.request_with(
            &self.job,
            &self.metadata,
            lease,
            lease.issued_at(),
            self.session,
        )
        .expect("valid authority request")
    }

    fn request_with<'a>(
        &self,
        job: &'a JobIrEnvelope,
        metadata: &'a JobIrMetadata,
        lease: &'a Lease,
        issued_at: UnixMillis,
        session: RunnerSessionFence,
    ) -> Result<RuntimeAuthorityIssueRequest<'a>, RuntimeAuthorityIssueRequestError> {
        RuntimeAuthorityIssueRequest::new(job, metadata, lease, issued_at, session, self.slot)
    }
}
