use automata_ci_core::{OperationId, RunId, Sha256Digest, UnixMillis, WorkflowId, WorkflowJobKey};
use automata_ci_store::{
    AdmissionObject, AdmissionRepository, AdmitLogicalWorkflowRun, AdmittedLogicalWorkflowJob,
    LOGICAL_ORCHESTRATION_SCHEMA, LogicalWorkflowAdmissionValueError, LogicalWorkflowInvocationId,
    LogicalWorkflowJobId, LogicalWorkflowJobKind, ObjectKey, RepositoryId, TenantScope,
    WORKFLOW_ADMISSION_EPOCH, WORKFLOW_PLAN_SCHEMA, WorkflowAdmissionIdempotency,
    WorkflowSnapshotId,
};
use uuid::Uuid;

fn object(name: &str, digest: u8) -> AdmissionObject {
    AdmissionObject::new(
        Sha256Digest::from_bytes([digest; 32]),
        ObjectKey::new(format!("logical-tests/{name}")).expect("object key"),
        512,
        "application/json",
    )
    .expect("admission object")
}

fn job(
    id: LogicalWorkflowJobId,
    key: &str,
    order: u16,
    kind: LogicalWorkflowJobKind,
    needs: Vec<LogicalWorkflowJobId>,
) -> AdmittedLogicalWorkflowJob {
    AdmittedLogicalWorkflowJob::new(
        id,
        WorkflowJobKey::new(key).expect("job key"),
        order,
        kind,
        needs,
    )
    .expect("logical job")
}

fn command(
    jobs: Vec<AdmittedLogicalWorkflowJob>,
) -> Result<AdmitLogicalWorkflowRun, LogicalWorkflowAdmissionValueError> {
    AdmitLogicalWorkflowRun::builder(
        TenantScope::from_authenticated_tenant_id("logical-tenant").expect("tenant"),
        WorkflowAdmissionIdempotency::provider_delivery("delivery-42").expect("idempotency"),
        Sha256Digest::from_bytes([42; 32]),
        AdmissionRepository::new(
            RepositoryId::from_uuid(Uuid::from_u128(1)),
            "forge",
            "repository-7",
            "sample-owner",
            "sample-repository",
        )
        .expect("repository"),
        WorkflowId::from_uuid(Uuid::from_u128(2)),
        ".ci/workflows/build.yml",
        "Build",
        "refs/heads/main",
        WorkflowSnapshotId::from_uuid(Uuid::from_u128(3)),
        object("source", 1),
        object("plan-v2", 2),
        RunId::from_uuid(Uuid::from_u128(4)),
        1,
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(5)).expect("root invocation"),
        "push",
        object("event", 3),
        vec![9; 20],
        jobs,
        UnixMillis::new(1_000),
    )
    .actor("sample-actor")
    .display_title("Synthetic build")
    .commit_subject("Exercise logical admission")
    .build()
}

#[test]
fn current_contract_retains_root_and_source_ordered_logical_graph() {
    let prepare_id =
        LogicalWorkflowJobId::from_uuid(Uuid::from_u128(10)).expect("prepare identity");
    let verify_id = LogicalWorkflowJobId::from_uuid(Uuid::from_u128(11)).expect("verify identity");
    let admitted = command(vec![
        job(
            prepare_id,
            "prepare",
            0,
            LogicalWorkflowJobKind::Steps,
            Vec::new(),
        ),
        job(
            verify_id,
            "verify",
            1,
            LogicalWorkflowJobKind::ReusableWorkflow,
            vec![prepare_id],
        ),
    ])
    .expect("valid logical admission");

    assert_eq!(WORKFLOW_ADMISSION_EPOCH, 4);
    assert_eq!(WORKFLOW_PLAN_SCHEMA, 2);
    assert_eq!(LOGICAL_ORCHESTRATION_SCHEMA, 1);
    assert_eq!(admitted.run_attempt(), 1);
    assert_eq!(admitted.root_invocation_id().as_uuid(), Uuid::from_u128(5));
    assert_eq!(admitted.jobs()[1].key().as_str(), "verify");
    assert_eq!(admitted.jobs()[1].source_order(), 1);
    assert_eq!(
        admitted.jobs()[1].kind(),
        LogicalWorkflowJobKind::ReusableWorkflow
    );
    assert_eq!(admitted.jobs()[1].prerequisites(), &[prepare_id]);
    assert_eq!(admitted.actor(), Some("sample-actor"));
    assert_eq!(admitted.display_title(), Some("Synthetic build"));
    assert_eq!(
        admitted.commit_subject(),
        Some("Exercise logical admission")
    );
}

#[test]
fn durable_logical_identities_reject_nil_sentinels() {
    assert!(matches!(
        LogicalWorkflowInvocationId::from_uuid(Uuid::nil()),
        Err(LogicalWorkflowAdmissionValueError::NilUuid(
            "logical workflow invocation ID"
        ))
    ));
    assert!(matches!(
        LogicalWorkflowJobId::from_uuid(Uuid::nil()),
        Err(LogicalWorkflowAdmissionValueError::NilUuid(
            "logical workflow job ID"
        ))
    ));

    let only = LogicalWorkflowJobId::from_uuid(Uuid::from_u128(20)).expect("job identity");
    let built = AdmitLogicalWorkflowRun::builder(
        TenantScope::from_authenticated_tenant_id("logical-tenant").expect("tenant"),
        WorkflowAdmissionIdempotency::provider_delivery("delivery-nil").expect("idempotency"),
        Sha256Digest::from_bytes([42; 32]),
        AdmissionRepository::new(
            RepositoryId::from_uuid(Uuid::from_u128(21)),
            "forge",
            "repository-nil",
            "sample-owner",
            "sample-repository",
        )
        .expect("repository"),
        WorkflowId::from_uuid(Uuid::from_u128(22)),
        ".ci/workflows/build.yml",
        "Build",
        "refs/heads/main",
        WorkflowSnapshotId::from_uuid(Uuid::from_u128(23)),
        object("nil-source", 1),
        object("nil-plan", 2),
        RunId::from_uuid(Uuid::nil()),
        1,
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(24)).expect("root"),
        "push",
        object("nil-event", 3),
        vec![9; 20],
        vec![job(
            only,
            "only",
            0,
            LogicalWorkflowJobKind::Steps,
            Vec::new(),
        )],
        UnixMillis::new(1_000),
    )
    .build();
    assert!(matches!(
        built,
        Err(LogicalWorkflowAdmissionValueError::NilUuid(
            "workflow run ID"
        ))
    ));

    let only = LogicalWorkflowJobId::from_uuid(Uuid::from_u128(25)).expect("job identity");
    let nil_operation = AdmitLogicalWorkflowRun::builder(
        TenantScope::from_authenticated_tenant_id("logical-tenant").expect("tenant"),
        WorkflowAdmissionIdempotency::operation(OperationId::from_uuid(Uuid::nil())),
        Sha256Digest::from_bytes([43; 32]),
        AdmissionRepository::new(
            RepositoryId::from_uuid(Uuid::from_u128(26)),
            "forge",
            "repository-operation",
            "sample-owner",
            "sample-repository",
        )
        .expect("repository"),
        WorkflowId::from_uuid(Uuid::from_u128(27)),
        ".ci/workflows/build.yml",
        "Build",
        "refs/heads/main",
        WorkflowSnapshotId::from_uuid(Uuid::from_u128(28)),
        object("operation-source", 1),
        object("operation-plan", 2),
        RunId::from_uuid(Uuid::from_u128(29)),
        1,
        LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(30)).expect("root"),
        "push",
        object("operation-event", 3),
        vec![9; 20],
        vec![job(
            only,
            "only",
            0,
            LogicalWorkflowJobKind::Steps,
            Vec::new(),
        )],
        UnixMillis::new(1_000),
    )
    .build();
    assert!(matches!(
        nil_operation,
        Err(LogicalWorkflowAdmissionValueError::NilUuid(
            "workflow admission operation ID"
        ))
    ));
}

#[test]
fn graph_validation_rejects_noncanonical_and_ambiguous_edges() {
    let first = LogicalWorkflowJobId::from_uuid(Uuid::from_u128(30)).expect("first");
    let second = LogicalWorkflowJobId::from_uuid(Uuid::from_u128(31)).expect("second");
    let outside = LogicalWorkflowJobId::from_uuid(Uuid::from_u128(32)).expect("outside");

    assert!(matches!(
        command(vec![job(
            first,
            "first",
            1,
            LogicalWorkflowJobKind::Steps,
            Vec::new(),
        )]),
        Err(LogicalWorkflowAdmissionValueError::InvalidSourceOrder)
    ));
    assert!(matches!(
        command(vec![
            job(first, "first", 0, LogicalWorkflowJobKind::Steps, Vec::new(),),
            job(
                second,
                "second",
                1,
                LogicalWorkflowJobKind::Steps,
                vec![outside],
            ),
        ]),
        Err(LogicalWorkflowAdmissionValueError::UnknownDependency)
    ));
    assert!(matches!(
        command(vec![
            job(first, "first", 0, LogicalWorkflowJobKind::Steps, Vec::new(),),
            job(
                second,
                "second",
                1,
                LogicalWorkflowJobKind::Steps,
                vec![first, first],
            ),
        ]),
        Err(LogicalWorkflowAdmissionValueError::DuplicateDependency)
    ));
}

#[test]
fn graph_validation_rejects_cycles_and_duplicate_keys() {
    let first = LogicalWorkflowJobId::from_uuid(Uuid::from_u128(40)).expect("first");
    let second = LogicalWorkflowJobId::from_uuid(Uuid::from_u128(41)).expect("second");
    assert!(matches!(
        command(vec![
            job(
                first,
                "first",
                0,
                LogicalWorkflowJobKind::Steps,
                vec![second],
            ),
            job(
                second,
                "second",
                1,
                LogicalWorkflowJobKind::Steps,
                vec![first],
            ),
        ]),
        Err(LogicalWorkflowAdmissionValueError::CyclicDependency)
    ));

    assert!(matches!(
        command(vec![
            job(
                first,
                "same-key",
                0,
                LogicalWorkflowJobKind::Steps,
                Vec::new(),
            ),
            job(
                second,
                "same-key",
                1,
                LogicalWorkflowJobKind::Steps,
                Vec::new(),
            ),
        ]),
        Err(LogicalWorkflowAdmissionValueError::DuplicateJob)
    ));
}

#[test]
fn run_shape_rejects_invalid_attempt_ref_sha_and_time() {
    let only = LogicalWorkflowJobId::from_uuid(Uuid::from_u128(50)).expect("only");
    let jobs = || {
        vec![job(
            only,
            "only",
            0,
            LogicalWorkflowJobKind::Steps,
            Vec::new(),
        )]
    };
    assert!(matches!(
        command(Vec::new()),
        Err(LogicalWorkflowAdmissionValueError::NoJobs)
    ));

    let build_with = |run_attempt, git_ref: &str, head_sha: Vec<u8>, admitted_at| {
        AdmitLogicalWorkflowRun::builder(
            TenantScope::from_authenticated_tenant_id("logical-tenant").expect("tenant"),
            WorkflowAdmissionIdempotency::provider_delivery("delivery-shape").expect("idempotency"),
            Sha256Digest::from_bytes([42; 32]),
            AdmissionRepository::new(
                RepositoryId::from_uuid(Uuid::from_u128(51)),
                "forge",
                "repository-shape",
                "sample-owner",
                "sample-repository",
            )
            .expect("repository"),
            WorkflowId::from_uuid(Uuid::from_u128(52)),
            ".ci/workflows/build.yml",
            "Build",
            git_ref,
            WorkflowSnapshotId::from_uuid(Uuid::from_u128(53)),
            object("shape-source", 1),
            object("shape-plan", 2),
            RunId::from_uuid(Uuid::from_u128(54)),
            run_attempt,
            LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(55)).expect("root"),
            "push",
            object("shape-event", 3),
            head_sha,
            jobs(),
            UnixMillis::new(admitted_at),
        )
        .build()
    };
    assert!(matches!(
        build_with(0, "refs/heads/main", vec![9; 20], 1),
        Err(LogicalWorkflowAdmissionValueError::InvalidRunAttempt)
    ));
    assert!(matches!(
        build_with(1, "main", vec![9; 20], 1),
        Err(LogicalWorkflowAdmissionValueError::InvalidGitRef)
    ));
    assert!(matches!(
        build_with(1, "refs/heads/main", vec![9; 19], 1),
        Err(LogicalWorkflowAdmissionValueError::InvalidHeadSha)
    ));
    assert!(matches!(
        build_with(1, "refs/heads/main", vec![9; 20], -1),
        Err(LogicalWorkflowAdmissionValueError::InvalidAdmissionTime)
    ));
}
