use automata_ci_core::{
    GitObjectAlgorithm, GitObjectId, InvocationInputType, OutputSensitivity, PermissionLevel,
    RunId, Sha256Digest, UnixMillis, WorkflowId, WorkflowJobKey,
};
use automata_ci_store::{
    AdmissionObject, AdmissionRepository, AdmitLogicalWorkflowRun, AdmittedLogicalWorkflowJob,
    AdmittedReusableInput, AdmittedReusableInputKind, AdmittedReusableInvocation,
    AdmittedReusableJob, AdmittedReusableOutput, AdmittedReusablePermissions,
    AdmittedReusableSecret, AdmittedReusableWorkflowCatalogEntry,
    AdmittedReusableWorkflowExpansion, JobCredentialRequirements, JobEnvironmentRequirement,
    LogicalWorkflowAdmissionValueError, LogicalWorkflowInvocationId, LogicalWorkflowJobId,
    LogicalWorkflowJobKind, ObjectKey, RepositoryId, TenantScope, WorkflowAdmissionIdempotency,
    WorkflowSnapshotId,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

const ROOT_PATH: &str = ".ci/workflows/root.yml";
const CHILD_PATH: &str = ".ci/workflows/child.yml";
const SOURCE_REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
const SAMPLE_INPUT_VALUE: &str = "sample-caller-value";

fn source_revision() -> GitObjectId {
    GitObjectId::from_provider_hex(SOURCE_REVISION).expect("revision")
}

fn head_revision() -> GitObjectId {
    GitObjectId::from_bytes(GitObjectAlgorithm::Sha1, &[7; 20]).expect("revision")
}

fn digest(tag: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([tag; 32])
}

fn hashed(value: &str) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(value.as_bytes()).into())
}

fn snapshot_id(value: u128) -> WorkflowSnapshotId {
    WorkflowSnapshotId::from_uuid(Uuid::from_u128(value))
}

fn invocation_id(value: u128) -> LogicalWorkflowInvocationId {
    LogicalWorkflowInvocationId::from_uuid(Uuid::from_u128(value)).expect("non-nil invocation ID")
}

fn job_id(value: u128) -> LogicalWorkflowJobId {
    LogicalWorkflowJobId::from_uuid(Uuid::from_u128(value)).expect("non-nil job ID")
}

fn object(name: &str, tag: u8, media_type: &str) -> AdmissionObject {
    AdmissionObject::new(
        digest(tag),
        ObjectKey::new(format!("reusable-admission/{name}")).expect("valid object key"),
        128,
        media_type,
    )
    .expect("valid admission object")
}

fn root_source() -> AdmissionObject {
    object("root-source.yml", 1, "application/yaml")
}

fn root_plan() -> AdmissionObject {
    object(
        "root-plan.json",
        2,
        "application/vnd.automata.workflow-plan+json",
    )
}

fn reusable_job(
    id: LogicalWorkflowJobId,
    key: &str,
    source_order: u16,
    reusable: bool,
    prerequisites: Vec<LogicalWorkflowJobId>,
) -> AdmittedReusableJob {
    AdmittedReusableJob::new(
        id,
        WorkflowJobKey::new(key).expect("valid job key"),
        source_order,
        reusable,
        digest(40_u8.saturating_add(u8::try_from(source_order).unwrap_or(u8::MAX))),
        prerequisites,
    )
}

// These digests are opaque, internally consistent store-boundary evidence.
// They deliberately do not claim to reproduce workflow-service derivation.
fn store_shape_catalog() -> Vec<AdmittedReusableWorkflowCatalogEntry> {
    vec![
        AdmittedReusableWorkflowCatalogEntry::new(
            snapshot_id(100),
            ROOT_PATH,
            source_revision(),
            root_source(),
            root_plan(),
            None,
            digest(10),
            2,
            1,
        ),
        AdmittedReusableWorkflowCatalogEntry::new(
            snapshot_id(101),
            CHILD_PATH,
            source_revision(),
            object("child-source.yml", 3, "application/yaml"),
            object(
                "child-plan.json",
                4,
                "application/vnd.automata.workflow-plan+json",
            ),
            Some(digest(5)),
            digest(11),
            2,
            0,
        ),
    ]
}

#[derive(Clone)]
struct RootShape {
    id: LogicalWorkflowInvocationId,
    parent_id: Option<LogicalWorkflowInvocationId>,
    caller_job_id: Option<LogicalWorkflowJobId>,
    depth: u16,
    workflow_path: &'static str,
    source_digest: Sha256Digest,
    plan_digest: Sha256Digest,
    jobs: Vec<AdmittedReusableJob>,
}

impl RootShape {
    fn store_shape() -> Self {
        let call_child = job_id(300);
        Self {
            id: invocation_id(200),
            parent_id: None,
            caller_job_id: None,
            depth: 0,
            workflow_path: ROOT_PATH,
            source_digest: digest(1),
            plan_digest: digest(2),
            jobs: vec![
                reusable_job(call_child, "call-child", 0, true, Vec::new()),
                reusable_job(job_id(301), "finish", 1, false, vec![call_child]),
            ],
        }
    }
}

fn root_invocation(shape: RootShape) -> AdmittedReusableInvocation {
    AdmittedReusableInvocation::new(
        shape.id,
        shape.parent_id,
        shape.caller_job_id,
        snapshot_id(100),
        shape.depth,
        vec![ROOT_PATH.to_owned()],
        shape.workflow_path,
        shape.source_digest,
        shape.plan_digest,
        None,
        digest(20),
        digest(21),
        digest(22),
        digest(23),
        vec![
            AdmittedReusableInput::new(
                "enabled",
                InvocationInputType::Boolean,
                AdmittedReusableInputKind::Caller,
                Some(hashed(SAMPLE_INPUT_VALUE)),
            ),
            AdmittedReusableInput::new(
                "retries",
                InvocationInputType::Number,
                AdmittedReusableInputKind::Default,
                Some(digest(24)),
            ),
            AdmittedReusableInput::new(
                "environment",
                InvocationInputType::String,
                AdmittedReusableInputKind::ImplicitDefault,
                None,
            ),
        ],
        vec![AdmittedReusableSecret::new(
            "deployment-token",
            "DEPLOY_TOKEN",
        )],
        vec![
            AdmittedReusableOutput::new("artifact-url", OutputSensitivity::Public),
            AdmittedReusableOutput::new("receipt", OutputSensitivity::SecretDerived),
        ],
        AdmittedReusablePermissions::new(
            PermissionLevel::Read,
            vec![
                ("actions".to_owned(), PermissionLevel::None),
                ("contents".to_owned(), PermissionLevel::Read),
                ("deployments".to_owned(), PermissionLevel::Write),
            ],
            digest(25),
        ),
        shape.jobs,
    )
}

fn store_shape_root_invocation() -> AdmittedReusableInvocation {
    root_invocation(RootShape::store_shape())
}

fn child_invocation() -> AdmittedReusableInvocation {
    let prepare = job_id(302);
    AdmittedReusableInvocation::new(
        invocation_id(201),
        Some(invocation_id(200)),
        Some(job_id(300)),
        snapshot_id(101),
        1,
        vec![ROOT_PATH.to_owned(), CHILD_PATH.to_owned()],
        CHILD_PATH,
        digest(3),
        digest(4),
        Some(digest(5)),
        digest(26),
        digest(27),
        digest(28),
        digest(29),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        AdmittedReusablePermissions::new(PermissionLevel::None, Vec::new(), digest(30)),
        vec![
            reusable_job(prepare, "prepare", 0, false, Vec::new()),
            reusable_job(job_id(303), "publish", 1, false, vec![prepare]),
        ],
    )
}

fn store_shape_expansion() -> AdmittedReusableWorkflowExpansion {
    AdmittedReusableWorkflowExpansion::new(
        digest(31),
        store_shape_catalog(),
        vec![store_shape_root_invocation(), child_invocation()],
    )
}

fn logical_job(
    id: LogicalWorkflowJobId,
    key: &str,
    source_order: u16,
    kind: LogicalWorkflowJobKind,
    prerequisites: Vec<LogicalWorkflowJobId>,
) -> AdmittedLogicalWorkflowJob {
    AdmittedLogicalWorkflowJob::new(
        id,
        WorkflowJobKey::new(key).expect("valid job key"),
        source_order,
        kind,
        prerequisites,
    )
    .expect("valid logical job")
}

fn build_command(
    expansion: Option<AdmittedReusableWorkflowExpansion>,
    reusable_root_job: bool,
) -> Result<AdmitLogicalWorkflowRun, LogicalWorkflowAdmissionValueError> {
    let call_child = job_id(300);
    let root_kind = if reusable_root_job {
        LogicalWorkflowJobKind::ReusableWorkflow
    } else {
        LogicalWorkflowJobKind::Steps
    };
    AdmitLogicalWorkflowRun::builder(
        TenantScope::from_authenticated_tenant_id("reusable-admission-tenant")
            .expect("valid tenant"),
        WorkflowAdmissionIdempotency::provider_delivery("reusable-admission-delivery")
            .expect("valid idempotency key"),
        digest(60),
        AdmissionRepository::new(
            RepositoryId::from_uuid(Uuid::from_u128(400)),
            "github",
            "400",
            "example",
            "repository",
        )
        .expect("valid repository"),
        WorkflowId::from_uuid(Uuid::from_u128(401)),
        ROOT_PATH,
        "Root workflow",
        "refs/heads/main",
        snapshot_id(100),
        root_source(),
        root_plan(),
        RunId::from_uuid(Uuid::from_u128(402)),
        1,
        invocation_id(200),
        "push",
        object("event.json", 61, "application/json"),
        head_revision(),
        vec![
            logical_job(call_child, "call-child", 0, root_kind, Vec::new()),
            logical_job(
                job_id(301),
                "finish",
                1,
                LogicalWorkflowJobKind::Steps,
                vec![call_child],
            ),
        ],
        UnixMillis::new(1_000),
    )
    .reusable_workflows(expansion)
    .build()
}

fn expansion_with_root(
    tag: u8,
    catalog: &[AdmittedReusableWorkflowCatalogEntry],
    root: RootShape,
) -> AdmittedReusableWorkflowExpansion {
    AdmittedReusableWorkflowExpansion::new(
        digest(tag),
        catalog.to_vec(),
        vec![root_invocation(root)],
    )
}

fn assert_invalid_expansion(case: &'static str, expansion: AdmittedReusableWorkflowExpansion) {
    assert_eq!(
        build_command(Some(expansion), true).expect_err(case),
        LogicalWorkflowAdmissionValueError::InvalidReusableExpansion,
        "malformed case: {case}"
    );
}

#[test]
fn expansion_summary_and_catalog_preserve_ordered_store_evidence() {
    let expansion = store_shape_expansion();

    assert_eq!(expansion.digest(), digest(31));
    assert_eq!(expansion.catalog().len(), 2);
    assert_eq!(expansion.invocations().len(), 2);
    assert_eq!(expansion.job_count(), 4);
    assert_eq!(expansion.maximum_depth(), 1);

    let root_catalog = &expansion.catalog()[0];
    assert_eq!(root_catalog.id(), snapshot_id(100));
    assert_eq!(root_catalog.workflow_path(), ROOT_PATH);
    assert_eq!(root_catalog.source_revision(), source_revision());
    assert_eq!(root_catalog.source(), &root_source());
    assert_eq!(root_catalog.plan(), &root_plan());
    assert_eq!(root_catalog.invocation_contract_digest(), None);
    assert_eq!(root_catalog.descriptor_digest(), digest(10));
    assert_eq!(root_catalog.logical_job_count(), 2);
    assert_eq!(root_catalog.reusable_call_count(), 1);

    let child_catalog = &expansion.catalog()[1];
    assert_eq!(child_catalog.id(), snapshot_id(101));
    assert_eq!(child_catalog.workflow_path(), CHILD_PATH);
    assert_eq!(child_catalog.invocation_contract_digest(), Some(digest(5)));
    assert_eq!(child_catalog.logical_job_count(), 2);
    assert_eq!(child_catalog.reusable_call_count(), 0);
}

#[test]
fn root_invocation_preserves_exact_descriptor_evidence() {
    let expansion = store_shape_expansion();
    let root = &expansion.invocations()[0];
    assert_eq!(root.id(), invocation_id(200));
    assert_eq!(root.parent_id(), None);
    assert_eq!(root.caller_job_id(), None);
    assert_eq!(root.catalog_entry_id(), snapshot_id(100));
    assert_eq!(root.depth(), 0);
    assert_eq!(root.call_path(), &[ROOT_PATH.to_owned()]);
    assert_eq!(root.workflow_path(), ROOT_PATH);
    assert_eq!(root.source_digest(), digest(1));
    assert_eq!(root.plan_digest(), digest(2));
    assert_eq!(root.call_reference_digest(), None);
    assert_eq!(root.input_bindings_digest(), digest(20));
    assert_eq!(root.secret_bindings_digest(), digest(21));
    assert_eq!(root.output_contract_digest(), digest(22));
    assert_eq!(root.descriptor_digest(), digest(23));
    assert_eq!(root.dependency_count(), 1);
}

#[test]
fn typed_contract_is_ordered_and_retains_only_value_digests() {
    let expansion = store_shape_expansion();
    let root = &expansion.invocations()[0];
    let inputs = root.inputs();
    assert_eq!(inputs.len(), 3);
    assert_eq!(inputs[0].key(), "enabled");
    assert_eq!(inputs[0].input_type(), InvocationInputType::Boolean);
    assert_eq!(inputs[0].kind(), AdmittedReusableInputKind::Caller);
    assert_eq!(inputs[0].value_digest(), Some(hashed(SAMPLE_INPUT_VALUE)));
    assert_eq!(inputs[1].key(), "retries");
    assert_eq!(inputs[1].input_type(), InvocationInputType::Number);
    assert_eq!(inputs[1].kind(), AdmittedReusableInputKind::Default);
    assert_eq!(inputs[1].value_digest(), Some(digest(24)));
    assert_eq!(inputs[2].key(), "environment");
    assert_eq!(inputs[2].input_type(), InvocationInputType::String);
    assert_eq!(inputs[2].kind(), AdmittedReusableInputKind::ImplicitDefault);
    assert_eq!(inputs[2].value_digest(), None);
    assert_eq!(AdmittedReusableInputKind::Caller.as_str(), "caller");
    assert_eq!(AdmittedReusableInputKind::Default.as_str(), "default");
    assert_eq!(
        AdmittedReusableInputKind::ImplicitDefault.as_str(),
        "implicit_default"
    );

    assert_eq!(root.secrets()[0].target(), "deployment-token");
    assert_eq!(root.secrets()[0].source(), "DEPLOY_TOKEN");
    assert_eq!(root.outputs()[0].key(), "artifact-url");
    assert_eq!(root.outputs()[0].sensitivity(), OutputSensitivity::Public);
    assert_eq!(root.outputs()[1].key(), "receipt");
    assert_eq!(
        root.outputs()[1].sensitivity(),
        OutputSensitivity::SecretDerived
    );

    assert_eq!(root.permissions().default_level(), PermissionLevel::Read);
    assert_eq!(
        root.permissions().grants(),
        &[
            ("actions".to_owned(), PermissionLevel::None),
            ("contents".to_owned(), PermissionLevel::Read),
            ("deployments".to_owned(), PermissionLevel::Write),
        ]
    );
    assert_eq!(root.permissions().digest(), digest(25));
}

#[test]
fn planned_jobs_child_linkage_and_command_attachment_remain_exact() {
    let expansion = store_shape_expansion();
    let root = &expansion.invocations()[0];
    assert_eq!(root.jobs()[0].id(), job_id(300));
    assert_eq!(root.jobs()[0].key().as_str(), "call-child");
    assert_eq!(root.jobs()[0].source_order(), 0);
    assert!(root.jobs()[0].is_reusable());
    assert_eq!(root.jobs()[0].descriptor_digest(), digest(40));
    assert!(root.jobs()[0].prerequisites().is_empty());
    assert_eq!(root.jobs()[1].source_order(), 1);
    assert!(!root.jobs()[1].is_reusable());
    assert_eq!(root.jobs()[1].descriptor_digest(), digest(41));
    assert_eq!(root.jobs()[1].prerequisites(), &[job_id(300)]);

    let child = &expansion.invocations()[1];
    assert_eq!(child.parent_id(), Some(invocation_id(200)));
    assert_eq!(child.caller_job_id(), Some(job_id(300)));
    assert_eq!(child.catalog_entry_id(), snapshot_id(101));
    assert_eq!(
        child.call_path(),
        &[ROOT_PATH.to_owned(), CHILD_PATH.to_owned()]
    );
    assert_eq!(child.call_reference_digest(), Some(digest(5)));
    assert!(child.inputs().is_empty());
    assert!(child.secrets().is_empty());
    assert!(child.outputs().is_empty());
    assert_eq!(child.permissions().default_level(), PermissionLevel::None);
    assert!(child.permissions().grants().is_empty());
    assert_eq!(child.dependency_count(), 1);

    let command = build_command(Some(expansion.clone()), true)
        .expect("the complete store-shape expansion must be admitted");
    assert_eq!(command.reusable_workflows(), Some(&expansion));
}

#[test]
fn planned_reusable_jobs_retain_exact_value_free_credential_requirements() {
    let requirements = JobCredentialRequirements::new(
        JobEnvironmentRequirement::Environment(digest(44)),
        ["DEPLOY_TOKEN".to_owned(), "RELEASE_TOKEN".to_owned()],
        ["CHANNEL".to_owned()],
    )
    .expect("valid credential requirements");
    let job = reusable_job(job_id(304), "deploy", 0, false, Vec::new())
        .with_credential_requirements(requirements.clone());

    assert_eq!(job.credential_requirements(), &requirements);
    assert_eq!(
        job.credential_requirements().environment(),
        JobEnvironmentRequirement::Environment(digest(44))
    );
    assert_eq!(
        job.credential_requirements().secret_names(),
        &["DEPLOY_TOKEN".to_owned(), "RELEASE_TOKEN".to_owned()]
    );
    assert_eq!(
        job.credential_requirements().variable_names(),
        &["CHANNEL".to_owned()]
    );
}

#[test]
fn aggregate_boundaries_and_input_order_remain_explicit() {
    let empty = AdmittedReusableWorkflowExpansion::new(digest(70), Vec::new(), Vec::new());
    assert_eq!(empty.job_count(), 0);
    assert_eq!(empty.maximum_depth(), 0);

    let deepest = root_invocation(RootShape {
        id: invocation_id(700),
        parent_id: Some(invocation_id(699)),
        caller_job_id: Some(job_id(698)),
        depth: u16::MAX,
        workflow_path: CHILD_PATH,
        source_digest: digest(71),
        plan_digest: digest(72),
        jobs: Vec::new(),
    });
    let boundary = AdmittedReusableWorkflowExpansion::new(
        digest(73),
        Vec::new(),
        vec![store_shape_root_invocation(), deepest],
    );
    assert_eq!(boundary.maximum_depth(), u16::MAX);
    assert_eq!(boundary.job_count(), 2);

    let ordered = store_shape_expansion();
    let mut reversed_catalog = ordered.catalog().to_vec();
    reversed_catalog.reverse();
    let reordered = AdmittedReusableWorkflowExpansion::new(
        ordered.digest(),
        reversed_catalog,
        ordered.invocations().to_vec(),
    );
    assert_eq!(reordered.catalog()[0].workflow_path(), CHILD_PATH);
    assert_ne!(
        reordered, ordered,
        "input order is retained evidence and must never be silently sorted"
    );
}

#[test]
fn logical_admission_requires_a_nonempty_matching_expansion() {
    let valid = store_shape_expansion();
    build_command(Some(valid.clone()), true).expect("control fixture must be valid");

    assert_invalid_expansion(
        "empty catalog",
        AdmittedReusableWorkflowExpansion::new(
            digest(80),
            Vec::new(),
            valid.invocations().to_vec(),
        ),
    );
    assert_invalid_expansion(
        "empty invocation list",
        AdmittedReusableWorkflowExpansion::new(digest(81), valid.catalog().to_vec(), Vec::new()),
    );
    assert_invalid_expansion(
        "empty expanded job graph",
        expansion_with_root(
            82,
            valid.catalog(),
            RootShape {
                jobs: Vec::new(),
                ..RootShape::store_shape()
            },
        ),
    );

    assert_eq!(
        build_command(None, true).expect_err("reusable jobs require an expansion"),
        LogicalWorkflowAdmissionValueError::InvalidReusableExpansion
    );
    assert_eq!(
        build_command(Some(valid), false).expect_err("step-only runs reject an expansion"),
        LogicalWorkflowAdmissionValueError::InvalidReusableExpansion
    );
}

#[test]
fn logical_admission_rejects_malformed_root_identity_and_evidence() {
    let valid = store_shape_expansion();
    let store_shape = RootShape::store_shape();
    let malformed = [
        (
            "wrong root invocation identity",
            83,
            RootShape {
                id: invocation_id(202),
                ..store_shape.clone()
            },
        ),
        (
            "root has parent",
            84,
            RootShape {
                parent_id: Some(invocation_id(201)),
                ..store_shape.clone()
            },
        ),
        (
            "root has caller job",
            85,
            RootShape {
                caller_job_id: Some(job_id(300)),
                ..store_shape.clone()
            },
        ),
        (
            "nonzero root depth",
            86,
            RootShape {
                depth: 1,
                ..store_shape.clone()
            },
        ),
        (
            "wrong root workflow path",
            87,
            RootShape {
                workflow_path: CHILD_PATH,
                ..store_shape.clone()
            },
        ),
        (
            "wrong root source digest",
            88,
            RootShape {
                source_digest: digest(99),
                ..store_shape.clone()
            },
        ),
        (
            "wrong root plan digest",
            89,
            RootShape {
                plan_digest: digest(99),
                ..store_shape
            },
        ),
    ];

    for (case, tag, root) in malformed {
        assert_invalid_expansion(case, expansion_with_root(tag, valid.catalog(), root));
    }
}
